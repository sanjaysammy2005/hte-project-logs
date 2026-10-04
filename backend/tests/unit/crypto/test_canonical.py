"""T2.1–T2.4: canonical serialisation is deterministic, unambiguous and strict."""

import json
import random
import unicodedata
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.crypto.canonical import (
    START_EVENT,
    AuditRecord,
    CanonicalizationError,
    canonical_json,
    encode_context,
    encode_event,
    format_timestamp,
    normalize_text,
)
from app.crypto.chain import GENESIS_HASH, compute_entry_hash, hash_input
from tests.factories import BASE_TIME, equivalent_variant, random_record
from tests.reference_tl_v1 import decode_hash_input


def _record(**overrides: object) -> AuditRecord:
    base = AuditRecord(
        event_type="FILE_OPEN",
        event_payload={"resource": "/reports/q3.xlsx"},
        actor_user_id="U101",
        session_id="S5001",
        prev_event_type="AUTHENTICATION",
        session_seq=3,
        event_timestamp=BASE_TIME,
    )
    return replace(base, **overrides)


def _encoded(record: AuditRecord) -> bytes:
    return encode_event(record) + encode_context(record)


# --- T2.1 / T2.2: same logical record -> identical bytes -------------------------------------


def test_payload_key_order_does_not_change_bytes() -> None:
    a = _record(event_payload={"resource": "/x", "outcome": "ok", "nested": {"b": 1, "a": 2}})
    b = _record(event_payload={"nested": {"a": 2, "b": 1}, "outcome": "ok", "resource": "/x"})

    assert _encoded(a) == _encoded(b)


def test_unicode_normalisation_forms_give_identical_bytes() -> None:
    composed = "café"
    decomposed = "café"
    assert composed != decomposed

    a = _record(actor_user_id=composed, event_payload={composed: composed})
    b = _record(actor_user_id=decomposed, event_payload={decomposed: decomposed})

    assert _encoded(a) == _encoded(b)


def test_equivalent_timestamps_in_other_time_zones_give_identical_bytes() -> None:
    india = timezone(timedelta(hours=5, minutes=30))

    a = _record(event_timestamp=datetime(2026, 10, 4, 10, 15, 32, 123456, tzinfo=UTC))
    b = _record(event_timestamp=datetime(2026, 10, 4, 15, 45, 32, 123456, tzinfo=india))

    assert _encoded(a) == _encoded(b)


def test_1000_randomised_equivalent_representations_encode_identically() -> None:
    rng = random.Random(20261004)
    for i in range(1000):
        original = random_record(rng, offset_seconds=i)
        variant = equivalent_variant(original, rng)
        # Simulate a storage round-trip of the payload (PostgreSQL jsonb re-serialises it).
        stored = replace(
            variant, event_payload=json.loads(json.dumps(variant.event_payload, ensure_ascii=True))
        )

        assert _encoded(variant) == _encoded(original), f"iteration {i}"
        assert _encoded(stored) == _encoded(original), f"iteration {i}"
        assert compute_entry_hash(variant, GENESIS_HASH) == compute_entry_hash(
            original, GENESIS_HASH
        )


# --- T2.3: no field-boundary ambiguity ------------------------------------------------------


def test_field_boundary_shift_changes_encoding() -> None:
    # Plain concatenation would make both "U10S".
    a = _record(actor_user_id="U1", session_id="0S")
    b = _record(actor_user_id="U10", session_id="S")

    assert _encoded(a) != _encoded(b)
    assert compute_entry_hash(a, GENESIS_HASH) != compute_entry_hash(b, GENESIS_HASH)


def test_event_type_and_payload_boundary_is_unambiguous() -> None:
    a = _record(event_type="FILE", event_payload={"x": "1"})
    b = _record(event_type='FILE{"x":"1"}', event_payload={})

    assert encode_event(a) != encode_event(b)


@pytest.mark.parametrize("field", ["actor_user_id", "session_id", "prev_event_type"])
def test_null_differs_from_empty_string(field: str) -> None:
    assert _encoded(_record(**{field: None})) != _encoded(_record(**{field: ""}))


def test_every_encoding_decodes_back_to_its_fields() -> None:
    """A prefix-free, fully decodable encoding cannot map two different records to one string."""
    rng = random.Random(42)
    for i in range(1000):
        record = random_record(rng, offset_seconds=i)
        prev = rng.randbytes(32)

        decoded = decode_hash_input(hash_input(record, prev))

        seq = record.session_seq
        assert decoded == {
            "event_type": unicodedata.normalize("NFC", record.event_type),
            "payload_json": canonical_json(record.event_payload),
            "actor_user_id": _nfc_or_none(record.actor_user_id),
            "session_id": _nfc_or_none(record.session_id),
            "prev_event_type": record.prev_event_type,
            "session_seq": None if seq is None else str(seq),
            "timestamp": format_timestamp(record.event_timestamp),
            "prev_hash": prev,
        }


def _nfc_or_none(value: str | None) -> str | None:
    return None if value is None else unicodedata.normalize("NFC", value)


# --- canonical JSON and timestamp format ----------------------------------------------------


def test_canonical_json_exact_form() -> None:
    payload = {"b": 1, "a": [True, None, "x"], "é": "naïve", "ctl": "line\nbreak\x01"}

    assert canonical_json(payload) == (
        '{"a":[true,null,"x"],"b":1,"ctl":"line\\nbreak\\u0001","é":"naïve"}'
    )


def test_tuple_and_list_encode_identically() -> None:
    assert canonical_json({"v": (1, 2)}) == canonical_json({"v": [1, 2]})


def test_empty_payload_is_empty_object() -> None:
    assert canonical_json({}) == "{}"


def test_timestamp_format_is_utc_with_microseconds() -> None:
    plus_two = timezone(timedelta(hours=2))

    assert format_timestamp(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)) == (
        "2026-01-02T03:04:05.000000Z"
    )
    assert format_timestamp(datetime(2026, 1, 2, 3, 4, 5, 7, tzinfo=plus_two)) == (
        "2026-01-02T01:04:05.000007Z"
    )


def test_first_event_of_session_uses_start_marker() -> None:
    assert START_EVENT == "__START__"
    assert _encoded(_record(prev_event_type=START_EVENT)) != _encoded(_record(prev_event_type=None))


# --- T2.4: strict rejection of values that cannot be encoded canonically --------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"ratio": 0.5},
        {"nested": {"ratio": 1.0}},
        {"list": [1, 2.5]},
        {"big": 2**53},
        {"small": -(2**53)},
        {"set": {1, 2}},
        {"bytes": b"raw"},
        {"nul": "a\x00b"},
        {"surrogate": "\ud800"},
        {1: "non-text key"},
        {"café": 1, "café": 2},  # same key after NFC
    ],
)
def test_unencodable_payloads_are_rejected(payload: dict) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json(payload)


def test_safe_integer_bounds_are_accepted() -> None:
    assert canonical_json({"max": 2**53 - 1, "min": -(2**53 - 1)}) == (
        '{"max":9007199254740991,"min":-9007199254740991}'
    )


def test_payload_must_be_an_object() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json(["not", "an", "object"])  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [123, None, b"bytes"])
def test_text_fields_must_be_text(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        normalize_text(value)


def test_text_with_nul_is_rejected_in_context_fields() -> None:
    with pytest.raises(CanonicalizationError):
        encode_context(_record(actor_user_id="U1\x00"))


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        format_timestamp(datetime(2026, 10, 4, 10, 15, 32))


def test_non_datetime_timestamp_is_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        format_timestamp("2026-10-04T10:15:32Z")  # type: ignore[arg-type]


@pytest.mark.parametrize("seq", [True, "3", 3.0])
def test_sequence_number_must_be_an_integer(seq: object) -> None:
    with pytest.raises(CanonicalizationError):
        encode_context(_record(session_seq=seq))
