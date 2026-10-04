"""Canonical byte encoding of audit records (hash scheme ``tl-v1``).

The paper requires that "the same logical record must always produce identical bytes"
(§VI-A) but does not define the bytes. This module does; see docs/VERIFICATION.md §2.

All text is NFC-normalised and UTF-8 encoded:

    str(x)   = uint32_be(len(utf8(x))) || utf8(x)
    opt(x)   = 0x00                if x is None
             = 0x01 || str(x)      otherwise
    enc(E_n) = str(event_type) || str(canonical_json(event_payload))
    enc(C_n) = opt(actor_user_id) || opt(session_id) || opt(prev_event_type)
               || opt(decimal(session_seq)) || str(timestamp)

The length prefixes make field boundaries unambiguous: ("U1", "0S") and ("U10", "S")
encode differently, and a null field differs from an empty one.
"""

import json
import struct
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# prev_event_type of the first event in a session [Rec, VERIFICATION §4.1].
START_EVENT = "__START__"

# Largest integer that every JSON consumer (including JavaScript) represents exactly.
MAX_SAFE_INTEGER = 2**53 - 1

_NULL = b"\x00"
_PRESENT = b"\x01"


class CanonicalizationError(ValueError):
    """A value cannot be encoded canonically, so it must not be hashed or stored."""


@dataclass(frozen=True)
class AuditRecord:
    """The hashed content of one audit record: the event E_n and its context C_n (paper Eq. 1)."""

    event_type: str
    event_payload: Mapping[str, Any]
    actor_user_id: str | None
    session_id: str | None
    prev_event_type: str | None
    session_seq: int | None
    event_timestamp: datetime


def normalize_text(value: object) -> str:
    """Return ``value`` in Unicode NFC form, rejecting text that cannot be stored or encoded."""
    if not isinstance(value, str):
        raise CanonicalizationError(f"expected text, got {type(value).__name__}")
    # PostgreSQL text and jsonb cannot store NUL, so such a record could never round-trip.
    if "\x00" in value:
        raise CanonicalizationError("text must not contain NUL characters")
    normalized = unicodedata.normalize("NFC", value)
    try:
        normalized.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("text contains an unpaired surrogate") from exc
    return normalized


def canonical_json(payload: Mapping[str, Any]) -> str:
    """Serialise an event payload deterministically: sorted keys, no whitespace, NFC text."""
    if not isinstance(payload, Mapping):
        raise CanonicalizationError("event payload must be a JSON object")
    return json.dumps(
        _canonical_value(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"integer {value} is outside the safe range ±(2^53 - 1)")
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floats are not allowed in event payloads")
    if isinstance(value, str):
        return normalize_text(value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = normalize_text(key)
            if normalized_key in result:
                raise CanonicalizationError(
                    f"duplicate payload key after normalisation: {normalized_key!r}"
                )
            result[normalized_key] = _canonical_value(item)
        return result
    if isinstance(value, list | tuple):
        return [_canonical_value(item) for item in value]
    raise CanonicalizationError(f"unsupported payload value type: {type(value).__name__}")


def format_timestamp(value: datetime) -> str:
    """Format as ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` in UTC (microsecond precision, like PostgreSQL)."""
    if not isinstance(value, datetime):
        raise CanonicalizationError("timestamp must be a datetime")
    if value.utcoffset() is None:
        raise CanonicalizationError("timestamp must be timezone-aware")
    utc = value.astimezone(UTC)
    return (
        f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}"
        f"T{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}.{utc.microsecond:06d}Z"
    )


def encode_str(value: object) -> bytes:
    data = normalize_text(value).encode("utf-8")
    return struct.pack(">I", len(data)) + data


def encode_opt(value: object | None) -> bytes:
    return _NULL if value is None else _PRESENT + encode_str(value)


def _sequence_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise CanonicalizationError("session sequence number must be an integer")
    return str(value)


def encode_event(record: AuditRecord) -> bytes:
    """enc(E_n): the event type and its canonical payload."""
    return encode_str(record.event_type) + encode_str(canonical_json(record.event_payload))


def encode_context(record: AuditRecord) -> bytes:
    """enc(C_n): user, session, previous event, sequence number and timestamp, in Eq. 1 order."""
    return (
        encode_opt(record.actor_user_id)
        + encode_opt(record.session_id)
        + encode_opt(record.prev_event_type)
        + encode_opt(_sequence_text(record.session_seq))
        + encode_str(format_timestamp(record.event_timestamp))
    )
