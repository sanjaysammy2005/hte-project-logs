"""T2.5–T2.10: the hash chain detects modification, deletion, insertion and reordering.

Positions (k) are 1-based chain indices, matching the paper and the report format.
"""

import hashlib
from dataclasses import replace
from datetime import timedelta

import pytest

from app.crypto.canonical import AuditRecord, CanonicalizationError
from app.crypto.chain import (
    GENESIS_HASH,
    ChainCheck,
    ChainedRecord,
    build_chain,
    compute_entry_hash,
    hash_input,
    rehash,
    verify_chain,
)
from tests.factories import make_chain, make_session

N = 100


def _checks(chain: list[ChainedRecord]) -> list[tuple[int, ChainCheck]]:
    return [(f.position, f.check) for f in verify_chain(chain).findings]


def _modify(chain: list[ChainedRecord], k: int, **fields: object) -> list[ChainedRecord]:
    """Naive attacker (A0): change stored fields of record k, keep its stored hashes."""
    tampered = list(chain)
    item = tampered[k - 1]
    tampered[k - 1] = replace(item, record=replace(item.record, **fields))
    return tampered


def _renumber(chain: list[ChainedRecord]) -> list[ChainedRecord]:
    return [replace(item, chain_index=i) for i, item in enumerate(chain, start=1)]


# --- T2.5: valid chains ---------------------------------------------------------------------


@pytest.mark.parametrize("length", [1, 2, N])
def test_valid_chain_verifies(length: int) -> None:
    result = verify_chain(make_chain(length))

    assert result.is_valid
    assert result.first_failure is None
    assert result.records_checked == length
    assert result.cascade_affected_records == 0


def test_empty_chain_is_valid() -> None:
    result = verify_chain([])

    assert result.is_valid and result.records_checked == 0


def test_first_record_links_to_genesis_and_each_record_to_its_predecessor() -> None:
    chain = make_chain(5)

    assert GENESIS_HASH == bytes(32)
    assert chain[0].prev_hash == GENESIS_HASH
    for previous, current in zip(chain, chain[1:], strict=False):
        assert current.prev_hash == previous.entry_hash
    assert [item.chain_index for item in chain] == [1, 2, 3, 4, 5]


def test_entry_hash_is_sha256_of_hash_input() -> None:
    item = make_chain(1)[0]

    assert item.entry_hash == hashlib.sha256(hash_input(item.record, GENESIS_HASH)).digest()


def test_hash_input_rejects_malformed_previous_hash() -> None:
    record = make_chain(1)[0].record
    for bad in (b"", bytes(31), bytes(33), "00" * 32):
        with pytest.raises(CanonicalizationError):
            compute_entry_hash(record, bad)  # type: ignore[arg-type]


# --- T2.6: modified event -------------------------------------------------------------------


@pytest.mark.parametrize("k", [1, 50, N])
def test_modified_event_type_detected_at_k(k: int) -> None:
    chain = make_chain(N)
    tampered = _modify(
        chain, k, event_type="LOGOUT" if chain[k - 1].record.event_type != "LOGOUT" else "LOGIN"
    )

    result = verify_chain(tampered)

    assert _checks(tampered) == [(k, ChainCheck.CHAIN_HASH)]
    assert result.first_failure is not None and result.first_failure.chain_index == k
    # The paper's "every subsequent chain value" property, as seen by full recomputation.
    assert result.cascade_affected_records == N - k + 1


@pytest.mark.parametrize("k", [1, 50, N])
def test_modified_event_payload_detected_at_k(k: int) -> None:
    chain = make_chain(N)
    tampered = _modify(chain, k, event_payload={"resource": "/attacker/edited"})

    assert _checks(tampered) == [(k, ChainCheck.CHAIN_HASH)]


# --- T2.7: modified context (each field separately) -----------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("actor_user_id", "U-ATTACKER"),
        ("session_id", "S-OTHER"),
        ("prev_event_type", "LOGOUT-X"),
        ("session_seq", 999_999),
        ("actor_user_id", None),
    ],
)
def test_modified_context_field_detected_at_k(field: str, value: object) -> None:
    k = 37
    chain = make_chain(N)
    tampered = _modify(chain, k, **{field: value})

    assert _checks(tampered) == [(k, ChainCheck.CHAIN_HASH)]


def test_timestamp_shifted_by_one_microsecond_detected() -> None:
    k = 12
    chain = make_chain(N)
    original = chain[k - 1].record.event_timestamp
    tampered = _modify(chain, k, event_timestamp=original + timedelta(microseconds=1))

    assert _checks(tampered) == [(k, ChainCheck.CHAIN_HASH)]


def test_attacker_who_recomputes_the_modified_record_hash_is_caught_at_successor() -> None:
    """Attacker A1: SHA-256 is unkeyed, so record k's own hash can be recomputed."""
    k = 40
    tampered = _modify(make_chain(N), k, event_payload={"resource": "/hidden"})
    tampered[k - 1] = rehash(tampered[k - 1])

    assert _checks(tampered) == [(k + 1, ChainCheck.CHAIN_LINK)]


def test_full_rewrite_from_k_is_not_detected() -> None:
    """Attacker A2 (paper §IX-B): recomputing every later hash produces a valid-looking chain.

    This documents a known limitation; it is not a bug.
    """
    k = 40
    tampered = _modify(make_chain(N), k, event_payload={"resource": "/hidden"})
    for i in range(k - 1, N):
        prev = GENESIS_HASH if i == 0 else tampered[i - 1].entry_hash
        tampered[i] = rehash(tampered[i], prev_hash=prev)

    assert verify_chain(tampered).is_valid


# --- T2.8: deleted record -------------------------------------------------------------------


@pytest.mark.parametrize("k", [2, 50, N - 1])
def test_deleted_record_detected_at_successor(k: int) -> None:
    chain = make_chain(N)
    tampered = chain[: k - 1] + chain[k:]

    result = verify_chain(tampered)

    assert _checks(tampered) == [
        (k, ChainCheck.CHAIN_INDEX_CONTINUITY),
        (k, ChainCheck.CHAIN_LINK),
    ]
    assert result.first_failure is not None
    assert result.first_failure.chain_index == k + 1  # the successor's stored index
    assert result.first_failure.expected == str(k)


def test_deleted_first_record_detected_against_genesis() -> None:
    chain = make_chain(N)

    result = verify_chain(chain[1:])

    assert _checks(chain[1:]) == [
        (1, ChainCheck.CHAIN_INDEX_CONTINUITY),
        (1, ChainCheck.CHAIN_LINK),
    ]
    assert result.findings[1].expected == GENESIS_HASH.hex()


def test_deleted_then_renumbered_record_still_detected_by_link() -> None:
    k = 30
    chain = make_chain(N)

    assert _checks(_renumber(chain[: k - 1] + chain[k:])) == [(k, ChainCheck.CHAIN_LINK)]


def test_deleting_the_last_record_is_not_detected_by_the_chain_alone() -> None:
    """Tail truncation (EXPERIMENTS S10): no later record refers to the deleted one.

    Documents a known limitation (SECURITY_LIMITATIONS §4); it is not a bug.
    """
    assert verify_chain(make_chain(N)[:-1]).is_valid


# --- T2.9: inserted record ------------------------------------------------------------------


def test_inserted_record_with_valid_own_hash_detected_at_successor() -> None:
    k = 25
    chain = make_chain(N)
    template = chain[k - 1].record
    forged_record = replace(template, event_type="DB_ACCESS", event_payload={"forged": True})
    forged = ChainedRecord(
        chain_index=k,
        record=forged_record,
        prev_hash=chain[k - 2].entry_hash,  # links correctly to its predecessor
        entry_hash=compute_entry_hash(forged_record, chain[k - 2].entry_hash),
    )
    tampered = _renumber(chain[: k - 1] + [forged] + chain[k - 1 :])

    # The forged record itself passes the chain checks (provenance checks target it later);
    # the original record k, now at position k+1, no longer links to its predecessor.
    assert _checks(tampered) == [(k + 1, ChainCheck.CHAIN_LINK)]


def test_inserted_record_without_renumbering_breaks_index_continuity() -> None:
    k = 25
    chain = make_chain(N)
    duplicate_index = replace(chain[k - 1], record=replace(chain[k - 1].record, session_seq=1))
    tampered = chain[:k] + [duplicate_index] + chain[k:]

    first = verify_chain(tampered).first_failure

    assert first is not None
    assert (first.position, first.check) == (k + 1, ChainCheck.CHAIN_INDEX_CONTINUITY)


# --- T2.10: reordered records ---------------------------------------------------------------


def test_swapped_records_detected_at_first_swapped_position() -> None:
    k, j = 20, 60
    chain = make_chain(N)
    tampered = list(chain)
    tampered[k - 1], tampered[j - 1] = chain[j - 1], chain[k - 1]
    tampered = _renumber(tampered)  # attacker also fixes the index column

    first = verify_chain(tampered).first_failure

    assert first is not None
    assert (first.position, first.check) == (k, ChainCheck.CHAIN_LINK)


def test_adjacent_swap_without_renumbering_detected() -> None:
    k = 10
    chain = make_chain(N)
    tampered = list(chain)
    tampered[k - 1], tampered[k] = chain[k], chain[k - 1]

    first = verify_chain(tampered).first_failure

    assert first is not None
    assert (first.position, first.check) == (k, ChainCheck.CHAIN_INDEX_CONTINUITY)


# --- robustness: verification never crashes on tampered storage -----------------------------


def test_unencodable_tampered_record_is_reported_not_raised() -> None:
    k = 15
    tampered = _modify(make_chain(N), k, event_payload={"ratio": 0.5})

    result = verify_chain(tampered)

    assert _checks(tampered) == [(k, ChainCheck.CHAIN_HASH)]
    assert result.findings[0].expected.startswith("<unencodable record:")
    assert result.cascade_affected_records == N - k + 1


def test_malformed_stored_previous_hash_is_reported_not_raised() -> None:
    k = 15
    chain = make_chain(N)
    tampered = list(chain)
    tampered[k - 1] = replace(chain[k - 1], prev_hash=b"\x01" * 5)

    assert _checks(tampered) == [(k, ChainCheck.CHAIN_LINK), (k, ChainCheck.CHAIN_HASH)]


def test_wrong_genesis_detected_at_first_record() -> None:
    result = verify_chain(make_chain(3), genesis_hash=b"\xff" * 32)

    assert [(f.position, f.check) for f in result.findings] == [(1, ChainCheck.CHAIN_LINK)]


# --- the paper's worked example (§VI-F), chain part ----------------------------------------


def test_paper_example_deleting_authentication_breaks_chain_at_open_file() -> None:
    """Paper §VI-F: "The hash chain no longer matches at 'Open File'"."""
    records: list[AuditRecord] = make_session()
    chain = build_chain(records)
    assert [c.record.event_type for c in chain] == [
        "LOGIN",
        "AUTHENTICATION",
        "FILE_OPEN",
        "FILE_EDIT",
        "LOGOUT",
    ]

    tampered = [c for c in chain if c.record.event_type != "AUTHENTICATION"]
    first = verify_chain(tampered).first_failure

    assert first is not None
    assert first.chain_index == 3
    assert tampered[first.position - 1].record.event_type == "FILE_OPEN"
    assert first.check == ChainCheck.CHAIN_INDEX_CONTINUITY
    assert ChainCheck.CHAIN_LINK in {f.check for f in verify_chain(tampered).findings}
