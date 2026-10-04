"""Verification engine over plain data: combined report, ordering, Merkle range edge cases."""

import uuid
from dataclasses import replace

from app.crypto.chain import GENESIS_HASH, build_chain
from app.crypto.merkle import merkle_root
from app.provenance.rules import load_rules
from app.verification.engine import BatchRecord, build_report
from tests.factories import make_session

RULES = load_rules()


def _stream(sessions: int = 4, batch_size: int = 4):
    records = []
    for i in range(sessions):
        records += make_session(
            user=f"U{i}",
            session=f"S{i}",
            start=records[-1].event_timestamp if records else make_session()[0].event_timestamp,
        )
    chain = build_chain(records)
    batches = []
    for b, first in enumerate(range(1, len(chain) + 1, batch_size), start=1):
        last = min(first + batch_size - 1, len(chain))
        if last - first + 1 < batch_size:
            break  # leave the remainder unsealed
        leaves = [c.entry_hash for c in chain[first - 1 : last]]
        batches.append(
            BatchRecord(uuid.uuid4(), b, first, last, last - first + 1, merkle_root(leaves))
        )
    return chain, batches


def test_untampered_stream_is_valid_and_counts_unbatched() -> None:
    chain, batches = _stream()  # 20 records, 5 batches of 4

    report = build_report(chain, batches, GENESIS_HASH, RULES)

    assert report.status == "VALID" and report.first_failure is None
    assert (report.records_checked, report.batches_checked, report.unbatched_records) == (20, 5, 0)
    assert report.rules_version == RULES.identifier and report.duration_ms >= 0

    partial, partial_batches = _stream(sessions=3, batch_size=4)  # 15 records, 3 batches
    assert build_report(partial, partial_batches, GENESIS_HASH, RULES).unbatched_records == 3


def test_modified_record_reports_chain_then_merkle_with_batch_id() -> None:
    chain, batches = _stream()
    k = 6  # inside batch 2 (records 5-8)
    chain[k - 1] = replace(chain[k - 1], record=replace(chain[k - 1].record, event_payload={}))

    report = build_report(chain, batches, GENESIS_HASH, RULES)

    first = report.first_failure
    assert report.status == "TAMPERING_DETECTED"
    assert first is not None
    assert (first.chain_index, first.check, first.batch_index) == (k, "CHAIN_HASH", 2)
    assert first.batch_id == batches[1].id
    assert report.failed_by_check == {"CHAIN_HASH": 1, "MERKLE_ROOT": 1}


def test_deleted_record_reports_chain_provenance_and_merkle() -> None:
    chain, batches = _stream()
    del chain[6]  # record 7

    report = build_report(chain, batches, GENESIS_HASH, RULES)

    checks = {f.check for f in report.findings}
    # The successor (8) is inside batch 2, so it explains the batch failure.
    assert report.first_failure is not None and report.first_failure.chain_index == 8
    assert {
        "CHAIN_INDEX_CONTINUITY",
        "CHAIN_LINK",
        "PROV_SEQUENCE",
        "MERKLE_RANGE",
        "MERKLE_ROOT",
    } <= checks


def test_altered_stored_root_is_detected() -> None:
    chain, batches = _stream()
    batches[2] = replace(batches[2], merkle_root=bytes(32))

    report = build_report(chain, batches, GENESIS_HASH, RULES)

    assert [(f.check, f.batch_index) for f in report.findings] == [("MERKLE_ROOT", 3)]


def test_gap_between_batches_and_wrong_leaf_count_are_range_failures() -> None:
    chain, batches = _stream()
    shrunk = replace(
        batches[1],
        last_chain_index=7,
        leaf_count=3,
        merkle_root=merkle_root([c.entry_hash for c in chain[4:7]]),
    )
    batches[1] = shrunk  # batch 3 now starts at 9 but 8 is uncovered
    bad_count = replace(batches[3], leaf_count=99)
    batches[3] = bad_count

    report = build_report(chain, batches, GENESIS_HASH, RULES)

    range_failures = {f.batch_index: f.actual for f in report.findings if f.check == "MERKLE_RANGE"}
    assert set(range_failures) == {3, 4}
    assert "starts at 9, expected 8" in range_failures[3]
    assert "leaf_count 99" in range_failures[4]


def test_deleted_whole_batch_is_detected() -> None:
    """Paper §VI-D: because the chain continues across batches, removing a batch breaks it."""
    chain, batches = _stream()
    tampered = chain[:4] + chain[8:]
    remaining = [batches[0], *batches[2:]]

    report = build_report(tampered, remaining, GENESIS_HASH, RULES)

    assert report.first_failure is not None
    assert report.first_failure.chain_index == 9
    assert {"CHAIN_LINK", "MERKLE_RANGE"} <= {f.check for f in report.findings}


def test_batch_with_no_remaining_records_reports_missing_root() -> None:
    chain, batches = _stream()

    report = build_report(chain[:4], batches[:2], GENESIS_HASH, RULES)

    root = [f for f in report.findings if f.check == "MERKLE_ROOT"]
    assert root and root[0].expected == "<no records>"
