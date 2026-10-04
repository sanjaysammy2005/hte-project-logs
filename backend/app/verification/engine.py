"""Verification engine (paper §VI-E; docs/VERIFICATION.md §6).

"The engine reads the stored records in order, recomputes each chain value, re-applies the
provenance checks and rebuilds the Merkle root of each batch." The result is VALID, or
TAMPERING_DETECTED with the batch identifier, the first failing record and the failed check.

``build_report`` is pure (plain data in, report out); ``verify_stream`` loads from and saves
to the database around it.
"""

import bisect
import time
import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.chain import ChainCheck, ChainedRecord, verify_chain
from app.crypto.merkle import MerkleCheck, merkle_root
from app.db.models import AuditEvent, Batch, LogStream, VerificationFinding, VerificationRun
from app.ingestion.service import to_chained
from app.provenance.checks import ProvenanceCheck, check_provenance
from app.provenance.rules import TransitionRules

# Global check order, used to break ties between findings on the same record (§6.1).
CHECK_ORDER = [*ChainCheck, *ProvenanceCheck, *MerkleCheck]
_RANK = {str(c): i for i, c in enumerate(CHECK_ORDER)}
MAX_STORED_FINDINGS = 1000


@dataclass(frozen=True)
class BatchRecord:
    id: uuid.UUID
    batch_index: int
    first_chain_index: int
    last_chain_index: int
    leaf_count: int
    merkle_root: bytes


@dataclass(frozen=True)
class Finding:
    chain_index: int | None
    batch_id: uuid.UUID | None
    batch_index: int | None
    check: str
    expected: str
    actual: str


@dataclass(frozen=True)
class Report:
    status: str
    findings: tuple[Finding, ...]
    failed_by_check: dict[str, int]
    records_checked: int
    batches_checked: int
    unbatched_records: int
    cascade_affected_records: int
    rules_version: str
    duration_ms: float
    first_failure: Finding | None
    # Wall-clock milliseconds per check family (time.perf_counter), for the experiments.
    timings_ms: dict[str, float]


def _first_failure(findings: Sequence[Finding], batches: Sequence[BatchRecord]) -> Finding | None:
    """Earliest record-level finding, or earliest batch finding not explained by one.

    A batch finding is explained when a record-level finding lies inside that batch's range:
    the record is then the more precise location of the change.
    """
    merkle = {str(c) for c in MerkleCheck}
    by_id = {b.id: b for b in batches}
    record_level = [f for f in findings if f.check not in merkle]
    candidates = list(record_level)
    for f in findings:
        if f.check in merkle:
            b = by_id[f.batch_id]  # type: ignore[index]
            explained = any(
                b.first_chain_index <= (r.chain_index or 0) <= b.last_chain_index
                for r in record_level
            )
            if not explained:
                candidates.append(f)
    return min(
        candidates,
        key=lambda f: (f.chain_index if f.chain_index is not None else 0, _RANK[f.check]),
        default=None,
    )


def _batch_lookup(batches: Sequence[BatchRecord]):
    ordered = sorted(batches, key=lambda b: b.first_chain_index)
    starts = [b.first_chain_index for b in ordered]

    def find(chain_index: int) -> BatchRecord | None:
        i = bisect.bisect_right(starts, chain_index) - 1
        if i >= 0 and ordered[i].last_chain_index >= chain_index:
            return ordered[i]
        return None

    return find


def _merkle_findings(
    leaves: Sequence[tuple[int, bytes | None]], batches: Sequence[BatchRecord]
) -> list[Finding]:
    """Check each sealed batch against leaves rebuilt from recomputed entry hashes.

    ``leaves`` holds (chain_index, recomputed H_n or None if unencodable). Using recomputed
    rather than stored hashes means a record modified without updating its stored hash still
    changes the batch root, as paper Table IV states (docs/VERIFICATION.md §5.2).
    """
    ordered = sorted(leaves, key=lambda leaf: leaf[0])
    indices = [index for index, _ in ordered]
    findings: list[Finding] = []
    expected_first = 1
    for b in sorted(batches, key=lambda b: b.batch_index):
        lo = bisect.bisect_left(indices, b.first_chain_index)
        hi = bisect.bisect_right(indices, b.last_chain_index)
        in_range = [h for _, h in ordered[lo:hi]]
        problems = []
        if b.first_chain_index != expected_first:
            problems.append(f"starts at {b.first_chain_index}, expected {expected_first}")
        if b.leaf_count != b.last_chain_index - b.first_chain_index + 1:
            problems.append(f"leaf_count {b.leaf_count} does not match its range")
        if len(in_range) != b.leaf_count:
            problems.append(f"{len(in_range)} records present for {b.leaf_count} leaves")
        if problems:
            findings.append(
                Finding(
                    b.first_chain_index,
                    b.id,
                    b.batch_index,
                    str(MerkleCheck.MERKLE_RANGE),
                    f"{b.leaf_count} contiguous records",
                    "; ".join(problems),
                )
            )
        if not in_range:
            expected = "<no records>"
        elif any(h is None for h in in_range):
            expected = "<unencodable record in batch>"
        else:
            expected = merkle_root([h for h in in_range if h is not None]).hex()
        if expected != b.merkle_root.hex():
            findings.append(
                Finding(
                    b.first_chain_index,
                    b.id,
                    b.batch_index,
                    str(MerkleCheck.MERKLE_ROOT),
                    expected,
                    b.merkle_root.hex(),
                )
            )
        expected_first = b.last_chain_index + 1
    return findings


def build_report(
    records: Sequence[ChainedRecord],
    batches: Sequence[BatchRecord],
    genesis_hash: bytes,
    rules: TransitionRules,
) -> Report:
    """Run chain, provenance and Merkle checks over records ordered by chain_index."""
    started = time.perf_counter()
    find_batch = _batch_lookup(batches)

    t0 = time.perf_counter()
    chain = verify_chain(records, genesis_hash)
    t1 = time.perf_counter()
    provenance = check_provenance(records, rules)
    t2 = time.perf_counter()
    raw: list[Finding] = []
    for f in [*chain.findings, *provenance.findings]:
        batch = find_batch(f.chain_index)
        raw.append(
            Finding(
                f.chain_index,
                batch.id if batch else None,
                batch.batch_index if batch else None,
                str(f.check),
                f.expected,
                f.actual,
            )
        )
    leaves = [(r.chain_index, h) for r, h in zip(records, chain.recomputed_hashes, strict=True)]
    raw.extend(_merkle_findings(leaves, batches))
    t3 = time.perf_counter()
    raw.sort(key=lambda f: (f.chain_index if f.chain_index is not None else 0, _RANK[f.check]))

    last_sealed = max((b.last_chain_index for b in batches), default=0)
    return Report(
        status="TAMPERING_DETECTED" if raw else "VALID",
        findings=tuple(raw),
        failed_by_check=dict(Counter(f.check for f in raw)),
        records_checked=len(records),
        batches_checked=len(batches),
        unbatched_records=sum(1 for r in records if r.chain_index > last_sealed),
        cascade_affected_records=chain.cascade_affected_records,
        rules_version=rules.identifier,
        duration_ms=(time.perf_counter() - started) * 1000,
        first_failure=_first_failure(raw, batches),
        timings_ms={
            "chain": (t1 - t0) * 1000,
            "provenance": (t2 - t1) * 1000,
            "merkle": (t3 - t2) * 1000,
        },
    )


def load_stream(db: Session, stream: LogStream) -> tuple[list[ChainedRecord], list[BatchRecord]]:
    rows = db.scalars(
        select(AuditEvent).where(AuditEvent.stream_id == stream.id).order_by(AuditEvent.chain_index)
    )
    batches = db.scalars(select(Batch).where(Batch.stream_id == stream.id))
    return [to_chained(r) for r in rows], [
        BatchRecord(
            b.id,
            b.batch_index,
            b.first_chain_index,
            b.last_chain_index,
            b.leaf_count,
            bytes(b.merkle_root),
        )
        for b in batches
    ]


def verify_stream(
    db: Session, stream: LogStream, rules: TransitionRules, triggered_by: uuid.UUID | None = None
) -> tuple[VerificationRun, Report]:
    """Verify a stored stream and persist the run. The caller must commit."""
    started_at = datetime.now(UTC)
    t0 = time.perf_counter()
    records, batches = load_stream(db, stream)
    report = build_report(records, batches, bytes(stream.genesis_hash), rules)
    total_ms = (time.perf_counter() - t0) * 1000  # includes reading from the database
    first = report.first_failure

    run = VerificationRun(
        stream_id=stream.id,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        duration_ms=total_ms,
        status=report.status,
        first_failing_batch_id=first.batch_id if first else None,
        first_failing_chain_index=first.chain_index if first else None,
        first_failed_check=first.check if first else None,
        records_checked=report.records_checked,
        unbatched_records=report.unbatched_records,
        rules_version=report.rules_version,
        triggered_by=triggered_by,
        report={
            "failed_by_check": report.failed_by_check,
            "findings_total": len(report.findings),
            "batches_checked": report.batches_checked,
            "cascade_affected_records": report.cascade_affected_records,
            "check_duration_ms": report.duration_ms,
            "hash_scheme": stream.hash_scheme,
            "merkle_scheme": stream.merkle_scheme,
            "first_failure_batch_index": first.batch_index if first else None,
        },
    )
    db.add(run)
    db.flush()
    db.add_all(
        VerificationFinding(
            run_id=run.id,
            chain_index=f.chain_index,
            batch_id=f.batch_id,
            check_name=f.check,
            expected=f.expected,
            actual=f.actual,
        )
        for f in report.findings[:MAX_STORED_FINDINGS]
    )
    db.flush()
    return run, report
