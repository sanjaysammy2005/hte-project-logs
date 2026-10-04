"""SHA-256 hash chain over context-enriched audit records (paper §VI-B, Eq. 1).

    H_n = SHA-256( enc(E_n) || enc(C_n) || H_{n-1} ),    H_0 = 32 zero bytes

Verification checks each record against its *stored* predecessor hash and its own *stored*
hash, so a single change is reported where it happened instead of at every later record
(docs/VERIFICATION.md §6.2). The cascade count still shows how many stored chain values a
full recomputation from H_0 would disagree with.
"""

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from app.crypto.canonical import AuditRecord, CanonicalizationError, encode_context, encode_event

HASH_SCHEME = "tl-v1"
HASH_LENGTH = 32
# Fixed genesis value H_0 [Paper §VI-B: "a fixed genesis value"; value decided in Q4].
GENESIS_HASH = bytes(HASH_LENGTH)


class ChainCheck(StrEnum):
    """Chain checks, in the order they are applied to each record."""

    CHAIN_INDEX_CONTINUITY = "CHAIN_INDEX_CONTINUITY"
    CHAIN_LINK = "CHAIN_LINK"
    CHAIN_HASH = "CHAIN_HASH"


@dataclass(frozen=True)
class ChainedRecord:
    """An audit record together with its position and stored chain values."""

    chain_index: int
    record: AuditRecord
    prev_hash: bytes
    entry_hash: bytes


@dataclass(frozen=True)
class ChainFinding:
    """One failed check. ``expected`` is what the verifier derived; ``actual`` is what is stored."""

    position: int  # 1-based position in the sequence that was verified
    chain_index: int  # chain_index stored on the record
    check: ChainCheck
    expected: str
    actual: str


@dataclass(frozen=True)
class ChainVerificationResult:
    records_checked: int
    findings: tuple[ChainFinding, ...]
    cascade_affected_records: int
    # H_n recomputed from each record's stored content and stored prev_hash, in sequence
    # order (None where the record cannot be encoded). Merkle roots are rebuilt from these.
    recomputed_hashes: tuple[bytes | None, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.findings

    @property
    def first_failure(self) -> ChainFinding | None:
        return self.findings[0] if self.findings else None


def hash_input(record: AuditRecord, prev_hash: bytes) -> bytes:
    """The exact bytes that are hashed: enc(E_n) || enc(C_n) || H_{n-1}."""
    if not isinstance(prev_hash, bytes) or len(prev_hash) != HASH_LENGTH:
        raise CanonicalizationError(f"previous hash must be exactly {HASH_LENGTH} bytes")
    return encode_event(record) + encode_context(record) + prev_hash


def compute_entry_hash(record: AuditRecord, prev_hash: bytes) -> bytes:
    return hashlib.sha256(hash_input(record, prev_hash)).digest()


def build_chain(
    records: Iterable[AuditRecord], genesis_hash: bytes = GENESIS_HASH
) -> list[ChainedRecord]:
    """Chain records in the given order, assigning chain_index 1, 2, 3, ..."""
    chained: list[ChainedRecord] = []
    prev_hash = genesis_hash
    for index, record in enumerate(records, start=1):
        entry_hash = compute_entry_hash(record, prev_hash)
        chained.append(ChainedRecord(index, record, prev_hash, entry_hash))
        prev_hash = entry_hash
    return chained


def rehash(item: ChainedRecord, prev_hash: bytes | None = None) -> ChainedRecord:
    """Return ``item`` with a freshly computed entry hash (optionally with a new prev_hash).

    Used by tests and the tamper lab to model an attacker who recomputes hashes.
    """
    new_prev = item.prev_hash if prev_hash is None else prev_hash
    return replace(item, prev_hash=new_prev, entry_hash=compute_entry_hash(item.record, new_prev))


def verify_chain(
    records: Sequence[ChainedRecord], genesis_hash: bytes = GENESIS_HASH
) -> ChainVerificationResult:
    """Check index continuity, predecessor links and recomputed hashes, in sequence order.

    ``records`` must be in the order being verified (by chain_index when read from storage).
    Tampered content that cannot even be encoded is reported as a CHAIN_HASH failure rather
    than raising, so verification always produces a report.
    """
    findings: list[ChainFinding] = []
    prev_index = 0
    prev_stored_hash = genesis_hash
    cascade_hash: bytes | None = genesis_hash
    cascade_affected = 0
    recomputed_hashes: list[bytes | None] = []

    for position, item in enumerate(records, start=1):
        failures: list[tuple[ChainCheck, str, str]] = []

        if item.chain_index != prev_index + 1:
            failures.append(
                (ChainCheck.CHAIN_INDEX_CONTINUITY, str(prev_index + 1), str(item.chain_index))
            )

        if item.prev_hash != prev_stored_hash:
            failures.append((ChainCheck.CHAIN_LINK, prev_stored_hash.hex(), item.prev_hash.hex()))

        try:
            recomputed = compute_entry_hash(item.record, item.prev_hash)
        except CanonicalizationError as exc:
            failures.append(
                (ChainCheck.CHAIN_HASH, f"<unencodable record: {exc}>", item.entry_hash.hex())
            )
            cascade_hash = None
            recomputed_hashes.append(None)
        else:
            recomputed_hashes.append(recomputed)
            if recomputed != item.entry_hash:
                failures.append((ChainCheck.CHAIN_HASH, recomputed.hex(), item.entry_hash.hex()))
            if cascade_hash is not None:
                cascade_hash = compute_entry_hash(item.record, cascade_hash)

        findings.extend(
            ChainFinding(position, item.chain_index, check, expected, actual)
            for check, expected, actual in failures
        )

        if cascade_hash is None or cascade_hash != item.entry_hash:
            cascade_affected += 1

        prev_index = item.chain_index
        prev_stored_hash = item.entry_hash

    return ChainVerificationResult(
        len(records), tuple(findings), cascade_affected, tuple(recomputed_hashes)
    )
