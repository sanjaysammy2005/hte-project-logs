"""Three-layer file integrity check (ZERO_TRUST_FILE_MODULE §12.2).

    L1 content   blob bytes            ⇄ file_versions.sha256 / size_bytes
    L2 anchor    file_versions.sha256  ⇄ sha256 recorded in the chained event that created it
    L3 evidence  that chained event    ⇄ its own entry hash, its predecessor's and successor's
                                         links and (if sealed) its Merkle batch root

L1 alone can be fooled by someone who replaces a blob *and* updates its stored hash; L2 catches
that because the original hash is inside the hash chain; L3 catches an edit of the anchoring
event itself. A full consistent rewrite of the chain and roots (paper §IX-B) defeats all three.
SHA-256 makes changes evident; it does not prevent them.
"""

import hashlib
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.access.model import IntegrityStatus
from app.batching.service import StreamInconsistentError, batch_for, proof_for
from app.crypto.canonical import CanonicalizationError
from app.crypto.chain import compute_entry_hash
from app.crypto.merkle import verify_proof
from app.db.models import AuditEvent, File, FileVersion, LogStream
from app.files.storage import BlobNotFoundError, InvalidStorageKeyError, StorageBackend
from app.ingestion.service import to_chained

OK = "OK"


class IntegrityFailure(Exception):
    def __init__(self, status: IntegrityStatus, actual_sha256: str | None = None) -> None:
        super().__init__(status.value)
        self.status = status
        self.actual_sha256 = actual_sha256


@dataclass(frozen=True)
class VersionIntegrity:
    version: int
    status: IntegrityStatus
    content: str  # OK or the L1 failure
    anchor: str  # OK or the L2 failure
    evidence: str  # OK or the L3 failure
    expected_sha256: str
    actual_sha256: str | None
    anchor_chain_index: int


def read_verified(storage: StorageBackend, version: FileVersion) -> bytes:
    """Return the version's bytes only if they match the stored SHA-256 and size (L1).

    At most size_bytes + 1 bytes are read, so a blob that was inflated on disk cannot exhaust
    memory. The bytes returned are exactly the bytes that were hashed (no re-read, no TOCTOU).
    """
    try:
        with storage.open(version.storage_key) as blob:
            data = blob.read(version.size_bytes + 1)
    except (BlobNotFoundError, InvalidStorageKeyError) as exc:
        raise IntegrityFailure(IntegrityStatus.BLOB_MISSING) from exc
    actual = hashlib.sha256(data).digest()
    if len(data) != version.size_bytes or actual != bytes(version.sha256):
        raise IntegrityFailure(IntegrityStatus.CONTENT_MISMATCH, actual.hex())
    return data


def _anchor(db: Session, version: FileVersion) -> AuditEvent | None:
    return db.scalars(
        select(AuditEvent).where(
            AuditEvent.stream_id == version.audit_stream_id,
            AuditEvent.chain_index == version.audit_chain_index,
        )
    ).first()


def _evidence_ok(db: Session, event: AuditEvent) -> bool:
    try:
        recomputed = compute_entry_hash(to_chained(event).record, bytes(event.prev_hash))
    except CanonicalizationError:
        return False
    if recomputed != bytes(event.entry_hash):
        return False
    stream = db.get(LogStream, event.stream_id)
    if stream is None:
        return False
    if event.chain_index == 1:
        predecessor_hash = bytes(stream.genesis_hash)
    else:
        predecessor = db.scalars(
            select(AuditEvent.entry_hash).where(
                AuditEvent.stream_id == event.stream_id,
                AuditEvent.chain_index == event.chain_index - 1,
            )
        ).first()
        if predecessor is None:
            return False
        predecessor_hash = bytes(predecessor)
    if bytes(event.prev_hash) != predecessor_hash:
        return False
    # An attacker who edits the event and recomputes its own hash (A1) breaks the *next*
    # record's link; check it so this is caught even before the event is sealed in a batch.
    successor = db.scalars(
        select(AuditEvent.prev_hash).where(
            AuditEvent.stream_id == event.stream_id,
            AuditEvent.chain_index == event.chain_index + 1,
        )
    ).first()
    if successor is not None and bytes(successor) != bytes(event.entry_hash):
        return False
    batch = batch_for(db, stream, event.chain_index)
    if batch is None:
        return True  # not sealed yet: protected by the chain only (VERIFICATION §5.2)
    try:
        _, proof = proof_for(db, stream, batch, event.chain_index)
    except StreamInconsistentError:
        return False
    return verify_proof(recomputed, proof, bytes(batch.merkle_root))


def check_version(
    db: Session, storage: StorageBackend, file: File, version: FileVersion
) -> VersionIntegrity:
    expected = bytes(version.sha256).hex()
    actual: str | None = expected
    try:
        read_verified(storage, version)
        content = OK
    except IntegrityFailure as failure:
        content, actual = failure.status.value, failure.actual_sha256

    event = _anchor(db, version)
    if event is None:
        anchor, evidence = (
            IntegrityStatus.ANCHOR_MISSING.value,
            IntegrityStatus.ANCHOR_MISSING.value,
        )
    else:
        p = event.event_payload or {}
        matches = (
            p.get("file_id") == str(file.id)
            and p.get("version") == version.version_number
            and p.get("sha256") == expected
        )
        anchor = OK if matches else IntegrityStatus.METADATA_MISMATCH.value
        evidence = OK if _evidence_ok(db, event) else IntegrityStatus.ANCHOR_TAMPERED.value

    status = next(
        (IntegrityStatus(s) for s in (content, anchor, evidence) if s != OK), IntegrityStatus.INTACT
    )
    return VersionIntegrity(
        version=version.version_number,
        status=status,
        content=content,
        anchor=anchor,
        evidence=evidence,
        expected_sha256=expected,
        actual_sha256=actual,
        anchor_chain_index=version.audit_chain_index,
    )
