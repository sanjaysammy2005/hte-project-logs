"""Seal contiguous ranges of a stream into Merkle batches (paper §VI-D, Q10).

Sealing takes the same per-stream advisory lock as ingestion (re-entrant within one
transaction), so batches can never overlap. The caller owns the transaction and must commit.
"""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.crypto.merkle import membership_proof, merkle_root
from app.db.models import AuditEvent, Batch, LogStream
from app.ingestion.locks import lock_stream


class StreamInconsistentError(Exception):
    """Stored records are not contiguous, so they must not be sealed or proven."""


def latest_batch(db: Session, stream: LogStream) -> Batch | None:
    return db.scalars(
        select(Batch).where(Batch.stream_id == stream.id).order_by(Batch.batch_index.desc())
    ).first()


def _leaves(db: Session, stream: LogStream, first: int, last: int) -> list[bytes]:
    rows = db.scalars(
        select(AuditEvent.entry_hash)
        .where(
            AuditEvent.stream_id == stream.id,
            AuditEvent.chain_index >= first,
            AuditEvent.chain_index <= last,
        )
        .order_by(AuditEvent.chain_index)
    )
    leaves = [bytes(h) for h in rows]
    if len(leaves) != last - first + 1:
        raise StreamInconsistentError(f"records {first}-{last} are not contiguous")
    return leaves


def seal_batches(db: Session, stream: LogStream, include_partial: bool = False) -> list[Batch]:
    """Seal every full batch of unsealed records (and the remainder if ``include_partial``)."""
    lock_stream(db, stream.id)
    previous = latest_batch(db, stream)
    first = previous.last_chain_index + 1 if previous else 1
    batch_index = previous.batch_index + 1 if previous else 1
    head = (
        db.scalar(select(func.max(AuditEvent.chain_index)).where(AuditEvent.stream_id == stream.id))
        or 0
    )

    created: list[Batch] = []
    while first + stream.batch_size - 1 <= head or (include_partial and first <= head):
        last = min(first + stream.batch_size - 1, head)
        batch = Batch(
            stream_id=stream.id,
            batch_index=batch_index,
            first_chain_index=first,
            last_chain_index=last,
            leaf_count=last - first + 1,
            merkle_root=merkle_root(_leaves(db, stream, first, last)),
        )
        db.add(batch)
        created.append(batch)
        first, batch_index = last + 1, batch_index + 1
    db.flush()
    return created


def batch_for(db: Session, stream: LogStream, chain_index: int) -> Batch | None:
    return db.scalars(
        select(Batch).where(
            Batch.stream_id == stream.id,
            Batch.first_chain_index <= chain_index,
            Batch.last_chain_index >= chain_index,
        )
    ).first()


def proof_for(db: Session, stream: LogStream, batch: Batch, chain_index: int):
    """(leaf, proof) for a record inside ``batch``."""
    leaves = _leaves(db, stream, batch.first_chain_index, batch.last_chain_index)
    position = chain_index - batch.first_chain_index
    return leaves[position], membership_proof(leaves, position)
