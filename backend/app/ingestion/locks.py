"""Per-stream serialisation via PostgreSQL transaction-scoped advisory locks."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session


def stream_lock_key(stream_id: uuid.UUID) -> int:
    return int.from_bytes(stream_id.bytes[:8], "big", signed=True)


def lock_stream(db: Session, stream_id: uuid.UUID) -> None:
    """Block until this transaction holds the stream's lock (released at commit/rollback)."""
    db.execute(select(func.pg_advisory_xact_lock(stream_lock_key(stream_id))))
