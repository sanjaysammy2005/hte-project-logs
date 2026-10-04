"""SQLAlchemy models for Phase 5 (docs/DATABASE.md §3.1–3.3).

audit_events is append-only by design: the application never UPDATEs or DELETEs its rows.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

ROLES = ("admin", "auditor", "ingestor")
STREAM_KINDS = ("primary", "synthetic", "lab")
SYSTEM_STREAM_NAME = "system"


class Operator(Base):
    """A TraceLock dashboard/API account (not an audited user inside events)."""

    __tablename__ = "operators"
    __table_args__ = (CheckConstraint(f"role IN {ROLES}", name="role_valid"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class LogStream(Base):
    """An independent hash chain with its own genesis, indices and batches."""

    __tablename__ = "log_streams"
    __table_args__ = (CheckConstraint(f"kind IN {STREAM_KINDS}", name="kind_valid"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, unique=True)
    kind: Mapped[str] = mapped_column(Text)
    source_stream_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("log_streams.id"))
    genesis_hash: Mapped[bytes] = mapped_column(LargeBinary)
    hash_scheme: Mapped[str] = mapped_column(Text)
    merkle_scheme: Mapped[str] = mapped_column(Text)
    batch_size: Mapped[int] = mapped_column(Integer)
    generator_seed: Mapped[int | None] = mapped_column(BigInteger)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditEvent(Base):
    """A context-enriched, hash-chained audit record (paper Table III + Eq. 1)."""

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("stream_id", "chain_index"),
        CheckConstraint(
            "octet_length(prev_hash) = 32 AND octet_length(entry_hash) = 32", name="hash_length"
        ),
        CheckConstraint("(session_id IS NULL) = (session_seq IS NULL)", name="session_seq_pair"),
        Index(
            "uq_audit_events_session_seq",
            "stream_id",
            "session_id",
            "session_seq",
            unique=True,
            postgresql_where=text("session_id IS NOT NULL"),
        ),
        Index("ix_audit_events_actor", "stream_id", "actor_user_id"),
        Index("ix_audit_events_timestamp", "stream_id", "event_timestamp"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    stream_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("log_streams.id"))
    chain_index: Mapped[int] = mapped_column(BigInteger)
    event_type: Mapped[str] = mapped_column(Text)
    event_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'"))
    actor_user_id: Mapped[str | None] = mapped_column(Text)
    session_id: Mapped[str | None] = mapped_column(Text)
    prev_event_type: Mapped[str | None] = mapped_column(Text)
    session_seq: Mapped[int | None] = mapped_column(Integer)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary)
    entry_hash: Mapped[bytes] = mapped_column(LargeBinary)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Batch(Base):
    """A sealed Merkle batch over a contiguous chain-index range (paper §VI-D)."""

    __tablename__ = "batches"
    __table_args__ = (
        UniqueConstraint("stream_id", "batch_index"),
        CheckConstraint(
            "leaf_count = last_chain_index - first_chain_index + 1", name="leaf_count_matches"
        ),
        CheckConstraint("octet_length(merkle_root) = 32", name="root_length"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    stream_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("log_streams.id"))
    batch_index: Mapped[int] = mapped_column(Integer)
    first_chain_index: Mapped[int] = mapped_column(BigInteger)
    last_chain_index: Mapped[int] = mapped_column(BigInteger)
    leaf_count: Mapped[int] = mapped_column(Integer)
    merkle_root: Mapped[bytes] = mapped_column(LargeBinary)
    sealed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VerificationRun(Base):
    """A stored verification report (paper §VI-E: status, batch id, first failing record, check)."""

    __tablename__ = "verification_runs"
    __table_args__ = (
        CheckConstraint("status IN ('VALID', 'TAMPERING_DETECTED', 'ERROR')", name="status_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    stream_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("log_streams.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(Text)
    # Not a foreign key: a run must survive even if an attacker deletes the batch row.
    first_failing_batch_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    first_failing_chain_index: Mapped[int | None] = mapped_column(BigInteger)
    first_failed_check: Mapped[str | None] = mapped_column(Text)
    records_checked: Mapped[int] = mapped_column(BigInteger)
    unbatched_records: Mapped[int] = mapped_column(BigInteger)
    rules_version: Mapped[str] = mapped_column(Text)
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL")
    )
    report: Mapped[dict[str, Any]] = mapped_column(JSONB)


class VerificationFinding(Base):
    __tablename__ = "verification_findings"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("verification_runs.id", ondelete="CASCADE"), index=True
    )
    chain_index: Mapped[int | None] = mapped_column(BigInteger)
    batch_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    check_name: Mapped[str] = mapped_column(Text)
    expected: Mapped[str] = mapped_column(Text)
    actual: Mapped[str] = mapped_column(Text)


class TamperScenario(Base):
    """A controlled tampering experiment on a cloned lab stream (EXPERIMENTS §3).

    The expected outcome and ground truth are stored before the tampering is verified.
    """

    __tablename__ = "tamper_scenarios"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scenario_type: Mapped[str] = mapped_column(Text)
    attacker_model: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    source_stream_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("log_streams.id"))
    lab_stream_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("log_streams.id"))
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB)
    expected_detected: Mapped[bool] = mapped_column(Boolean)
    # Ground truth: the first stored record affected by the tampering (None if not applicable).
    true_first_index: Mapped[int | None] = mapped_column(BigInteger)
    verification_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("verification_runs.id", ondelete="SET NULL")
    )
    actual_detected: Mapped[bool | None] = mapped_column(Boolean)
    first_failure_index: Mapped[int | None] = mapped_column(BigInteger)
    first_failure_check: Mapped[str | None] = mapped_column(Text)
    located_correctly: Mapped[bool | None] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExperimentRun(Base):
    """One execution of the experiment matrix (EXPERIMENTS §5). Summary is NULL until measured."""

    __tablename__ = "experiment_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')", name="status_valid"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)
    environment: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_results: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
