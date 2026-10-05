"""SQLAlchemy models (docs/DATABASE.md §3; file module: docs/ZERO_TRUST_FILE_MODULE.md §5).

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
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.access.model import Classification, FileOrigin, IntegrityStatus, Permission, Role
from app.db.base import Base

# manager and employee are file-platform users (ZERO_TRUST_FILE_MODULE §8, Z16).
ROLES = tuple(r.value for r in Role)
STREAM_KINDS = ("primary", "synthetic", "lab")
SYSTEM_STREAM_NAME = "system"


class Operator(Base):
    """A TraceLock dashboard/API account (not an audited user inside events)."""

    __tablename__ = "operators"
    __table_args__ = (
        CheckConstraint(f"role IN {ROLES}", name="role_valid"),
        CheckConstraint("char_length(display_name) BETWEEN 1 AND 128", name="display_name_length"),
        CheckConstraint("char_length(department) BETWEEN 1 AND 128", name="department_length"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    display_name: Mapped[str | None] = mapped_column(Text)
    department: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


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
        # File module: history of one file, and per-type counts/windows (indexes only; the
        # hashed columns are unchanged).
        Index(
            "ix_audit_events_file_id",
            text("stream_id"),
            text("(event_payload ->> 'file_id')"),
            postgresql_where=text("(event_payload ->> 'file_id') IS NOT NULL"),
        ),
        Index("ix_audit_events_type_time", "stream_id", "event_type", "event_timestamp"),
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


# --- File module (docs/ZERO_TRUST_FILE_MODULE.md §5) ------------------------------------------
#
# These tables hold *current state* and are mutable. The evidence of every change will be a
# chained audit event; rows keep an audit reference (stream id + chain index) without a foreign
# key, like verification_runs, so the reference survives tampering and can be cross-checked.

CLASSIFICATIONS = tuple(c.value for c in Classification)
FILE_ORIGINS = tuple(o.value for o in FileOrigin)
PERMISSIONS = tuple(p.value for p in Permission)
INTEGRITY_STATUSES = tuple(s.value for s in IntegrityStatus)
_PERMISSIONS_ARRAY = "ARRAY[" + ", ".join(f"'{p}'" for p in PERMISSIONS) + "]::text[]"


class File(Base):
    """A logical document. Its contents live in immutable ``file_versions``."""

    __tablename__ = "files"
    __table_args__ = (
        CheckConstraint(f"classification IN {CLASSIFICATIONS}", name="classification_valid"),
        CheckConstraint(f"origin IN {FILE_ORIGINS}", name="origin_valid"),
        CheckConstraint("octet_length(display_name) BETWEEN 1 AND 255", name="display_name_length"),
        CheckConstraint("extension ~ '^[a-z0-9]{1,10}$'", name="extension_format"),
        CheckConstraint("char_length(description) <= 1000", name="description_length"),
        CheckConstraint("char_length(department) BETWEEN 1 AND 128", name="department_length"),
        CheckConstraint("current_version >= 1", name="current_version_positive"),
        CheckConstraint("(deleted_at IS NULL) = (deleted_by IS NULL)", name="deleted_pair"),
        CheckConstraint("purged_at IS NULL OR deleted_at IS NOT NULL", name="purge_after_delete"),
        Index("ix_files_owner_id", "owner_id"),
        Index("ix_files_created_by", "created_by"),
        Index("ix_files_classification", "classification"),
        Index("ix_files_created_at", "created_at"),
        Index("ix_files_updated_at", "updated_at"),
        Index("ix_files_origin", "origin"),
        Index("ix_files_department", "department"),
        Index("ix_files_deleted_at", "deleted_at", postgresql_where=text("deleted_at IS NOT NULL")),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    display_name: Mapped[str] = mapped_column(Text)
    extension: Mapped[str] = mapped_column(Text)
    mime_type: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("operators.id", ondelete="RESTRICT"))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("operators.id", ondelete="RESTRICT"))
    current_version: Mapped[int] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(Text, server_default=text("'user'"))
    # The uploader's department at creation; scopes department-limited role access (Z20).
    department: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT")
    )
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Sorting convenience only; the authoritative access history is the audit chain.
    last_accessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    versions: Mapped[list["FileVersion"]] = relationship(
        back_populates="file", order_by="FileVersion.version_number"
    )
    permissions: Mapped[list["FilePermission"]] = relationship(back_populates="file")


class FileVersion(Base):
    """Immutable content version. The application never UPDATEs these rows, except the two
    integrity-cache columns, which are explicitly untrusted."""

    __tablename__ = "file_versions"
    __table_args__ = (
        UniqueConstraint("file_id", "version_number"),
        CheckConstraint("version_number >= 1", name="version_number_positive"),
        CheckConstraint("storage_key ~ '^[0-9a-f]{32}$'", name="storage_key_format"),
        CheckConstraint("octet_length(sha256) = 32", name="sha256_length"),
        CheckConstraint("size_bytes >= 0", name="size_non_negative"),
        CheckConstraint(
            "octet_length(original_filename) BETWEEN 1 AND 255", name="original_filename_length"
        ),
        CheckConstraint("char_length(change_reason) <= 500", name="change_reason_length"),
        CheckConstraint(
            "restored_from_version IS NULL"
            " OR (restored_from_version >= 1 AND restored_from_version < version_number)",
            name="restored_from_earlier",
        ),
        CheckConstraint("audit_chain_index >= 1", name="audit_chain_index_positive"),
        CheckConstraint(
            f"last_integrity_status IS NULL OR last_integrity_status IN {INTEGRITY_STATUSES}",
            name="integrity_status_valid",
        ),
        Index("ix_file_versions_uploaded_by", "uploaded_by"),
        Index("ix_file_versions_storage_key", "storage_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("files.id", ondelete="RESTRICT"))
    version_number: Mapped[int] = mapped_column(Integer)
    # Never returned by the API (see app/files/schemas.py).
    storage_key: Mapped[str] = mapped_column(Text)
    sha256: Mapped[bytes] = mapped_column(LargeBinary)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    mime_type: Mapped[str] = mapped_column(Text)
    original_filename: Mapped[str] = mapped_column(Text)
    uploaded_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("operators.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    change_reason: Mapped[str | None] = mapped_column(Text)
    restored_from_version: Mapped[int | None] = mapped_column(Integer)
    # The chained event that created this version. Not a foreign key, on purpose (see above).
    audit_stream_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    audit_chain_index: Mapped[int] = mapped_column(BigInteger)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_integrity_status: Mapped[str | None] = mapped_column(Text)

    file: Mapped[File] = relationship(back_populates="versions")


class FilePermission(Base):
    """An explicit grant (a "share") of permissions on one file to one user.

    Grants are never edited: changing one means revoking it and creating a new one, so the
    history stays complete. At most one active (unrevoked) grant per user per file.
    """

    __tablename__ = "file_permissions"
    __table_args__ = (
        CheckConstraint(
            f"cardinality(permissions) >= 1 AND permissions <@ {_PERMISSIONS_ARRAY}",
            name="permissions_valid",
        ),
        CheckConstraint(
            "NOT (permissions && ARRAY['CREATE', 'MANAGE_PERMISSIONS']::text[])",
            name="permissions_grantable",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at", name="expires_after_created"
        ),
        CheckConstraint("(revoked_at IS NULL) = (revoked_by IS NULL)", name="revoked_pair"),
        CheckConstraint("char_length(reason) <= 500", name="reason_length"),
        CheckConstraint("audit_chain_index >= 1", name="audit_chain_index_positive"),
        CheckConstraint("num_nonnulls(grantee_id, grantee_role) = 1", name="one_target"),
        CheckConstraint(
            f"grantee_role IS NULL OR grantee_role IN {ROLES}", name="grantee_role_valid"
        ),
        Index(
            "uq_file_permissions_active_role_grant",
            "file_id",
            "grantee_role",
            unique=True,
            postgresql_where=text("revoked_at IS NULL AND grantee_role IS NOT NULL"),
        ),
        Index(
            "uq_file_permissions_active_grant",
            "file_id",
            "grantee_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
        Index("ix_file_permissions_file_id", "file_id"),
        Index(
            "ix_file_permissions_grantee_active",
            "grantee_id",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("files.id", ondelete="RESTRICT"))
    # Exactly one target: a user, or every user with a role (file-level role grant).
    grantee_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT")
    )
    grantee_role: Mapped[str | None] = mapped_column(Text)
    permissions: Mapped[list[str]] = mapped_column(ARRAY(Text))
    granted_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("operators.id", ondelete="RESTRICT"))
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="RESTRICT")
    )
    audit_stream_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    audit_chain_index: Mapped[int] = mapped_column(BigInteger)
    revoked_audit_chain_index: Mapped[int | None] = mapped_column(BigInteger)

    file: Mapped[File] = relationship(back_populates="permissions")
