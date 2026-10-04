"""Initial schema: operators, log_streams, audit_events; seed the system stream.

Revision ID: 0001
Revises:
Create Date: 2026-10-04

"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Fixed id so the system stream is identical in every installation.
SYSTEM_STREAM_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")


def upgrade() -> None:
    op.create_table(
        "operators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "role IN ('admin', 'auditor', 'ingestor')", name=op.f("ck_operators_role_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_operators")),
        sa.UniqueConstraint("username", name=op.f("uq_operators_username")),
    )

    log_streams = op.create_table(
        "log_streams",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("source_stream_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("genesis_hash", sa.LargeBinary(), nullable=False),
        sa.Column("hash_scheme", sa.Text(), nullable=False),
        sa.Column("merkle_scheme", sa.Text(), nullable=False),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("generator_seed", sa.BigInteger(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "kind IN ('primary', 'synthetic', 'lab')", name=op.f("ck_log_streams_kind_valid")
        ),
        sa.ForeignKeyConstraint(
            ["source_stream_id"],
            ["log_streams.id"],
            name=op.f("fk_log_streams_source_stream_id_log_streams"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_log_streams")),
        sa.UniqueConstraint("name", name=op.f("uq_log_streams_name")),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("stream_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("chain_index", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column(
            "event_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("actor_user_id", sa.Text(), nullable=True),
        sa.Column("session_id", sa.Text(), nullable=True),
        sa.Column("prev_event_type", sa.Text(), nullable=True),
        sa.Column("session_seq", sa.Integer(), nullable=True),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prev_hash", sa.LargeBinary(), nullable=False),
        sa.Column("entry_hash", sa.LargeBinary(), nullable=False),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "octet_length(prev_hash) = 32 AND octet_length(entry_hash) = 32",
            name=op.f("ck_audit_events_hash_length"),
        ),
        sa.CheckConstraint(
            "(session_id IS NULL) = (session_seq IS NULL)",
            name=op.f("ck_audit_events_session_seq_pair"),
        ),
        sa.ForeignKeyConstraint(
            ["stream_id"], ["log_streams.id"], name=op.f("fk_audit_events_stream_id_log_streams")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
        sa.UniqueConstraint("stream_id", "chain_index", name=op.f("uq_audit_events_stream_id")),
    )
    op.create_index(
        "uq_audit_events_session_seq",
        "audit_events",
        ["stream_id", "session_id", "session_seq"],
        unique=True,
        postgresql_where=sa.text("session_id IS NOT NULL"),
    )
    op.create_index("ix_audit_events_actor", "audit_events", ["stream_id", "actor_user_id"])
    op.create_index("ix_audit_events_timestamp", "audit_events", ["stream_id", "event_timestamp"])

    # The stream that records TraceLock's own operator logins and logouts (Q13).
    op.bulk_insert(
        log_streams,
        [
            {
                "id": SYSTEM_STREAM_ID,
                "name": "system",
                "kind": "primary",
                "genesis_hash": bytes(32),
                "hash_scheme": "tl-v1",
                "merkle_scheme": "paper-dup-v1",
                "batch_size": 64,
                "description": "TraceLock operator logins, logouts and failed logins.",
            }
        ],
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("log_streams")
    op.drop_table("operators")
