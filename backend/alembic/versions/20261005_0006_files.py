"""File module tables: files, file_versions, file_permissions (ZERO_TRUST_FILE_MODULE §5.3).

Binary content is not stored here; file_versions.storage_key points into the storage backend.
Audit references (audit_stream_id, audit_chain_index) deliberately have no foreign key.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-05

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CLASSIFICATIONS = "('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'HIGHLY_RESTRICTED')"
PERMISSIONS = (
    "ARRAY['READ', 'DOWNLOAD', 'CREATE', 'UPLOAD', 'UPDATE', 'RENAME', 'DELETE', 'RESTORE',"
    " 'SHARE', 'VERIFY', 'MANAGE_PERMISSIONS']::text[]"
)
INTEGRITY_STATUSES = (
    "('INTACT', 'CONTENT_MISMATCH', 'BLOB_MISSING', 'METADATA_MISMATCH', 'ANCHOR_MISSING',"
    " 'ANCHOR_TAMPERED')"
)


def _timestamp(name: str, nullable: bool = False) -> sa.Column:
    default = None if nullable else sa.func.now()
    return sa.Column(name, sa.DateTime(timezone=True), server_default=default, nullable=nullable)


def _operator_fk(column: str, table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column], ["operators.id"], name=op.f(f"fk_{table}_{column}_operators"), ondelete="RESTRICT"
    )


def upgrade() -> None:
    op.create_table(
        "files",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("extension", sa.Text(), nullable=False),
        sa.Column("mime_type", sa.Text(), nullable=False),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("owner_id", sa.UUID(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=False),
        sa.Column("current_version", sa.Integer(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("origin", sa.Text(), server_default=sa.text("'user'"), nullable=False),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        _timestamp("deleted_at", nullable=True),
        sa.Column("deleted_by", sa.UUID(), nullable=True),
        _timestamp("purged_at", nullable=True),
        _timestamp("last_accessed_at", nullable=True),
        sa.CheckConstraint(
            f"classification IN {CLASSIFICATIONS}", name=op.f("ck_files_classification_valid")
        ),
        sa.CheckConstraint("origin IN ('user', 'demo', 'lab')", name=op.f("ck_files_origin_valid")),
        sa.CheckConstraint(
            "octet_length(display_name) BETWEEN 1 AND 255",
            name=op.f("ck_files_display_name_length"),
        ),
        sa.CheckConstraint(
            "extension ~ '^[a-z0-9]{1,10}$'", name=op.f("ck_files_extension_format")
        ),
        sa.CheckConstraint(
            "char_length(description) <= 1000", name=op.f("ck_files_description_length")
        ),
        sa.CheckConstraint("current_version >= 1", name=op.f("ck_files_current_version_positive")),
        sa.CheckConstraint(
            "(deleted_at IS NULL) = (deleted_by IS NULL)", name=op.f("ck_files_deleted_pair")
        ),
        sa.CheckConstraint(
            "purged_at IS NULL OR deleted_at IS NOT NULL", name=op.f("ck_files_purge_after_delete")
        ),
        _operator_fk("owner_id", "files"),
        _operator_fk("created_by", "files"),
        _operator_fk("deleted_by", "files"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_files")),
    )
    for column in (
        "owner_id",
        "created_by",
        "classification",
        "created_at",
        "updated_at",
        "origin",
    ):
        op.create_index(f"ix_files_{column}", "files", [column])
    op.create_index(
        "ix_files_deleted_at",
        "files",
        ["deleted_at"],
        postgresql_where=sa.text("deleted_at IS NOT NULL"),
    )

    op.create_table(
        "file_versions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("file_id", sa.UUID(), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("storage_key", sa.Text(), nullable=False),
        sa.Column("sha256", sa.LargeBinary(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("mime_type", sa.Text(), nullable=False),
        sa.Column("original_filename", sa.Text(), nullable=False),
        sa.Column("uploaded_by", sa.UUID(), nullable=False),
        _timestamp("created_at"),
        sa.Column("change_reason", sa.Text(), nullable=True),
        sa.Column("restored_from_version", sa.Integer(), nullable=True),
        sa.Column("audit_stream_id", sa.UUID(), nullable=False),
        sa.Column("audit_chain_index", sa.BigInteger(), nullable=False),
        _timestamp("last_verified_at", nullable=True),
        sa.Column("last_integrity_status", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "version_number >= 1", name=op.f("ck_file_versions_version_number_positive")
        ),
        sa.CheckConstraint(
            "storage_key ~ '^[0-9a-f]{32}$'", name=op.f("ck_file_versions_storage_key_format")
        ),
        sa.CheckConstraint(
            "octet_length(sha256) = 32", name=op.f("ck_file_versions_sha256_length")
        ),
        sa.CheckConstraint("size_bytes >= 0", name=op.f("ck_file_versions_size_non_negative")),
        sa.CheckConstraint(
            "octet_length(original_filename) BETWEEN 1 AND 255",
            name=op.f("ck_file_versions_original_filename_length"),
        ),
        sa.CheckConstraint(
            "char_length(change_reason) <= 500", name=op.f("ck_file_versions_change_reason_length")
        ),
        sa.CheckConstraint(
            "restored_from_version IS NULL"
            " OR (restored_from_version >= 1 AND restored_from_version < version_number)",
            name=op.f("ck_file_versions_restored_from_earlier"),
        ),
        sa.CheckConstraint(
            "audit_chain_index >= 1", name=op.f("ck_file_versions_audit_chain_index_positive")
        ),
        sa.CheckConstraint(
            f"last_integrity_status IS NULL OR last_integrity_status IN {INTEGRITY_STATUSES}",
            name=op.f("ck_file_versions_integrity_status_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["file_id"],
            ["files.id"],
            name=op.f("fk_file_versions_file_id_files"),
            ondelete="RESTRICT",
        ),
        _operator_fk("uploaded_by", "file_versions"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_file_versions")),
        sa.UniqueConstraint("file_id", "version_number", name=op.f("uq_file_versions_file_id")),
    )
    op.create_index("ix_file_versions_uploaded_by", "file_versions", ["uploaded_by"])
    op.create_index("ix_file_versions_storage_key", "file_versions", ["storage_key"])

    op.create_table(
        "file_permissions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("file_id", sa.UUID(), nullable=False),
        sa.Column("grantee_id", sa.UUID(), nullable=False),
        sa.Column("permissions", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("granted_by", sa.UUID(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        _timestamp("created_at"),
        _timestamp("expires_at", nullable=True),
        _timestamp("revoked_at", nullable=True),
        sa.Column("revoked_by", sa.UUID(), nullable=True),
        sa.Column("audit_stream_id", sa.UUID(), nullable=False),
        sa.Column("audit_chain_index", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            f"cardinality(permissions) >= 1 AND permissions <@ {PERMISSIONS}",
            name=op.f("ck_file_permissions_permissions_valid"),
        ),
        sa.CheckConstraint(
            "NOT (permissions && ARRAY['CREATE', 'MANAGE_PERMISSIONS']::text[])",
            name=op.f("ck_file_permissions_permissions_grantable"),
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name=op.f("ck_file_permissions_expires_after_created"),
        ),
        sa.CheckConstraint(
            "(revoked_at IS NULL) = (revoked_by IS NULL)",
            name=op.f("ck_file_permissions_revoked_pair"),
        ),
        sa.CheckConstraint(
            "char_length(reason) <= 500", name=op.f("ck_file_permissions_reason_length")
        ),
        sa.CheckConstraint(
            "audit_chain_index >= 1", name=op.f("ck_file_permissions_audit_chain_index_positive")
        ),
        sa.ForeignKeyConstraint(
            ["file_id"],
            ["files.id"],
            name=op.f("fk_file_permissions_file_id_files"),
            ondelete="RESTRICT",
        ),
        _operator_fk("grantee_id", "file_permissions"),
        _operator_fk("granted_by", "file_permissions"),
        _operator_fk("revoked_by", "file_permissions"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_file_permissions")),
    )
    op.create_index(
        "uq_file_permissions_active_grant",
        "file_permissions",
        ["file_id", "grantee_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.create_index("ix_file_permissions_file_id", "file_permissions", ["file_id"])
    op.create_index(
        "ix_file_permissions_grantee_active",
        "file_permissions",
        ["grantee_id"],
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_table("file_permissions")
    op.drop_table("file_versions")
    op.drop_table("files")
