"""Role-level file grants and revocation audit references (file sharing phase).

A grant now targets exactly one of: a user (grantee_id) or a role (grantee_role).
revoked_audit_chain_index points at the chained event that revoked the grant.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-05

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLES = "('admin', 'auditor', 'manager', 'employee', 'ingestor')"


def upgrade() -> None:
    op.alter_column("file_permissions", "grantee_id", nullable=True)
    op.add_column("file_permissions", sa.Column("grantee_role", sa.Text(), nullable=True))
    op.add_column(
        "file_permissions", sa.Column("revoked_audit_chain_index", sa.BigInteger(), nullable=True)
    )
    op.create_check_constraint(
        op.f("ck_file_permissions_one_target"),
        "file_permissions",
        "num_nonnulls(grantee_id, grantee_role) = 1",
    )
    op.create_check_constraint(
        op.f("ck_file_permissions_grantee_role_valid"),
        "file_permissions",
        f"grantee_role IS NULL OR grantee_role IN {ROLES}",
    )
    op.create_index(
        "uq_file_permissions_active_role_grant",
        "file_permissions",
        ["file_id", "grantee_role"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL AND grantee_role IS NOT NULL"),
    )


def downgrade() -> None:
    op.execute("DELETE FROM file_permissions WHERE grantee_role IS NOT NULL")
    op.drop_index("uq_file_permissions_active_role_grant", table_name="file_permissions")
    op.drop_constraint(
        op.f("ck_file_permissions_grantee_role_valid"), "file_permissions", type_="check"
    )
    op.drop_constraint(op.f("ck_file_permissions_one_target"), "file_permissions", type_="check")
    op.drop_column("file_permissions", "revoked_audit_chain_index")
    op.drop_column("file_permissions", "grantee_role")
    op.alter_column("file_permissions", "grantee_id", nullable=False)
