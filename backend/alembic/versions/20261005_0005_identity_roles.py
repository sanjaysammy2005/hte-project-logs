"""Identity for the file module: new roles and user profile columns; file-event indexes.

Reuses the existing operators table as the single user store (ZERO_TRUST_FILE_MODULE §5.2, Z1).
audit_events gets indexes only; its hashed columns are unchanged.

Downgrade fails (by design, without deleting anyone) while manager/employee accounts exist.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-05

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_operators_role_valid"), "operators", type_="check")
    op.create_check_constraint(
        op.f("ck_operators_role_valid"),
        "operators",
        "role IN ('admin', 'auditor', 'manager', 'employee', 'ingestor')",
    )
    op.add_column("operators", sa.Column("display_name", sa.Text(), nullable=True))
    op.add_column("operators", sa.Column("department", sa.Text(), nullable=True))
    op.add_column(
        "operators",
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_check_constraint(
        op.f("ck_operators_display_name_length"),
        "operators",
        "char_length(display_name) BETWEEN 1 AND 128",
    )
    op.create_check_constraint(
        op.f("ck_operators_department_length"),
        "operators",
        "char_length(department) BETWEEN 1 AND 128",
    )

    op.create_index(
        "ix_audit_events_file_id",
        "audit_events",
        [sa.text("stream_id"), sa.text("(event_payload ->> 'file_id')")],
        postgresql_where=sa.text("(event_payload ->> 'file_id') IS NOT NULL"),
    )
    op.create_index(
        "ix_audit_events_type_time", "audit_events", ["stream_id", "event_type", "event_timestamp"]
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_type_time", table_name="audit_events")
    op.drop_index("ix_audit_events_file_id", table_name="audit_events")
    op.drop_constraint(op.f("ck_operators_department_length"), "operators", type_="check")
    op.drop_constraint(op.f("ck_operators_display_name_length"), "operators", type_="check")
    op.drop_column("operators", "updated_at")
    op.drop_column("operators", "department")
    op.drop_column("operators", "display_name")
    op.drop_constraint(op.f("ck_operators_role_valid"), "operators", type_="check")
    op.create_check_constraint(
        op.f("ck_operators_role_valid"), "operators", "role IN ('admin', 'auditor', 'ingestor')"
    )
