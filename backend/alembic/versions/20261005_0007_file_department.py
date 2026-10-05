"""File department, for department-scoped role access (ZERO_TRUST_FILE_MODULE Z20).

A file belongs to the department of its uploader at creation time. Role permissions on
department-scoped levels (employees: INTERNAL; managers: INTERNAL, CONFIDENTIAL) apply only
when the user's department equals the file's department.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-05

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("files", sa.Column("department", sa.Text(), nullable=True))
    op.create_check_constraint(
        op.f("ck_files_department_length"), "files", "char_length(department) BETWEEN 1 AND 128"
    )
    op.create_index("ix_files_department", "files", ["department"])


def downgrade() -> None:
    op.drop_index("ix_files_department", table_name="files")
    op.drop_constraint(op.f("ck_files_department_length"), "files", type_="check")
    op.drop_column("files", "department")
