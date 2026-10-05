"""ZT-F1: the permission/classification vocabulary matches the approved design (§7, §10)."""

from app.access.model import (
    GRANTABLE_PERMISSIONS,
    REQUIRED_PERMISSION,
    Action,
    Classification,
    Permission,
)
from app.db.models import CLASSIFICATIONS, PERMISSIONS, ROLES

# Independent oracle: written from ZERO_TRUST_FILE_MODULE.md, not from the code.
DESIGN_CLASSIFICATIONS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "HIGHLY_RESTRICTED"]
DESIGN_PERMISSIONS = {
    "READ", "DOWNLOAD", "CREATE", "UPLOAD", "UPDATE", "RENAME",
    "DELETE", "RESTORE", "SHARE", "VERIFY", "MANAGE_PERMISSIONS",
}  # fmt: skip
DESIGN_ACTIONS = {
    "VIEW", "DOWNLOAD", "CREATE", "UPLOAD", "UPDATE", "RENAME",
    "DELETE", "SHARE", "RESTORE", "VERIFY", "MANAGE_PERMISSIONS",
}  # fmt: skip


def test_classifications_are_ordered_by_sensitivity() -> None:
    assert [c.value for c in Classification] == DESIGN_CLASSIFICATIONS
    assert [c.rank for c in Classification] == [0, 1, 2, 3, 4]
    assert Classification.RESTRICTED.rank > Classification.CONFIDENTIAL.rank


def test_permission_and_action_sets_match_design() -> None:
    assert {p.value for p in Permission} == DESIGN_PERMISSIONS
    assert {a.value for a in Action} == DESIGN_ACTIONS


def test_every_action_needs_exactly_one_permission() -> None:
    assert set(REQUIRED_PERMISSION) == set(Action)
    assert REQUIRED_PERMISSION[Action.VIEW] is Permission.READ
    assert REQUIRED_PERMISSION[Action.DOWNLOAD] is Permission.DOWNLOAD


def test_escalating_permissions_are_not_grantable() -> None:
    assert Permission.MANAGE_PERMISSIONS not in GRANTABLE_PERMISSIONS
    assert Permission.CREATE not in GRANTABLE_PERMISSIONS  # workspace-level, not per file
    assert GRANTABLE_PERMISSIONS == frozenset(Permission) - {
        Permission.MANAGE_PERMISSIONS,
        Permission.CREATE,
    }


def test_database_vocabularies_come_from_the_model() -> None:
    assert CLASSIFICATIONS == tuple(DESIGN_CLASSIFICATIONS)
    assert set(PERMISSIONS) == DESIGN_PERMISSIONS
    assert ROLES == ("admin", "auditor", "manager", "employee", "ingestor")
