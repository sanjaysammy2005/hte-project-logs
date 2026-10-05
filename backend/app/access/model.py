"""Classifications, permissions and actions of the file module (ZERO_TRUST_FILE_MODULE §7, §10).

These are engineering additions [Eng], not part of the research paper. The values are stored in
the database (CHECK constraints are built from them) and will appear in audit event payloads,
so renaming one is a schema change.

The access-decision engine that combines them is a later phase; this module only defines the
vocabulary and the fixed relationships between its terms.
"""

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType


class Role(StrEnum):
    """Platform account roles (ZERO_TRUST_FILE_MODULE §8). Stored in operators.role."""

    ADMIN = "admin"
    AUDITOR = "auditor"
    MANAGER = "manager"
    EMPLOYEE = "employee"
    INGESTOR = "ingestor"


class Classification(StrEnum):
    """Security classification of a file, from least to most sensitive (§10)."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    HIGHLY_RESTRICTED = "HIGHLY_RESTRICTED"

    @property
    def rank(self) -> int:
        """0 for PUBLIC up to 4 for HIGHLY_RESTRICTED; used to tell upgrades from downgrades."""
        return list(Classification).index(self)


class Permission(StrEnum):
    """What a user may do with a file (§7.1)."""

    READ = "READ"
    DOWNLOAD = "DOWNLOAD"
    CREATE = "CREATE"
    UPLOAD = "UPLOAD"
    UPDATE = "UPDATE"
    RENAME = "RENAME"
    DELETE = "DELETE"
    RESTORE = "RESTORE"
    SHARE = "SHARE"
    VERIFY = "VERIFY"
    MANAGE_PERMISSIONS = "MANAGE_PERMISSIONS"


class Action(StrEnum):
    """A requested operation. Each needs exactly one permission (§7.1)."""

    VIEW = "VIEW"
    DOWNLOAD = "DOWNLOAD"
    CREATE = "CREATE"
    UPLOAD = "UPLOAD"
    UPDATE = "UPDATE"
    RENAME = "RENAME"
    DELETE = "DELETE"
    SHARE = "SHARE"
    RESTORE = "RESTORE"
    VERIFY = "VERIFY"
    MANAGE_PERMISSIONS = "MANAGE_PERMISSIONS"


REQUIRED_PERMISSION: Mapping[Action, Permission] = MappingProxyType(
    {
        Action.VIEW: Permission.READ,
        Action.DOWNLOAD: Permission.DOWNLOAD,
        Action.CREATE: Permission.CREATE,
        Action.UPLOAD: Permission.UPLOAD,
        Action.UPDATE: Permission.UPDATE,
        Action.RENAME: Permission.RENAME,
        Action.DELETE: Permission.DELETE,
        Action.SHARE: Permission.SHARE,
        Action.RESTORE: Permission.RESTORE,
        Action.VERIFY: Permission.VERIFY,
        Action.MANAGE_PERMISSIONS: Permission.MANAGE_PERMISSIONS,
    }
)

# CREATE is checked at workspace level (there is no file yet), so it cannot be granted on a file.
# MANAGE_PERMISSIONS is never grantable: it would let a grantee escalate everyone (§7.4).
GRANTABLE_PERMISSIONS: frozenset[Permission] = frozenset(Permission) - {
    Permission.CREATE,
    Permission.MANAGE_PERMISSIONS,
}


class FileOrigin(StrEnum):
    """Where a file came from. Non-user files are always labelled in the UI (CLAUDE.md)."""

    USER = "user"
    DEMO = "demo"
    LAB = "lab"


class IntegrityStatus(StrEnum):
    """Outcome of the three-layer integrity check (§12.2)."""

    INTACT = "INTACT"
    CONTENT_MISMATCH = "CONTENT_MISMATCH"
    BLOB_MISSING = "BLOB_MISSING"
    METADATA_MISMATCH = "METADATA_MISMATCH"
    ANCHOR_MISSING = "ANCHOR_MISSING"
    ANCHOR_TAMPERED = "ANCHOR_TAMPERED"
