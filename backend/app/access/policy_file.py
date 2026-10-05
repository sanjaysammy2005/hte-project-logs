"""Load and validate the versioned access policy (ZERO_TRUST_FILE_MODULE §10.2, Z4).

Mirrors ``provenance/rules.py``: the policy is a JSON file in git, its SHA-256 is computed on
load, and ``identifier`` ("access-policy.v1 sha256:…") is written into every decision event,
so each audit record states exactly which policy produced it. An invalid file stops startup.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from app.access.model import Classification, Permission, Role

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "config" / "access_policy.v1.json"
VISIBILITIES = ("all", "permitted", "none")
# At levels that require explicit access, roles may only verify or manage, never read content.
_EXPLICIT_LEVEL_ROLE_PERMISSIONS = frozenset({Permission.VERIFY, Permission.MANAGE_PERMISSIONS})


class PolicyError(ValueError):
    """The policy file is missing fields or internally inconsistent."""


@dataclass(frozen=True)
class LevelPolicy:
    requires_explicit_access: bool
    max_session_age_minutes: int | None
    step_up_minutes: int | None
    max_downloads_per_hour: int | None
    preview_allowed: bool
    redact_name_in_audit: bool
    audit_metadata_views: bool
    share_is_grantable: bool  # may SHARE itself be passed on at this level?
    share_owner_or_manager_only: bool  # only the owner or a permission manager may share
    share_reason_required: bool
    role_grants_allowed: bool  # may a whole role be granted access to one file at this level?


@dataclass(frozen=True)
class RolePolicy:
    metadata_visibility: str  # all | permitted | none
    workspace: frozenset[Permission]
    by_classification: Mapping[Classification, frozenset[Permission]]
    # Levels where the role's permissions apply only to files of the user's own department.
    department_scoped: frozenset[Classification] = frozenset()


@dataclass(frozen=True)
class DenialBurst:
    window_minutes: int
    threshold: int
    from_classification: Classification


@dataclass(frozen=True)
class AccessPolicy:
    version: str
    sha256: str
    levels: Mapping[Classification, LevelPolicy]
    roles: Mapping[Role, RolePolicy]
    owner_permissions: frozenset[Permission]
    denial_burst: DenialBurst

    @property
    def identifier(self) -> str:
        return f"{self.version} sha256:{self.sha256}"


def _optional_positive_int(value: object, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PolicyError(f"{name} must be a positive integer or null")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{name} must be true or false")
    return value


def _permissions(values: object, name: str) -> frozenset[Permission]:
    if not isinstance(values, list):
        raise PolicyError(f"{name} must be a list")
    try:
        return frozenset(Permission(v) for v in values)
    except ValueError as exc:
        raise PolicyError(f"{name}: {exc}") from exc


def load_policy(path: Path = DEFAULT_POLICY_PATH) -> AccessPolicy:
    raw = path.read_bytes()
    try:
        data = json.loads(raw)
        levels_raw, roles_raw = data["classifications"], data["roles"]
        burst_raw = data["signals"]["denial_burst"]
        version = data["version"]
        owner_raw = data["owner_permissions"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"malformed policy file {path.name}: {exc!r}") from exc
    if not isinstance(version, str) or not version:
        raise PolicyError("version must be a non-empty string")

    if not isinstance(levels_raw, dict) or set(levels_raw) != {c.value for c in Classification}:
        raise PolicyError("classifications must define exactly the five levels")
    levels = {}
    for name, item in levels_raw.items():
        try:
            levels[Classification(name)] = LevelPolicy(
                requires_explicit_access=_bool(item["requires_explicit_access"], name),
                max_session_age_minutes=_optional_positive_int(
                    item["max_session_age_minutes"], name
                ),
                step_up_minutes=_optional_positive_int(item["step_up_minutes"], name),
                max_downloads_per_hour=_optional_positive_int(item["max_downloads_per_hour"], name),
                preview_allowed=_bool(item["preview_allowed"], name),
                redact_name_in_audit=_bool(item["redact_name_in_audit"], name),
                audit_metadata_views=_bool(item["audit_metadata_views"], name),
                share_is_grantable=_bool(item["share_is_grantable"], name),
                share_owner_or_manager_only=_bool(item["share_owner_or_manager_only"], name),
                share_reason_required=_bool(item["share_reason_required"], name),
                role_grants_allowed=_bool(item["role_grants_allowed"], name),
            )
        except (KeyError, TypeError) as exc:
            raise PolicyError(f"classification {name}: missing or invalid field {exc}") from exc

    if not isinstance(roles_raw, dict) or set(roles_raw) != {r.value for r in Role}:
        raise PolicyError("roles must define exactly the platform roles")
    roles = {}
    for name, item in roles_raw.items():
        try:
            visibility = item["metadata_visibility"]
            by_class_raw = item["by_classification"]
            workspace = _permissions(item["workspace"], f"{name}.workspace")
        except (KeyError, TypeError) as exc:
            raise PolicyError(f"role {name}: missing field {exc}") from exc
        if visibility not in VISIBILITIES:
            raise PolicyError(f"role {name}: metadata_visibility must be one of {VISIBILITIES}")
        if workspace - {Permission.CREATE}:
            raise PolicyError(f"role {name}: only CREATE is a workspace permission")
        if not isinstance(by_class_raw, dict):
            raise PolicyError(f"role {name}: by_classification must be an object")
        by_class = {}
        for level_name, perms in by_class_raw.items():
            try:
                level = Classification(level_name)
            except ValueError as exc:
                raise PolicyError(f"role {name}: unknown classification {level_name}") from exc
            granted = _permissions(perms, f"{name}.{level_name}")
            if Permission.CREATE in granted:
                raise PolicyError(f"role {name}: CREATE is not a per-file permission")
            if (
                levels[level].requires_explicit_access
                and granted - _EXPLICIT_LEVEL_ROLE_PERMISSIONS
            ):
                raise PolicyError(
                    f"role {name}: {level_name} requires explicit access, so the role may only"
                    " hold VERIFY / MANAGE_PERMISSIONS there"
                )
            by_class[level] = granted
        scoped_raw = item.get("department_scoped", [])
        try:
            scoped = frozenset(Classification(c) for c in scoped_raw)
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"role {name}: invalid department_scoped {scoped_raw!r}") from exc
        for level in scoped:
            if level not in by_class or levels[level].requires_explicit_access:
                raise PolicyError(
                    f"role {name}: department scope on {level.value} needs role permissions"
                    " there and a level without explicit-access requirements"
                )
        roles[Role(name)] = RolePolicy(visibility, workspace, MappingProxyType(by_class), scoped)

    owner = _permissions(owner_raw, "owner_permissions")
    if owner & {Permission.CREATE, Permission.MANAGE_PERMISSIONS}:
        raise PolicyError("owners must not hold CREATE or MANAGE_PERMISSIONS")

    try:
        burst = DenialBurst(
            window_minutes=_optional_positive_int(burst_raw["window_minutes"], "window_minutes")
            or 0,
            threshold=_optional_positive_int(burst_raw["threshold"], "threshold") or 0,
            from_classification=Classification(burst_raw["from_classification"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyError(f"signals.denial_burst: {exc}") from exc
    if not burst.window_minutes or not burst.threshold:
        raise PolicyError("signals.denial_burst needs a window and a threshold")

    return AccessPolicy(
        version=version,
        sha256=hashlib.sha256(raw).hexdigest(),
        levels=MappingProxyType(levels),
        roles=MappingProxyType(roles),
        owner_permissions=owner,
        denial_burst=burst,
    )
