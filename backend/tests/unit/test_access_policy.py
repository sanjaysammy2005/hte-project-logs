"""ZT1: the pure access-decision engine and the policy file (ZERO_TRUST_FILE_MODULE §7–§10)."""

import itertools
import json
import uuid
from pathlib import Path

import pytest

from app.access.model import Action, Classification, Permission, Role
from app.access.policy import Context, FileFacts, Principal, ReasonCode, decide
from app.access.policy_file import DEFAULT_POLICY_PATH, PolicyError, load_policy

POLICY = load_policy()
ME, OTHER = uuid.uuid4(), uuid.uuid4()

# --- independent oracle: the role matrix exactly as printed in ZERO_TRUST_FILE_MODULE.md §8 ----
_ADMIN_FULL = "R D U Up Rn Del Res S V M"
DESIGN_MATRIX = {
    "admin": [_ADMIN_FULL, _ADMIN_FULL, _ADMIN_FULL, "V M", "V M"],
    "auditor": ["R V", "V", "V", "V", "V"],
    "manager": ["R D S", "R D S", "R D S", "", ""],
    "employee": ["R D", "R D", "", "", ""],
    "ingestor": ["", "", "", "", ""],
}
_ABBREV = {
    "R": "READ", "D": "DOWNLOAD", "U": "UPDATE", "Up": "UPLOAD", "Rn": "RENAME",
    "Del": "DELETE", "Res": "RESTORE", "S": "SHARE", "V": "VERIFY", "M": "MANAGE_PERMISSIONS",
}  # fmt: skip
DESIGN_OWNER = {"READ", "DOWNLOAD", "UPLOAD", "UPDATE", "RENAME", "DELETE", "RESTORE", "SHARE"}
DESIGN_OWNER |= {"VERIFY"}
ACTION_NEEDS = {
    "VIEW": "READ", "DOWNLOAD": "DOWNLOAD", "UPLOAD": "UPLOAD", "UPDATE": "UPDATE",
    "RENAME": "RENAME", "DELETE": "DELETE", "SHARE": "SHARE", "RESTORE": "RESTORE",
    "VERIFY": "VERIFY", "MANAGE_PERMISSIONS": "MANAGE_PERMISSIONS",
}  # fmt: skip
LEVELS = [c.value for c in Classification]


# Z20 (Access Control phase): role access on these levels applies only inside the user's own
# department; elsewhere ownership or an explicit grant is needed.
DESIGN_DEPARTMENT_SCOPED = {"employee": {"INTERNAL"}, "manager": {"INTERNAL", "CONFIDENTIAL"}}
MY_DEPT, OTHER_DEPT = "Engineering", "Finance"


def oracle_role_perms(role: str, level: str, same_department: bool = True) -> set[str]:
    if level in DESIGN_DEPARTMENT_SCOPED.get(role, set()) and not same_department:
        return set()
    return {_ABBREV[a] for a in DESIGN_MATRIX[role][LEVELS.index(level)].split()}


def facts(
    level: Classification,
    owner: uuid.UUID = OTHER,
    deleted: bool = False,
    department: str | None = MY_DEPT,
) -> FileFacts:
    return FileFacts(uuid.uuid4(), level, owner, deleted, department)


def principal(role: Role, department: str | None = MY_DEPT) -> Principal:
    return Principal(ME, f"{role.value}-user", role, department)


# --- the matrix --------------------------------------------------------------------------------

FILE_ACTIONS = [a for a in Action if a is not Action.CREATE]
GRANT_SETS = [
    frozenset(),
    frozenset({Permission.READ}),
    frozenset({Permission.READ, Permission.DOWNLOAD}),
]


@pytest.mark.parametrize(
    ("role", "level", "action", "owned", "grants", "same_department"),
    list(
        itertools.product(
            Role, Classification, FILE_ACTIONS, [False, True], GRANT_SETS, [True, False]
        )
    ),
)
def test_permission_matrix_matches_design(
    role: Role,
    level: Classification,
    action: Action,
    owned: bool,
    grants: frozenset,
    same_department: bool,
) -> None:
    """Every role × classification × action × ownership × grant × department combination
    (3,000 cases), with a fresh session so only permissions decide."""
    file = facts(
        level, ME if owned else OTHER, department=MY_DEPT if same_department else OTHER_DEPT
    )
    decision = decide(POLICY, principal(role), action, file, grants)

    if role is Role.INGESTOR:
        expected = set()
    else:
        expected = oracle_role_perms(role.value, level.value, same_department)
        expected |= {g.value for g in grants}
        if owned:
            expected |= DESIGN_OWNER
    needed = ACTION_NEEDS[action.value]
    should_allow = needed in expected and not (
        action is Action.VIEW and level is Classification.HIGHLY_RESTRICTED  # no preview there
    )
    assert decision.allowed is should_allow, decision
    if should_allow:
        source = "OWNER" if owned and needed in DESIGN_OWNER else (
            "GRANT" if needed in {g.value for g in grants} else "ROLE"
        )  # fmt: skip
        assert decision.permission_source == source
        assert decision.reason is ReasonCode[f"ALLOW_{source}"]


@pytest.mark.parametrize("role", list(Role))
def test_workspace_create(role: Role) -> None:
    decision = decide(POLICY, principal(role), Action.CREATE, None)
    assert decision.allowed is (role in {Role.ADMIN, Role.MANAGER, Role.EMPLOYEE})


def test_ingestor_cannot_discover_or_use_anything() -> None:
    decision = decide(POLICY, principal(Role.INGESTOR), Action.VIEW, facts(Classification.PUBLIC))
    assert decision.reason is ReasonCode.ROLE_NOT_PERMITTED and not decision.discoverable


def test_explicit_access_levels_say_grant_required() -> None:
    decision = decide(
        POLICY, principal(Role.MANAGER), Action.DOWNLOAD, facts(Classification.RESTRICTED)
    )
    assert decision.reason is ReasonCode.GRANT_REQUIRED
    assert decision.required_permission is Permission.DOWNLOAD
    assert not decision.discoverable  # a manager does not even learn the file exists


def test_lower_levels_say_no_permission() -> None:
    decision = decide(
        POLICY, principal(Role.AUDITOR), Action.DOWNLOAD, facts(Classification.INTERNAL)
    )
    assert decision.reason is ReasonCode.NO_PERMISSION and decision.discoverable


@pytest.mark.parametrize(
    ("role", "owned", "grants", "discoverable"),
    [
        (Role.ADMIN, False, frozenset(), True),  # all-visibility roles
        (Role.AUDITOR, False, frozenset(), True),
        (Role.EMPLOYEE, True, frozenset(), True),  # owner
        (Role.EMPLOYEE, False, frozenset({Permission.READ}), False),  # grantee loses trash access
        (Role.MANAGER, False, frozenset(), False),
    ],
)
def test_deleted_files(role: Role, owned: bool, grants: frozenset, discoverable: bool) -> None:
    file = facts(Classification.INTERNAL, ME if owned else OTHER, deleted=True)
    for action in FILE_ACTIONS:
        decision = decide(POLICY, principal(role), action, file, grants)
        if action is Action.VERIFY:  # integrity checks stay possible on trashed files
            assert decision.allowed is (Permission.VERIFY in decision.effective_permissions)
        else:
            assert not decision.allowed and ReasonCode.FILE_DELETED in decision.reasons
        assert decision.discoverable is discoverable


# --- context requirements ----------------------------------------------------------------------


def owner_decision(level: Classification, action: Action, **signals: int):
    return decide(
        POLICY, principal(Role.EMPLOYEE), action, facts(level, ME), context=Context(**signals)
    )


@pytest.mark.parametrize(
    ("level", "limit_minutes"),
    [(Classification.CONFIDENTIAL, 480), (Classification.RESTRICTED, 60)],
)
def test_session_age_limit(level: Classification, limit_minutes: int) -> None:
    assert owner_decision(level, Action.DOWNLOAD, session_age_s=limit_minutes * 60).allowed
    late = owner_decision(level, Action.DOWNLOAD, session_age_s=limit_minutes * 60 + 1)
    assert late.reason is ReasonCode.SESSION_TOO_OLD


def test_no_session_age_limit_for_lower_levels() -> None:
    assert owner_decision(Classification.INTERNAL, Action.DOWNLOAD, session_age_s=10**8).allowed


def test_step_up_window_for_highly_restricted() -> None:
    level = Classification.HIGHLY_RESTRICTED
    assert owner_decision(level, Action.DOWNLOAD, auth_age_s=600).allowed
    stale = owner_decision(level, Action.DOWNLOAD, auth_age_s=601)
    assert stale.reason is ReasonCode.STEP_UP_REQUIRED
    assert owner_decision(Classification.RESTRICTED, Action.DOWNLOAD, auth_age_s=10**6).allowed


def test_denial_burst_applies_from_confidential() -> None:
    assert owner_decision(Classification.INTERNAL, Action.DOWNLOAD, recent_denials=50).allowed
    assert owner_decision(Classification.CONFIDENTIAL, Action.DOWNLOAD, recent_denials=4).allowed
    blocked = owner_decision(Classification.CONFIDENTIAL, Action.DOWNLOAD, recent_denials=5)
    assert blocked.reason is ReasonCode.DENIAL_BURST


@pytest.mark.parametrize(
    ("level", "limit"), [(Classification.RESTRICTED, 20), (Classification.HIGHLY_RESTRICTED, 5)]
)
def test_download_rate_limit(level: Classification, limit: int) -> None:
    assert owner_decision(level, Action.DOWNLOAD, recent_downloads=limit - 1).allowed
    assert (
        owner_decision(level, Action.DOWNLOAD, recent_downloads=limit).reason
        is ReasonCode.RATE_LIMIT
    )
    # The limit is about downloads only.
    assert owner_decision(level, Action.RENAME, recent_downloads=limit).allowed


def test_verify_is_exempt_from_context_rules() -> None:
    signals = {
        "session_age_s": 10**8,
        "auth_age_s": 10**8,
        "recent_denials": 99,
        "recent_downloads": 99,
    }
    for level in Classification:
        assert owner_decision(level, Action.VERIFY, **signals).allowed


def test_all_failed_requirements_are_reported_in_order() -> None:
    decision = decide(
        POLICY,
        principal(Role.EMPLOYEE),
        Action.DOWNLOAD,
        facts(Classification.HIGHLY_RESTRICTED),
        context=Context(
            session_age_s=10**6, auth_age_s=10**6, recent_denials=9, recent_downloads=9
        ),
    )
    assert decision.reasons == (
        ReasonCode.GRANT_REQUIRED,
        ReasonCode.SESSION_TOO_OLD,
        ReasonCode.STEP_UP_REQUIRED,
        ReasonCode.DENIAL_BURST,
        ReasonCode.RATE_LIMIT,
    )
    assert "explicit DOWNLOAD grant" in decision.message


def test_signals_are_integers_or_text_only() -> None:
    """Signals go into hashed payloads, where floats are not allowed (tl-v1)."""
    decision = owner_decision(Classification.RESTRICTED, Action.DOWNLOAD, session_age_s=5)
    assert all(
        isinstance(v, int | str | bool) and not isinstance(v, float)
        for v in decision.signals.values()
    )
    assert decision.signals["ownership"] == "OWNER"


# --- policy file -------------------------------------------------------------------------------


def test_policy_identifier_names_version_and_hash() -> None:
    import hashlib

    digest = hashlib.sha256(DEFAULT_POLICY_PATH.read_bytes()).hexdigest()
    assert POLICY.identifier == f"access-policy.v1 sha256:{digest}"


def _write(tmp_path: Path, mutate) -> Path:
    data = json.loads(DEFAULT_POLICY_PATH.read_text())
    mutate(data)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data))
    return path


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["classifications"].pop("PUBLIC"),
        lambda d: d["roles"].pop("auditor"),
        lambda d: d["roles"].update(root=d["roles"]["admin"]),
        lambda d: d["roles"]["employee"]["by_classification"].update(RESTRICTED=["READ"]),
        lambda d: d["roles"]["employee"]["by_classification"].update(SECRET=["READ"]),
        lambda d: d["roles"]["employee"]["by_classification"].update(PUBLIC=["CREATE"]),
        lambda d: d["roles"]["employee"].update(workspace=["READ"]),
        lambda d: d["roles"]["employee"].update(metadata_visibility="some"),
        lambda d: d.update(owner_permissions=["READ", "MANAGE_PERMISSIONS"]),
        lambda d: d.update(owner_permissions=["READ", "FLY"]),
        lambda d: d["classifications"]["RESTRICTED"].update(max_session_age_minutes=0),
        lambda d: d["classifications"]["RESTRICTED"].update(preview_allowed="yes"),
        lambda d: d["classifications"]["RESTRICTED"].pop("step_up_minutes"),
        lambda d: d["signals"]["denial_burst"].update(threshold=None),
        lambda d: d["signals"]["denial_burst"].update(from_classification="SECRET"),
        lambda d: d.pop("signals"),
        lambda d: d.update(version=""),
    ],
)
def test_inconsistent_policy_files_rejected(tmp_path: Path, mutate) -> None:
    with pytest.raises(PolicyError):
        load_policy(_write(tmp_path, mutate))


def test_malformed_json_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{")
    with pytest.raises(PolicyError):
        load_policy(path)
