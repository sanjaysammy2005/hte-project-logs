"""ZT-AC (pure): sharing, revocation, ownership transfer, rule attribution, department scope.

Every decision must name the policy rule that produced it (ALLOW) or the rules that failed
(DENY), and the policy version it came from.
"""

import uuid

import pytest

from app.access.model import Action, Classification, Permission, Role
from app.access.policy import (
    AccountFacts,
    Context,
    FileFacts,
    Principal,
    ReasonCode,
    decide,
    decide_grant,
    decide_revoke,
    decide_transfer,
    update_actions,
)
from app.access.policy_file import load_policy

POLICY = load_policy()
ME, OWNER, OTHER = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
P = Permission
C = Classification
FRESH = Context()


def who(role: Role, dept: str | None = "Eng", uid: uuid.UUID = ME, active: bool = True):
    return Principal(uid, role.value, role, dept, active)


def file(level: C, owner: uuid.UUID = OWNER, dept: str | None = "Eng", deleted: bool = False):
    return FileFacts(uuid.uuid4(), level, owner, deleted, dept)


def account(role: Role = Role.EMPLOYEE, active: bool = True, uid: uuid.UUID = OTHER):
    return AccountFacts(uid, role, active)


def grant(principal, f, perms, grants=frozenset(), grantee=None):
    return decide_grant(POLICY, principal, f, grants, FRESH, grantee or account(), frozenset(perms))


# --- rule attribution --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("principal", "f", "action", "grants", "rule"),
    [
        (who(Role.EMPLOYEE), file(C.INTERNAL), Action.DOWNLOAD, frozenset(),
         "roles.employee.by_classification[INTERNAL] (same department)"),
        (who(Role.EMPLOYEE), file(C.PUBLIC), Action.VIEW, frozenset(),
         "roles.employee.by_classification[PUBLIC]"),
        (who(Role.EMPLOYEE), file(C.RESTRICTED, owner=ME), Action.DOWNLOAD, frozenset(),
         "owner_permissions"),
        (who(Role.EMPLOYEE), file(C.RESTRICTED), Action.DOWNLOAD, frozenset({P.DOWNLOAD}),
         "explicit_grant"),
        (who(Role.ADMIN), None, Action.CREATE, frozenset(), "roles.admin.workspace"),
    ],
)  # fmt: skip
def test_allow_names_the_rule(principal, f, action, grants, rule) -> None:
    decision = decide(POLICY, principal, action, f, grants)
    assert decision.allowed and decision.rule == rule
    assert decision.policy_id == POLICY.identifier and decision.rules == ()


@pytest.mark.parametrize(
    ("principal", "f", "action", "reason", "rule"),
    [
        (who(Role.EMPLOYEE), file(C.INTERNAL, dept="Fin"), Action.DOWNLOAD,
         ReasonCode.DEPARTMENT_MISMATCH, "roles.employee.department_scoped[INTERNAL]"),
        (who(Role.EMPLOYEE), file(C.CONFIDENTIAL), Action.VIEW,
         ReasonCode.NO_PERMISSION, "default_deny: no role, owner or grant rule allows it"),
        (who(Role.ADMIN), file(C.RESTRICTED), Action.DOWNLOAD,
         ReasonCode.GRANT_REQUIRED, "classifications.RESTRICTED.requires_explicit_access"),
        (who(Role.EMPLOYEE), file(C.PUBLIC, deleted=True, owner=ME), Action.DOWNLOAD,
         ReasonCode.FILE_DELETED, "lifecycle.trash: VERIFY only"),
        (who(Role.INGESTOR), file(C.PUBLIC), Action.VIEW,
         ReasonCode.ROLE_NOT_PERMITTED, "roles.ingestor.metadata_visibility=none"),
        (who(Role.EMPLOYEE, active=False), file(C.PUBLIC), Action.VIEW,
         ReasonCode.ACCOUNT_INACTIVE, "accounts.active"),
        (who(Role.EMPLOYEE), None, Action.VIEW, ReasonCode.NOT_FOUND, "resource.exists"),
        (who(Role.AUDITOR), None, Action.CREATE,
         ReasonCode.NO_PERMISSION, "default_deny: no role, owner or grant rule allows it"),
    ],
)  # fmt: skip
def test_deny_names_the_failed_rule(principal, f, action, reason, rule) -> None:
    decision = decide(POLICY, principal, action, f)
    assert not decision.allowed
    assert (decision.reason, decision.rule) == (reason, rule)
    assert decision.rules[0] == rule and decision.policy_id == POLICY.identifier
    assert decision.message  # a human-readable explanation


def test_context_rules_name_their_thresholds() -> None:
    decision = decide(
        POLICY, who(Role.EMPLOYEE), Action.DOWNLOAD, file(C.HIGHLY_RESTRICTED, owner=ME),
        context=Context(
            session_age_s=10**6, auth_age_s=10**6, recent_denials=9, recent_downloads=9
        ),
    )  # fmt: skip
    assert decision.rules == (
        "classifications.HIGHLY_RESTRICTED.max_session_age_minutes=30",
        "classifications.HIGHLY_RESTRICTED.step_up_minutes=10",
        "signals.denial_burst: 5 denials in 10 min from CONFIDENTIAL",
        "classifications.HIGHLY_RESTRICTED.max_downloads_per_hour=5",
    )


# --- department scope (Z20) --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "level", "user_dept", "file_dept", "allowed"),
    [
        (Role.EMPLOYEE, C.INTERNAL, "Eng", "Eng", True),
        (Role.EMPLOYEE, C.INTERNAL, "Eng", "Fin", False),
        (Role.EMPLOYEE, C.INTERNAL, None, None, False),  # no department: no scoped access at all
        (Role.EMPLOYEE, C.INTERNAL, None, "Eng", False),
        (Role.EMPLOYEE, C.PUBLIC, "Eng", "Fin", True),  # PUBLIC is organisation-wide
        (Role.EMPLOYEE, C.CONFIDENTIAL, "Eng", "Eng", False),  # not even in the same department
        (Role.MANAGER, C.CONFIDENTIAL, "Eng", "Eng", True),
        (Role.MANAGER, C.CONFIDENTIAL, "Eng", "Fin", False),
        (Role.MANAGER, C.INTERNAL, "Eng", "Fin", False),
        (Role.ADMIN, C.CONFIDENTIAL, "Eng", "Fin", True),  # admins are not department-scoped
    ],
)
def test_role_access_is_department_scoped(role, level, user_dept, file_dept, allowed) -> None:
    decision = decide(POLICY, who(role, user_dept), Action.DOWNLOAD, file(level, dept=file_dept))
    assert decision.allowed is allowed


def test_department_mismatch_still_allows_owner_and_grantee() -> None:
    owned = file(C.INTERNAL, owner=ME, dept="Fin")
    assert decide(POLICY, who(Role.EMPLOYEE), Action.DOWNLOAD, owned).allowed
    shared = file(C.INTERNAL, dept="Fin")
    assert decide(
        POLICY, who(Role.EMPLOYEE), Action.DOWNLOAD, shared, frozenset({P.DOWNLOAD})
    ).allowed


def test_inactive_account_gets_nothing_even_as_owner() -> None:
    decision = decide(
        POLICY, who(Role.ADMIN, active=False), Action.VERIFY, file(C.PUBLIC, owner=ME)
    )
    assert decision.reason is ReasonCode.ACCOUNT_INACTIVE and not decision.discoverable


# --- sharing -----------------------------------------------------------------------------------


def test_owner_shares_a_subset_of_owner_permissions() -> None:
    decision = grant(who(Role.EMPLOYEE), file(C.RESTRICTED, owner=ME), {P.READ, P.DOWNLOAD})
    assert decision.allowed and decision.rule == "sharing.subset_of_own_permissions"
    assert decision.signals["path"] == "SHARE"


def test_role_holder_with_share_may_pass_on_what_they_hold() -> None:
    manager = who(Role.MANAGER)
    assert grant(manager, file(C.CONFIDENTIAL), {P.READ}).allowed
    escalation = grant(manager, file(C.CONFIDENTIAL), {P.READ, P.UPDATE})
    assert escalation.reason is ReasonCode.SHARE_ESCALATION
    assert escalation.rule == "sharing.subset_of_own_permissions"


def test_holder_without_share_cannot_share() -> None:
    decision = grant(who(Role.EMPLOYEE), file(C.INTERNAL), {P.READ})
    assert decision.reason is ReasonCode.NO_PERMISSION
    assert (
        decide(POLICY, who(Role.EMPLOYEE), Action.SHARE, file(C.INTERNAL)).required_permission
        is P.SHARE
    )


def test_grantee_with_read_cannot_reshare() -> None:
    decision = grant(who(Role.EMPLOYEE), file(C.RESTRICTED), {P.READ}, grants=frozenset({P.READ}))
    assert not decision.allowed and ReasonCode.GRANT_REQUIRED in decision.reasons


def test_grantee_with_share_cannot_exceed_their_grant() -> None:
    mine = frozenset({P.READ, P.SHARE})
    assert grant(who(Role.EMPLOYEE), file(C.RESTRICTED), {P.READ}, grants=mine).allowed
    escalation = grant(who(Role.EMPLOYEE), file(C.RESTRICTED), {P.DOWNLOAD}, grants=mine)
    assert escalation.reason is ReasonCode.SHARE_ESCALATION


@pytest.mark.parametrize(
    "perms", [{P.MANAGE_PERMISSIONS}, {P.CREATE}, {P.READ, P.MANAGE_PERMISSIONS}]
)
def test_escalating_permissions_are_never_grantable(perms) -> None:
    for principal in (who(Role.EMPLOYEE), who(Role.ADMIN)):
        decision = grant(principal, file(C.INTERNAL, owner=ME), perms)
        assert ReasonCode.NOT_GRANTABLE in decision.reasons


def test_self_grant_blocked_except_break_glass() -> None:
    me = account(Role.EMPLOYEE, uid=ME)
    assert grant(who(Role.EMPLOYEE), file(C.INTERNAL, owner=ME), {P.READ}, grantee=me).reason is (
        ReasonCode.SELF_GRANT
    )
    # An admin holds MANAGE_PERMISSIONS even on RESTRICTED files: an audited break-glass.
    admin = who(Role.ADMIN)
    decision = grant(
        admin, file(C.RESTRICTED), {P.READ, P.DOWNLOAD}, grantee=account(Role.ADMIN, uid=ME)
    )
    assert decision.allowed and decision.rule == "sharing.manage_permissions"
    assert (
        decision.signals["self_grant"] is True and decision.signals["path"] == "MANAGE_PERMISSIONS"
    )


@pytest.mark.parametrize("grantee", [account(Role.INGESTOR), account(Role.EMPLOYEE, active=False)])
def test_ineligible_grantees(grantee) -> None:
    decision = grant(who(Role.EMPLOYEE), file(C.INTERNAL, owner=ME), {P.READ}, grantee=grantee)
    assert decision.reason is ReasonCode.GRANTEE_NOT_ELIGIBLE


def test_highly_restricted_sharing_rules() -> None:
    hr_owned = file(C.HIGHLY_RESTRICTED, owner=ME)
    assert grant(who(Role.EMPLOYEE), hr_owned, {P.READ, P.DOWNLOAD}).allowed
    reshare = grant(who(Role.EMPLOYEE), hr_owned, {P.SHARE})
    assert reshare.reason is ReasonCode.NOT_GRANTABLE  # SHARE cannot be passed on here
    # A grantee holding SHARE (granted before the file was reclassified) still may not share.
    grantee = grant(
        who(Role.EMPLOYEE), file(C.HIGHLY_RESTRICTED), {P.READ}, grants=frozenset({P.READ, P.SHARE})
    )
    assert grantee.reason is ReasonCode.OWNER_OR_MANAGER_ONLY


# --- revocation and ownership --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("principal", "f", "grants", "granted_by", "allowed", "reason"),
    [
        (who(Role.EMPLOYEE), file(C.RESTRICTED, owner=ME), frozenset(), OTHER, True, None),
        (who(Role.EMPLOYEE), file(C.RESTRICTED), frozenset({P.READ, P.SHARE}), ME, True, None),
        (who(Role.EMPLOYEE), file(C.RESTRICTED), frozenset({P.READ, P.SHARE}), OTHER, False,
         ReasonCode.NOT_GRANTOR),
        (who(Role.EMPLOYEE), file(C.RESTRICTED), frozenset({P.READ}), ME, False,
         ReasonCode.GRANT_REQUIRED),  # a grantor who no longer holds SHARE
        (who(Role.ADMIN), file(C.RESTRICTED), frozenset(), OTHER, True, None),
        (who(Role.AUDITOR), file(C.INTERNAL), frozenset(), OTHER, False, ReasonCode.NO_PERMISSION),
    ],
)  # fmt: skip
def test_revocation(principal, f, grants, granted_by, allowed, reason) -> None:
    decision = decide_revoke(POLICY, principal, f, grants, FRESH, granted_by)
    assert decision.allowed is allowed
    if reason:
        assert decision.reason is reason


@pytest.mark.parametrize(
    ("principal", "f", "new_owner", "allowed", "reason"),
    [
        (who(Role.ADMIN), file(C.INTERNAL), account(), True, None),
        (who(Role.ADMIN), file(C.HIGHLY_RESTRICTED), account(), True, None),
        (who(Role.EMPLOYEE), file(C.INTERNAL, owner=ME), account(), False,
         ReasonCode.NO_PERMISSION),  # owners cannot give files away
        (who(Role.ADMIN), file(C.INTERNAL), account(Role.INGESTOR), False,
         ReasonCode.GRANTEE_NOT_ELIGIBLE),
        (who(Role.ADMIN), file(C.INTERNAL, owner=OTHER), account(uid=OTHER), False,
         ReasonCode.ALREADY_OWNER),
    ],
)  # fmt: skip
def test_ownership_transfer(principal, f, new_owner, allowed, reason) -> None:
    decision = decide_transfer(POLICY, principal, f, frozenset(), FRESH, new_owner)
    assert decision.allowed is allowed
    if reason:
        assert decision.reason is reason


@pytest.mark.parametrize(
    ("current", "new", "renamed", "described", "expected"),
    [
        (C.INTERNAL, None, True, False, [Action.RENAME]),
        (C.INTERNAL, None, False, True, [Action.UPDATE]),
        (C.INTERNAL, C.RESTRICTED, False, False, [Action.UPDATE]),
        (C.RESTRICTED, C.INTERNAL, False, False, [Action.MANAGE_PERMISSIONS]),
        (
            C.RESTRICTED,
            C.PUBLIC,
            True,
            True,
            [Action.RENAME, Action.UPDATE, Action.MANAGE_PERMISSIONS],
        ),
        (C.INTERNAL, C.INTERNAL, False, False, []),
    ],
)
def test_update_actions(current, new, renamed, described, expected) -> None:
    assert update_actions(current, new, renamed, described) == expected
