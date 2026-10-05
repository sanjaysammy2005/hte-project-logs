"""The Zero-Trust policy decision point (ZERO_TRUST_FILE_MODULE §9). Pure: data in, decision out.

Every authorization rule of the file module lives in this module and in the versioned policy
file it reads. Controllers and services never decide; they ask (via ``app/access/enforcer.py``).

Deny by default. A request is allowed only when

1. the principal's role may use the workspace at all,
2. the required permission is held, from ONE of:
     - the role, for the file's classification, and (for department-scoped levels) only
       inside the principal's own department,
     - ownership of the file,
     - an explicit, unexpired, unrevoked grant,
3. the file's lifecycle allows the action (trashed files: VERIFY only),
4. every requirement of the classification and the request context is met
   (session age, step-up re-authentication, denial burst, download rate, preview),
5. and, for sharing / revoking / ownership transfer, the anti-escalation rules hold.

Being authenticated is never enough by itself, and neither is a role: an employee reaches
INTERNAL files of their own department only, and nothing above that without ownership or a
grant. Every failed requirement is collected with the policy rule that caused it, so a denial
can be explained completely; the first one is the primary reason.

Context rules do not apply to VERIFY: an integrity check compares hashes and discloses no
content.
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from app.access.model import (
    GRANTABLE_PERMISSIONS,
    REQUIRED_PERMISSION,
    Action,
    Classification,
    Permission,
    Role,
)
from app.access.policy_file import AccessPolicy


class ReasonCode(StrEnum):
    ALLOW_ROLE = "ALLOW_ROLE"
    ALLOW_OWNER = "ALLOW_OWNER"
    ALLOW_GRANT = "ALLOW_GRANT"
    ROLE_NOT_PERMITTED = "ROLE_NOT_PERMITTED"
    ACCOUNT_INACTIVE = "ACCOUNT_INACTIVE"
    NOT_FOUND = "NOT_FOUND"
    FILE_DELETED = "FILE_DELETED"
    NO_PERMISSION = "NO_PERMISSION"
    DEPARTMENT_MISMATCH = "DEPARTMENT_MISMATCH"
    GRANT_REQUIRED = "GRANT_REQUIRED"
    SESSION_TOO_OLD = "SESSION_TOO_OLD"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    DENIAL_BURST = "DENIAL_BURST"
    RATE_LIMIT = "RATE_LIMIT"
    PREVIEW_NOT_ALLOWED = "PREVIEW_NOT_ALLOWED"
    # Sharing, revocation and ownership (anti-escalation, §7.4)
    SHARE_ESCALATION = "SHARE_ESCALATION"
    NOT_GRANTABLE = "NOT_GRANTABLE"
    SELF_GRANT = "SELF_GRANT"
    GRANTEE_NOT_ELIGIBLE = "GRANTEE_NOT_ELIGIBLE"
    OWNER_OR_MANAGER_ONLY = "OWNER_OR_MANAGER_ONLY"
    NOT_GRANTOR = "NOT_GRANTOR"
    ALREADY_OWNER = "ALREADY_OWNER"
    ROLE_GRANT_NOT_ALLOWED = "ROLE_GRANT_NOT_ALLOWED"


@dataclass(frozen=True)
class Principal:
    id: uuid.UUID
    username: str
    role: Role
    department: str | None = None
    is_active: bool = True


@dataclass(frozen=True)
class FileFacts:
    id: uuid.UUID
    classification: Classification
    owner_id: uuid.UUID
    deleted: bool
    department: str | None = None


@dataclass(frozen=True)
class Context:
    """Signals computed per request from the audit chain (app/access/context.py)."""

    session_age_s: int = 0
    auth_age_s: int = 0
    recent_denials: int = 0
    recent_downloads: int = 0


NO_SIGNALS = Context()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: ReasonCode
    reasons: tuple[ReasonCode, ...]
    rule: str  # the policy rule that decided (allow) or the first one that failed (deny)
    rules: tuple[str, ...]  # one per reason
    message: str
    required_permission: Permission | None
    permission_source: str | None  # OWNER | GRANT | ROLE when allowed
    discoverable: bool  # False → answer 404, exactly as if the file did not exist
    effective_permissions: frozenset[Permission]
    policy_id: str
    signals: Mapping[str, int | str | bool] = field(default_factory=dict)

    @property
    def effect(self) -> str:
        return "ALLOW" if self.allowed else "DENY"


# --- permissions -------------------------------------------------------------------------------


def _same_department(principal: Principal, file: FileFacts) -> bool:
    return principal.department is not None and principal.department == file.department


def role_permissions(
    policy: AccessPolicy, principal: Principal, file: FileFacts
) -> tuple[frozenset[Permission], bool]:
    """Role permissions that apply to this file, and whether a department scope removed some."""
    role = policy.roles.get(principal.role)
    if role is None or not principal.is_active:
        return frozenset(), False
    perms = role.by_classification.get(file.classification, frozenset())
    if file.classification in role.department_scoped and not _same_department(principal, file):
        return frozenset(), bool(perms)
    return perms, False


def effective_permissions(
    policy: AccessPolicy, principal: Principal, file: FileFacts, grants: frozenset[Permission]
) -> tuple[frozenset[Permission], dict[Permission, str]]:
    """Union of role, grant and owner permissions, with the source of each (owner first)."""
    if not principal.is_active:
        return frozenset(), {}
    sources: dict[Permission, str] = {}
    role_perms, _ = role_permissions(policy, principal, file)
    owner_perms = policy.owner_permissions if principal.id == file.owner_id else frozenset()
    for source, perms in (("ROLE", role_perms), ("GRANT", grants), ("OWNER", owner_perms)):
        for p in perms:
            sources[p] = source  # later sources win, so OWNER > GRANT > ROLE
    return frozenset(sources), sources


def is_discoverable(
    policy: AccessPolicy, principal: Principal, file: FileFacts, grants: frozenset[Permission]
) -> bool:
    """May this principal learn that the file exists (see its metadata)?"""
    role = policy.roles.get(principal.role)
    if role is None or role.metadata_visibility == "none" or not principal.is_active:
        return False
    if role.metadata_visibility == "all" or principal.id == file.owner_id:
        return True
    if file.deleted:  # trash is visible only to the owner and to all-visibility roles
        return False
    return bool(effective_permissions(policy, principal, file, grants)[0])


# --- explanations ------------------------------------------------------------------------------

_MESSAGES = {
    ReasonCode.ALLOW_ROLE: "Allowed: your role grants {permission} for {classification} files.",
    ReasonCode.ALLOW_OWNER: "Allowed: you own this file.",
    ReasonCode.ALLOW_GRANT: "Allowed: you hold an explicit {permission} grant for this file.",
    ReasonCode.ROLE_NOT_PERMITTED: "Your role ({role}) cannot use the file workspace.",
    ReasonCode.ACCOUNT_INACTIVE: "Your account is deactivated.",
    ReasonCode.NOT_FOUND: "File not found.",
    ReasonCode.FILE_DELETED: "This file is in the trash; only integrity verification is possible.",
    ReasonCode.NO_PERMISSION: (
        "You signed in successfully, but you do not have {permission} permission"
        " for this {classification} file."
    ),
    ReasonCode.DEPARTMENT_MISMATCH: (
        "You signed in successfully, but your role reaches {classification} files of your own"
        " department only; this file belongs to another department."
    ),
    ReasonCode.GRANT_REQUIRED: (
        "You signed in successfully, but {classification} files require ownership or an explicit"
        " {permission} grant; your role alone is not enough."
    ),
    ReasonCode.SESSION_TOO_OLD: (
        "Your session is older than {classification} files allow. Sign in again to continue."
    ),
    ReasonCode.STEP_UP_REQUIRED: (
        "{classification} files require you to re-enter your password before this action."
    ),
    ReasonCode.DENIAL_BURST: (
        "Too many denied requests recently; access to sensitive files is paused for a while."
    ),
    ReasonCode.RATE_LIMIT: "Download limit for {classification} files reached; try again later.",
    ReasonCode.PREVIEW_NOT_ALLOWED: "{classification} files cannot be previewed; download instead.",
    ReasonCode.SHARE_ESCALATION: "You can only share permissions you hold yourself.",
    ReasonCode.NOT_GRANTABLE: (
        "Some of these permissions cannot be granted on {classification} files."
    ),
    ReasonCode.SELF_GRANT: "You cannot grant permissions to yourself.",
    ReasonCode.GRANTEE_NOT_ELIGIBLE: "That account cannot receive file permissions.",
    ReasonCode.OWNER_OR_MANAGER_ONLY: (
        "Only the owner or a permission manager may share {classification} files."
    ),
    ReasonCode.NOT_GRANTOR: (
        "Only the grantor, the owner or a permission manager may revoke this grant."
    ),
    ReasonCode.ALREADY_OWNER: "That user already owns this file.",
    ReasonCode.ROLE_GRANT_NOT_ALLOWED: (
        "Granting a whole role access to {classification} files is not allowed."
    ),
}


def _rule_for(
    reason: ReasonCode, policy: AccessPolicy, principal: Principal, file: FileFacts | None
) -> str:
    level = file.classification.value if file else "-"
    role = principal.role.value
    level_policy = policy.levels.get(file.classification) if file else None
    return {
        ReasonCode.ROLE_NOT_PERMITTED: f"roles.{role}.metadata_visibility=none",
        ReasonCode.ACCOUNT_INACTIVE: "accounts.active",
        ReasonCode.NOT_FOUND: "resource.exists",
        ReasonCode.FILE_DELETED: "lifecycle.trash: VERIFY only",
        ReasonCode.NO_PERMISSION: "default_deny: no role, owner or grant rule allows it",
        ReasonCode.DEPARTMENT_MISMATCH: f"roles.{role}.department_scoped[{level}]",
        ReasonCode.GRANT_REQUIRED: f"classifications.{level}.requires_explicit_access",
        ReasonCode.SESSION_TOO_OLD: (
            f"classifications.{level}.max_session_age_minutes="
            f"{level_policy.max_session_age_minutes if level_policy else '-'}"
        ),
        ReasonCode.STEP_UP_REQUIRED: (
            f"classifications.{level}.step_up_minutes="
            f"{level_policy.step_up_minutes if level_policy else '-'}"
        ),
        ReasonCode.DENIAL_BURST: (
            f"signals.denial_burst: {policy.denial_burst.threshold} denials in"
            f" {policy.denial_burst.window_minutes} min from"
            f" {policy.denial_burst.from_classification.value}"
        ),
        ReasonCode.RATE_LIMIT: (
            f"classifications.{level}.max_downloads_per_hour="
            f"{level_policy.max_downloads_per_hour if level_policy else '-'}"
        ),
        ReasonCode.PREVIEW_NOT_ALLOWED: f"classifications.{level}.preview_allowed=false",
        ReasonCode.SHARE_ESCALATION: "sharing.subset_of_own_permissions",
        ReasonCode.NOT_GRANTABLE: f"sharing.grantable[{level}]",
        ReasonCode.SELF_GRANT: "sharing.no_self_grant (admins: break-glass via MANAGE_PERMISSIONS)",
        ReasonCode.GRANTEE_NOT_ELIGIBLE: "sharing.grantee_active_and_workspace_role",
        ReasonCode.OWNER_OR_MANAGER_ONLY: f"classifications.{level}.share_owner_or_manager_only",
        ReasonCode.NOT_GRANTOR: "sharing.revoke_by_grantor_owner_or_manager",
        ReasonCode.ALREADY_OWNER: "ownership.transfer_to_other_user",
        ReasonCode.ROLE_GRANT_NOT_ALLOWED: f"classifications.{level}.role_grants_allowed=false",
    }[reason]


def _allow_rule(source: str, policy: AccessPolicy, principal: Principal, file: FileFacts | None):
    role = principal.role.value
    if file is None:
        return f"roles.{role}.workspace"
    if source == "OWNER":
        return "owner_permissions"
    if source == "GRANT":
        return "explicit_grant"
    level = file.classification.value
    scoped = file.classification in policy.roles[principal.role].department_scoped
    return f"roles.{role}.by_classification[{level}]" + (" (same department)" if scoped else "")


@dataclass
class _Builder:
    """Collects failed requirements, then produces the Decision."""

    policy: AccessPolicy
    principal: Principal
    file: FileFacts | None
    required: Permission
    signals: dict[str, int | str | bool]
    reasons: list[ReasonCode] = field(default_factory=list)

    def fail(self, reason: ReasonCode) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)

    def build(
        self,
        effective: frozenset[Permission],
        source: str | None = None,
        discoverable: bool = True,
        allow_rule: str | None = None,
    ) -> Decision:
        classification = self.file.classification if self.file else None
        rules = tuple(_rule_for(r, self.policy, self.principal, self.file) for r in self.reasons)
        if self.reasons:
            primary, rule = self.reasons[0], rules[0]
        else:
            primary = ReasonCode[f"ALLOW_{source}"]
            rule = allow_rule or _allow_rule(source or "", self.policy, self.principal, self.file)
        message = _MESSAGES[primary].format(
            role=self.principal.role.value,
            permission=self.required.value,
            classification=classification.value if classification else "",
        )
        return Decision(
            allowed=not self.reasons,
            reason=primary,
            reasons=tuple(self.reasons),
            rule=rule,
            rules=rules,
            message=message,
            required_permission=self.required,
            permission_source=None if self.reasons else source,
            discoverable=discoverable,
            effective_permissions=effective,
            policy_id=self.policy.identifier,
            signals=self.signals,
        )


# --- the decision ------------------------------------------------------------------------------


def decide(
    policy: AccessPolicy,
    principal: Principal,
    action: Action,
    file: FileFacts | None,
    grants: frozenset[Permission] = frozenset(),
    context: Context = NO_SIGNALS,
) -> Decision:
    required = REQUIRED_PERMISSION[action]
    role = policy.roles.get(principal.role)
    signals: dict[str, int | str | bool] = {
        "session_age_s": context.session_age_s,
        "auth_age_s": context.auth_age_s,
        "recent_denials": context.recent_denials,
        "recent_downloads": context.recent_downloads,
    }
    b = _Builder(policy, principal, file, required, signals)

    if role is None or role.metadata_visibility == "none":
        b.fail(ReasonCode.ROLE_NOT_PERMITTED)
        return b.build(frozenset(), discoverable=False)
    if not principal.is_active:
        b.fail(ReasonCode.ACCOUNT_INACTIVE)
        return b.build(frozenset(), discoverable=False)

    if action is Action.CREATE:  # workspace level: there is no file yet
        if required not in role.workspace:
            b.fail(ReasonCode.NO_PERMISSION)
        return b.build(role.workspace, source="ROLE")

    if file is None:
        b.fail(ReasonCode.NOT_FOUND)
        return b.build(frozenset(), discoverable=False)

    effective, sources = effective_permissions(policy, principal, file, grants)
    _, scoped_out = role_permissions(policy, principal, file)
    signals["ownership"] = (
        "OWNER" if principal.id == file.owner_id else "GRANTEE" if grants else
        "ROLE" if effective else "NONE"
    )  # fmt: skip
    signals["same_department"] = _same_department(principal, file)
    level = policy.levels[file.classification]

    if file.deleted and action is not Action.VERIFY:
        b.fail(ReasonCode.FILE_DELETED)
    if required not in effective:
        if level.requires_explicit_access:
            b.fail(ReasonCode.GRANT_REQUIRED)
        elif scoped_out and required in policy.roles[principal.role].by_classification.get(
            file.classification, frozenset()
        ):
            b.fail(ReasonCode.DEPARTMENT_MISMATCH)
        else:
            b.fail(ReasonCode.NO_PERMISSION)
    if action is not Action.VERIFY:
        if (
            level.max_session_age_minutes is not None
            and context.session_age_s > level.max_session_age_minutes * 60
        ):
            b.fail(ReasonCode.SESSION_TOO_OLD)
        if level.step_up_minutes is not None and context.auth_age_s > level.step_up_minutes * 60:
            b.fail(ReasonCode.STEP_UP_REQUIRED)
        burst = policy.denial_burst
        if (
            file.classification.rank >= burst.from_classification.rank
            and context.recent_denials >= burst.threshold
        ):
            b.fail(ReasonCode.DENIAL_BURST)
        if (
            action is Action.DOWNLOAD
            and level.max_downloads_per_hour is not None
            and context.recent_downloads >= level.max_downloads_per_hour
        ):
            b.fail(ReasonCode.RATE_LIMIT)
        if action is Action.VIEW and not level.preview_allowed:
            b.fail(ReasonCode.PREVIEW_NOT_ALLOWED)

    return b.build(
        effective,
        source=sources.get(required),
        discoverable=is_discoverable(policy, principal, file, grants),
    )


# --- sharing, revocation, ownership --------------------------------------------------------------


@dataclass(frozen=True)
class AccountFacts:
    """The other account in a sharing or ownership operation."""

    id: uuid.UUID
    role: Role
    is_active: bool


def _eligible(policy: AccessPolicy, account: AccountFacts) -> bool:
    role = policy.roles.get(account.role)
    return account.is_active and role is not None and role.metadata_visibility != "none"


def decide_grant(
    policy: AccessPolicy,
    principal: Principal,
    file: FileFacts,
    grants: frozenset[Permission],
    context: Context,
    grantee: AccountFacts,
    permissions: frozenset[Permission],
) -> Decision:
    """May ``principal`` give ``grantee`` these permissions on ``file``?

    Two paths: MANAGE_PERMISSIONS (a permission manager, e.g. an admin at any level, may grant
    anything grantable, including to themselves as an audited break-glass), or SHARE (owners
    and holders of SHARE may pass on only permissions they currently hold themselves).
    """
    manage = decide(policy, principal, Action.MANAGE_PERMISSIONS, file, grants, context)
    share = decide(policy, principal, Action.SHARE, file, grants, context)
    base = manage if manage.allowed else share
    b = _Builder(policy, principal, file, Permission.SHARE, dict(base.signals))
    b.reasons.extend(base.reasons)
    level = policy.levels[file.classification]
    is_owner = principal.id == file.owner_id

    if not permissions <= GRANTABLE_PERMISSIONS or (
        Permission.SHARE in permissions and not level.share_is_grantable
    ):
        b.fail(ReasonCode.NOT_GRANTABLE)
    if not _eligible(policy, grantee):
        b.fail(ReasonCode.GRANTEE_NOT_ELIGIBLE)
    if grantee.id == principal.id and not manage.allowed:
        b.fail(ReasonCode.SELF_GRANT)
    if level.share_owner_or_manager_only and not (is_owner or manage.allowed):
        b.fail(ReasonCode.OWNER_OR_MANAGER_ONLY)
    if not manage.allowed and not permissions <= share.effective_permissions:
        b.fail(ReasonCode.SHARE_ESCALATION)
    b.signals["self_grant"] = grantee.id == principal.id
    b.signals["path"] = "MANAGE_PERMISSIONS" if manage.allowed else "SHARE"
    if manage.allowed:
        b.required = Permission.MANAGE_PERMISSIONS
    return b.build(
        base.effective_permissions,
        source=base.permission_source,
        discoverable=base.discoverable,
        allow_rule=(
            "sharing.manage_permissions" if manage.allowed else "sharing.subset_of_own_permissions"
        ),
    )


def decide_role_grant(
    policy: AccessPolicy,
    principal: Principal,
    file: FileFacts,
    grants: frozenset[Permission],
    context: Context,
    role: Role,
    permissions: frozenset[Permission],
) -> Decision:
    """May ``principal`` give every user with ``role`` these permissions on ``file``?

    A role grant reaches many people at once, so only a permission manager may create it
    (SHARE is not enough), never for the ingestor role, and never where the classification
    forbids role grants (HIGHLY_RESTRICTED by default).
    """
    manage = decide(policy, principal, Action.MANAGE_PERMISSIONS, file, grants, context)
    b = _Builder(policy, principal, file, Permission.MANAGE_PERMISSIONS, dict(manage.signals))
    b.reasons.extend(manage.reasons)
    level = policy.levels[file.classification]
    target = policy.roles.get(role)
    if not level.role_grants_allowed:
        b.fail(ReasonCode.ROLE_GRANT_NOT_ALLOWED)
    if not permissions <= GRANTABLE_PERMISSIONS or (
        Permission.SHARE in permissions and not level.share_is_grantable
    ):
        b.fail(ReasonCode.NOT_GRANTABLE)
    if target is None or target.metadata_visibility == "none":
        b.fail(ReasonCode.GRANTEE_NOT_ELIGIBLE)
    b.signals["includes_self"] = role is principal.role
    b.signals["path"] = "MANAGE_PERMISSIONS"
    return b.build(
        manage.effective_permissions,
        source=manage.permission_source,
        discoverable=manage.discoverable,
        allow_rule="sharing.role_grant_requires_manage_permissions",
    )


def decide_revoke(
    policy: AccessPolicy,
    principal: Principal,
    file: FileFacts,
    grants: frozenset[Permission],
    context: Context,
    granted_by: uuid.UUID,
) -> Decision:
    """Revoking a grant: a permission manager, the file's owner, or the grantor (still holding
    SHARE) may do it. Nobody else, including the grantee of a different grant."""
    manage = decide(policy, principal, Action.MANAGE_PERMISSIONS, file, grants, context)
    if manage.allowed:
        return manage
    share = decide(policy, principal, Action.SHARE, file, grants, context)
    b = _Builder(policy, principal, file, Permission.SHARE, dict(share.signals))
    b.reasons.extend(share.reasons)
    if principal.id not in (file.owner_id, granted_by):
        b.fail(ReasonCode.NOT_GRANTOR)
    return b.build(
        share.effective_permissions,
        source=share.permission_source,
        discoverable=share.discoverable,
        allow_rule="sharing.revoke_by_grantor_owner_or_manager",
    )


def decide_transfer(
    policy: AccessPolicy,
    principal: Principal,
    file: FileFacts,
    grants: frozenset[Permission],
    context: Context,
    new_owner: AccountFacts,
) -> Decision:
    """Ownership transfer needs MANAGE_PERMISSIONS; the new owner must be another eligible user."""
    manage = decide(policy, principal, Action.MANAGE_PERMISSIONS, file, grants, context)
    b = _Builder(policy, principal, file, Permission.MANAGE_PERMISSIONS, dict(manage.signals))
    b.reasons.extend(manage.reasons)
    if not _eligible(policy, new_owner):
        b.fail(ReasonCode.GRANTEE_NOT_ELIGIBLE)
    if new_owner.id == file.owner_id:
        b.fail(ReasonCode.ALREADY_OWNER)
    return b.build(
        manage.effective_permissions,
        source=manage.permission_source,
        discoverable=manage.discoverable,
        allow_rule="ownership.transfer_requires_manage_permissions",
    )


def update_actions(
    current: Classification,
    new: Classification | None,
    renamed: bool,
    description_changed: bool,
) -> list[Action]:
    """Which actions a metadata change needs (§10.3): renaming needs RENAME; editing the
    description or raising the classification needs UPDATE; lowering it needs
    MANAGE_PERMISSIONS (owners cannot launder a file by downgrading it)."""
    actions: list[Action] = []
    downgrade = new is not None and new.rank < current.rank
    if renamed:
        actions.append(Action.RENAME)
    if description_changed or (new is not None and new is not current and not downgrade):
        actions.append(Action.UPDATE)
    if downgrade:
        actions.append(Action.MANAGE_PERMISSIONS)
    return actions
