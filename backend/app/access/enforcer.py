"""Policy enforcement point (ZERO_TRUST_FILE_MODULE §9).

``policy.py`` decides; this module enforces. It is the single place that

* gathers the inputs of a decision (identity, role, department, active session, ownership,
  classification, explicit grants, chained context signals, the current time),
* asks the pure policy for a decision,
* records every DENY as a chained ``FILE_ACCESS_DENIED`` event (committed on its own, because the
  operation never runs) and turns it into the HTTP answer: 403 with a full explanation, or 404
  when the caller may not even learn that the file exists,
* records ALLOW decisions for sensitive operations through ``record_allow`` (in the same
  transaction as the change the caller then makes),
* and builds the visibility filter for listings from the same policy.

Services call ``require*`` before touching anything; they contain no authorization rules.
"""

import uuid
from collections.abc import Callable, Iterable
from datetime import datetime
from functools import cached_property
from typing import Any

from sqlalchemy import ColumnElement, Select, and_, false, or_, select, true
from sqlalchemy.orm import Session

from app.access import audit
from app.access.audit import Actor, AuditRejectedError, AuditTarget
from app.access.context import build_context
from app.access.model import Action, Classification, Permission
from app.access.policy import (
    Context,
    Decision,
    FileFacts,
    Principal,
    ReasonCode,
    decide,
    is_discoverable,
)
from app.access.policy_file import AccessPolicy
from app.auth.service import get_system_stream
from app.core.errors import APIError
from app.crypto.canonical import format_timestamp
from app.db.models import AuditEvent, File, FilePermission
from app.provenance.rules import TransitionRules

# Inline rendering is offered only for these types (a content-safety rule, see §16.5).
INLINE_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "pdf"})
FILE_ACTIONS = (
    Action.VIEW,
    Action.DOWNLOAD,
    Action.UPLOAD,
    Action.UPDATE,
    Action.RENAME,
    Action.DELETE,
    Action.RESTORE,
    Action.SHARE,
    Action.VERIFY,
    Action.MANAGE_PERMISSIONS,
)


class PolicyEnforcer:
    def __init__(
        self,
        db: Session,
        policy: AccessPolicy,
        rules: TransitionRules,
        actor: Actor,
        clock: Callable[[], datetime],
    ) -> None:
        self.db = db
        self.policy = policy
        self.rules = rules
        self.actor = actor
        self.clock = clock

    # --- inputs --------------------------------------------------------------------------------

    @property
    def principal(self) -> Principal:
        return self.actor.principal

    @cached_property
    def context(self) -> Context:
        return build_context(
            self.db,
            get_system_stream(self.db),
            self.policy,
            self.actor.operator.username,
            self.actor.session_id,
            self.clock(),
        )

    def grants(self, file_ids: Iterable[uuid.UUID]) -> dict[uuid.UUID, frozenset[Permission]]:
        """The caller's active (unrevoked, unexpired) explicit permissions per file: the union of
        grants to them personally and grants to their role on that file (allows only add up;
        lifecycle, classification and context rules still apply on top)."""
        ids = list(file_ids)
        if not ids:
            return {}
        rows = self.db.execute(
            select(FilePermission.file_id, FilePermission.permissions).where(
                FilePermission.file_id.in_(ids), self._mine(), self._active_grant()
            )
        ).all()
        result: dict[uuid.UUID, frozenset[Permission]] = {}
        for file_id, perms in rows:
            result[file_id] = result.get(file_id, frozenset()) | {Permission(p) for p in perms}
        return result

    def granted_file_ids(self) -> Select:
        """Subquery: files on which the caller holds an active explicit grant."""
        return select(FilePermission.file_id).where(self._mine(), self._active_grant())

    def _mine(self) -> ColumnElement[bool]:
        """Grants that target the caller, personally or through their role."""
        operator = self.actor.operator
        if not operator.is_active:
            return false()
        return or_(
            FilePermission.grantee_id == operator.id, FilePermission.grantee_role == operator.role
        )

    def _active_grant(self) -> ColumnElement[bool]:
        return and_(
            FilePermission.revoked_at.is_(None),
            or_(FilePermission.expires_at.is_(None), FilePermission.expires_at > self.clock()),
        )

    @staticmethod
    def facts(file: File) -> FileFacts:
        return FileFacts(
            file.id,
            Classification(file.classification),
            file.owner_id,
            file.deleted_at is not None,
            file.department,
        )

    @staticmethod
    def target(file: File | None, file_id: uuid.UUID | None = None) -> AuditTarget | None:
        if file is not None:
            return AuditTarget(file.id, Classification(file.classification), file.display_name)
        return AuditTarget(file_id, None, None) if file_id is not None else None

    # --- deciding ------------------------------------------------------------------------------

    def decide(
        self, action: Action, file: File | None, grants: frozenset[Permission] | None = None
    ) -> Decision:
        if file is None:
            return decide(self.policy, self.principal, action, None, context=self.context)
        if grants is None:
            grants = self.grants([file.id]).get(file.id, frozenset())
        return decide(self.policy, self.principal, action, self.facts(file), grants, self.context)

    def file_inputs(self, file: File) -> tuple[FileFacts, frozenset[Permission], Context]:
        """Inputs for the specialised decisions (grant, revoke, transfer) in policy.py."""
        return self.facts(file), self.grants([file.id]).get(file.id, frozenset()), self.context

    def require(self, action: Action, file_id: uuid.UUID | None, file: File | None) -> Decision:
        """Decide; on DENY record it and raise. Returns the ALLOW decision otherwise."""
        decision = self.decide(action, file)
        return self.require_decision(decision, action, self.target(file, file_id))

    def require_decision(
        self, decision: Decision, action: Action, target: AuditTarget | None, **extra: Any
    ) -> Decision:
        if not decision.allowed:
            raise self.deny(action, decision, target, **extra)
        return decision

    def require_visible(self, file_id: uuid.UUID, file: File | None, scope: str) -> File:
        """Metadata access: the caller must be allowed to know the file exists."""
        if file is not None and is_discoverable(
            self.policy,
            self.principal,
            self.facts(file),
            self.grants([file.id]).get(file.id, frozenset()),
        ):
            return file
        raise self.deny(
            Action.VIEW, self.decide(Action.VIEW, file), self.target(file, file_id), scope=scope
        )

    def allowed_actions(
        self, file: File, grants: frozenset[Permission] | None = None
    ) -> list[Action]:
        """What the policy would allow right now. The UI shows only these; it never decides."""
        if grants is None:
            grants = self.grants([file.id]).get(file.id, frozenset())
        return [
            action
            for action in FILE_ACTIONS
            if not (action is Action.VIEW and file.extension not in INLINE_EXTENSIONS)
            and self.decide(action, file, grants).allowed
        ]

    # --- recording -----------------------------------------------------------------------------

    def payload(
        self, target: AuditTarget | None, action: Action, verdict: Decision | None, **extra: Any
    ) -> dict[str, Any]:
        body = audit.payload(self.policy, self.actor, target, action, verdict, **extra)
        if verdict is not None:
            body.update(rule=verdict.rule, rules=list(verdict.rules))
        return body

    def record(self, event_type: str, body: dict[str, Any]) -> AuditEvent:
        try:
            return audit.record(self.db, self.rules, self.actor, event_type, body, self.clock)
        except AuditRejectedError as exc:
            self.db.commit()  # keep the SECURITY_VIOLATION; nothing else is pending
            raise APIError(
                409,
                "AUDIT_REJECTED",
                "The operation was refused because its audit event broke the session's"
                " provenance rules; the attempt was recorded.",
                {"security_event_chain_index": exc.chain_index},
            ) from exc

    def record_allow(
        self,
        event_type: str,
        action: Action,
        decision: Decision,
        target: AuditTarget | None,
        **extra: Any,
    ) -> AuditEvent:
        """Chain an ALLOW decision. The caller makes its change in the same transaction."""
        return self.record(event_type, self.payload(target, action, decision, **extra))

    def deny(
        self, action: Action, decision: Decision, target: AuditTarget | None, **extra: Any
    ) -> APIError:
        """Chain the denial, commit it alone, and return the error to raise."""
        self.db.rollback()  # nothing may be pending except locks; release them
        event = self.record("FILE_ACCESS_DENIED", self.payload(target, action, decision, **extra))
        self.db.commit()
        if not decision.discoverable and target is not None:
            # Identical to a file that does not exist: no classification, no audit reference.
            return APIError(404, "FILE_NOT_FOUND", "File not found")
        code = (
            "STEP_UP_REQUIRED"
            if decision.reason is ReasonCode.STEP_UP_REQUIRED
            else "ACCESS_DENIED"
        )
        classification = target.classification if target else None
        details: dict[str, Any] = {
            "action": action.value,
            "decision": "DENY",
            "reason_code": decision.reason.value,
            "reasons": [r.value for r in decision.reasons],
            "rule": decision.rule,
            "rules": list(decision.rules),
            "policy": decision.policy_id,
            "required_permission": (
                decision.required_permission.value if decision.required_permission else None
            ),
            "classification": classification.value if classification else None,
            "your_role": self.actor.operator.role,
            "your_permissions": sorted(p.value for p in decision.effective_permissions),
            "evaluated_at": format_timestamp(event.event_timestamp),
            "audit": {"stream_id": str(event.stream_id), "chain_index": event.chain_index},
        }
        if code == "STEP_UP_REQUIRED" and classification is not None:
            details["step_up_minutes"] = self.policy.levels[classification].step_up_minutes
        return APIError(403, code, decision.message, details)

    # --- listing -------------------------------------------------------------------------------

    def visibility_clause(self) -> ColumnElement[bool]:
        """SQL form of ``is_discoverable`` for listings. Tested to agree with it file by file."""
        principal = self.principal
        role = self.policy.roles.get(principal.role)
        if role is None or role.metadata_visibility == "none" or not principal.is_active:
            return false()
        if role.metadata_visibility == "all":
            return true()
        me = principal.id
        granted = self.granted_file_ids()
        open_levels = [
            c.value
            for c, perms in role.by_classification.items()
            if perms and c not in role.department_scoped
        ]
        live_reach = [File.classification.in_(open_levels), File.id.in_(granted)]
        scoped_levels = [c.value for c in role.department_scoped if role.by_classification.get(c)]
        if principal.department is not None and scoped_levels:
            live_reach.append(
                and_(
                    File.classification.in_(scoped_levels),
                    File.department == principal.department,
                )
            )
        return or_(File.owner_id == me, and_(File.deleted_at.is_(None), or_(*live_reach)))
