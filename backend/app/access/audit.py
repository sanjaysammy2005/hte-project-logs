"""Access-decision and file audit events in the TraceLock pipeline (ZERO_TRUST_FILE_MODULE §13).

There is no separate log. Every file event is appended with ``ingestion.append_event`` to the
``system`` stream, inside the acting user's chained login session (the token's session id),
so it is context-enriched, hash-chained, Merkle-batched and provenance-checked exactly like
LOGIN and AUTHENTICATION. The payload below becomes part of E_n and is therefore hashed.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.access.model import Action, Classification, Role
from app.access.policy import Decision, Principal
from app.access.policy_file import AccessPolicy
from app.auth.service import get_system_stream
from app.db.models import AuditEvent, Operator
from app.ingestion.service import EventInput, append_event
from app.provenance.rules import TransitionRules

REDACTED = "[redacted]"


@dataclass(frozen=True)
class Actor:
    """Who is asking, from which chained session, and from where."""

    operator: Operator
    session_id: str
    ip_address: str | None
    request_id: str

    @property
    def principal(self) -> Principal:
        op = self.operator
        return Principal(op.id, op.username, Role(op.role), op.department, op.is_active)


@dataclass(frozen=True)
class AuditTarget:
    """What the event is about. ``classification`` is None when the file does not exist."""

    file_id: uuid.UUID
    classification: Classification | None
    name: str | None


class AuditRejectedError(Exception):
    """The provenance policy refused the event (Q6); a SECURITY_VIOLATION was stored instead."""

    def __init__(self, chain_index: int) -> None:
        super().__init__("audit event rejected by the provenance policy")
        self.chain_index = chain_index


def audit_name(policy: AccessPolicy, classification: Classification | None, name: str | None):
    """The filename as written into the immutable chain: redacted for RESTRICTED+ (Z11)."""
    if name is None or classification is None:
        return None
    return REDACTED if policy.levels[classification].redact_name_in_audit else name


def payload(
    policy: AccessPolicy,
    actor: Actor,
    target: AuditTarget | None,
    action: Action,
    verdict: Decision | None,
    **extra: Any,
) -> dict[str, Any]:
    """The hashed payload of a file event. ``verdict`` is the policy decision, if one was made;
    events without one (integrity failures, metadata views) pass their own ``decision=...``."""
    body: dict[str, Any] = {
        "action": action.value,
        "file_id": str(target.file_id) if target else None,
        "classification": target.classification.value if target and target.classification else None,
        "filename": audit_name(policy, target.classification, target.name) if target else None,
        "policy": policy.identifier,
        "ip_address": actor.ip_address,
        "request_id": actor.request_id,
    }
    if verdict is not None:
        body.update(
            decision=verdict.effect,
            reason_code=verdict.reason.value,
            reasons=[r.value for r in verdict.reasons],
            required_permission=(
                verdict.required_permission.value if verdict.required_permission else None
            ),
            permission_source=verdict.permission_source,
            signals={**verdict.signals, "discoverable": verdict.discoverable},
        )
    body.update(extra)
    return body


def record(
    db: Session,
    rules: TransitionRules,
    actor: Actor,
    event_type: str,
    body: dict[str, Any],
    clock: Callable[[], datetime],
) -> AuditEvent:
    """Append one chained event in the actor's session. The caller commits.

    ``clock`` is the same time source the policy used for this request, so event timestamps
    and policy windows (session age, step-up) agree.
    """
    event = EventInput(actor.operator.username, actor.session_id, event_type, body)
    result = append_event(db, get_system_stream(db), event, rules, clock=clock)
    if not result.accepted:
        raise AuditRejectedError(result.event.chain_index)
    return result.event
