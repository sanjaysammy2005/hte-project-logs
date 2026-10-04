"""Operator login/logout. Each is recorded as real audit events in the system stream (Q13):

    success: LOGIN, AUTHENTICATION (session = the token's session id)
    failure: LOGIN_FAILED (sessionless)
    logout:  LOGOUT

A token is accepted only while its system-stream session is open, so logout revokes it.
Callers own the transaction and must commit.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import verify_password
from app.db.models import SYSTEM_STREAM_NAME, AuditEvent, LogStream, Operator
from app.ingestion.service import EventInput, append_event
from app.provenance.rules import TransitionRules


def get_system_stream(db: Session) -> LogStream:
    return db.scalars(select(LogStream).where(LogStream.name == SYSTEM_STREAM_NAME)).one()


def login(
    db: Session, username: str, password: str, ip_address: str | None, rules: TransitionRules
) -> tuple[Operator, str] | None:
    """Return (operator, session_id) on success, None on failure."""
    operator = db.scalars(select(Operator).where(Operator.username == username)).first()
    usable = operator is not None and operator.is_active
    ok = verify_password(password, operator.password_hash if usable and operator else None)
    stream = get_system_stream(db)
    context = {"ip_address": ip_address}

    if not ok or operator is None:
        failed = EventInput(None, None, "LOGIN_FAILED", {**context, "username": username})
        append_event(db, stream, failed, rules)
        return None

    session_id = f"S-{uuid.uuid4().hex}"
    for event_type, payload in (
        ("LOGIN", context),
        ("AUTHENTICATION", {"method": "password", "outcome": "success"}),
    ):
        result = append_event(
            db, stream, EventInput(username, session_id, event_type, payload), rules
        )
        if not result.accepted:  # pragma: no cover - a fresh random session cannot violate
            raise RuntimeError("system-stream login rejected by provenance policy")
    return operator, session_id


def logout(db: Session, operator: Operator, session_id: str, rules: TransitionRules) -> bool:
    event = EventInput(operator.username, session_id, "LOGOUT", {})
    return append_event(db, get_system_stream(db), event, rules).accepted


def session_is_open(db: Session, session_id: str) -> bool:
    latest = db.scalars(
        select(AuditEvent.event_type)
        .join(LogStream, LogStream.id == AuditEvent.stream_id)
        .where(LogStream.name == SYSTEM_STREAM_NAME, AuditEvent.session_id == session_id)
        .order_by(AuditEvent.session_seq.desc())
        .limit(1)
    ).first()
    return latest is not None and latest != "LOGOUT"
