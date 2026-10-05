"""Context signals for access decisions, read from the audit chain (ZERO_TRUST_FILE_MODULE §9.3).

Signals are derived from chained events rather than from separate counters, so "what the
policy saw" can be reconstructed from the evidence. They are heuristics for access decisions
and auditing, not threat detection.
"""

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.access.policy import Context
from app.access.policy_file import AccessPolicy
from app.db.models import AuditEvent, LogStream

AUTH_EVENTS = ("AUTHENTICATION", "REAUTHENTICATION")


def _seconds(now: datetime, then: datetime | None) -> int:
    return max(0, int((now - then).total_seconds())) if then is not None else 0


def latest_event_time(
    db: Session, stream: LogStream, session_id: str, types: tuple[str, ...]
) -> datetime | None:
    return db.scalar(
        select(func.max(AuditEvent.event_timestamp)).where(
            AuditEvent.stream_id == stream.id,
            AuditEvent.session_id == session_id,
            AuditEvent.event_type.in_(types),
        )
    )


def _count(db: Session, stream: LogStream, username: str, event_type: str, since: datetime) -> int:
    return (
        db.scalar(
            select(func.count()).where(
                AuditEvent.stream_id == stream.id,
                AuditEvent.event_type == event_type,
                AuditEvent.actor_user_id == username,
                AuditEvent.event_timestamp >= since,
            )
        )
        or 0
    )


def build_context(
    db: Session,
    stream: LogStream,
    policy: AccessPolicy,
    username: str,
    session_id: str,
    now: datetime,
) -> Context:
    started = latest_event_time(db, stream, session_id, ("LOGIN",))
    authenticated = latest_event_time(db, stream, session_id, AUTH_EVENTS)
    window = timedelta(minutes=policy.denial_burst.window_minutes)
    return Context(
        session_age_s=_seconds(now, started),
        auth_age_s=_seconds(now, authenticated),
        recent_denials=_count(db, stream, username, "FILE_ACCESS_DENIED", now - window),
        recent_downloads=_count(db, stream, username, "FILE_DOWNLOAD", now - timedelta(hours=1)),
    )
