"""Shared FastAPI dependencies: settings, DB session, rules, current operator, role checks."""

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Annotated

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.access.audit import Actor
from app.access.policy_file import AccessPolicy, load_policy
from app.auth.service import get_system_stream, session_is_open
from app.core.config import Settings, get_settings
from app.core.errors import APIError
from app.core.security import decode_access_token, peek_claims
from app.db.models import Operator
from app.db.session import get_db
from app.files.service import FileService
from app.files.storage import LocalFileStorage, StorageBackend
from app.ingestion.service import EventInput, append_event
from app.provenance.rules import TransitionRules, load_rules

logger = logging.getLogger(__name__)
_bearer = HTTPBearer(auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


@lru_cache
def get_rules() -> TransitionRules:
    return load_rules()


RulesDep = Annotated[TransitionRules, Depends(get_rules)]


@lru_cache
def get_policy() -> AccessPolicy:
    """The versioned access policy. Also loaded at startup, so an invalid file stops the app."""
    return load_policy()


PolicyDep = Annotated[AccessPolicy, Depends(get_policy)]


@lru_cache
def _storage() -> StorageBackend:
    return LocalFileStorage(get_settings().storage_root)


def get_storage() -> StorageBackend:
    """The file store. Created on first use, so the API starts even if the volume is missing."""
    try:
        return _storage()
    except OSError as exc:
        logger.error("File storage unavailable: %s", type(exc).__name__)
        raise APIError(503, "STORAGE_UNAVAILABLE", "File storage is unavailable") from exc


StorageDep = Annotated[StorageBackend, Depends(get_storage)]


def get_clock() -> Callable[[], datetime]:
    """Wall clock for policy windows; tests override it to move time forward."""
    return lambda: datetime.now(UTC)


ClockDep = Annotated[Callable[[], datetime], Depends(get_clock)]


@dataclass(frozen=True)
class CurrentOperator:
    operator: Operator
    session_id: str


def _unauthorized(code: str, message: str) -> APIError:
    return APIError(401, code, message)


def get_current_operator(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: DbSession,
    settings: SettingsDep,
) -> CurrentOperator:
    if credentials is None:
        raise _unauthorized("NOT_AUTHENTICATED", "Authentication required")
    try:
        claims = decode_access_token(credentials.credentials, settings)
    except jwt.InvalidTokenError as exc:
        logger.info("Rejected token: %s", type(exc).__name__)  # never log the token itself
        raise _unauthorized("INVALID_TOKEN", "Invalid or expired token") from exc
    operator = db.get(Operator, claims.operator_id)
    if operator is None or not operator.is_active or operator.role != claims.role:
        logger.info("Rejected token: operator missing, inactive or role changed")
        raise _unauthorized("INVALID_TOKEN", "Invalid or expired token")
    if not session_is_open(db, claims.session_id):
        raise _unauthorized("SESSION_ENDED", "Session has ended; log in again")
    return CurrentOperator(operator, claims.session_id)


def require_roles(*roles: str) -> Callable[..., CurrentOperator]:
    def dependency(
        current: Annotated[CurrentOperator, Depends(get_current_operator)],
    ) -> CurrentOperator:
        if current.operator.role not in roles:
            raise APIError(403, "FORBIDDEN", "Your role does not permit this action")
        return current

    return dependency


AnyOperator = Annotated[CurrentOperator, Depends(get_current_operator)]


UNAUTHENTICATED_ACCESS = "UNAUTHENTICATED_ACCESS"


def get_audited_operator(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: DbSession,
    settings: SettingsDep,
    rules: RulesDep,
    clock: ClockDep,
) -> CurrentOperator:
    """Authentication for sensitive (file) endpoints: a rejected token is a DENY decision too,
    so it is chained as a sessionless UNAUTHENTICATED_ACCESS event before the 401.

    The event names the route template (never the raw path), the rejection code and, only when
    the token's signature is valid (expired or logged-out session), the claimed user.
    """
    try:
        return get_current_operator(credentials, db, settings)
    except APIError as exc:
        if exc.status_code != 401:  # pragma: no cover - get_current_operator only raises 401
            raise
        claims = peek_claims(credentials.credentials, settings) if credentials else None
        claimed = db.get(Operator, claims.operator_id) if claims else None
        route = request.scope.get("route")
        payload = {
            "method": request.method,
            "route": getattr(route, "path", None),
            "reason": exc.code,
            "claimed_session_id": claims.session_id if claims and claimed else None,
            "ip_address": request.client.host if request.client else None,
        }
        event = EventInput(
            claimed.username if claimed else None, None, UNAUTHENTICATED_ACCESS, payload
        )
        db.rollback()
        append_event(db, get_system_stream(db), event, rules, clock=clock)
        db.commit()
        raise


AuditedOperator = Annotated[CurrentOperator, Depends(get_audited_operator)]


def get_file_service(
    current: AuditedOperator,
    request: Request,
    db: DbSession,
    storage: StorageDep,
    settings: SettingsDep,
    policy: PolicyDep,
    rules: RulesDep,
    clock: ClockDep,
) -> FileService:
    """A FileService acting for the authenticated caller, in their chained session."""
    actor = Actor(
        operator=current.operator,
        session_id=current.session_id,
        ip_address=request.client.host if request.client else None,
        request_id=uuid.uuid4().hex,
    )
    return FileService(db, storage, settings, policy, rules, actor, clock)


Admin = Annotated[CurrentOperator, Depends(require_roles("admin"))]
Reader = Annotated[CurrentOperator, Depends(require_roles("admin", "auditor"))]
Ingestor = Annotated[CurrentOperator, Depends(require_roles("admin", "ingestor"))]
