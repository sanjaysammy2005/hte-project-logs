"""Shared FastAPI dependencies: settings, DB session, rules, current operator, role checks."""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated

import jwt
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.auth.service import session_is_open
from app.core.config import Settings, get_settings
from app.core.errors import APIError
from app.core.security import decode_access_token
from app.db.models import Operator
from app.db.session import get_db
from app.provenance.rules import TransitionRules, load_rules

logger = logging.getLogger(__name__)
_bearer = HTTPBearer(auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


@lru_cache
def get_rules() -> TransitionRules:
    return load_rules()


RulesDep = Annotated[TransitionRules, Depends(get_rules)]


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
Admin = Annotated[CurrentOperator, Depends(require_roles("admin"))]
Reader = Annotated[CurrentOperator, Depends(require_roles("admin", "auditor"))]
Ingestor = Annotated[CurrentOperator, Depends(require_roles("admin", "ingestor"))]
