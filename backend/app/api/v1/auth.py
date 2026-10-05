"""Operator login, logout and identity; operator creation."""

from fastapi import APIRouter, Request, Response, status
from sqlalchemy import select

from app.api.deps import Admin, AnyOperator, ClockDep, DbSession, RulesDep, SettingsDep
from app.api.v1.schemas import LoginIn, OperatorCreate, OperatorOut, ReauthIn, ReauthOut, TokenOut
from app.auth import service
from app.core.errors import APIError
from app.core.security import TokenClaims, create_access_token, hash_password
from app.crypto.canonical import CanonicalizationError, format_timestamp
from app.db.models import Operator

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=TokenOut)
def login(
    body: LoginIn, request: Request, db: DbSession, rules: RulesDep, settings: SettingsDep
) -> TokenOut:
    ip = request.client.host if request.client else None
    try:
        result = service.login(db, body.username, body.password, ip, rules)
    except CanonicalizationError as exc:
        db.rollback()
        raise APIError(422, "INVALID_CREDENTIALS_FORMAT", "Username cannot be recorded") from exc
    db.commit()  # persists LOGIN_FAILED too
    if result is None:
        raise APIError(401, "INVALID_CREDENTIALS", "Invalid username or password")
    operator, session_id = result
    token = create_access_token(TokenClaims(operator.id, operator.role, session_id), settings)
    return TokenOut(
        access_token=token, expires_in=settings.access_token_minutes * 60, role=operator.role
    )


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(current: AnyOperator, db: DbSession, rules: RulesDep) -> Response:
    service.logout(db, current.operator, current.session_id, rules)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/auth/reauthenticate", response_model=ReauthOut)
def reauthenticate(
    body: ReauthIn, current: AnyOperator, db: DbSession, rules: RulesDep, clock: ClockDep
) -> ReauthOut:
    """Re-enter the password to satisfy step-up requirements (e.g. HIGHLY_RESTRICTED files)."""
    event = service.reauthenticate(
        db, current.operator, current.session_id, body.password, rules, clock
    )
    db.commit()  # the failed attempt is evidence too
    if event is None:
        # 403, not 401: the session itself stays valid; only the step-up failed.
        raise APIError(403, "REAUTHENTICATION_FAILED", "Password not accepted")
    return ReauthOut(
        authenticated_at=format_timestamp(event.event_timestamp), chain_index=event.chain_index
    )


@router.get("/auth/me", response_model=OperatorOut)
def me(current: AnyOperator) -> OperatorOut:
    op = current.operator
    return OperatorOut(id=op.id, username=op.username, role=op.role)


@router.post("/operators", response_model=OperatorOut, status_code=status.HTTP_201_CREATED)
def create_operator(body: OperatorCreate, _: Admin, db: DbSession) -> OperatorOut:
    if db.scalars(select(Operator.id).where(Operator.username == body.username)).first():
        raise APIError(409, "USERNAME_TAKEN", "That username is already in use")
    operator = Operator(
        username=body.username, password_hash=hash_password(body.password), role=body.role
    )
    db.add(operator)
    db.commit()
    return OperatorOut(id=operator.id, username=operator.username, role=operator.role)
