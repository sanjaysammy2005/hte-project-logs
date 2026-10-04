"""Operator password hashing (Argon2id) and signed access tokens (JWT, HS256)."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import Settings

_hasher = PasswordHasher()
# Verified against when the username does not exist, so both paths cost the same time.
_DUMMY_HASH = _hasher.hash("tracelock-timing-equaliser")
_ALGORITHM = "HS256"
# Docker Desktop's VM clock was measured stepping backwards by up to ~1.1 s, which made
# freshly issued tokens look "issued in the future". Allow a small skew (also extends expiry).
CLOCK_SKEW_LEEWAY_SECONDS = 10


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


@dataclass(frozen=True)
class TokenClaims:
    operator_id: uuid.UUID
    role: str
    session_id: str  # the operator's session in the system stream


def create_access_token(
    claims: TokenClaims, settings: Settings, now: datetime | None = None
) -> str:
    issued = now or datetime.now(UTC)
    payload = {
        "sub": str(claims.operator_id),
        "role": claims.role,
        "sid": claims.session_id,
        "iat": issued,
        "exp": issued + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret.get_secret_value(), algorithm=_ALGORITHM)


def decode_access_token(token: str, settings: Settings) -> TokenClaims:
    """Raises jwt.InvalidTokenError for bad signatures, expiry, algorithms or claims."""
    payload = jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=[_ALGORITHM],
        leeway=CLOCK_SKEW_LEEWAY_SECONDS,
        options={"require": ["exp", "iat", "sub", "sid", "role"]},
    )
    try:
        return TokenClaims(uuid.UUID(payload["sub"]), str(payload["role"]), str(payload["sid"]))
    except (ValueError, TypeError) as exc:
        raise jwt.InvalidTokenError("malformed claims") from exc
