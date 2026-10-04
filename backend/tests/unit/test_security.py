"""Token clock-skew tolerance and password hashing helpers."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import Settings
from app.core.security import (
    CLOCK_SKEW_LEEWAY_SECONDS,
    TokenClaims,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)

SETTINGS = Settings(database_url="postgresql+psycopg://u:p@h/d", jwt_secret="s" * 40)
CLAIMS = TokenClaims(uuid.uuid4(), "auditor", "S-1")


def test_token_issued_slightly_in_the_future_is_accepted() -> None:
    """Regression: a backward clock step made fresh tokens fail with ImmatureSignatureError."""
    token = create_access_token(CLAIMS, SETTINGS, now=datetime.now(UTC) + timedelta(seconds=2))

    assert decode_access_token(token, SETTINGS) == CLAIMS


def test_token_far_in_the_future_or_expired_is_rejected() -> None:
    future = datetime.now(UTC) + timedelta(seconds=CLOCK_SKEW_LEEWAY_SECONDS + 30)
    expired = datetime.now(UTC) - timedelta(minutes=SETTINGS.access_token_minutes, seconds=30)

    for issued in (future, expired):
        with pytest.raises(jwt.InvalidTokenError):
            decode_access_token(create_access_token(CLAIMS, SETTINGS, now=issued), SETTINGS)


def test_token_with_malformed_subject_is_rejected() -> None:
    token = jwt.encode(
        {
            "sub": "not-a-uuid",
            "role": "admin",
            "sid": "S",
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        SETTINGS.jwt_secret.get_secret_value(),
        algorithm="HS256",
    )

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(token, SETTINGS)


def test_password_verification() -> None:
    stored = hash_password("correct-horse-battery")

    assert verify_password("correct-horse-battery", stored)
    assert not verify_password("wrong", stored)
    assert not verify_password("anything", None)
    assert not verify_password("anything", "not-an-argon2-hash")
