"""T1.2: settings come from the environment; missing required values fail; secrets stay hidden."""

import logging

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.db.session import build_engine, check_database

SECRET = "x" * 40


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db:5432/x")
    monkeypatch.setenv("JWT_SECRET", SECRET)


def test_settings_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "test")

    settings = Settings()

    assert settings.database_url.get_secret_value() == "postgresql+psycopg://u:p@db:5432/x"
    assert settings.jwt_secret.get_secret_value() == SECRET
    assert settings.app_env == "test"


@pytest.mark.parametrize("variable", ["DATABASE_URL", "JWT_SECRET"])
def test_missing_required_setting_fails(monkeypatch: pytest.MonkeyPatch, variable: str) -> None:
    monkeypatch.delenv(variable, raising=False)

    with pytest.raises(ValidationError):
        Settings()


def test_short_jwt_secret_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SECRET", "too-short")

    with pytest.raises(ValidationError):
        Settings()


def test_secrets_not_exposed_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:sup3r-secret@db:5432/x")

    settings = Settings()

    for text in (repr(settings), str(settings.model_dump())):
        assert "sup3r-secret" not in text
        assert SECRET not in text


def test_failed_health_check_does_not_log_password(caplog: pytest.LogCaptureFixture) -> None:
    engine = build_engine(
        "postgresql+psycopg://nobody:sup3r-secret@127.0.0.1:1/none", connect_timeout_seconds=1
    )
    try:
        with caplog.at_level(logging.DEBUG):
            assert check_database(engine) is False
    finally:
        engine.dispose()

    assert "sup3r-secret" not in caplog.text
