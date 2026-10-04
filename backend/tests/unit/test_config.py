"""T1.2: settings come from the environment; missing required values fail; secrets stay hidden."""

import logging

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.db.session import build_engine, check_database


def test_settings_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db:5432/x")
    monkeypatch.setenv("APP_ENV", "test")

    settings = Settings()

    assert settings.database_url.get_secret_value() == "postgresql+psycopg://u:p@db:5432/x"
    assert settings.app_env == "test"


def test_missing_database_url_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValidationError):
        Settings()


def test_database_password_not_exposed_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:sup3r-secret@db:5432/x")

    settings = Settings()

    assert "sup3r-secret" not in repr(settings)
    assert "sup3r-secret" not in str(settings.model_dump())


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
