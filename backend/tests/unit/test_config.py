"""T1.2: settings come from the environment; missing required values fail; secrets stay hidden."""

import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.api import deps
from app.api.deps import get_storage
from app.core.config import Settings, get_settings
from app.db.session import build_engine, check_database
from app.files.storage import LocalFileStorage
from app.files.validation import FILE_TYPES

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


# --- ZT-F5: file module settings ---------------------------------------------------------------


def test_file_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    # docker-compose sets these; clear them so the code defaults are what is tested.
    for variable in (
        "TRACELOCK_MAX_UPLOAD_BYTES",
        "TRACELOCK_ALLOWED_EXTENSIONS",
        "TRACELOCK_STORAGE_ROOT",
    ):
        monkeypatch.delenv(variable, raising=False)

    settings = Settings()

    assert settings.max_upload_bytes == 25 * 1024 * 1024
    assert settings.allowed_extensions == frozenset(FILE_TYPES)
    assert settings.storage_root.is_absolute()


def test_file_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRACELOCK_MAX_UPLOAD_BYTES", "1048576")
    monkeypatch.setenv("TRACELOCK_ALLOWED_EXTENSIONS", " PDF, .docx ,png,")
    monkeypatch.setenv("TRACELOCK_STORAGE_ROOT", "/srv/files")

    settings = Settings()

    assert settings.max_upload_bytes == 1048576
    assert settings.allowed_extensions == frozenset({"pdf", "docx", "png"})
    assert str(settings.storage_root) == "/srv/files"


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("TRACELOCK_ALLOWED_EXTENSIONS", "pdf,exe"),  # no content rule for exe
        ("TRACELOCK_ALLOWED_EXTENSIONS", "svg"),
        ("TRACELOCK_ALLOWED_EXTENSIONS", " , "),  # nothing allowed
        ("TRACELOCK_MAX_UPLOAD_BYTES", "0"),
        ("TRACELOCK_MAX_UPLOAD_BYTES", str(2 * 1024**3)),
        ("TRACELOCK_STORAGE_ROOT", "relative/files"),
    ],
)
def test_invalid_file_settings_fail_at_startup(
    monkeypatch: pytest.MonkeyPatch, variable: str, value: str
) -> None:
    monkeypatch.setenv(variable, value)

    with pytest.raises(ValidationError):
        Settings()


def test_non_list_extensions_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(TRACELOCK_ALLOWED_EXTENSIONS=123)


def test_storage_dependency_uses_configured_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TRACELOCK_STORAGE_ROOT", str(tmp_path / "store"))
    get_settings.cache_clear()
    deps._storage.cache_clear()
    try:
        storage = get_storage()
        assert isinstance(storage, LocalFileStorage)
        assert storage.root == (tmp_path / "store").resolve()
    finally:
        get_settings.cache_clear()
        deps._storage.cache_clear()
