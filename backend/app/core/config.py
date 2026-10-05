"""Application settings, read from environment variables.

Secrets (the database password inside DATABASE_URL, the JWT signing key) are held as
SecretStr so they are never printed in reprs, logs or error messages.
"""

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.files.validation import FILE_TYPES

DEFAULT_ALLOWED_EXTENSIONS = frozenset(FILE_TYPES)
MAX_UPLOAD_LIMIT = 1024**3  # sanity ceiling for the configurable limit (1 GiB)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    app_env: str = "development"
    # Required: startup fails if DATABASE_URL or JWT_SECRET is missing.
    database_url: SecretStr
    jwt_secret: SecretStr
    # Used only by the test suite (see tests/api/conftest.py).
    test_database_url: SecretStr | None = None
    # Keeps the health check fast when the database is unreachable.
    db_connect_timeout_seconds: int = 3
    access_token_minutes: int = Field(default=30, ge=1, le=24 * 60)
    # The tamper lab mutates (cloned) data, so it is off unless explicitly enabled.
    lab_enabled: bool = Field(default=False, validation_alias="TRACELOCK_LAB_ENABLED")

    # File module (ZERO_TRUST_FILE_MODULE §6, §16). The storage root is only ever combined with
    # server-generated keys, never with user input.
    storage_root: Path = Field(
        default=Path("/var/lib/tracelock/files"), validation_alias="TRACELOCK_STORAGE_ROOT"
    )
    max_upload_bytes: int = Field(
        default=25 * 1024 * 1024,
        ge=1,
        le=MAX_UPLOAD_LIMIT,
        validation_alias="TRACELOCK_MAX_UPLOAD_BYTES",
    )
    # Comma-separated in the environment, e.g. "pdf,docx,png". Each must have a content rule.
    allowed_extensions: Annotated[frozenset[str], NoDecode] = Field(
        default=DEFAULT_ALLOWED_EXTENSIONS, validation_alias="TRACELOCK_ALLOWED_EXTENSIONS"
    )

    @field_validator("allowed_extensions", mode="before")
    @classmethod
    def _parse_extensions(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.split(",")
        if isinstance(value, list | tuple | set | frozenset):
            cleaned = {str(v).strip().lstrip(".").lower() for v in value} - {""}
            unknown = cleaned - set(FILE_TYPES)
            if unknown:
                raise ValueError(
                    f"no content-validation rule for: {', '.join(sorted(unknown))}"
                    f" (supported: {', '.join(sorted(FILE_TYPES))})"
                )
            if not cleaned:
                raise ValueError("at least one file extension must be allowed")
            return frozenset(cleaned)
        return value

    @field_validator("storage_root")
    @classmethod
    def _absolute_root(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("TRACELOCK_STORAGE_ROOT must be an absolute path")
        return value

    @field_validator("jwt_secret")
    @classmethod
    def _secret_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
