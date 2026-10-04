"""Application settings, read from environment variables.

Secrets (the database password inside DATABASE_URL, the JWT signing key) are held as
SecretStr so they are never printed in reprs, logs or error messages.
"""

from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    @field_validator("jwt_secret")
    @classmethod
    def _secret_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
