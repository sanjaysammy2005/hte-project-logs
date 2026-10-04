"""Application settings, read from environment variables.

Secrets (such as the database password inside DATABASE_URL) are held as SecretStr so they
are never printed in reprs, logs or error messages.
"""

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    app_env: str = "development"
    # Required: startup fails if DATABASE_URL is missing.
    database_url: SecretStr
    # Used only by the test suite (see tests/conftest.py).
    test_database_url: SecretStr | None = None
    # Keeps the health check fast when the database is unreachable.
    db_connect_timeout_seconds: int = 3


@lru_cache
def get_settings() -> Settings:
    return Settings()
