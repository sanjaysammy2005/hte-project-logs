"""Database engine creation, request-scoped sessions and connectivity check."""

import logging
from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def build_engine(url: str, connect_timeout_seconds: int) -> Engine:
    return create_engine(
        url,
        pool_pre_ping=True,
        connect_args={"connect_timeout": connect_timeout_seconds},
    )


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    return build_engine(
        settings.database_url.get_secret_value(), settings.db_connect_timeout_seconds
    )


def get_db(engine: Annotated[Engine, Depends(get_engine)]) -> Iterator[Session]:
    with Session(engine, expire_on_commit=False) as session:
        yield session


def check_database(engine: Engine) -> bool:
    """Return True if a trivial query succeeds."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError as exc:
        # Log only the exception type: driver messages can include connection details.
        logger.warning("Database health check failed: %s", type(exc).__name__)
        return False
