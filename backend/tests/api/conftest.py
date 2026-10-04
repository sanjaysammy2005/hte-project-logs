"""API test fixtures. Database tests use TEST_DATABASE_URL (the tracelock_test database)."""

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.db.session import build_engine, get_engine
from app.main import app


@pytest.fixture(scope="session")
def test_engine() -> Iterator[Engine]:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.fail(
            "TEST_DATABASE_URL is not set; run tests via `docker compose run --rm backend pytest`."
        )
    engine = build_engine(url, connect_timeout_seconds=3)
    yield engine
    engine.dispose()


@pytest.fixture
def client(test_engine: Engine) -> Iterator[TestClient]:
    app.dependency_overrides[get_engine] = lambda: test_engine
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
