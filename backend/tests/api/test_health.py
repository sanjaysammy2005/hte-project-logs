"""T1.1: health endpoint reports database reachability."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.db.session import build_engine, get_engine
from app.main import app


def test_health_ok_when_database_reachable(client: TestClient) -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


@pytest.fixture
def unreachable_engine() -> Iterator[Engine]:
    # Port 1 on localhost has nothing listening, so the connection is refused quickly.
    engine = build_engine(
        "postgresql+psycopg://nobody:nopassword@127.0.0.1:1/none", connect_timeout_seconds=1
    )
    yield engine
    engine.dispose()


def test_health_503_when_database_unreachable(unreachable_engine: Engine) -> None:
    app.dependency_overrides[get_engine] = lambda: unreachable_engine
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/health")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "database": "unavailable"}
