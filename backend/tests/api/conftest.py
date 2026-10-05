"""Fixtures for DB-backed tests. They use TEST_DATABASE_URL (the tracelock_test database)."""

import os
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from app.api.deps import get_clock, get_storage
from app.core.config import get_settings
from app.core.security import hash_password
from app.db.models import SYSTEM_STREAM_NAME, LogStream, Operator
from app.db.session import build_engine, get_engine
from app.files.storage import LocalFileStorage
from app.main import app

PASSWORD = "correct-horse-battery"


def alembic_config(url: str) -> Config:
    config = Config("alembic.ini")
    config.attributes["database_url"] = url
    return config


@pytest.fixture(scope="session")
def test_database_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.fail(
            "TEST_DATABASE_URL is not set; run tests via `docker compose run --rm backend pytest`."
        )
    return url


@pytest.fixture(scope="session")
def test_engine(test_database_url: str) -> Iterator[Engine]:
    """Rebuild the test schema from scratch once per run (also exercises downgrade/upgrade)."""
    config = alembic_config(test_database_url)
    engine = build_engine(test_database_url, connect_timeout_seconds=3)
    # Empty the previous run's data first: migration 0005 refuses to downgrade while
    # manager/employee accounts exist (by design), and a partial run may leave some behind.
    with engine.begin() as conn:
        tables = (
            conn.execute(
                text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
                    " AND tablename <> 'alembic_version'"
                )
            )
            .scalars()
            .all()
        )
        if tables:
            conn.execute(text(f"TRUNCATE {', '.join(tables)} RESTART IDENTITY CASCADE"))
    engine.dispose()
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    engine = build_engine(test_database_url, connect_timeout_seconds=3)
    yield engine
    engine.dispose()


@pytest.fixture(autouse=True)
def clean_database(request: pytest.FixtureRequest) -> None:
    """Empty the tables before each DB test; the seeded system stream is kept."""
    if "test_engine" not in request.fixturenames:
        return
    engine: Engine = request.getfixturevalue("test_engine")
    with engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE file_permissions, file_versions, files,"
                " experiment_runs, tamper_scenarios, verification_findings,"
                " verification_runs, batches,"
                " audit_events,"
                " operators RESTART IDENTITY"
            )
        )
        conn.execute(text("DELETE FROM log_streams WHERE name <> :n"), {"n": SYSTEM_STREAM_NAME})


@pytest.fixture
def db(test_engine: Engine) -> Iterator[Session]:
    with Session(test_engine, expire_on_commit=False) as session:
        yield session


@pytest.fixture
def client(test_engine: Engine) -> Iterator[TestClient]:
    app.dependency_overrides[get_engine] = lambda: test_engine
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def make_operator(db: Session) -> Callable[..., Operator]:
    def factory(
        username: str, role: str, password: str = PASSWORD, department: str | None = None
    ) -> Operator:
        operator = Operator(
            username=username,
            password_hash=hash_password(password),
            role=role,
            department=department,
        )
        db.add(operator)
        db.commit()
        return operator

    return factory


@pytest.fixture
def login(client: TestClient, make_operator: Callable[..., Operator]) -> Callable[[str], dict]:
    """Create an operator with the given role and return its Authorization header."""

    def factory(role: str) -> dict[str, str]:
        make_operator(f"{role}-user", role)
        response = client.post(
            "/api/v1/auth/login", json={"username": f"{role}-user", "password": PASSWORD}
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return factory


@pytest.fixture
def system_stream(db: Session) -> LogStream:
    return db.scalars(select(LogStream).where(LogStream.name == SYSTEM_STREAM_NAME)).one()


# --- file module fixtures ----------------------------------------------------------------------


@pytest.fixture
def file_storage(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LocalFileStorage]:
    """An isolated storage root per test; the API uses it instead of the Docker volume."""
    storage = LocalFileStorage(tmp_path_factory.mktemp("filestore"))
    app.dependency_overrides[get_storage] = lambda: storage
    yield storage
    app.dependency_overrides.pop(get_storage, None)


class Clock:
    """Wall clock with an adjustable offset, for session-age and step-up windows."""

    def __init__(self) -> None:
        self.offset = timedelta(0)

    def __call__(self) -> datetime:
        return datetime.now(UTC) + self.offset


@pytest.fixture
def clock() -> Iterator[Clock]:
    value = Clock()
    app.dependency_overrides[get_clock] = lambda: value
    yield value
    app.dependency_overrides.pop(get_clock, None)


@pytest.fixture
def upload_limit(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[int], None]]:
    """Set TRACELOCK_MAX_UPLOAD_BYTES for one test (the middleware reads it too)."""

    def set_limit(max_bytes: int) -> None:
        monkeypatch.setenv("TRACELOCK_MAX_UPLOAD_BYTES", str(max_bytes))
        get_settings.cache_clear()

    yield set_limit
    get_settings.cache_clear()


@dataclass
class User:
    operator: Operator
    headers: dict[str, str]
    password: str = PASSWORD

    @property
    def id(self) -> uuid.UUID:
        return self.operator.id


@pytest.fixture
def sign_in(client: TestClient, make_operator: Callable[..., Operator]) -> Callable[..., User]:
    """Create a user and sign in through the API (a real chained session)."""

    def factory(username: str, role: str, department: str | None = "Engineering") -> User:
        operator = make_operator(username, role, department=department)
        response = client.post(
            "/api/v1/auth/login", json={"username": username, "password": PASSWORD}
        )
        assert response.status_code == 200, response.text
        return User(operator, {"Authorization": f"Bearer {response.json()['access_token']}"})

    return factory
