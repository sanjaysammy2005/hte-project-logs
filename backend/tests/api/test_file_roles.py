"""ZT-F6: the new manager/employee roles reuse the existing auth stack and gain no audit access."""

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditEvent, LogStream
from app.provenance.rules import load_rules
from app.verification.engine import verify_stream

API = "/api/v1"
STREAM = "00000000-0000-4000-8000-000000000001"

READER_ADMIN_INGESTOR_ENDPOINTS = [
    ("get", f"{API}/streams", None),
    ("get", f"{API}/streams/{STREAM}", None),
    ("get", f"{API}/streams/{STREAM}/events", None),
    ("get", f"{API}/streams/{STREAM}/batches", None),
    ("post", f"{API}/streams/{STREAM}/verify", None),
    ("post", f"{API}/streams", {"name": "s"}),
    ("post", f"{API}/streams/{STREAM}/events", {"event_type": "LOGIN_FAILED"}),
    ("post", f"{API}/operators", {"username": "x", "password": "p" * 12, "role": "admin"}),
    ("get", f"{API}/experiments", None),
]


@pytest.mark.parametrize("role", ["manager", "employee"])
@pytest.mark.parametrize(("method", "url", "body"), READER_ADMIN_INGESTOR_ENDPOINTS)
def test_file_roles_have_no_audit_or_admin_access(
    client: TestClient, login: Callable, role: str, method: str, url: str, body: dict | None
) -> None:
    response = client.request(method, url, json=body, headers=login(role))

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.parametrize("role", ["manager", "employee"])
def test_file_roles_sign_in_through_the_chained_session(
    client: TestClient, login: Callable, db: Session, system_stream: LogStream, role: str
) -> None:
    headers = login(role)

    me = client.get(f"{API}/auth/me", headers=headers).json()
    assert me["role"] == role
    events = db.scalars(
        select(AuditEvent.event_type)
        .where(AuditEvent.stream_id == system_stream.id, AuditEvent.actor_user_id == f"{role}-user")
        .order_by(AuditEvent.chain_index)
    ).all()
    assert events == ["LOGIN", "AUTHENTICATION"]
    run, _ = verify_stream(db, system_stream, load_rules())
    assert run.status == "VALID"


def test_admin_can_create_file_role_accounts(client: TestClient, login: Callable) -> None:
    headers = login("admin")
    for role in ("manager", "employee"):
        body = {"username": f"new-{role}", "password": "long-enough-pass", "role": role}
        created = client.post(f"{API}/operators", json=body, headers=headers)
        assert created.status_code == 201 and created.json()["role"] == role


def test_unknown_role_rejected(client: TestClient, login: Callable) -> None:
    body = {"username": "x", "password": "long-enough-pass", "role": "superuser"}
    response = client.post(f"{API}/operators", json=body, headers=login("admin"))
    assert response.status_code == 422
