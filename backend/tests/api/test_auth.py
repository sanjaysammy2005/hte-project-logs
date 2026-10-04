"""T5.6–T5.8: authentication, roles, tokens; logins recorded in the system stream."""

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import TokenClaims, create_access_token
from app.crypto.chain import verify_chain
from app.db.models import AuditEvent, LogStream, Operator
from app.ingestion.service import to_chained
from app.provenance.checks import check_provenance
from app.provenance.rules import load_rules
from tests.api.conftest import PASSWORD

API = "/api/v1"


def _system_events(db: Session, stream: LogStream) -> list[AuditEvent]:
    db.expire_all()
    return list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.stream_id == stream.id)
            .order_by(AuditEvent.chain_index)
        )
    )


def test_login_records_login_and_authentication_events(
    client: TestClient, login: Callable, db: Session, system_stream: LogStream
) -> None:
    headers = login("auditor")

    events = _system_events(db, system_stream)
    assert [e.event_type for e in events] == ["LOGIN", "AUTHENTICATION"]
    assert {e.actor_user_id for e in events} == {"auditor-user"}
    assert client.get(f"{API}/auth/me", headers=headers).json()["role"] == "auditor"


def test_logout_records_event_and_revokes_token(
    client: TestClient, login: Callable, db: Session, system_stream: LogStream
) -> None:
    headers = login("auditor")

    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 204

    response = client.get(f"{API}/auth/me", headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "SESSION_ENDED"
    chained = [to_chained(e) for e in _system_events(db, system_stream)]
    assert [c.record.event_type for c in chained] == ["LOGIN", "AUTHENTICATION", "LOGOUT"]
    assert verify_chain(chained).is_valid
    assert check_provenance(chained, load_rules()).is_valid


def test_failed_login_is_generic_recorded_and_leaks_no_password(
    client: TestClient,
    make_operator: Callable,
    db: Session,
    system_stream: LogStream,
    caplog: pytest.LogCaptureFixture,
) -> None:
    make_operator("alice", "admin")
    with caplog.at_level(logging.DEBUG):
        wrong = client.post(
            f"{API}/auth/login", json={"username": "alice", "password": "wrong-Pa55word!"}
        )
        unknown = client.post(
            f"{API}/auth/login", json={"username": "nobody", "password": "wrong-Pa55word!"}
        )

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()  # no hint whether the username exists
    events = _system_events(db, system_stream)
    assert [(e.event_type, e.event_payload["username"]) for e in events] == [
        ("LOGIN_FAILED", "alice"),
        ("LOGIN_FAILED", "nobody"),
    ]
    assert "wrong-Pa55word!" not in str([e.event_payload for e in events])
    assert "wrong-Pa55word!" not in caplog.text


def test_validation_errors_do_not_echo_submitted_password(client: TestClient) -> None:
    response = client.post(f"{API}/auth/login", json={"username": "", "password": "s3cret-val"})

    assert response.status_code == 422
    assert "s3cret-val" not in response.text


def test_passwords_stored_as_argon2id(make_operator: Callable, db: Session) -> None:
    operator = make_operator("bob", "auditor")

    stored = db.get(Operator, operator.id)
    assert stored is not None
    assert stored.password_hash.startswith("$argon2id$")
    assert PASSWORD not in stored.password_hash


def test_inactive_operator_cannot_log_in(
    client: TestClient, make_operator: Callable, db: Session
) -> None:
    operator = make_operator("carol", "admin")
    operator.is_active = False
    db.commit()

    response = client.post(f"{API}/auth/login", json={"username": "carol", "password": PASSWORD})

    assert response.status_code == 401


# --- T5.8 tokens -----------------------------------------------------------------------------


def _token_for(client: TestClient, login: Callable) -> tuple[str, dict]:
    headers = login("admin")
    me = client.get(f"{API}/auth/me", headers=headers).json()
    return headers["Authorization"].removeprefix("Bearer "), me


def test_expired_token_rejected(client: TestClient, login: Callable, db: Session) -> None:
    token, me = _token_for(client, login)
    claims = jwt.decode(token, options={"verify_signature": False})
    expired = create_access_token(
        TokenClaims(me["id"], "admin", claims["sid"]),  # type: ignore[arg-type]
        get_settings(),
        now=datetime.now(UTC) - timedelta(hours=2),
    )

    response = client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {expired}"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_TOKEN"


@pytest.mark.parametrize("attack", ["bad_signature", "alg_none", "garbage", "role_escalation"])
def test_tampered_tokens_rejected(client: TestClient, login: Callable, attack: str) -> None:
    token, _ = _token_for(client, login)
    claims = jwt.decode(token, options={"verify_signature": False})
    forged = {
        "bad_signature": jwt.encode(claims, "x" * 40, algorithm="HS256"),
        "alg_none": jwt.encode(claims, None, algorithm="none"),
        "garbage": "not.a.token",
        "role_escalation": "",
    }[attack]
    if attack == "role_escalation":
        # Correctly signed, but the role claim differs from the operator's real role.
        login_headers = login("auditor")
        auditor_token = login_headers["Authorization"].removeprefix("Bearer ")
        c = jwt.decode(auditor_token, options={"verify_signature": False})
        forged = jwt.encode(
            {**c, "role": "admin"}, get_settings().jwt_secret.get_secret_value(), algorithm="HS256"
        )

    response = client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {forged}"})

    assert response.status_code == 401


# --- T5.6 roles ------------------------------------------------------------------------------

STREAM = "00000000-0000-4000-8000-000000000001"  # system stream id (exists in every DB)
PROTECTED = [
    ("get", f"{API}/auth/me", None),
    ("post", f"{API}/auth/logout", None),
    ("post", f"{API}/operators", {"username": "x", "password": "p" * 12, "role": "auditor"}),
    ("get", f"{API}/streams", None),
    ("post", f"{API}/streams", {"name": "s"}),
    ("get", f"{API}/streams/{STREAM}", None),
    ("get", f"{API}/streams/{STREAM}/events", None),
    ("get", f"{API}/streams/{STREAM}/events/1", None),
    ("get", f"{API}/streams/{STREAM}/sessions/S1", None),
    ("post", f"{API}/streams/{STREAM}/events", {"event_type": "LOGIN_FAILED"}),
]


@pytest.mark.parametrize(("method", "url", "body"), PROTECTED)
def test_unauthenticated_requests_get_401(
    client: TestClient, method: str, url: str, body: dict | None
) -> None:
    response = client.request(method, url, json=body)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json()["error"]["code"] == "NOT_AUTHENTICATED"


@pytest.mark.parametrize(
    ("role", "method", "url", "body"),
    [
        ("auditor", "post", f"{API}/streams", {"name": "s"}),
        (
            "auditor",
            "post",
            f"{API}/operators",
            {"username": "x", "password": "p" * 12, "role": "admin"},
        ),
        ("auditor", "post", f"{API}/streams/{STREAM}/events", {"event_type": "LOGIN_FAILED"}),
        ("ingestor", "get", f"{API}/streams", None),
        ("ingestor", "get", f"{API}/streams/{STREAM}/events", None),
        ("ingestor", "post", f"{API}/streams", {"name": "s"}),
    ],
)
def test_wrong_role_gets_403(
    client: TestClient, login: Callable, role: str, method: str, url: str, body: dict | None
) -> None:
    response = client.request(method, url, json=body, headers=login(role))

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


def test_admin_creates_operator_and_duplicate_is_rejected(
    client: TestClient, login: Callable
) -> None:
    headers = login("admin")
    body = {"username": "dave", "password": "long-enough-pass", "role": "ingestor"}

    created = client.post(f"{API}/operators", json=body, headers=headers)
    duplicate = client.post(f"{API}/operators", json=body, headers=headers)

    assert created.status_code == 201 and created.json()["role"] == "ingestor"
    assert duplicate.status_code == 409
    login_ok = client.post(
        f"{API}/auth/login", json={"username": "dave", "password": "long-enough-pass"}
    )
    assert login_ok.status_code == 200
