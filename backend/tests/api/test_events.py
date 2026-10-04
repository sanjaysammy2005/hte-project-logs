"""T5.2, T5.3, T5.5: event ingestion, enrichment, provenance policy, storage round-trip."""

import unicodedata
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.chain import GENESIS_HASH, verify_chain
from app.db.models import AuditEvent
from app.ingestion.service import to_chained
from app.provenance.checks import check_provenance
from app.provenance.rules import load_rules

API = "/api/v1"
SESSION = ["LOGIN", "AUTHENTICATION", "FILE_OPEN", "FILE_EDIT", "LOGOUT"]


@pytest.fixture
def admin(login: Callable) -> dict:
    return login("admin")


@pytest.fixture
def stream_id(client: TestClient, admin: dict) -> str:
    response = client.post(f"{API}/streams", json={"name": "app", "batch_size": 4}, headers=admin)
    assert response.status_code == 201
    return response.json()["id"]


def _post(client: TestClient, headers: dict, stream_id: str, **body: object):
    return client.post(f"{API}/streams/{stream_id}/events", json=body, headers=headers)


def _session(client: TestClient, headers: dict, stream_id: str, user: str, sid: str) -> None:
    for event_type in SESSION:
        response = _post(
            client,
            headers,
            stream_id,
            actor_user_id=user,
            session_id=sid,
            event_type=event_type,
            payload={"resource": "/r", "n": 1},
        )
        assert response.status_code == 201, response.text


def _stored(db: Session, stream_id: str) -> list[AuditEvent]:
    db.expire_all()
    return list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.stream_id == stream_id)
            .order_by(AuditEvent.chain_index)
        )
    )


def test_server_assigns_context_and_hashes(client: TestClient, admin: dict, stream_id: str) -> None:
    first = _post(
        client,
        admin,
        stream_id,
        actor_user_id="U101",
        session_id="S5001",
        event_type="LOGIN",
        payload={"ip_address": "10.0.0.12"},
    ).json()
    second = _post(
        client,
        admin,
        stream_id,
        actor_user_id="U101",
        session_id="S5001",
        event_type="AUTHENTICATION",
    ).json()

    assert (first["chain_index"], first["session_seq"], first["prev_event_type"]) == (
        1,
        1,
        "__START__",
    )
    assert first["prev_hash"] == GENESIS_HASH.hex()
    assert (second["chain_index"], second["session_seq"], second["prev_event_type"]) == (
        2,
        2,
        "LOGIN",
    )
    assert second["prev_hash"] == first["entry_hash"]
    assert first["event_timestamp"].endswith("Z") and len(first["event_timestamp"]) == 27


@pytest.mark.parametrize(
    "field",
    ["chain_index", "session_seq", "prev_event_type", "event_timestamp", "prev_hash", "entry_hash"],
)
def test_server_only_fields_rejected(
    client: TestClient, admin: dict, stream_id: str, field: str
) -> None:
    response = _post(client, admin, stream_id, event_type="LOGIN_FAILED", **{field: "x"})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"event_type": "SECURITY_VIOLATION"}, "UNKNOWN_EVENT_TYPE"),  # reserved for the server
        ({"event_type": "NOT_A_TYPE"}, "UNKNOWN_EVENT_TYPE"),
        ({"event_type": "LOGIN_FAILED", "payload": {"ratio": 0.5}}, "INVALID_EVENT"),
        ({"event_type": "LOGIN_FAILED", "payload": {"x": "a\u0000b"}}, "INVALID_EVENT"),
        ({"event_type": "LOGIN_FAILED", "actor_user_id": "a\u0000b"}, "INVALID_EVENT"),
    ],
)
def test_invalid_events_rejected_and_not_stored(
    client: TestClient, admin: dict, stream_id: str, db: Session, body: dict, code: str
) -> None:
    response = _post(client, admin, stream_id, **body)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == code
    assert _stored(db, stream_id) == []


def test_system_stream_not_writable_through_api(
    client: TestClient, admin: dict, system_stream
) -> None:
    response = _post(client, admin, str(system_stream.id), event_type="LOGIN_FAILED")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "STREAM_NOT_WRITABLE"


def test_unknown_stream_is_404(client: TestClient, admin: dict) -> None:
    response = _post(client, admin, "11111111-1111-4111-8111-111111111111", event_type="LOGIN")

    assert response.status_code == 404


# --- T5.5 provenance policy at ingestion (Q6) ------------------------------------------------


@pytest.mark.parametrize(
    ("setup", "attempt", "failed"),
    [
        (
            [],
            {"actor_user_id": "U1", "session_id": "S1", "event_type": "FILE_OPEN"},
            "PROV_TRANSITION",
        ),
        (
            ["LOGIN", "AUTHENTICATION"],
            {"actor_user_id": "U-OTHER", "session_id": "S1", "event_type": "FILE_OPEN"},
            "PROV_WHO",
        ),
        (
            ["LOGIN", "AUTHENTICATION", "LOGOUT"],
            {"actor_user_id": "U1", "session_id": "S1", "event_type": "FILE_OPEN"},
            "PROV_SESSION",
        ),
        ([], {"event_type": "FILE_OPEN"}, "PROV_SESSION"),
    ],
)
def test_violating_event_rejected_and_security_violation_recorded(
    client: TestClient,
    admin: dict,
    stream_id: str,
    db: Session,
    setup: list[str],
    attempt: dict,
    failed: str,
) -> None:
    for event_type in setup:
        assert (
            _post(
                client, admin, stream_id, actor_user_id="U1", session_id="S1", event_type=event_type
            ).status_code
            == 201
        )

    response = _post(client, admin, stream_id, **attempt)

    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "PROVENANCE_VIOLATION"
    assert failed in {c["check"] for c in error["details"]["failed_checks"]}
    stored = _stored(db, stream_id)
    violation = stored[-1]
    assert violation.chain_index == error["details"]["security_event_chain_index"]
    assert violation.event_type == "SECURITY_VIOLATION" and violation.session_id is None
    assert violation.event_payload["attempted_event_type"] == attempt["event_type"]
    assert failed in violation.event_payload["failed_checks"]
    # The stored stream still verifies: rejected events never enter it.
    chained = [to_chained(e) for e in stored]
    assert verify_chain(chained).is_valid
    assert check_provenance(chained, load_rules()).is_valid


# --- T5.3 storage round-trip -----------------------------------------------------------------


def test_records_rehash_after_database_round_trip(
    client: TestClient, admin: dict, stream_id: str, db: Session
) -> None:
    _session(client, admin, stream_id, "U101", "S1")
    _post(
        client,
        admin,
        stream_id,
        event_type="IP_SECURITY_EVENT",
        payload={
            "ip_address": "203.0.113.7",
            "attempts": 5,
            "nested": {"ok": True, "n": None},
            "list": [1, "two"],
            "text": 'café 東京 \n\t"q"',
        },
    )
    _session(client, admin, stream_id, "U202", "S2")

    chained = [to_chained(e) for e in _stored(db, stream_id)]

    assert len(chained) == 11
    assert verify_chain(chained).is_valid  # every stored hash recomputes from stored fields
    assert check_provenance(chained, load_rules()).is_valid


def test_text_stored_in_nfc_form(client: TestClient, admin: dict, stream_id: str) -> None:
    # Built from escapes at runtime so no formatter or editor can change the normalisation form.
    cafe_nfd = "cafe" + chr(0x0301)  # e + combining acute
    naive_nfd = "nai" + chr(0x0308) + "ve"  # i + combining diaeresis
    cafe_nfc = unicodedata.normalize("NFC", cafe_nfd)
    naive_nfc = unicodedata.normalize("NFC", naive_nfd)
    assert (len(cafe_nfd), len(cafe_nfc), len(naive_nfd), len(naive_nfc)) == (5, 4, 6, 5)

    body = _post(
        client,
        admin,
        stream_id,
        event_type="LOGIN_FAILED",
        actor_user_id=cafe_nfd,
        payload={cafe_nfd: naive_nfd},
    ).json()

    assert body["actor_user_id"] == cafe_nfc
    assert body["payload"] == {cafe_nfc: naive_nfc}


# --- reading events --------------------------------------------------------------------------


def test_list_filter_paginate_detail_and_session(
    client: TestClient, admin: dict, stream_id: str
) -> None:
    _session(client, admin, stream_id, "U1", "S1")
    _session(client, admin, stream_id, "U2", "S2")
    base = f"{API}/streams/{stream_id}"

    page1 = client.get(f"{base}/events", params={"limit": 4}, headers=admin).json()
    page2 = client.get(
        f"{base}/events", params={"limit": 4, "cursor": page1["next_cursor"]}, headers=admin
    ).json()
    by_user = client.get(f"{base}/events", params={"actor_user_id": "U2"}, headers=admin).json()
    session = client.get(f"{base}/sessions/S1", headers=admin).json()
    detail = client.get(f"{base}/events/3", headers=admin).json()
    first = client.get(f"{base}/events/1", headers=admin).json()
    stream = client.get(base, headers=admin).json()

    assert [e["chain_index"] for e in page1["items"]] == [1, 2, 3, 4]
    assert [e["chain_index"] for e in page2["items"]] == [5, 6, 7, 8]
    assert {e["actor_user_id"] for e in by_user["items"]} == {"U2"} and len(by_user["items"]) == 5
    assert [e["event_type"] for e in session] == SESSION
    assert detail["hash_matches"] and detail["link_matches"]
    assert detail["predecessor"]["chain_index"] == 2
    assert detail["recomputed_hash"] == detail["record"]["entry_hash"]
    assert first["predecessor"] == {"chain_index": None, "entry_hash": GENESIS_HASH.hex()}
    assert stream["record_count"] == 10 and stream["genesis_hash"] == GENESIS_HASH.hex()
    assert client.get(f"{base}/events/99", headers=admin).status_code == 404


def test_event_detail_exposes_tampering(
    client: TestClient, admin: dict, stream_id: str, db: Session
) -> None:
    """Direct DB modification (simulated attacker) shows up as a hash mismatch in the API."""
    _session(client, admin, stream_id, "U1", "S1")
    row = _stored(db, stream_id)[2]
    row.event_payload = {"resource": "/attacker"}
    db.commit()

    detail = client.get(f"{API}/streams/{stream_id}/events/3", headers=admin).json()

    assert detail["hash_matches"] is False and detail["link_matches"] is True


def test_stream_names_are_unique_and_listed(
    client: TestClient, admin: dict, stream_id: str
) -> None:
    duplicate = client.post(f"{API}/streams", json={"name": "app"}, headers=admin)
    names = [s["name"] for s in client.get(f"{API}/streams", headers=admin).json()]

    assert duplicate.status_code == 409
    assert set(names) == {"system", "app"}
