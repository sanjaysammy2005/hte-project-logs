"""T6.1–T6.6: batching, proofs and verification runs on stored data, tampered via SQL."""

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

API = "/api/v1"
SESSION = ["LOGIN", "AUTHENTICATION", "FILE_OPEN", "FILE_EDIT", "LOGOUT"]


@pytest.fixture
def admin(login: Callable) -> dict:
    return login("admin")


@pytest.fixture
def stream(client: TestClient, admin: dict) -> str:
    """A primary stream with batch size 4 holding 4 sessions (20 records, 5 sealed batches)."""
    stream_id = client.post(
        f"{API}/streams", json={"name": "app", "batch_size": 4}, headers=admin
    ).json()["id"]
    for i in range(4):
        for event_type in SESSION:
            r = client.post(
                f"{API}/streams/{stream_id}/events",
                headers=admin,
                json={
                    "actor_user_id": f"U{i}",
                    "session_id": f"S{i}",
                    "event_type": event_type,
                    "payload": {"n": i},
                },
            )
            assert r.status_code == 201, r.text
    return stream_id


def _verify(client: TestClient, headers: dict, stream_id: str) -> dict:
    response = client.post(f"{API}/streams/{stream_id}/verify", headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def _sql(engine: Engine, statement: str, **params: object) -> None:
    """Simulated attacker with direct database write access."""
    with engine.begin() as conn:
        conn.execute(text(statement), params)


# --- T6.1 sealing ----------------------------------------------------------------------------


def test_full_batches_are_sealed_automatically_and_contiguously(
    client: TestClient, admin: dict, stream: str
) -> None:
    batches = client.get(f"{API}/streams/{stream}/batches", headers=admin).json()

    assert [
        (b["batch_index"], b["first_chain_index"], b["last_chain_index"], b["leaf_count"])
        for b in batches
    ] == [(i, 4 * i - 3, 4 * i, 4) for i in range(1, 6)]


def test_manual_seal_of_partial_batch(client: TestClient, admin: dict, stream: str) -> None:
    client.post(
        f"{API}/streams/{stream}/events", headers=admin, json={"event_type": "IP_SECURITY_EVENT"}
    )

    nothing = client.post(f"{API}/streams/{stream}/batches/seal", json={}, headers=admin).json()
    partial = client.post(
        f"{API}/streams/{stream}/batches/seal", json={"include_partial": True}, headers=admin
    ).json()

    assert nothing == []
    assert [(b["first_chain_index"], b["last_chain_index"], b["leaf_count"]) for b in partial] == [
        (21, 21, 1)  # single-leaf batch: root = leaf (Q10)
    ]
    detail = client.get(f"{API}/streams/{stream}/events/21", headers=admin).json()
    assert partial[0]["merkle_root"] == detail["record"]["entry_hash"]
    assert detail["batch"]["batch_index"] == 6


def test_sealing_refuses_a_gapped_stream(
    client: TestClient, admin: dict, stream: str, test_engine: Engine
) -> None:
    client.post(
        f"{API}/streams/{stream}/events", headers=admin, json={"event_type": "IP_SECURITY_EVENT"}
    )
    client.post(
        f"{API}/streams/{stream}/events", headers=admin, json={"event_type": "IP_SECURITY_EVENT"}
    )
    _sql(
        test_engine, "DELETE FROM audit_events WHERE stream_id = :s AND chain_index = 21", s=stream
    )

    response = client.post(
        f"{API}/streams/{stream}/batches/seal", json={"include_partial": True}, headers=admin
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "STREAM_INCONSISTENT"


def test_only_admin_can_seal(client: TestClient, login: Callable, stream: str) -> None:
    response = client.post(
        f"{API}/streams/{stream}/batches/seal", json={}, headers=login("auditor")
    )

    assert response.status_code == 403


# --- T6.2 / T6.5 untampered verification -----------------------------------------------------


def test_untampered_stream_verifies_valid_and_run_is_persisted(
    client: TestClient, login: Callable, stream: str
) -> None:
    auditor = login("auditor")
    client.post(
        f"{API}/streams/{stream}/events",
        headers=login("ingestor"),
        json={"event_type": "IP_SECURITY_EVENT"},
    )  # one unbatched record

    report = _verify(client, auditor, stream)

    assert report["status"] == "VALID" and report["first_failure"] is None
    assert report["findings"] == [] and report["findings_total"] == 0
    assert (report["records_checked"], report["batches_checked"], report["unbatched_records"]) == (
        21,
        5,
        1,
    )
    assert report["rules_version"].startswith("transitions.v2 sha256:")
    assert (report["hash_scheme"], report["merkle_scheme"]) == ("tl-v1", "paper-dup-v1")

    stored = client.get(f"{API}/verification-runs/{report['run_id']}", headers=auditor).json()
    history = client.get(f"{API}/streams/{stream}/verification-runs", headers=auditor).json()
    listing = client.get(f"{API}/streams", headers=auditor).json()
    assert stored["status"] == "VALID" and [r["run_id"] for r in history] == [report["run_id"]]
    assert {s["name"]: s["last_verification_status"] for s in listing}["app"] == "VALID"


def test_system_stream_of_logins_verifies(client: TestClient, admin: dict, system_stream) -> None:
    report = _verify(client, admin, str(system_stream.id))

    assert report["status"] == "VALID" and report["records_checked"] == 2


# --- T6.3 / T6.4 tampering on stored rows ----------------------------------------------------


def _first(report: dict) -> tuple:
    f = report["first_failure"]
    return f["chain_index"], f["check"], f["batch_index"]


def test_modified_payload_detected_at_record_with_batch(
    client: TestClient, admin: dict, stream: str, test_engine: Engine
) -> None:
    _sql(
        test_engine,
        "UPDATE audit_events SET event_payload = '{\"n\": 99}'"
        " WHERE stream_id = :s AND chain_index = 6",
        s=stream,
    )

    report = _verify(client, admin, stream)

    assert report["status"] == "TAMPERING_DETECTED"
    assert _first(report) == (6, "CHAIN_HASH", 2)
    assert report["failed_by_check"] == {"CHAIN_HASH": 1, "MERKLE_ROOT": 1}
    detail = client.get(f"{API}/streams/{stream}/events/6", headers=admin).json()
    assert detail["hash_matches"] is False


def test_modified_context_detected_by_hash_and_provenance(
    client: TestClient, admin: dict, stream: str, test_engine: Engine
) -> None:
    _sql(
        test_engine,
        "UPDATE audit_events SET actor_user_id = 'U-ATTACKER'"
        " WHERE stream_id = :s AND chain_index = 8",
        s=stream,
    )

    report = _verify(client, admin, stream)

    assert _first(report) == (8, "CHAIN_HASH", 2)
    assert {"PROV_WHO", "MERKLE_ROOT"} <= set(report["failed_by_check"])


def test_deleted_record_detected(
    client: TestClient, admin: dict, stream: str, test_engine: Engine
) -> None:
    _sql(
        test_engine, "DELETE FROM audit_events WHERE stream_id = :s AND chain_index = 12", s=stream
    )

    report = _verify(client, admin, stream)

    # Batch 3 (records 9-12) is now short a leaf; the chain breaks at the successor 13.
    assert _first(report) == (9, "MERKLE_RANGE", 3)
    checks = {(f["chain_index"], f["check"]) for f in report["findings"]}
    assert {(13, "CHAIN_INDEX_CONTINUITY"), (13, "CHAIN_LINK"), (9, "MERKLE_ROOT")} <= checks


def test_reordered_records_detected(
    client: TestClient, admin: dict, stream: str, test_engine: Engine
) -> None:
    """Swap the positions of two records (all their stored columns move together)."""
    _sql(
        test_engine,
        "UPDATE audit_events SET chain_index = -1 WHERE stream_id = :s AND chain_index = 3",
        s=stream,
    )
    _sql(
        test_engine,
        "UPDATE audit_events SET chain_index = 3 WHERE stream_id = :s AND chain_index = 14",
        s=stream,
    )
    _sql(
        test_engine,
        "UPDATE audit_events SET chain_index = 14 WHERE stream_id = :s AND chain_index = -1",
        s=stream,
    )

    report = _verify(client, admin, stream)

    assert _first(report) == (3, "CHAIN_LINK", 1)  # explains batch 1's root mismatch
    checks = {(f["chain_index"], f["check"]) for f in report["findings"]}
    assert (3, "CHAIN_LINK") in checks and (14, "CHAIN_LINK") in checks


def test_inserted_record_detected(
    client: TestClient, admin: dict, stream: str, test_engine: Engine
) -> None:
    """Attacker shifts records 10.. up by one and inserts a copy at 10 (unique index permits)."""
    _sql(
        test_engine,
        "UPDATE audit_events SET chain_index = chain_index + 1000"
        " WHERE stream_id = :s AND chain_index >= 10",
        s=stream,
    )
    _sql(
        test_engine,
        "UPDATE audit_events SET chain_index = chain_index - 999"
        " WHERE stream_id = :s AND chain_index >= 1010",
        s=stream,
    )
    _sql(
        test_engine,
        "INSERT INTO audit_events (stream_id, chain_index, event_type,"
        " event_payload, actor_user_id, session_id, prev_event_type, session_seq,"
        " event_timestamp, prev_hash, entry_hash) SELECT stream_id, 10, 'DB_ACCESS',"
        " event_payload, actor_user_id, session_id, prev_event_type, 99, event_timestamp,"
        " prev_hash, entry_hash FROM audit_events WHERE stream_id = :s AND chain_index = 9",
        s=stream,
    )

    report = _verify(client, admin, stream)

    assert report["status"] == "TAMPERING_DETECTED"
    checks = {(f["chain_index"], f["check"]) for f in report["findings"]}
    assert (10, "CHAIN_HASH") in checks or (10, "CHAIN_LINK") in checks
    assert any(c.startswith("PROV_") for _, c in checks)


def test_altered_merkle_root_detected(
    client: TestClient, admin: dict, stream: str, test_engine: Engine
) -> None:
    _sql(
        test_engine,
        "UPDATE batches SET merkle_root = decode(repeat('00', 32), 'hex')"
        " WHERE stream_id = :s AND batch_index = 4",
        s=stream,
    )

    report = _verify(client, admin, stream)

    assert _first(report) == (13, "MERKLE_ROOT", 4)
    assert report["failed_by_check"] == {"MERKLE_ROOT": 1}


def test_shrunk_batch_range_detected(
    client: TestClient, admin: dict, stream: str, test_engine: Engine
) -> None:
    """leaf_count and range changed together (the DB constraint forces both)."""
    _sql(
        test_engine,
        "UPDATE batches SET leaf_count = 3, last_chain_index = 7"
        " WHERE stream_id = :s AND batch_index = 2",
        s=stream,
    )

    report = _verify(client, admin, stream)

    assert {"MERKLE_ROOT", "MERKLE_RANGE"} <= set(report["failed_by_check"])


def test_findings_are_paginated(
    client: TestClient, admin: dict, stream: str, test_engine: Engine
) -> None:
    _sql(test_engine, "UPDATE audit_events SET event_payload = '{}' WHERE stream_id = :s", s=stream)
    report = _verify(client, admin, stream)

    page = client.get(
        f"{API}/verification-runs/{report['run_id']}",
        params={"limit": 3, "offset": 2},
        headers=admin,
    ).json()

    assert report["findings_total"] == page["findings_stored"] == 25  # 20 hashes + 5 roots
    assert page["findings"] == report["findings"][2:5]


# --- T6.6 proofs -----------------------------------------------------------------------------


def test_api_proof_verifies_locally_and_via_api(
    client: TestClient, admin: dict, stream: str
) -> None:
    from app.crypto.merkle import ProofStep, verify_proof

    proof = client.get(f"{API}/streams/{stream}/events/7/proof", headers=admin).json()
    steps = [ProofStep(bytes.fromhex(s["sibling"]), s["position"]) for s in proof["proof"]]

    assert proof["batch_index"] == 2 and len(steps) == 2  # ceil(log2 4)
    assert verify_proof(bytes.fromhex(proof["leaf"]), steps, bytes.fromhex(proof["merkle_root"]))
    body = {"leaf": proof["leaf"], "merkle_root": proof["merkle_root"], "proof": proof["proof"]}
    assert client.post(f"{API}/proofs/verify", json=body, headers=admin).json() == {"valid": True}
    body["leaf"] = "00" * 32
    assert client.post(f"{API}/proofs/verify", json=body, headers=admin).json() == {"valid": False}


def test_proof_for_unbatched_record_is_404(client: TestClient, admin: dict, stream: str) -> None:
    client.post(
        f"{API}/streams/{stream}/events", headers=admin, json={"event_type": "IP_SECURITY_EVENT"}
    )

    response = client.get(f"{API}/streams/{stream}/events/21/proof", headers=admin)

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "EVENT_NOT_BATCHED"


def test_proof_over_tampered_batch_is_refused(
    client: TestClient, admin: dict, stream: str, test_engine: Engine
) -> None:
    _sql(test_engine, "DELETE FROM audit_events WHERE stream_id = :s AND chain_index = 6", s=stream)

    response = client.get(f"{API}/streams/{stream}/events/7/proof", headers=admin)

    assert response.status_code == 409


def test_malformed_proof_request_rejected(client: TestClient, admin: dict) -> None:
    body = {"leaf": "zz", "merkle_root": "00" * 32, "proof": []}

    assert client.post(f"{API}/proofs/verify", json=body, headers=admin).status_code == 422


def test_unknown_run_is_404(client: TestClient, admin: dict) -> None:
    response = client.get(
        f"{API}/verification-runs/11111111-1111-4111-8111-111111111111", headers=admin
    )

    assert response.status_code == 404
