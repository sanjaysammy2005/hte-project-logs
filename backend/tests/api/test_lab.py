"""T7.1–T7.5: tamper lab safety, deterministic workloads, scenarios S1–S11."""

from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import AuditEvent, LogStream, TamperScenario, VerificationRun
from app.ingestion.service import to_chained
from app.lab.generator import WorkloadSpec, generate_workload
from app.lab.scenarios import LabSafetyError, apply_tampering
from app.main import app
from app.provenance.rules import load_rules
from app.verification.engine import build_report, load_stream

API = "/api/v1"
RULES = load_rules()
SMALL = {"users": 3, "sessions_per_user": 2, "events_per_session": 6, "seed": 7, "batch_size": 8}


@pytest.fixture
def lab_enabled() -> Iterator[None]:
    enabled = get_settings().model_copy(update={"lab_enabled": True})
    app.dependency_overrides[get_settings] = lambda: enabled
    yield
    app.dependency_overrides.pop(get_settings, None)


@pytest.fixture
def admin(login: Callable) -> dict:
    return login("admin")


@pytest.fixture
def workload(client: TestClient, admin: dict, lab_enabled: None) -> dict:
    response = client.post(f"{API}/lab/workloads", json={**SMALL, "name": "w"}, headers=admin)
    assert response.status_code == 201, response.text
    return response.json()


def _rows(db: Session, stream_id) -> list[tuple]:
    db.expire_all()
    rows = db.scalars(
        select(AuditEvent).where(AuditEvent.stream_id == stream_id).order_by(AuditEvent.chain_index)
    )
    return [
        (
            r.chain_index,
            r.event_type,
            r.actor_user_id,
            r.session_id,
            r.session_seq,
            r.event_payload,
            r.event_timestamp,
            bytes(r.entry_hash),
        )
        for r in rows
    ]


# --- T7.1 disabled by default ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/lab/workloads"),
        ("post", "/lab/scenarios"),
        ("get", "/lab/scenarios"),
        ("get", "/lab/scenario-types"),
    ],
)
def test_lab_is_404_when_disabled(client: TestClient, admin: dict, method: str, path: str) -> None:
    assert get_settings().lab_enabled is False  # the default
    response = client.request(method, f"{API}{path}", json={}, headers=admin)

    assert response.status_code == 404


def test_lab_requires_admin(client: TestClient, login: Callable, lab_enabled: None) -> None:
    response = client.get(f"{API}/lab/scenarios", headers=login("auditor"))

    assert response.status_code == 403


# --- T7.3 deterministic workloads ------------------------------------------------------------


def test_same_seed_produces_identical_streams(db: Session) -> None:
    spec = WorkloadSpec(
        name="a", users=4, sessions_per_user=3, events_per_session=7, seed=42, batch_size=16
    )
    a = generate_workload(db, spec, RULES)
    b = generate_workload(db, WorkloadSpec(**{**spec.__dict__, "name": "b"}), RULES)
    c = generate_workload(db, WorkloadSpec(**{**spec.__dict__, "name": "c", "seed": 43}), RULES)

    rows_a, rows_b, rows_c = _rows(db, a.id), _rows(db, b.id), _rows(db, c.id)
    assert rows_a == rows_b
    assert rows_a != rows_c
    assert len({r[3] for r in rows_a if r[3]}) == 12  # 4 users x 3 sessions
    assert a.kind == "synthetic" and a.generator_seed == 42


def test_generated_stream_verifies_valid_with_interleaved_sessions(db: Session) -> None:
    spec = WorkloadSpec(
        name="v",
        users=5,
        sessions_per_user=4,
        events_per_session=10,
        seed=1,
        batch_size=32,
        sessionless_rate=0.1,
    )
    stream = generate_workload(db, spec, RULES)
    records, batches = load_stream(db, stream)

    report = build_report(records, batches, bytes(stream.genesis_hash), RULES)

    assert report.status == "VALID" and report.unbatched_records == 0
    sessions = [r.record.session_id for r in records]
    assert sum(a != b for a, b in zip(sessions, sessions[1:], strict=False)) > 20
    assert any(s is None for s in sessions)  # sessionless events present


def test_workload_too_large_for_api_is_rejected(
    client: TestClient, admin: dict, lab_enabled: None
) -> None:
    body = {"users": 1000, "sessions_per_user": 100, "events_per_session": 500, "seed": 1}

    response = client.post(f"{API}/lab/workloads", json=body, headers=admin)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "WORKLOAD_TOO_LARGE"


# --- T7.2 safety ---------------------------------------------------------------------------


def test_tampering_refuses_non_lab_streams(db: Session, system_stream: LogStream) -> None:
    synthetic = generate_workload(db, WorkloadSpec(name="s", **SMALL), RULES)

    for stream in (system_stream, synthetic):
        with pytest.raises(LabSafetyError):
            apply_tampering(db, stream, "S1", {"k": 1})
    db.rollback()


def test_scenarios_never_change_the_source_stream(
    client: TestClient, admin: dict, workload: dict, db: Session
) -> None:
    before = _rows(db, workload["id"])
    for code in ("S1", "S5", "S11"):
        response = client.post(
            f"{API}/lab/scenarios",
            headers=admin,
            json={"source_stream_id": workload["id"], "scenario_type": code},
        )
        assert response.status_code == 201, response.text

    assert _rows(db, workload["id"]) == before
    report = client.post(f"{API}/streams/{workload['id']}/verify", headers=admin).json()
    assert report["status"] == "VALID"


def test_lab_clone_cannot_be_a_scenario_source(
    client: TestClient, admin: dict, workload: dict
) -> None:
    first = client.post(
        f"{API}/lab/scenarios",
        headers=admin,
        json={"source_stream_id": workload["id"], "scenario_type": "S1"},
    ).json()

    response = client.post(
        f"{API}/lab/scenarios",
        headers=admin,
        json={"source_stream_id": first["lab_stream_id"], "scenario_type": "S1"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "SCENARIO_NOT_APPLICABLE"


def test_ingest_api_cannot_write_to_lab_or_synthetic_streams(
    client: TestClient, admin: dict, workload: dict
) -> None:
    response = client.post(
        f"{API}/streams/{workload['id']}/events",
        headers=admin,
        json={"event_type": "IP_SECURITY_EVENT"},
    )

    assert response.status_code == 403


# --- T7.4 / T7.5 scenarios -------------------------------------------------------------------

DETECTED = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9"]
UNDETECTED = ["S10", "S11"]


@pytest.mark.parametrize("code", DETECTED + UNDETECTED)
def test_scenario_records_expectation_first_and_matches_it(
    client: TestClient, admin: dict, workload: dict, test_engine: Engine, code: str
) -> None:
    response = client.post(
        f"{API}/lab/scenarios",
        headers=admin,
        json={"source_stream_id": workload["id"], "scenario_type": code, "seed": 3},
    )

    assert response.status_code == 201, response.text
    result = response.json()
    assert result["expected_detected"] is (code in DETECTED)
    assert result["actual_detected"] is result["expected_detected"], result
    assert result["outcome"] == "AS_EXPECTED"
    if code in UNDETECTED:  # T7.5: documented limitations, reported honestly
        assert result["first_failure_index"] is None and result["located_correctly"] is None
    else:
        assert result["true_first_index"] is not None and result["first_failure_check"]

    with Session(test_engine) as db:
        scenario = db.get(TamperScenario, result["id"])
        run = db.get(VerificationRun, result["verification_run_id"])
        assert scenario is not None and run is not None
        assert scenario.created_at <= run.started_at  # expectation stored before verifying
        lab = db.get(LogStream, result["lab_stream_id"])
        assert lab is not None and lab.kind == "lab"


@pytest.mark.parametrize("code", ["S1", "S3", "S6", "S7"])
def test_scenarios_located_at_the_true_first_record(
    client: TestClient, admin: dict, workload: dict, code: str
) -> None:
    result = client.post(
        f"{API}/lab/scenarios",
        headers=admin,
        json={"source_stream_id": workload["id"], "scenario_type": code, "target_chain_index": 10},
    ).json()

    assert result["located_correctly"] is True, result
    assert result["first_failure_index"] == result["true_first_index"] == 10


def test_paper_example_scenario_flags_session_successor(
    client: TestClient, admin: dict, workload: dict
) -> None:
    result = client.post(
        f"{API}/lab/scenarios",
        headers=admin,
        json={"source_stream_id": workload["id"], "scenario_type": "S9"},
    ).json()
    run = client.get(
        f"{API}/verification-runs/{result['verification_run_id']}", headers=admin
    ).json()

    checks = set(run["failed_by_check"])
    assert {"PROV_PREV_EVENT", "PROV_SEQUENCE", "PROV_TRANSITION", "CHAIN_LINK"} <= checks


@pytest.mark.parametrize(
    "body",
    [
        {"scenario_type": "S1", "target_chain_index": 10_000},
        {"scenario_type": "S7", "target_chain_index": 5, "j": 3},
        {"scenario_type": "S8", "batch_index": 99},
        {"scenario_type": "S10", "t": 10_000},
    ],
)
def test_inapplicable_scenarios_rejected(
    client: TestClient, admin: dict, workload: dict, body: dict
) -> None:
    response = client.post(
        f"{API}/lab/scenarios", headers=admin, json={"source_stream_id": workload["id"], **body}
    )

    assert response.status_code == 400


def test_scenario_listing_and_types(client: TestClient, admin: dict, workload: dict) -> None:
    created = client.post(
        f"{API}/lab/scenarios",
        headers=admin,
        json={"source_stream_id": workload["id"], "scenario_type": "S1"},
    ).json()

    listed = client.get(f"{API}/lab/scenarios", headers=admin).json()
    one = client.get(f"{API}/lab/scenarios/{created['id']}", headers=admin).json()
    types = client.get(f"{API}/lab/scenario-types", headers=admin).json()
    missing = client.get(f"{API}/lab/scenarios/11111111-1111-4111-8111-111111111111", headers=admin)

    assert [s["id"] for s in listed] == [created["id"]] and one == created
    assert [t["code"] for t in types] == [f"S{i}" for i in range(1, 12)]
    assert missing.status_code == 404


def test_lab_stream_tamper_is_visible_in_stored_rows(
    client: TestClient, admin: dict, workload: dict, db: Session
) -> None:
    result = client.post(
        f"{API}/lab/scenarios",
        headers=admin,
        json={"source_stream_id": workload["id"], "scenario_type": "S1", "target_chain_index": 4},
    ).json()

    lab_rows = [
        to_chained(r)
        for r in db.scalars(
            select(AuditEvent)
            .where(AuditEvent.stream_id == result["lab_stream_id"])
            .order_by(AuditEvent.chain_index)
        )
    ]
    assert lab_rows[3].record.event_payload.get("tampered") is True
