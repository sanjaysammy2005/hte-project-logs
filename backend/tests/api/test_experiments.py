"""T9.2, T9.3: experiment harness end to end on a tiny configuration."""

from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import LogStream
from app.experiments.runner import ExperimentConfig, ExperimentConfigError, create_run, execute_run
from app.main import app
from app.provenance.rules import load_rules

API = "/api/v1"
TINY = {
    "name": "tiny",
    "sizes": [120],
    "seeds": [1, 2],
    "batch_sizes": [8, 32],
    "base_batch_size": 16,
    "trials_per_scenario": 2,
    "timing_repetitions": 2,
    "proof_samples": 5,
}


def _run(engine: Engine, config: dict) -> dict:
    with Session(engine, expire_on_commit=False) as db:
        run = create_run(db, ExperimentConfig.from_dict(config), git_commit="test")
        run = execute_run(db, run.id, load_rules())
        return {
            "raw": run.raw_results,
            "summary": run.summary,
            "env": run.environment,
            "status": run.status,
        }


@pytest.fixture
def tiny_run(test_engine: Engine) -> dict:
    return _run(test_engine, TINY)


def test_tiny_run_completes_with_all_sections(tiny_run: dict, test_engine: Engine) -> None:
    summary = tiny_run["summary"]

    assert tiny_run["status"] == "completed"
    assert {r["scenario"] for r in summary["detection"]} == {f"S{i}" for i in range(1, 12)}
    assert summary["false_positive"][0]["false_positive"]["n"] == 2
    assert {r["batch_size"] for r in summary["timing"]} == {8, 32}
    assert all(r["all_valid"] for r in summary["timing"])
    assert summary["storage"][0]["records"] > 0
    assert {p["batch_size"] for p in summary["proofs"]} == {8, 32}
    # Trials and timing copies were rolled back: only the two synthetic base streams remain.
    with Session(test_engine) as db:
        kinds = dict(
            db.execute(select(LogStream.kind, func.count()).group_by(LogStream.kind)).all()
        )
    assert kinds.get("lab", 0) == 0 and kinds["synthetic"] == 2


def test_environment_is_captured(tiny_run: dict) -> None:
    env = tiny_run["env"]

    assert env["git_commit"] == "test" and env["python"] and env["cpu_count"]
    assert "PostgreSQL" in env["postgresql"] and env["packages"]["sqlalchemy"]
    assert env["timer"].startswith("time.perf_counter")


def test_same_configuration_reproduces_detection_outcomes(
    tiny_run: dict, test_engine: Engine
) -> None:
    again = _run(test_engine, {**TINY, "name": "tiny-again"})

    def outcomes(run: dict) -> list[tuple]:
        return [
            (
                t["scenario"],
                t["trial"],
                t["seed"],
                t["detected"],
                t["first_failure_index"],
                t["true_first_index"],
            )
            for t in run["raw"]["detection"]
        ]

    assert outcomes(again) == outcomes(tiny_run)


@pytest.mark.parametrize(
    "bad",
    [
        {"sizes": []},
        {"sizes": [5]},
        {"scenarios": ["S99"]},
        {"timing_repetitions": 0},
        {"unexpected": 1},
    ],
)
def test_invalid_configurations_rejected(bad: dict) -> None:
    with pytest.raises(ExperimentConfigError):
        ExperimentConfig.from_dict({**TINY, **bad})


@pytest.fixture
def lab_enabled() -> Iterator[None]:
    enabled = get_settings().model_copy(update={"lab_enabled": True})
    app.dependency_overrides[get_settings] = lambda: enabled
    yield
    app.dependency_overrides.pop(get_settings, None)


def test_api_start_requires_lab_and_admin(client: TestClient, login: Callable) -> None:
    disabled = get_settings().model_copy(update={"lab_enabled": False})
    app.dependency_overrides[get_settings] = lambda: disabled
    try:
        response = client.post(f"{API}/experiments", json=TINY, headers=login("admin"))
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 404


def test_api_runs_in_background_and_serves_results(
    client: TestClient, login: Callable, lab_enabled: None
) -> None:
    admin = login("admin")
    small = {**TINY, "seeds": [1], "scenarios": ["S1", "S10"], "batch_sizes": [8]}

    started = client.post(f"{API}/experiments", json=small, headers=admin)
    run_id = started.json()["id"]
    detail = client.get(f"{API}/experiments/{run_id}", headers=admin).json()
    listing = client.get(f"{API}/experiments", headers=admin).json()
    csv_text = client.get(
        f"{API}/experiments/{run_id}/raw",
        params={"section": "detection", "format": "csv"},
        headers=admin,
    ).text
    rows = client.get(
        f"{API}/experiments/{run_id}/raw", params={"section": "timing"}, headers=admin
    ).json()

    assert started.status_code == 202 and started.json()["summary"] is None
    assert detail["status"] == "completed" and detail["summary"]["detection"]
    assert [r["id"] for r in listing] == [run_id] and listing[0]["summary"] is None
    assert csv_text.splitlines()[0] == (
        "base_stream_id,detected,error,expected_detected,first_failure_check,"
        "first_failure_index,scenario,seed,size,trial,true_first_index,verify_ms"
    )
    assert len(csv_text.splitlines()) == 1 + 2 * 2  # header + 2 scenarios x 2 trials
    assert len(rows) == 3  # 1 warm-up + 2 repetitions
    assert client.post(f"{API}/experiments", json={"sizes": []}, headers=admin).status_code == 422
    assert (
        client.get(
            f"{API}/experiments/11111111-1111-4111-8111-111111111111", headers=admin
        ).status_code
        == 404
    )
