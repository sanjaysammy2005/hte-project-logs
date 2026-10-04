"""Tamper lab API (API_SPEC §3, Phase 7). Every endpoint is 404 unless the lab is enabled."""

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.api.deps import Admin, DbSession, RulesDep, SettingsDep
from app.api.v1.schemas import StreamDetail
from app.api.v1.streams import stream_or_404
from app.core.errors import APIError
from app.db.models import AuditEvent, TamperScenario
from app.lab.generator import WorkloadError, WorkloadSpec, generate_workload
from app.lab.scenarios import SCENARIOS, ScenarioError, run_scenario

MAX_API_EVENTS = 50_000


def require_lab(settings: SettingsDep) -> None:
    if not settings.lab_enabled:
        raise APIError(404, "NOT_FOUND", "Not found")


router = APIRouter(prefix="/lab", tags=["lab"], dependencies=[Depends(require_lab)])

ScenarioCode = Literal["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11"]


class WorkloadIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=128)
    users: int = Field(ge=1, le=1000)
    sessions_per_user: int = Field(ge=1, le=100)
    events_per_session: int = Field(ge=3, le=500)
    seed: int
    batch_size: int = Field(default=64, ge=1, le=4096)
    sessionless_rate: float = Field(default=0.05, ge=0, lt=0.5)


class ScenarioIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_stream_id: uuid.UUID
    scenario_type: ScenarioCode
    seed: int = 0
    target_chain_index: int | None = Field(default=None, ge=1)
    j: int | None = Field(default=None, ge=1)
    t: int | None = Field(default=None, ge=1)
    batch_index: int | None = Field(default=None, ge=1)


class ScenarioOut(BaseModel):
    id: uuid.UUID
    scenario_type: str
    attacker_model: str
    description: str
    source_stream_id: uuid.UUID
    lab_stream_id: uuid.UUID
    parameters: dict[str, Any]
    expected_detected: bool
    true_first_index: int | None
    verification_run_id: uuid.UUID | None
    actual_detected: bool | None
    first_failure_index: int | None
    first_failure_check: str | None
    located_correctly: bool | None
    outcome: Literal["AS_EXPECTED", "UNEXPECTED", "PENDING"]
    created_at: datetime

    @classmethod
    def build(cls, s: TamperScenario) -> "ScenarioOut":
        if s.actual_detected is None:
            outcome = "PENDING"
        else:
            outcome = "AS_EXPECTED" if s.actual_detected == s.expected_detected else "UNEXPECTED"
        return cls(
            id=s.id,
            scenario_type=s.scenario_type,
            attacker_model=s.attacker_model,
            description=s.description,
            source_stream_id=s.source_stream_id,
            lab_stream_id=s.lab_stream_id,
            parameters=s.parameters,
            expected_detected=s.expected_detected,
            true_first_index=s.true_first_index,
            verification_run_id=s.verification_run_id,
            actual_detected=s.actual_detected,
            first_failure_index=s.first_failure_index,
            first_failure_check=s.first_failure_check,
            located_correctly=s.located_correctly,
            outcome=outcome,
            created_at=s.created_at,
        )


@router.post("/workloads", response_model=StreamDetail, status_code=status.HTTP_201_CREATED)
def create_workload(body: WorkloadIn, _: Admin, db: DbSession, rules: RulesDep) -> StreamDetail:
    spec = WorkloadSpec(
        name=body.name or f"synthetic-seed{body.seed}-{uuid.uuid4().hex[:6]}",
        users=body.users,
        sessions_per_user=body.sessions_per_user,
        events_per_session=body.events_per_session,
        seed=body.seed,
        batch_size=body.batch_size,
        sessionless_rate=body.sessionless_rate,
    )
    if spec.approximate_events > MAX_API_EVENTS:
        raise APIError(
            422,
            "WORKLOAD_TOO_LARGE",
            f"About {spec.approximate_events} events; the API limit is {MAX_API_EVENTS}",
        )
    try:
        stream = generate_workload(db, spec, rules)
    except IntegrityError as exc:
        db.rollback()
        raise APIError(409, "STREAM_NAME_TAKEN", "A stream with that name already exists") from exc
    except WorkloadError as exc:  # pragma: no cover - request validation prevents it
        db.rollback()
        raise APIError(422, "INVALID_WORKLOAD", str(exc)) from exc
    count = db.scalar(select(func.count()).where(AuditEvent.stream_id == stream.id)) or 0
    return StreamDetail.build(stream, count)


@router.post("/scenarios", response_model=ScenarioOut, status_code=status.HTTP_201_CREATED)
def create_scenario(
    body: ScenarioIn, current: Admin, db: DbSession, rules: RulesDep
) -> ScenarioOut:
    source = stream_or_404(db, body.source_stream_id)
    params = body.model_dump(
        include={"target_chain_index", "j", "t", "batch_index"}, exclude_none=True
    )
    try:
        scenario = run_scenario(
            db,
            source,
            body.scenario_type,
            params,
            body.seed,
            rules,
            triggered_by=current.operator.id,
        )
    except ScenarioError as exc:
        db.rollback()
        raise APIError(400, "SCENARIO_NOT_APPLICABLE", str(exc)) from exc
    return ScenarioOut.build(scenario)


@router.get("/scenarios", response_model=list[ScenarioOut])
def list_scenarios(_: Admin, db: DbSession) -> list[ScenarioOut]:
    rows = db.scalars(select(TamperScenario).order_by(TamperScenario.created_at.desc()).limit(500))
    return [ScenarioOut.build(s) for s in rows]


@router.get("/scenarios/{scenario_id}", response_model=ScenarioOut)
def get_scenario(scenario_id: uuid.UUID, _: Admin, db: DbSession) -> ScenarioOut:
    scenario = db.get(TamperScenario, scenario_id)
    if scenario is None:
        raise APIError(404, "SCENARIO_NOT_FOUND", "No such scenario")
    return ScenarioOut.build(scenario)


@router.get("/scenario-types")
def scenario_types(_: Admin) -> list[dict[str, str]]:
    return [
        {"code": d.code, "attacker_model": d.attacker_model, "description": d.description}
        for d in SCENARIOS.values()
    ]
