"""Experiment runs (API_SPEC §3, Phase 9).

Starting a run needs the lab to be enabled (trials tamper with rolled-back lab clones) and the
admin role; it runs as a background task after the 202 response. Reading results needs the
auditor or admin role. Large runs are better started with ``python -m app.experiments``.
"""

import csv
import io
import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.api.deps import Admin, DbSession, Reader, RulesDep
from app.api.v1.lab import require_lab
from app.core.errors import APIError
from app.db.models import ExperimentRun
from app.db.session import get_engine
from app.experiments.runner import (
    ExperimentConfig,
    ExperimentConfigError,
    create_run,
    execute_run,
)
from app.provenance.rules import TransitionRules

router = APIRouter(prefix="/experiments", tags=["experiments"])

Section = Literal["base_streams", "false_positive", "detection", "timing", "proofs", "storage"]


class ExperimentOut(BaseModel):
    id: uuid.UUID
    name: str
    status: str
    config: dict[str, Any]
    environment: dict[str, Any] | None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    summary: dict[str, Any] | None  # None until measured

    @classmethod
    def build(cls, run: ExperimentRun, with_summary: bool = True) -> "ExperimentOut":
        return cls(
            id=run.id,
            name=run.name,
            status=run.status,
            config=run.config,
            environment=run.environment,
            started_at=run.started_at,
            finished_at=run.finished_at,
            error=run.error,
            summary=run.summary if with_summary else None,
        )


def _run_in_background(engine: Engine, run_id: uuid.UUID, rules: TransitionRules) -> None:
    with Session(engine, expire_on_commit=False) as db:
        try:
            execute_run(db, run_id, rules)
        except Exception:  # noqa: BLE001 - failure is recorded on the run row
            pass


@router.post(
    "",
    response_model=ExperimentOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_lab)],
)
def start_experiment(
    body: dict[str, Any],
    background: BackgroundTasks,
    current: Admin,
    db: DbSession,
    rules: RulesDep,
    engine: Engine = Depends(get_engine),  # noqa: B008
) -> ExperimentOut:
    try:
        config = ExperimentConfig.from_dict(body)
    except ExperimentConfigError as exc:
        raise APIError(422, "INVALID_EXPERIMENT", str(exc)) from exc
    run = create_run(db, config, triggered_by=current.operator.id)
    background.add_task(_run_in_background, engine, run.id, rules)
    return ExperimentOut.build(run)


@router.get("", response_model=list[ExperimentOut])
def list_experiments(_: Reader, db: DbSession) -> list[ExperimentOut]:
    runs = db.scalars(select(ExperimentRun).order_by(ExperimentRun.created_at.desc()).limit(100))
    return [ExperimentOut.build(r, with_summary=False) for r in runs]


def _run_or_404(db: Session, run_id: uuid.UUID) -> ExperimentRun:
    run = db.get(ExperimentRun, run_id)
    if run is None:
        raise APIError(404, "EXPERIMENT_NOT_FOUND", "No such experiment run")
    return run


@router.get("/{run_id}", response_model=ExperimentOut)
def get_experiment(run_id: uuid.UUID, _: Reader, db: DbSession) -> ExperimentOut:
    return ExperimentOut.build(_run_or_404(db, run_id))


@router.get("/{run_id}/raw", response_model=None)
def get_raw(
    run_id: uuid.UUID,
    _: Reader,
    db: DbSession,
    section: Section = "detection",
    format: Literal["json", "csv"] = Query(default="json"),  # noqa: A002
) -> Any:
    run = _run_or_404(db, run_id)
    rows = (run.raw_results or {}).get(section, [])
    if format == "json":
        return rows
    flat = [{k: v for k, v in row.items() if not isinstance(v, list | dict)} for row in rows]
    buffer = io.StringIO()
    if flat:
        # jsonb does not preserve key order, so columns are written in sorted order.
        columns = sorted({key for row in flat for key in row})
        writer = csv.DictWriter(buffer, fieldnames=columns)
        writer.writeheader()
        writer.writerows(flat)
    return PlainTextResponse(buffer.getvalue(), media_type="text/csv")
