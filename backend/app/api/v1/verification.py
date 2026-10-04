"""Batches, membership proofs and verification runs (API_SPEC §3, Phase 6)."""

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app.api.deps import Admin, DbSession, Reader, RulesDep
from app.api.v1.streams import stream_or_404
from app.batching.service import StreamInconsistentError, batch_for, proof_for, seal_batches
from app.core.errors import APIError
from app.crypto.merkle import ProofStep, verify_proof
from app.db.models import Batch, VerificationFinding, VerificationRun
from app.verification.engine import verify_stream

router = APIRouter(tags=["verification"])

Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class BatchOut(BaseModel):
    batch_id: uuid.UUID
    batch_index: int
    first_chain_index: int
    last_chain_index: int
    leaf_count: int
    merkle_root: str
    sealed_at: datetime

    @classmethod
    def build(cls, b: Batch) -> "BatchOut":
        return cls(
            batch_id=b.id,
            batch_index=b.batch_index,
            first_chain_index=b.first_chain_index,
            last_chain_index=b.last_chain_index,
            leaf_count=b.leaf_count,
            merkle_root=bytes(b.merkle_root).hex(),
            sealed_at=b.sealed_at,
        )


class SealIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    include_partial: bool = False


class ProofStepOut(BaseModel):
    sibling: Hex32
    position: Literal["left", "right"]


class ProofOut(BaseModel):
    chain_index: int
    leaf: str
    batch_id: uuid.UUID
    batch_index: int
    merkle_root: str
    proof: list[ProofStepOut]


class ProofVerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    leaf: Hex32
    merkle_root: Hex32
    proof: list[ProofStepOut] = Field(max_length=64)


class FindingOut(BaseModel):
    chain_index: int | None
    batch_id: uuid.UUID | None
    check: str
    expected: str
    actual: str


class FirstFailure(BaseModel):
    chain_index: int | None
    batch_id: uuid.UUID | None
    batch_index: int | None
    check: str


class RunSummary(BaseModel):
    run_id: uuid.UUID
    stream_id: uuid.UUID
    status: str
    first_failure: FirstFailure | None
    records_checked: int
    unbatched_records: int
    batches_checked: int
    failed_by_check: dict[str, int]
    findings_total: int
    cascade_affected_records: int
    rules_version: str
    hash_scheme: str
    merkle_scheme: str
    started_at: datetime
    duration_ms: float

    @classmethod
    def build(cls, run: VerificationRun) -> "RunSummary":
        r = run.report
        first = None
        if run.first_failed_check is not None:
            first = FirstFailure(
                chain_index=run.first_failing_chain_index,
                batch_id=run.first_failing_batch_id,
                batch_index=r.get("first_failure_batch_index"),
                check=run.first_failed_check,
            )
        return cls(
            run_id=run.id,
            stream_id=run.stream_id,
            status=run.status,
            first_failure=first,
            records_checked=run.records_checked,
            unbatched_records=run.unbatched_records,
            batches_checked=r["batches_checked"],
            failed_by_check=r["failed_by_check"],
            findings_total=r["findings_total"],
            cascade_affected_records=r["cascade_affected_records"],
            rules_version=run.rules_version,
            hash_scheme=r["hash_scheme"],
            merkle_scheme=r["merkle_scheme"],
            started_at=run.started_at,
            duration_ms=run.duration_ms,
        )


class RunDetail(RunSummary):
    findings: list[FindingOut]
    findings_stored: int


def _run_detail(db: DbSession, run: VerificationRun, limit: int, offset: int) -> RunDetail:
    query = select(VerificationFinding).where(VerificationFinding.run_id == run.id)
    rows = db.scalars(query.order_by(VerificationFinding.id).offset(offset).limit(limit))
    stored = db.scalar(select(func.count()).where(VerificationFinding.run_id == run.id)) or 0
    return RunDetail(
        **RunSummary.build(run).model_dump(),
        findings=[
            FindingOut(
                chain_index=f.chain_index,
                batch_id=f.batch_id,
                check=f.check_name,
                expected=f.expected,
                actual=f.actual,
            )
            for f in rows
        ],
        findings_stored=stored,
    )


@router.get("/streams/{stream_id}/batches", response_model=list[BatchOut])
def list_batches(stream_id: uuid.UUID, _: Reader, db: DbSession) -> list[BatchOut]:
    stream_or_404(db, stream_id)
    rows = db.scalars(select(Batch).where(Batch.stream_id == stream_id).order_by(Batch.batch_index))
    return [BatchOut.build(b) for b in rows]


@router.post("/streams/{stream_id}/batches/seal", response_model=list[BatchOut])
def seal(stream_id: uuid.UUID, body: SealIn, _: Admin, db: DbSession) -> list[BatchOut]:
    stream = stream_or_404(db, stream_id)
    try:
        created = seal_batches(db, stream, include_partial=body.include_partial)
    except StreamInconsistentError as exc:
        db.rollback()
        raise APIError(409, "STREAM_INCONSISTENT", f"Cannot seal: {exc}") from exc
    db.commit()
    return [BatchOut.build(b) for b in created]


@router.get("/streams/{stream_id}/events/{chain_index}/proof", response_model=ProofOut)
def get_proof(stream_id: uuid.UUID, chain_index: int, _: Reader, db: DbSession) -> ProofOut:
    stream = stream_or_404(db, stream_id)
    batch = batch_for(db, stream, chain_index)
    if batch is None:
        raise APIError(404, "EVENT_NOT_BATCHED", "No sealed batch covers that chain index")
    try:
        leaf, proof = proof_for(db, stream, batch, chain_index)
    except StreamInconsistentError as exc:
        raise APIError(409, "STREAM_INCONSISTENT", f"Cannot build proof: {exc}") from exc
    return ProofOut(
        chain_index=chain_index,
        leaf=leaf.hex(),
        batch_id=batch.id,
        batch_index=batch.batch_index,
        merkle_root=bytes(batch.merkle_root).hex(),
        proof=[ProofStepOut(sibling=s.sibling.hex(), position=s.position) for s in proof],
    )


@router.post("/proofs/verify")
def verify_membership(body: ProofVerifyIn, _: Reader) -> dict[str, bool]:
    steps = [ProofStep(bytes.fromhex(s.sibling), s.position) for s in body.proof]
    valid = verify_proof(bytes.fromhex(body.leaf), steps, bytes.fromhex(body.merkle_root))
    return {"valid": valid}


@router.post(
    "/streams/{stream_id}/verify", response_model=RunDetail, status_code=status.HTTP_201_CREATED
)
def verify(stream_id: uuid.UUID, current: Reader, db: DbSession, rules: RulesDep) -> RunDetail:
    stream = stream_or_404(db, stream_id)
    run, _ = verify_stream(db, stream, rules, triggered_by=current.operator.id)
    db.commit()
    return _run_detail(db, run, limit=100, offset=0)


@router.get("/streams/{stream_id}/verification-runs", response_model=list[RunSummary])
def list_runs(stream_id: uuid.UUID, _: Reader, db: DbSession) -> list[RunSummary]:
    stream_or_404(db, stream_id)
    runs = db.scalars(
        select(VerificationRun)
        .where(VerificationRun.stream_id == stream_id)
        .order_by(VerificationRun.started_at.desc())
        .limit(100)
    )
    return [RunSummary.build(r) for r in runs]


@router.get("/verification-runs/{run_id}", response_model=RunDetail)
def get_run(
    run_id: uuid.UUID,
    _: Reader,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> RunDetail:
    run = db.get(VerificationRun, run_id)
    if run is None:
        raise APIError(404, "RUN_NOT_FOUND", "No such verification run")
    return _run_detail(db, run, limit, offset)
