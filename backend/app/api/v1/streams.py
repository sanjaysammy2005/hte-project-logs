"""Log streams and their events (ingest, list, detail, session view)."""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import Admin, DbSession, Ingestor, Reader, RulesDep
from app.api.v1.schemas import (
    EventBatch,
    EventDetail,
    EventIn,
    EventOut,
    EventPage,
    Predecessor,
    StreamCreate,
    StreamDetail,
    StreamOut,
    stream_out,
)
from app.batching.service import batch_for
from app.core.errors import APIError
from app.crypto.canonical import CanonicalizationError
from app.crypto.chain import GENESIS_HASH, HASH_SCHEME, compute_entry_hash
from app.crypto.merkle import MERKLE_SCHEME
from app.db.models import SYSTEM_STREAM_NAME, AuditEvent, LogStream, VerificationRun
from app.ingestion.service import SECURITY_VIOLATION, EventInput, append_event, to_chained

router = APIRouter(tags=["streams"])


def stream_or_404(db: Session, stream_id: uuid.UUID) -> LogStream:
    stream = db.get(LogStream, stream_id)
    if stream is None:
        raise APIError(404, "STREAM_NOT_FOUND", "No such stream")
    return stream


def _record_count(db: Session, stream_id: uuid.UUID) -> int:
    return db.scalar(select(func.count()).where(AuditEvent.stream_id == stream_id)) or 0


@router.get("/streams", response_model=list[StreamOut])
def list_streams(_: Reader, db: DbSession) -> list[StreamOut]:
    counts = dict(
        db.execute(select(AuditEvent.stream_id, func.count()).group_by(AuditEvent.stream_id)).all()
    )
    newest = (
        select(VerificationRun.stream_id, func.max(VerificationRun.started_at).label("at"))
        .group_by(VerificationRun.stream_id)
        .subquery()
    )
    latest = select(VerificationRun.stream_id, VerificationRun.status).join(
        newest,
        (VerificationRun.stream_id == newest.c.stream_id)
        & (VerificationRun.started_at == newest.c.at),
    )
    statuses = dict(db.execute(latest).all())
    streams = db.scalars(select(LogStream).order_by(LogStream.created_at, LogStream.name))
    return [stream_out(s, counts.get(s.id, 0), statuses.get(s.id)) for s in streams]


@router.post("/streams", response_model=StreamDetail, status_code=status.HTTP_201_CREATED)
def create_stream(body: StreamCreate, _: Admin, db: DbSession) -> StreamDetail:
    if db.scalars(select(LogStream.id).where(LogStream.name == body.name)).first():
        raise APIError(409, "STREAM_NAME_TAKEN", "A stream with that name already exists")
    stream = LogStream(
        name=body.name,
        kind="primary",
        genesis_hash=GENESIS_HASH,
        hash_scheme=HASH_SCHEME,
        merkle_scheme=MERKLE_SCHEME,
        batch_size=body.batch_size,
        description=body.description,
    )
    db.add(stream)
    db.commit()
    return StreamDetail.build(stream, 0)


@router.get("/streams/{stream_id}", response_model=StreamDetail)
def get_stream(stream_id: uuid.UUID, _: Reader, db: DbSession) -> StreamDetail:
    stream = stream_or_404(db, stream_id)
    return StreamDetail.build(stream, _record_count(db, stream_id))


@router.post(
    "/streams/{stream_id}/events", response_model=EventOut, status_code=status.HTTP_201_CREATED
)
def ingest_event(
    stream_id: uuid.UUID, body: EventIn, _: Ingestor, db: DbSession, rules: RulesDep
) -> EventOut:
    stream = stream_or_404(db, stream_id)
    if stream.kind != "primary" or stream.name == SYSTEM_STREAM_NAME:
        raise APIError(403, "STREAM_NOT_WRITABLE", "Events cannot be ingested into this stream")
    accepted_types = (rules.session_events | rules.sessionless_events) - {SECURITY_VIOLATION}
    if body.event_type not in accepted_types:
        raise APIError(
            422,
            "UNKNOWN_EVENT_TYPE",
            f"Unknown event type {body.event_type!r}",
            {"accepted": sorted(accepted_types)},
        )
    try:
        result = append_event(
            db,
            stream,
            EventInput(body.actor_user_id, body.session_id, body.event_type, body.payload),
            rules,
        )
    except CanonicalizationError as exc:
        db.rollback()
        raise APIError(422, "INVALID_EVENT", str(exc)) from exc
    db.commit()
    if not result.accepted:
        raise APIError(
            409,
            "PROVENANCE_VIOLATION",
            "Event rejected: it would break the session's provenance rules",
            {
                "failed_checks": [
                    {"check": str(v.check), "expected": v.expected, "actual": v.actual}
                    for v in result.violations
                ],
                "security_event_chain_index": result.event.chain_index,
            },
        )
    return EventOut.build(result.event)


@router.get("/streams/{stream_id}/events", response_model=EventPage)
def list_events(
    stream_id: uuid.UUID,
    _: Reader,
    db: DbSession,
    actor_user_id: str | None = None,
    session_id: str | None = None,
    event_type: str | None = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    cursor: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> EventPage:
    stream_or_404(db, stream_id)
    query = select(AuditEvent).where(AuditEvent.stream_id == stream_id)
    for column, value in (
        (AuditEvent.actor_user_id, actor_user_id),
        (AuditEvent.session_id, session_id),
        (AuditEvent.event_type, event_type),
    ):
        if value is not None:
            query = query.where(column == value)
    if from_ is not None:
        query = query.where(AuditEvent.event_timestamp >= from_)
    if to is not None:
        query = query.where(AuditEvent.event_timestamp <= to)
    if cursor is not None:
        query = query.where(AuditEvent.chain_index > cursor)
    rows = list(db.scalars(query.order_by(AuditEvent.chain_index).limit(limit + 1)))
    next_cursor = rows[limit - 1].chain_index if len(rows) > limit else None
    return EventPage(items=[EventOut.build(r) for r in rows[:limit]], next_cursor=next_cursor)


@router.get("/streams/{stream_id}/events/{chain_index}", response_model=EventDetail)
def get_event(stream_id: uuid.UUID, chain_index: int, _: Reader, db: DbSession) -> EventDetail:
    stream = stream_or_404(db, stream_id)
    row = db.scalars(
        select(AuditEvent).where(
            AuditEvent.stream_id == stream_id, AuditEvent.chain_index == chain_index
        )
    ).first()
    if row is None:
        raise APIError(404, "EVENT_NOT_FOUND", "No event at that chain index")
    predecessor = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.stream_id == stream_id, AuditEvent.chain_index < chain_index)
        .order_by(AuditEvent.chain_index.desc())
        .limit(1)
    ).first()
    pred_hash = bytes(predecessor.entry_hash) if predecessor else bytes(stream.genesis_hash)
    chained = to_chained(row)
    batch = batch_for(db, stream, chain_index)
    try:
        recomputed: bytes | None = compute_entry_hash(chained.record, chained.prev_hash)
    except CanonicalizationError:
        recomputed = None
    return EventDetail(
        record=EventOut.build(row),
        predecessor=Predecessor(
            chain_index=predecessor.chain_index if predecessor else None,
            entry_hash=pred_hash.hex(),
        ),
        recomputed_hash=recomputed.hex() if recomputed else None,
        hash_matches=recomputed == chained.entry_hash,
        link_matches=chained.prev_hash == pred_hash,
        batch=EventBatch(batch_id=batch.id, batch_index=batch.batch_index) if batch else None,
    )


@router.get("/streams/{stream_id}/sessions/{session_id}", response_model=list[EventOut])
def get_session(stream_id: uuid.UUID, session_id: str, _: Reader, db: DbSession) -> list[EventOut]:
    stream_or_404(db, stream_id)
    rows = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.stream_id == stream_id, AuditEvent.session_id == session_id)
        .order_by(AuditEvent.session_seq, AuditEvent.chain_index)
    )
    return [EventOut.build(r) for r in rows]
