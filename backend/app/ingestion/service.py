"""Append events to a stream: enrich, check provenance, hash, store (paper §IV steps 1–4, 7).

The caller owns the transaction and must commit. A per-stream PostgreSQL advisory lock is
taken first and held until that commit, so concurrent appends cannot claim the same
predecessor (ARCHITECTURE §8). Full batches are sealed in the same transaction (Q10).

Ingestion policy (Q6): the candidate event is checked with the *same* provenance code the
verifier uses. A violating event is not stored; a sessionless SECURITY_VIOLATION event is
stored instead. Every stored record therefore satisfied provenance when it was captured.
"""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.batching.service import seal_batches
from app.crypto.canonical import AuditRecord, canonical_json, normalize_text
from app.crypto.chain import ChainedRecord, compute_entry_hash
from app.db.models import AuditEvent, LogStream
from app.ingestion.locks import lock_stream
from app.provenance.checks import ProvenanceFinding, check_provenance
from app.provenance.rules import TransitionRules

SECURITY_VIOLATION = "SECURITY_VIOLATION"


@dataclass(frozen=True)
class EventInput:
    """What a client may supply. Everything else is assigned by the server."""

    actor_user_id: str | None
    session_id: str | None
    event_type: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class IngestResult:
    event: AuditEvent  # the stored event: the requested one, or the SECURITY_VIOLATION
    violations: tuple[ProvenanceFinding, ...] = ()

    @property
    def accepted(self) -> bool:
        return not self.violations


def _utc_now() -> datetime:
    return datetime.now(UTC)


def to_chained(row: AuditEvent) -> ChainedRecord:
    record = AuditRecord(
        event_type=row.event_type,
        event_payload=row.event_payload,
        actor_user_id=row.actor_user_id,
        session_id=row.session_id,
        prev_event_type=row.prev_event_type,
        session_seq=row.session_seq,
        event_timestamp=row.event_timestamp,
    )
    return ChainedRecord(row.chain_index, record, bytes(row.prev_hash), bytes(row.entry_hash))


def _optional_text(value: str | None) -> str | None:
    return None if value is None else normalize_text(value)


def append_event(
    db: Session,
    stream: LogStream,
    event: EventInput,
    rules: TransitionRules,
    clock: Callable[[], datetime] = _utc_now,
) -> IngestResult:
    """Raises CanonicalizationError for values that cannot be encoded (caller maps to 422)."""
    payload = json.loads(canonical_json(event.payload))  # stored in normalised form
    actor = _optional_text(event.actor_user_id)
    session_id = _optional_text(event.session_id)
    event_type = normalize_text(event.event_type)

    lock_stream(db, stream.id)

    head = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.stream_id == stream.id)
        .order_by(AuditEvent.chain_index.desc())
        .limit(1)
    ).first()
    timestamp = clock()
    if head is not None and timestamp < head.event_timestamp:
        timestamp = head.event_timestamp  # keep the chain's timestamps non-decreasing (Q15)

    history: list[AuditEvent] = []
    if session_id is not None:
        history = list(
            db.scalars(
                select(AuditEvent)
                .where(AuditEvent.stream_id == stream.id, AuditEvent.session_id == session_id)
                .order_by(AuditEvent.chain_index)
            )
        )
        last = history[-1] if history else None
        prev_type: str | None = last.event_type if last else rules.start_event
        seq: int | None = (last.session_seq or 0) + 1 if last else 1
    else:
        prev_type, seq = None, None

    record = AuditRecord(event_type, payload, actor, session_id, prev_type, seq, timestamp)
    candidate = ChainedRecord(0, record, b"", b"")
    findings = check_provenance([*map(to_chained, history), candidate], rules).findings
    violations = tuple(f for f in findings if f.position == len(history) + 1)

    if violations:
        record = AuditRecord(
            SECURITY_VIOLATION,
            {
                "attempted_event_type": event_type,
                "attempted_session_id": session_id,
                "failed_checks": sorted({str(v.check) for v in violations}),
            },
            actor,
            None,
            None,
            None,
            timestamp,
        )
    stored = _insert(db, stream, head, record)
    seal_batches(db, stream)
    return IngestResult(stored, violations)


def _insert(
    db: Session, stream: LogStream, head: AuditEvent | None, record: AuditRecord
) -> AuditEvent:
    prev_hash = bytes(head.entry_hash) if head is not None else bytes(stream.genesis_hash)
    row = AuditEvent(
        stream_id=stream.id,
        chain_index=(head.chain_index + 1) if head is not None else 1,
        event_type=record.event_type,
        event_payload=dict(record.event_payload),
        actor_user_id=record.actor_user_id,
        session_id=record.session_id,
        prev_event_type=record.prev_event_type,
        session_seq=record.session_seq,
        event_timestamp=record.event_timestamp,
        prev_hash=prev_hash,
        entry_hash=compute_entry_hash(record, prev_hash),
    )
    db.add(row)
    db.flush()
    return row
