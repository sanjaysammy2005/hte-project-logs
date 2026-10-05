"""File security investigation endpoints (ZERO_TRUST_FILE_MODULE §29). Admin and auditor only.

All answers come from the chained audit events of the system stream; nothing here writes.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query

from app.api.deps import DbSession, Reader, RulesDep, StorageDep
from app.core.errors import APIError
from app.crypto.canonical import format_timestamp
from app.db.models import AuditEvent
from app.files.schemas import FileVersionOut
from app.investigation.service import CATEGORIES, EventQuery, Investigation, summary

router = APIRouter(prefix="/security", tags=["security"])
Category = Literal[tuple(CATEGORIES)]  # type: ignore[valid-type]


def get_investigation(
    _: Reader, db: DbSession, storage: StorageDep, rules: RulesDep
) -> Investigation:
    """Security administrators (admin) and auditors only."""
    return Investigation(db, storage, rules)


Inv = Annotated[Investigation, Depends(get_investigation)]


def _full(e: AuditEvent) -> dict[str, Any]:
    return {
        "chain_index": e.chain_index,
        "event_type": e.event_type,
        "timestamp": format_timestamp(e.event_timestamp),
        "user": e.actor_user_id,
        "session_id": e.session_id,
        "prev_event_type": e.prev_event_type,
        "session_seq": e.session_seq,
        "payload": e.event_payload,
        "prev_hash": bytes(e.prev_hash).hex(),
        "entry_hash": bytes(e.entry_hash).hex(),
    }


def _event_or_404(inv: Investigation, chain_index: int) -> AuditEvent:
    event = inv.event(chain_index)
    if event is None:
        raise APIError(404, "EVENT_NOT_FOUND", "No event at that chain index in the system stream")
    return event


@router.get("/events")
def search_events(
    inv: Inv,
    user: Annotated[str | None, Query(max_length=128)] = None,
    file_id: uuid.UUID | None = None,
    action: Annotated[str | None, Query(pattern=r"^[A-Z_]{1,32}$")] = None,
    decision: Literal["ALLOW", "DENY", "BLOCKED"] | None = None,
    classification: Annotated[str | None, Query(pattern=r"^[A-Z_]{1,32}$")] = None,
    event_type: Annotated[list[str] | None, Query()] = None,
    category: Category | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> dict[str, Any]:
    """Search file-security events, newest first. ``cursor`` = next page's starting point."""
    rows, next_cursor = inv.search(
        EventQuery(
            user=user,
            file_id=file_id,
            action=action,
            decision=decision,
            classification=classification,
            event_types=tuple(event_type or ()),
            category=category,
            since=since,
            until=until,
            before_chain_index=cursor,
            limit=limit,
        )
    )
    return {"items": [summary(e) for e in rows], "next_cursor": next_cursor}


@router.get("/events/{chain_index}")
def inspect_event(chain_index: int, inv: Inv) -> dict[str, Any]:
    """One event with its hash-chain neighbours, its Merkle batch and the related file."""
    event = _event_or_404(inv, chain_index)
    related: dict[str, Any] | None = None
    file_id = (event.event_payload or {}).get("file_id")
    if file_id:
        try:
            file = inv.file(uuid.UUID(file_id))
        except ValueError:
            file = None
        if file is not None:
            related = {
                "file_id": str(file.id),
                "display_name": file.display_name,
                "classification": file.classification,
                "current_version": file.current_version,
                "deleted": file.deleted_at is not None,
                "versions": [FileVersionOut.build(v) for v in inv.file_versions(file)],
            }
    return {
        "event": _full(event),
        "chain": inv.chain_relationship(event),
        "merkle": inv.merkle_status(event),
        "related_file": related,
    }


@router.post("/events/{chain_index}/verify")
def verify_event(chain_index: int, inv: Inv) -> dict[str, Any]:
    """Re-verify one event: hash, links to both neighbours, Merkle batch, session provenance."""
    return inv.verify_event(_event_or_404(inv, chain_index))


def _file_or_404(inv: Investigation, file_id: uuid.UUID):
    file = inv.file(file_id)
    if file is None:
        raise APIError(404, "FILE_NOT_FOUND", "File not found")
    return file


@router.get("/files/{file_id}/timeline")
def file_timeline(file_id: uuid.UUID, inv: Inv) -> dict[str, Any]:
    """Every chained event about a file, oldest first, with its versions."""
    file = _file_or_404(inv, file_id)
    return {
        "file_id": str(file.id),
        "display_name": file.display_name,
        "classification": file.classification,
        "owner_id": str(file.owner_id),
        "deleted": file.deleted_at is not None,
        "versions": [FileVersionOut.build(v) for v in inv.file_versions(file)],
        "events": [summary(e) for e in inv.file_timeline(file.id)],
    }


@router.get("/files/{file_id}/integrity")
def file_integrity(file_id: uuid.UUID, inv: Inv) -> dict[str, Any]:
    """FILE INTEGRITY vs AUDIT LOG INTEGRITY for one file (read-only; nothing is recorded)."""
    return inv.file_integrity(_file_or_404(inv, file_id))


@router.get("/findings")
def findings(
    inv: Inv,
    since: datetime | None = None,
    until: datetime | None = None,
    threshold: Annotated[int, Query(ge=1, le=10_000)] = 5,
) -> dict[str, Any]:
    """Repeated denials, unauthenticated attempts, high-frequency downloads, probing, integrity
    failures, break-glass self-grants, downgrades, deletions. Heuristics, not detection."""
    until = until or datetime.now(UTC)
    since = since or until - timedelta(hours=24)
    if since > until:
        raise APIError(422, "INVALID_WINDOW", "since must be before until")
    return inv.findings(since, until, threshold)
