"""Request and response models (docs/API_SPEC.md)."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.crypto.canonical import format_timestamp
from app.db.models import AuditEvent, LogStream

# Text identifiers: bounded length, no NUL (NUL also rejected by the canonical encoder).
Identifier = Field(min_length=1, max_length=128, pattern=r"^[^\x00]*$")


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Identifier
    password: str = Field(min_length=1, max_length=1024)


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    role: str


class OperatorCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Identifier
    password: str = Field(min_length=12, max_length=1024)
    role: Literal["admin", "auditor", "ingestor"]


class OperatorOut(BaseModel):
    id: uuid.UUID
    username: str
    role: str


class StreamCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Identifier
    batch_size: int = Field(default=64, ge=1, le=4096)
    description: str | None = Field(default=None, max_length=1000)


class StreamOut(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    batch_size: int
    description: str | None
    created_at: datetime
    record_count: int
    last_verification_status: str | None = None


class StreamDetail(StreamOut):
    source_stream_id: uuid.UUID | None
    genesis_hash: str
    hash_scheme: str
    merkle_scheme: str

    @classmethod
    def build(cls, stream: LogStream, record_count: int) -> "StreamDetail":
        return cls(
            **_stream_fields(stream, record_count),
            source_stream_id=stream.source_stream_id,
            genesis_hash=bytes(stream.genesis_hash).hex(),
            hash_scheme=stream.hash_scheme,
            merkle_scheme=stream.merkle_scheme,
        )


def _stream_fields(stream: LogStream, record_count: int) -> dict[str, Any]:
    return {
        "id": stream.id,
        "name": stream.name,
        "kind": stream.kind,
        "batch_size": stream.batch_size,
        "description": stream.description,
        "created_at": stream.created_at,
        "record_count": record_count,
    }


def stream_out(stream: LogStream, record_count: int, last_status: str | None = None) -> StreamOut:
    return StreamOut(**_stream_fields(stream, record_count), last_verification_status=last_status)


class EventIn(BaseModel):
    """Client-supplied fields only. Server-assigned fields are rejected (extra='forbid')."""

    model_config = ConfigDict(extra="forbid")
    actor_user_id: str | None = Field(default=None, min_length=1, max_length=128)
    session_id: str | None = Field(default=None, min_length=1, max_length=128)
    event_type: str = Identifier
    payload: dict[str, Any] = Field(default_factory=dict)


class EventOut(BaseModel):
    chain_index: int
    event_type: str
    payload: dict[str, Any]
    actor_user_id: str | None
    session_id: str | None
    prev_event_type: str | None
    session_seq: int | None
    event_timestamp: str
    prev_hash: str
    entry_hash: str

    @classmethod
    def build(cls, row: AuditEvent) -> "EventOut":
        return cls(
            chain_index=row.chain_index,
            event_type=row.event_type,
            payload=row.event_payload,
            actor_user_id=row.actor_user_id,
            session_id=row.session_id,
            prev_event_type=row.prev_event_type,
            session_seq=row.session_seq,
            event_timestamp=format_timestamp(row.event_timestamp),
            prev_hash=bytes(row.prev_hash).hex(),
            entry_hash=bytes(row.entry_hash).hex(),
        )


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: int | None


class Predecessor(BaseModel):
    chain_index: int | None  # None: the predecessor is the genesis value
    entry_hash: str


class EventBatch(BaseModel):
    batch_id: uuid.UUID
    batch_index: int


class EventDetail(BaseModel):
    record: EventOut
    predecessor: Predecessor
    recomputed_hash: str | None  # None if the stored record cannot be encoded
    hash_matches: bool
    link_matches: bool
    batch: EventBatch | None  # None while the record is not yet in a sealed batch
