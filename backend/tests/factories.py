"""Test data builders for audit records and chains."""

import random
import unicodedata
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from app.crypto.canonical import START_EVENT, AuditRecord
from app.crypto.chain import ChainedRecord, build_chain

BASE_TIME = datetime(2026, 10, 4, 10, 15, 30, tzinfo=UTC)

# Text that changes under NFC normalisation, so variants can use the decomposed form.
_UNICODE_WORDS = ["café", "Ångström", "naïve", "résumé", "東京", "😀", "plain", "Ωmega", "über"]
_PAYLOAD_KEYS = ["resource", "ip_address", "outcome", "détail", "zone", "a", "B", "ñ", "key"]
_EVENT_TYPES = ["LOGIN", "AUTHENTICATION", "FILE_OPEN", "FILE_EDIT", "DB_ACCESS", "LOGOUT"]


def record_from_dict(data: dict[str, Any]) -> AuditRecord:
    """Build an AuditRecord from the dict format used by tests/reference_tl_v1.py."""
    return AuditRecord(
        event_type=data["event_type"],
        event_payload=data["event_payload"],
        actor_user_id=data["actor_user_id"],
        session_id=data["session_id"],
        prev_event_type=data["prev_event_type"],
        session_seq=data["session_seq"],
        event_timestamp=datetime.fromisoformat(data["event_timestamp"]),
    )


def record_to_dict(record: AuditRecord) -> dict[str, Any]:
    return {
        "event_type": record.event_type,
        "event_payload": record.event_payload,
        "actor_user_id": record.actor_user_id,
        "session_id": record.session_id,
        "prev_event_type": record.prev_event_type,
        "session_seq": record.session_seq,
        "event_timestamp": record.event_timestamp.isoformat(),
    }


def make_session(
    user: str = "U101",
    session: str = "S5001",
    events: tuple[str, ...] = ("LOGIN", "AUTHENTICATION", "FILE_OPEN", "FILE_EDIT", "LOGOUT"),
    start: datetime = BASE_TIME,
) -> list[AuditRecord]:
    """One well-formed session (the paper's §VI-F example sequence by default)."""
    records = []
    prev = START_EVENT
    for seq, event_type in enumerate(events, start=1):
        records.append(
            AuditRecord(
                event_type=event_type,
                event_payload={"step": seq},
                actor_user_id=user,
                session_id=session,
                prev_event_type=prev,
                session_seq=seq,
                event_timestamp=start + timedelta(seconds=seq),
            )
        )
        prev = event_type
    return records


def make_chain(length: int, seed: int = 7) -> list[ChainedRecord]:
    rng = random.Random(seed)
    return build_chain(random_record(rng, offset_seconds=i) for i in range(length))


def _random_scalar(rng: random.Random) -> Any:
    choice = rng.randrange(5)
    if choice == 0:
        return rng.choice(_UNICODE_WORDS) + rng.choice(['"', "\\", "\n", "\t", "\x01", "/", ""])
    if choice == 1:
        return rng.randint(-(2**53 - 1), 2**53 - 1)
    if choice == 2:
        return rng.choice([True, False])
    if choice == 3:
        return None
    return str(rng.randint(0, 999))


def random_payload(rng: random.Random, depth: int = 0) -> dict[str, Any]:
    keys = rng.sample(_PAYLOAD_KEYS, rng.randint(0, 5))
    payload: dict[str, Any] = {}
    for key in keys:
        kind = rng.randrange(6) if depth < 2 else 0
        if kind == 4:
            payload[key] = random_payload(rng, depth + 1)
        elif kind == 5:
            payload[key] = [_random_scalar(rng) for _ in range(rng.randint(0, 3))]
        else:
            payload[key] = _random_scalar(rng)
    return payload


def random_record(rng: random.Random, offset_seconds: int = 0) -> AuditRecord:
    sessionless = rng.random() < 0.15
    user = f"U{rng.randint(1, 99)}-{rng.choice(_UNICODE_WORDS)}"
    return AuditRecord(
        event_type=rng.choice(_EVENT_TYPES),
        event_payload=random_payload(rng),
        actor_user_id=None if sessionless else user,
        session_id=None if sessionless else f"S{rng.randint(1, 9999)}",
        prev_event_type=None if sessionless else rng.choice([START_EVENT, *_EVENT_TYPES]),
        session_seq=None if sessionless else rng.randint(1, 500),
        event_timestamp=BASE_TIME
        + timedelta(seconds=offset_seconds, microseconds=rng.randint(0, 999_999)),
    )


def _nfd(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFD", value)
    if isinstance(value, dict):
        return {_nfd(k): _nfd(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_nfd(v) for v in value]
    return value


def _shuffled(value: Any, rng: random.Random) -> Any:
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {k: _shuffled(v, rng) for k, v in items}
    if isinstance(value, list):
        return [_shuffled(v, rng) for v in value]
    return value


def equivalent_variant(record: AuditRecord, rng: random.Random) -> AuditRecord:
    """Same logical record, different representation: key order, NFD text, other time zone."""
    offset = timezone(timedelta(minutes=rng.choice([-720, -330, -60, 0, 60, 330, 345, 840])))
    payload = _shuffled(_nfd(record.event_payload), rng)
    if rng.random() < 0.5:
        payload = {k: (tuple(v) if isinstance(v, list) else v) for k, v in payload.items()}
    return AuditRecord(
        event_type=_nfd(record.event_type),
        event_payload=payload,
        actor_user_id=_nfd(record.actor_user_id),
        session_id=_nfd(record.session_id),
        prev_event_type=_nfd(record.prev_event_type),
        session_seq=record.session_seq,
        event_timestamp=record.event_timestamp.astimezone(offset),
    )
