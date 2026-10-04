"""T5.4: concurrent appends produce one gapless, valid chain (per-stream advisory lock)."""

from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.crypto.chain import GENESIS_HASH, verify_chain
from app.db.models import AuditEvent, LogStream
from app.ingestion.service import EventInput, append_event, to_chained
from app.provenance.checks import check_provenance
from app.provenance.rules import load_rules

CLIENTS = 20
EVENTS_PER_CLIENT = 50


def test_parallel_clients_produce_a_gapless_valid_chain(test_engine: Engine) -> None:
    rules = load_rules()
    with Session(test_engine) as db:
        stream = LogStream(
            name="concurrency",
            kind="primary",
            genesis_hash=GENESIS_HASH,
            hash_scheme="tl-v1",
            merkle_scheme="paper-dup-v1",
            batch_size=64,
        )
        db.add(stream)
        db.commit()
        stream_id = stream.id

    def client(n: int) -> int:
        events = ["LOGIN", "AUTHENTICATION"] + ["DB_ACCESS"] * (EVENTS_PER_CLIENT - 3) + ["LOGOUT"]
        accepted = 0
        with Session(test_engine) as db:
            target = db.get(LogStream, stream_id)
            assert target is not None
            for event_type in events:
                result = append_event(
                    db, target, EventInput(f"U{n}", f"S{n}", event_type, {"client": n}), rules
                )
                db.commit()
                accepted += result.accepted
        return accepted

    with ThreadPoolExecutor(max_workers=CLIENTS) as pool:
        accepted = sum(pool.map(client, range(CLIENTS)))

    with Session(test_engine) as db:
        rows = list(
            db.scalars(
                select(AuditEvent)
                .where(AuditEvent.stream_id == stream_id)
                .order_by(AuditEvent.chain_index)
            )
        )
    chained = [to_chained(r) for r in rows]

    assert accepted == CLIENTS * EVENTS_PER_CLIENT
    assert [c.chain_index for c in chained] == list(range(1, CLIENTS * EVENTS_PER_CLIENT + 1))
    assert verify_chain(chained).is_valid
    assert check_provenance(chained, rules).is_valid
    # Sessions really did interleave (otherwise the lock was never contended).
    sessions_in_order = [c.record.session_id for c in chained]
    switches = sum(a != b for a, b in zip(sessions_in_order, sessions_in_order[1:], strict=False))
    assert switches > CLIENTS


def test_clock_stepping_backwards_never_breaks_timestamp_order(test_engine: Engine) -> None:
    """Q15: timestamps are server-assigned under the lock and clamped to be non-decreasing."""
    from datetime import UTC, datetime

    rules = load_rules()
    times = iter(
        [datetime(2026, 10, 4, 12, 0, tzinfo=UTC), datetime(2026, 10, 4, 11, 0, tzinfo=UTC)]
    )
    with Session(test_engine, expire_on_commit=False) as db:
        stream = LogStream(
            name="clock",
            kind="primary",
            genesis_hash=GENESIS_HASH,
            hash_scheme="tl-v1",
            merkle_scheme="paper-dup-v1",
            batch_size=64,
        )
        db.add(stream)
        db.commit()
        first = append_event(
            db, stream, EventInput(None, None, "LOGIN_FAILED", {}), rules, clock=lambda: next(times)
        ).event
        second = append_event(
            db, stream, EventInput(None, None, "LOGIN_FAILED", {}), rules, clock=lambda: next(times)
        ).event
        db.commit()

    assert second.event_timestamp == first.event_timestamp
    assert check_provenance([to_chained(first), to_chained(second)], rules).is_valid
