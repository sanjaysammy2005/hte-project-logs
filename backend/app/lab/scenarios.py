"""Tamper scenarios S1–S11 (EXPERIMENTS §3) applied to cloned 'lab' streams only.

Workflow (``run_scenario``): clone source -> plan target and record the expected outcome and
ground truth (committed) -> apply tampering with direct row changes -> verify -> record the
actual outcome. Expectations are therefore fixed before the verifier runs.

Attacker models: A0 edits stored fields only; A1 also recomputes the edited record's own hash
(SHA-256 is unkeyed); A2 recomputes every later hash and affected batch root (paper §IX-B).
"""

import random
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from app.crypto.canonical import AuditRecord
from app.crypto.chain import compute_entry_hash
from app.crypto.merkle import merkle_root
from app.db.models import AuditEvent, Batch, LogStream, TamperScenario
from app.ingestion.service import to_chained
from app.provenance.rules import TransitionRules
from app.verification.engine import verify_stream


class LabSafetyError(RuntimeError):
    """An attempt to mutate a stream that is not a lab clone."""


class ScenarioError(ValueError):
    """The scenario cannot be applied to this stream with these parameters."""


@dataclass(frozen=True)
class Plan:
    parameters: dict[str, Any]
    expected_detected: bool
    true_first_index: int | None


@dataclass(frozen=True)
class ScenarioDefinition:
    code: str
    attacker_model: str
    description: str
    plan: Callable[[Session, LogStream, random.Random, dict[str, Any]], Plan]
    apply: Callable[[Session, LogStream, dict[str, Any]], None]


# --- safety and helpers ------------------------------------------------------------------------


def assert_lab_stream(stream: LogStream) -> None:
    if stream.kind != "lab":
        raise LabSafetyError(f"refusing to tamper with {stream.kind!r} stream {stream.name!r}")


def clone_stream(
    db: Session,
    source: LogStream,
    name: str,
    copy_batches: bool = True,
    batch_size: int | None = None,
) -> LogStream:
    """Copy records (and batches) of ``source`` into a new 'lab' stream (identical hashes).

    With ``copy_batches=False`` and a new ``batch_size`` the copy can be re-sealed with a
    different batch size, which the experiments use to vary m without regenerating data.
    """
    clone = LogStream(
        name=name,
        kind="lab",
        source_stream_id=source.id,
        genesis_hash=source.genesis_hash,
        hash_scheme=source.hash_scheme,
        merkle_scheme=source.merkle_scheme,
        batch_size=batch_size or source.batch_size,
        generator_seed=source.generator_seed,
        description=f"Lab clone of {source.name}",
    )
    db.add(clone)
    db.flush()
    params = {"new": clone.id, "src": source.id}
    db.execute(
        text(
            "INSERT INTO audit_events (stream_id, chain_index, event_type, event_payload,"
            " actor_user_id, session_id, prev_event_type, session_seq, event_timestamp, prev_hash,"
            " entry_hash) SELECT :new, chain_index, event_type, event_payload, actor_user_id,"
            " session_id, prev_event_type, session_seq, event_timestamp, prev_hash, entry_hash"
            " FROM audit_events WHERE stream_id = :src"
        ),
        params,
    )
    if not copy_batches:
        return clone
    db.execute(
        text(
            "INSERT INTO batches (id, stream_id, batch_index, first_chain_index, last_chain_index,"
            " leaf_count, merkle_root, sealed_at) SELECT gen_random_uuid(), :new, batch_index,"
            " first_chain_index, last_chain_index, leaf_count, merkle_root, sealed_at"
            " FROM batches WHERE stream_id = :src"
        ),
        params,
    )
    return clone


def _head(db: Session, stream: LogStream) -> int:
    return (
        db.scalar(select(func.max(AuditEvent.chain_index)).where(AuditEvent.stream_id == stream.id))
        or 0
    )


def _row(db: Session, stream: LogStream, chain_index: int) -> AuditEvent:
    row = db.scalars(
        select(AuditEvent).where(
            AuditEvent.stream_id == stream.id, AuditEvent.chain_index == chain_index
        )
    ).first()
    if row is None:
        raise ScenarioError(f"no record at chain index {chain_index}")
    return row


def _batches(db: Session, stream: LogStream) -> list[Batch]:
    return list(
        db.scalars(select(Batch).where(Batch.stream_id == stream.id).order_by(Batch.batch_index))
    )


def _rehash(row: AuditEvent) -> None:
    row.entry_hash = compute_entry_hash(to_chained(row).record, bytes(row.prev_hash))


def _pick(rng: random.Random, params: dict[str, Any], low: int, high: int) -> int:
    if high < low:
        raise ScenarioError("stream is too short for this scenario")
    k = params.get("target_chain_index")
    if k is None:
        return rng.randint(low, high)
    if not low <= k <= high:
        raise ScenarioError(f"target_chain_index must be between {low} and {high}")
    return int(k)


def _shift(db: Session, stream: LogStream, from_index: int, delta: int) -> None:
    """Renumber records >= from_index by delta (two steps to respect the unique index)."""
    big = 1_000_000_000
    base = update(AuditEvent).where(AuditEvent.stream_id == stream.id)
    db.execute(
        base.where(AuditEvent.chain_index >= from_index).values(
            chain_index=AuditEvent.chain_index + big
        )
    )
    db.execute(
        base.where(AuditEvent.chain_index >= from_index + big).values(
            chain_index=AuditEvent.chain_index - big + delta
        )
    )


# --- plans -------------------------------------------------------------------------------------


def _plan_at_k(rng, db, stream, params, high_offset=0, low=1) -> int:
    return _pick(rng, params, low, _head(db, stream) - high_offset)


def plan_record(db, stream, rng, params) -> Plan:
    k = _plan_at_k(rng, db, stream, params)
    return Plan({"k": k}, True, k)


def plan_delete(db, stream, rng, params) -> Plan:
    k = _plan_at_k(rng, db, stream, params, high_offset=1)
    return Plan({"k": k}, True, k + 1)  # first affected stored record: the successor


def plan_insert(db, stream, rng, params) -> Plan:
    k = _plan_at_k(rng, db, stream, params, low=2)
    return Plan({"k": k}, True, k)  # the forged record now occupies index k


def plan_swap(db, stream, rng, params) -> Plan:
    n = _head(db, stream)
    k = _pick(rng, params, 1, n - 1)
    j = int(params.get("j") or rng.randint(k + 1, n))
    if not k < j <= n:
        raise ScenarioError(f"j must be between {k + 1} and {n}")
    return Plan({"k": k, "j": j}, True, k)


def plan_delete_batch(db, stream, rng, params) -> Plan:
    batches = _batches(db, stream)
    if len(batches) < 2:
        raise ScenarioError("needs at least two sealed batches")
    candidates = batches[:-1]  # a successor must exist
    chosen = params.get("batch_index")
    batch = (
        next((b for b in candidates if b.batch_index == chosen), None)
        if chosen
        else rng.choice(candidates)
    )
    if batch is None:
        raise ScenarioError(f"batch_index must be one of 1..{len(candidates)}")
    return Plan(
        {
            "batch_index": batch.batch_index,
            "first": batch.first_chain_index,
            "last": batch.last_chain_index,
        },
        True,
        batch.last_chain_index + 1,
    )


def plan_delete_authentication(db, stream, rng, params) -> Plan:
    n = _head(db, stream)
    rows = list(
        db.scalars(
            select(AuditEvent.chain_index)
            .where(
                AuditEvent.stream_id == stream.id,
                AuditEvent.event_type == "AUTHENTICATION",
                AuditEvent.chain_index < n,
            )
            .order_by(AuditEvent.chain_index)
        )
    )
    if not rows:
        raise ScenarioError("no AUTHENTICATION record with a successor")
    target = params.get("target_chain_index")
    k = next((r for r in rows if r >= target), rows[-1]) if target else rng.choice(rows)
    return Plan({"k": k}, True, k + 1)


def plan_tail(db, stream, rng, params) -> Plan:
    n = _head(db, stream)
    t = int(params.get("t") or 3)
    if not 1 <= t < n:
        raise ScenarioError(f"t must be between 1 and {n - 1}")
    return Plan({"t": t, "first_deleted": n - t + 1}, False, None)


def plan_rewrite(db, stream, rng, params) -> Plan:
    k = _plan_at_k(rng, db, stream, params)
    return Plan({"k": k}, False, None)


# --- tampering ---------------------------------------------------------------------------------


def apply_modify_payload(db, stream, p, recompute=False) -> None:
    row = _row(db, stream, p["k"])
    row.event_payload = {**row.event_payload, "tampered": True}
    if recompute:
        _rehash(row)


def apply_modify_user(db, stream, p) -> None:
    row = _row(db, stream, p["k"])
    row.actor_user_id = "U-ATTACKER"


def apply_modify_session(db, stream, p) -> None:
    row = _row(db, stream, p["k"])
    if row.session_id is None:
        row.session_id, row.session_seq = f"S-HIJACK-{p['k']}", 1
    else:
        row.session_id = f"S-HIJACK-{p['k']}"
    _rehash(row)


def apply_delete(db, stream, p) -> None:
    db.delete(_row(db, stream, p["k"]))


def apply_insert(db, stream, p) -> None:
    """Forge an activity for a fabricated session, with a correct link and own hash (A1)."""
    k = p["k"]
    predecessor = _row(db, stream, k - 1)
    _shift(db, stream, k, +1)
    record = AuditRecord(
        "FILE_OPEN",
        {"resource": "/forged/evidence.txt"},
        predecessor.actor_user_id or "U-FORGED",
        f"S-FORGED-{k}",
        "__START__",
        1,
        predecessor.event_timestamp,
    )
    prev_hash = bytes(predecessor.entry_hash)
    db.add(
        AuditEvent(
            stream_id=stream.id,
            chain_index=k,
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
    )


def apply_swap(db, stream, p) -> None:
    a, b = _row(db, stream, p["k"]), _row(db, stream, p["j"])
    a.chain_index = -1
    db.flush()
    b.chain_index = p["k"]
    db.flush()
    a.chain_index = p["j"]


def apply_delete_batch(db, stream, p) -> None:
    db.execute(
        AuditEvent.__table__.delete().where(
            AuditEvent.stream_id == stream.id,
            AuditEvent.chain_index >= p["first"],
            AuditEvent.chain_index <= p["last"],
        )
    )
    db.execute(
        Batch.__table__.delete().where(
            Batch.stream_id == stream.id, Batch.batch_index == p["batch_index"]
        )
    )


def apply_tail(db, stream, p) -> None:
    """Delete the newest records and every batch that covered any of them."""
    first = p["first_deleted"]
    db.execute(
        AuditEvent.__table__.delete().where(
            AuditEvent.stream_id == stream.id, AuditEvent.chain_index >= first
        )
    )
    db.execute(
        Batch.__table__.delete().where(
            Batch.stream_id == stream.id, Batch.last_chain_index >= first
        )
    )


def apply_rewrite(db, stream, p) -> None:
    """A2: modify record k, then recompute every later hash and every affected batch root."""
    k = p["k"]
    apply_modify_payload(db, stream, p)
    rows = list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.stream_id == stream.id, AuditEvent.chain_index >= k)
            .order_by(AuditEvent.chain_index)
        )
    )
    prev = bytes(rows[0].prev_hash)
    for row in rows:
        row.prev_hash = prev
        _rehash(row)
        prev = bytes(row.entry_hash)
    db.flush()
    for batch in _batches(db, stream):
        if batch.last_chain_index >= k:
            leaves = db.scalars(
                select(AuditEvent.entry_hash)
                .where(
                    AuditEvent.stream_id == stream.id,
                    AuditEvent.chain_index.between(batch.first_chain_index, batch.last_chain_index),
                )
                .order_by(AuditEvent.chain_index)
            )
            batch.merkle_root = merkle_root([bytes(h) for h in leaves])


SCENARIOS: dict[str, ScenarioDefinition] = {
    d.code: d
    for d in [
        ScenarioDefinition(
            "S1", "A0", "Modify event payload at k", plan_record, apply_modify_payload
        ),
        ScenarioDefinition(
            "S2",
            "A1",
            "Modify event payload at k and recompute its hash",
            plan_record,
            lambda db, s, p: apply_modify_payload(db, s, p, True),
        ),
        ScenarioDefinition(
            "S3", "A0", "Modify user (context) at k", plan_record, apply_modify_user
        ),
        ScenarioDefinition(
            "S4",
            "A1",
            "Move record k to another session and recompute its hash",
            plan_record,
            apply_modify_session,
        ),
        ScenarioDefinition("S5", "A0", "Delete record k (not the last)", plan_delete, apply_delete),
        ScenarioDefinition(
            "S6",
            "A1",
            "Insert a forged record before k (indices renumbered)",
            plan_insert,
            apply_insert,
        ),
        ScenarioDefinition("S7", "A0", "Swap records k and j", plan_swap, apply_swap),
        ScenarioDefinition(
            "S8",
            "A0",
            "Delete an entire sealed batch (records and root)",
            plan_delete_batch,
            apply_delete_batch,
        ),
        ScenarioDefinition(
            "S9",
            "A0",
            "Paper example: delete an AUTHENTICATION record",
            plan_delete_authentication,
            apply_delete,
        ),
        ScenarioDefinition(
            "S10", "A0", "Tail truncation: delete the newest t records", plan_tail, apply_tail
        ),
        ScenarioDefinition(
            "S11", "A2", "Full consistent rewrite from k", plan_rewrite, apply_rewrite
        ),
    ]
}


def apply_tampering(db: Session, stream: LogStream, code: str, params: dict[str, Any]) -> None:
    """The only entry point that mutates data: refuses anything but a lab stream."""
    assert_lab_stream(stream)
    SCENARIOS[code].apply(db, stream, params)


def run_scenario(
    db: Session,
    source: LogStream,
    code: str,
    params: dict[str, Any],
    seed: int,
    rules: TransitionRules,
    triggered_by: uuid.UUID | None = None,
) -> TamperScenario:
    """Clone, record expectations, tamper, verify, record results. Commits at each stage."""
    definition = SCENARIOS.get(code)
    if definition is None:
        raise ScenarioError(f"unknown scenario {code!r}")
    if source.kind == "lab":
        raise ScenarioError("source must be a primary or synthetic stream, not a lab clone")

    clone = clone_stream(db, source, f"lab-{code.lower()}-{uuid.uuid4().hex[:8]}")
    plan = definition.plan(db, clone, random.Random(seed), params)
    scenario = TamperScenario(
        scenario_type=code,
        attacker_model=definition.attacker_model,
        description=definition.description,
        source_stream_id=source.id,
        lab_stream_id=clone.id,
        parameters={**plan.parameters, "seed": seed},
        expected_detected=plan.expected_detected,
        true_first_index=plan.true_first_index,
    )
    db.add(scenario)
    db.commit()  # expectations are stored before any tampering or verification

    apply_tampering(db, clone, code, plan.parameters)
    db.commit()

    run, report = verify_stream(db, clone, rules, triggered_by=triggered_by)
    first = report.first_failure
    scenario.verification_run_id = run.id
    scenario.actual_detected = report.status == "TAMPERING_DETECTED"
    scenario.first_failure_index = first.chain_index if first else None
    scenario.first_failure_check = first.check if first else None
    if scenario.actual_detected and plan.true_first_index is not None:
        scenario.located_correctly = scenario.first_failure_index == plan.true_first_index
    db.commit()
    return scenario
