"""Experiment runner (docs/EXPERIMENTS.md §2–§5).

For each target size N and seed a synthetic base stream is generated once (kept, kind
'synthetic'). Measurements that need modified or re-sealed copies run inside a transaction that
is rolled back afterwards, so trials leave no data behind:

- false positives: verify every untampered base stream;
- detection: per scenario, ``trials_per_scenario`` tampered clones with seeded random targets;
  the expectation and ground truth come from the scenario plan, fixed before tampering;
- timing: per (N, batch size) re-seal an untampered copy, then 1 warm-up + R measured runs;
- proofs: membership-proof generation/verification time per batch size;
- storage: relation sizes of an N-record copy with and without the context/hash columns.

Raw per-trial data is stored and the summary is computed from it (``metrics.summarize``).
"""

import random
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.batching.service import seal_batches
from app.crypto.merkle import membership_proof, merkle_root, verify_proof
from app.db.models import AuditEvent, ExperimentRun, LogStream
from app.experiments.environment import capture_environment
from app.experiments.metrics import summarize
from app.lab.generator import WorkloadSpec, generate_workload
from app.lab.scenarios import SCENARIOS, ScenarioError, apply_tampering, clone_stream
from app.provenance.rules import TransitionRules
from app.verification.engine import build_report, load_stream

SESSIONS_PER_USER = 5
EVENTS_PER_SESSION = 20
SESSIONLESS_RATE = 0.05


class ExperimentConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ExperimentConfig:
    name: str
    sizes: list[int]  # target records per base stream (actual counts are recorded)
    seeds: list[int]
    batch_sizes: list[int] = field(default_factory=lambda: [16, 64, 256, 1024])
    base_batch_size: int = 64
    scenarios: list[str] = field(default_factory=lambda: list(SCENARIOS))
    trials_per_scenario: int = 100
    detection_max_size: int = 10_000  # larger sizes get `large_size_trials` trials instead
    large_size_trials: int = 20
    timing_repetitions: int = 10
    proof_samples: int = 200

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExperimentConfig":
        try:
            config = cls(**data)
        except TypeError as exc:
            raise ExperimentConfigError(str(exc)) from exc
        if not config.sizes or not config.seeds:
            raise ExperimentConfigError("sizes and seeds must be non-empty")
        if any(n < 20 for n in config.sizes):
            raise ExperimentConfigError("sizes must be at least 20 records")
        if any(m < 1 for m in [*config.batch_sizes, config.base_batch_size]):
            raise ExperimentConfigError("batch sizes must be positive")
        unknown = set(config.scenarios) - set(SCENARIOS)
        if unknown:
            raise ExperimentConfigError(f"unknown scenarios: {sorted(unknown)}")
        if config.trials_per_scenario < 0 or config.timing_repetitions < 1:
            raise ExperimentConfigError("trials must be >= 0 and timing repetitions >= 1")
        return config


def workload_for(size: int, seed: int, name: str, batch_size: int) -> WorkloadSpec:
    """10 users x 5 sessions x 20 events per 1,000 records (EXPERIMENTS §5), scaled with N."""
    users = max(1, round(size * (1 - SESSIONLESS_RATE) / (SESSIONS_PER_USER * EVENTS_PER_SESSION)))
    return WorkloadSpec(
        name=name,
        users=users,
        sessions_per_user=SESSIONS_PER_USER,
        events_per_session=EVENTS_PER_SESSION,
        seed=seed,
        batch_size=batch_size,
        sessionless_rate=SESSIONLESS_RATE,
    )


def trial_seed(base_seed: int, scenario: str, trial: int) -> int:
    return base_seed * 1_000_000 + int(scenario[1:]) * 10_000 + trial


def create_run(
    db: Session,
    config: ExperimentConfig,
    triggered_by: uuid.UUID | None = None,
    git_commit: str | None = None,
) -> ExperimentRun:
    run = ExperimentRun(
        name=config.name,
        status="queued",
        config=asdict(config),
        environment=capture_environment(db, git_commit),
        triggered_by=triggered_by,
    )
    db.add(run)
    db.commit()
    return run


def _verify(db: Session, stream: LogStream, rules: TransitionRules) -> dict[str, Any]:
    t0 = time.perf_counter()
    records, batches = load_stream(db, stream)
    t1 = time.perf_counter()
    report = build_report(records, batches, bytes(stream.genesis_hash), rules)
    t2 = time.perf_counter()
    return {
        "records": len(records),
        "batches": len(batches),
        "status": report.status,
        "findings": len(report.findings),
        "first_failure": report.first_failure,
        "load_ms": (t1 - t0) * 1000,
        "check_ms": (t2 - t1) * 1000,
        "chain_ms": report.timings_ms["chain"],
        "provenance_ms": report.timings_ms["provenance"],
        "merkle_ms": report.timings_ms["merkle"],
    }


def _detection_trial(
    db: Session,
    base: LogStream,
    size: int,
    code: str,
    trial: int,
    seed: int,
    rules: TransitionRules,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "size": size,
        "scenario": code,
        "trial": trial,
        "seed": seed,
        "base_stream_id": str(base.id),
    }
    try:
        clone = clone_stream(db, base, f"exp-trial-{uuid.uuid4().hex[:12]}")
        plan = SCENARIOS[code].plan(db, clone, random.Random(seed), {})
        # Expectation and ground truth are fixed here, before any tampering or verification.
        row.update(
            expected_detected=plan.expected_detected,
            true_first_index=plan.true_first_index,
            parameters=plan.parameters,
        )
        apply_tampering(db, clone, code, plan.parameters)
        db.flush()
        result = _verify(db, clone, rules)
        first = result["first_failure"]
        row.update(
            detected=result["status"] == "TAMPERING_DETECTED",
            first_failure_index=first.chain_index if first else None,
            first_failure_check=first.check if first else None,
            verify_ms=result["load_ms"] + result["check_ms"],
            error=None,
        )
    except ScenarioError as exc:
        row.update(
            expected_detected=None,
            true_first_index=None,
            detected=None,
            first_failure_index=None,
            first_failure_check=None,
            verify_ms=None,
            error=str(exc),
        )
    finally:
        db.rollback()  # discard the clone and its tampering
    return row


def _timing(
    db: Session,
    base: LogStream,
    size: int,
    batch_size: int,
    repetitions: int,
    rules: TransitionRules,
) -> list[dict[str, Any]]:
    rows = []
    try:
        copy = clone_stream(
            db,
            base,
            f"exp-timing-{uuid.uuid4().hex[:12]}",
            copy_batches=False,
            batch_size=batch_size,
        )
        seal_batches(db, copy, include_partial=True)
        db.flush()
        for repetition in range(repetitions + 1):
            result = _verify(db, copy, rules)
            result.pop("first_failure")
            rows.append(
                {
                    "size": size,
                    "batch_size": batch_size,
                    "repetition": repetition,
                    "warmup": repetition == 0,
                    **result,
                }
            )
    finally:
        db.rollback()
    return rows


def _proofs(
    db: Session, base: LogStream, batch_size: int, samples: int, rng: random.Random
) -> dict[str, Any] | None:
    leaves = [
        bytes(h)
        for h in db.scalars(
            select(AuditEvent.entry_hash)
            .where(AuditEvent.stream_id == base.id)
            .order_by(AuditEvent.chain_index)
            .limit(batch_size)
        )
    ]
    if len(leaves) < batch_size:
        return None
    root = merkle_root(leaves)
    generate_us, verify_us = [], []
    for _ in range(samples):
        index = rng.randrange(batch_size)
        t0 = time.perf_counter()
        proof = membership_proof(leaves, index)
        t1 = time.perf_counter()
        ok = verify_proof(leaves[index], proof, root)
        t2 = time.perf_counter()
        if not ok:  # pragma: no cover - would indicate a bug, never a measurement
            raise RuntimeError("membership proof failed on untampered data")
        generate_us.append((t1 - t0) * 1e6)
        verify_us.append((t2 - t1) * 1e6)
    return {
        "batch_size": batch_size,
        "proof_length": len(proof),
        "generate_us": generate_us,
        "verify_us": verify_us,
    }


_BASELINE_COLUMNS = (
    "id, stream_id, event_type, event_payload, actor_user_id, session_id, event_timestamp"
)
_FULL_COLUMNS = (
    _BASELINE_COLUMNS + ", chain_index, prev_event_type, session_seq, prev_hash, entry_hash"
)


def _storage(db: Session, base: LogStream, size: int) -> dict[str, Any]:
    """Storage of identical N-row copies with and without the context/hash columns.

    Allocated relation size is NOT used: PostgreSQL 16 extends tables several pages at a time,
    so small fresh tables report pre-allocated empty pages (both copies measured 270,336 bytes
    in the first smoke run). Instead, per copy:
      tuple_bytes = sum(pg_column_size(row))          (logical row data)
      used_pages  = distinct heap pages holding rows   (physical estimate, x 8 KiB)
    Indexes are excluded (the real tables are shared by all streams). Temporary tables are
    dropped by the rollback.
    """
    try:
        params = {"s": base.id}
        measured: dict[str, dict[str, int]] = {}
        for table, columns, source in (
            ("exp_full", _FULL_COLUMNS, "audit_events"),
            ("exp_baseline", _BASELINE_COLUMNS, "audit_events"),
            ("exp_batches", "*", "batches"),
        ):
            db.execute(
                text(
                    f"CREATE TEMP TABLE {table} AS SELECT {columns} FROM {source}"
                    " WHERE stream_id = :s"
                ),
                params,
            )
            row = db.execute(
                text(
                    f"SELECT count(*), coalesce(sum(pg_column_size(t.*)), 0),"
                    f" count(DISTINCT (ctid::text::point)[0]) FROM {table} t"
                )
            ).one()
            measured[table] = {"rows": row[0], "tuple_bytes": row[1], "used_pages": row[2]}
        page = db.scalar(text("SELECT current_setting('block_size')::int"))
        full, baseline, batches = (measured[t] for t in ("exp_full", "exp_baseline", "exp_batches"))
        return {
            "size": size,
            "records": full["rows"],
            "page_bytes": page,
            "full_tuple_bytes": full["tuple_bytes"],
            "baseline_tuple_bytes": baseline["tuple_bytes"],
            "full_used_pages": full["used_pages"],
            "baseline_used_pages": baseline["used_pages"],
            "batch_rows": batches["rows"],
            "batch_tuple_bytes": batches["tuple_bytes"],
        }
    finally:
        db.rollback()


def execute_run(
    db: Session,
    run_id: uuid.UUID,
    rules: TransitionRules,
    progress: Callable[[str], None] = lambda _: None,
) -> ExperimentRun:
    run = db.get(ExperimentRun, run_id)
    if run is None:
        raise ExperimentConfigError(f"no experiment run {run_id}")
    config = ExperimentConfig.from_dict(run.config)
    run.status, run.started_at = "running", datetime.now(UTC)
    db.commit()
    raw: dict[str, Any] = {
        "base_streams": [],
        "false_positive": [],
        "detection": [],
        "timing": [],
        "proofs": [],
        "storage": [],
    }
    try:
        bases: dict[int, list[LogStream]] = {}
        for size in config.sizes:
            for seed in config.seeds:
                name = f"exp-{run.id.hex[:8]}-n{size}-s{seed}"
                progress(f"generating {name}")
                spec = workload_for(size, seed, name, config.base_batch_size)
                stream = generate_workload(db, spec, rules)
                bases.setdefault(size, []).append(stream)
                result = _verify(db, stream, rules)
                raw["base_streams"].append(
                    {
                        "size": size,
                        "seed": seed,
                        "stream_id": str(stream.id),
                        "records": result["records"],
                        "batches": result["batches"],
                    }
                )
                raw["false_positive"].append(
                    {
                        "size": size,
                        "seed": seed,
                        "records": result["records"],
                        "status": result["status"],
                        "findings": result["findings"],
                    }
                )

        for size, streams in bases.items():
            trials = (
                config.trials_per_scenario
                if size <= config.detection_max_size
                else min(config.trials_per_scenario, config.large_size_trials)
            )
            for code in config.scenarios:
                progress(f"detection N={size} {code} x{trials}")
                for trial in range(trials):
                    base = streams[trial % len(streams)]
                    seed = trial_seed(base.generator_seed or 0, code, trial)
                    raw["detection"].append(
                        _detection_trial(db, base, size, code, trial, seed, rules)
                    )

        for size, streams in bases.items():
            for batch_size in config.batch_sizes:
                progress(f"timing N={size} m={batch_size}")
                raw["timing"].extend(
                    _timing(db, streams[0], size, batch_size, config.timing_repetitions, rules)
                )
            progress(f"storage N={size}")
            raw["storage"].append(_storage(db, streams[0], size))

        largest = bases[max(bases)][0]
        rng = random.Random(config.seeds[0])
        for batch_size in config.batch_sizes:
            measured = _proofs(db, largest, batch_size, config.proof_samples, rng)
            if measured:
                raw["proofs"].append(measured)
        db.rollback()

        run = db.get(ExperimentRun, run_id)
        assert run is not None
        run.raw_results, run.summary = raw, summarize(raw)
        run.status, run.finished_at = "completed", datetime.now(UTC)
        db.commit()
        progress("completed")
        return run
    except Exception as exc:
        db.rollback()
        failed = db.get(ExperimentRun, run_id)
        if failed is not None:
            failed.status, failed.finished_at = "failed", datetime.now(UTC)
            failed.error = f"{type(exc).__name__}: {exc}"
            failed.raw_results = raw
            db.commit()
        raise
