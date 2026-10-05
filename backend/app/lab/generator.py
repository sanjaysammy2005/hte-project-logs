"""Deterministic synthetic workload generator (EXPERIMENTS §2, §5).

The same parameters and seed always produce the same events, timestamps and hashes. Events
go through the normal ingestion service (`append_event`), so enrichment, provenance policy,
hashing and sealing are exactly those used for real events; only the clock is scripted.
"""

import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.batching.service import seal_batches
from app.crypto.chain import GENESIS_HASH, HASH_SCHEME
from app.crypto.merkle import MERKLE_SCHEME
from app.db.models import LogStream
from app.ingestion.service import EventInput, append_event
from app.provenance.rules import V1_RULES_PATH, TransitionRules, load_rules

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
STEP = timedelta(milliseconds=250)
MAX_CONCURRENT_SESSIONS = 8
COMMIT_EVERY = 500
_TABLES = ["accounts", "orders", "patients", "payroll", "inventory"]
# Session paths are always drawn from transitions.v1, whatever rules verify the stream, so the
# same seed reproduces the same workload after the rules gained file-module event types (v2).
GENERATION_RULES = load_rules(V1_RULES_PATH)


@dataclass(frozen=True)
class WorkloadSpec:
    name: str
    users: int
    sessions_per_user: int
    events_per_session: int  # including LOGIN, AUTHENTICATION and LOGOUT; at least 3
    seed: int
    batch_size: int = 64
    sessionless_rate: float = 0.05
    seal_remainder: bool = True

    @property
    def approximate_events(self) -> int:
        session_events = self.users * self.sessions_per_user * self.events_per_session
        return round(session_events / (1 - self.sessionless_rate))


class WorkloadError(ValueError):
    pass


def _session_path(rng: random.Random, length: int, rules: TransitionRules) -> list[str]:
    path = [rules.session_start, rules.owner_confirmation]
    while len(path) < length - 1:
        options = sorted(rules.allowed[path[-1]] - {rules.session_end})
        path.append(rng.choice(options))
    return [*path, rules.session_end]


def _payload(rng: random.Random, event_type: str, user_number: int) -> dict[str, Any]:
    if event_type in ("FILE_OPEN", "FILE_EDIT"):
        return {"resource": f"/data/file-{rng.randint(1, 200):03d}.txt"}
    if event_type == "DB_ACCESS":
        return {"table": rng.choice(_TABLES), "rows": rng.randint(1, 500)}
    if event_type == "LOGIN":
        return {"ip_address": f"10.0.{user_number % 256}.{rng.randint(1, 254)}"}
    if event_type == "AUTHENTICATION":
        return {"method": "password", "outcome": "success"}
    return {}


def generate_workload(db: Session, spec: WorkloadSpec, rules: TransitionRules) -> LogStream:
    """Create a 'synthetic' stream filled according to ``spec``. Commits as it goes."""
    if spec.events_per_session < 3:
        raise WorkloadError("events_per_session must be at least 3 (LOGIN, AUTHENTICATION, LOGOUT)")
    if not 0 <= spec.sessionless_rate < 1:
        raise WorkloadError("sessionless_rate must be in [0, 1)")

    rng = random.Random(spec.seed)
    stream = LogStream(
        name=spec.name,
        kind="synthetic",
        genesis_hash=GENESIS_HASH,
        hash_scheme=HASH_SCHEME,
        merkle_scheme=MERKLE_SCHEME,
        batch_size=spec.batch_size,
        generator_seed=spec.seed,
        description=(
            f"Synthetic workload: {spec.users} users x {spec.sessions_per_user} sessions"
            f" x {spec.events_per_session} events, seed {spec.seed}"
        ),
    )
    db.add(stream)
    db.commit()

    pending = [
        (
            u,
            f"U{u:03d}",
            f"S{u:03d}-{s:03d}",
            _session_path(rng, spec.events_per_session, GENERATION_RULES),
        )
        for u in range(1, spec.users + 1)
        for s in range(1, spec.sessions_per_user + 1)
    ]
    rng.shuffle(pending)
    active: list[list[Any]] = []  # [user_number, user, session, path, next_position]
    step = 0

    def emit(event: EventInput) -> None:
        nonlocal step
        timestamp = BASE_TIME + step * STEP
        result = append_event(db, stream, event, rules, clock=lambda: timestamp)
        if not result.accepted:  # pragma: no cover - generated paths follow the rules
            raise WorkloadError(f"generated event rejected: {result.violations}")
        step += 1
        if step % COMMIT_EVERY == 0:
            db.commit()

    while pending or active:
        while pending and len(active) < MAX_CONCURRENT_SESSIONS:
            active.append([*pending.pop(), 0])
        if rng.random() < spec.sessionless_rate:
            emit(
                EventInput(
                    None,
                    None,
                    "IP_SECURITY_EVENT",
                    {
                        "ip_address": f"203.0.113.{rng.randint(1, 254)}",
                        "reason": "blocked: repeated failures",
                    },
                )
            )
            continue
        session = rng.choice(active)
        user_number, user, session_id, path, position = session
        event_type = path[position]
        emit(EventInput(user, session_id, event_type, _payload(rng, event_type, user_number)))
        session[4] += 1
        if session[4] == len(path):
            active.remove(session)

    if spec.seal_remainder:
        seal_batches(db, stream, include_partial=True)
    db.commit()
    return stream
