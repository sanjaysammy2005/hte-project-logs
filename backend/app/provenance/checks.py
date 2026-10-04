"""The five provenance checks of paper §VI-C, plus timestamp order (paper Table IV).

Session state is replayed only from the chained records themselves (VERIFICATION §6.3):
nothing outside the hash chain is trusted. After a failing record the state still advances
with that record's actual values, so one deletion is reported at one place, not as a cascade.

Interpretations approved in Q5–Q9, Q15:
- P1 Who: LOGIN claims a user; AUTHENTICATION must name the claimed user and establishes the
  owner; later events must name the owner (or the claimed user while no AUTHENTICATION has
  been seen — missing authentication is reported by the transition check instead).
- P2 Session: lifetime is LOGIN..LOGOUT, no timeout; events after LOGOUT and events dated
  before the session started fail; sessionless records must be sessionless event types with
  no previous event or sequence number.
- P3/P4/P5 compare with the *actual* preceding event of the same session.
- Sessionless records skip P1, P3–P5; all records get the global timestamp-order check.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from app.crypto.chain import ChainedRecord
from app.provenance.rules import TransitionRules


class ProvenanceCheck(StrEnum):
    """In the order applied to each record."""

    PROV_TIMESTAMP_ORDER = "PROV_TIMESTAMP_ORDER"
    PROV_WHO = "PROV_WHO"
    PROV_SESSION = "PROV_SESSION"
    PROV_PREV_EVENT = "PROV_PREV_EVENT"
    PROV_SEQUENCE = "PROV_SEQUENCE"
    PROV_TRANSITION = "PROV_TRANSITION"


@dataclass(frozen=True)
class ProvenanceFinding:
    position: int
    chain_index: int
    session_id: str | None
    check: ProvenanceCheck
    expected: str
    actual: str


@dataclass(frozen=True)
class ProvenanceResult:
    rules: str  # rule-set version and SHA-256
    records_checked: int
    sessionless_records: int
    sessions_seen: int
    findings: tuple[ProvenanceFinding, ...]

    @property
    def is_valid(self) -> bool:
        return not self.findings

    @property
    def first_failure(self) -> ProvenanceFinding | None:
        return self.findings[0] if self.findings else None


@dataclass
class _SessionState:
    claimed_user: str | None
    owner: str | None
    last_type: str
    last_seq: int
    start_ts: datetime
    closed: bool


def check_provenance(records: Sequence[ChainedRecord], rules: TransitionRules) -> ProvenanceResult:
    findings: list[ProvenanceFinding] = []
    sessions: dict[str, _SessionState] = {}
    sessionless = 0
    prev_ts: datetime | None = None

    for position, item in enumerate(records, start=1):
        r = item.record
        failures: list[tuple[ProvenanceCheck, str, str]] = []

        if prev_ts is not None and r.event_timestamp < prev_ts:
            failures.append(
                (
                    ProvenanceCheck.PROV_TIMESTAMP_ORDER,
                    f">= {prev_ts.isoformat()}",
                    r.event_timestamp.isoformat(),
                )
            )
        prev_ts = r.event_timestamp

        if r.session_id is None:
            sessionless += 1
            if r.event_type not in rules.sessionless_events:
                failures.append(
                    (
                        ProvenanceCheck.PROV_SESSION,
                        "a session for this event type",
                        f"{r.event_type} without session",
                    )
                )
            elif r.prev_event_type is not None or r.session_seq is not None:
                failures.append(
                    (
                        ProvenanceCheck.PROV_SESSION,
                        "no previous event or sequence number",
                        f"prev={r.prev_event_type!r}, seq={r.session_seq!r}",
                    )
                )
        else:
            state = sessions.get(r.session_id)
            if state is None:
                state = _SessionState(
                    r.actor_user_id, None, rules.start_event, 0, r.event_timestamp, closed=False
                )
                sessions[r.session_id] = state
                if r.event_type == rules.session_start and r.actor_user_id is None:
                    failures.append((ProvenanceCheck.PROV_WHO, "a claimed user", "None"))
            else:
                # P1 Who
                expected_user = state.owner if state.owner is not None else state.claimed_user
                if r.actor_user_id != expected_user:
                    failures.append(
                        (ProvenanceCheck.PROV_WHO, str(expected_user), str(r.actor_user_id))
                    )
                # P2 Session lifetime
                if state.closed:
                    failures.append(
                        (
                            ProvenanceCheck.PROV_SESSION,
                            "open session",
                            f"event after {rules.session_end}",
                        )
                    )
                if r.event_timestamp < state.start_ts:
                    failures.append(
                        (
                            ProvenanceCheck.PROV_SESSION,
                            f">= session start {state.start_ts.isoformat()}",
                            r.event_timestamp.isoformat(),
                        )
                    )

            # P3 previous event, P4 sequence, P5 transition — against the actual predecessor.
            if r.prev_event_type != state.last_type:
                failures.append(
                    (ProvenanceCheck.PROV_PREV_EVENT, state.last_type, str(r.prev_event_type))
                )
            expected_seq = state.last_seq + 1
            if r.session_seq != expected_seq:
                failures.append(
                    (ProvenanceCheck.PROV_SEQUENCE, str(expected_seq), str(r.session_seq))
                )
            if not rules.is_allowed(state.last_type, r.event_type):
                failures.append(
                    (
                        ProvenanceCheck.PROV_TRANSITION,
                        "an allowed transition",
                        f"{state.last_type} -> {r.event_type}",
                    )
                )

            # Advance state with the record's actual values.
            if r.event_type == rules.owner_confirmation:
                state.owner = r.actor_user_id
            state.last_type = r.event_type
            state.last_seq = r.session_seq if isinstance(r.session_seq, int) else expected_seq
            if r.event_type == rules.session_end:
                state.closed = True

        findings.extend(
            ProvenanceFinding(position, item.chain_index, r.session_id, check, expected, actual)
            for check, expected, actual in failures
        )

    return ProvenanceResult(
        rules=rules.identifier,
        records_checked=len(records),
        sessionless_records=sessionless,
        sessions_seen=len(sessions),
        findings=tuple(findings),
    )
