"""ZT1.6–ZT1.7: transitions.v2 extends v1 without changing it (ZERO_TRUST_FILE_MODULE §13.4)."""

from datetime import UTC, datetime, timedelta

import pytest

from app.crypto.canonical import AuditRecord
from app.crypto.chain import build_chain
from app.lab.generator import GENERATION_RULES, _session_path
from app.provenance.checks import ProvenanceCheck, check_provenance
from app.provenance.rules import DEFAULT_RULES_PATH, V1_RULES_PATH, load_rules

V1 = load_rules(V1_RULES_PATH)
V2 = load_rules(DEFAULT_RULES_PATH)
V1_TYPES = V1.session_events | V1.sessionless_events
FILE_TYPES = V2.session_events - V1.session_events
T0 = datetime(2026, 10, 5, 9, 0, tzinfo=UTC)


def pairs(rules, types=None):
    return {
        (a, b)
        for a, targets in rules.allowed.items()
        for b in targets
        if types is None or (a in types | {rules.start_event} and b in types)
    }


def test_v2_is_the_default_and_v1_is_unchanged() -> None:
    assert V2.version == "transitions.v2" and V1.version == "transitions.v1"
    assert V1.server_only_events == frozenset()


def test_every_v1_pair_is_still_allowed() -> None:
    assert pairs(V1) <= pairs(V2)


def test_no_new_pair_between_v1_types() -> None:
    """So v1-shaped streams (synthetic data, the paper's example) behave exactly as before."""
    assert pairs(V2, V1_TYPES) == pairs(V1)
    assert not V2.is_allowed("LOGIN", "FILE_OPEN")  # paper §VI-F
    assert not V2.is_allowed("LOGIN", "FILE_DOWNLOAD")  # file activity also needs authentication


def test_file_events_are_server_only_session_events() -> None:
    assert {"FILE_UPLOAD", "FILE_DOWNLOAD", "FILE_ACCESS_DENIED", "REAUTHENTICATION"} <= FILE_TYPES
    assert FILE_TYPES <= V2.server_only_events
    assert "SECURITY_VIOLATION" in V2.server_only_events


def session(events, users=None, session_id="S-1"):
    users = users or ["alice"] * len(events)
    records, prev = [], V2.start_event
    for seq, (event, user) in enumerate(zip(events, users, strict=True), start=1):
        records.append(
            AuditRecord(event, {}, user, session_id, prev, seq, T0 + timedelta(seconds=seq))
        )
        prev = event
    return build_chain(records)


def findings(chain):
    return [(f.chain_index, f.check) for f in check_provenance(chain, V2).findings]


def test_file_session_verifies() -> None:
    events = ["LOGIN", "AUTHENTICATION", "FILE_UPLOAD", "FILE_ACCESS_DENIED",
              "REAUTHENTICATION", "FILE_DOWNLOAD", "FILE_VERSION_CREATED", "LOGOUT"]  # fmt: skip
    assert findings(session(events)) == []


@pytest.mark.parametrize(
    ("events", "users", "expected"),
    [
        # A forged download before authentication: disallowed transition.
        (["LOGIN", "FILE_DOWNLOAD"], None, (2, ProvenanceCheck.PROV_TRANSITION)),
        # A forged download after logout: event outside the session's lifetime.
        (
            ["LOGIN", "AUTHENTICATION", "LOGOUT", "FILE_DOWNLOAD"],
            None,
            (4, ProvenanceCheck.PROV_SESSION),
        ),
        # A download attributed to someone else inside alice's session.
        (
            ["LOGIN", "AUTHENTICATION", "FILE_DOWNLOAD"],
            ["alice", "alice", "mallory"],
            (3, ProvenanceCheck.PROV_WHO),
        ),
    ],
)
def test_forged_file_events_fail_paper_checks(events, users, expected) -> None:
    assert expected in findings(session(events, users))


def test_deleted_denial_event_leaves_a_sequence_gap() -> None:
    chain = session(["LOGIN", "AUTHENTICATION", "FILE_ACCESS_DENIED", "FILE_DOWNLOAD"])
    tampered = [chain[0], chain[1], chain[3]]
    result = {check for _, check in findings(tampered)}
    assert {ProvenanceCheck.PROV_SEQUENCE, ProvenanceCheck.PROV_PREV_EVENT} <= result


def test_paper_worked_example_unchanged_under_v2() -> None:
    """T4.6 under v2: deleting AUTHENTICATION gives exactly the paper's three findings."""
    chain = session(["LOGIN", "AUTHENTICATION", "FILE_OPEN", "FILE_EDIT", "LOGOUT"])
    del chain[1]
    assert sorted(check for _, check in findings(chain)) == sorted(
        [
            ProvenanceCheck.PROV_PREV_EVENT,
            ProvenanceCheck.PROV_SEQUENCE,
            ProvenanceCheck.PROV_TRANSITION,
        ]
    )


def test_generator_is_pinned_to_v1() -> None:
    """The same seed must keep producing the same synthetic stream (EXPERIMENTS reproducibility)."""
    import random

    assert GENERATION_RULES.version == "transitions.v1"
    for seed in range(20):
        path = _session_path(random.Random(seed), 12, GENERATION_RULES)
        assert set(path) <= V1.session_events
        assert path == _session_path(random.Random(seed), 12, V1)
