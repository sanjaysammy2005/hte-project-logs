"""T4.1–T4.8: provenance checks (paper §VI-C) and the transition rule file."""

import hashlib
import json
from collections import deque
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from app.crypto.canonical import START_EVENT, AuditRecord
from app.crypto.chain import ChainedRecord, build_chain
from app.provenance.checks import ProvenanceCheck as P
from app.provenance.checks import check_provenance
from app.provenance.rules import V1_RULES_PATH, RulesError, TransitionRules, load_rules
from tests.factories import BASE_TIME, make_session

# These tests pin the paper-derived v1 rule set; v2 is tested in test_transitions_v2.py.
RULES = load_rules(V1_RULES_PATH)
RULES_JSON = {k: sorted(v) for k, v in RULES.allowed.items()}
PAPER_EVENTS = ("LOGIN", "AUTHENTICATION", "FILE_OPEN", "FILE_EDIT", "LOGOUT")


def _findings(chain: list[ChainedRecord]) -> list[tuple[int, P]]:
    """(chain_index, check) pairs, in report order."""
    return [(f.chain_index, f.check) for f in check_provenance(chain, RULES).findings]


def _edit(chain: list[ChainedRecord], k: int, **fields: object) -> list[ChainedRecord]:
    tampered = list(chain)
    tampered[k - 1] = replace(chain[k - 1], record=replace(chain[k - 1].record, **fields))
    return tampered


def _sessionless(seconds: float, event_type: str = "IP_SECURITY_EVENT") -> AuditRecord:
    return AuditRecord(
        event_type,
        {"ip_address": "203.0.113.7"},
        None,
        None,
        None,
        None,
        BASE_TIME + timedelta(seconds=seconds),
    )


def _paper_chain() -> list[ChainedRecord]:
    return build_chain(make_session())


# --- rules file ------------------------------------------------------------------------------


def test_default_rules_identifier_names_version_and_file_hash() -> None:
    expected_hash = hashlib.sha256(V1_RULES_PATH.read_bytes()).hexdigest()

    assert RULES.version == "transitions.v1"
    assert RULES.identifier == f"transitions.v1 sha256:{expected_hash}"
    assert check_provenance(_paper_chain(), RULES).rules == RULES.identifier


def test_paper_transition_examples() -> None:
    assert RULES.is_allowed("AUTHENTICATION", "FILE_OPEN")  # "Authentication before Open File"
    assert not RULES.is_allowed("LOGIN", "FILE_OPEN")  # paper §VI-F: not allowed
    assert not RULES.is_allowed("NOT_A_TYPE", "LOGIN")


def _path_to(target: str, rules: TransitionRules) -> list[str]:
    """Shortest allowed event path from session start to ``target``."""
    queue = deque([[rules.start_event]])
    while queue:
        path = queue.popleft()
        if path[-1] == target:
            return path[1:]
        queue.extend(path + [n] for n in sorted(rules.allowed[path[-1]]) if n not in path)
    raise AssertionError(f"{target} unreachable")


def test_every_allowed_transition_verifies_in_a_session() -> None:
    pairs = [(a, b) for a, targets in RULES.allowed.items() for b in targets]
    assert pairs
    for prev, current in pairs:
        events = (*_path_to(prev, RULES), current) if prev != START_EVENT else (current,)

        assert _findings(build_chain(make_session(events=events))) == [], (prev, current)


def _write(tmp_path: Path, **changes: object) -> Path:
    data = json.loads(V1_RULES_PATH.read_text())
    data.update(changes)
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(data))
    return path


def test_rule_hash_changes_when_file_changes(tmp_path: Path) -> None:
    changed = load_rules(_write(tmp_path, description="edited"))

    assert changed.sha256 != RULES.sha256
    assert changed.allowed == RULES.allowed


@pytest.mark.parametrize(
    "changes",
    [
        {"roles": {"session_start": "LOGIN"}},  # missing roles
        {"sessionless_events": ["LOGIN"]},  # overlap
        {
            "roles": {
                "session_start": "LOGIN",
                "owner_confirmation": "NOPE",
                "session_end": "LOGOUT",
            }
        },
        {"allowed": {**RULES_JSON, "LOGIN": ["UNKNOWN"]}},
        {"allowed": {**RULES_JSON, START_EVENT: ["LOGIN", "FILE_OPEN"]}},
        {"allowed": {**RULES_JSON, "LOGOUT": ["LOGIN"]}},
        {"allowed": "not-a-mapping"},
    ],
)
def test_inconsistent_rule_files_rejected(tmp_path: Path, changes: dict) -> None:
    with pytest.raises(RulesError):
        load_rules(_write(tmp_path, **changes))


def test_malformed_json_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json")

    with pytest.raises(RulesError):
        load_rules(path)


# --- T4.6: the paper's worked example (§VI-F) -----------------------------------------------


def test_paper_example_valid_session_passes() -> None:
    result = check_provenance(_paper_chain(), RULES)

    assert result.is_valid and result.sessions_seen == 1 and result.first_failure is None


def test_paper_example_deleting_authentication_gives_exactly_the_predicted_findings() -> None:
    """Paper §VI-F: sequence jumps 1 -> 3; previous event "Authentication" does not match the
    actual predecessor "Login"; the transition Login -> Open File is not allowed."""
    tampered = [c for c in _paper_chain() if c.record.event_type != "AUTHENTICATION"]

    result = check_provenance(tampered, RULES)

    assert _findings(tampered) == [
        (3, P.PROV_PREV_EVENT),
        (3, P.PROV_SEQUENCE),
        (3, P.PROV_TRANSITION),
    ]
    by_check = {f.check: f for f in result.findings}
    assert (by_check[P.PROV_SEQUENCE].expected, by_check[P.PROV_SEQUENCE].actual) == ("2", "3")
    assert by_check[P.PROV_PREV_EVENT].expected == "LOGIN"
    assert by_check[P.PROV_PREV_EVENT].actual == "AUTHENTICATION"
    assert by_check[P.PROV_TRANSITION].actual == "LOGIN -> FILE_OPEN"
    assert result.first_failure is not None and result.first_failure.chain_index == 3


# --- T4.1 Who -------------------------------------------------------------------------------


def test_actor_changed_mid_session_fails_who() -> None:
    assert _findings(_edit(_paper_chain(), 4, actor_user_id="U666")) == [(4, P.PROV_WHO)]


def test_authentication_by_different_user_than_login_fails_who() -> None:
    """Paper P1: the owner is "established by the authentication event". AUTHENTICATION naming
    U666 fails against the LOGIN claim, and U666 then owns the session, so the remaining
    U101 events also fail."""
    assert _findings(_edit(_paper_chain(), 2, actor_user_id="U666")) == [
        (2, P.PROV_WHO),
        (3, P.PROV_WHO),
        (4, P.PROV_WHO),
        (5, P.PROV_WHO),
    ]


def test_login_without_user_fails_who() -> None:
    assert (1, P.PROV_WHO) in _findings(_edit(_paper_chain(), 1, actor_user_id=None))


# --- T4.2 Session ---------------------------------------------------------------------------


def test_event_after_logout_fails_session() -> None:
    late = AuditRecord(
        "FILE_OPEN", {}, "U101", "S5001", "LOGOUT", 6, BASE_TIME + timedelta(seconds=10)
    )
    chain = build_chain([*make_session(), late])

    assert _findings(chain) == [(6, P.PROV_SESSION), (6, P.PROV_TRANSITION)]


def test_session_id_reused_by_new_login_fails_session() -> None:
    reuse = make_session(user="U200", events=("LOGIN",), start=BASE_TIME + timedelta(seconds=20))
    chain = build_chain([*make_session(), *reuse])

    checks = {c for i, c in _findings(chain) if i == 6}
    assert {P.PROV_SESSION, P.PROV_WHO, P.PROV_TRANSITION} <= checks


def test_event_dated_before_session_start_fails_session() -> None:
    chain = _edit(_paper_chain(), 3, event_timestamp=BASE_TIME - timedelta(seconds=1))

    assert {P.PROV_SESSION, P.PROV_TIMESTAMP_ORDER} <= {c for i, c in _findings(chain) if i == 3}


def test_session_event_type_without_session_fails_session() -> None:
    chain = _edit(_paper_chain(), 3, session_id=None, prev_event_type=None, session_seq=None)

    assert (3, P.PROV_SESSION) in _findings(chain)


def test_sessionless_event_with_sequence_number_fails_session() -> None:
    chain = build_chain([replace(_sessionless(1), session_seq=4)])

    assert _findings(chain) == [(1, P.PROV_SESSION)]


# --- T4.3 previous event, T4.4 sequence, T4.5 transition ------------------------------------


def test_stored_previous_event_mismatch_fails_prev_event_only() -> None:
    assert _findings(_edit(_paper_chain(), 4, prev_event_type="DB_ACCESS")) == [
        (4, P.PROV_PREV_EVENT)
    ]


def test_sequence_gap_fails_sequence() -> None:
    """State advances with the actual value, so the successor is also reported."""
    assert _findings(_edit(_paper_chain(), 3, session_seq=9)) == [
        (3, P.PROV_SEQUENCE),
        (4, P.PROV_SEQUENCE),
    ]


def test_duplicate_sequence_fails_sequence() -> None:
    assert (3, P.PROV_SEQUENCE) in _findings(_edit(_paper_chain(), 3, session_seq=2))


@pytest.mark.parametrize(
    "events",
    [
        ("LOGIN", "AUTHENTICATION", "FILE_EDIT"),
        ("LOGIN", "FILE_OPEN"),
        ("LOGIN", "AUTHENTICATION", "NOT_A_TYPE"),
    ],
)
def test_disallowed_transition_fails_transition_only(events: tuple[str, ...]) -> None:
    chain = build_chain(make_session(events=events))

    assert _findings(chain) == [(len(events), P.PROV_TRANSITION)]


def test_session_not_starting_with_login_fails() -> None:
    chain = build_chain(make_session(events=("AUTHENTICATION",)))

    assert _findings(chain) == [(1, P.PROV_TRANSITION)]


# --- T4.7 interleaved sessions and sessionless events ---------------------------------------


def test_interleaved_concurrent_sessions_and_sessionless_events_are_valid() -> None:
    records = [_sessionless(0.1), _sessionless(3.3, "LOGIN_FAILED")]
    for i in range(4):
        records += make_session(
            user=f"U{i}",
            session=f"S{i}",
            events=PAPER_EVENTS,
            start=BASE_TIME + timedelta(milliseconds=250 * i),
        )
    records.sort(key=lambda r: r.event_timestamp)

    result = check_provenance(build_chain(records), RULES)

    assert result.is_valid
    assert (result.sessions_seen, result.sessionless_records, result.records_checked) == (4, 2, 22)


# --- T4.8 timestamp order, and tampering scenarios ------------------------------------------


def test_decreasing_timestamp_fails_timestamp_order() -> None:
    chain = _edit(_paper_chain(), 4, event_timestamp=BASE_TIME + timedelta(seconds=2.5))

    assert _findings(chain) == [(4, P.PROV_TIMESTAMP_ORDER)]


def test_inserted_forged_event_is_flagged_at_the_forged_record() -> None:
    """EXPERIMENTS S6: the chain points at the successor; provenance points at the forgery."""
    chain = _paper_chain()
    forged = replace(chain[2].record, event_type="DB_ACCESS")
    records = [c.record for c in chain]
    tampered = build_chain([*records[:3], forged, *records[3:]])

    assert _findings(tampered)[0][0] == 4


def test_reordered_session_events_flagged_at_first_moved_record() -> None:
    records = [c.record for c in _paper_chain()]
    records[2], records[3] = records[3], records[2]

    assert _findings(build_chain(records))[0][0] == 3
