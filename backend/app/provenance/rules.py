"""Allowed-transition rules, loaded from a versioned JSON file.

The paper says the allowed set "is defined per application" (§VI-C). Every verification
report names the rule file's version and SHA-256, so results always state which rules applied.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "config" / "transitions.v1.json"


class RulesError(ValueError):
    """The rule file is missing fields or internally inconsistent."""


@dataclass(frozen=True)
class TransitionRules:
    version: str
    sha256: str
    start_event: str
    session_start: str
    owner_confirmation: str
    session_end: str
    session_events: frozenset[str]
    sessionless_events: frozenset[str]
    allowed: Mapping[str, frozenset[str]]

    @property
    def identifier(self) -> str:
        return f"{self.version} sha256:{self.sha256}"

    def is_allowed(self, previous: str, current: str) -> bool:
        return current in self.allowed.get(previous, frozenset())


def load_rules(path: Path = DEFAULT_RULES_PATH) -> TransitionRules:
    raw = path.read_bytes()
    try:
        data = json.loads(raw)
        roles = data["roles"]
        rules = TransitionRules(
            version=data["version"],
            sha256=hashlib.sha256(raw).hexdigest(),
            start_event=data["start_event"],
            session_start=roles["session_start"],
            owner_confirmation=roles["owner_confirmation"],
            session_end=roles["session_end"],
            session_events=frozenset(data["session_events"]),
            sessionless_events=frozenset(data["sessionless_events"]),
            allowed={k: frozenset(v) for k, v in data["allowed"].items()},
        )
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise RulesError(f"malformed rule file {path.name}: {exc!r}") from exc
    _validate(rules)
    return rules


def _validate(rules: TransitionRules) -> None:
    known = rules.session_events | {rules.start_event}
    if rules.session_events & rules.sessionless_events:
        raise RulesError("an event type cannot be both session and sessionless")
    for role in (rules.session_start, rules.owner_confirmation, rules.session_end):
        if role not in rules.session_events:
            raise RulesError(f"role event {role!r} is not a session event")
    for source, targets in rules.allowed.items():
        if source not in known or not targets <= rules.session_events:
            raise RulesError(f"transition from {source!r} uses an unknown event type")
    if rules.allowed.get(rules.start_event) != frozenset({rules.session_start}):
        raise RulesError("sessions must start only with the session_start event")
    if rules.allowed.get(rules.session_end, frozenset()):
        raise RulesError("the session_end event must be terminal")
