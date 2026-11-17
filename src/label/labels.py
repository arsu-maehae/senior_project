"""Apply the locked rules to the in-window events (LB-02, LB-06): one ``Match`` per (event, rule).

WHY a module of its own: this is the only place where rule input (the raw ``field_values_json``) meets the rules. It
returns uids and rule ids only, so no field text can travel further (LB-09). Pure: events and rules in, matches out.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from .errors import LabelError
from .events import Event
from .matcher import event_fields, match_detection
from .rules import Rule

__all__ = ["Match", "parse_fields", "rules_for", "match_event", "apply_rules", "wanted"]


@dataclass(frozen=True)
class Match:
    """One label: the event (with its corrected time for sorting) and the rule that matched it."""
    event: Event
    rule: Rule

    def sort_key(self) -> tuple[int, str, str]:
        """LB-13: corrected time, event uid, rule id."""
        return self.event.us, self.event.uid, self.rule.rule_id


def wanted(rules: Sequence[Rule]) -> Callable[[str, int], bool]:
    """``(channel, event_id) -> bool``: does any rule's logsource cover this event? Used by the scan to keep the raw
    field text only where it can be needed."""
    def test(channel: str, event_id: int) -> bool:
        return any(r.logsource.applies(channel, event_id) for r in rules)
    return test


def parse_fields(e: Event) -> dict[str, tuple[str, ...]]:
    """The event's ``field_values_json`` as lower-case key -> values (``matcher.event_fields``). An event with no
    field text has no fields; malformed JSON is a LabelError (the DB is not what the spec describes)."""
    if not e.fields_json:
        return {}
    try:
        raw = json.loads(e.fields_json)
    except ValueError as exc:
        raise LabelError(f"event {e.uid}: field_values_json is not JSON ({exc})") from exc
    if not isinstance(raw, dict):
        raise LabelError(f"event {e.uid}: field_values_json is not a JSON object")
    return event_fields(raw)


def rules_for(e: Event, rules: Sequence[Rule]) -> list[Rule]:
    """The rules whose logsource covers this event (LB-04)."""
    return [r for r in rules if r.logsource.applies(e.channel, e.event_id)]


def match_event(e: Event, rules: Sequence[Rule]) -> list[Match]:
    """Every rule that matches one event (LB-06: several rules may match; none is dropped)."""
    candidates = rules_for(e, rules)
    if not candidates:
        return []
    fields = parse_fields(e)
    return [Match(e, r) for r in candidates
            if match_detection(r.detection, fields, r.logsource.process_creation_4688(e.channel, e.event_id))]


def apply_rules(events: Iterable[Event], rules: Sequence[Rule]) -> list[Match]:
    """All matches of all rules on all events, in LB-13 order."""
    out: list[Match] = []
    for e in events:
        out.extend(match_event(e, rules))
    return sorted(out, key=Match.sort_key)
