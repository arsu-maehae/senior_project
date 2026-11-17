"""One pure pass over the DB rows: corrected time and window (LB-01), clock flag, near-duplicate collapse (LB-03) and
the LB-11 count keys.

WHY pure: the DB reading lives in ``inputs.read_events``; this module takes any iterable of row mappings, so a test
can feed synthetic rows and get exactly what the real run gets. Nothing here opens a file.

WHY the same functions as the stitcher: the window predicate (``stitch.scan.in_window``), the corrected time and the
event clock flag (``clock_offset.correct``), the Sysmon 1 / 4688 pairing (``stitch.processes.collapse``) and the
4697 / 7045 pairing (``gate.classify.pair_services``) are imported, so a label sits on exactly the events, times and
actions the gate and the stitcher see.

The raw ``field_values_json`` text is kept only for events some rule can apply to (``keep_json``), is parsed only
by ``labels.py`` and is never copied into an output (LB-09).
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Mapping, Sequence

from clock_offset.correct import ClockChanges, Offsets, corrected_us, event_unreliable
from gate.classify import pair_services
from gate.timeutil import to_us
from stitch.processes import collapse
from stitch.scan import in_window

from .errors import LabelError

__all__ = ["Event", "EventScan", "to_event", "scan_events", "collapse_near_duplicates", "count_keys",
           "event_sort_key"]


@dataclass(frozen=True)
class Event:
    """One event as the labeller uses it. ``dup_uids`` are the LB-03 copies (sorted, without ``uid``)."""
    uid: str
    host: str
    channel: str
    event_id: int
    record_id: int | None
    us_raw: int
    us: int                                   # corrected (CO-09)
    clock_unreliable: int
    process_id: int | None = None
    service_name: str | None = None
    account_name: str | None = None
    machine_account: int | None = None
    fields_json: str | None = field(default=None, repr=False)   # raw rule input, never written (LB-09)
    dup_uids: tuple[str, ...] = ()

    @property
    def uids(self) -> tuple[str, ...]:
        """The representative uid and its copies: every uid this event stands for."""
        return (self.uid,) + self.dup_uids


@dataclass
class EventScan:
    """What one pass yields: the in-window events (collapsed, sorted) and the counts of spec 3.4 ``stats.json``
    (events in and outside the window by channel; never a list of out-of-window events, LB-01)."""
    events: list[Event] = field(default_factory=list)
    loaded_total: int = 0
    in_window_rows: int = 0
    outside_window_rows: int = 0
    in_window_by_channel: dict[str, int] = field(default_factory=dict)
    outside_window_by_channel: dict[str, int] = field(default_factory=dict)
    near_duplicate_groups: int = 0


def _int_or_none(value: Any) -> int | None:
    """An integer DB cell, None when NULL or not a number (a NULL key never pairs, decision 005)."""
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def to_event(raw: Mapping[str, Any], offsets: Offsets | None, changes: ClockChanges | Iterable = (),
             keep_json: bool = False) -> Event:
    """One DB row -> Event. LabelError for a row with no parseable ``event_utc``: it cannot be placed in or out of
    the window, and dropping it silently could drop a label (the stitcher refuses the same row)."""
    try:
        us_raw = to_us(raw["event_utc"])
    except (KeyError, TypeError, ValueError) as exc:
        raise LabelError(f"event {raw.get('event_uid')} has no valid event_utc ({exc})") from exc
    host = str(raw.get("host"))
    us = us_raw if offsets is None else corrected_us(us_raw, host, offsets)
    flag = 0 if offsets is None else int(event_unreliable(host, us_raw, offsets, changes))
    eid = _int_or_none(raw.get("event_id"))
    return Event(uid=str(raw["event_uid"]), host=host, channel=str(raw.get("channel")),
                 event_id=-1 if eid is None else eid, record_id=_int_or_none(raw.get("record_id")),
                 us_raw=us_raw, us=us, clock_unreliable=flag, process_id=_int_or_none(raw.get("process_id")),
                 service_name=raw.get("service_name"), account_name=raw.get("account_name"),
                 machine_account=_int_or_none(raw.get("machine_account")),
                 fields_json=raw.get("field_values_json") if keep_json else None)


def _bump(table: dict[str, int], key: str) -> None:
    """Increment a counter."""
    table[key] = table.get(key, 0) + 1


def event_sort_key(e: Event) -> tuple[int, str]:
    """LB-13 order: corrected time, then uid."""
    return e.us, e.uid


def collapse_near_duplicates(events: Iterable[Event]) -> tuple[list[Event], int]:
    """LB-03: events with one (host, channel, record_id), record_id not None, are one event; the representative is
    the smallest uid and the others go into ``dup_uids``. Returns (events, groups of two or more).

    WHY only in-window events are grouped (the caller passes them): an out-of-window row is never listed (LB-01),
    so its uid must not appear in ``dup_uids`` either. Rows with no record_id are never grouped (decision 005).
    """
    groups: dict[tuple[str, str, int], list[Event]] = {}
    out: list[Event] = []
    for e in events:
        if e.record_id is None:
            out.append(e)
        else:
            groups.setdefault((e.host, e.channel, e.record_id), []).append(e)
    n_groups = 0
    for members in groups.values():
        keep = min(members, key=lambda m: m.uid)
        if len(members) > 1:
            n_groups += 1
            keep = replace(keep, dup_uids=tuple(sorted(m.uid for m in members if m.uid != keep.uid)))
        out.append(keep)
    return out, n_groups


def scan_events(rows: Iterable[Mapping[str, Any]], start_us: int, end_us: int, offsets: Offsets | None,
                changes: ClockChanges | Iterable = (),
                keep_json: Callable[[str, int], bool] = lambda ch, eid: False) -> EventScan:
    """LB-01 and LB-03 in one pass: every row is counted in or outside the window (corrected time, the gate's
    predicate); in-window rows become events, collapsed and sorted by corrected time and uid.

    ``keep_json(channel, event_id)`` says whether a rule can apply; only then is the raw field text kept, so the
    memory held is bounded by the rule logsources.
    """
    res = EventScan()
    kept: list[Event] = []
    for raw in rows:
        res.loaded_total += 1
        ch = str(raw.get("channel"))
        eid = _int_or_none(raw.get("event_id"))
        ev = to_event(raw, offsets, changes, keep_json(ch, -1 if eid is None else eid))
        if in_window(ev.us, start_us, end_us):
            res.in_window_rows += 1
            _bump(res.in_window_by_channel, ch)
            kept.append(ev)
        else:
            res.outside_window_rows += 1
            _bump(res.outside_window_by_channel, ch)
    collapsed, res.near_duplicate_groups = collapse_near_duplicates(kept)
    res.events = sorted(collapsed, key=event_sort_key)
    res.in_window_by_channel = dict(sorted(res.in_window_by_channel.items()))
    res.outside_window_by_channel = dict(sorted(res.outside_window_by_channel.items()))
    return res


# ---------------------------------------------------------------- LB-11 count keys

def _row(e: Event) -> dict[str, Any]:
    """The mapping the shared pairing functions read (host, uid, times, process id, service name)."""
    return {"event_uid": e.uid, "host": e.host, "channel": e.channel, "event_id": e.event_id, "us_raw": e.us_raw,
            "us": e.us, "process_id": e.process_id, "service_name": e.service_name}


def _is(e: Event, channel: str, event_id: int) -> bool:
    """Channel and event id together (ids collide across channels)."""
    return e.channel == channel and e.event_id == event_id


def count_keys(events: Sequence[Event], process_collapse_s: float, service_pair_s: float) -> dict[str, str]:
    """uid -> count key for every event (LB-11). A Sysmon 1 and a 4688 of one process (spec 03 ST-11 pairing) share
    the Sysmon 1 uid; a 4697 and a 7045 of one install (02_gate GT-12 pairing) share the 4697 uid; every other event
    keys on its own uid. WHY all in-window events and not only labelled ones: the pairing is a fact about events,
    computed exactly as the stitcher and the gate compute it on the same rows."""
    keys = {e.uid: e.uid for e in events}
    s1 = [_row(e) for e in events if _is(e, "Sysmon", 1)]
    e4688 = [_row(e) for e in events if _is(e, "Security", 4688)]
    for s, p in collapse(s1, e4688, process_collapse_s):
        if s is not None and p is not None:
            keys[str(p["event_uid"])] = str(s["event_uid"])
    e7045 = [_row(e) for e in events if _is(e, "System", 7045)]
    e4697 = [_row(e) for e in events if _is(e, "Security", 4697)]
    for uid_7045, uid_4697 in pair_services(e7045, e4697, service_pair_s).items():
        keys[uid_7045] = uid_4697
    return keys
