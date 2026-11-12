"""Clock-change events: counted or routine, position against the pairs, the "logged before" interval, and the
``<trial>.clock_changes.csv`` rows (spec 08 CO-15, CO-18, CO-19; owner decisions D1-D5, 2026-11-12).

WHY one module: the pair cut (pairs.py), the CO-19 report (scan.py), the CO-10 check and every consumer of
``clock_unreliable`` (correct.py) must agree on which change counts (D1), how it is classified (D3) and which
events were logged before it (D4/D5). Everything here is pure: it works on row dicts carrying ``us`` and on
``ClockChange`` records, and reads no file.

Definitions (owner D1, D3, D4):
- A Security 4616 / Kernel-General System 1 is **counted** when |new - previous| >= ``MIN_CLOCK_STEP_MS``, or
  when its shift is unknown (conservative). A smaller one is **routine**: listed, it changes nothing.
- Boot/shutdown events always count for the pair cut (CO-15) but are not clock changes: they are not in the
  changes file and do not make events ``clock_unreliable`` (D5).
- An event was **logged before** a change when its recorded time is in
  [the host's last boot before the change, max(previous_time, change time)). For a backward step the end is
  previous_time inclusive: the overlap [new_time, previous_time] holds events of both clocks, so all of it is
  treated as before the change.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping, Sequence

from gate.timeutil import fmt_us, to_us

from . import params

CLASS_ROUTINE = "routine"
CLASS_EXPECTED = "expected_before_first_pair"
CLASS_BETWEEN = "between_pairs"
CLASS_AFTER = "after_last_pair"
CLASS_NO_PAIRS = "no_pairs"
CLASSIFICATIONS: tuple[str, ...] = (CLASS_ROUTINE, CLASS_EXPECTED, CLASS_BETWEEN, CLASS_AFTER, CLASS_NO_PAIRS)
# D3: a counted step after the host's first pair, or on a host with no pairs (dc01 included), flags the trial.
FLAG_CLASSES: frozenset[str] = frozenset({CLASS_BETWEEN, CLASS_AFTER, CLASS_NO_PAIRS})

SOURCE_DB = "db"
SOURCE_EXPORT = "export"

# Trial-level CO-19 scan status, written into the offsets file (review SF-4, owner 2026-11-12); consumers refuse
# anything but ``complete``. Defined here because scan.py (writer) and correct.py (reader) both import this module.
SCAN_COMPLETE = "complete"
SCAN_INCOMPLETE = "incomplete"
SCAN_STATUSES: tuple[str, ...] = (SCAN_COMPLETE, SCAN_INCOMPLETE)

CHANGES_SUFFIX = ".clock_changes.csv"
# D5 file. ``channel``, ``event_id`` and ``last_boot_before_utc`` are added to the owner's list: the first two
# tell a 4616 from a System 1, the third is the lower end of the "logged before" interval (D4), which a
# consumer reading only this file could not find otherwise.
CLOCK_CHANGES_COLUMNS: tuple[str, ...] = (
    "trial_id", "host", "channel", "event_id", "change_utc", "previous_time", "new_time", "shift_ms", "counted",
    "classification", "last_boot_before_utc", "source", "event_uid_or_record", "source_sha256",
)
# D4: event uids listed per step in clock_scan.json (the full count is always given).
PRE_STEP_UID_CAP = 50

Bounds = Mapping[str, tuple[int, int]]


@dataclass(frozen=True)
class ShiftInfo:
    """Previous/new time of one DB clock-change row, resolved from its JSONL line (D2); ``reason`` says why
    the shift is unknown when it could not be resolved."""
    previous_time: str | None
    new_time: str | None
    shift_ms: int | None
    reason: str | None = None


@dataclass(frozen=True)
class ClockChange:
    """One clock-change record (DB row or export record) with what the cut, the flag and D5 need."""
    host: str
    channel: str
    event_id: int
    change_us: int
    previous_time: str | None
    new_time: str | None
    previous_us: int | None
    shift_ms: int | None
    counted: bool
    source: str
    ref: str
    source_sha256: str | None
    last_boot_before_us: int | None = None


# ---------------------------------------------------------------- small pure helpers

def parse_instant_us(text: Any) -> int | None:
    """ISO-8601 instant with a zone to integer µs, or None when absent or not parseable.

    WHY tolerant: a previous/new time that cannot be read only leaves the shift unknown (which counts, D1);
    it must not stop the step. Fractions beyond 6 digits (EVTX writes 7, 4616 data 9) are truncated by
    ``datetime.fromisoformat`` (Python >= 3.11).
    """
    if text is None or not str(text).strip():
        return None
    try:
        return to_us(str(text).strip())
    except (TypeError, ValueError):
        return None


def shift_between(previous_us: int | None, new_us: int | None) -> int | None:
    """new - previous in whole ms, rounded half away from zero; None when either time is missing."""
    if previous_us is None or new_us is None:
        return None
    d = new_us - previous_us
    mag = (abs(d) + 500) // 1000
    return -mag if d < 0 else mag


def is_counted_shift(shift_ms: int | None, min_step_ms: int = params.MIN_CLOCK_STEP_MS) -> bool:
    """D1: unknown shift counts (conservative); otherwise |shift| >= ``MIN_CLOCK_STEP_MS``."""
    return shift_ms is None or abs(shift_ms) >= min_step_ms


def is_clock_change_row(row: Mapping) -> bool:
    """DB row that is a clock change: Security 4616 or System 1 (CO-18 keeps System 1 only from Kernel-General)."""
    return (row.get("channel"), row.get("event_id")) in params.CLOCK_CHANGE_EVENTS


def is_boot_row(row: Mapping) -> bool:
    """System boot/shutdown event (CO-15). Channel and id together: Sysmon/Security reuse these ids."""
    return row.get("channel") == "System" and row.get("event_id") in params.BOOT_EVENT_IDS


def make_change(*, host: str, channel: str, event_id: int, change_us: int, previous_time: str | None,
                new_time: str | None, source: str, ref: str, source_sha256: str | None,
                shift_ms: int | None = None, min_step_ms: int = params.MIN_CLOCK_STEP_MS) -> ClockChange:
    """ClockChange with ``previous_us``, ``shift_ms`` (from the two times unless given) and ``counted`` set."""
    prev_us, new_us = parse_instant_us(previous_time), parse_instant_us(new_time)
    shift = shift_ms if shift_ms is not None else shift_between(prev_us, new_us)
    return ClockChange(host, channel, int(event_id), change_us, previous_time, new_time, prev_us, shift,
                       is_counted_shift(shift, min_step_ms), source, ref, source_sha256)


def db_changes(events: Iterable[Mapping], shifts: Mapping[str, ShiftInfo] | None, lo_us: int, hi_us: int,
               min_step_ms: int = params.MIN_CLOCK_STEP_MS) -> list[ClockChange]:
    """Clock-change rows of the DB inside [lo, hi], with the shift resolved by the caller (unknown -> counts)."""
    out = []
    for e in events:
        if not is_clock_change_row(e) or not lo_us <= e["us"] <= hi_us:
            continue
        info = (shifts or {}).get(str(e["event_uid"]))
        out.append(make_change(host=e["host"], channel=e["channel"], event_id=e["event_id"], change_us=e["us"],
                               previous_time=info.previous_time if info else None,
                               new_time=info.new_time if info else None, source=SOURCE_DB,
                               ref=str(e["event_uid"]), source_sha256=e.get("source_sha256"),
                               shift_ms=info.shift_ms if info else None, min_step_ms=min_step_ms))
    return out


def boot_times(events: Iterable[Mapping]) -> dict[str, list[int]]:
    """host -> sorted recorded instants of its boot/shutdown events (whole DB)."""
    out: dict[str, list[int]] = {}
    for e in events:
        if is_boot_row(e):
            out.setdefault(e["host"], []).append(e["us"])
    return {h: sorted(v) for h, v in out.items()}


def last_boot_before(host: str, us: int, boots: Mapping[str, Sequence[int]]) -> int | None:
    """The host's latest boot strictly before ``us`` (recorded time), or None."""
    times = boots.get(host, ())
    i = bisect.bisect_left(times, us)
    return times[i - 1] if i else None


def with_last_boot(changes: Iterable[ClockChange], boots: Mapping[str, Sequence[int]]) -> list[ClockChange]:
    """Each change with ``last_boot_before_us`` filled (the lower end of the D4 interval)."""
    return [replace(c, last_boot_before_us=last_boot_before(c.host, c.change_us, boots)) for c in changes]


def sort_changes(changes: Iterable[ClockChange]) -> list[ClockChange]:
    """File order (D5): host, change instant, then source/channel/ref so equal keys sort the same way."""
    return sorted(changes, key=lambda c: (c.host, c.change_us, c.source, c.channel, c.ref))


# ---------------------------------------------------------------- classification and flag (D3)

def classify(change: ClockChange, bounds: Bounds | None) -> str:
    """routine (not counted) / expected (before the first kept pair) / between / after / no_pairs (D3).

    The bounds are the host's first and last ORIGINAL pair 4624: the mutual-nearest pairs after the far drop
    and before the change cut (owner 2026-11-12, ``pairs.original_bounds``), for DB and export changes alike.
    So a step before the first original pair is expected; a step between the first and last original pair is
    ``between_pairs`` and flags the trial even though the cut dropped the earlier pairs; a step after the last
    original pair is ``after_last_pair`` and flags (the cut rule makes the host stale).
    """
    if not change.counted:
        return CLASS_ROUTINE
    b = (bounds or {}).get(change.host)
    if b is None:
        return CLASS_NO_PAIRS
    first, last = b
    if change.change_us < first:
        return CLASS_EXPECTED
    return CLASS_BETWEEN if change.change_us <= last else CLASS_AFTER


def flags_trial(changes: Iterable[ClockChange], bounds: Bounds | None) -> bool:
    """D3 ``clock_change_in_window``: any counted change classified between / after / no_pairs."""
    return any(classify(c, bounds) in FLAG_CLASSES for c in changes)


def class_counts(changes: Sequence[ClockChange], bounds: Bounds | None) -> dict[str, Any]:
    """Counts by classification; expected = counted before the first pair, unexpected = the flagging ones."""
    by = {k: 0 for k in CLASSIFICATIONS}
    for c in changes:
        by[classify(c, bounds)] += 1
    return {"by_classification": by, "routine_count": by[CLASS_ROUTINE], "expected_count": by[CLASS_EXPECTED],
            "unexpected_count": sum(by[k] for k in FLAG_CLASSES)}


def pair_bounds(pair_rows: Iterable[Mapping]) -> dict[str, tuple[int, int]]:
    """host -> (first, last) 4624 instant of the given pairs rows (``host``, ``t_4624_utc``).

    Not the classification bounds since owner 2026-11-12 (those come from the original pairs,
    ``pairs.original_bounds``); kept for callers that hold only pairs rows.
    """
    out: dict[str, tuple[int, int]] = {}
    for r in pair_rows:
        us = to_us(r["t_4624_utc"])
        lo, hi = out.get(r["host"], (us, us))
        out[r["host"]] = (min(lo, us), max(hi, us))
    return out


# ---------------------------------------------------------------- logged before (D4, D5)

def logged_before_bounds(change: ClockChange) -> tuple[int | None, int]:
    """(lo or None, hi exclusive) of the D4 interval: [last boot before, max(previous_time, change time)).

    Backward step (previous after the change): hi = previous_time + 1 µs, so the whole overlap
    [new_time, previous_time] counts as before the change (owner D5). Unknown previous time: hi = change time.
    """
    hi = change.change_us
    if change.previous_us is not None and change.previous_us > change.change_us:
        hi = change.previous_us + 1
    return change.last_boot_before_us, hi


def logged_before(change: ClockChange, recorded_us: int) -> bool:
    """True when an event of the change's host with this recorded time was logged before the change (D4)."""
    lo, hi = logged_before_bounds(change)
    return (lo is None or lo <= recorded_us) and recorded_us < hi


def before_counted(host: str, recorded_us: int, changes: Iterable[ClockChange]) -> bool:
    """D5: the event was logged before a counted clock change on its host (boots are not in ``changes``)."""
    return any(c.host == host and c.counted and logged_before(c, recorded_us) for c in changes)


# ---------------------------------------------------------------- rows

def change_row(trial_id: str, change: ClockChange, bounds: Bounds | None) -> dict[str, Any]:
    """One clock_changes.csv row; instants are written as ``...ffffffZ`` so DB and export rows sort alike."""
    return {"trial_id": trial_id, "host": change.host, "channel": change.channel, "event_id": change.event_id,
            "change_utc": fmt_us(change.change_us), "previous_time": change.previous_time,
            "new_time": change.new_time, "shift_ms": change.shift_ms, "counted": change.counted,
            "classification": classify(change, bounds),
            "last_boot_before_utc": (None if change.last_boot_before_us is None
                                     else fmt_us(change.last_boot_before_us)),
            "source": change.source, "event_uid_or_record": change.ref, "source_sha256": change.source_sha256}


def change_rows(trial_id: str, changes: Iterable[ClockChange], bounds: Bounds | None) -> list[dict[str, Any]]:
    """Every change as a row, in file order."""
    return [change_row(trial_id, c, bounds) for c in sort_changes(changes)]


def _bool(text: str) -> bool:
    """``true``/``false`` cell to bool; anything else is an error (never guessed)."""
    t = str(text).strip().lower()
    if t not in ("true", "false"):
        raise ValueError(f"not a boolean cell: {text!r}")
    return t == "true"


def _opt_int(text: Any) -> int | None:
    """Empty cell -> None, else int."""
    t = "" if text is None else str(text).strip()
    return int(t) if t else None


def change_from_row(row: Mapping[str, Any]) -> ClockChange:
    """ClockChange from a clock_changes.csv row; ``counted`` is taken from the file (what the step decided)."""
    prev = row.get("previous_time") or None
    boot = row.get("last_boot_before_utc") or None
    return ClockChange(host=str(row["host"]), channel=str(row["channel"]), event_id=int(row["event_id"]),
                       change_us=to_us(row["change_utc"]), previous_time=prev, new_time=row.get("new_time") or None,
                       previous_us=parse_instant_us(prev), shift_ms=_opt_int(row.get("shift_ms")),
                       counted=_bool(row["counted"]), source=str(row["source"]),
                       ref=str(row["event_uid_or_record"]), source_sha256=row.get("source_sha256") or None,
                       last_boot_before_us=None if boot is None else to_us(boot))


# ---------------------------------------------------------------- pre-step events (D4)

def pre_step(events: Sequence[Mapping], change: ClockChange, win_start_us: int, win_end_excl_us: int,
             cap: int = PRE_STEP_UID_CAP) -> dict[str, Any]:
    """D4 for one counted step: (a) host events logged before it whose real time (recorded + shift) is in the
    window, (b) host events recorded in [window start, step time), (c) their uids (capped, full count given).

    (a) is None when the shift is unknown: the real time of those events cannot be computed.
    """
    lo, hi = logged_before_bounds(change)
    host_ev = sorted((e for e in events if e.get("host") == change.host),
                     key=lambda e: (e["us"], str(e["event_uid"])))
    before = [e for e in host_ev if (lo is None or lo <= e["us"]) and e["us"] < hi]
    real: list[Mapping] | None = None
    if change.shift_ms is not None:
        shift_us = change.shift_ms * 1000
        real = [e for e in before if win_start_us <= e["us"] + shift_us < win_end_excl_us]
    literal = [e for e in host_ev if win_start_us <= e["us"] < change.change_us]
    return {"host": change.host, "step_utc": fmt_us(change.change_us), "channel": change.channel,
            "event_id": change.event_id, "source": change.source, "event_uid_or_record": change.ref,
            "previous_time": change.previous_time, "new_time": change.new_time, "shift_ms": change.shift_ms,
            "last_boot_before_utc": (None if change.last_boot_before_us is None
                                     else fmt_us(change.last_boot_before_us)),
            "logged_before_interval": [None if lo is None else fmt_us(lo), fmt_us(hi)],
            "logged_before_count": len(before),
            "a_real_time_in_window_count": None if real is None else len(real),
            "a_event_uids": None if real is None else [str(e["event_uid"]) for e in real[:cap]],
            "b_literal_in_window_before_step_count": len(literal),
            "b_event_uids": [str(e["event_uid"]) for e in literal[:cap]],
            "uid_cap": cap}


def pre_steps(events: Sequence[Mapping], changes: Iterable[ClockChange], win_start_us: int,
              win_end_excl_us: int, cap: int = PRE_STEP_UID_CAP) -> list[dict[str, Any]]:
    """D4 for every counted clock change inside the agent window [start, end + 1 ms), in file order."""
    return [pre_step(events, c, win_start_us, win_end_excl_us, cap) for c in sort_changes(changes)
            if c.counted and win_start_us <= c.change_us < win_end_excl_us]
