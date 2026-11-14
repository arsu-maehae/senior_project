"""One pure pass over the event rows: window flag (ST-01), corrected time and clock flag (ST-02), the kinds
T7.2 keeps, the identity look-back view, the T7.3 link kinds, and near-duplicate collapse (ST-05).

WHY pure: the DB reading lives in ``inputs.load_scan``; this module takes any iterable of row mappings, so a
test can feed synthetic rows and get exactly what the real run would get. Nothing here opens a file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from clock_offset.correct import ClockChanges, Offsets, corrected_us, event_unreliable
from gate.inputs import event_key
from gate.timeutil import US_PER_MS, to_us

from .errors import StitchError
from .params import BOOT_CHANNEL, BOOT_SHUTDOWN_IDS, BOOT_STARTUP_IDS, LOG_CLEAR_EVENTS, SCAN_COLUMNS

__all__ = ["StitchError", "ScanResult", "scan_rows", "in_window", "is_logon", "is_logoff", "is_boot",
           "is_log_clear", "is_sysmon1", "is_sec4688", "is_sysmon_attached", "is_window_kind",
           "is_lookback_kind", "is_link_kind", "collapse_near_duplicates", "LINK_KINDS"]

Row = dict[str, Any]


# ---------------------------------------------------------------- window (ST-01)

def in_window(us: int, start_us: int, end_us: int) -> bool:
    """``start <= us < end + 1 ms``: the same predicate as gate GT-01 (``gate.inputs.scan_events``).

    WHY + 1 ms: the window file holds millisecond text, the DB microseconds; an event logged within the
    last millisecond of the window is inside it. Using the gate's exact predicate means the stitcher never
    sees an event the gate clipped, or misses one it kept.
    """
    return start_us <= us < end_us + US_PER_MS


# ---------------------------------------------------------------- kinds

def _is(row: Mapping, channel: str, *event_ids: int) -> bool:
    """Channel and event id together: event ids alone collide across channels (Sysmon 1 vs System 1)."""
    return row.get("channel") == channel and row.get("event_id") in event_ids


def is_logon(row: Mapping) -> bool:
    """Security 4624: opens a session (ST-10)."""
    return _is(row, "Security", 4624)


def is_logoff(row: Mapping) -> bool:
    """Security 4634 or 4647: closes a session; a 4647 carries its logon ID in ``target_logon_id`` (ST-10)."""
    return _is(row, "Security", 4634, 4647)


def is_boot(row: Mapping) -> bool:
    """System startup (41, 6005, 6008) or shutdown (1074, 6006): an epoch boundary candidate (ST-10, 047)."""
    return _is(row, BOOT_CHANNEL, *sorted(BOOT_STARTUP_IDS | BOOT_SHUTDOWN_IDS))


def is_log_clear(row: Mapping) -> bool:
    """Security 1102 only (ST-63; decision 047 item 7): a clear makes a session's end unknown."""
    return (row.get("channel"), row.get("event_id")) in LOG_CLEAR_EVENTS


def is_sysmon1(row: Mapping) -> bool:
    """Sysmon 1: a process start with its guid tree and LogonId (ST-11; 047 item 1)."""
    return _is(row, "Sysmon", 1)


def is_sec4688(row: Mapping) -> bool:
    """Security 4688: a process start, collapsed with its Sysmon 1 twin when there is one (ST-11)."""
    return _is(row, "Security", 4688)


def is_sysmon_attached(row: Mapping) -> bool:
    """Sysmon 3, 10 or 11: events that belong to a process by ``process_guid`` (ST-11)."""
    return _is(row, "Sysmon", 3, 10, 11)


def is_lookback_kind(row: Mapping) -> bool:
    """Kinds kept BEFORE the window: what ST-63 may read for identity (opens, closes, boots, clears).

    WHY no Sysmon 1: owner Q13b; a pre-window process never becomes a process of the index.
    """
    return is_logon(row) or is_logoff(row) or is_boot(row) or is_log_clear(row)


def is_window_kind(row: Mapping) -> bool:
    """Kinds kept INSIDE the window by T7.2: the look-back kinds plus process starts and attached events."""
    return is_lookback_kind(row) or is_sysmon1(row) or is_sec4688(row) or is_sysmon_attached(row)


# T7.3 link kinds (decision 048 item 2): target-side artefacts (5140 / 5145 shares, 4697 / 7045 installs, WinRM
# 91), source-side 4648 (ST-42) and Kerberos 4769 (ST-47). 4769 is kept on every host here; the dc01
# restriction is applied where it is read, so this predicate stays a pure channel/event test.
LINK_KINDS: frozenset[tuple[str, int]] = frozenset({
    ("Security", 5140), ("Security", 5145), ("Security", 4697), ("Security", 4648), ("Security", 4769),
    ("System", 7045), ("WinRM", 91),
})


def is_link_kind(row: Mapping) -> bool:
    """A T7.3 link kind (``LINK_KINDS``). Disjoint from ``is_window_kind`` by construction.

    WHY a separate predicate and list: adding these kinds to ``is_window_kind`` would change the T7.2
    ``in_window`` list and every T7.2 count; kept apart, ``t72_index.json`` stays byte-identical (048 item 2).
    """
    return (row.get("channel"), row.get("event_id")) in LINK_KINDS


# ---------------------------------------------------------------- result

@dataclass
class ScanResult:
    """What one pass yields. Every kept row carries the ``SCAN_COLUMNS`` plus ``us_raw``, ``us``,
    ``in_window``, ``clock_unreliable`` and ``event_uids``.

    ``in_window`` holds the in-window rows of the T7.2 kinds; ``lookback`` the pre-window rows of the
    look-back kinds (ST-63 only, never a member, artefact, evidence or node: ST-01). Out-of-window rows of
    every kind are counted in ``removed_by_window`` (host -> "Channel/eid" -> n), also those kept in
    ``lookback``. ``near_duplicate_groups`` counts ST-05 groups of two or more kept rows;
    ``near_duplicate_split_by_window`` counts those whose members lie on both sides of the window start
    (the kept row is the earliest, so such a group is placed by its earliest copy). These counts cover the
    T7.2 kinds only.

    ``link_rows`` holds the in-window rows of the link kinds (``is_link_kind``; decision 048 item 2), sorted
    like ``in_window``; they are in neither ``in_window`` nor ``lookback``. They are collapsed (ST-05) in a
    separate call with their own counters ``link_near_duplicate_groups`` and
    ``link_near_duplicate_split_by_window``, so every T7.2 field keeps its T7.2 value.

    ``hosts_loaded`` is the sorted list of hosts of EVERY row read, whatever its kind or time (a NULL host is
    left out: it names no host). WHY: ``source_host_no_logs`` means "the DB holds no row of that host"
    (048 item 6 as amended in task 5); the kept and counted lists miss hosts whose only rows are in-window
    rows of a kind the scan neither keeps nor counts. It enters no T7.2 count, so ``t72_index.json`` is
    unchanged.
    """
    in_window: list[Row] = field(default_factory=list)
    lookback: list[Row] = field(default_factory=list)
    loaded_total: int = 0
    removed_by_window: dict[str, dict[str, int]] = field(default_factory=dict)
    kept_lookback_by_type: dict[str, int] = field(default_factory=dict)
    near_duplicate_groups: int = 0
    near_duplicate_split_by_window: int = 0
    link_rows: list[Row] = field(default_factory=list)
    link_near_duplicate_groups: int = 0
    link_near_duplicate_split_by_window: int = 0
    hosts_loaded: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- per-row steps

def _instant_raw(row: Mapping) -> int:
    """Logged ``event_utc`` as µs; StitchError when missing or unparseable.

    WHY refuse and not skip: an event with no time cannot be placed in or out of the window, and dropping
    it silently could remove a hop member (ST-04: nothing dropped).
    """
    try:
        return to_us(row["event_utc"])
    except (KeyError, TypeError, ValueError) as exc:
        raise StitchError(f"event {row.get('event_uid')} has no valid event_utc ({exc})") from exc


def kept_row(raw: Mapping, start_us: int, end_us: int, offsets: Offsets | None,
             changes: ClockChanges | Iterable = ()) -> Row:
    """A new dict with only the ``SCAN_COLUMNS`` values plus the ST-01 / ST-02 fields.

    WHY a new dict of SCAN_COLUMNS only: whatever extra keys the caller's rows carry (a test may pass a
    command line) never reach the index. ``us`` is the shared CO-09 correction; ``clock_unreliable`` the
    shared event-level flag (spec 08 D5). With no offsets there is no correction and no flag.
    """
    row: Row = {c: raw.get(c) for c in SCAN_COLUMNS}
    host = str(row.get("host"))
    row["us_raw"] = _instant_raw(raw)
    row["us"] = row["us_raw"] if offsets is None else corrected_us(row["us_raw"], host, offsets)
    row["in_window"] = in_window(row["us"], start_us, end_us)
    row["clock_unreliable"] = (0 if offsets is None
                               else int(event_unreliable(host, row["us_raw"], offsets, changes)))
    row["event_uids"] = [row["event_uid"]]
    return row


def _bump(table: dict[str, dict[str, int]], host: str, key: str) -> None:
    """Increment a host x key counter."""
    inner = table.setdefault(host, {})
    inner[key] = inner.get(key, 0) + 1


def _order_key(row: Mapping) -> tuple[int, str]:
    """(us_raw, event_uid): the ST-05 representative is the earliest logged copy, uid as the tie-break."""
    return row["us_raw"], str(row["event_uid"])


def collapse_near_duplicates(rows: Iterable[Row]) -> tuple[list[Row], int, int]:
    """ST-05: rows with one (host, channel, record_id), record_id not None, become one row.

    The earliest by (us_raw, event_uid) is kept and every uid of the group goes into its ``event_uids``
    (sorted), so one event counts once and stays traceable to all its copies. Returns (rows, groups of two
    or more, groups whose copies lie on both sides of the window start). Rows with no record_id are never
    grouped (a NULL never matches, decision 005).
    """
    groups: dict[tuple, list[Row]] = {}
    out: list[Row] = []
    for row in rows:
        if row.get("record_id") is None:
            out.append(row)
        else:
            groups.setdefault((row.get("host"), row.get("channel"), row["record_id"]), []).append(row)
    n_groups = n_split = 0
    for members in groups.values():
        keep = min(members, key=_order_key)
        if len(members) > 1:
            n_groups += 1
            n_split += int(len({m["in_window"] for m in members}) > 1)
            keep["event_uids"] = sorted({str(m["event_uid"]) for m in members})
        out.append(keep)
    return out, n_groups, n_split


def _sort_key(row: Mapping) -> tuple[int, str]:
    """Output order: corrected time, then uid, so two runs on the same rows give the same lists."""
    return row["us"], str(row["event_uid"])


# ---------------------------------------------------------------- the pass

def _collapse_links(link_seen: list[Row]) -> tuple[list[Row], int, int]:
    """ST-05 over the link kinds alone; returns (in-window representatives sorted, groups, split groups).

    ``link_seen`` holds the in-window link rows plus the PRE-window ones. WHY the pre-window copies: the
    T7.2 rule places a near-duplicate group by its earliest copy, so a group with a copy before the window
    start is not an in-window event; the same must hold for link rows. The pre-window rows are only used
    for this placement and are never returned (link rows are never kept before the window, ST-01).
    """
    collapsed, groups, split = collapse_near_duplicates(link_seen)
    kept = sorted((r for r in collapsed if r["in_window"]), key=_sort_key)
    return kept, groups, split


def scan_rows(rows: Iterable[Mapping], start_us: int, end_us: int, offsets: Offsets | None,
              changes: ClockChanges | Iterable = ()) -> ScanResult:
    """ST-01, ST-02, ST-05 in one pass: keep in-window T7.2 kinds and pre-window look-back kinds, keep
    in-window link kinds apart (``link_rows``), count the rest.

    A row after the window is only counted, never kept. A pre-window row is kept in ``lookback`` only when
    it is a 4624, 4634, 4647, boot or 1102 (ST-63); a pre-window Sysmon 1 is never kept (owner Q13b); a
    pre-window link row is never kept (it only places its near-duplicate group, ``_collapse_links``).
    ``removed_by_window`` counts every out-of-window row of every kind, link kinds included, as in T7.2.
    ``hosts_loaded`` collects the host of every row read (048 item 6 as amended).
    Raises StitchError for a row without a parseable ``event_utc``.
    """
    res = ScanResult()
    kept: list[Row] = []
    link_seen: list[Row] = []
    hosts: set[str] = set()
    for raw in rows:
        res.loaded_total += 1
        row = kept_row(raw, start_us, end_us, offsets, changes)
        if row.get("host") is not None:
            hosts.add(str(row["host"]))
        if row["in_window"]:
            if is_window_kind(row):
                kept.append(row)
            elif is_link_kind(row):
                link_seen.append(row)
            continue
        _bump(res.removed_by_window, str(row.get("host")), event_key(row))
        if row["us"] < start_us and is_lookback_kind(row):
            kept.append(row)
        elif row["us"] < start_us and is_link_kind(row):
            link_seen.append(row)
    res.link_rows, res.link_near_duplicate_groups, res.link_near_duplicate_split_by_window = (
        _collapse_links(link_seen))
    collapsed, res.near_duplicate_groups, res.near_duplicate_split_by_window = collapse_near_duplicates(kept)
    collapsed.sort(key=_sort_key)
    res.in_window = [r for r in collapsed if r["in_window"]]
    res.lookback = [r for r in collapsed if not r["in_window"]]
    for r in res.lookback:
        key = event_key(r)
        res.kept_lookback_by_type[key] = res.kept_lookback_by_type.get(key, 0) + 1
    res.kept_lookback_by_type = dict(sorted(res.kept_lookback_by_type.items()))
    res.removed_by_window = {h: dict(sorted(c.items())) for h, c in sorted(res.removed_by_window.items())}
    res.hosts_loaded = sorted(hosts)
    return res
