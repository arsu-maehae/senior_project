"""Evidence and pairing for the clock offset (spec 08 CO-02, CO-03, CO-04, CO-14, CO-15, CO-18).

WHY pure functions on row dicts with integer microseconds (``row["us"]``): every pair must be
traceable to its two event uids, every tie must be broken the same way on every run (CO-14), and
the 60 s / 120 s bounds must be exact at the boundary (no float error). Nothing here reads a file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from . import params
from .changes import ShiftInfo, is_counted_shift
from .common import is_event, lab_ip_set, norm_guid, norm_ip, s_to_us

Row = Mapping


@dataclass(frozen=True)
class Pair:
    """One endpoint 4624 <-> dc01 4769 pair with the same LogonGuid (CO-03).

    ``delta_us`` = 4624 instant (host clock) - 4769 instant (dc01 clock) (CO-04).
    ``candidate_count`` = dc01 4769s with that GUID in the edge-widened span (CLAUDE.md code rules).
    """
    host: str
    guid: str
    e4624: Row
    e4769: Row
    delta_us: int
    candidate_count: int


@dataclass(frozen=True)
class HostPairs:
    """Everything the pairing decided for one endpoint, so each count in stats.json is traceable.

    ``kept`` are the pairs the estimate uses; ``dropped_far`` (CO-02) and ``dropped_before_change``
    (CO-15/CO-18, owner D2) keep the pairs that were removed, with their uids. ``kept`` plus
    ``dropped_before_change`` are the host's ORIGINAL pairs (mutual nearest after the far drop, before the
    change cut), against which clock changes are classified (owner 2026-11-12). ``cut_event_uid`` is the
    counted change that set the cut; ``stale_event_uids`` are counted changes after the last kept pair.
    ``expected_change_uids``: counted clock changes before the first kept pair (planned resync, revert
    catch-up); ``routine_change_uids``: clock changes below ``MIN_CLOCK_STEP_MS`` (listed only, D1).
    """
    host: str
    n_4624_guid: int
    n_4624_with_candidate: int
    mutual: tuple[Pair, ...]
    dropped_far: tuple[Pair, ...]
    dropped_before_change: tuple[Pair, ...]
    kept: tuple[Pair, ...]
    cut_event_uid: str | None
    stale_event_uids: tuple[str, ...] = field(default=())
    expected_change_uids: tuple[str, ...] = field(default=())
    routine_change_uids: tuple[str, ...] = field(default=())

    @property
    def original(self) -> tuple[Pair, ...]:
        """The pairs before the change cut (mutual nearest after the far drop), in pairs.csv order.

        WHY: the owner (2026-11-12) classifies a clock change against these, so a step that the cut used
        to drop earlier pairs is still reported as ``between_pairs`` instead of disappearing as expected.
        """
        return tuple(sort_pairs(self.kept + self.dropped_before_change))

    @property
    def stale(self) -> bool:
        """CO-15: a restart or clock change after the last kept pair makes the estimate describe an old clock."""
        return bool(self.stale_event_uids)

    @property
    def dropped_by_mutual_nearest(self) -> int:
        """4624s that had a same-GUID 4769 but lost the 1:1 mutual-nearest test (stats.json)."""
        return self.n_4624_with_candidate - len(self.mutual)


# ---------------------------------------------------------------- evidence (CO-02)

def in_span(row: Row, lo_us: int, hi_us: int) -> bool:
    """Inclusive span test on integer microseconds."""
    return lo_us <= row["us"] <= hi_us


def endpoint_logons(events: Iterable[Row], lo_us: int, hi_us: int,
                    endpoints: Sequence[str] = params.ENDPOINTS) -> list[Row]:
    """Security 4624 on an endpoint with a non-NULL LogonGuid, inside the search span (CO-02)."""
    return [e for e in events if e.get("host") in endpoints and is_event(e, "Security", 4624)
            and norm_guid(e.get("logon_guid")) is not None and in_span(e, lo_us, hi_us)]


def dc_tickets(events: Iterable[Row], lo_us: int, hi_us: int, edge_us: int,
               reference_host: str = params.REFERENCE_HOST) -> list[Row]:
    """dc01 Security 4769 with a non-NULL LogonGuid in the span widened by ``edge_us`` on both sides.

    WHY wider than the 4624 span: a 4624 at the very edge of the span must keep its 4769 partner,
    which the DC may log a few seconds on the other side of the edge (CO-02, ``DC_EDGE_S``).
    """
    return [e for e in events if e.get("host") == reference_host and is_event(e, "Security", 4769)
            and norm_guid(e.get("logon_guid")) is not None and in_span(e, lo_us - edge_us, hi_us + edge_us)]


def by_guid(rows: Iterable[Row]) -> dict[str, list[Row]]:
    """GUID -> rows with that GUID (comparison form)."""
    out: dict[str, list[Row]] = {}
    for r in rows:
        g = norm_guid(r.get("logon_guid"))
        if g is not None:
            out.setdefault(g, []).append(r)
    return out


# ---------------------------------------------------------------- pairing (CO-03, CO-14)

def nearest(t_us: int, candidates: Sequence[Row]) -> Row:
    """Candidate nearest in time to ``t_us``; equal distances are broken by the smaller event_uid (CO-14)."""
    return min(candidates, key=lambda c: (abs(c["us"] - t_us), str(c["event_uid"])))


def mutual_nearest(logons: Sequence[Row], tickets: Sequence[Row]) -> list[tuple[Row, Row]]:
    """1:1 mutual-nearest pairs within each GUID: a 4624 a and a 4769 b pair only if b is a's nearest
    same-GUID 4769 AND a is b's nearest same-GUID 4624 (CO-03).

    WHY this rule: GUIDs reused by several 4624s or 4769s (s06_t01 ep-03) would otherwise yield every
    combination and pull the median (spec 10.3, rule B fails the independent check). Because the
    tie-break is deterministic, each b has exactly one nearest a, so every event is used at most once.
    ``logons`` must all come from one host.
    """
    tix = by_guid(tickets)
    out: list[tuple[Row, Row]] = []
    for g, alist in sorted(by_guid(logons).items()):
        blist = tix.get(g)
        if not blist:
            continue
        for a in sorted(alist, key=lambda r: (r["us"], str(r["event_uid"]))):
            b = nearest(a["us"], blist)
            if nearest(b["us"], alist)["event_uid"] == a["event_uid"]:
                out.append((a, b))
    return out


def make_pairs(host: str, logons: Sequence[Row], tickets: Sequence[Row]) -> list[Pair]:
    """Mutual-nearest pairs of one host as ``Pair`` records, sorted by (4624 time, 4624 uid, 4769 uid)."""
    tix = by_guid(tickets)
    pairs = []
    for a, b in mutual_nearest(logons, tickets):
        g = norm_guid(a.get("logon_guid"))
        assert g is not None
        pairs.append(Pair(host, g, a, b, a["us"] - b["us"], len(tix[g])))
    return sort_pairs(pairs)


def sort_pairs(pairs: Iterable[Pair]) -> list[Pair]:
    """Pairs in the pairs.csv order: (host, 4624 instant, 4624 uid, 4769 uid) (CO-14)."""
    return sorted(pairs, key=lambda p: (p.host, p.e4624["us"], str(p.e4624["event_uid"]), str(p.e4769["event_uid"])))


def split_far(pairs: Sequence[Pair], max_delta_us: int) -> tuple[list[Pair], list[Pair]]:
    """(kept, dropped): a pair with |delta| > ``MAX_PAIR_DELTA_S`` is dropped (CO-02, ATK-02).

    WHY after pairing: a lone GUID pair minutes apart (ticket cache, reuse) is still the mutual
    nearest of its GUID; only its distance shows it cannot be a clock offset (largest real skew 27 s).
    """
    kept = [p for p in pairs if abs(p.delta_us) <= max_delta_us]
    dropped = [p for p in pairs if abs(p.delta_us) > max_delta_us]
    return kept, dropped


# ---------------------------------------------------------------- restarts and clock changes (CO-15, CO-18)

def shift_of(row: Row, shifts: Mapping[str, ShiftInfo] | None) -> int | None:
    """Resolved shift (ms) of a DB clock-change row, or None when unknown (no entry, or unresolved)."""
    info = (shifts or {}).get(str(row.get("event_uid")))
    return info.shift_ms if info is not None else None


def is_clock_change(row: Row, clock_events: frozenset[tuple[str, int]] = params.CLOCK_CHANGE_EVENTS) -> bool:
    """Security 4616 / System 1 only (CO-18), without the boot events.

    WHY every System 1: the DB has no provider column, and the amended CO-18 ingest keeps a System 1
    only when its provider is Microsoft-Windows-Kernel-General, so a System 1 in a DB is a time change.
    """
    return (row.get("channel"), row.get("event_id")) in clock_events


def is_change_event(row: Row, shifts: Mapping[str, ShiftInfo] | None = None,
                    boot_ids: frozenset[int] = params.BOOT_EVENT_IDS,
                    clock_events: frozenset[tuple[str, int]] = params.CLOCK_CHANGE_EVENTS,
                    min_step_ms: int = params.MIN_CLOCK_STEP_MS) -> bool:
    """A counted change for the pair cut: a System boot/shutdown event (CO-15, always), or a clock change
    (CO-18) whose |shift| >= ``MIN_CLOCK_STEP_MS`` or whose shift is unknown (owner D1, conservative).

    ``shifts`` maps a DB clock-change row's event_uid to its resolved previous/new time (D2); a row
    without an entry has an unknown shift and counts.
    """
    if row.get("channel") == "System" and row.get("event_id") in boot_ids:
        return True
    if is_clock_change(row, clock_events):
        return is_counted_shift(shift_of(row, shifts), min_step_ms)
    return False


def change_key(row: Row) -> tuple:
    """(host, channel, event_id, instant) of a change row: the identity used to deduplicate DB and export rows.

    WHY these four: a post-CO-18 DB row and the export record it was imported from describe one physical
    event and share all four, while their event_uids differ (DB uid vs ``export:<sha256>:<record_index>``).
    """
    return (row.get("host"), row.get("channel"), row.get("event_id"), row["us"])


def host_change_rows(events: Iterable[Row], host: str, extra_changes: Iterable[Row] = ()) -> list[Row]:
    """The host's DB rows plus its export change rows (SF-1), an export row dropped when a DB row (or an earlier
    export row) has the same ``change_key``; sorted by (instant, uid).

    WHY DB rows are kept as they are: they come from ``events_dedup`` (already deduplicated), and a DB row
    carries the uid the rest of the pipeline knows; the export row only adds a change the DB does not hold
    (every DB ingested before CO-18).
    """
    rows = [e for e in events if e.get("host") == host]
    seen = {change_key(e) for e in rows if is_clock_change(e)}
    for x in extra_changes:
        if x.get("host") != host:
            continue
        k = change_key(x)
        if k not in seen:
            seen.add(k)
            rows.append(x)
    return sorted(rows, key=lambda e: (e["us"], str(e["event_uid"])))


def change_events(events: Iterable[Row], host: str, shifts: Mapping[str, ShiftInfo] | None = None,
                  extra_changes: Iterable[Row] = ()) -> list[Row]:
    """The host's counted change events over the whole DB and the export change rows, sorted by (instant, uid).

    ``extra_changes`` are the CO-19 export hits as change rows (SF-1); their shifts must be in ``shifts``.
    """
    return [e for e in host_change_rows(events, host, extra_changes) if is_change_event(e, shifts)]


def routine_changes(events: Iterable[Row], host: str, shifts: Mapping[str, ShiftInfo] | None,
                    lo_us: int, hi_us: int, extra_changes: Iterable[Row] = ()) -> tuple[str, ...]:
    """uids of the host's clock changes (DB and export rows) in the search span that do not count
    (|shift| < 1 s, D1)."""
    return tuple(str(e["event_uid"]) for e in host_change_rows(events, host, extra_changes)
                 if is_clock_change(e) and lo_us <= e["us"] <= hi_us and not is_change_event(e, shifts))


def change_cut(pairs: Sequence[Pair], changes: Sequence[Row], window_end_excl_us: int
               ) -> tuple[list[Pair], list[Pair], str | None, tuple[str, ...]]:
    """(kept, dropped, cut uid, stale uids) for one host (CO-15, CO-18; owner D2).

    ``changes`` are the host's counted changes (DB and export rows, SF-1), sorted. The cut is the last
    counted change at or before the host's last pair; every pair at or before it is dropped, so only pairs after the last change that
    precedes the last pair are used. A counted change after the last kept pair and before the window end
    makes the host stale. WHY: a restart or a clock step can change the clock, so pairs from before it
    describe another clock; one after the last pair means the estimate is out of date. A change at the very
    instant of the last pair drops every pair (it cannot be ordered against it).
    """
    if not pairs:
        return [], [], None, ()
    last_us = max(p.e4624["us"] for p in pairs)
    before = [c for c in changes if c["us"] <= last_us]
    cut = before[-1] if before else None
    if cut is None:
        kept, dropped = list(pairs), []
    else:
        kept = [p for p in pairs if p.e4624["us"] > cut["us"]]
        dropped = [p for p in pairs if p.e4624["us"] <= cut["us"]]
    cut_uid = str(cut["event_uid"]) if cut is not None else None
    if not kept:
        return kept, dropped, cut_uid, ()
    last_kept = max(p.e4624["us"] for p in kept)
    stale = tuple(str(c["event_uid"]) for c in changes if last_kept < c["us"] < window_end_excl_us)
    return kept, dropped, cut_uid, stale


def expected_changes(original: Sequence[Pair], changes: Sequence[Row], lo_us: int) -> tuple[str, ...]:
    """uids of counted clock changes in the search span before the host's first ORIGINAL pair (amended CO-18;
    owner 2026-11-12: original = after the far drop, before the change cut).

    These are a snapshot revert catching up (or a planned resync; the reruns are not synced, owner
    2026-11-12); nothing was measured before them, so they are reported as expected, never as stale. With
    no original pair: none. Same rule as ``changes.classify`` with ``original_bounds``.
    """
    if not original:
        return ()
    first_us = min(p.e4624["us"] for p in original)
    return tuple(str(c["event_uid"]) for c in changes if is_clock_change(c) and lo_us <= c["us"] < first_us)


# ---------------------------------------------------------------- per host

def is_lab_ip_logon(pair: Pair, lab_ips: frozenset[str] | None = None) -> bool:
    """True when the pair's 4624 came from a lab host IP (a hop logon, counted in n_pairs_lab_ip, ATK-02)."""
    ips = lab_ips if lab_ips is not None else lab_ip_set()
    return norm_ip(pair.e4624.get("source_ip")) in ips


def merged_shifts(shifts: Mapping[str, ShiftInfo] | None,
                  extra_shifts: Mapping[str, ShiftInfo] | None) -> dict[str, ShiftInfo]:
    """DB shifts and export shifts in one map keyed by event_uid (export uids start with ``export:``, so the
    two key sets cannot collide)."""
    return {**(shifts or {}), **(extra_shifts or {})}


def pair_host(host: str, events: Sequence[Row], tickets: Sequence[Row], lo_us: int, hi_us: int,
              window_end_excl_us: int, max_delta_us: int,
              shifts: Mapping[str, ShiftInfo] | None = None,
              extra_changes: Sequence[Row] = (),
              extra_shifts: Mapping[str, ShiftInfo] | None = None) -> HostPairs:
    """All pairing steps for one endpoint: evidence, mutual nearest, far drop, change cut (D2).

    ``extra_changes`` / ``extra_shifts``: the CO-19 export hits as change rows and their shifts (SF-1), so a
    step logged only in the exports cuts the pairs, gives ``stale`` and is listed as expected or routine
    exactly like a DB row. ``change_cut`` itself is unchanged.
    """
    all_shifts = merged_shifts(shifts, extra_shifts)
    logons = endpoint_logons(events, lo_us, hi_us, endpoints=(host,))
    guids = set(by_guid(tickets))
    with_cand = sum(1 for a in logons if norm_guid(a.get("logon_guid")) in guids)
    mutual = make_pairs(host, logons, tickets)
    near, far = split_far(mutual, max_delta_us)
    changes = change_events(events, host, all_shifts, extra_changes)
    kept, before, cut, stale = change_cut(near, changes, window_end_excl_us)
    expected = expected_changes(near, changes, lo_us)
    routine = routine_changes(events, host, all_shifts, lo_us, hi_us, extra_changes)
    return HostPairs(host, len(logons), with_cand, tuple(mutual), tuple(far), tuple(before), tuple(kept),
                     cut, stale, expected, routine)


def original_bounds(host_pairs: Mapping[str, HostPairs]) -> dict[str, tuple[int, int]]:
    """host -> (first, last) 4624 instant of its ORIGINAL pairs (before the change cut); hosts without any
    original pair are absent (``no_pairs``). The classification bounds of owner 2026-11-12."""
    out: dict[str, tuple[int, int]] = {}
    for h, hp in host_pairs.items():
        times = [p.e4624["us"] for p in hp.original]
        if times:
            out[h] = (min(times), max(times))
    return out


def pair_trial(events: Sequence[Row], lo_us: int, hi_us: int, window_end_excl_us: int,
               endpoints: Sequence[str] = params.ENDPOINTS,
               edge_s: float = params.DC_EDGE_S,
               max_delta_s: float = params.MAX_PAIR_DELTA_S,
               shifts: Mapping[str, ShiftInfo] | None = None,
               extra_changes: Sequence[Row] = (),
               extra_shifts: Mapping[str, ShiftInfo] | None = None) -> tuple[dict[str, HostPairs], list[Row]]:
    """(host -> HostPairs, dc01 tickets used) for every endpoint of one trial; ``shifts`` resolves the DB
    clock-change rows (D2; missing -> unknown shift -> counts); ``extra_changes`` / ``extra_shifts`` are the
    CO-19 export change rows and their shifts (SF-1, see ``pair_host``)."""
    tickets = dc_tickets(events, lo_us, hi_us, s_to_us(edge_s))
    max_us = s_to_us(max_delta_s)
    return ({h: pair_host(h, events, tickets, lo_us, hi_us, window_end_excl_us, max_us, shifts,
                          extra_changes, extra_shifts)
             for h in endpoints}, tickets)
