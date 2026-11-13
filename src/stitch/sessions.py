"""ST-10 sessions per host: (host, logon ID, boot epoch, sequence), opened by a 4624, closed by a 4634 / 4647
or the next boot boundary; plus the session-state query of ST-63 (decision 047, accepted 2026-11-13).

WHY pure: the input is the rows of ``scan.ScanResult`` (``in_window`` + ``lookback``); nothing here reads a
file, so a test can build any session history from a handful of dicts. Every comparison on one host uses
the logged time ``us_raw`` (047 item 6): the per-host offset is one constant per trial, so it never changes
the order of two events of one host, and the raw time is what the host's own log order means.

Two views (decision 039; plan section 3): ``window_view`` is what linking and path nodes may use (sessions
opened inside the window, and unknown-open sessions of in-window processes); ``lookback_view`` adds the
sessions known only from pre-window rows and is for identity (ST-63) only.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .params import BOOT_SHUTDOWN_IDS, BOOT_STARTUP_IDS, StitchParams
from .scan import is_boot, is_log_clear, is_logoff, is_logon

__all__ = ["SessionKey", "Session", "SessionIndex", "logon_id_int", "boot_boundaries", "boot_boundary_events",
           "boot_groups", "group_boundaries",
           "epoch_of", "build_sessions", "state_at", "window_open", "CLOSE_KINDS", "STATES"]

# (host, logon_id, epoch, seq). seq = 0 for the first session of (host, id, epoch), 1+ for a re-open after a
# close (047 item 4).
SessionKey = tuple[str, int, int, int]

CLOSE_KINDS: tuple[str, ...] = ("4634", "4647", "boot", "none")
STATES: tuple[str, ...] = ("not_open", "open", "closed", "end_unknown")

_STARTUP, _SHUTDOWN = "startup", "shutdown"


# ---------------------------------------------------------------- logon IDs (D1)

def logon_id_int(value: Any) -> int | None:
    """Logon ID as an integer for joins (D1); None for NULL / empty, which never matches (decision 005).

    WHY accept hex text: the DB stores integers, but a display value (``"0x3e7"``) and its integer (999)
    must name the same session wherever one comes from. A bool is refused: it is never a logon ID.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if not text:
        return None
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


def hex_id(logon_id: int) -> str:
    """Display form ``0x...`` in lower case (D1: hex only for display)."""
    return f"0x{logon_id:x}"


# ---------------------------------------------------------------- boot epochs (047 item 3)

def _boot_kind(row: Mapping) -> str:
    """``startup`` (41, 6005, 6008) or ``shutdown`` (1074, 6006): only events of one kind form one restart."""
    return _STARTUP if row.get("event_id") in BOOT_STARTUP_IDS else _SHUTDOWN


def _row_uids(row: Mapping) -> list[str]:
    """All uids a kept row stands for (ST-05 near-duplicates), so a close stays traceable to every copy."""
    uids = row.get("event_uids") or [row.get("event_uid")]
    return [str(u) for u in uids]


def boot_groups(rows: Iterable[Mapping], boot_group_s: float) -> list[tuple[str, list[Mapping]]]:
    """One host's boot rows cut into restart groups, in time order: (kind, rows) (047 item 3).

    Consecutive boot events of the same kind at most ``boot_group_s`` apart are one group; a change of kind
    or a larger gap starts a new group. WHY groups: one restart logs 41, 6005 and 6008 up to 40.9 s apart
    (shutdown 1074 / 6006 up to 33.4 s), and each event as its own boundary would close a session opened
    during start-up at the next event of the same restart (047 counts).
    """
    gap_us = int(round(boot_group_s * 1_000_000))
    groups: list[tuple[str, list[Mapping]]] = []
    prev: Mapping | None = None
    for row in sorted(rows, key=lambda r: (r["us_raw"], str(r.get("event_uid")))):
        if prev is None or _boot_kind(row) != _boot_kind(prev) or row["us_raw"] - prev["us_raw"] > gap_us:
            groups.append((_boot_kind(row), []))
        groups[-1][1].append(row)
        prev = row
    return groups


def group_boundaries(groups: list[tuple[str, list[Mapping]]]) -> list[tuple[int, list[str]]]:
    """Boundary (us_raw, uids) per group, as amended by the owner on 2026-11-14 (047 item 3, ST-10).

    - A shutdown group gives a boundary at its LAST event (6006 "Event log service stopped"): nothing logged
      after it belongs to the old boot. In a clean restart (shutdown group, then startup group) this is the
      restart's ONE boundary, and the startup group right after adds none.
    - A startup group with no shutdown group right before it (the first group in the DB, or a startup after a
      startup: a dirty boot) gives a boundary at its FIRST event.

    WHY: boot-time 4624s (UMFD-/DWM-, SYSTEM, cached type 11) are logged up to 6.3 s before the first startup
    event; with the boundary at that event they fell in the old epoch and were closed seconds after opening
    (047 amendment evidence). The uids are kept so a boot-closed session's ``close_uids`` name the event.
    """
    out: list[tuple[int, list[str]]] = []
    for i, (kind, rows) in enumerate(groups):
        if kind == _SHUTDOWN:
            out.append((rows[-1]["us_raw"], _row_uids(rows[-1])))
        elif i == 0 or groups[i - 1][0] != _SHUTDOWN:
            out.append((rows[0]["us_raw"], _row_uids(rows[0])))
    return out


def boot_boundary_events(boot_rows: Iterable[Mapping], boot_group_s: float) -> dict[str, list[tuple[int, list[str]]]]:
    """Host -> sorted (us_raw, uids) of the boot boundaries (``boot_groups`` then ``group_boundaries``).

    Look-back and in-window boot rows are both used, so an epoch is the same number whichever view asks.
    """
    by_host: dict[str, list[Mapping]] = {}
    for row in boot_rows:
        if is_boot(row):
            by_host.setdefault(str(row.get("host")), []).append(row)
    return {h: group_boundaries(boot_groups(rows, boot_group_s)) for h, rows in sorted(by_host.items())}


def boot_boundaries(boot_rows: Iterable[Mapping], boot_group_s: float) -> dict[str, list[int]]:
    """Host -> sorted boundary instants (``us_raw``), placed as ``group_boundaries`` says (047 item 3)."""
    return {h: [us for us, _ in evs] for h, evs in boot_boundary_events(boot_rows, boot_group_s).items()}


def epoch_of(host: str, us_raw: int, boundaries: Mapping[str, list[int]]) -> int:
    """Number of the host's boundaries at or before ``us_raw`` (047 item 3).

    WHY "at or before": an event logged at the boundary instant already belongs to the new boot, so a
    session closed by that boundary is ``closed`` at that instant (``state_at``).
    """
    return bisect_right(boundaries.get(host, []), us_raw)


# ---------------------------------------------------------------- sessions

@dataclass
class Session:
    """One logon session on one host (ST-10). ``open_known`` False = a process named this logon ID but no 4624
    for it exists in the rows (047 item 7); then ``open_uids`` is empty, ``open_us_raw`` None and
    ``first_seen_us_raw`` the earliest process instant that named it.

    ``close_kind`` is the first close (``4634`` / ``4647``), else ``boot`` (the next boundary, whose uids are
    in ``close_uids``), else ``none``. ``clear_us_raw`` = the host's 1102 instants after the open (for an
    unknown open: in the session's epoch). ``clock_unreliable`` is the opening event's ST-02 flag (0 for an
    unknown open, which has no opening event). ``epoch_start_us_raw`` is the boundary that starts the
    session's epoch (None for epoch 0), so ``state_at`` can answer ``not_open`` before the epoch begins.

    ``seq`` is 0 for the first session of (host, ID, epoch) and 1+ for a re-open after a close (047 item 4).
    An unknown-open session gets seq -1 when a known session of the same (host, ID, epoch) exists that opens
    after the instant that named it: the unknown one comes first and the keys stay distinct (accepted by the
    coordinator, T7.2 task 3). It occurs in data at boot: SYSTEM (0x3e7) processes logged a few seconds
    before the boot's own SYSTEM 4624 (development: 0-2 per trial, system IDs only).
    """
    host: str
    logon_id: int
    logon_id_hex: str
    epoch: int
    seq: int
    key: SessionKey
    open_uids: list[str] = field(default_factory=list)
    open_us_raw: int | None = None
    open_us: int | None = None
    logon_type: int | None = None
    account: str | None = None
    machine_account: int | None = None
    is_system: bool = False
    open_known: bool = True
    opened_before_window: bool = False
    close_uids: list[str] = field(default_factory=list)
    close_kind: str = "none"
    close_us_raw: int | None = None
    clear_us_raw: list[int] = field(default_factory=list)
    clock_unreliable: int = 0
    first_seen_us_raw: int | None = None
    epoch_start_us_raw: int | None = None


def window_open(session: Session) -> tuple[list[str], str | None, int | None]:
    """(open uids, account, logon type) of the session's opening 4624 when that 4624 is inside the window;
    ([], None, None) when it opened before the window or has no 4624.

    WHY: ST-01 and decision 039 allow pre-window events for identity (ST-63) only; they never feed linking.
    A session opened before the window can still be the session of an in-window process (it keeps its real
    key), but its 4624 must not reach a link row: spec 3 ``links.csv`` fills ``source_session_account`` /
    ``_logon_type`` / ``_logon_uid`` only "if it is inside the window". T7.3 / T7.4 read link fields through
    this function, never from ``open_uids`` / ``account`` / ``logon_type`` directly.
    """
    if session.opened_before_window or not session.open_known:
        return [], None, None
    return list(session.open_uids), session.account, session.logon_type


def state_at(session: Session, us_raw: int) -> str:
    """ST-63 query on the host's own clock: ``not_open``, ``closed``, ``end_unknown`` or ``open``.

    ``not_open``: ``us_raw`` before the session's epoch starts (also for an unknown open; coordinator, T7.2
    task 3), or before a known open. ``closed``: a close at or before ``us_raw``; it wins over a
    log clear, because the close is a logged fact (plan section 3). ``end_unknown``: a Security 1102 in
    (open, ``us_raw``] (unknown open: any 1102 of its epoch at or before ``us_raw``), so a missing logoff may
    have been erased and the session is not counted as open (ST-63). Else ``open``.
    """
    if session.epoch_start_us_raw is not None and us_raw < session.epoch_start_us_raw:
        return "not_open"
    if session.open_known and session.open_us_raw is not None and us_raw < session.open_us_raw:
        return "not_open"
    if session.close_us_raw is not None and session.close_us_raw <= us_raw:
        return "closed"
    lo = session.open_us_raw
    if any((lo is None or c > lo) and c <= us_raw for c in session.clear_us_raw):
        return "end_unknown"
    return "open"


# ---------------------------------------------------------------- the index

_GroupKey = tuple[str, int, int]   # (host, logon_id, epoch)


@dataclass
class SessionIndex:
    """All sessions of a trial, the boot boundaries, the 1102 instants and the build counts (ST-10)."""
    sessions: dict[SessionKey, Session]
    boundaries: dict[str, list[int]]
    clears: dict[str, list[int]]
    params: StitchParams
    boundary_uids: dict[str, list[list[str]]] = field(default_factory=dict)
    logoffs: dict[_GroupKey, list[tuple[int, str, list[str]]]] = field(default_factory=dict)
    build_counts: dict[str, int] = field(default_factory=dict)
    by_group: dict[_GroupKey, list[Session]] = field(default_factory=dict)
    referenced: set[SessionKey] = field(default_factory=set)

    # -- lookups ---------------------------------------------------------

    def epoch(self, host: str, us_raw: int) -> int:
        """Epoch of an instant on this host (047 item 3)."""
        return epoch_of(host, us_raw, self.boundaries)

    def session_at(self, host: str, logon_id: Any, us_raw: int) -> Session | None:
        """The known session of ``logon_id`` on ``host`` whose open is at or before ``us_raw``, in the epoch of
        ``us_raw``; the latest seq when several. None for a NULL ID or when no 4624 qualifies.

        WHY known opens only: an unknown-open session is created on purpose by ``ensure_unknown``, so the
        caller sees the difference between "found its 4624" and "no 4624" (047 item 7).
        """
        lid = logon_id_int(logon_id)
        if lid is None:
            return None
        ep = self.epoch(host, us_raw)
        best: Session | None = None
        for s in self._group(host, lid, ep):
            if s.open_known and s.open_us_raw is not None and s.open_us_raw <= us_raw:
                if best is None or s.seq > best.seq:
                    best = s
        return best

    def ensure_unknown(self, host: str, logon_id: Any, us_raw: int, referenced: bool = True) -> Session:
        """Create (or return) the unknown-open session of ``logon_id`` in the epoch of ``us_raw`` (047 item 7).

        WHY: a process whose session has no 4624 in the rows (opened before the export, or a lost event) must
        still belong to a session, flagged ``open_known`` = False, rather than be dropped. Its close is found
        like a known one, from the earliest instant that named it: the first 4634 / 4647 of that ID in the
        epoch at or after it, else the next boundary. seq is 0, or -1 when a known session of the same
        (host, ID, epoch) exists (it opens later, so the unknown one comes first and the keys stay distinct).
        The session is marked referenced (``mark_referenced``) unless ``referenced`` is False, because only
        in-window processes create unknown-open sessions (plan section 3). Raises ValueError for a NULL ID
        (decision 005: NULL never forms a session).
        """
        lid = logon_id_int(logon_id)
        if lid is None:
            raise ValueError("a NULL logon ID never forms a session (decision 005)")
        ep = self.epoch(host, us_raw)
        group = self._group(host, lid, ep)
        for s in group:
            if not s.open_known:
                if s.first_seen_us_raw is None or us_raw < s.first_seen_us_raw:
                    s.first_seen_us_raw = us_raw
                    self._set_close(s, us_raw)
                if referenced:
                    self.mark_referenced(s.key)
                return s
        seq = -1 if group else 0
        s = Session(host=host, logon_id=lid, logon_id_hex=hex_id(lid), epoch=ep, seq=seq,
                    key=(host, lid, ep, seq), open_known=False, first_seen_us_raw=us_raw,
                    is_system=lid in self.params.system_logon_ids,
                    epoch_start_us_raw=_epoch_start(self.boundaries.get(host, []), ep))
        self._set_close(s, us_raw)
        s.clear_us_raw = self._epoch_clears(host, ep)
        self.add(s)
        if referenced:
            self.mark_referenced(s.key)
        return s

    def mark_referenced(self, key: SessionKey) -> None:
        """Register a session as the session of an in-window process (task 4 calls it for ``session_at`` hits).

        WHY: such a session belongs in ``window_view`` even when its 4624 lies before the window; it keeps its
        real key, and ``window_open`` keeps that pre-window 4624 out of link rows (ST-01, decision 039).
        Raises KeyError for a key that is not in the index.
        """
        if key not in self.sessions:
            raise KeyError(f"no session {key!r}")
        self.referenced.add(key)

    def window_view(self) -> list[Session]:
        """Sessions linking and nodes may use (ST-01, decision 039): opened by an in-window 4624, plus every
        session referenced by an in-window process (``mark_referenced``; unknown-open sessions through
        ``ensure_unknown``), whether it opened before the window or has no 4624. Never a session known only
        from look-back rows. Link fields of these sessions come from ``window_open`` only."""
        return [s for s in self._ordered()
                if (s.open_known and not s.opened_before_window) or s.key in self.referenced]

    def lookback_view(self) -> list[Session]:
        """Every session, pre-window opens included: for identity (ST-63) only, never a node (decision 039)."""
        return self._ordered()

    @property
    def counts(self) -> dict[str, Any]:
        """Counts for the T7.2 check file (plan section 3): recomputed on each call, so unknown-open sessions
        added later by ``ensure_unknown`` are included."""
        ss = list(self.sessions.values())
        known = [s for s in ss if s.open_known]
        per_host: dict[str, int] = {}
        for s in ss:
            per_host[s.host] = per_host.get(s.host, 0) + 1
        return {
            "per_host": dict(sorted(per_host.items())),
            "open_in_window": sum(1 for s in known if not s.opened_before_window),
            "opened_before_window": sum(1 for s in known if s.opened_before_window),
            "open_unknown": len(ss) - len(known),
            "system": sum(1 for s in ss if s.is_system),
            "close_kind": {k: sum(1 for s in ss if s.close_kind == k) for k in CLOSE_KINDS},
            "with_clear_after_open": sum(1 for s in ss if s.clear_us_raw),
            "with_clear_while_open": sum(1 for s in ss if _clear_while_open(s)),
            "multi_close": sum(1 for s in ss if s.close_kind in ("4634", "4647") and len(s.close_uids) > 1),
            "duplicate_open": self.build_counts.get("duplicate_open", 0),
            "reopen_after_close": self.build_counts.get("reopen_after_close", 0),
            "closes_without_open": self.build_counts.get("closes_without_open", 0),
            "boundaries_per_host": {h: len(b) for h, b in sorted(self.boundaries.items())},
            "window_view": len(self.window_view()),
            "referenced_opened_before_window": sum(1 for k in self.referenced
                                                   if self.sessions[k].opened_before_window),
        }

    # -- internals -------------------------------------------------------

    def add(self, s: Session) -> None:
        """Register a session under its key and its (host, ID, epoch) group."""
        self.sessions[s.key] = s
        self.by_group.setdefault((s.host, s.logon_id, s.epoch), []).append(s)

    def _group(self, host: str, lid: int, ep: int) -> list[Session]:
        """Sessions of one (host, ID, epoch), any seq (indexed: task 4 asks once per process)."""
        return list(self.by_group.get((host, lid, ep), []))

    def _ordered(self) -> list[Session]:
        """Deterministic order: host, open (or first-seen) instant, logon ID, seq."""
        def key(s: Session) -> tuple:
            t = s.open_us_raw if s.open_us_raw is not None else s.first_seen_us_raw
            return s.host, t if t is not None else 0, s.logon_id, s.seq
        return sorted(self.sessions.values(), key=key)

    def _epoch_clears(self, host: str, ep: int) -> list[int]:
        """The host's 1102 instants inside one epoch (for an unknown open, which has no open instant)."""
        return [c for c in self.clears.get(host, []) if self.epoch(host, c) == ep]

    def _set_close(self, s: Session, from_us_raw: int) -> None:
        """First logoff of the session's (host, ID, epoch) at or after ``from_us_raw``, else the next boundary."""
        s.close_uids, s.close_kind, s.close_us_raw = [], "none", None
        for us, kind, uids in self.logoffs.get((s.host, s.logon_id, s.epoch), []):
            if us >= from_us_raw:
                s.close_uids, s.close_kind, s.close_us_raw = list(uids), kind, us
                return
        _close_by_boundary(s, self.boundaries.get(s.host, []), self.boundary_uids.get(s.host, []))


def _clear_while_open(s: Session) -> bool:
    """A 1102 after the open and before the close (or with no close): the case ST-63 reads as ``end_unknown``."""
    lo, hi = s.open_us_raw, s.close_us_raw
    return any((lo is None or c > lo) and (hi is None or c < hi) for c in s.clear_us_raw)


def _epoch_start(bounds: list[int], epoch: int) -> int | None:
    """The boundary that starts ``epoch`` (``bounds[epoch - 1]``); None for epoch 0 (no earlier boot)."""
    return bounds[epoch - 1] if 0 < epoch <= len(bounds) else None


def _close_by_boundary(s: Session, bounds: list[int], bound_uids: list[list[str]]) -> None:
    """ST-10: with no logoff, the next boundary closes the session (``boot``); with none, ``none``.

    The boundary that ends epoch e is the (e+1)-th boundary, ``bounds[e]``, always after any instant of e.
    """
    if s.epoch < len(bounds):
        s.close_kind, s.close_us_raw = "boot", bounds[s.epoch]
        s.close_uids = list(bound_uids[s.epoch]) if s.epoch < len(bound_uids) else []


# ---------------------------------------------------------------- build

def _event_order(row: Mapping) -> tuple[int, int, str]:
    """Same-host order: us_raw, then opens before closes at one instant ("at or after the open", ST-10), uid."""
    return row["us_raw"], 0 if is_logon(row) else 1, str(row.get("event_uid"))


def _open_session(row: Mapping, host: str, lid: int, ep: int, seq: int, params: StitchParams) -> Session:
    """A session from its first 4624; account, type and the ST-02 flag come from that event."""
    return Session(host=host, logon_id=lid, logon_id_hex=hex_id(lid), epoch=ep, seq=seq, key=(host, lid, ep, seq),
                   open_uids=_row_uids(row), open_us_raw=row["us_raw"], open_us=row.get("us"),
                   logon_type=row.get("logon_type"), account=row.get("account_name"),
                   machine_account=row.get("machine_account"), is_system=lid in params.system_logon_ids,
                   open_known=True, opened_before_window=not bool(row.get("in_window")),
                   clock_unreliable=int(row.get("clock_unreliable") or 0))


def _sweep_group(rows: list[Mapping], host: str, lid: int, ep: int, params: StitchParams,
                 counts: dict[str, int]) -> list[Session]:
    """One (host, ID, epoch) in time order (047 items 4, 5).

    A 4624 while the current session is open joins its ``open_uids`` (``duplicate_open``); a 4624 after it
    closed starts seq + 1 (``reopen_after_close``). The first logoff closes the session; later logoffs before
    the next re-open are kept in ``close_uids``. A logoff with no session yet is ``closes_without_open``.
    """
    out: list[Session] = []
    cur: Session | None = None
    for row in sorted(rows, key=_event_order):
        if is_logon(row):
            if cur is not None and cur.close_us_raw is None:
                cur.open_uids.extend(_row_uids(row))
                counts["duplicate_open"] += 1
                continue
            if cur is not None:
                counts["reopen_after_close"] += 1
            cur = _open_session(row, host, lid, ep, cur.seq + 1 if cur is not None else 0, params)
            out.append(cur)
        elif cur is None:
            counts["closes_without_open"] += 1
        elif cur.close_us_raw is None:
            cur.close_kind, cur.close_us_raw, cur.close_uids = str(row["event_id"]), row["us_raw"], _row_uids(row)
        else:
            cur.close_uids.extend(_row_uids(row))
    return out


def build_sessions(rows: Iterable[Mapping], params: StitchParams = StitchParams()) -> SessionIndex:
    """ST-10 on the scan rows (``in_window`` + ``lookback``): boundaries, then sessions per (host, ID, epoch).

    A 4624 or logoff whose ``target_logon_id`` is NULL is ignored (decision 005); ``target_linked_logon_id``
    is never read (it is never a key). Sessions without a logoff close at the next boundary, else ``none``.
    Unknown-open sessions are added later through ``SessionIndex.ensure_unknown``.
    """
    rows = list(rows)
    events = boot_boundary_events((r for r in rows if is_boot(r)), params.boot_group_s)
    boundaries = {h: [us for us, _ in ev] for h, ev in events.items()}
    clears: dict[str, list[int]] = {}
    for r in rows:
        if is_log_clear(r):
            clears.setdefault(str(r.get("host")), []).append(r["us_raw"])
    clears = {h: sorted(v) for h, v in sorted(clears.items())}
    groups: dict[_GroupKey, list[Mapping]] = {}
    for r in rows:
        if is_logon(r) or is_logoff(r):
            lid = logon_id_int(r.get("target_logon_id"))
            if lid is not None:
                host = str(r.get("host"))
                groups.setdefault((host, lid, epoch_of(host, r["us_raw"], boundaries)), []).append(r)
    index = SessionIndex(sessions={}, boundaries=boundaries, clears=clears, params=params,
                         boundary_uids={h: [u for _, u in ev] for h, ev in events.items()},
                         build_counts={"duplicate_open": 0, "reopen_after_close": 0, "closes_without_open": 0})
    for gk in sorted(groups):
        index.logoffs[gk] = [(r["us_raw"], str(r["event_id"]), _row_uids(r))
                             for r in sorted(groups[gk], key=_event_order) if is_logoff(r)]
        for s in _sweep_group(groups[gk], *gk, params, index.build_counts):
            if s.close_us_raw is None:
                _close_by_boundary(s, boundaries.get(s.host, []), index.boundary_uids.get(s.host, []))
            s.clear_us_raw = [c for c in clears.get(s.host, []) if s.open_us_raw is not None and c > s.open_us_raw]
            s.epoch_start_us_raw = _epoch_start(boundaries.get(s.host, []), s.epoch)
            index.add(s)
    return index
