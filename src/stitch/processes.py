"""ST-11 process trees: Sysmon 1 / 4688 collapse, the session of each process (047 items 1, 2, 7), the guid tree,
Sysmon 3 / 10 / 11 attachment, and the data side of ST-41 (``resolve_session``) and ST-71 (``events_of_session``).

WHY pure: the input is the in-window rows of ``scan.ScanResult`` and a ``SessionIndex``; nothing here reads a file.
Processes come from IN-WINDOW Sysmon 1 and 4688 only (ST-01; owner Q13b): a pre-window process start is never a
process, so an in-window Sysmon 3 of it stays unattached (``no_sysmon1_in_window``). Same-host comparisons use
``us_raw`` (047 item 6). The ``SessionIndex`` is updated in place (``mark_referenced`` / ``ensure_unknown``),
because the sessions of in-window processes belong in its ``window_view`` (coordinator, T7.2 task 3).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .params import StitchParams
from .scan import is_sec4688, is_sysmon1, is_sysmon_attached
from .sessions import SessionIndex, SessionKey, logon_id_int

__all__ = ["ProcessKey", "Process", "ProcessIndex", "Pair", "norm_guid", "collapse", "collapse_with_stats",
           "session_logon_id_of", "build_processes", "ATTACH_KINDS", "REASONS"]

# (host, lower-case process_guid) for a process with a Sysmon 1; (host, "4688:" + uid) for a 4688 alone.
ProcessKey = tuple[str, str]
Row = Mapping[str, Any]
Pair = tuple[Row | None, Row | None]

ATTACH_KINDS: dict[int, str] = {3: "sysmon3", 10: "sysmon10", 11: "sysmon11"}
# ST-41 ``session_unresolved_reason`` values ("" = resolved).
REASON_RESOLVED, REASON_NO_SYSMON1, REASON_SYSTEM = "", "no_sysmon1_in_window", "system_process"
# Not an ST-41 value: a Sysmon 1 with a NULL LogonId (0 rows on development data, 047 P1). Reported, never guessed.
REASON_NO_SESSION_ID = "no_session_id"
REASONS: tuple[str, ...] = (REASON_RESOLVED, REASON_NO_SYSMON1, REASON_SYSTEM, REASON_NO_SESSION_ID)


def norm_guid(value: Any) -> str:
    """Guid compared case-insensitively and without braces (Sysmon writes ``{...}`` in varying case)."""
    return str(value or "").strip().strip("{}").lower()


def _uids(row: Row) -> list[str]:
    """Every uid a kept row stands for (ST-05 near-duplicates)."""
    return [str(u) for u in (row.get("event_uids") or [row.get("event_uid")])]


# ---------------------------------------------------------------- collapse (ST-11)

def _candidates(sysmon1_rows: list[Row], sec4688_rows: list[Row], collapse_us: int) -> list[tuple[int, str, str, int, int]]:
    """Every (|Δ|, sysmon uid, 4688 uid, i, j) with the same host and non-NULL ``process_id`` and |Δ| <= limit."""
    by_pid: dict[tuple[str, int], list[int]] = {}
    for j, e in enumerate(sec4688_rows):
        if e.get("process_id") is not None:
            by_pid.setdefault((str(e.get("host")), e["process_id"]), []).append(j)
    out = []
    for i, s in enumerate(sysmon1_rows):
        if s.get("process_id") is None:
            continue
        for j in by_pid.get((str(s.get("host")), s["process_id"]), []):
            d = abs(s["us_raw"] - sec4688_rows[j]["us_raw"])
            if d <= collapse_us:
                out.append((d, str(s.get("event_uid")), str(sec4688_rows[j].get("event_uid")), i, j))
    return out


def collapse_with_stats(sysmon1_rows: Iterable[Row], sec4688_rows: Iterable[Row],
                        collapse_s: float) -> tuple[list[Pair], dict[str, int]]:
    """ST-11 pairing plus its counts.

    A Sysmon 1 and a 4688 are one process when they share host and ``process_id`` (NULL never pairs, decision
    005) and |Δ us_raw| <= ``collapse_s`` (inclusive). Pairing is 1:1 and global: the smallest |Δ| first, ties
    by (Sysmon uid, 4688 uid), so the result does not depend on input order. Unpaired rows stand alone.
    Counts: ``ambiguous_sysmon1`` / ``ambiguous_4688`` = rows with two or more candidates; ``ambiguous_pairs``
    = their sum. Pairs are returned in time order (Sysmon 1 time when present), then uid.
    """
    s_rows, e_rows = list(sysmon1_rows), list(sec4688_rows)
    cands = _candidates(s_rows, e_rows, int(round(collapse_s * 1_000_000)))
    n_s: dict[int, int] = {}
    n_e: dict[int, int] = {}
    for _, _, _, i, j in cands:
        n_s[i] = n_s.get(i, 0) + 1
        n_e[j] = n_e.get(j, 0) + 1
    used_s: set[int] = set()
    used_e: set[int] = set()
    pairs: list[Pair] = []
    for _, _, _, i, j in sorted(cands):
        if i not in used_s and j not in used_e:
            used_s.add(i)
            used_e.add(j)
            pairs.append((s_rows[i], e_rows[j]))
    pairs += [(s, None) for i, s in enumerate(s_rows) if i not in used_s]
    pairs += [(None, e) for j, e in enumerate(e_rows) if j not in used_e]
    pairs.sort(key=_pair_order)
    amb_s = sum(1 for v in n_s.values() if v >= 2)
    amb_e = sum(1 for v in n_e.values() if v >= 2)
    return pairs, {"ambiguous_sysmon1": amb_s, "ambiguous_4688": amb_e, "ambiguous_pairs": amb_s + amb_e}


def collapse(sysmon1_rows: Iterable[Row], sec4688_rows: Iterable[Row], collapse_s: float) -> list[Pair]:
    """ST-11 pairs only (see ``collapse_with_stats``)."""
    return collapse_with_stats(sysmon1_rows, sec4688_rows, collapse_s)[0]


def _pair_order(pair: Pair) -> tuple[int, str]:
    """Time order of a pair: its Sysmon 1 if present (the process start Sysmon logged), else its 4688."""
    row = pair[0] if pair[0] is not None else pair[1]
    assert row is not None
    return row["us_raw"], str(row.get("event_uid"))


# ---------------------------------------------------------------- session of a process (047)

def _sec4688_logon_id(row: Row) -> int | None:
    """047 item 2: a 4688's ``target_logon_id`` when present and non-zero, else its ``subject_logon_id``.

    WHY: the subject of these 4688s is a system ID (0x3e7) while Sysmon's LogonId equals the target ID in
    every pair (047 P2); the plain subject reading would put user processes in a SYSTEM session.
    """
    target = logon_id_int(row.get("target_logon_id"))
    if target is not None and target != 0:
        return target
    return logon_id_int(row.get("subject_logon_id"))


def session_logon_id_of(sysmon1_row: Row | None, sec4688_row: Row | None) -> int | None:
    """Logon ID of a process (047 items 1, 2): the Sysmon 1 ``session_id`` (the Sysmon LogonId, P1) whenever a
    Sysmon 1 exists, even when NULL (decision 005: no guess); a 4688 alone by ``_sec4688_logon_id``."""
    if sysmon1_row is not None:
        return logon_id_int(sysmon1_row.get("session_id"))
    if sec4688_row is not None:
        return _sec4688_logon_id(sec4688_row)
    return None


def session_rule_disagrees(sysmon1_row: Row | None, sec4688_row: Row | None) -> bool:
    """True for a pair whose 4688 rule names another logon ID than the Sysmon 1 (047 kill criterion item 2)."""
    if sysmon1_row is None or sec4688_row is None:
        return False
    a, b = logon_id_int(sysmon1_row.get("session_id")), _sec4688_logon_id(sec4688_row)
    return a is not None and b is not None and a != b


# ---------------------------------------------------------------- processes

@dataclass
class Process:
    """One process start (ST-11): a Sysmon 1, a 4688, or a collapsed pair of both.

    ``start_us_raw`` / ``start_us`` / ``image`` / guids come from the Sysmon 1 when there is one (it carries the
    guid tree); ``clock_unreliable`` is 1 when either row is flagged (ST-02). ``parent_resolved`` = the parent
    guid has an in-window Sysmon 1 on the same host (always False for a 4688 alone: it has no guid).
    ``event_uids_by_kind`` holds the uids of the attached Sysmon 3 / 10 / 11 events.
    """
    host: str
    key: ProcessKey
    process_guid: str | None
    parent_process_guid: str | None
    process_id: int | None
    session_logon_id: int | None
    session_key: SessionKey | None
    sysmon1_uids: list[str]
    sec4688_uids: list[str]
    start_us_raw: int
    start_us: int
    image: str | None
    parent_image: str | None
    parent_resolved: bool = False
    event_uids_by_kind: dict[str, list[str]] = field(
        default_factory=lambda: {k: [] for k in ATTACH_KINDS.values()})
    clock_unreliable: int = 0


def _process_key(s: Row | None, e: Row | None) -> ProcessKey:
    """Guid key for a process with a Sysmon 1; ``4688:<uid>`` for a 4688 alone. A Sysmon 1 without a guid (none
    on development data) gets ``sysmon1:<uid>`` so it can never merge with another process."""
    if s is not None:
        g = norm_guid(s.get("process_guid"))
        return str(s.get("host")), g if g else f"sysmon1:{s.get('event_uid')}"
    assert e is not None
    return str(e.get("host")), f"4688:{e.get('event_uid')}"


def _make_process(s: Row | None, e: Row | None) -> Process:
    """A Process from one collapse pair (session fields filled later by ``_attach_session``)."""
    main = s if s is not None else e
    assert main is not None
    flags = [int(r.get("clock_unreliable") or 0) for r in (s, e) if r is not None]
    return Process(host=str(main.get("host")), key=_process_key(s, e),
                   process_guid=norm_guid(s.get("process_guid")) or None if s is not None else None,
                   parent_process_guid=norm_guid(s.get("parent_process_guid")) or None if s is not None else None,
                   process_id=main.get("process_id"), session_logon_id=session_logon_id_of(s, e), session_key=None,
                   sysmon1_uids=_uids(s) if s is not None else [], sec4688_uids=_uids(e) if e is not None else [],
                   start_us_raw=main["us_raw"], start_us=main["us"],
                   image=main.get("image"), parent_image=main.get("parent_image"), clock_unreliable=max(flags))


def _attach_session(p: Process, sessions: SessionIndex) -> None:
    """ST-10 / 047 item 7: the session open at the process start, else an unknown-open session; NULL -> None.

    Both paths mark the session referenced, so it is in ``window_view`` even if its 4624 is pre-window; its
    link fields still come from ``sessions.window_open`` only (ST-01, decision 039).
    """
    if p.session_logon_id is None:
        return
    found = sessions.session_at(p.host, p.session_logon_id, p.start_us_raw)
    if found is not None:
        sessions.mark_referenced(found.key)
        p.session_key = found.key
    else:
        p.session_key = sessions.ensure_unknown(p.host, p.session_logon_id, p.start_us_raw).key


@dataclass
class ProcessIndex:
    """All in-window processes of a trial, their tree, attachments and counts (ST-11)."""
    processes: dict[ProcessKey, Process]
    system_logon_ids: frozenset[int]
    by_parent: dict[ProcessKey, list[ProcessKey]] = field(default_factory=dict)
    by_session: dict[SessionKey, list[ProcessKey]] = field(default_factory=dict)
    event_us_raw: dict[str, int] = field(default_factory=dict)
    build_counts: dict[str, Any] = field(default_factory=dict)

    def children(self, key: ProcessKey) -> list[ProcessKey]:
        """Processes whose parent guid is this process (same host), in key order."""
        return list(self.by_parent.get(key, []))

    def parent(self, key: ProcessKey) -> ProcessKey | None:
        """The parent process key when the parent has an in-window Sysmon 1 on the same host, else None."""
        p = self.processes.get(key)
        if p is None or not p.parent_process_guid:
            return None
        pk = (p.host, p.parent_process_guid)
        return pk if pk in self.processes and pk != key else None

    def ancestors(self, key: ProcessKey) -> list[ProcessKey]:
        """Parent, grandparent, ... nearest first. WHY the guard: a guid cycle (bad data) must still terminate."""
        out: list[ProcessKey] = []
        seen = {key}
        cur = self.parent(key)
        while cur is not None and cur not in seen:
            out.append(cur)
            seen.add(cur)
            cur = self.parent(cur)
        return out

    def resolve_session(self, host: str, process_guid: Any) -> tuple[SessionKey | None, str]:
        """ST-41 last sentence: the session of the process with this guid, and ``session_unresolved_reason``.

        ``no_sysmon1_in_window`` when the guid has no in-window Sysmon 1 on the host; ``system_process`` when its
        logon ID is a system ID (the key is still returned; ST-44 excludes it later); ``no_session_id`` when the
        Sysmon 1 has a NULL LogonId: an internal reason, not an ST-41 column value, accepted by the coordinator
        (T7.2 task 4; 0 rows on development data, 047 P1); T7.3 maps it to the link row. Else "".
        """
        g = norm_guid(process_guid)
        p = self.processes.get((str(host), g)) if g else None
        if p is None or not p.sysmon1_uids:
            return None, REASON_NO_SYSMON1
        if p.session_logon_id is None:
            return None, REASON_NO_SESSION_ID
        if p.session_logon_id in self.system_logon_ids:
            return p.session_key, REASON_SYSTEM
        return p.session_key, REASON_RESOLVED

    def events_of_session(self, session_key: SessionKey, until_us_raw: int | None = None) -> list[str]:
        """ST-71 data side: uids of the session's processes (Sysmon 1, 4688) and their attached events, logged
        at or before ``until_us_raw`` when given; sorted and unique. In-window events only (ST-01)."""
        out: set[str] = set()
        for pk in self.by_session.get(session_key, []):
            p = self.processes[pk]
            uids = p.sysmon1_uids + p.sec4688_uids + [u for v in p.event_uids_by_kind.values() for u in v]
            out.update(u for u in uids if until_us_raw is None or self.event_us_raw[u] <= until_us_raw)
        return sorted(out)

    @property
    def counts(self) -> dict[str, Any]:
        """Counts for the T7.2 check file (plan section 3 ``processes`` and ``attached``)."""
        ps = list(self.processes.values())
        with_s1 = [p for p in ps if p.sysmon1_uids]
        c = dict(self.build_counts)
        c.update({
            "processes": len(ps),
            "parent_resolved": sum(1 for p in with_s1 if p.parent_resolved),
            "parent_unresolved": sum(1 for p in with_s1 if not p.parent_resolved),
            "parent_not_applicable": len(ps) - len(with_s1),
            "null_session": sum(1 for p in ps if p.session_logon_id is None),
        })
        return c


def _kind_rows(rows: Iterable[Row]) -> tuple[list[Row], list[Row], list[Row]]:
    """In-window Sysmon 1, 4688 and Sysmon 3 / 10 / 11 rows (a pre-window row is never a process: ST-01, Q13b)."""
    s1, e, att = [], [], []
    for r in rows:
        if not r.get("in_window"):
            continue
        if is_sysmon1(r):
            s1.append(r)
        elif is_sec4688(r):
            e.append(r)
        elif is_sysmon_attached(r):
            att.append(r)
    return s1, e, att


def _add_process(index: ProcessIndex, p: Process, counts: dict[str, Any]) -> None:
    """Register a process; a second Sysmon 1 with the same (host, guid) joins the first (counted)."""
    old = index.processes.get(p.key)
    if old is None:
        index.processes[p.key] = p
        return
    counts["duplicate_guid"] += 1
    old.sysmon1_uids = sorted(set(old.sysmon1_uids) | set(p.sysmon1_uids))
    old.sec4688_uids = sorted(set(old.sec4688_uids) | set(p.sec4688_uids))


def _attach_events(index: ProcessIndex, att_rows: list[Row]) -> dict[str, dict[str, int]]:
    """ST-11: a Sysmon 3 / 10 / 11 belongs to the process with its guid when that has an in-window Sysmon 1;
    otherwise it stays unattached and is counted. Counts per kind use the ST-41 reasons."""
    out = {k: {REASON_NO_SYSMON1: 0, "resolved": 0, REASON_SYSTEM: 0, REASON_NO_SESSION_ID: 0}
           for k in ATTACH_KINDS.values()}
    for r in sorted(att_rows, key=lambda x: (x["us_raw"], str(x.get("event_uid")))):
        kind = ATTACH_KINDS[r["event_id"]]
        for u in _uids(r):
            index.event_us_raw[u] = r["us_raw"]
        _, reason = index.resolve_session(str(r.get("host")), r.get("process_guid"))
        out[kind]["resolved" if reason == REASON_RESOLVED else reason] += 1
        if reason != REASON_NO_SYSMON1:
            p = index.processes[(str(r.get("host")), norm_guid(r.get("process_guid")))]
            p.event_uids_by_kind[kind].extend(_uids(r))
    return out


def build_processes(in_window_rows: Iterable[Row], sessions: SessionIndex,
                    params: StitchParams = StitchParams()) -> ProcessIndex:
    """ST-11 on the in-window rows: collapse Sysmon 1 / 4688, give each process its session (047), build the guid
    tree, attach Sysmon 3 / 10 / 11. ``sessions`` gains referenced and unknown-open sessions (see module doc)."""
    s1, e, att = _kind_rows(in_window_rows)
    pairs, stats = collapse_with_stats(s1, e, params.process_collapse_s)
    index = ProcessIndex(processes={}, system_logon_ids=frozenset(params.system_logon_ids))
    counts: dict[str, Any] = {
        "sysmon1": len(s1), "sec4688": len(e),
        "collapsed_pairs": sum(1 for a, b in pairs if a is not None and b is not None),
        "sysmon1_only": sum(1 for a, b in pairs if b is None), "sec4688_only": sum(1 for a, b in pairs if a is None),
        "session_rule_disagreements": sum(1 for a, b in pairs if session_rule_disagrees(a, b)),
        "duplicate_guid": 0, **stats}
    for a, b in pairs:
        for r in (a, b):
            if r is not None:
                for u in _uids(r):
                    index.event_us_raw[u] = r["us_raw"]
        _add_process(index, _make_process(a, b), counts)
    for p in index.processes.values():
        _attach_session(p, sessions)
        if p.session_key is not None:
            index.by_session.setdefault(p.session_key, []).append(p.key)
    for p in index.processes.values():
        pk = index.parent(p.key)
        p.parent_resolved = pk is not None
        if pk is not None:
            index.by_parent.setdefault(pk, []).append(p.key)
    for v in index.by_parent.values():
        v.sort()
    counts["attached"] = _attach_events(index, att)
    index.build_counts = counts
    return index
