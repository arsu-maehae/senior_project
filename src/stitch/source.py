"""Source host and candidate source sessions of a hop (spec 03_stitch ST-40..ST-44, ST-49; decisions 013, 014,
044, 048 items 3, 4, 5, 6, 12).

Three methods find candidate source sessions, each its own ``method`` (Correction I as amended by 013):
``sysmon3_port`` (ST-41: Sysmon 3 port join -> process -> session), ``source_4648`` (ST-42: a 4648 naming the
target -> its SubjectLogonId) and ``cmdline_target`` (ST-43: a process start whose command names the target ->
its session). Account is never a join condition here; the account data T7.4 needs (ST-45 / ST-46) is only
collected.

WHY pure and text-free: the methods take the scan, the T7.2 index and the PRECOMPUTED match facts of
``cmdtext`` (``CmdResult`` per process-start uid, 4648 target texts per uid) as arguments. Nothing here opens a
file or reads command text, so a test can drive every case from hand-built rows, and no output built from these
records can carry a part of a command (spec 2). The one side effect is on the ``SessionIndex``: ``by_4648`` may
create an unknown-open session (``ensure_unknown``) and marks the 4648's session referenced, exactly as T7.2
does for processes (documented on ``by_4648``).

WHY a "subject" and not a ``Hop``: the methods need only (target host, source host, members). A follow-up
group (ST-26) has the same three facts, so a test can run the methods on it to reproduce spec 10.4's
"no artefact" row, while ``build_links`` links hops only (follow-ups produce no link rows, ST-26).

Times: every comparison between the source and the target host uses corrected times (``us``; ST-02,
decision 014); both the corrected and the logged-time delta are kept. A session on the source host is found on
that host's own clock (``us_raw``), as in T7.2.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, NamedTuple, Sequence

from clock_offset.correct import Offsets, clock_unreliable as hosts_unreliable
from gate.classify import ip_kind, norm_ip
from gate.timeutil import delta_ms, seconds_to_us

from .cmdtext import CmdResult, match_4648, target_name_forms
from .hops import Hop, HopSet, RemoteLogon
from .index import TrialIndex
from .params import METHODS, StitchParams
from .processes import (REASON_NO_SESSION_ID, REASON_NO_SYSMON1, REASON_RESOLVED, REASON_SYSTEM, Process,
                        ProcessIndex)
from .scan import ScanResult
from .sessions import SessionIndex, SessionKey, hex_id, logon_id_int, window_open

__all__ = ["Subject", "as_subject", "subject_of", "Evidence", "MethodResult", "SessionData", "LinkRow",
           "SubjectLinks", "source_host_of", "hosts_with_rows", "port_join", "by_4648", "by_cmdline",
           "link_subject", "build_links", "hop_subject", "lab_ip_of", "EVIDENCE_BEFORE_MAX_S", "EVIDENCE_AFTER_MAX_S",
           "METHOD_PORT", "METHOD_4648", "METHOD_CMD", "METHOD_TARGET_ONLY", "REASON_NO_SESSION_ID"]

Row = Mapping[str, Any]

METHOD_PORT, METHOD_4648, METHOD_CMD, METHOD_TARGET_ONLY = METHODS
TARGET_ONLY_UNKNOWN, TARGET_ONLY_NO_LOGS, TARGET_ONLY_NO_EVIDENCE = (
    "source_host_unknown", "source_host_no_logs", "no_evidence_in_range")

# ST-42 fixes the out-of-range bands in the rule text ("within 120 s before or 30 s after"); they are not section
# 5 parameters, so they are module constants and not ``StitchParams`` fields.
EVIDENCE_BEFORE_MAX_S = 120.0
EVIDENCE_AFTER_MAX_S = 30.0

_METHOD_ORDER = {m: i for i, m in enumerate(METHODS)}


# ---------------------------------------------------------------- subject

class Subject(NamedTuple):
    """What the three methods look at: the target host, the source host (None when unknown, ST-40) and the
    member logons. A NamedTuple, so a test may also pass a plain ``(target, source, members)`` tuple
    (``as_subject``)."""
    target_host: str
    source_host: str | None
    members: Sequence[RemoteLogon]


def as_subject(subject: Subject | tuple) -> Subject:
    """A ``Subject`` from a Subject or a plain 3-tuple; ValueError for a subject with no member.

    WHY refuse an empty member list: "first member" and every range are undefined without one.
    """
    s = subject if isinstance(subject, Subject) else Subject(*subject)
    if not s.members:
        raise ValueError("a subject needs at least one member logon")
    return s


def _first(s: Subject) -> RemoteLogon:
    """The first member by corrected time, then uid: every ``time_delta_ms`` is measured from it (spec 3)."""
    return min(s.members, key=lambda m: (m.us, m.uid))


def _first_us(s: Subject) -> int:
    """min member ``us`` (corrected): the left edge of the ST-42 / ST-43 range."""
    return min(m.us for m in s.members)


def _last_us(s: Subject) -> int:
    """max member ``us`` (corrected): the right edge of the ST-42 / ST-43 range."""
    return max(m.us for m in s.members)


def lab_ip_of(host: str | None, lab_host_ips: Mapping[str, str]) -> str | None:
    """The normalised lab IP of a lab host, None for an unknown host (spec 5: one definition, gate params)."""
    if host is None:
        return None
    return norm_ip(lab_host_ips.get(host))


def source_host_of(source_ip: Any, lab_host_ips: Mapping[str, str]) -> str | None:
    """ST-40: the lab host that owns the normalised source IP; None for a blank, unparseable, link-local or
    unknown IP (``target_only`` with ``source_host_unknown``).

    WHY the gate's ``norm_ip`` / ``ip_kind``: the hop's IP is the gate's normalised IP, and the reverse lookup
    must compare the same form (``::ffff:a.b.c.d`` = ``a.b.c.d``). A link-local address is never a lab host's
    (the lab IPs are IPv4), so it is refused before the lookup.
    """
    ip = norm_ip(source_ip)
    if ip is None or ip_kind(ip) in ("blank", "link_local"):
        return None
    owners = {norm_ip(v): str(h) for h, v in sorted(lab_host_ips.items())}
    return owners.get(ip)


def subject_of(target_host: str, source_ip: Any, members: Sequence[RemoteLogon],
               params: StitchParams = StitchParams()) -> Subject:
    """A ``Subject`` for a hop or a follow-up group: source host from the IP (ST-40), members as given."""
    return as_subject(Subject(target_host, source_host_of(source_ip, params.lab_host_ips), tuple(members)))


def hosts_with_rows(scan: ScanResult) -> set[str]:
    """Hosts with at least one row the scan kept or counted: ``in_window``, ``lookback``, ``link_rows`` and the
    hosts of ``removed_by_window`` (048 item 6, ``source_host_no_logs``).

    Note: an in-window row of a kind the scan neither keeps nor counts (e.g. a Sysmon 22) is not seen here, so a
    host whose ONLY rows were such in-window rows would read as "no logs". The scan offers no other host list
    without a new DB read; on the development trials the hosts with no rows at all are the 048 pre-check list.
    """
    out: set[str] = set()
    for rows in (scan.in_window, scan.lookback, scan.link_rows):
        out.update(str(r.get("host")) for r in rows)
    out.update(str(h) for h in scan.removed_by_window)
    return out


# ---------------------------------------------------------------- evidence records

@dataclass
class Evidence:
    """One (method, session) group of source evidence, or one (method, unresolved reason) group with no session.

    ``session_key`` None with ``reason`` set = an unresolved row (ST-41 ``session_unresolved_reason``; the
    internal ``no_session_id`` = a NULL logon ID, see ``by_cmdline``). ``evidence_uids`` = every uid of the
    evidence events (ST-05 copies included), sorted. ``matched_member_uids`` = the members this evidence
    matched (port join: per member; 4648 / command line: every member, because the range covers the whole
    subject). ``time_delta_ms`` / ``time_delta_raw_ms`` = the evidence event nearest in corrected time to the
    first member, minus that member's 4624 (corrected / logged); ``nearest_uid`` names that event.
    ``clock_unreliable`` = any evidence event or matched member flagged (ST-02, event part only; the host part is
    added in ``link_subject``). ``credential_accounts`` (4648 only): the TargetUserName of its naming 4648s, the
    ST-45 data side. ``names_found`` / ``names_event_uids`` (command line only): the target-side names found in
    its matching command events and those events (ST-46 data side). ``match_kinds`` / ``match_vias`` (command
    line only): counts of the matched field kind and of plain / decoded matches.
    """
    method: str
    session_key: SessionKey | None
    reason: str
    evidence_uids: list[str]
    matched_member_uids: list[str]
    matched_member_event_uids: list[str]
    time_delta_ms: int | None
    time_delta_raw_ms: int | None
    nearest_uid: str
    clock_unreliable: int
    credential_accounts: list[str] = field(default_factory=list)
    names_found: list[str] = field(default_factory=list)
    names_event_uids: list[str] = field(default_factory=list)
    match_kinds: dict[str, int] = field(default_factory=dict)
    match_vias: dict[str, int] = field(default_factory=dict)

    @property
    def is_candidate(self) -> bool:
        """A resolved, non-system session (ST-44): only these count in ``candidate_count``."""
        return self.session_key is not None and self.reason == REASON_RESOLVED


@dataclass
class MethodResult:
    """One method's output for one subject.

    ``evidence``: candidate groups sorted by session key, then the unresolved groups sorted by reason.
    ``system_evidence``: events whose session is a system session (ST-44: excluded, counted; for the port join
    they ALSO give a ``system_process`` row). ``before_range`` / ``after_range``: in-window events naming the
    target in [first - 120 s, first - look-back) / (last + after, last + 30 s] (ST-42, 048 item 12).
    ``match_deltas_us`` (port join only): (corrected, logged) Sysmon 3 - matched member 4624 per individual
    (Sysmon 3, member) match, in µs (spec 10.5 measures it per match).
    """
    method: str
    evidence: list[Evidence] = field(default_factory=list)
    system_evidence: int = 0
    before_range: int = 0
    after_range: int = 0
    match_deltas_us: list[tuple[int, int]] = field(default_factory=list)

    @property
    def sessions(self) -> list[SessionKey]:
        """Distinct candidate sessions of this method, sorted (``candidate_count`` = their number)."""
        return sorted({e.session_key for e in self.evidence if e.is_candidate and e.session_key is not None})


class _Acc:
    """Accumulates the events of one evidence group and keeps the one nearest to the first member.

    WHY nearest by |corrected delta|, uid as tie-break: spec 3 ``time_delta_ms`` is "the evidence event nearest
    in corrected time to the hop's first member", and the uid makes the choice deterministic.
    """

    def __init__(self) -> None:
        self.uids: set[str] = set()
        self.members: dict[str, RemoteLogon] = {}
        self.best: tuple[int, str, int, int] | None = None   # (|d|, uid, d, d_raw)
        self.flag = 0
        self.accounts: set[str] = set()
        self.names: set[str] = set()
        self.name_uids: set[str] = set()
        self.kinds: dict[str, int] = {}
        self.vias: dict[str, int] = {}

    def add(self, uids: Iterable[str], key_uid: str, d_us: int, d_raw_us: int, flag: int) -> None:
        """One evidence event: its uids, its deltas to the first member and its ST-02 event flag."""
        self.uids.update(str(u) for u in uids)
        cand = (abs(d_us), key_uid, d_us, d_raw_us)
        if self.best is None or cand[:2] < self.best[:2]:
            self.best = cand
        self.flag = max(self.flag, int(flag or 0))

    def add_members(self, members: Iterable[RemoteLogon]) -> None:
        """Members matched by this group (their own ST-02 flags count for the row, ST-02)."""
        for m in members:
            self.members[m.uid] = m
            self.flag = max(self.flag, int(m.clock_unreliable or 0))

    def build(self, method: str, key: SessionKey | None, reason: str) -> Evidence:
        """The finished ``Evidence``; members in member order (us_raw, uid)."""
        assert self.best is not None
        members = sorted(self.members.values(), key=lambda m: (m.us_raw, m.uid))
        return Evidence(method=method, session_key=key, reason=reason, evidence_uids=sorted(self.uids),
                        matched_member_uids=[m.uid for m in members],
                        matched_member_event_uids=[u for m in members for u in m.event_uids],
                        time_delta_ms=delta_ms(self.best[2], 0), time_delta_raw_ms=delta_ms(self.best[3], 0),
                        nearest_uid=self.best[1], clock_unreliable=self.flag,
                        credential_accounts=sorted(self.accounts, key=lambda a: (a.lower(), a)),
                        names_found=sorted(self.names, key=lambda n: (n.lower(), n)),
                        names_event_uids=sorted(self.name_uids),
                        match_kinds=dict(sorted(self.kinds.items())), match_vias=dict(sorted(self.vias.items())))


def _finish(method: str, groups: Mapping[tuple[SessionKey | None, str], _Acc]) -> list[Evidence]:
    """Candidate groups first (by session key), then unresolved / system groups (by reason)."""
    def order(k: tuple[SessionKey | None, str]) -> tuple:
        key, reason = k
        return (0, key, "") if key is not None else (1, (), reason)
    return [groups[k].build(method, k[0], k[1]) for k in sorted(groups, key=order)]


def _row_uids(row: Row) -> list[str]:
    """Every uid of a scan row (ST-05 copies included)."""
    return [str(u) for u in (row.get("event_uids") or [row.get("event_uid")])]


def _in_range(us: int, first_us: int, last_us: int, params: StitchParams) -> bool:
    """ST-42 / ST-43 range, inclusive: first - ``link_lookback_s`` <= us <= last + ``link_after_s``."""
    return first_us - seconds_to_us(params.link_lookback_s) <= us <= last_us + seconds_to_us(params.link_after_s)


def _band(us: int, first_us: int, last_us: int, params: StitchParams) -> str:
    """``before`` / ``after`` for evidence in the ST-42 out-of-range bands, else "" (inside the range or beyond
    the bands). Before: [first - 120 s, first - look-back); after: (last + after, last + 30 s]."""
    lo = first_us - seconds_to_us(params.link_lookback_s)
    hi = last_us + seconds_to_us(params.link_after_s)
    if first_us - seconds_to_us(EVIDENCE_BEFORE_MAX_S) <= us < lo:
        return "before"
    if hi < us <= last_us + seconds_to_us(EVIDENCE_AFTER_MAX_S):
        return "after"
    return ""


# ---------------------------------------------------------------- ST-41 port join

def _initiated(value: Any) -> bool:
    """Sysmon 3 ``Initiated`` = 1 (the DB stores 0 / 1 integers; text ``true`` is accepted for hand-built rows)."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true")


def _port(value: Any) -> int | None:
    """A port > 0 as int, else None: NULL and 0 never join (ST-41, decisions 005, 015)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        p = int(str(value).strip())
    except ValueError:
        return None
    return p if p > 0 else None


def port_join(subject: Subject | tuple, scan: ScanResult, processes: ProcessIndex,
              params: StitchParams = StitchParams()) -> MethodResult:
    """ST-41 (048 item 5): in-window Sysmon 3 rows LOGGED ON THE SOURCE HOST only, ``initiated`` = 1,
    normalised destination IP = the target's lab IP, ``source_port`` = a member's port (> 0), and
    |Sysmon 3 - that member's 4624| <= ``port_join_s`` on corrected times (inclusive). The join is per member;
    one Sysmon 3 may match several members. There is no source-IP condition (048 item 5).

    Session: ``processes.resolve_session(source host, process_guid)``. ``""`` -> a candidate session;
    ``system_process`` -> a row with no session (not a candidate), also counted in ``system_evidence`` (ST-44);
    ``no_sysmon1_in_window`` -> a row with no session (ST-41: never dropped). ``no_session_id`` (a Sysmon 1 with
    a NULL LogonId; 0 rows on development data) is KEPT as its own internal reason rather than mapped to
    ``no_sysmon1_in_window``: the Sysmon 1 does exist, so that column value would be false; the T7.4 writer
    decides its column spelling.

    A subject with no known source host or a target with no lab IP gives an empty result.
    """
    s = as_subject(subject)
    out = MethodResult(METHOD_PORT)
    target_ip = lab_ip_of(s.target_host, params.lab_host_ips)
    if s.source_host is None or target_ip is None:
        return out
    by_port: dict[int, list[RemoteLogon]] = {}
    for m in s.members:
        p = _port(m.source_port)
        if p is not None:
            by_port.setdefault(p, []).append(m)
    if not by_port:
        return out
    tol = seconds_to_us(params.port_join_s)
    first = _first(s)
    groups: dict[tuple[SessionKey | None, str], _Acc] = {}
    system_uids: set[str] = set()
    for r in scan.in_window:
        if (str(r.get("host")) != s.source_host or r.get("channel") != "Sysmon" or r.get("event_id") != 3
                or not _initiated(r.get("initiated")) or norm_ip(r.get("destination_ip")) != target_ip):
            continue
        p = _port(r.get("source_port"))
        matched = [m for m in by_port.get(p, []) if abs(r["us"] - m.us) <= tol] if p is not None else []
        if not matched:
            continue
        for m in matched:
            out.match_deltas_us.append((r["us"] - m.us, r["us_raw"] - m.us_raw))
        key, reason = processes.resolve_session(s.source_host, r.get("process_guid"))
        if reason == REASON_SYSTEM:
            system_uids.add(str(r.get("event_uid")))
            key = None
        acc = groups.setdefault((key if reason == REASON_RESOLVED else None, reason), _Acc())
        acc.add(_row_uids(r), str(r.get("event_uid")), r["us"] - first.us, r["us_raw"] - first.us_raw,
                r.get("clock_unreliable") or 0)
        acc.add_members(matched)
    out.evidence = _finish(METHOD_PORT, groups)
    out.system_evidence = len(system_uids)
    out.match_deltas_us.sort()
    return out


# ---------------------------------------------------------------- ST-42 source 4648

def _targets_of(row: Row, targets4648: Mapping[str, Sequence[str]]) -> Sequence[str] | None:
    """The 4648 target texts of a link row, looked up by any of its uids (ST-05 copies); None when not read."""
    for u in _row_uids(row):
        if u in targets4648:
            return targets4648[u]
    return None


def by_4648(subject: Subject | tuple, scan: ScanResult, targets4648: Mapping[str, Sequence[str]],
            sessions: SessionIndex, params: StitchParams = StitchParams()) -> MethodResult:
    """ST-42: in-window Security 4648 link rows on the source host whose target texts name the target
    (``cmdtext.match_4648`` with ``cmdtext.target_name_forms(target, lab IP)``, boundary-aware), with corrected
    time in [first - ``link_lookback_s``, last + ``link_after_s``] (inclusive).

    Session = ``subject_logon_id`` (048 item 3): ``sessions.session_at(source host, id, us_raw)``; when no 4624
    qualifies, ``sessions.ensure_unknown(...)``. **Side effect on ``sessions``:** ``ensure_unknown`` may ADD an
    unknown-open session, and the session found is marked referenced (``mark_referenced``), as T7.2 does for
    the session of an in-window process: a 4648 is in-window evidence of that session. A system logon ID is
    not a candidate and is counted in ``system_evidence`` (ST-44). A NULL ID (none on development data, 048)
    gives a row with no session and reason ``no_session_id``.

    Naming 4648s in the ST-42 bands are counted in ``before_range`` / ``after_range`` (any session; in-window
    events only, 048 item 12). Per session the TargetUserName (``account_name``) of its naming in-range 4648s
    is kept as ``credential_accounts`` (ST-45 data side).
    """
    s = as_subject(subject)
    out = MethodResult(METHOD_4648)
    if s.source_host is None:
        return out
    forms = target_name_forms(s.target_host, lab_ip_of(s.target_host, params.lab_host_ips))
    first = _first(s)
    lo_us, hi_us = _first_us(s), _last_us(s)
    groups: dict[tuple[SessionKey | None, str], _Acc] = {}
    for r in scan.link_rows:
        if str(r.get("host")) != s.source_host or r.get("channel") != "Security" or r.get("event_id") != 4648:
            continue
        texts = _targets_of(r, targets4648)
        if not texts or match_4648(texts, forms) is None:
            continue
        if not _in_range(r["us"], lo_us, hi_us, params):
            band = _band(r["us"], lo_us, hi_us, params)
            out.before_range += band == "before"
            out.after_range += band == "after"
            continue
        lid = logon_id_int(r.get("subject_logon_id"))
        if lid is not None and lid in params.system_logon_ids:
            out.system_evidence += 1
            continue
        key, reason = _session_of_4648(sessions, s.source_host, lid, r["us_raw"])
        acc = groups.setdefault((key, reason), _Acc())
        acc.add(_row_uids(r), str(r.get("event_uid")), r["us"] - first.us, r["us_raw"] - first.us_raw,
                r.get("clock_unreliable") or 0)
        acc.add_members(s.members)
        if r.get("account_name"):
            acc.accounts.add(str(r["account_name"]))
    out.evidence = _finish(METHOD_4648, groups)
    return out


def _session_of_4648(sessions: SessionIndex, host: str, lid: int | None,
                     us_raw: int) -> tuple[SessionKey | None, str]:
    """(session key, reason) of a 4648 by its SubjectLogonId on the source host's own clock (048 item 3).

    Mutates ``sessions`` (see ``by_4648``). A NULL ID never forms a session (decision 005): ``no_session_id``.
    """
    if lid is None:
        return None, REASON_NO_SESSION_ID
    found = sessions.session_at(host, lid, us_raw)
    if found is not None:
        sessions.mark_referenced(found.key)
        return found.key, REASON_RESOLVED
    return sessions.ensure_unknown(host, lid, us_raw).key, REASON_RESOLVED


# ---------------------------------------------------------------- ST-43 command line

def _process_hits(p: Process, cmd: Mapping[str, CmdResult], target: str) -> list[tuple[str, str, str]]:
    """(uid, kind, via) for every Sysmon 1 / 4688 uid of the process whose ``CmdResult`` names ``target``."""
    out = []
    for u in p.sysmon1_uids + p.sec4688_uids:
        res = cmd.get(u)
        if res is None:
            continue
        for t, kind, via in res.targets:
            if t == target:
                out.append((u, kind, via))
                break
    return out


def by_cmdline(subject: Subject | tuple, processes: ProcessIndex, cmd: Mapping[str, CmdResult],
               params: StitchParams = StitchParams()) -> MethodResult:
    """ST-43 (048 item 4): processes of the T7.2 ``ProcessIndex`` on the source host (in-window by
    construction, ST-01) whose start (``start_us``, the Sysmon 1 time when collapsed) is in the ST-42 range.
    A process matches when any of its Sysmon 1 / 4688 uids has a ``CmdResult`` naming the target; it counts
    ONCE (a collapsed Sysmon 1 + 4688 is one process, STT-05) and its evidence uids are the matching uids.

    Session = ``Process.session_key`` (047 rule for a 4688-only process). A process with a NULL logon ID has no
    session: a row with no session and the INTERNAL reason ``no_session_id`` (not an ST-41 column value; the
    process does have its start event, so ``no_sysmon1_in_window`` would be false). A system session is not a
    candidate and is counted in ``system_evidence`` (ST-44). Matching processes in the ST-42 bands are counted
    in ``before_range`` / ``after_range``. Per session: ``names_found`` = the target-side names of THIS target
    found in its matching uids (ST-46 data side) and the field kind / via counts of the matches.
    """
    s = as_subject(subject)
    out = MethodResult(METHOD_CMD)
    if s.source_host is None:
        return out
    first = _first(s)
    lo_us, hi_us = _first_us(s), _last_us(s)
    groups: dict[tuple[SessionKey | None, str], _Acc] = {}
    procs = sorted((p for p in processes.processes.values() if p.host == s.source_host),
                   key=lambda p: (p.start_us, p.key))
    for p in procs:
        hits = _process_hits(p, cmd, s.target_host)
        if not hits:
            continue
        if not _in_range(p.start_us, lo_us, hi_us, params):
            band = _band(p.start_us, lo_us, hi_us, params)
            out.before_range += band == "before"
            out.after_range += band == "after"
            continue
        if p.session_logon_id is not None and p.session_logon_id in params.system_logon_ids:
            out.system_evidence += 1
            continue
        key = p.session_key if p.session_logon_id is not None else None
        reason = REASON_RESOLVED if key is not None else REASON_NO_SESSION_ID
        acc = groups.setdefault((key, reason), _Acc())
        uids = [u for u, _, _ in hits]
        acc.add(uids, min(uids), p.start_us - first.us, p.start_us_raw - first.us_raw, p.clock_unreliable)
        acc.add_members(s.members)
        for u, kind, via in hits:
            acc.kinds[kind] = acc.kinds.get(kind, 0) + 1
            acc.vias[via] = acc.vias.get(via, 0) + 1
            found = [n for t, n in cmd[u].names_found if t == s.target_host]
            if found:
                acc.names.update(found)
                acc.name_uids.add(u)
    out.evidence = _finish(METHOD_CMD, groups)
    return out


# ---------------------------------------------------------------- per subject

@dataclass(frozen=True)
class SessionData:
    """The T7.4 data side of one candidate session (plan section 1): its own 4624 through ``window_open``
    (empty when that 4624 is before the window or unknown, ST-01 / decision 039), the 4648 credential accounts
    naming the target (ST-45), and the target-side names found in its command evidence (ST-46)."""
    session_key: SessionKey
    logon_id: int
    logon_id_hex: str
    open_uids: tuple[str, ...]
    account: str | None
    logon_type: int | None
    open_known: bool
    opened_before_window: bool
    credential_accounts: tuple[str, ...]
    names_found: tuple[str, ...]
    names_event_uids: tuple[str, ...]


@dataclass
class LinkRow:
    """One link row of a subject (spec 3 ``links.csv``, the columns T7.3 can know; tiers, ``account_match``,
    ``name_check`` and ranks are T7.4). One row per (session, method), one per (method, unresolved reason), and
    one ``target_only`` row when the subject has no candidate session (ST-49)."""
    method: str
    source_host: str | None
    session_key: SessionKey | None
    source_session_id: int | None
    source_session_id_hex: str
    session_unresolved_reason: str
    session_methods: list[str]
    candidate_count: int
    candidate_count_all: int
    matched_member_count: int
    time_delta_ms: int | None
    time_delta_raw_ms: int | None
    evidence_uids: list[str]
    matched_member_uids: list[str]
    supporting_event_uids: list[str]
    source_session_logon_uids: list[str]
    source_session_account: str | None
    source_session_logon_type: int | None
    credential_accounts: list[str]
    names_found: list[str]
    names_event_uids: list[str]
    match_kinds: dict[str, int]
    match_vias: dict[str, int]
    target_only_reason: str
    clock_unreliable: int


@dataclass
class SubjectLinks:
    """Everything the three methods found for one subject (a hop in ``build_links``).

    ``target_only_reason`` is "" when at least one candidate session exists. ``methods`` keeps each method's
    full result (evidence, counts, port-match deltas) for the check file and spec 10.5. ``sessions`` holds the
    T7.4 data side per candidate session. ``evidence_before_range`` / ``_after_range`` = 4648 + command-line
    out-of-range counts (ST-42). ``system_session_evidence`` = per method, the events excluded as system
    (ST-44). ``host_clock_unreliable`` = the source or target host is none / wide / stale (ST-02 host part).
    """
    target_host: str
    source_host: str | None
    member_uids: list[str]
    rows: list[LinkRow]
    target_only_reason: str
    candidate_counts: dict[str, int]
    candidate_count_all: int
    session_methods: dict[SessionKey, list[str]]
    sessions: dict[SessionKey, SessionData]
    evidence_before_range: int
    evidence_after_range: int
    system_session_evidence: dict[str, int]
    methods: dict[str, MethodResult]
    host_clock_unreliable: int

    @property
    def candidate_sessions(self) -> list[SessionKey]:
        """Distinct candidate sessions over all methods, sorted."""
        return sorted(self.session_methods)


def _host_flag(s: Subject, offsets: Offsets | None) -> int:
    """ST-02 host part: 1 when the source or target host is none / wide / stale (or unknown to the offsets file),
    through the shared ``clock_offset.correct.clock_unreliable``. An unknown source host (None) adds nothing: it
    has no clock to judge. With no offsets there is no flag, as in ``scan.kept_row``."""
    if offsets is None:
        return 0
    hosts = [h for h in (s.source_host, s.target_host) if h]
    return int(hosts_unreliable(*hosts, offsets=offsets))


def _target_only_reason(s: Subject, hosts: set[str]) -> str:
    """ST-40 / ST-49 reason for a subject with no candidate session (048 item 6)."""
    if s.source_host is None:
        return TARGET_ONLY_UNKNOWN
    if s.source_host not in hosts:
        return TARGET_ONLY_NO_LOGS
    return TARGET_ONLY_NO_EVIDENCE


def _session_data(key: SessionKey, sessions: SessionIndex, ev: Sequence[Evidence]) -> SessionData:
    """``SessionData`` of one candidate session; link fields only through ``window_open`` (ST-01, 039)."""
    sess = sessions.sessions[key]
    open_uids, account, logon_type = window_open(sess)
    mine = [e for e in ev if e.session_key == key]
    accounts = sorted({a for e in mine for a in e.credential_accounts}, key=lambda a: (a.lower(), a))
    names = sorted({n for e in mine for n in e.names_found}, key=lambda n: (n.lower(), n))
    return SessionData(session_key=key, logon_id=sess.logon_id, logon_id_hex=sess.logon_id_hex,
                       open_uids=tuple(open_uids), account=account, logon_type=logon_type,
                       open_known=sess.open_known, opened_before_window=sess.opened_before_window,
                       credential_accounts=tuple(accounts), names_found=tuple(names),
                       names_event_uids=tuple(sorted({u for e in mine for u in e.names_event_uids})))


def _evidence_row(e: Evidence, s: Subject, counts: Mapping[str, int], n_all: int,
                  session_methods: Mapping[SessionKey, list[str]], data: Mapping[SessionKey, SessionData],
                  host_flag: int) -> LinkRow:
    """One ``LinkRow`` from an evidence group (resolved or unresolved)."""
    d = data.get(e.session_key) if e.is_candidate and e.session_key is not None else None
    sid = e.session_key[1] if d is not None and e.session_key is not None else None
    supporting = sorted(set(e.evidence_uids) | set(e.matched_member_event_uids))
    return LinkRow(method=e.method, source_host=s.source_host, session_key=e.session_key if d else None,
                   source_session_id=sid, source_session_id_hex="" if sid is None else hex_id(sid),
                   session_unresolved_reason=e.reason,
                   session_methods=list(session_methods.get(e.session_key, [])) if d else [],
                   candidate_count=counts[e.method], candidate_count_all=n_all,
                   matched_member_count=len(e.matched_member_uids), time_delta_ms=e.time_delta_ms,
                   time_delta_raw_ms=e.time_delta_raw_ms, evidence_uids=list(e.evidence_uids),
                   matched_member_uids=list(e.matched_member_uids), supporting_event_uids=supporting,
                   source_session_logon_uids=list(d.open_uids) if d else [],
                   source_session_account=d.account if d else None,
                   source_session_logon_type=d.logon_type if d else None,
                   credential_accounts=list(e.credential_accounts), names_found=list(e.names_found),
                   names_event_uids=list(e.names_event_uids), match_kinds=dict(e.match_kinds),
                   match_vias=dict(e.match_vias), target_only_reason="",
                   clock_unreliable=max(host_flag, e.clock_unreliable))


def _target_only_row(s: Subject, reason: str, host_flag: int) -> LinkRow:
    """ST-49: the one ``target_only`` row (``candidate_count`` 0, no session, no delta). Its supporting uids are
    the member uids (the hop is kept and traceable); ``matched_member_count`` is 0 (no method matched)."""
    members = sorted(s.members, key=lambda m: (m.us_raw, m.uid))
    flag = max([host_flag] + [int(m.clock_unreliable or 0) for m in members])
    return LinkRow(method=METHOD_TARGET_ONLY, source_host=s.source_host, session_key=None, source_session_id=None,
                   source_session_id_hex="", session_unresolved_reason="", session_methods=[], candidate_count=0,
                   candidate_count_all=0, matched_member_count=0, time_delta_ms=None, time_delta_raw_ms=None,
                   evidence_uids=[], matched_member_uids=[],
                   supporting_event_uids=sorted({u for m in members for u in m.event_uids}),
                   source_session_logon_uids=[], source_session_account=None, source_session_logon_type=None,
                   credential_accounts=[], names_found=[], names_event_uids=[], match_kinds={}, match_vias={},
                   target_only_reason=reason, clock_unreliable=flag)


def link_subject(subject: Subject | tuple, scan: ScanResult, processes: ProcessIndex, sessions: SessionIndex,
                 cmd: Mapping[str, CmdResult], targets4648: Mapping[str, Sequence[str]], hosts: set[str],
                 params: StitchParams = StitchParams(), *, offsets: Offsets | None = None) -> SubjectLinks:
    """ST-40..ST-44, ST-49 for one subject: run the three methods, then build the link rows.

    The methods run even when the source host has no logs, so every count is complete; with an unknown source
    host they return nothing. Rows: one per (candidate session, method), one per (method, unresolved reason),
    in METHODS order, and, when no candidate session exists, one ``target_only`` row with its reason
    (``source_host_unknown`` / ``source_host_no_logs`` / ``no_evidence_in_range``). ``candidate_count`` per
    method = its distinct resolved non-system sessions; ``candidate_count_all`` over all methods;
    ``session_methods`` = every method that found the session. ``clock_unreliable`` per row = host part
    (``offsets``; keyword-only, None = no host flag as in ``scan.kept_row``) or any event of the row flagged.
    Mutates ``sessions`` through ``by_4648`` (see there).
    """
    s = as_subject(subject)
    results = {METHOD_PORT: port_join(s, scan, processes, params),
               METHOD_4648: by_4648(s, scan, targets4648, sessions, params),
               METHOD_CMD: by_cmdline(s, processes, cmd, params)}
    counts = {m: len(r.sessions) for m, r in results.items()}
    session_methods: dict[SessionKey, list[str]] = {}
    for m in (METHOD_PORT, METHOD_4648, METHOD_CMD):
        for key in results[m].sessions:
            session_methods.setdefault(key, []).append(m)
    session_methods = {k: sorted(v, key=_METHOD_ORDER.__getitem__) for k, v in sorted(session_methods.items())}
    all_ev = [e for r in results.values() for e in r.evidence]
    data = {k: _session_data(k, sessions, all_ev) for k in session_methods}
    host_flag = _host_flag(s, offsets)
    rows = [_evidence_row(e, s, counts, len(session_methods), session_methods, data, host_flag)
            for m in (METHOD_PORT, METHOD_4648, METHOD_CMD) for e in results[m].evidence]
    reason = "" if session_methods else _target_only_reason(s, hosts)
    if reason:
        rows.append(_target_only_row(s, reason, host_flag))
    return SubjectLinks(
        target_host=s.target_host, source_host=s.source_host,
        member_uids=[u for m in sorted(s.members, key=lambda m: (m.us_raw, m.uid)) for u in m.event_uids],
        rows=rows, target_only_reason=reason, candidate_counts=counts, candidate_count_all=len(session_methods),
        session_methods=session_methods, sessions=data,
        evidence_before_range=results[METHOD_4648].before_range + results[METHOD_CMD].before_range,
        evidence_after_range=results[METHOD_4648].after_range + results[METHOD_CMD].after_range,
        system_session_evidence={m: r.system_evidence for m, r in results.items()},
        methods=results, host_clock_unreliable=host_flag)


def hop_subject(hop: Hop, params: StitchParams = StitchParams()) -> Subject:
    """The subject of a hop: its target, the source host of its IP (ST-40) and its members (not follow-ups)."""
    return subject_of(hop.target_host, hop.source_ip, hop.members, params)


def build_links(hopset: HopSet, scan: ScanResult, index: TrialIndex, cmd: Mapping[str, CmdResult],
                targets4648: Mapping[str, Sequence[str]], params: StitchParams = StitchParams(), *,
                offsets: Offsets | None = None) -> dict[str, SubjectLinks]:
    """``link_subject`` for every HOP of the set, by hop id. Follow-up groups produce no links (ST-26).

    ``index.sessions`` is mutated through ``by_4648`` (unknown-open 4648 sessions; see there). ``offsets`` gives
    the ST-02 host part of ``clock_unreliable`` (keyword-only; None = none).
    """
    hosts = hosts_with_rows(scan)
    return {h.hop_id: link_subject(hop_subject(h, params), scan, index.processes, index.sessions, cmd, targets4648,
                                   hosts, params, offsets=offsets)
            for h in hopset.hops}

