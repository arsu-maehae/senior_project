"""T7.3 assembly: hops, artefacts, candidate source sessions, confirmations, data limits and counts of one trial
(plan T7.3 sections 1, 3 and task 5; spec 03_stitch ST-01..ST-47; decision 048).

WHY one assembly function: the T7.3 steps depend on each other in a fixed order (index -> hops -> artefacts ->
command facts -> links -> confirmations), and the command facts must be read on the SAME read-only connection,
inside the SAME hash bracket, as the scan (048 item 1). ``assemble`` is therefore the ``extra`` callback of
``inputs.load_link_inputs``; it receives the open connection and the scan and returns a ``LinkIndex``. The only
code here that touches the connection is the two ``cmdtext`` readers, which return facts and never text.

Everything is driven by ``StitchParams``: a sensitivity run (plan section 5, C13) passes a
``dataclasses.replace`` copy to ``run_links`` and gets a complete, independent ``LinkIndex``.

The data-limit and count functions are pure (scan, hop set, links in; plain values out), so a test can feed them
hand-built objects. Nothing in this module reads an answer key or any test trial: ``run_links`` refuses every
trial outside the development allowlist before any file is opened (``inputs.check_allowed``, decision 046).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from gate.classify import norm_ip
from gate.timeutil import delta_ms, seconds_to_us

from .artefacts import KIND_BURST, KIND_INSTALL, ArtefactSet, build_artefacts
from .cmdtext import CmdResult, TargetForms, match_4648, read_4648_targets, read_command_results, target_name_forms
from .confirm import CONFIRM_KERBEROS, CONFIRM_SERVICE, confirm_of
from .hops import Hop, HopSet, build_hops
from .index import TrialIndex, build_index
from .inputs import CheckedInputs, GateRows, TrialPaths, check_allowed, load_link_inputs, read_gate_rows, trial_paths
from .params import METHODS, TARGET_ONLY_REASONS, StitchParams
from .processes import ProcessIndex
from .scan import ScanResult
from .sessions import SessionIndex
from .source import (METHOD_4648, METHOD_CMD, METHOD_PORT, METHOD_TARGET_ONLY, SubjectLinks, _initiated,
                     _targets_of, build_links, lab_ip_of)

__all__ = ["LinkIndex", "HostLimit", "assemble", "run_links", "run_links_checked", "command_probes",
           "names_by_target", "process_uids_by_host", "link_4648_uids", "last_security_events", "data_limits",
           "link_counts", "EVIDENCE_METHODS", "REASON_EVIDENCE_AFTER", "REASON_UNKNOWN_SESSION_PROCESS",
           "LIMIT_REASONS", "unknown_session_processes_after"]

Row = Mapping[str, Any]

# The three source-evidence methods, in METHODS order (data limits count per method; ``target_only`` is no
# evidence). WHY derived from METHODS: one spelling for every method name (params).
EVIDENCE_METHODS: tuple[str, ...] = tuple(m for m in METHODS if m != METHOD_TARGET_ONLY)
# Artefact kinds whose ``names`` are target-side file / service names (ST-46 data side): the share burst's ``.exe``
# names (5145) and the install's service name and binary file name (4697 / 7045).
NAMED_ARTEFACT_KINDS: tuple[str, ...] = (KIND_BURST, KIND_INSTALL)
# Why a host is labelled ``data_limitation`` = 1 (048 item 13; owner instruction 2026-11-14). WHY names and not a
# bare 0 / 1: the owner must see which condition fired, because the two have different causes (evidence on other
# hosts vs. a process on the host itself whose logon is missing from its log).
REASON_EVIDENCE_AFTER = "evidence_after"
REASON_UNKNOWN_SESSION_PROCESS = "unknown_session_process"
LIMIT_REASONS: tuple[str, ...] = (REASON_EVIDENCE_AFTER, REASON_UNKNOWN_SESSION_PROCESS)


# ---------------------------------------------------------------- result

@dataclass(frozen=True)
class HostLimit:
    """048 item 13 (as amended) for one host with in-window Security rows in the scan.

    ``last_*``: its last kept in-window Security event (by logged time, then uid) and that event's corrected time.
    ``evidence_after`` / ``evidence_after_uids``: per method, source evidence on OTHER hosts that names this host
    and lies after that event (corrected time, inside the window): Sysmon 3 rows, 4648 rows, processes.
    ``unknown_session_processes_after`` / ``unknown_session_process_uids`` (owner instruction 2026-11-14): index
    processes ON this host that start (logged time) after that event and belong to a session with no logon
    (``open_known`` False); split into ``_system`` / ``_user`` by the session's ``is_system`` (system logon IDs).
    ``data_limitation`` = 1 when the ``evidence_after`` sum > 0 or ``unknown_session_processes_after`` > 0 (a
    quiet host is not a limitation); ``data_limitation_reasons`` names the condition(s) that fired, sorted, from
    ``LIMIT_REASONS``. ``hops_near_end``: for a labelled host (either reason), the hops into it whose last member
    is within ``link_after_s`` before the last event (same-host logged times); empty otherwise. Counts and ids
    only: never a stitcher error, never a test failure.
    """
    host: str
    last_security_uid: str
    last_security_us_raw: int
    last_security_us: int
    ms_before_window_end: int
    evidence_after: dict[str, int]
    evidence_after_uids: dict[str, list[str]]
    data_limitation: int
    hops_near_end: list[str] = field(default_factory=list)
    unknown_session_processes_after: int = 0
    unknown_session_processes_after_system: int = 0
    unknown_session_processes_after_user: int = 0
    unknown_session_process_uids: list[str] = field(default_factory=list)
    data_limitation_reasons: list[str] = field(default_factory=list)


@dataclass
class LinkIndex:
    """Everything T7.3 knows about one trial, in memory (plan section 3 ``links.py``).

    ``links``: hop id -> ``SubjectLinks`` (follow-up groups have none, ST-26). ``confirm``: hop id ->
    (``confirm`` label, ``confirm_event_uids``) (ST-47). ``data_limits``: host -> ``HostLimit`` (048 item 13).
    ``counts``: the JSON-ready counts block of ``link_counts``.
    """
    trial_id: str
    hopset: HopSet
    artefacts: ArtefactSet
    links: dict[str, SubjectLinks]
    confirm: dict[str, tuple[str, list[str]]]
    data_limits: dict[str, HostLimit]
    counts: dict[str, Any]


# ---------------------------------------------------------------- command probes and uids

def command_probes(params: StitchParams) -> dict[str, list[tuple[str, TargetForms]]]:
    """Source host -> (target host, forms) for every OTHER lab host (ST-43). WHY every lab host, not only the hop
    targets: the same ``CmdResult`` also feeds the data limits, which ask whether any command names a host."""
    hosts = sorted(params.lab_host_ips)
    return {h: [(t, target_name_forms(t, params.lab_host_ips[t])) for t in hosts if t != h] for h in hosts}


def names_by_target(hopset: HopSet, artefact_set: ArtefactSet) -> dict[str, list[str]]:
    """Target host -> its target-side names (the ``names`` of its share-burst and install rows: ``.exe`` file
    names, service names, binary file names), sorted unique. WHY only these: spec 2 allows names taken from
    target-side events in outputs, and ST-46 compares exactly these with the source command evidence."""
    target_of = {h.hop_id: h.target_host for h in hopset.hops}
    out: dict[str, set[str]] = {}
    for r in artefact_set.rows:
        if r.kind in NAMED_ARTEFACT_KINDS:
            out.setdefault(target_of[r.hop_id], set()).update(n for n in r.names if n)
    return {k: sorted(v) for k, v in sorted(out.items())}


def process_uids_by_host(processes: ProcessIndex) -> dict[str, list[str]]:
    """Host -> the Sysmon 1 / 4688 uids of its index processes (in-window by construction, ST-01, Q13b), sorted.
    WHY the index and not the raw rows: command evidence is a process of the T7.2 index (048 item 4)."""
    out: dict[str, set[str]] = {}
    for p in processes.processes.values():
        out.setdefault(p.host, set()).update(p.sysmon1_uids + p.sec4688_uids)
    return {h: sorted(u) for h, u in sorted(out.items())}


def link_4648_uids(scan: ScanResult) -> list[str]:
    """Every uid (ST-05 copies included) of the in-window Security 4648 link rows, sorted (ST-42, ST-01)."""
    return sorted({str(u) for r in scan.link_rows if (r.get("channel"), r.get("event_id")) == ("Security", 4648)
                   for u in (r.get("event_uids") or [r.get("event_uid")])})


# ---------------------------------------------------------------- data limits (048 item 13)

def last_security_events(scan: ScanResult) -> dict[str, Row]:
    """Host -> its last in-window Security row the scan kept (``in_window`` + ``link_rows``), by (us_raw, uid).

    WHY the logged time: "the log ends at" is a fact of the host's own log; the corrected time is reported next
    to it for the cross-host comparison.
    """
    out: dict[str, Row] = {}
    for r in list(scan.in_window) + list(scan.link_rows):
        if r.get("channel") != "Security" or r.get("host") is None:
            continue
        h = str(r["host"])
        cur = out.get(h)
        if cur is None or (r["us_raw"], str(r["event_uid"])) > (cur["us_raw"], str(cur["event_uid"])):
            out[h] = r
    return dict(sorted(out.items()))


def _row_uids(row: Row) -> list[str]:
    """Every uid of a scan row (ST-05 copies included)."""
    return [str(u) for u in (row.get("event_uids") or [row.get("event_uid")])]


def _sysmon3_after(host: str, after_us: int, scan: ScanResult, params: StitchParams) -> list[str]:
    """Uids of in-window Sysmon 3 rows on other hosts, ``initiated`` = 1, destination IP = ``host``'s lab IP,
    corrected time after ``after_us``. The same field tests as the port join (ST-41), without the port."""
    ip = lab_ip_of(host, params.lab_host_ips)
    if ip is None:
        return []
    return sorted({u for r in scan.in_window
                   if str(r.get("host")) != host and (r.get("channel"), r.get("event_id")) == ("Sysmon", 3)
                   and _initiated(r.get("initiated")) and norm_ip(r.get("destination_ip")) == ip
                   and r["us"] > after_us for u in _row_uids(r)})


def _4648_after(host: str, after_us: int, scan: ScanResult, t4648: Mapping[str, Sequence[str]],
                params: StitchParams) -> list[str]:
    """Uids of in-window 4648 link rows on other hosts whose target texts name ``host`` (ST-42 matcher),
    corrected time after ``after_us``."""
    forms = target_name_forms(host, lab_ip_of(host, params.lab_host_ips))
    out: set[str] = set()
    for r in scan.link_rows:
        if (str(r.get("host")) == host or (r.get("channel"), r.get("event_id")) != ("Security", 4648)
                or r["us"] <= after_us):
            continue
        texts = _targets_of(r, t4648)
        if texts and match_4648(texts, forms) is not None:
            out.update(_row_uids(r))
    return sorted(out)


def _cmd_after(host: str, after_us: int, processes: ProcessIndex, cmd: Mapping[str, CmdResult]) -> tuple[int, list[str]]:
    """(processes, their naming uids) on other hosts whose ``CmdResult`` names ``host`` and whose start
    (corrected) is after ``after_us``. A collapsed Sysmon 1 + 4688 counts once (048 item 4)."""
    n = 0
    uids: set[str] = set()
    for p in processes.processes.values():
        if p.host == host or p.start_us <= after_us:
            continue
        hits = [u for u in p.sysmon1_uids + p.sec4688_uids
                if u in cmd and any(t == host for t, _k, _v in cmd[u].targets)]
        if hits:
            n += 1
            uids.update(hits)
    return n, sorted(uids)


def unknown_session_processes_after(host: str, after_us_raw: int, processes: ProcessIndex,
                                    sessions: SessionIndex) -> tuple[int, int, list[str]]:
    """(system count, user count, Sysmon 1 / 4688 uids) of the index processes ON ``host`` that start after
    ``after_us_raw`` (logged time) and whose session has no logon (``open_known`` False). Owner instruction
    2026-11-14, added to 048 item 13.

    WHY it signals a data limit: such a process names a logon ID that no 4624 in the host's own rows opened,
    and it runs after the host's last kept Security event, so the host was still active while its Security log
    shows nothing (the logon may be missing from the export). WHY same-host logged times: both instants come
    from the same host's clock, as the rest of ``data_limits`` compares same-host times. A process with a NULL
    session (``session_key`` None) does not count: decision 005, NULL never forms a session. The session is
    read through the ``SessionIndex`` and never changed here; its ``is_system`` (system logon IDs) gives the
    split, so the owner can see what fired. A collapsed Sysmon 1 + 4688 counts once (048 item 4). Pure.
    """
    n_system = n_user = 0
    uids: set[str] = set()
    for p in processes.processes.values():
        if p.host != host or p.start_us_raw <= after_us_raw or p.session_key is None:
            continue
        session = sessions.sessions[p.session_key]
        if session.open_known:
            continue
        if session.is_system:
            n_system += 1
        else:
            n_user += 1
        uids.update(p.sysmon1_uids + p.sec4688_uids)
    return n_system, n_user, sorted(uids)


def _limit_reasons(evidence_counts: Mapping[str, int], unknown_session_processes: int) -> list[str]:
    """The ``data_limitation_reasons`` of one host, sorted: which of the two 048 item 13 conditions (as extended
    by the owner instruction 2026-11-14) fired. Empty = the host is not labelled."""
    out: list[str] = []
    if sum(evidence_counts.values()) > 0:
        out.append(REASON_EVIDENCE_AFTER)
    if unknown_session_processes > 0:
        out.append(REASON_UNKNOWN_SESSION_PROCESS)
    return sorted(out)


def data_limits(scan: ScanResult, hopset: HopSet, processes: ProcessIndex, cmd: Mapping[str, CmdResult],
                t4648: Mapping[str, Sequence[str]], window_end_us: int,
                params: StitchParams = StitchParams(), *, sessions: SessionIndex) -> dict[str, HostLimit]:
    """048 item 13 (as amended, and extended by the owner instruction 2026-11-14): per host with in-window
    Security rows, its last Security event, the source evidence naming it after that event per method, the
    processes on it after that event whose session has no logon, ``data_limitation`` with its reasons, and the
    hops near the end.

    Pure. WHY only these two conditions label a host: a host's Security log may simply be quiet near the window
    end (the window runs 300 s past the last agent command, 048 pre-check), and that is no limitation; evidence
    elsewhere that something reached the host after its log stops is, and so is activity on the host itself
    under a logon its log never recorded (owner, 2026-11-14). ``sessions`` is required (keyword only) so no
    caller can silently skip the second condition.
    """
    after_s = seconds_to_us(params.link_after_s)
    out: dict[str, HostLimit] = {}
    for host, last in last_security_events(scan).items():
        s3 = _sysmon3_after(host, last["us"], scan, params)
        x4648 = _4648_after(host, last["us"], scan, t4648, params)
        n_cmd, cmd_uids = _cmd_after(host, last["us"], processes, cmd)
        counts = {METHOD_PORT: len(s3), METHOD_4648: len(x4648), METHOD_CMD: n_cmd}
        n_sys, n_user, unk_uids = unknown_session_processes_after(host, last["us_raw"], processes, sessions)
        reasons = _limit_reasons(counts, n_sys + n_user)
        flagged = int(bool(reasons))
        near = sorted(h.hop_id for h in hopset.hops
                      if h.target_host == host and last["us_raw"] - h.last_us_raw <= after_s) if flagged else []
        out[host] = HostLimit(host=host, last_security_uid=str(last["event_uid"]),
                              last_security_us_raw=last["us_raw"], last_security_us=last["us"],
                              ms_before_window_end=delta_ms(window_end_us, last["us"]),
                              evidence_after=counts,
                              evidence_after_uids={METHOD_PORT: s3, METHOD_4648: x4648, METHOD_CMD: cmd_uids},
                              data_limitation=flagged, hops_near_end=near,
                              unknown_session_processes_after=n_sys + n_user,
                              unknown_session_processes_after_system=n_sys,
                              unknown_session_processes_after_user=n_user,
                              unknown_session_process_uids=unk_uids, data_limitation_reasons=reasons)
    return out


# ---------------------------------------------------------------- counts

def _bump(table: dict[str, int], key: str, n: int = 1) -> None:
    """Increment a counter."""
    table[key] = table.get(key, 0) + n


def _methods_linked(sl: SubjectLinks) -> int:
    """Number of methods (0..3) that found at least one candidate session for the hop."""
    return sum(1 for m in EVIDENCE_METHODS if sl.candidate_counts.get(m, 0) > 0)


_HOP_COUNT_KEYS: tuple[str, ...] = ("remote_logons", "groups_before_followups", "ip_groups_before_followups", "hops",
                                    "seeds", "followup_groups", "followup_logons", "protocols",
                                    "gap_near_threshold", "gap_near_threshold_user_e2e")


def link_counts(scan: ScanResult, hopset: HopSet, artefact_set: ArtefactSet, links: Mapping[str, SubjectLinks],
                confirm: Mapping[str, tuple[str, list[str]]], limits: Mapping[str, HostLimit]) -> dict[str, Any]:
    """The counts block of the check file (task 5 list; spec 3 ``stats.json`` items T7.3 can know). Pure."""
    by_proto: dict[str, dict[str, int]] = {}
    reasons = {r: 0 for r in TARGET_ONLY_REASONS}
    cand_rows = {m: 0 for m in EVIDENCE_METHODS}
    unresolved: dict[str, int] = {}
    system = {m: 0 for m in EVIDENCE_METHODS}
    for h in hopset.hops:
        sl = links[h.hop_id]
        _bump(by_proto.setdefault(h.protocol, {str(n): 0 for n in range(len(EVIDENCE_METHODS) + 1)}),
              str(_methods_linked(sl)))
        if sl.target_only_reason:
            _bump(reasons, sl.target_only_reason)
        for r in sl.rows:
            if r.method == METHOD_TARGET_ONLY:
                continue
            if r.session_key is not None:
                _bump(cand_rows, r.method)
            else:
                _bump(unresolved, r.session_unresolved_reason)
        for m, n in sl.system_session_evidence.items():
            _bump(system, m, n)
    labels = [confirm[h.hop_id][0] for h in hopset.hops]
    out: dict[str, Any] = {k: hopset.counts[k] for k in _HOP_COUNT_KEYS}
    out.update({
        "hops_by_methods_linked": {p: dict(v) for p, v in sorted(by_proto.items())},
        "target_only_reasons": reasons,
        "hops_candidate_count_all_gt_1": sum(1 for h in hopset.hops if links[h.hop_id].candidate_count_all > 1),
        "candidate_rows_by_method": cand_rows,
        "unresolved_rows_by_reason": dict(sorted(unresolved.items())),
        "system_session_evidence": system,
        "kerberos_confirmed_hops": sum(1 for lb in labels if CONFIRM_KERBEROS in lb.split(";")),
        "service_admin_write_hops": sum(1 for lb in labels if CONFIRM_SERVICE in lb.split(";")),
        "artefacts": dict(artefact_set.counts),
        "link_near_duplicate_groups": scan.link_near_duplicate_groups,
        "link_near_duplicate_split_by_window": scan.link_near_duplicate_split_by_window,
        "data_limitation_hosts": sorted(h for h, lim in limits.items() if lim.data_limitation),
    })
    return out


# ---------------------------------------------------------------- assembly

def assemble(trial_id: str, con: sqlite3.Connection, scan: ScanResult, gate_rows: GateRows,
             checked: CheckedInputs, params: StitchParams = StitchParams()) -> LinkIndex:
    """The ``extra`` step of ``inputs.load_link_inputs``: index, hops, artefacts, command facts (read on ``con``),
    links (ST-40..44), confirmations (ST-47), data limits (048 item 13; owner instruction 2026-11-14) and counts.

    ``checked`` supplies the clock offsets (ST-02 host part of ``clock_unreliable``) and the window end. The
    index's ``SessionIndex`` is mutated by ``source.by_4648`` (unknown-open 4648 sessions, as documented there).
    """
    index: TrialIndex = build_index(trial_id, scan, params)
    hopset = build_hops(trial_id, gate_rows, scan, index.sessions, params)
    arts = build_artefacts(hopset, scan, index.sessions, gate_rows, params)
    cmd = read_command_results(con, process_uids_by_host(index.processes), command_probes(params),
                               names_by_target(hopset, arts))
    t4648 = read_4648_targets(con, link_4648_uids(scan))
    links = build_links(hopset, scan, index, cmd, t4648, params, offsets=checked.clock.offsets)
    confirm = {h.hop_id: confirm_of(h, scan.link_rows, arts) for h in hopset.hops}
    limits = data_limits(scan, hopset, index.processes, cmd, t4648, checked.end_us, params,
                         sessions=index.sessions)
    counts = link_counts(scan, hopset, arts, links, confirm, limits)
    return LinkIndex(trial_id=trial_id, hopset=hopset, artefacts=arts, links=links, confirm=confirm,
                     data_limits=limits, counts=counts)


def run_links_checked(repo: Path, trial_id: str, params: StitchParams = StitchParams()
                      ) -> tuple[LinkIndex, CheckedInputs, TrialPaths, str, str]:
    """``run_links`` plus the ST-00 facts the check file records (gate stats hash, DB path).

    Order: ``check_allowed`` (development allowlist before any file is touched, decision 046; then every ST-00
    refusal), the gate rows, then one hash bracket around the scan and ``assemble``. Raises StitchError on any
    refusal; writes nothing.
    """
    paths = trial_paths(Path(repo), trial_id)
    checked = check_allowed(paths, params)
    gate_rows = read_gate_rows(paths.gate_dir)

    def extra(con: sqlite3.Connection, scan: ScanResult) -> LinkIndex:
        return assemble(trial_id, con, scan, gate_rows, checked, params)

    _scan, link_index, before, after = load_link_inputs(checked, paths, extra, params)
    return link_index, checked, paths, before, after


def run_links(repo: Path, trial_id: str, params: StitchParams = StitchParams()) -> tuple[LinkIndex, str, str]:
    """(LinkIndex, DB sha256 before, after) for one development trial. Pass a ``dataclasses.replace`` copy of
    ``StitchParams`` for a sensitivity run. Raises StitchError on any refusal."""
    link_index, _checked, _paths, before, after = run_links_checked(repo, trial_id, params)
    return link_index, before, after
