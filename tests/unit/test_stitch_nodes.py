"""T7.5 task 3 tests for ``stitch.nodes``: path nodes (ST-71), notes (ST-73), in-window rule (ST-01, STT-12).

Written from spec 03_stitch (ST-01, ST-05, ST-71, ST-73, STT-12, STT-14) and decision 050 items 5 and 7, with
synthetic inputs only (fast, no DB). Hops, links, verdicts, artefact rows, a ProcessIndex and ``event_us`` are built
by hand and put into a ``LinkIndex``. Corrected times are ``us``; ``us_raw`` and ``ProcessIndex.event_us_raw`` are
set to decoys wherever a test must show that the corrected time decides (decision 014, ST-02).
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Sequence

import pytest

from stitch import nodes as N
from stitch import paths as P
from stitch.artefacts import ArtefactRow
from stitch.hops import Hop, HopSet, RemoteLogon
from stitch.index import TrialIndex
from stitch.linkids import numbered_link_rows
from stitch.links import LinkIndex
from stitch.processes import Process, ProcessIndex
from stitch.source import METHOD_4648, METHOD_PORT, METHOD_TARGET_ONLY, LinkRow, SubjectLinks
from stitch.tiers import HopVerdicts, SessionVerdict

TRIAL = "s04_t00"
BASE = 1_700_000_000_000_000
S = 1_000_000
DEFAULT_OFF = 10 * S                  # default corrected offset of an event whose time a test does not care about


def skey(host: str, lid: int, epoch: int = 3, seq: int = 0) -> tuple:
    return (host, lid, epoch, seq)


# ------------------------------------------------------------------ builders

def mk_logon(uid: str, host: str, us: int, lid: int, *, copies: Sequence[str] = (), key: tuple | None = None,
             us_raw: int | None = None, triggers: Sequence[str] = ("T",)) -> RemoteLogon:
    return RemoteLogon(uid=uid, event_uids=[uid, *copies], gate_uids=[], host=host,
                       us_raw=us if us_raw is None else us_raw, us=us, source_ip="10.0.0.2", ip_kind="lab",
                       source_port=50000, account="acct_a", account_key="acct_a", logon_id=lid,
                       logon_id_hex=hex(lid), authentication_package="NTLM", logon_guid=None, machine_account=0,
                       rules=["R4_smb"], trigger_ids=list(triggers), gate_clock_unreliable=0, clock_unreliable=0,
                       session_key=key)


def mk_hop(hop_id: str, target: str, members: Sequence[RemoteLogon], followups: Sequence[RemoteLogon] = ()) -> Hop:
    trig = sorted({t for m in members for t in m.trigger_ids})
    return Hop(hop_id=hop_id, target_host=target, source_ip="10.0.0.2", ip_kind="lab", members=list(members),
               protocol="smb", rules=["R4_smb"], trigger_ids=trig, authentication_packages=["NTLM"],
               mixed_account=0, followups=list(followups))


def mk_row(method: str, key: tuple | None, evidence: Sequence[str] = (), matched: Sequence[str] = (),
           source_host: str | None = None, reason: str = "") -> LinkRow:
    return LinkRow(method=method, source_host=source_host if source_host is not None else (key[0] if key else None),
                   session_key=key, source_session_id=None if key is None else key[1], source_session_id_hex="",
                   session_unresolved_reason=reason, session_methods=[], candidate_count=1, candidate_count_all=1,
                   matched_member_count=len(matched), time_delta_ms=0, time_delta_raw_ms=0,
                   evidence_uids=list(evidence), matched_member_uids=list(matched), supporting_event_uids=[],
                   source_session_logon_uids=[], source_session_account=None, source_session_logon_type=None,
                   credential_accounts=[], names_found=[], names_event_uids=[], match_kinds={}, match_vias={},
                   target_only_reason="no_evidence_in_range" if method == METHOD_TARGET_ONLY else "",
                   clock_unreliable=0)


def mk_verdict(key: tuple, tier: str, rank: int) -> SessionVerdict:
    return SessionVerdict(session_key=key, account_match="direct", account_match_members=("direct",),
                          account_match_member_count=1, name_check="no_names", name_check_names=(),
                          name_check_event_uids=(), confidence_tier=tier, link_rank=rank, tie=0, rank_basis="only")


def mk_art(hop: Hop, kind: str, uids: Sequence[str], member_uid: str = "") -> ArtefactRow:
    return ArtefactRow(hop_id=hop.hop_id, kind=kind, member_logon_uid=member_uid or hop.members[0].uid,
                       logged_under_hop_id=hop.hop_id, method="logon_id", candidate_count=1, time_delta_ms=0,
                       supporting_span_ms=0, confidence_tier="A", event_uids=list(uids), names=[],
                       untied_same_name_bursts=[], ref_id="", first_us_raw=0, last_us_raw=0)


def mk_process(host: str, n: int, key: tuple, uids: Sequence[str]) -> Process:
    return Process(host=host, key=(host, f"guid{n}"), process_guid=f"guid{n}", parent_process_guid=None,
                   process_id=n, session_logon_id=key[1], session_key=key, sysmon1_uids=list(uids), sec4688_uids=[],
                   start_us_raw=0, start_us=0, image=None, parent_image=None)


@dataclass
class SessSpec:
    """One candidate source session of a hop: its key, tier, rank, link rows (method, evidence, matched) and the
    process events of the session (uid -> corrected offset from BASE, µs)."""
    key: tuple
    tier: str
    rank: int
    rows: list[tuple[str, list[str], list[str]]] = field(default_factory=list)
    events: dict[str, int] = field(default_factory=dict)


class World:
    def __init__(self) -> None:
        self.hops: list[Hop] = []
        self.links: dict[str, SubjectLinks] = {}
        self.verdicts: dict[str, HopVerdicts] = {}
        self.art_rows: list[ArtefactRow] = []
        self.event_us: dict[str, int] = {}
        self.proc_events: dict[tuple, dict[str, int]] = {}      # session key -> uid -> corrected µs
        self.raw: dict[str, int] = {}                           # decoy raw times
        self.followups: list = []

    def t(self, uid: str, off_us: int = DEFAULT_OFF) -> None:
        self.event_us[uid] = BASE + off_us

    def add_hop(self, hop: Hop, source_host: str | None, sessions: Sequence[SessSpec] = (),
                extra_rows: Sequence[LinkRow] = ()) -> Hop:
        self.hops.append(hop)
        rows: list[LinkRow] = []
        for m in hop.members:
            for u in m.event_uids:
                if u not in self.event_us:
                    self.t(u, m.us - BASE)
        for s in sessions:
            for method, ev, matched in s.rows:
                rows.append(mk_row(method, s.key, ev, matched))
                for u in ev:
                    if u not in self.event_us:
                        self.t(u)
            for u, off in s.events.items():
                self.event_us[u] = BASE + off
                self.proc_events.setdefault(s.key, {})[u] = BASE + off
        rows.extend(extra_rows)
        for r in extra_rows:
            for u in r.evidence_uids:
                self.event_us.setdefault(u, BASE + DEFAULT_OFF)
        if not sessions and not extra_rows:
            rows.append(mk_row(METHOD_TARGET_ONLY, None, source_host=source_host))
        self.links[hop.hop_id] = SubjectLinks(
            target_host=hop.target_host, source_host=source_host, member_uids=[m.uid for m in hop.members],
            rows=rows, target_only_reason="" if rows and rows[0].method != METHOD_TARGET_ONLY else "no_evidence_in_range",
            candidate_counts={}, candidate_count_all=len(sessions), session_methods={}, sessions={},
            evidence_before_range=0, evidence_after_range=0, system_session_evidence={}, methods={},
            host_clock_unreliable=0)
        vs = {s.key: mk_verdict(s.key, s.tier, s.rank) for s in sessions}
        self.verdicts[hop.hop_id] = HopVerdicts(hop_id=hop.hop_id, sessions=vs, candidate_count_account=0, names=(),
                                                no_session_name_check="no_names",
                                                best_tier=min((s.tier for s in sessions), default="D"))
        return hop

    def add_target_events(self, key: tuple, events: dict[str, int]) -> None:
        for u, off in events.items():
            self.event_us[u] = BASE + off
            self.proc_events.setdefault(key, {})[u] = BASE + off

    def index(self) -> LinkIndex:
        procs: dict[tuple, Process] = {}
        by_session: dict[tuple, list] = {}
        raw: dict[str, int] = {}
        for n, (key, evs) in enumerate(sorted(self.proc_events.items())):
            p = mk_process(key[0], n, key, sorted(evs))
            procs[p.key] = p
            by_session.setdefault(key, []).append(p.key)
            for u, us in evs.items():
                raw[u] = self.raw.get(u, us)
        pi = ProcessIndex(processes=procs, system_logon_ids=frozenset(), by_session=by_session, event_us_raw=raw)
        ti = TrialIndex(trial_id=TRIAL, sessions=None, processes=pi, scan_counts={})   # type: ignore[arg-type]
        hs = HopSet(trial_id=TRIAL, hops=list(self.hops), followups=list(self.followups), counts={})
        return LinkIndex(trial_id=TRIAL, hopset=hs, artefacts=SimpleNamespace(rows=list(self.art_rows)),  # type: ignore[arg-type]
                         links=self.links, confirm={}, data_limits={}, counts={}, verdicts=self.verdicts,
                         index=ti, offsets=None, event_us=dict(self.event_us))

    def nodes(self) -> list[N.PathNode]:
        li = self.index()
        return N.build_nodes(li, P.build_paths(li))


def one_hop(sessions: Sequence[SessSpec] = (), *, target: str = "ep-02", last_off: int = 100 * S,
            member_key: tuple | None = None, copies: Sequence[str] = ()) -> tuple[World, Hop]:
    """One hop: first member at +0, last member at ``last_off`` (corrected); raw times are decoys 1000 s later."""
    w = World()
    m1 = mk_logon("m1", target, BASE, 0x1000, copies=copies, key=member_key, us_raw=BASE + 1000 * S)
    m2 = mk_logon("m2", target, BASE + last_off, 0x1001, key=member_key, us_raw=BASE + 1000 * S + last_off)
    hop = w.add_hop(mk_hop("h1", target, [m1, m2]), "ep-01", sessions)
    return w, hop


def by_role(nodes: Sequence[N.PathNode], role: str) -> list[N.PathNode]:
    return [n for n in nodes if n.role == role]


def uids(nodes: Sequence[N.PathNode]) -> set[str]:
    return {n.event_uid for n in nodes}


SA = skey("ep-01", 100)
SB = skey("ep-01", 200)


# ------------------------------------------------------------------ constants

def test_role_constants() -> None:
    assert (N.ROLE_TARGET_LOGON, N.ROLE_ARTEFACT, N.ROLE_SOURCE_EVIDENCE, N.ROLE_SOURCE_SESSION_EVENT,
            N.ROLE_TARGET_SESSION_EVENT) == ("target_logon", "artefact", "source_evidence", "source_session_event",
                                             "target_session_event")
    assert N.ROLES == ("target_logon", "artefact", "source_evidence", "source_session_event",
                       "target_session_event")


def test_event_time_and_missing_uid() -> None:
    assert N.event_time("a", {"a": 5}) == 5
    with pytest.raises(ValueError):
        N.event_time("zzz", {"a": 5})


# ------------------------------------------------------------------ target_logon (ST-71, ST-05)

def test_target_logon_every_member_uid_incl_st05_copies() -> None:
    w, hop = one_hop(copies=["m1-copy"])
    li = w.index()
    ns = N.target_logon_nodes("p1", hop, li.event_us)
    assert sorted(n.event_uid for n in ns) == ["m1", "m1-copy", "m2"]
    assert all(n.context == 0 and n.role == "target_logon" and n.host == "ep-02" and n.link_id == "" for n in ns)
    assert {n.event_uid: n.session_id for n in ns} == {"m1": 0x1000, "m1-copy": 0x1000, "m2": 0x1001}
    assert all(n.path_id == "p1" and n.hop_id == "h1" for n in ns)


def test_target_logon_via_build_nodes() -> None:
    w, _ = one_hop(copies=["m1-copy"])
    ns = by_role(w.nodes(), "target_logon")
    assert uids(ns) == {"m1", "m1-copy", "m2"}


def test_target_logon_time_is_corrected_time() -> None:
    w, hop = one_hop()
    ns = N.target_logon_nodes("p1", hop, w.index().event_us)
    assert {n.event_uid: n.us for n in ns} == {"m1": BASE, "m2": BASE + 100 * S}


# ------------------------------------------------------------------ artefact (ST-71)

def test_artefact_nodes_context_0_and_followup_context_1() -> None:
    fu = mk_logon("f1", "ep-02", BASE + 20 * S, 0x2000, triggers=[])
    w = World()
    hop = w.add_hop(mk_hop("h1", "ep-02", [mk_logon("m1", "ep-02", BASE, 0x1000)], followups=[fu]), "ep-01")
    w.art_rows = [mk_art(hop, "share_burst", ["a1", "a2"]), mk_art(hop, "service_install", ["a3"]),
                  mk_art(hop, "followup_logon", ["f1"])]
    for u in ("a1", "a2", "a3", "f1"):
        w.t(u)
    ns = by_role(w.nodes(), "artefact")
    assert {n.event_uid: n.context for n in ns} == {"a1": 0, "a2": 0, "a3": 0, "f1": 1}
    assert all(n.host == "ep-02" and n.link_id == "" for n in ns)


def test_artefact_rows_of_other_hops_not_used() -> None:
    w = World()
    h1 = w.add_hop(mk_hop("h1", "ep-02", [mk_logon("m1", "ep-02", BASE, 0x1000)]), "ep-01")
    h2 = w.add_hop(mk_hop("h2", "ep-03", [mk_logon("m2", "ep-03", BASE + 500 * S, 0x1001)]), "ep-01")
    w.art_rows = [mk_art(h1, "share_burst", ["a1"]), mk_art(h2, "share_burst", ["a2"])]
    w.t("a1")
    w.t("a2")
    ns = by_role(w.nodes(), "artefact")
    assert {(n.hop_id, n.event_uid) for n in ns} == {("h1", "a1"), ("h2", "a2")}


# ------------------------------------------------------------------ source_evidence (ST-71, 050 item 7)

def test_source_evidence_rank1_rows_context_0_with_links_csv_link_ids() -> None:
    sa = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-a1"], ["m1"]), (METHOD_4648, ["ev-a2"], ["m2"])])
    w, hop = one_hop([sa])
    li = w.index()
    ns = by_role(w.nodes(), "source_evidence")
    expected = {(lid, u) for lid, r in numbered_link_rows(hop, li) for u in r.evidence_uids}
    assert {(n.link_id, n.event_uid) for n in ns} == expected == {("h1-l01", "ev-a1"), ("h1-l02", "ev-a2")}
    assert all(n.context == 0 and n.host == "ep-01" and n.session_id == 100 for n in ns)


def test_source_evidence_link_id_follows_rank_numbering() -> None:
    # the rank-2 session's rows get later link ids; the rank-1 evidence sits on l01
    s1 = SessSpec(SB, "A", 1, rows=[(METHOD_PORT, ["ev-b"], [])])
    s2 = SessSpec(SA, "B", 2, rows=[(METHOD_PORT, ["ev-a"], [])])
    w, hop = one_hop([s2, s1])
    li = w.index()
    ids = {r.session_key: lid for lid, r in numbered_link_rows(hop, li)}
    assert ids == {SB: "h1-l01", SA: "h1-l02"}
    ns = by_role(w.nodes(), "source_evidence")
    assert {(n.link_id, n.event_uid) for n in ns} == {("h1-l01", "ev-b")}


def test_source_evidence_same_event_two_rows_two_nodes() -> None:
    sa = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-x"], []), (METHOD_4648, ["ev-x"], [])])
    w, _ = one_hop([sa])
    ns = by_role(w.nodes(), "source_evidence")
    assert sorted((n.link_id, n.event_uid) for n in ns) == [("h1-l01", "ev-x"), ("h1-l02", "ev-x")]


def test_matched_member_uids_are_not_source_evidence() -> None:
    sa = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-a"], ["m1", "m2"])])
    w, _ = one_hop([sa])
    ns = w.nodes()
    assert uids(by_role(ns, "source_evidence")) == {"ev-a"}
    assert {n.role for n in ns if n.event_uid in ("m1", "m2")} == {"target_logon"}


def test_source_evidence_rank1_tier_d_sole_candidate_kept() -> None:
    sa = SessSpec(SA, "D", 1, rows=[(METHOD_PORT, ["ev-d"], [])], events={"se-d": 10 * S})
    w, _ = one_hop([sa])
    ns = w.nodes()
    assert uids(by_role(ns, "source_evidence")) == {"ev-d"}
    assert by_role(ns, "source_session_event") == []        # STT-14: a tier D link adds no source-session nodes


def test_source_evidence_rank1_tier_c_tie_both_kept() -> None:
    sa = SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-c1"], [])], events={"se-c1": 10 * S})
    sb = SessSpec(SB, "C", 1, rows=[(METHOD_4648, ["ev-c2"], [])], events={"se-c2": 10 * S})
    w, _ = one_hop([sa, sb])
    ns = w.nodes()
    assert uids(by_role(ns, "source_evidence")) == {"ev-c1", "ev-c2"}
    assert by_role(ns, "source_session_event") == []


def test_source_evidence_rank2_session_gives_none() -> None:
    s1 = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-1"], [])])
    s2 = SessSpec(SB, "C", 2, rows=[(METHOD_PORT, ["ev-2"], [])], events={"se-2": 10 * S})
    w, _ = one_hop([s1, s2])
    ns = w.nodes()
    assert uids(by_role(ns, "source_evidence")) == {"ev-1"}
    assert "se-2" not in uids(ns)


def test_unresolved_and_target_only_rows_give_no_source_nodes() -> None:
    w = World()
    hop = mk_hop("h1", "ep-02", [mk_logon("m1", "ep-02", BASE, 0x1000)])
    unresolved = mk_row(METHOD_PORT, None, ["ev-u"], reason="no_sysmon1_in_window")
    target_only = mk_row(METHOD_TARGET_ONLY, None, ["ev-t"])
    w.add_hop(hop, "ep-01", [], extra_rows=[unresolved, target_only])
    ns = w.nodes()
    assert uids(by_role(ns, "source_evidence")) == set()
    assert "ev-u" not in uids(ns) and "ev-t" not in uids(ns)
    assert {n.role for n in ns} == {"target_logon"}


def test_target_only_hop_has_only_own_nodes() -> None:
    w = World()
    hop = mk_hop("h1", "ep-02", [mk_logon("m1", "ep-02", BASE, 0x1000)])
    w.add_hop(hop, None)
    ns = w.nodes()
    assert [n.role for n in ns] == ["target_logon"]


# ------------------------------------------------------------------ source_session_event (ST-71, 050 item 7)

@pytest.mark.parametrize("tier", ["A", "B"])
def test_source_session_events_for_tier_a_and_b_context_1(tier: str) -> None:
    sa = SessSpec(SA, tier, 1, rows=[(METHOD_PORT, ["ev-a"], [])], events={"se1": 10 * S, "se2": 20 * S})
    w, hop = one_hop([sa])
    li = w.index()
    ns = by_role(w.nodes(), "source_session_event")
    assert uids(ns) == {"se1", "se2"}
    assert all(n.context == 1 and n.host == "ep-01" and n.session_id == 100 for n in ns)
    row_ids = {lid for lid, r in numbered_link_rows(hop, li) if r.session_key == SA}
    assert all(n.link_id in row_ids for n in ns)


@pytest.mark.parametrize("tier", ["C", "D"])
def test_no_source_session_events_for_tier_c_and_d(tier: str) -> None:
    sa = SessSpec(SA, tier, 1, rows=[(METHOD_PORT, ["ev-a"], [])], events={"se1": 10 * S})
    w, _ = one_hop([sa])
    assert by_role(w.nodes(), "source_session_event") == []


def test_source_session_events_only_for_rank1() -> None:
    s1 = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-1"], [])], events={"se-1": 10 * S})
    s2 = SessSpec(SB, "A", 2, rows=[(METHOD_PORT, ["ev-2"], [])], events={"se-2": 10 * S})
    w, _ = one_hop([s1, s2])
    assert uids(by_role(w.nodes(), "source_session_event")) == {"se-1"}


def test_source_cutoff_equal_kept_plus_1us_dropped() -> None:
    last = 100 * S
    sa = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-a"], [])],
                  events={"e-before": last - S, "e-equal": last, "e-plus": last + 1, "e-late": last + 60 * S})
    w, _ = one_hop([sa], last_off=last)
    assert uids(by_role(w.nodes(), "source_session_event")) == {"e-before", "e-equal"}


def test_source_cutoff_uses_corrected_not_raw() -> None:
    last = 100 * S
    sa = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-a"], [])],
                  events={"corr-before-raw-after": last - 5 * S, "corr-after-raw-before": last + 5 * S})
    w, _ = one_hop([sa], last_off=last)
    w.raw["corr-before-raw-after"] = BASE + last + 500 * S         # raw says after the hop
    w.raw["corr-after-raw-before"] = BASE - 500 * S                # raw says before the hop
    assert uids(by_role(w.nodes(), "source_session_event")) == {"corr-before-raw-after"}


def test_source_cutoff_is_the_last_member_not_the_first() -> None:
    last = 100 * S
    sa = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-a"], [])], events={"after-first-before-last": 50 * S})
    w, _ = one_hop([sa], last_off=last)
    assert "after-first-before-last" in uids(by_role(w.nodes(), "source_session_event"))


# ------------------------------------------------------------------ target_session_event

def test_target_session_events_whole_window_context_1() -> None:
    tk = skey("ep-02", 0x1000)
    w, hop = one_hop(member_key=tk)
    w.add_target_events(tk, {"te-early": -50 * S, "te-mid": 50 * S, "te-late": 1000 * S})
    ns = by_role(w.nodes(), "target_session_event")
    assert uids(ns) == {"te-early", "te-mid", "te-late"}           # no cutoff
    assert all(n.context == 1 and n.host == "ep-02" and n.session_id == 0x1000 and n.link_id == "" for n in ns)


def test_target_session_events_distinct_member_sessions() -> None:
    tk1, tk2 = skey("ep-02", 0x1000), skey("ep-02", 0x1001)
    w = World()
    m1 = mk_logon("m1", "ep-02", BASE, 0x1000, key=tk1)
    m2 = mk_logon("m2", "ep-02", BASE + S, 0x1001, key=tk2)
    m3 = mk_logon("m3", "ep-02", BASE + 2 * S, 0x1000, key=tk1)       # same session as m1: events once
    w.add_hop(mk_hop("h1", "ep-02", [m1, m2, m3]), "ep-01")
    w.add_target_events(tk1, {"t1": 5 * S})
    w.add_target_events(tk2, {"t2": 6 * S})
    ns = by_role(w.nodes(), "target_session_event")
    assert sorted((n.event_uid, n.session_id) for n in ns) == [("t1", 0x1000), ("t2", 0x1001)]


def test_followup_logon_sessions_add_no_target_session_nodes() -> None:
    fk = skey("ep-02", 0x2000)
    fu = mk_logon("f1", "ep-02", BASE + 20 * S, 0x2000, key=fk, triggers=[])
    w = World()
    hop = w.add_hop(mk_hop("h1", "ep-02", [mk_logon("m1", "ep-02", BASE, 0x1000)], followups=[fu]), "ep-01")
    w.add_target_events(fk, {"fk-ev": 30 * S})
    w.art_rows = [mk_art(hop, "followup_logon", ["f1"])]
    w.t("f1", 20 * S)
    ns = w.nodes()
    assert "fk-ev" not in uids(ns)
    assert by_role(ns, "target_session_event") == []


def test_member_without_session_key_gives_no_target_session_nodes() -> None:
    w, _ = one_hop(member_key=None)
    assert by_role(w.nodes(), "target_session_event") == []


# ------------------------------------------------------------------ ST-01 / STT-12 in-window only

def test_node_uid_missing_from_event_us_raises() -> None:
    sa = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-a"], [])])
    w, _ = one_hop([sa])
    del w.event_us["ev-a"]
    with pytest.raises(ValueError):
        w.nodes()


def test_process_event_outside_window_raises() -> None:
    sa = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-a"], [])], events={"se-out": 10 * S})
    w, _ = one_hop([sa])
    del w.event_us["se-out"]
    with pytest.raises(ValueError):
        w.nodes()


def test_artefact_uid_outside_window_raises() -> None:
    w, hop = one_hop()
    w.art_rows = [mk_art(hop, "share_burst", ["a-out"])]
    with pytest.raises(ValueError):
        w.nodes()


def test_member_uid_outside_window_raises() -> None:
    w, _ = one_hop(copies=["m1-copy"])
    del w.event_us["m1-copy"]
    with pytest.raises(ValueError):
        w.nodes()


def test_every_node_uid_is_in_event_us() -> None:
    tk = skey("ep-02", 0x1000)
    sa = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-a"], ["m1"])], events={"se1": 10 * S})
    w, hop = one_hop([sa], member_key=tk, copies=["m1-copy"])
    w.add_target_events(tk, {"te1": 5 * S})
    w.art_rows = [mk_art(hop, "share_burst", ["a1"])]
    w.t("a1")
    ns = w.nodes()
    assert {n.role for n in ns} == set(N.ROLES)
    assert uids(ns) <= set(w.event_us)
    assert all(n.us == w.event_us[n.event_uid] for n in ns)


# ------------------------------------------------------------------ dedupe and order

def node(path: str = "p1", hop: str = "h1", role: str = "target_logon", uid: str = "u", link: str = "",
         us: int = 0, ctx: int = 0, sid: int | None = 1, host: str = "ep-02") -> N.PathNode:
    return N.PathNode(path_id=path, hop_id=hop, role=role, context=ctx, host=host, session_id=sid, event_uid=uid,
                      link_id=link, us=us)


HOP_POS = {"h1": (0, "h1"), "h2": (10, "h2"), "h3": (20, "h3")}


def test_dedupe_identical_rows_once() -> None:
    out = N.dedupe_nodes([node(uid="a"), node(uid="a"), node(uid="a")], HOP_POS)
    assert len(out) == 1


def test_dedupe_same_uid_different_role_kept() -> None:
    out = N.dedupe_nodes([node(uid="a", role="target_logon"), node(uid="a", role="artefact")], HOP_POS)
    assert [n.role for n in out] == ["target_logon", "artefact"]


def test_dedupe_same_uid_different_link_id_kept() -> None:
    out = N.dedupe_nodes([node(uid="a", role="source_evidence", link="h1-l01"),
                          node(uid="a", role="source_evidence", link="h1-l02")], HOP_POS)
    assert [n.link_id for n in out] == ["h1-l01", "h1-l02"]


def test_dedupe_same_uid_different_hop_or_path_kept() -> None:
    out = N.dedupe_nodes([node(uid="a", hop="h1"), node(uid="a", hop="h2"), node(uid="a", path="p2")], HOP_POS)
    assert len(out) == 3


def test_dedupe_order_path_hop_time_role_uid_link() -> None:
    expected = [
        node(path="p1", hop="h1", role="target_logon", uid="a", us=1),
        node(path="p1", hop="h1", role="artefact", uid="a", us=1),
        node(path="p1", hop="h1", role="source_evidence", uid="a", us=1, link="h1-l01"),
        node(path="p1", hop="h1", role="source_evidence", uid="a", us=1, link="h1-l02"),
        node(path="p1", hop="h1", role="source_evidence", uid="b", us=1, link="h1-l01"),
        node(path="p1", hop="h1", role="target_logon", uid="c", us=2),
        node(path="p1", hop="h2", role="target_logon", uid="a", us=0),     # later hop: after every h1 row
        node(path="p1", hop="h3", role="target_session_event", uid="a", us=0),
        node(path="p2", hop="h1", role="target_logon", uid="a", us=0),
    ]
    for seed in range(5):
        shuffled = list(expected)
        random.Random(seed).shuffle(shuffled)
        assert N.dedupe_nodes(shuffled, HOP_POS) == expected


def test_dedupe_role_order_at_equal_time() -> None:
    rows = [node(role=r, uid="a", us=5, link="h1-l01" if r == "source_evidence" else "") for r in reversed(N.ROLES)]
    assert [n.role for n in N.dedupe_nodes(rows, HOP_POS)] == list(N.ROLES)


def test_build_nodes_rows_in_order_and_unique() -> None:
    tk = skey("ep-02", 0x1000)
    sa = SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-a"], []), (METHOD_4648, ["ev-a"], [])],
                  events={"se1": 10 * S})
    w, hop = one_hop([sa], member_key=tk, copies=["m1-copy"])
    w.add_target_events(tk, {"te1": 5 * S, "m2": 100 * S})                # m2 is also a target-session event (new role)
    w.art_rows = [mk_art(hop, "share_burst", ["a1"]), mk_art(hop, "service_install", ["a1"])]
    w.t("a1", 7 * S)
    ns = w.nodes()
    ident = [(n.path_id, n.hop_id, n.role, n.event_uid, n.link_id) for n in ns]
    assert len(ident) == len(set(ident))
    assert [n.event_uid for n in by_role(ns, "artefact")] == ["a1"]
    assert {n.role for n in ns if n.event_uid == "m2"} == {"target_logon", "target_session_event"}
    keys = [(n.path_id, n.us, N.ROLES.index(n.role), n.event_uid, n.link_id) for n in ns]
    assert keys == sorted(keys)


def test_build_nodes_follows_path_and_hop_order() -> None:
    w = World()
    w.add_hop(mk_hop("h1", "ep-02", [mk_logon("m1", "ep-02", BASE, 0x1000)]), "ep-01")
    w.add_hop(mk_hop("h2", "ep-03", [mk_logon("m2", "ep-03", BASE + 500 * S, 0x1001)]), "ep-01")
    ns = w.nodes()
    assert [(n.path_id, n.hop_id) for n in ns] == [(f"{TRIAL}-p0001", "h1"), (f"{TRIAL}-p0002", "h2")]


# ------------------------------------------------------------------ notes (ST-73, 050 item 5)

def two_path_world(s1: Sequence[SessSpec], s2: Sequence[SessSpec]) -> World:
    """Two seed hops that do not chain (both leave ep-01; neither target is the other's source)."""
    w = World()
    w.add_hop(mk_hop("h1", "ep-02", [mk_logon("m1", "ep-02", BASE, 0x1000)]), "ep-01", s1)
    w.add_hop(mk_hop("h2", "ep-03", [mk_logon("m2", "ep-03", BASE + 500 * S, 0x1001)]), "ep-01", s2)
    return w


def notes_of(w: World):
    li = w.index()
    ps = P.build_paths(li)
    ns = N.build_nodes(li, ps)
    return ps, ns, N.path_notes(li, ps, ns), li


P1, P2 = f"{TRIAL}-p0001", f"{TRIAL}-p0002"


def test_notes_shared_rank1_session_two_paths_never_merged() -> None:
    w = two_path_world([SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-1"], [])])],
                       [SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-2"], [])])])
    ps, _, notes, _ = notes_of(w)
    assert [p.hop_ids for p in ps.paths] == [["h1"], ["h2"]]                  # never merged
    assert notes[P1] == ([P2], [])
    assert notes[P2] == ([P1], [])


def test_notes_shared_tier_d_rank1_session_counts() -> None:
    w = two_path_world([SessSpec(SA, "D", 1, rows=[(METHOD_PORT, ["ev-1"], [])])],
                       [SessSpec(SA, "D", 1, rows=[(METHOD_PORT, ["ev-2"], [])])])
    _, _, notes, _ = notes_of(w)
    assert notes[P1][0] == [P2] and notes[P2][0] == [P1]


def test_notes_shared_event_only() -> None:
    w = two_path_world([SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-shared"], [])])],
                       [SessSpec(SB, "C", 1, rows=[(METHOD_PORT, ["ev-shared"], [])])])
    ps, _, notes, _ = notes_of(w)
    assert len(ps.paths) == 2
    assert notes[P1] == ([], [P2])
    assert notes[P2] == ([], [P1])


def test_notes_shared_context_event_counts() -> None:
    w = World()
    h1 = w.add_hop(mk_hop("h1", "ep-02", [mk_logon("m1", "ep-02", BASE, 0x1000)],
                          followups=[mk_logon("f1", "ep-02", BASE + 20 * S, 0x2000, triggers=[])]), "ep-01")
    h2 = w.add_hop(mk_hop("h2", "ep-03", [mk_logon("m2", "ep-03", BASE + 500 * S, 0x1001)]), "ep-01")
    w.art_rows = [mk_art(h1, "followup_logon", ["f1"]), mk_art(h2, "share_burst", ["f1"])]   # context row vs plain
    w.t("f1", 20 * S)
    _, ns, notes, _ = notes_of(w)
    assert {(n.hop_id, n.context) for n in ns if n.event_uid == "f1"} == {("h1", 1), ("h2", 0)}
    assert notes[P1] == ([], [P2]) and notes[P2] == ([], [P1])


def test_notes_rank2_only_shared_session_gives_no_session_note() -> None:
    w = two_path_world(
        [SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-1"], [])])],
        [SessSpec(SB, "C", 1, rows=[(METHOD_PORT, ["ev-2"], [])]),
         SessSpec(SA, "D", 2, rows=[(METHOD_PORT, ["ev-3"], [])])])
    _, _, notes, _ = notes_of(w)
    assert notes[P1] == ([], [])
    assert notes[P2] == ([], [])


def test_notes_no_overlap_empty() -> None:
    w = two_path_world([SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-1"], [])])],
                       [SessSpec(SB, "C", 1, rows=[(METHOD_PORT, ["ev-2"], [])])])
    _, _, notes, _ = notes_of(w)
    assert notes == {P1: ([], []), P2: ([], [])}


def test_notes_session_compared_on_full_key() -> None:
    other_boot = skey("ep-01", 100, epoch=4)
    w = two_path_world([SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-1"], [])])],
                       [SessSpec(other_boot, "C", 1, rows=[(METHOD_PORT, ["ev-2"], [])])])
    _, _, notes, _ = notes_of(w)
    assert notes[P1][0] == [] and notes[P2][0] == []


def test_notes_lists_sorted_and_exclude_self() -> None:
    w = World()
    for i, tgt in enumerate(["ep-02", "ep-03", "ep-04"], start=1):
        w.add_hop(mk_hop(f"h{i}", tgt, [mk_logon(f"m{i}", tgt, BASE + 500 * i * S, 0x1000 + i)]), "ep-01",
                  [SessSpec(SA, "C", 1, rows=[(METHOD_PORT, [f"ev-{i}"], [])])])
    _, _, notes, _ = notes_of(w)
    p1, p2, p3 = (f"{TRIAL}-p000{i}" for i in (1, 2, 3))
    assert notes[p1][0] == [p2, p3] and notes[p2][0] == [p1, p3] and notes[p3][0] == [p1, p2]


# ------------------------------------------------------------------ apply_notes

def test_apply_notes_returns_new_pathset_membership_unchanged_input_unchanged() -> None:
    w = two_path_world([SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-shared"], [])])],
                       [SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-shared"], [])])])
    ps, _, notes, _ = notes_of(w)
    before = [(p.path_id, list(p.hop_ids), list(p.hosts), list(p.merged_from), p.isolated, dict(p.edge_types),
               list(p.seed_trigger_ids)) for p in ps.paths]
    new = N.apply_notes(ps, notes)
    assert new is not ps
    # input unchanged
    assert [p.shared_source_session_with for p in ps.paths] == [[], []]
    assert [p.shared_event_with for p in ps.paths] == [[], []]
    # notes written
    assert [p.shared_source_session_with for p in new.paths] == [[P2], [P1]]
    assert [p.shared_event_with for p in new.paths] == [[P2], [P1]]
    # membership and everything else unchanged
    after = [(p.path_id, list(p.hop_ids), list(p.hosts), list(p.merged_from), p.isolated, dict(p.edge_types),
              list(p.seed_trigger_ids)) for p in new.paths]
    assert after == before
    assert new.trial_id == ps.trial_id
    assert new.edges == ps.edges
    assert new.hop_facts == ps.hop_facts
    assert new.counts == ps.counts


def test_apply_notes_does_not_alias_note_lists() -> None:
    w = two_path_world([SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-1"], [])])],
                       [SessSpec(SA, "C", 1, rows=[(METHOD_PORT, ["ev-2"], [])])])
    ps, _, notes, _ = notes_of(w)
    new = N.apply_notes(ps, notes)
    new.paths[0].shared_source_session_with.append("x")
    assert notes[P1][0] == [P2]
    assert ps.paths[0].shared_source_session_with == []


def test_notes_never_change_nodes_or_paths() -> None:
    w = two_path_world([SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-1"], [])], events={"se": 5 * S})],
                       [SessSpec(SA, "A", 1, rows=[(METHOD_PORT, ["ev-2"], [])], events={"se": 5 * S})])
    li = w.index()
    ps = P.build_paths(li)
    ns = N.build_nodes(li, ps)
    new = N.apply_notes(ps, N.path_notes(li, ps, ns))
    assert [p.hop_ids for p in new.paths] == [["h1"], ["h2"]]
    assert N.build_nodes(li, new) == ns
