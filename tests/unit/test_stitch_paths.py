"""T7.5 task 2 tests for ``stitch.paths``: chain edges, merge into paths, per-hop path facts (STT-14).

Written from spec 03_stitch (ST-04, ST-23, ST-70..ST-74, STT-14, limitation L-ST2) and decision 050 items 1-4 and 6,
with synthetic inputs only (fast, no DB). Hops, links, verdicts and the LinkIndex are built by hand from the T7.3 /
T7.4 dataclasses. All times are corrected microseconds (``us``); ``us_raw`` is set to something different on purpose
wherever a test must show that the corrected time is the one compared (ST-02).
"""
from __future__ import annotations

from typing import Sequence

import pytest

from stitch import paths as P
from stitch.hops import Hop, HopSet, RemoteLogon
from stitch.links import LinkIndex
from stitch.source import METHOD_TARGET_ONLY, LinkRow, SubjectLinks
from stitch.tiers import HopVerdicts, SessionVerdict

TRIAL = "s05_t00"
BASE = 1_700_000_000_000_000          # a corrected instant, µs
S = 1_000_000                         # one second in µs
TOL = 5 * S


# ------------------------------------------------------------------ builders

def skey(host: str, lid: int, epoch: int = 3, seq: int = 0) -> tuple:
    return (host, lid, epoch, seq)


def logon(uid: str, host: str, us: int, *, us_raw: int | None = None, machine: int = 0,
          key: tuple | None = None, triggers: Sequence[str] = ("T",), account: str = "acct_a") -> RemoteLogon:
    return RemoteLogon(uid=uid, event_uids=[uid], gate_uids=[], host=host, us_raw=us if us_raw is None else us_raw,
                       us=us, source_ip="10.0.0.2", ip_kind="lab", source_port=50000, account=account,
                       account_key=account.lower(), logon_id=0x1000, logon_id_hex="0x1000",
                       authentication_package="NTLM", logon_guid=None, machine_account=machine, rules=["R4_smb"],
                       trigger_ids=list(triggers), gate_clock_unreliable=0, clock_unreliable=0, session_key=key)


def mk_hop(hop_id: str, target: str, first_off_us: int, *, us_raw_off_us: int | None = None,
           triggers: Sequence[str] | None = None, machine: bool = False, clock: int = 0,
           key: tuple | None = None, source_ip: str | None = "10.0.0.2",
           extra_members: Sequence[RemoteLogon] = ()) -> Hop:
    """A hop whose first member is at BASE + first_off_us (corrected). ``triggers`` default: one trigger id
    ``T-<hop_id>``; pass [] for a non-seed hop. ``machine`` = every member a machine account (DB flag = 1)."""
    trig = [f"T-{hop_id}"] if triggers is None else list(triggers)
    raw = None if us_raw_off_us is None else BASE + us_raw_off_us
    first = logon(f"{hop_id}-m0", target, BASE + first_off_us, us_raw=raw, machine=int(machine), key=key,
                  triggers=trig)
    members = [first, *extra_members]
    return Hop(hop_id=hop_id, target_host=target, source_ip=source_ip, ip_kind="lab", members=members,
               protocol="smb", rules=["R4_smb"], trigger_ids=trig, authentication_packages=["NTLM"],
               mixed_account=0, clock_unreliable=clock,
               machine_account_only=int(all(m.machine_account == 1 for m in members)))


def mk_links(hop: Hop, source_host: str | None, *, host_clock: int = 0, target_only: bool = False
             ) -> SubjectLinks:
    rows: list[LinkRow] = []
    if target_only:
        rows.append(LinkRow(method=METHOD_TARGET_ONLY, source_host=source_host, session_key=None,
                            source_session_id=None, source_session_id_hex="", session_unresolved_reason="",
                            session_methods=[], candidate_count=0, candidate_count_all=0, matched_member_count=0,
                            time_delta_ms=None, time_delta_raw_ms=None, evidence_uids=[], matched_member_uids=[],
                            supporting_event_uids=[], source_session_logon_uids=[], source_session_account=None,
                            source_session_logon_type=None, credential_accounts=[], names_found=[],
                            names_event_uids=[], match_kinds={}, match_vias={},
                            target_only_reason="no_evidence_in_range", clock_unreliable=0))
    return SubjectLinks(target_host=hop.target_host, source_host=source_host,
                        member_uids=[m.uid for m in hop.members], rows=rows,
                        target_only_reason="no_evidence_in_range" if target_only else "", candidate_counts={},
                        candidate_count_all=0, session_methods={}, sessions={}, evidence_before_range=0,
                        evidence_after_range=0, system_session_evidence={}, methods={},
                        host_clock_unreliable=host_clock)


def sv(key: tuple, tier: str, rank: int) -> SessionVerdict:
    return SessionVerdict(session_key=key, account_match="direct", account_match_members=("direct",),
                          account_match_member_count=1, name_check="no_names", name_check_names=(),
                          name_check_event_uids=(), confidence_tier=tier, link_rank=rank, tie=0,
                          rank_basis="only")


def mk_verdicts(hop: Hop, sessions: Sequence[SessionVerdict] = ()) -> HopVerdicts:
    best = min((s.confidence_tier for s in sessions), default="D")
    return HopVerdicts(hop_id=hop.hop_id, sessions={s.session_key: s for s in sessions}, candidate_count_account=0,
                       names=(), no_session_name_check="no_names", best_tier=best)


class World:
    """A hand-built trial: add hops with their source host (and optional session verdicts), then read the edges
    or the paths."""

    def __init__(self) -> None:
        self.hops: list[Hop] = []
        self.links: dict[str, SubjectLinks] = {}
        self.verdicts: dict[str, HopVerdicts] = {}

    def add(self, hop: Hop, source_host: str | None, *, verdicts: Sequence[SessionVerdict] = (),
            host_clock: int = 0, target_only: bool = False) -> Hop:
        self.hops.append(hop)
        self.links[hop.hop_id] = mk_links(hop, source_host, host_clock=host_clock, target_only=target_only)
        self.verdicts[hop.hop_id] = mk_verdicts(hop, verdicts)
        return hop

    def edges(self) -> list[P.ChainEdge]:
        return P.chain_edges(self.hops, self.links, self.verdicts)

    def index(self) -> LinkIndex:
        hs = HopSet(trial_id=TRIAL, hops=list(self.hops), followups=[], counts={})
        return LinkIndex(trial_id=TRIAL, hopset=hs, artefacts=None, links=self.links, confirm={}, data_limits={},
                         counts={}, verdicts=self.verdicts)

    def build(self) -> P.PathSet:
        return P.build_paths(self.index())


def pair(delta_us: int, *, h1_raw_off: int | None = None, h2_raw_off: int | None = None, **h2kw) -> World:
    """H1 enters ep-02 (from ep-01) at BASE; H2 leaves ep-02 (to ep-03) at BASE + delta_us (corrected)."""
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0, us_raw_off_us=h1_raw_off), "ep-01")
    w.add(mk_hop("p-h2", "ep-03", delta_us, us_raw_off_us=h2_raw_off), "ep-02", **h2kw)
    return w


def edge_ids(edges: Sequence[P.ChainEdge]) -> list[tuple[str, str]]:
    return [(e.from_hop_id, e.to_hop_id) for e in edges]


# ------------------------------------------------------------------ constants

def test_link_type_constants() -> None:
    assert P.LINK_HOST_TIME == "host_time"
    assert P.LINK_SESSION == "session"


# ------------------------------------------------------------------ ST-72 host_time edge

def test_host_time_edge_basic() -> None:
    edges = pair(10 * S).edges()
    assert edge_ids(edges) == [("p-h1", "p-h2")]
    e = edges[0]
    assert e.link_type == "host_time"
    assert e.time_delta_ms == 10_000
    assert e.order_within_tolerance == 0          # |10 s| > 5 s
    assert e.clock_unreliable == 0


def test_edge_delta_ms_is_second_first_minus_first_first() -> None:
    e = pair(123_456_000).edges()[0]              # 123.456 s
    assert e.time_delta_ms == 123_456


def test_edge_uses_corrected_time_not_raw_forward() -> None:
    # raw order says H2 is 100 s BEFORE H1; corrected says 10 s after. Edge exists, delta from corrected.
    e = pair(10 * S, h2_raw_off=-100 * S).edges()
    assert edge_ids(e) == [("p-h1", "p-h2")]
    assert e[0].time_delta_ms == 10_000


def test_edge_uses_corrected_time_not_raw_backward() -> None:
    # raw order says H2 is 100 s AFTER H1; corrected says 6 s before H1: outside the tolerance, so no edge.
    assert pair(-6 * S, h2_raw_off=100 * S).edges() == []


def test_edge_h2_before_h1_far_no_edge() -> None:
    assert pair(-60 * S).edges() == []


# ------------------------------------------------------------------ decision 050 item 2: boundary

def test_boundary_minus_5s_exactly_edge_flag_1() -> None:
    e = pair(-TOL).edges()
    assert edge_ids(e) == [("p-h1", "p-h2")]
    assert e[0].order_within_tolerance == 1
    assert e[0].time_delta_ms == -5000


def test_boundary_minus_5s_minus_1us_no_edge() -> None:
    assert pair(-TOL - 1).edges() == []


def test_boundary_plus_5s_exactly_edge_flag_1() -> None:
    e = pair(TOL).edges()
    assert edge_ids(e) == [("p-h1", "p-h2")]
    assert e[0].order_within_tolerance == 1


def test_boundary_plus_5s_plus_1us_flag_0() -> None:
    e = pair(TOL + 1).edges()
    assert edge_ids(e) == [("p-h1", "p-h2")]
    assert e[0].order_within_tolerance == 0


def test_boundary_zero_delta_flag_1() -> None:
    e = pair(0).edges()
    assert edge_ids(e) == [("p-h1", "p-h2")]
    assert e[0].order_within_tolerance == 1


@pytest.mark.parametrize("delta_us, flag", [(-TOL, 1), (-1, 1), (1, 1), (TOL, 1), (TOL + 1, 0), (60 * S, 0)])
def test_flag_is_abs_delta_le_tolerance(delta_us: int, flag: int) -> None:
    assert pair(delta_us).edges()[0].order_within_tolerance == flag


def test_boundary_on_corrected_not_raw() -> None:
    # corrected delta is -5 s - 1 µs (no edge) although raw delta is +5 s (would be an edge)
    assert pair(-TOL - 1, h2_raw_off=TOL).edges() == []
    # corrected delta is exactly -5 s (edge, flag 1) although raw delta is far outside
    e = pair(-TOL, h2_raw_off=-600 * S).edges()
    assert len(e) == 1 and e[0].order_within_tolerance == 1


# ------------------------------------------------------------------ source host rules

def test_unknown_source_host_never_chains() -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-h2", "ep-03", 10 * S), None)          # source host unknown (target_only-like)
    assert w.edges() == []


def test_source_host_not_h1_target_no_edge() -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-h2", "ep-03", 10 * S), "ep-01")       # leaves ep-01, not ep-02
    assert w.edges() == []


def test_unknown_source_host_with_ip_still_never_chains() -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-h2", "ep-03", 10 * S, source_ip="192.168.50.22"), None)
    assert w.edges() == []


# ------------------------------------------------------------------ session vs host_time (050 item 3)

K = skey("ep-02", 0x5000)


def session_world(h2_verdicts: Sequence[SessionVerdict], h1_key: tuple | None = K) -> World:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0, key=h1_key), "ep-01")
    w.add(mk_hop("p-h2", "ep-03", 10 * S), "ep-02", verdicts=h2_verdicts)
    return w


@pytest.mark.parametrize("tier", ["A", "B"])
def test_session_edge_rank1_tier_ab(tier: str) -> None:
    e = session_world([sv(K, tier, 1)]).edges()
    assert edge_ids(e) == [("p-h1", "p-h2")]
    assert e[0].link_type == "session"
    assert e[0].supporting_sessions == (K,)


@pytest.mark.parametrize("tier", ["C", "D"])
def test_shared_session_tier_cd_is_host_time(tier: str) -> None:
    e = session_world([sv(K, tier, 1)]).edges()
    assert len(e) == 1 and e[0].link_type == "host_time"
    assert e[0].supporting_sessions == ()


@pytest.mark.parametrize("tier", ["A", "B"])
def test_shared_session_rank2_is_host_time(tier: str) -> None:
    other = skey("ep-02", 0x6000)
    e = session_world([sv(other, "A", 1), sv(K, tier, 2)]).edges()
    assert len(e) == 1 and e[0].link_type == "host_time"


def test_session_edge_requires_full_key_boot_epoch() -> None:
    same_id_other_boot = skey("ep-02", 0x5000, epoch=4)
    e = session_world([sv(same_id_other_boot, "A", 1)]).edges()
    assert len(e) == 1 and e[0].link_type == "host_time"


def test_session_edge_requires_full_key_seq() -> None:
    reopened = skey("ep-02", 0x5000, seq=1)
    e = session_world([sv(reopened, "A", 1)]).edges()
    assert len(e) == 1 and e[0].link_type == "host_time"


def test_session_edge_other_session_no_match_is_host_time() -> None:
    e = session_world([sv(skey("ep-02", 0x7777), "A", 1)]).edges()
    assert len(e) == 1 and e[0].link_type == "host_time"


def test_session_edge_h1_without_session_key_is_host_time() -> None:
    e = session_world([sv(K, "A", 1)], h1_key=None).edges()
    assert len(e) == 1 and e[0].link_type == "host_time"


def test_session_edge_tie_both_rank1_one_matching_ab_gives_session() -> None:
    other = skey("ep-02", 0x6000)
    e = session_world([sv(other, "C", 1), sv(K, "A", 1)]).edges()
    assert len(e) == 1 and e[0].link_type == "session"


def test_session_edge_does_not_relax_time_rule() -> None:
    # shared A session but H2 is 6 s before H1: no edge at all (the time rule still applies)
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0, key=K), "ep-01")
    w.add(mk_hop("p-h2", "ep-03", -6 * S), "ep-02", verdicts=[sv(K, "A", 1)])
    assert w.edges() == []


def test_first_ranked_helpers() -> None:
    a, b, c = skey("ep-02", 1), skey("ep-02", 2), skey("ep-02", 3)
    hv = mk_verdicts(mk_hop("x", "ep-03", 0), [sv(a, "A", 1), sv(b, "C", 1), sv(c, "B", 2)])
    assert P.first_ranked_sessions(hv) == {a, b}
    assert P.first_ranked_ab_sessions(hv) == {a}


# ------------------------------------------------------------------ clock_unreliable on an edge

@pytest.mark.parametrize("h1_clock, h2_clock, h1_host, h2_host, expected", [
    (0, 0, 0, 0, 0),
    (1, 0, 0, 0, 1),
    (0, 1, 0, 0, 1),
    (0, 0, 1, 0, 1),
    (0, 0, 0, 1, 1),
    (1, 1, 1, 1, 1),
])
def test_edge_clock_unreliable_is_max_of_hops(h1_clock: int, h2_clock: int, h1_host: int, h2_host: int,
                                              expected: int) -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0, clock=h1_clock), "ep-01", host_clock=h1_host)
    w.add(mk_hop("p-h2", "ep-03", 10 * S, clock=h2_clock), "ep-02", host_clock=h2_host)
    assert w.edges()[0].clock_unreliable == expected


def test_hop_clock_unreliable_definition() -> None:
    h = mk_hop("x", "ep-02", 0, clock=0)
    assert P.hop_clock_unreliable(h, mk_links(h, "ep-01", host_clock=0)) == 0
    assert P.hop_clock_unreliable(h, mk_links(h, "ep-01", host_clock=1)) == 1
    h1 = mk_hop("y", "ep-02", 0, clock=1)
    assert P.hop_clock_unreliable(h1, mk_links(h1, "ep-01", host_clock=0)) == 1
    assert P.hop_clock_unreliable(h1, mk_links(h1, "ep-01", host_clock=1)) == 1


# ------------------------------------------------------------------ Q15 (b) machine accounts

def test_chainable_definition() -> None:
    assert P.chainable(mk_hop("a", "ep-02", 0)) is True
    assert P.chainable(mk_hop("a", "ep-02", 0, machine=True)) is False
    assert P.chainable(mk_hop("a", "ep-02", 0, triggers=[])) is False


def test_machine_only_hop_no_edge_as_second_hop() -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-h2", "dc01", 10 * S, machine=True), "ep-02")
    assert w.edges() == []


def test_machine_only_hop_no_edge_as_first_hop() -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0, machine=True), "dc01")
    w.add(mk_hop("p-h2", "ep-03", 10 * S), "ep-02")
    assert w.edges() == []


def test_machine_only_hop_still_its_own_path() -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-h2", "dc01", 10 * S, machine=True), "ep-02")
    ps = w.build()
    assert [p.hop_ids for p in ps.paths] == [["p-h1"], ["p-h2"]]
    assert [p.isolated for p in ps.paths] == [1, 1]
    assert ps.hop_facts["p-h2"].in_path == 1
    assert ps.hop_facts["p-h2"].chain_parent_count == 0
    assert ps.counts["seeds"] == 2
    assert ps.counts["chainable_seeds"] == 1


def test_mixed_machine_and_user_member_still_chains() -> None:
    user = logon("p-h2-m1", "ep-03", BASE + 10 * S + 1000, machine=0, triggers=["T-x"])
    mixed = mk_hop("p-h2", "ep-03", 10 * S, machine=True, extra_members=[user])
    assert mixed.machine_account_only == 0
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0), "ep-01")
    w.add(mixed, "ep-02")
    assert edge_ids(w.edges()) == [("p-h1", "p-h2")]
    assert len(w.build().paths) == 1


# ------------------------------------------------------------------ ST-23 non-seed hops

def non_seed_world() -> World:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-h2", "ep-03", 10 * S, triggers=[]), "ep-02")     # would chain, but has no trigger
    w.add(mk_hop("p-h3", "ep-04", 20 * S), "ep-03")                  # would chain from h2, if h2 counted
    return w


def test_non_seed_hop_gets_no_edge_either_direction() -> None:
    assert non_seed_world().edges() == []


def test_non_seed_hop_in_no_path() -> None:
    ps = non_seed_world().build()
    assert [p.hop_ids for p in ps.paths] == [["p-h1"], ["p-h3"]]
    f = ps.hop_facts["p-h2"]
    assert (f.in_path, f.path_id, f.chain_parent_count, f.chain_parent_hop_ids, f.multi_chain_parent) == \
        (0, None, 0, [], 0)


def test_non_seed_counts_listed() -> None:
    c = non_seed_world().build().counts
    assert c["hops_in_no_path"] == ["p-h2"]
    assert c["non_seed_hops"] == ["p-h2"]
    assert c["seeds"] == 2


def test_hop_facts_cover_every_hop_seed_or_not() -> None:
    ps = non_seed_world().build()
    assert sorted(ps.hop_facts) == ["p-h1", "p-h2", "p-h3"]


# ------------------------------------------------------------------ s05 shape: two parents into one hop (L-ST2)

def s05_world() -> World:
    # ids deliberately NOT in time order: p-h0009 is the earlier parent, p-h0002 the later one
    w = World()
    w.add(mk_hop("p-h0009", "ep-02", 10 * S), "ep-01")
    w.add(mk_hop("p-h0002", "ep-02", 50 * S), "ep-03")
    w.add(mk_hop("p-h0005", "ep-04", 200 * S), "ep-02")
    return w


def test_two_parents_two_host_time_edges() -> None:
    e = s05_world().edges()
    assert edge_ids(e) == [("p-h0009", "p-h0005"), ("p-h0002", "p-h0005")]
    assert [x.link_type for x in e] == ["host_time", "host_time"]
    assert [x.time_delta_ms for x in e] == [190_000, 150_000]


def test_two_parents_one_merged_path() -> None:
    ps = s05_world().build()
    assert len(ps.paths) == 1
    p = ps.paths[0]
    assert p.path_id == "s05_t00-p0001"
    assert p.hop_ids == ["p-h0009", "p-h0002", "p-h0005"]       # time order, not id order
    assert p.n_hops == 3
    assert p.isolated == 0
    assert p.edge_types == {"host_time": 2, "session": 0}
    assert p.hosts == ["ep-01>ep-02", "ep-03>ep-02", "ep-02>ep-04"]
    assert p.merged_from == ["p-h0009>p-h0005", "p-h0002>p-h0005"]


def test_two_parents_child_flagged_multi_chain_parent() -> None:
    ps = s05_world().build()
    f = ps.hop_facts["p-h0005"]
    assert f.multi_chain_parent == 1
    assert f.chain_parent_count == 2
    assert f.chain_parent_hop_ids == ["p-h0009", "p-h0002"]     # hop order
    assert f.in_path == 1 and f.path_id == "s05_t00-p0001"
    for parent in ("p-h0009", "p-h0002"):
        pf = ps.hop_facts[parent]
        assert (pf.chain_parent_count, pf.multi_chain_parent, pf.chain_parent_hop_ids) == (0, 0, [])
        assert pf.path_id == "s05_t00-p0001"


def test_two_parents_counts() -> None:
    c = s05_world().build().counts
    assert c["chain_edges_by_type"] == {"host_time": 2, "session": 0}
    assert c["paths"] == 1
    assert c["multi_hop_paths"] == 1
    assert c["isolated_paths"] == 0
    assert c["multi_chain_parent_hops"] == {"p-h0005": ["p-h0009", "p-h0002"]}
    assert c["hops_in_no_path"] == []
    assert c["non_seed_hops"] == []


def test_two_session_edges_edge_types_count() -> None:
    w = World()
    ka, kb = skey("ep-02", 0x5000), skey("ep-02", 0x5001)
    w.add(mk_hop("p-h1", "ep-02", 0, key=ka), "ep-01")
    w.add(mk_hop("p-h2", "ep-02", 10 * S, key=kb), "ep-03")
    w.add(mk_hop("p-h3", "ep-04", 20 * S), "ep-02", verdicts=[sv(ka, "A", 1), sv(kb, "B", 1)])
    p = w.build().paths[0]
    assert p.edge_types == {"host_time": 0, "session": 2}
    assert [e.link_type for e in p.edges] == ["session", "session"]


# ------------------------------------------------------------------ chains and merge

def line_world() -> World:
    w = World()
    w.add(mk_hop("p-a", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-b", "ep-03", 10 * S), "ep-02")
    w.add(mk_hop("p-c", "ep-04", 20 * S), "ep-03")
    return w


def test_chain_abc_one_path() -> None:
    ps = line_world().build()
    assert len(ps.paths) == 1
    p = ps.paths[0]
    assert p.hop_ids == ["p-a", "p-b", "p-c"]
    assert p.merged_from == ["p-a>p-b>p-c"]
    assert p.hosts == ["ep-01>ep-02", "ep-02>ep-03", "ep-03>ep-04"]
    assert p.edge_types == {"host_time": 2, "session": 0}
    assert p.isolated == 0
    assert ps.hop_facts["p-b"].chain_parent_hop_ids == ["p-a"]
    assert ps.hop_facts["p-b"].multi_chain_parent == 0


def test_transitive_merge_two_parents_then_child() -> None:
    w = World()
    w.add(mk_hop("p-a", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-b", "ep-02", 5 * S), "ep-05")
    w.add(mk_hop("p-c", "ep-03", 10 * S), "ep-02")
    w.add(mk_hop("p-d", "ep-04", 20 * S), "ep-03")
    ps = w.build()
    assert edge_ids(w.edges()) == [("p-a", "p-c"), ("p-b", "p-c"), ("p-c", "p-d")]
    assert len(ps.paths) == 1
    p = ps.paths[0]
    assert p.hop_ids == ["p-a", "p-b", "p-c", "p-d"]
    assert p.merged_from == ["p-a>p-c>p-d", "p-b>p-c>p-d"]
    assert ps.hop_facts["p-c"].multi_chain_parent == 1
    assert ps.hop_facts["p-d"].multi_chain_parent == 0


def test_one_parent_two_children_one_path() -> None:
    w = World()
    w.add(mk_hop("p-a", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-b", "ep-03", 10 * S), "ep-02")
    w.add(mk_hop("p-c", "ep-04", 20 * S), "ep-02")
    ps = w.build()
    assert len(ps.paths) == 1
    assert ps.paths[0].merged_from == ["p-a>p-b", "p-a>p-c"]
    assert all(f.multi_chain_parent == 0 for f in ps.hop_facts.values())


def test_unrelated_chains_stay_separate_paths() -> None:
    w = line_world()
    w.add(mk_hop("p-x", "ep-06", 5 * S), "ep-05")
    ps = w.build()
    assert [p.hop_ids for p in ps.paths] == [["p-a", "p-b", "p-c"], ["p-x"]]
    assert [p.isolated for p in ps.paths] == [0, 1]
    assert ps.counts["multi_hop_paths"] == 1
    assert ps.counts["isolated_paths"] == 1


# ------------------------------------------------------------------ cycles

def cycle_world() -> World:
    w = World()
    w.add(mk_hop("p-a", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-b", "ep-01", 2 * S), "ep-02")       # leaves ep-02 (A's target) and enters ep-01 (A's source)
    return w


def test_two_cycle_edges_and_termination() -> None:
    e = cycle_world().edges()
    assert edge_ids(e) == [("p-a", "p-b"), ("p-b", "p-a")]
    assert [x.time_delta_ms for x in e] == [2000, -2000]
    assert [x.order_within_tolerance for x in e] == [1, 1]


def test_two_cycle_one_path() -> None:
    ps = cycle_world().build()
    assert len(ps.paths) == 1
    p = ps.paths[0]
    assert p.hop_ids == ["p-a", "p-b"]
    assert p.n_hops == 2 and p.isolated == 0
    assert p.merged_from == ["p-a>p-b", "p-b>p-a"]
    assert ps.hop_facts["p-a"].chain_parent_hop_ids == ["p-b"]
    assert ps.hop_facts["p-b"].chain_parent_hop_ids == ["p-a"]


def test_maximal_chains_two_cycle_direct() -> None:
    w = cycle_world()
    assert P.maximal_chains(["p-a", "p-b"], w.edges()) == [("p-a", "p-b"), ("p-b", "p-a")]


# ------------------------------------------------------------------ maximal_chains direct

def fake_edge(a: str, b: str) -> P.ChainEdge:
    return P.ChainEdge(from_hop_id=a, to_hop_id=b, link_type="host_time", time_delta_us=S, time_delta_ms=1000,
                       order_within_tolerance=1, clock_unreliable=0)


def test_maximal_chains_single_hop() -> None:
    assert P.maximal_chains(["a"], []) == [("a",)]


def test_maximal_chains_line() -> None:
    assert P.maximal_chains(["a", "b", "c"], [fake_edge("a", "b"), fake_edge("b", "c")]) == [("a", "b", "c")]


def test_maximal_chains_diamond() -> None:
    edges = [fake_edge("a", "b"), fake_edge("a", "c"), fake_edge("b", "d"), fake_edge("c", "d")]
    assert P.maximal_chains(["a", "b", "c", "d"], edges) == [("a", "b", "d"), ("a", "c", "d")]


def test_maximal_chains_two_parents() -> None:
    edges = [fake_edge("a", "c"), fake_edge("b", "c")]
    assert P.maximal_chains(["a", "b", "c"], edges) == [("a", "c"), ("b", "c")]


def test_maximal_chains_ignores_foreign_edges() -> None:
    assert P.maximal_chains(["a", "b"], [fake_edge("a", "z")]) == [("a",), ("b",)]


def test_components_direct() -> None:
    edges = [fake_edge("a", "c"), fake_edge("b", "c"), fake_edge("d", "e")]
    assert P.components(["a", "b", "c", "d", "e", "f"], edges) == [["a", "b", "c"], ["d", "e"], ["f"]]


def test_components_ignores_foreign_edges() -> None:
    assert P.components(["a", "b"], [fake_edge("a", "z")]) == [["a"], ["b"]]


def test_chain_text_and_path_id() -> None:
    assert P.chain_text(("h1", "h2", "h3")) == "h1>h2>h3"
    assert P.chain_text(("h1",)) == "h1"
    assert P.path_id("s05_t00", 1) == "s05_t00-p0001"
    assert P.path_id("s05_t00", 12345) == "s05_t00-p12345"


# ------------------------------------------------------------------ ST-74 isolated target_only seed

def test_isolated_target_only_seed_is_a_path() -> None:
    w = World()
    h = w.add(mk_hop("p-h1", "ep-02", 0), None, target_only=True)
    ps = w.build()
    assert len(ps.paths) == 1
    p = ps.paths[0]
    assert p.hop_ids == [h.hop_id]
    assert p.n_hops == 1
    assert p.isolated == 1
    assert p.merged_from == ["p-h1"]
    assert p.edge_types == {"host_time": 0, "session": 0}
    assert p.edges == []
    assert ps.counts["isolated_paths"] == 1


def test_target_only_seed_listed_even_next_to_chain() -> None:
    w = line_world()
    w.add(mk_hop("p-z", "ep-02", 100 * S), None, target_only=True)
    ps = w.build()
    assert [p.hop_ids for p in ps.paths] == [["p-a", "p-b", "p-c"], ["p-z"]]
    assert ps.paths[1].isolated == 1


# ------------------------------------------------------------------ ids, order, hosts, triggers (050 item 6)

def test_path_ids_numbered_by_earliest_hop_corrected_time_then_hop_id() -> None:
    w = World()
    # input order and id order differ from time order; corrected time decides, raw time is a decoy
    w.add(mk_hop("p-z1", "ep-02", 30 * S, us_raw_off_us=-500 * S), "ep-01")
    w.add(mk_hop("p-a1", "ep-03", 10 * S, us_raw_off_us=900 * S), "ep-01")
    w.add(mk_hop("p-b1", "ep-04", 10 * S), "ep-01")                      # same time as p-a1: id breaks the tie
    ps = w.build()
    assert [p.path_id for p in ps.paths] == [f"{TRIAL}-p000{i}" for i in (1, 2, 3)]
    assert [p.hop_ids for p in ps.paths] == [["p-a1"], ["p-b1"], ["p-z1"]]


def test_hop_ids_in_path_in_time_order_by_corrected() -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0, us_raw_off_us=500 * S), "ep-01")
    w.add(mk_hop("p-h2", "ep-03", 3 * S, us_raw_off_us=-500 * S), "ep-02")
    assert w.build().paths[0].hop_ids == ["p-h1", "p-h2"]


def test_hosts_one_source_gt_target_per_hop() -> None:
    p = line_world().build().paths[0]
    assert p.hosts == ["ep-01>ep-02", "ep-02>ep-03", "ep-03>ep-04"]


def test_hosts_source_falls_back_to_ip_then_empty() -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0, source_ip="192.168.50.21"), None)
    w.add(mk_hop("p-h2", "ep-03", 100 * S, source_ip=None), None)
    ps = w.build()
    assert ps.paths[0].hosts == ["192.168.50.21>ep-02"]
    assert ps.paths[1].hosts == [">ep-03"]


def test_hosts_prefers_source_host_over_ip() -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0, source_ip="192.168.50.21"), "ep-01")
    assert w.build().paths[0].hosts == ["ep-01>ep-02"]


def test_source_label_and_hop_hosts_direct() -> None:
    h = mk_hop("x", "ep-02", 0, source_ip="1.2.3.4")
    assert P.source_label(h, mk_links(h, "ep-01")) == "ep-01"
    assert P.source_label(h, mk_links(h, None)) == "1.2.3.4"
    assert P.source_label(h, None) == "1.2.3.4"
    h2 = mk_hop("y", "ep-02", 0, source_ip=None)
    assert P.source_label(h2, mk_links(h2, None)) == ""
    assert P.hop_hosts(h, mk_links(h, "ep-01")) == "ep-01>ep-02"


def test_seed_trigger_ids_sorted_union() -> None:
    w = World()
    w.add(mk_hop("p-h1", "ep-02", 0, triggers=["R6-3", "R4-9"]), "ep-01")
    w.add(mk_hop("p-h2", "ep-03", 10 * S, triggers=["R4-9", "R4-1"]), "ep-02")
    assert w.build().paths[0].seed_trigger_ids == ["R4-1", "R4-9", "R6-3"]


def test_path_edges_hold_only_own_edges() -> None:
    w = line_world()
    w.add(mk_hop("p-x", "ep-06", 5 * S), "ep-05")
    w.add(mk_hop("p-y", "ep-07", 8 * S), "ep-06")
    ps = w.build()
    own = [edge_ids(p.edges) for p in ps.paths]
    assert own == [[("p-a", "p-b"), ("p-b", "p-c")], [("p-x", "p-y")]]
    assert edge_ids(ps.edges) == [("p-a", "p-b"), ("p-x", "p-y"), ("p-b", "p-c")] or \
        sorted(edge_ids(ps.edges)) == sorted(sum(own, []))


def test_pathset_edges_in_from_hop_then_to_hop_order() -> None:
    w = s05_world()
    assert edge_ids(w.build().edges) == [("p-h0009", "p-h0005"), ("p-h0002", "p-h0005")]


# ------------------------------------------------------------------ ST-04 / ST-70 coverage

def test_every_seed_in_exactly_one_path_no_hop_in_two() -> None:
    w = World()
    w.add(mk_hop("p-a", "ep-02", 0), "ep-01")
    w.add(mk_hop("p-b", "ep-03", 10 * S), "ep-02")
    w.add(mk_hop("p-c", "ep-04", 20 * S), "ep-03")
    w.add(mk_hop("p-m", "dc01", 25 * S, machine=True), "ep-03")        # machine-only seed
    w.add(mk_hop("p-n", "ep-02", 30 * S, triggers=[]), "ep-01")        # non-seed
    w.add(mk_hop("p-t", "ep-02", 40 * S), None, target_only=True)      # isolated target_only seed
    w.add(mk_hop("p-u", "ep-06", 50 * S), "ep-05")
    ps = w.build()
    seeds = sorted(h.hop_id for h in w.hops if h.is_seed)
    in_paths = [h for p in ps.paths for h in p.hop_ids]
    assert sorted(in_paths) == seeds                   # no seed dropped, no hop twice, no non-seed added
    assert len(in_paths) == len(set(in_paths))
    for p in ps.paths:
        for h in p.hop_ids:
            assert ps.hop_facts[h].path_id == p.path_id and ps.hop_facts[h].in_path == 1
    assert ps.hop_facts["p-n"].in_path == 0
    assert ps.counts["hops_in_no_path"] == ["p-n"]
    assert ps.counts["seeds"] == len(seeds)
    assert ps.counts["paths"] == len(ps.paths)


def test_no_hops_gives_empty_pathset() -> None:
    ps = World().build()
    assert ps.paths == [] and ps.edges == [] and ps.hop_facts == {}
    assert ps.counts["paths"] == 0


def test_build_paths_is_pure_and_repeatable() -> None:
    w = s05_world()
    a, b = w.build(), w.build()
    assert [(p.path_id, p.hop_ids, p.merged_from) for p in a.paths] == \
        [(p.path_id, p.hop_ids, p.merged_from) for p in b.paths]
    assert a.counts == b.counts


def test_pathset_trial_id() -> None:
    assert s05_world().build().trial_id == TRIAL
