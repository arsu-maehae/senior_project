"""Tests for T7.3 task 2: remote logons, hop groups, protocol, seeds, flags and follow-up logons
(`stitch.hops`, `stitch.inputs.read_gate_rows`). Fast: synthetic gate rows plus synthetic event rows, nothing real.

Written from docs/specs/03_stitch.md (ST-03, ST-05, ST-20..ST-24, ST-26, STT-02, section 6), decision 048 items 7-9 and
the T7.3 plan task 2, not from the implementation (the code was read only for names and signatures).

Readings tested as stated by the owner: port 0 is treated like NULL; prev / next gaps and `merges_at_3s` look at
neighbouring hops only (never a follow-up group); `inside_gap_max_ms` is None for a one-member hop; a NULL account is
its own value for `mixed_account`; a follow-up group is never "the hop before"; follow-up rows are kind
`followup_logon`, method `port_reuse`, tier C, `candidate_count` 1.
"""
from __future__ import annotations

import itertools
import random
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_fixtures as cf  # noqa: E402
import stitch_fixtures as sf  # noqa: E402
from clock_offset.correct import load_clock_changes, load_offsets  # noqa: E402
from gate.classify import ip_kind  # noqa: E402
from gate.timeutil import to_us  # noqa: E402
from stitch.hops import (FollowupGroup, Hop, HopSet, LogonGroup, RemoteLogon, attach_followups, build_hops,  # noqa: E402
                         group_hops, hop_id_of, protocol_of, remote_logons)
from stitch.index import build_index  # noqa: E402
from stitch.inputs import GateRows, StitchError, read_gate_rows  # noqa: E402
from stitch.params import StitchParams  # noqa: E402
from stitch.scan import scan_rows  # noqa: E402

TRIAL = sf.TRIAL
START_US = to_us(sf.WIN_START)
END_US = to_us(sf.WIN_END)
P = StitchParams()
IP = "192.168.50.21"
IP2 = "192.168.50.23"
R4, R5, R6, R8 = "R4_smb", "R5_rdp", "R6_service", "R8_winrm"


# ------------------------------------------------------------------------------------------------ the synthetic world
@dataclass
class World:
    events: list[dict] = field(default_factory=list)
    triggers: list[dict] = field(default_factory=list)
    unmatched: list[dict] = field(default_factory=list)
    _lid: itertools.count = field(default_factory=lambda: itertools.count(1000))

    def logon(self, uid: str, off: float, *, lid: int | None = None, ip: str | None = IP, port: int | None = 50000,
              account: str | None = "acct_a", host: str = "ep-02", rule: str | None = None, machine: int = 0,
              record_id: int | str = "auto", in_gate: bool = True, kind: str = "4624") -> str:
        """One 4624 event and (when `in_gate`) its gate row: a trigger row when `rule` is given, else an unmatched
        row. `off` is seconds after 10:30:00 of the logged time. Returns the uid."""
        lid = next(self._lid) if lid is None else lid
        self.events.append(sf.ev(uid, "Security", 4624, host=host, off=off, logon_type=3, target_logon_id=lid,
                                 account_name=account, source_ip=ip, source_port=port,
                                 authentication_package="NTLM", record_id=record_id))
        if in_gate:
            row = {"trigger_id": f"{'t' if rule else 'u'}-{uid}", "host": host, "anchor_logon_uid": uid,
                   "trigger_event_uid": uid, "target_logon_id": str(lid), "source_ip": ip or "",
                   "ip_kind": ip_kind(ip), "machine_account": str(machine), "clock_unreliable": "0"}
            if rule:
                row["rule"] = rule
                self.triggers.append(row)
            else:
                self.unmatched.append(row)
        return uid

    def burst(self, prefix: str, offsets, **kw) -> list[str]:
        """Logons `prefix0`, `prefix1`, ... at the given offsets (all with the same keywords)."""
        return [self.logon(f"{prefix}{i}", o, **kw) for i, o in enumerate(offsets)]


def clocks(tmp_path: Path, spec: dict):
    repo = tmp_path / "clk"
    cf.write_clock_files(repo, TRIAL, "0" * 64, spec, None)
    return load_offsets(cf.offsets_path(repo, TRIAL)), load_clock_changes(cf.changes_path(repo, TRIAL))


def scan_of(w: World, offsets=None, changes=()):
    return scan_rows([dict(e) for e in w.events], START_US, END_US, offsets, changes)


def gate_of(w: World) -> GateRows:
    return GateRows(triggers=[dict(r) for r in w.triggers], unmatched=[dict(r) for r in w.unmatched], supporting=[])


def build(w: World, params: StitchParams = P, offsets=None, changes=()) -> HopSet:
    scan = scan_of(w, offsets, changes)
    sessions = build_index(TRIAL, scan).sessions
    return build_hops(TRIAL, gate_of(w), scan, sessions, params)


def logons_of(w: World, offsets=None) -> list[RemoteLogon]:
    scan = scan_of(w, offsets)
    return remote_logons(gate_of(w), scan, build_index(TRIAL, scan).sessions)


def hop_of(hs: HopSet, uid: str) -> Hop:
    found = [h for h in hs.hops if any(uid in m.event_uids for m in h.members)]
    assert len(found) == 1, f"{uid} is a member of {len(found)} hops"
    return found[0]


def member_sets(hs: HopSet) -> set[frozenset[str]]:
    return {frozenset(m.uid for m in h.members) for h in hs.hops}


def group_sets(groups: list[LogonGroup]) -> set[frozenset[str]]:
    return {frozenset(m.uid for m in g.members) for g in groups}


def followup_uids(hs: HopSet) -> set[str]:
    return {lg.uid for f in hs.followups for lg in f.logons}


# ================================================================================================ contract
def test_contract_types_and_ids_of_a_small_trial():
    w = World()
    w.burst("a", [0.0, 0.5], ip=IP, rule=R4)
    w.logon("b0", 60.0, ip=IP2, rule=R8)
    hs = build(w)
    assert isinstance(hs, HopSet) and hs.trial_id == TRIAL
    assert all(isinstance(h, Hop) for h in hs.hops) and all(isinstance(f, FollowupGroup) for f in hs.followups)
    assert [h.hop_id for h in hs.hops] == [f"{TRIAL}-h0001", f"{TRIAL}-h0002"]
    assert hop_id_of(TRIAL, 1) == f"{TRIAL}-h0001" and hop_id_of(TRIAL, 12) == f"{TRIAL}-h0012"
    h = hs.hops[0]
    assert h.target_host == "ep-02" and h.source_ip == IP and h.ip_kind == "ipv4"
    assert h.member_count == 2 and h.member_uids == ["a0", "a1"]
    assert all(isinstance(m, RemoteLogon) for m in h.members)
    assert [m.logon_id_hex for m in h.members] == ["0x3e8", "0x3e9"]            # D1: hex for display only
    assert [m.logon_id for m in h.members] == [1000, 1001]
    assert h.first_utc == sf.at(0.0) and h.first_utc_corrected == sf.at(0.0)


def test_counts_are_consistent_with_the_hops():
    w = World()
    w.burst("a", [0.0, 0.5], ip=IP, rule=R4)
    w.logon("u", 60.0, ip=IP, rule=None)
    w.logon("blank0", 100.0, ip=None)
    hs = build(w)
    assert hs.counts["remote_logons"] == 4
    assert hs.counts["hops"] == len(hs.hops) == 3
    assert hs.counts["seeds"] == sum(h.is_seed for h in hs.hops) == 1
    assert hs.counts["followup_groups"] == len(hs.followups) == 0
    assert hs.counts["blank_ip_hops"] == 1


def test_remote_logons_are_sorted_by_host_logged_time_then_uid_and_carry_gate_facts():
    w = World()
    w.logon("z", 1.0, host="ep-03", ip=IP, rule=R8, port=51000, account="Alice", machine=0)
    w.logon("b", 2.0, host="ep-02", ip="::ffff:192.168.50.21", rule=None, machine=1)
    w.logon("a", 2.0, host="ep-02", ip=IP, rule=R4)
    lgs = logons_of(w)
    assert [lg.uid for lg in lgs] == ["a", "b", "z"]
    by = {lg.uid: lg for lg in lgs}
    assert by["b"].source_ip == IP                                     # IPv4-mapped IPv6 normalised (spec 2)
    assert by["b"].machine_account == 1 and by["a"].machine_account == 0
    assert by["z"].rules == [R8] and by["z"].trigger_ids == ["t-z"] and by["z"].is_trigger
    assert by["b"].rules == [] and by["b"].trigger_ids == [] and not by["b"].is_trigger
    assert by["z"].source_port == 51000 and by["z"].account == "Alice"


def test_an_ipv4_mapped_source_joins_the_group_of_the_plain_address():
    w = World()
    w.logon("p", 0.0, ip=IP, rule=R4)
    w.logon("m", 0.5, ip="::ffff:192.168.50.21", rule=R4)
    hs = build(w)
    assert len(hs.hops) == 1 and hs.hops[0].member_count == 2


# ================================================================================================ ST-20 gaps
@pytest.mark.parametrize("gap,hops", [(1.999, 1), (2.0, 1), (2.000001, 2), (2.001, 2), (5.0, 2)])
def test_a_gap_of_exactly_group_gap_joins_and_one_microsecond_more_splits(gap, hops):
    w = World()
    w.logon("a", 0.0, rule=R4, port=50001, account="acct_a")
    w.logon("b", gap, rule=R4, port=50002, account="acct_b")
    hs = build(w)
    assert len(hs.hops) == hops, f"gap {gap}: {len(hs.hops)} hops"
    assert (hop_of(hs, "a") is hop_of(hs, "b")) == (hops == 1)


def test_gap_is_between_consecutive_members_and_not_from_the_first():
    w = World()
    w.burst("c", [0.0, 1.9, 3.8, 5.7], rule=R4)                       # 1.9 s steps: 5.7 s long, still one hop
    w.logon("d", 8.0, rule=R4)                                          # 2.3 s after the last: a new hop
    hs = build(w)
    assert [h.member_uids for h in hs.hops] == [["c0", "c1", "c2", "c3"], ["d"]]


def test_group_gap_is_a_parameter():
    w = World()
    w.burst("c", [0.0, 3.0, 6.0], rule=R4)
    assert len(build(w).hops) == 3
    assert len(build(w, replace(P, group_gap_s=3.0)).hops) == 1


def test_grouping_uses_same_host_logged_time_so_a_host_offset_changes_no_group(tmp_path):
    w = World()
    w.burst("a", [0.0, 1.0, 2.5], rule=R4)                              # 1.0 then 1.5: one hop of three
    w.burst("b", [2.5 + 1.9, 2.5 + 4.0], rule=R4)                       # 1.9 s after a2: joins; then 2.1 s: splits
    base = build(w)
    offs, chg = clocks(tmp_path, cf.offsets_spec(ep_02=(7000, "ok", True)))
    shifted = build(w, offsets=offs, changes=chg)
    assert member_sets(shifted) == member_sets(base)
    assert [h.member_uids for h in base.hops] == [["a0", "a1", "a2", "b0"], ["b1"]]
    assert shifted.hops[0].first_us != shifted.hops[0].first_us_raw     # the correction was really applied
    assert shifted.hops[0].first_us_raw == base.hops[0].first_us_raw
    assert [h.inside_gap_max_ms for h in shifted.hops] == [h.inside_gap_max_ms for h in base.hops]


def test_the_same_source_ip_on_two_target_hosts_is_two_hops():
    w = World()
    w.logon("a", 0.0, host="ep-02", rule=R4)
    w.logon("b", 0.5, host="ep-03", rule=R4)
    hs = build(w)
    assert len(hs.hops) == 2 and {h.target_host for h in hs.hops} == {"ep-02", "ep-03"}


def test_two_source_ips_on_one_target_host_are_two_hops_even_at_the_same_instant():
    w = World()
    w.logon("a", 0.0, ip=IP, rule=R4)
    w.logon("b", 0.0, ip=IP2, rule=R4)
    hs = build(w)
    assert len(hs.hops) == 2 and {h.source_ip for h in hs.hops} == {IP, IP2}


# ================================================================================================ ST-21 account
def test_two_accounts_in_one_group_set_mixed_account_and_the_account_is_never_a_key():
    w = World()
    w.logon("a", 0.0, rule=R4, account="acct_a")
    w.logon("b", 0.4, rule=None, account="acct_b")
    hs = build(w)
    assert len(hs.hops) == 1 and hs.hops[0].mixed_account == 1 and hs.hops[0].member_count == 2


def test_one_account_gives_mixed_account_zero_and_a_null_account_counts_as_its_own_value():
    w = World()
    w.burst("a", [0.0, 0.3], rule=R4, account="acct_a")
    w.burst("n", [10.0, 10.3], rule=R4, account=None, ip=IP2)           # two NULL accounts: one value
    w.burst("m", [20.0, 20.3], rule=R4, account="acct_a", ip="192.168.50.22")
    w.logon("m2", 20.5, rule=R4, account=None, ip="192.168.50.22")      # NULL next to an account: two values
    hs = build(w)
    assert hop_of(hs, "a0").mixed_account == 0
    assert hop_of(hs, "n0").mixed_account == 0
    assert hop_of(hs, "m0").mixed_account == 1 and hop_of(hs, "m2") is hop_of(hs, "m0")


def test_different_accounts_never_split_a_group_and_the_same_account_never_joins_two():
    w = World()
    w.logon("a", 0.0, rule=R4, account="acct_a")
    w.logon("b", 1.0, rule=R4, account="acct_b")
    w.logon("c", 2.0, rule=R4, account="acct_a")
    w.logon("d", 10.0, rule=R4, account="acct_a")
    hs = build(w)
    assert [h.member_uids for h in hs.hops] == [["a", "b", "c"], ["d"]]


# ================================================================================================ ST-24 port
def test_the_same_ip_and_port_in_two_groups_lists_each_hop_in_the_other_and_is_never_a_key():
    w = World()
    w.burst("a", [0.0, 0.4], rule=R4, port=49734)
    w.burst("b", [30.0, 30.4], rule=R4, port=49734)
    w.logon("c", 60.0, rule=R4, port=49999)
    hs = build(w)
    assert len(hs.hops) == 3
    ha, hb, hc = hop_of(hs, "a0"), hop_of(hs, "b0"), hop_of(hs, "c")
    assert ha.shares_port_with_hops == [hb.hop_id] and hb.shares_port_with_hops == [ha.hop_id]
    assert hc.shares_port_with_hops == []


def test_two_logons_of_one_burst_with_different_ports_are_one_group():
    w = World()
    w.logon("a", 0.0, rule=R4, port=50001)
    w.logon("b", 0.5, rule=R4, port=50002)
    w.logon("c", 1.0, rule=R4, port=50001)
    hs = build(w)
    assert len(hs.hops) == 1 and hs.hops[0].shares_port_with_hops == []


def test_a_port_shared_with_another_source_ip_is_not_shared():
    w = World()
    w.logon("a", 0.0, rule=R4, ip=IP, port=49734)
    w.logon("b", 30.0, rule=R4, ip=IP2, port=49734)
    hs = build(w)
    assert all(h.shares_port_with_hops == [] for h in hs.hops)


@pytest.mark.parametrize("port", [0, None])
def test_port_zero_and_null_never_share_a_port(port):
    w = World()
    w.logon("a", 0.0, rule=R4, port=port)
    w.logon("b", 30.0, rule=R4, port=port)
    hs = build(w)
    assert len(hs.hops) == 2 and all(h.shares_port_with_hops == [] for h in hs.hops)


# ================================================================================================ blank IP
def test_a_blank_ip_logon_is_a_hop_of_its_own_even_a_tenth_of_a_second_after_another():
    w = World()
    w.logon("b0", 0.0, ip=None, rule=R4)
    w.logon("b1", 0.1, ip=None, rule=R4)
    w.logon("b2", 0.2, ip="", rule=None)
    hs = build(w)
    assert len(hs.hops) == 3 and all(h.member_count == 1 for h in hs.hops)
    assert all(h.source_ip is None for h in hs.hops)
    assert all(h.prev_gap_ms is None and h.next_gap_ms is None for h in hs.hops)
    assert all(h.shares_port_with_hops == [] for h in hs.hops)


def test_a_blank_ip_logon_never_joins_a_group_with_an_ip_and_is_never_a_follow_up():
    w = World()
    w.burst("s", [0.0, 0.5], rule=R8, ip=IP, port=50001)
    w.logon("blank", 0.7, ip=None, port=50001)                           # inside the seed's time, port in its ports
    w.logon("blank2", 12.0, ip=None, port=50001)                         # 11 s after the seed, port in its ports
    hs = build(w)
    assert len(hs.hops) == 3 and len(hs.followups) == 0
    assert hop_of(hs, "s0").member_uids == ["s0", "s1"]
    assert hop_of(hs, "blank").source_ip is None and hop_of(hs, "blank2").source_ip is None


def test_blank_ip_hops_stay_hops_and_do_not_take_a_hop_number_out_of_order():
    w = World()
    w.logon("b", 5.0, ip=None)
    w.logon("a", 1.0, rule=R4)
    hs = build(w)
    assert [h.member_uids for h in hs.hops] == [["a"], ["b"]]
    assert [h.hop_id for h in hs.hops] == [hop_id_of(TRIAL, 1), hop_id_of(TRIAL, 2)]


# ================================================================================================ union property
def _random_world(seed: int, n: int = 90, trig_share: float = 1.0) -> World:
    rnd = random.Random(seed)
    steps = [0.2, 0.9, 1.0, 1.4, 1.99, 2.0, 2.4, 3.0, 3.5, 6.0, 40.0]
    w = World()
    clock = {(h, i): 0.0 for h in ("ep-02", "ep-03") for i in (IP, IP2, "192.168.50.22")}
    for k in range(n):
        host = rnd.choice(["ep-02", "ep-03"])
        ip = rnd.choice([IP, IP2, "192.168.50.22"])
        clock[(host, ip)] += rnd.choice(steps)
        rule = R4 if rnd.random() < trig_share else None
        w.logon(f"r{k:03d}", clock[(host, ip)], host=host, ip=ip, port=rnd.choice([49734, 49735, 50001, 50002, 0, None]),
                account=rnd.choice(["acct_a", "acct_b", None]), rule=rule)
    return w


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_groups_at_a_larger_gap_are_unions_of_the_groups_at_a_smaller_gap(seed):
    w = _random_world(seed)
    lgs = logons_of(w)
    by_gap = {g: group_hops(lgs, replace(P, group_gap_s=g)) for g in (1.0, 2.0, 3.0)}
    for g in by_gap:                                                   # each is a partition of all logons
        uids = [m.uid for grp in by_gap[g] for m in grp.members]
        assert sorted(uids) == sorted(lg.uid for lg in lgs), f"gap {g}: not a partition"
    for small, large in ((1.0, 2.0), (2.0, 3.0), (1.0, 3.0)):
        small_sets, large_sets = group_sets(by_gap[small]), group_sets(by_gap[large])
        for s in small_sets:
            inside = [L for L in large_sets if s <= L]
            assert len(inside) == 1, f"gap {small} group of {len(s)} not inside exactly one group at {large}"
        for L in large_sets:
            assert frozenset().union(*[s for s in small_sets if s <= L]) == L
    assert len(by_gap[3.0]) < len(by_gap[2.0]) < len(by_gap[1.0])      # the property is not vacuous


# ================================================================================================ protocol (ST-22)
@pytest.mark.parametrize("rules,want", [
    ([R4, R6, R8], "winrm"), ([R8], "winrm"), ([R4, R5, R6], "rdp"), ([R5, R4], "rdp"), ([R6, R4], "smb_service"),
    ([R6], "smb_service"), ([R4], "smb"), ([], "none"), ([R4, R8, R5], "winrm"),
])
def test_protocol_of_orders_r8_r5_r6_r4_none(rules, want):
    assert protocol_of(rules) == want
    assert protocol_of(reversed(rules)) == want


@pytest.mark.parametrize("member_rules,want", [
    ([R4, R6, R8], "winrm"), ([R4, R5, R6], "rdp"), ([R6, R4], "smb_service"), ([R4], "smb"), ([None], "none"),
    ([None, R4], "smb"), ([R6, None], "smb_service"), ([R4, None, R8], "winrm"),
])
def test_a_hops_protocol_follows_the_rules_of_all_its_members(member_rules, want):
    w = World()
    for i, rule in enumerate(member_rules):
        w.logon(f"m{i}", i * 0.1, rule=rule, port=50000 + i)
    hs = build(w)
    assert len(hs.hops) == 1
    h = hs.hops[0]
    assert h.protocol == want
    assert h.rules == sorted({r for r in member_rules if r})


def test_a_hops_trigger_ids_are_the_distinct_trigger_rows_of_its_members():
    w = World()
    w.logon("a", 0.0, rule=R6)
    w.logon("b", 0.2, rule=None)
    w.logon("c", 0.4, rule=R4)
    h = build(w).hops[0]
    assert h.trigger_ids == ["t-a", "t-c"]


# ================================================================================================ seeds (ST-23)
def test_a_hop_is_a_seed_when_at_least_one_member_has_a_trigger_row():
    w = World()
    w.logon("a", 0.0, rule=None)
    w.logon("b", 0.3, rule=R6)
    w.logon("c", 30.0, rule=None, ip=IP2)                               # only unmatched logons
    hs = build(w)
    assert hop_of(hs, "a").is_seed == 1 and hop_of(hs, "a").trigger_ids == ["t-b"]
    c = hop_of(hs, "c")
    assert c.is_seed == 0 and c.trigger_ids == [] and c.protocol == "none" and c.rules == []
    assert hs.counts["seeds"] == 1


def test_a_trigger_row_with_no_anchor_starts_nothing():
    w = World()
    w.logon("a", 0.0, rule=R4)
    w.triggers.append({"trigger_id": "t-orphan", "rule": R6, "host": "ep-02", "anchor_logon_uid": "",
                       "trigger_event_uid": "some-4697-uid", "target_logon_id": "", "source_ip": "",
                       "ip_kind": "blank", "machine_account": "0", "clock_unreliable": "0"})
    hs = build(w)
    assert len(hs.hops) == 1 and hs.hops[0].member_uids == ["a"]


def test_an_unmatched_row_with_a_blank_anchor_uses_its_trigger_event_uid():
    w = World()
    w.logon("a", 0.0, rule=None)
    w.unmatched[0]["anchor_logon_uid"] = ""
    hs = build(w)
    assert hs.hops[0].member_uids == ["a"] and hs.hops[0].is_seed == 0


# ================================================================================================ hop ids
def test_hop_ids_follow_corrected_first_member_time_then_uid(tmp_path):
    w = World()
    w.logon("late_raw_early_corr", 12.0, host="ep-03", rule=R4, ip=IP)  # raw +12 s, corrected +7 s (offset +5 s)
    w.logon("early_raw_late_corr", 10.0, host="ep-02", rule=R4, ip=IP)  # raw +10 s, corrected +10 s
    offs, chg = clocks(tmp_path, cf.offsets_spec(ep_03=(5000, "ok", True)))
    hs = build(w, offsets=offs, changes=chg)
    assert [h.member_uids for h in hs.hops] == [["late_raw_early_corr"], ["early_raw_late_corr"]]
    assert [h.hop_id for h in hs.hops] == [f"{TRIAL}-h0001", f"{TRIAL}-h0002"]
    assert hs.hops[0].first_us < hs.hops[1].first_us
    assert hs.hops[0].first_us_raw > hs.hops[1].first_us_raw            # raw order is the opposite


def test_equal_corrected_first_member_times_are_ordered_by_uid():
    w = World()
    w.logon("zz", 5.0, host="ep-02", rule=R4)
    w.logon("aa", 5.0, host="ep-03", rule=R4)
    w.logon("mm", 5.0, host="ep-02", rule=R4, ip=IP2)
    hs = build(w)
    assert [h.members[0].uid for h in hs.hops] == ["aa", "mm", "zz"]
    assert [h.hop_id for h in hs.hops] == [hop_id_of(TRIAL, n) for n in (1, 2, 3)]


def test_a_follow_up_group_takes_no_hop_number():
    w = World()
    w.burst("s", [0.0, 0.5], rule=R8, port=50001)
    w.logon("f", 11.5, rule=None, port=50001)                           # follow-up
    w.logon("n", 100.0, rule=R4, ip=IP2)
    hs = build(w)
    assert [h.hop_id for h in hs.hops] == [hop_id_of(TRIAL, 1), hop_id_of(TRIAL, 2)]
    assert [f.hop_id for f in hs.followups] == [hop_id_of(TRIAL, 1)]


# ================================================================================================ ST-26 follow-ups
S_OFFSETS = [0.0, 0.4, 0.8]
S_PORTS = [50001, 50002, 50003]


def _seed(w: World, ip: str = IP, ports=S_PORTS, offsets=S_OFFSETS) -> None:
    for i, (o, p) in enumerate(zip(offsets, ports)):
        w.logon(f"s{i}", o, ip=ip, port=p, rule=R8 if i == 0 else None, account="acct_a", machine=0)


def _group(w: World, prefix: str, start: float, ports, *, ip: str = IP, rule=None, account="acct_a") -> list[str]:
    return [w.logon(f"{prefix}{i}", start + 0.5 * i, ip=ip, port=p, rule=rule, account=account)
            for i, p in enumerate(ports)]


def test_an_untriggered_group_on_the_seeds_ports_11_s_after_its_last_member_is_attached():
    w = World()
    _seed(w)
    _group(w, "f", 0.8 + 11.0, [50001, 50003])
    hs = build(w)
    assert [h.member_uids for h in hs.hops] == [["s0", "s1", "s2"]]
    assert len(hs.followups) == 1
    f, h = hs.followups[0], hs.hops[0]
    assert [lg.uid for lg in f.logons] == ["f0", "f1"] and f.hop_id == h.hop_id
    assert [lg.uid for lg in h.followups] == ["f0", "f1"] and h.followup_group_count == 1
    assert f.time_delta_ms == 11000                                     # first follow-up logon minus the hop's last member
    assert f.ports == [50001, 50003]
    assert (f.kind, f.method, f.confidence_tier, f.candidate_count) == ("followup_logon", "port_reuse", "C", 1)
    assert hs.counts["followup_groups"] == 1 and hs.counts["followup_logons"] == 2


def test_a_follow_up_group_adds_no_members_no_protocol_and_no_trigger_ids_to_its_hop():
    w1 = World()
    _seed(w1)
    w2 = World()
    _seed(w2)
    _group(w2, "f", 11.8, [50001, 50003], rule=None, account="someone_else", ip=IP)
    a, b = build(w1).hops[0], build(w2).hops[0]
    assert (a.member_uids, a.member_count, a.protocol, a.rules, a.trigger_ids, a.is_seed, a.mixed_account,
            a.authentication_packages) == \
           (b.member_uids, b.member_count, b.protocol, b.rules, b.trigger_ids, b.is_seed, b.mixed_account,
            b.authentication_packages)
    assert b.protocol == "winrm" and b.mixed_account == 0               # the other account is not a member


def test_the_same_group_after_an_untriggered_group_is_a_hop():
    w = World()
    _seed(w)
    _group(w, "u", 0.8 + 40.0, [50001, 50002])                          # 40 s after the seed: a hop of its own, no trigger
    _group(w, "f", 40.8 + 0.5 + 11.0, [50001, 50002])                   # on the ports of u, 11 s after u's last member
    hs = build(w)
    assert len(hs.followups) == 0
    assert [h.member_uids for h in hs.hops] == [["s0", "s1", "s2"], ["u0", "u1"], ["f0", "f1"]]
    assert [h.is_seed for h in hs.hops] == [1, 0, 0]


def test_the_same_group_with_one_new_port_is_a_hop():
    w = World()
    _seed(w)
    _group(w, "f", 11.8, [50001, 50999])
    hs = build(w)
    assert len(hs.followups) == 0 and len(hs.hops) == 2


@pytest.mark.parametrize("after,attached", [(11.0, True), (29.999, True), (30.0, True), (30.000001, False),
                                            (30.001, False), (31.0, False)])
def test_followup_max_s_is_inclusive_and_measured_from_the_hops_last_member(after, attached):
    w = World()
    _seed(w)
    _group(w, "f", 0.8 + after, [50001, 50002])
    hs = build(w)
    assert (len(hs.followups), len(hs.hops)) == ((1, 1) if attached else (0, 2)), f"{after}: {len(hs.hops)} hops"


def test_followup_max_s_is_a_parameter():
    w = World()
    _seed(w)
    _group(w, "f", 0.8 + 20.0, [50001, 50002])
    assert len(build(w).followups) == 1
    assert len(build(w, replace(P, followup_max_s=15.0)).followups) == 0


def test_a_triggered_group_is_never_a_follow_up():
    w = World()
    _seed(w)
    _group(w, "f", 11.8, [50001, 50003], rule=R4)
    hs = build(w)
    assert len(hs.followups) == 0 and len(hs.hops) == 2 and hs.hops[1].is_seed == 1


def test_a_group_with_one_trigger_row_among_untriggered_members_is_a_hop():
    w = World()
    _seed(w)
    w.logon("f0", 11.8, port=50001, rule=None)
    w.logon("f1", 12.3, port=50003, rule=R4)
    hs = build(w)
    assert len(hs.followups) == 0 and len(hs.hops) == 2


def test_a_follow_up_needs_the_same_target_host_and_source_ip():
    w = World()
    _seed(w)
    _group(w, "x", 11.8, [50001, 50002], ip=IP2)                        # another source IP, same ports
    w.logon("y0", 11.8, host="ep-03", port=50001)
    w.logon("y1", 12.3, host="ep-03", port=50002)                       # another target host, same ports
    hs = build(w)
    assert len(hs.followups) == 0 and len(hs.hops) == 3


def test_a_follow_up_group_needs_every_member_port_non_null_and_in_the_hops_ports():
    w = World()
    _seed(w)
    w.logon("n0", 11.8, port=50001)
    w.logon("n1", 12.3, port=None)
    hs = build(w)
    assert len(hs.followups) == 0 and len(hs.hops) == 2


def test_port_zero_is_treated_like_null_for_the_follow_up_match():
    w = World()
    w.logon("s0", 0.0, port=0, rule=R8)
    w.logon("s1", 0.4, port=50002, rule=None)
    w.logon("z", 11.0, port=0, rule=None)                               # port 0 equals a hop port 0 only as text
    hs = build(w)
    assert len(hs.followups) == 0 and len(hs.hops) == 2


def test_a_follow_up_group_is_never_the_hop_before_a_later_group():
    w = World()
    _seed(w)
    _group(w, "f1", 0.8 + 20.0, [50001, 50002])                         # attached: 20 s after the seed
    _group(w, "f2", 0.8 + 40.0, [50001, 50002])                         # 20 s after f1 but 40 s after the seed: a hop
    hs = build(w)
    assert [h.member_uids for h in hs.hops] == [["s0", "s1", "s2"], ["f20", "f21"]]
    assert [lg.uid for f in hs.followups for lg in f.logons] == ["f10", "f11"]
    assert hs.hops[1].is_seed == 0


def test_a_second_follow_up_group_is_compared_with_the_seed_not_with_the_first_follow_up():
    w = World()
    _seed(w)
    _group(w, "f1", 0.8 + 11.0, [50001, 50002])
    _group(w, "f2", 0.8 + 22.0, [50003])
    hs = build(w)
    assert len(hs.hops) == 1 and len(hs.followups) == 2
    assert hs.hops[0].followup_group_count == 2
    assert sorted(f.time_delta_ms for f in hs.followups) == [11000, 22000]    # both measured from the seed's last member


def test_follow_up_groups_do_not_count_as_neighbouring_hops_for_gaps_and_flags():
    w = World()
    _seed(w)
    _group(w, "f", 0.8 + 2.5, [50001, 50002])                           # attached 2.5 s after: inside [1, 3] and <= 3 s
    w.logon("n", 0.8 + 100.0, ip=IP, port=60000, rule=R4)
    hs = build(w)
    s, n = hs.hops
    assert len(hs.followups) == 1
    assert s.next_gap_ms == 100000 and n.prev_gap_ms == 100000          # seed-to-hop, not seed-to-follow-up
    assert s.merges_at_3s == 0 and s.gap_near_threshold == 0 and n.merges_at_3s == 0
    assert s.prev_gap_ms is None and n.next_gap_ms is None


def test_followup_group_after_a_triggered_group_that_is_itself_preceded_by_an_untriggered_one():
    w = World()
    _group(w, "u", 0.0, [50001, 50002])                                  # untriggered hop
    _group(w, "s", 40.0, [50001, 50002], rule=R4)                        # seed hop
    _group(w, "f", 40.5 + 11.0, [50001])                                 # after the seed: attached
    hs = build(w)
    assert [h.member_uids for h in hs.hops] == [["u0", "u1"], ["s0", "s1"]]
    assert [lg.uid for lg in hs.followups[0].logons] == ["f0"] and hs.followups[0].hop_id == hs.hops[1].hop_id


# ================================================================================================ flags (ST-20)
def test_inside_gap_max_ms_and_none_for_a_one_member_hop():
    w = World()
    w.burst("a", [0.0, 0.4, 1.6], rule=R4)
    w.logon("one", 50.0, rule=R4)
    hs = build(w)
    assert hop_of(hs, "a0").inside_gap_max_ms == 1200
    assert hop_of(hs, "one").inside_gap_max_ms is None
    assert hop_of(hs, "one").splits_at_1s == 0 and hop_of(hs, "one").gap_near_threshold == 0


@pytest.mark.parametrize("gap,splits", [(0.5, 0), (0.999999, 0), (1.0, 0), (1.000001, 1), (1.33, 1), (2.0, 1)])
def test_splits_at_1s_is_an_inside_gap_over_one_second(gap, splits):
    w = World()
    w.burst("a", [0.0, gap], rule=R4)
    h = build(w).hops[0]
    assert h.splits_at_1s == splits, f"gap {gap}"
    assert h.inside_gap_max_ms == int(round(gap * 1000))


def test_splits_at_1s_looks_at_every_inside_gap_not_only_the_last_or_the_first():
    w = World()
    w.burst("a", [0.0, 1.5, 1.7, 1.9], rule=R4)
    assert build(w).hops[0].splits_at_1s == 1


@pytest.mark.parametrize("gap,merges", [(2.5, 1), (3.0, 1), (3.000001, 0), (3.001, 0), (10.0, 0)])
def test_merges_at_3s_is_a_neighbour_gap_of_at_most_three_seconds(gap, merges):
    w = World()
    w.burst("a", [0.0, 0.5], rule=R4)
    w.burst("b", [0.5 + gap, 1.0 + gap], rule=R4)
    hs = build(w)
    assert len(hs.hops) == 2
    a, b = hs.hops
    assert (a.merges_at_3s, b.merges_at_3s) == (merges, merges), f"gap {gap}"
    assert a.next_gap_ms == int(round(gap * 1000)) == b.prev_gap_ms


@pytest.mark.parametrize("gap,near", [(0.999999, 0), (1.0, 1), (1.4, 1), (2.0, 1)])
def test_gap_near_threshold_for_an_inside_gap_is_inclusive_at_one_second(gap, near):
    w = World()
    w.burst("a", [0.0, gap], rule=R4)
    assert build(w).hops[0].gap_near_threshold == near, f"gap {gap}"


@pytest.mark.parametrize("gap,near", [(2.5, 1), (3.0, 1), (3.000001, 0), (3.001, 0), (4.0, 0)])
def test_gap_near_threshold_for_a_neighbour_gap_is_inclusive_at_three_seconds(gap, near):
    w = World()
    w.logon("a", 0.0, rule=R4)
    w.logon("b", gap, rule=R4)
    a, b = build(w).hops
    assert (a.gap_near_threshold, b.gap_near_threshold) == (near, near), f"gap {gap}"


def test_gap_near_threshold_uses_the_review_band_parameter_and_lower_bound_inclusive():
    w = World()
    w.logon("a", 0.0, rule=R4)
    w.logon("b", 5.0, rule=R4)
    assert [h.gap_near_threshold for h in build(w).hops] == [0, 0]
    wide = replace(P, group_review_band_s=(1.0, 5.0))
    assert [h.gap_near_threshold for h in build(w, wide).hops] == [1, 1]
    low = replace(P, group_gap_s=0.5)                                   # a 1.0 s neighbour gap: lower bound, inclusive
    w2 = World()
    w2.logon("a", 0.0, rule=R4)
    w2.logon("b", 1.0, rule=R4)
    assert [h.gap_near_threshold for h in build(w2, low).hops] == [1, 1]


def test_prev_and_next_gaps_are_from_the_last_member_of_the_previous_hop_of_the_same_target_and_ip():
    w = World()
    w.burst("a", [0.0, 0.5], rule=R4)                                    # last member at 0.5
    w.burst("b", [5.5, 6.0], rule=R4)                                    # 5.0 s after a's last; last member at 6.0
    w.logon("c", 13.5, rule=R4)                                          # 7.5 s after b's last
    w.logon("o", 6.5, ip=IP2, rule=R4)                                   # another IP: never a neighbour
    w.logon("p", 6.7, host="ep-03", rule=R4)                             # another host: never a neighbour
    hs = build(w)
    a, b, c = hop_of(hs, "a0"), hop_of(hs, "b0"), hop_of(hs, "c")
    assert (a.prev_gap_ms, a.next_gap_ms) == (None, 5000)
    assert (b.prev_gap_ms, b.next_gap_ms) == (5000, 7500)
    assert (c.prev_gap_ms, c.next_gap_ms) == (7500, None)
    for uid in ("o", "p"):
        h = hop_of(hs, uid)
        assert (h.prev_gap_ms, h.next_gap_ms) == (None, None)


def test_the_s04_shape_two_hops_2_47_s_apart_flag_each_other():
    w = World()
    w.burst("A", [0.0, 0.2, 0.4], rule=R4, port=49734, account="acct_a")
    w.burst("B", [0.4 + 2.47, 2.87 + 0.27], rule=R4, port=49734, account="acct_b")
    hs = build(w)
    a, b = hs.hops
    assert (a.merges_at_3s, b.merges_at_3s, a.gap_near_threshold, b.gap_near_threshold) == (1, 1, 1, 1)
    assert a.next_gap_ms == b.prev_gap_ms == 2470
    assert a.shares_port_with_hops == [b.hop_id] and b.shares_port_with_hops == [a.hop_id]
    assert len(build(w, replace(P, group_gap_s=5.0)).hops) == 1         # at 5 s the two merge (spec 10.2)


# ================================================================================================ ST-05
def test_a_near_duplicate_gate_logon_is_one_member_with_both_uids():
    w = World()
    w.logon("d1", 0.0, rule=R4, record_id=777, lid=4242)
    w.logon("d2", 0.0, rule=None, record_id=777, lid=4242)               # same host, channel, record id; second gate row
    w.logon("e", 0.5, rule=None)
    hs = build(w)
    assert len(hs.hops) == 1
    h = hs.hops[0]
    assert h.member_count == 2 and h.member_uids == ["d1", "d2", "e"]
    dup = h.members[0]
    assert dup.event_uids == ["d1", "d2"] and dup.near_duplicate and dup.gate_uids == ["d1", "d2"]
    assert dup.trigger_ids == ["t-d1"] and dup.rules == [R4]            # facts of both gate rows are kept
    assert hs.counts["near_duplicate_members"] == 1
    assert hs.counts["remote_logons"] == 2


def test_a_gate_row_that_names_the_non_representative_copy_still_finds_the_one_member():
    w = World()
    w.logon("d1", 0.0, rule=None, record_id=888, lid=4243, in_gate=False)
    w.logon("d2", 0.0, rule=R4, record_id=888, lid=4243)                 # the gate names only d2
    hs = build(w)
    assert len(hs.hops) == 1 and hs.hops[0].member_count == 1
    assert hs.hops[0].member_uids == ["d1", "d2"] and hs.hops[0].trigger_ids == ["t-d2"]


def test_two_events_with_different_record_ids_are_two_members():
    w = World()
    w.logon("d1", 0.0, rule=R4, record_id=901, lid=4244)
    w.logon("d2", 0.0, rule=R4, record_id=902, lid=4245)
    assert build(w).hops[0].member_count == 2


# ================================================================================================ errors
def test_a_gate_uid_that_is_not_in_the_db_is_a_stitch_error():
    w = World()
    w.logon("a", 0.0, rule=R4)
    w.triggers[0]["anchor_logon_uid"] = "no-such-uid"
    with pytest.raises(StitchError):
        build(w)


def test_a_gate_uid_that_is_not_a_4624_is_a_stitch_error():
    w = World()
    w.logon("a", 0.0, rule=R4)
    w.events.append(sf.ev("p", "Security", 4688, host="ep-02", off=0.1, process_id=10, target_logon_id=1000))
    w.triggers[0]["anchor_logon_uid"] = "p"
    with pytest.raises(StitchError):
        build(w)


@pytest.mark.parametrize("off", [-4000.0, 4000.0])
def test_a_4624_outside_the_window_is_a_stitch_error(off):
    w = World()
    w.logon("a", off, rule=R4)                                           # 09:23:20 or 11:36:40 (window 10:00-11:00)
    with pytest.raises(StitchError):
        build(w)


def test_a_gate_row_whose_host_differs_from_its_4624_is_a_stitch_error():
    w = World()
    w.logon("a", 0.0, rule=R4)
    w.triggers[0]["host"] = "ep-03"
    with pytest.raises(StitchError):
        build(w)


def test_a_gate_row_whose_logon_id_differs_from_its_4624_is_a_stitch_error():
    w = World()
    w.logon("a", 0.0, rule=None, lid=1000)
    w.unmatched[0]["target_logon_id"] = "1001"
    with pytest.raises(StitchError):
        build(w)


def test_a_gate_logon_id_in_hex_text_equals_the_integer_id():
    w = World()
    w.logon("a", 0.0, rule=R4, lid=1000)
    w.triggers[0]["target_logon_id"] = "0x3e8"
    assert build(w).hops[0].member_uids == ["a"]


def test_an_unmatched_row_that_names_no_uid_at_all_is_a_stitch_error():
    w = World()
    w.logon("a", 0.0, rule=None)
    w.unmatched[0]["anchor_logon_uid"] = ""
    w.unmatched[0]["trigger_event_uid"] = ""
    with pytest.raises(StitchError):
        build(w)


# ================================================================================================ STA-01 invariant
@pytest.mark.parametrize("seed", [11, 12, 13])
def test_every_remote_logon_is_a_member_of_exactly_one_hop_or_a_follow_up_of_exactly_one_hop(seed):
    w = _random_world(seed, n=120, trig_share=0.35)
    hs = build(w)
    gate_uids = {r["anchor_logon_uid"] for r in w.triggers + w.unmatched}
    seen: list[str] = []
    for h in hs.hops:
        seen += [m.uid for m in h.members] + [lg.uid for lg in h.followups]
    assert sorted(seen) == sorted(gate_uids)
    assert len(seen) == len(set(seen)) == hs.counts["remote_logons"] == 120
    assert hs.counts["groups_before_followups"] == len(hs.hops) + len(hs.followups)
    assert sum(h.followup_group_count for h in hs.hops) == len(hs.followups)
    assert sum(len(f.logons) for f in hs.followups) == hs.counts["followup_logons"] == sum(len(h.followups) for h in hs.hops)
    members = {m.uid for h in hs.hops for m in h.members}
    assert members.isdisjoint(followup_uids(hs))
    for h in hs.hops:                                                    # a follow-up never adds to its hop's facts
        assert all(m.uid not in followup_uids(hs) for m in h.members)


def test_the_random_world_with_few_triggers_really_has_follow_ups():
    n = sum(len(build(_random_world(s, n=120, trig_share=0.35)).followups) for s in (11, 12, 13))
    assert n >= 1, "the invariant test would be vacuous without any follow-up group"


def test_attach_followups_returns_hop_groups_and_follow_up_pairs():
    w = World()
    _seed(w)
    _group(w, "f", 11.8, [50001, 50002])
    _group(w, "g", 0.8 + 100.0, [50001, 50002])
    groups = group_hops(logons_of(w), P)
    hops, pairs = attach_followups(groups, P)
    assert len(groups) == 3 and len(hops) == 2 and len(pairs) == 1
    (fgroup, parent), = pairs
    assert [m.uid for m in fgroup.members] == ["f0", "f1"] and [m.uid for m in parent.members] == ["s0", "s1", "s2"]
    assert [m.uid for m in hops[0].members] == ["s0", "s1", "s2"] and hops[0].is_seed and not hops[1].is_seed


# ================================================================================================ read_gate_rows
def _write_gate_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    import csv
    with open(path, "w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(header)
        wr.writerows(rows)


def _gate_dir(tmp_path: Path) -> Path:
    d = tmp_path / "gate"
    d.mkdir()
    _write_gate_csv(d / "triggers.csv", ["trigger_id", "rule", "anchor_logon_uid"], [["g1", R4, "u1"], ["g2", R6, "u2"]])
    _write_gate_csv(d / "unmatched_remote.csv", ["trigger_id", "anchor_logon_uid"], [["u1", "x1"]])
    _write_gate_csv(d / "supporting.csv", ["trigger_id", "rule"], [["s1", "R1_lsass"], ["s2", "R3_explicit"],
                                                                  ["s3", "R8_parent"]])
    return d


def test_read_gate_rows_reads_the_three_csvs_as_text_rows(tmp_path):
    rows = read_gate_rows(_gate_dir(tmp_path))
    assert isinstance(rows, GateRows)
    assert [r["trigger_id"] for r in rows.triggers] == ["g1", "g2"] and rows.triggers[1]["rule"] == R6
    assert [r["trigger_id"] for r in rows.unmatched] == ["u1"] and rows.unmatched[0]["anchor_logon_uid"] == "x1"
    assert [r["rule"] for r in rows.supporting] == ["R1_lsass", "R3_explicit", "R8_parent"]


def test_read_gate_rows_reads_header_only_files_as_empty_lists(tmp_path):
    d = tmp_path / "gate"
    d.mkdir()
    for name in ("triggers.csv", "unmatched_remote.csv", "supporting.csv"):
        _write_gate_csv(d / name, ["trigger_id"], [])
    rows = read_gate_rows(d)
    assert (rows.triggers, rows.unmatched, rows.supporting) == ([], [], [])


@pytest.mark.parametrize("missing", ["triggers.csv", "unmatched_remote.csv", "supporting.csv"])
def test_a_missing_gate_file_raises_stitch_error(tmp_path, missing):
    d = _gate_dir(tmp_path)
    (d / missing).unlink()
    with pytest.raises(StitchError):
        read_gate_rows(d)


def test_a_missing_gate_folder_raises_stitch_error(tmp_path):
    with pytest.raises(StitchError):
        read_gate_rows(tmp_path / "nowhere")
