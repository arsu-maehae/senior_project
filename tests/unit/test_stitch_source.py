"""Tests for T7.3 task 4: source host and the three linking methods (`stitch.source`), the Kerberos / service
confirmation (`stitch.confirm`). Fast: synthetic event rows, synthetic gate rows and hand-built `CmdResult` objects.
Nothing real is opened.

Written from docs/specs/03_stitch.md (ST-01, ST-02, ST-40..ST-44, ST-47, ST-49, STT-04, STT-05, STT-09, STT-10, section
6), decision 048 items 3-6, 11 (as amended) and 12, and the T7.3 plan task 4, not from the implementation (the code was
read only for names and signatures).

Readings tested as stated by the coordinator:
- `no_session_id` is an internal unresolved reason (a NULL logon ID);
- for the 4648 and the command-line method `matched_member_count` = the member count;
- a hop with unresolved rows and no candidate keeps the unresolved rows AND one `target_only` row;
- the out-of-range bands are 120 s before / 30 s after and count evidence of any session;
- the port-join system process gives one empty-session `system_process` row and is not a candidate;
- a 4769 outside the window neither confirms nor is counted.

World: target ep-02 (192.168.50.22), source ep-01 (192.168.50.21). Event times are seconds after 10:30:00
(`stitch_fixtures.at`), the window is 10:00-11:00 (-2000 s is before it). The first (or only) member 4624 is at 100 s, so an
evidence time of 100 + d is d seconds after it. Messages carry uids, counts and ids only.
"""
from __future__ import annotations

import itertools
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
from stitch import source as src  # noqa: E402
from stitch.artefacts import build_artefacts  # noqa: E402
from stitch.cmdtext import CmdResult  # noqa: E402
from stitch.confirm import (confirm_of, kerberos_confirm, norm_logon_guid, service_admin_write)  # noqa: E402
from stitch.hops import build_hops  # noqa: E402
from stitch.index import build_index  # noqa: E402
from stitch.inputs import GateRows  # noqa: E402
from stitch.params import StitchParams  # noqa: E402
from stitch.scan import scan_rows  # noqa: E402

TRIAL = sf.TRIAL
START_US = to_us(sf.WIN_START)
END_US = to_us(sf.WIN_END)
P = StitchParams()
SRC, TGT = "ep-01", "ep-02"
SRC_IP, TGT_IP, OTHER_IP = "192.168.50.21", "192.168.50.22", "192.168.50.23"
R4, R8 = "R4_smb", "R8_winrm"
T = 100.0                       # first member 4624
PRE = -2000.0                   # before the window
POST = 2000.0
M_LID, M_PORT = 7000, 50000
S5000, S5001 = 5000, 5001
PORT, E4648, CMD = src.METHOD_PORT, src.METHOD_4648, src.METHOD_CMD
GUID = "{ABCDEF01-2345-6789-ABCD-EF0123456789}"
GUID_NORM = "abcdef01-2345-6789-abcd-ef0123456789"
ZERO_GUID = "00000000-0000-0000-0000-000000000000"


def cr(uid: str, *targets: str) -> CmdResult:
    """A hand-built command result naming `targets` (no text anywhere)."""
    return CmdResult(event_uid=uid, targets=tuple((t, "host_name", "plain") for t in sorted(targets)),
                     undecodable=False, names_found=(), has_command=True)


def skey(lid: int, host: str = SRC, epoch: int = 0, seq: int = 0) -> tuple:
    return (host, lid, epoch, seq)


# ------------------------------------------------------------------------------------------------ the synthetic world
@dataclass
class World:
    events: list[dict] = field(default_factory=list)
    triggers: list[dict] = field(default_factory=list)
    unmatched: list[dict] = field(default_factory=list)
    cmd: dict = field(default_factory=dict)
    t4648: dict = field(default_factory=dict)
    _pid: itertools.count = field(default_factory=lambda: itertools.count(100))

    def member(self, uid: str, off: float = T, lid: int = M_LID, port: int | None = M_PORT, *, ip: str | None = SRC_IP,
               account: str | None = "acct_a", guid: str | None = None, rule: str | None = R4, host: str = TGT,
               machine: int = 0, record_id="auto") -> str:
        """A remote 4624 on the target and its gate row (a trigger row when `rule`, else an unmatched row)."""
        self.events.append(sf.ev(uid, "Security", 4624, host=host, off=off, logon_type=3, target_logon_id=lid,
                                 account_name=account, source_ip=ip, source_port=port, logon_guid=guid,
                                 authentication_package="Kerberos" if guid else "NTLM", machine_account=machine,
                                 record_id=record_id))
        row = {"trigger_id": f"{'t' if rule else 'u'}-{uid}", "host": host, "anchor_logon_uid": uid,
               "trigger_event_uid": uid, "target_logon_id": str(lid), "source_ip": ip or "", "ip_kind": ip_kind(ip),
               "machine_account": str(machine), "clock_unreliable": "0"}
        if rule:
            row["rule"] = rule
            self.triggers.append(row)
        else:
            self.unmatched.append(row)
        return uid

    def src_logon(self, uid: str, off: float, lid: int, *, host: str = SRC, account: str = "src_acct",
                  logon_type: int = 3) -> str:
        """A 4624 on the source host: opens the session `lid` there."""
        self.events.append(sf.ev(uid, "Security", 4624, host=host, off=off, logon_type=logon_type,
                                 target_logon_id=lid, account_name=account))
        return uid

    def s1(self, uid: str, off: float, guid: str, lid: int | None, *, pid: int | None = None, host: str = SRC,
           cmd_target: str | None = TGT) -> str:
        """A Sysmon 1 (session_id = `lid`); when `cmd_target` its CmdResult names that target."""
        self.events.append(sf.ev(uid, "Sysmon", 1, host=host, off=off, process_guid=guid, process_id=pid,
                                 session_id=lid, image="PLACEHOLDER-IMAGE"))
        if cmd_target is not None:
            self.cmd[uid] = cr(uid, cmd_target)
        return uid

    def e4688(self, uid: str, off: float, pid: int, lid: int | None, *, host: str = SRC,
              cmd_target: str | None = TGT) -> str:
        self.events.append(sf.ev(uid, "Security", 4688, host=host, off=off, process_id=pid, target_logon_id=lid))
        if cmd_target is not None:
            self.cmd[uid] = cr(uid, cmd_target)
        return uid

    def s3(self, uid: str, off: float, guid: str | None, sport: int | None = M_PORT, *, dip: str = TGT_IP,
           initiated: int = 1, host: str = SRC) -> str:
        self.events.append(sf.ev(uid, "Sysmon", 3, host=host, off=off, process_guid=guid, initiated=initiated,
                                 source_ip=SRC_IP, source_port=sport, destination_ip=dip, destination_port=445))
        return uid

    def e4648(self, uid: str, off: float, subj_lid: int | None, *, host: str = SRC, cred: str = "cred_acct",
              subj_account: str = "subj_acct", texts: tuple = (TGT,), session_id: int | None = 999999) -> str:
        """A 4648 whose target texts are `texts` (read by uid in the tests: `t4648`)."""
        self.events.append(sf.ev(uid, "Security", 4648, host=host, off=off, subject_logon_id=subj_lid,
                                 session_id=session_id, account_name=cred, subject_account=subj_account,
                                 destination_host=texts[0] if texts else None))
        if texts is not None:
            self.t4648[uid] = tuple(texts)
        return uid

    def e4769(self, uid: str, off: float, guid: str | None, *, host: str = "dc01", record_id="auto") -> str:
        self.events.append(sf.ev(uid, "Security", 4769, host=host, off=off, logon_guid=guid, record_id=record_id))
        return uid


@dataclass
class Run:
    w: World
    scan: object
    index: object
    gate: GateRows
    hs: object
    params: StitchParams

    @property
    def hop(self):
        assert len(self.hs.hops) == 1, f"{len(self.hs.hops)} hops"
        return self.hs.hops[0]

    @property
    def subject(self):
        return src.hop_subject(self.hop, self.params)

    def links(self, *, offsets=None, cmd=None, t4648=None, hosts=None, subject=None) -> src.SubjectLinks:
        return src.link_subject(self.subject if subject is None else subject, self.scan, self.index.processes,
                                self.index.sessions, self.w.cmd if cmd is None else cmd,
                                self.w.t4648 if t4648 is None else t4648,
                                src.hosts_with_rows(self.scan) if hosts is None else hosts, self.params,
                                offsets=offsets)

    def port(self):
        return src.port_join(self.subject, self.scan, self.index.processes, self.params)

    def e4648(self):
        return src.by_4648(self.subject, self.scan, self.w.t4648, self.index.sessions, self.params)

    def cmdline(self):
        return src.by_cmdline(self.subject, self.index.processes, self.w.cmd, self.params)


def clocks(tmp_path: Path, spec: dict):
    repo = tmp_path / "clk"
    cf.write_clock_files(repo, TRIAL, "0" * 64, spec, None)
    return load_offsets(cf.offsets_path(repo, TRIAL)), load_clock_changes(cf.changes_path(repo, TRIAL))


def run(w: World, params: StitchParams = P, offsets=None, changes=()) -> Run:
    events = [dict(e) for e in w.events]
    scan = scan_rows(events, START_US, END_US, offsets, changes)
    index = build_index(TRIAL, scan, params)
    gate = GateRows(triggers=[dict(r) for r in w.triggers], unmatched=[dict(r) for r in w.unmatched], supporting=[])
    hs = build_hops(TRIAL, gate, scan, index.sessions, params)
    return Run(w, scan, index, gate, hs, params)


def base(**kw) -> World:
    """One member 4624 at 100 s (port 50000) and the source session 5000 opened at 0 s."""
    w = World()
    w.member("M1", **kw)
    w.src_logon("L5000", 0.0, S5000)
    return w


def two_members(port2: int | None = M_PORT) -> World:
    """Two members of one hop (same IP, 1 s apart): first 100 s, last 101 s."""
    w = base()
    w.member("M2", T + 1.0, M_LID + 1, port2)
    return w


def keys_of(res: src.MethodResult) -> list:
    return res.sessions


def rows_by_method(links: src.SubjectLinks) -> dict[str, list]:
    out: dict[str, list] = {}
    for r in links.rows:
        out.setdefault(r.method, []).append(r)
    return out


# ================================================================================================ contract
def test_contract_rows_columns_types_and_nothing_lost_or_duplicated():
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s3("N1", 100.5, "{G1}")
    w.e4648("F1", 95.0, S5000)
    r = run(w)
    links = r.links()
    assert isinstance(links, src.SubjectLinks)
    assert links.target_host == TGT and links.source_host == SRC and links.member_uids == ["M1"]
    # one row per (session, method): the same session found by 3 methods -> 3 rows, in METHODS order
    assert [row.method for row in links.rows] == [PORT, E4648, CMD]
    assert all(isinstance(row, src.LinkRow) for row in links.rows)
    assert len({(row.method, row.session_key, row.session_unresolved_reason) for row in links.rows}) == 3
    for row in links.rows:
        assert row.source_host == SRC and row.source_session_id == S5000 and row.source_session_id_hex == "0x1388"
        assert isinstance(row.time_delta_ms, int) and isinstance(row.time_delta_raw_ms, int)
        assert isinstance(row.candidate_count, int) and isinstance(row.candidate_count_all, int)
        assert isinstance(row.evidence_uids, list) and isinstance(row.supporting_event_uids, list)
        assert row.target_only_reason == "" and row.session_unresolved_reason == ""
        assert "M1" in row.supporting_event_uids and set(row.evidence_uids) <= set(row.supporting_event_uids)
    scan_uids = {u for rr in r.scan.in_window + r.scan.link_rows for u in rr["event_uids"]}
    assert {u for row in links.rows for u in row.supporting_event_uids} <= scan_uids
    assert links.candidate_counts == {PORT: 1, E4648: 1, CMD: 1} and links.candidate_count_all == 1


def test_the_method_names_are_the_spec_values():
    assert (PORT, E4648, CMD, src.METHOD_TARGET_ONLY) == ("sysmon3_port", "source_4648", "cmdline_target", "target_only")


def test_build_links_has_one_entry_per_hop_and_none_for_a_follow_up_group():
    w = World()
    w.member("H1", T, 7000, 50000, rule=R8)
    w.member("H2", 300.0, 7001, 50100, rule=R8)                       # a second hop (far in time)
    w.member("F1", T + 11.0, 7002, 50000, rule=None)                 # untriggered, same port, 11 s later: follow-up
    w.src_logon("L5000", 0.0, S5000)
    w.s1("S1", 90.0, "{G1}", S5000)
    r = run(w)
    assert [h.hop_id for h in r.hs.hops] == [f"{TRIAL}-h0001", f"{TRIAL}-h0002"] and len(r.hs.followups) == 1
    got = src.build_links(r.hs, r.scan, r.index, w.cmd, w.t4648, P)
    assert sorted(got) == [h.hop_id for h in r.hs.hops]
    fol_uids = {u for f in r.hs.followups for lg in f.logons for u in lg.event_uids}
    for links in got.values():
        assert isinstance(links, src.SubjectLinks)
        assert fol_uids.isdisjoint(links.member_uids)
        assert fol_uids.isdisjoint(u for row in links.rows for u in row.supporting_event_uids)
    # the same methods can still be run on the follow-up group (the "no artefact" row of spec 10.4), by hand
    f = r.hs.followups[0]
    hop = next(h for h in r.hs.hops if h.hop_id == f.hop_id)
    subj = src.subject_of(hop.target_host, hop.source_ip, f.logons, P)
    assert subj.source_host == SRC and [m.uid for m in subj.members] == ["F1"]
    links = src.link_subject(subj, r.scan, r.index.processes, r.index.sessions, w.cmd, w.t4648,
                             src.hosts_with_rows(r.scan), P)
    assert links.member_uids == ["F1"] and links.candidate_counts[CMD] == 1       # S1 at 90 s is 21 s before F1: inside


def test_build_links_does_not_change_the_hop_set():
    w = base()
    r = run(w)
    before = [(h.hop_id, h.member_uids) for h in r.hs.hops]
    src.build_links(r.hs, r.scan, r.index, w.cmd, w.t4648, P)
    assert [(h.hop_id, h.member_uids) for h in r.hs.hops] == before


# ================================================================================================ source host (ST-40)
@pytest.mark.parametrize("ip,want", [
    (SRC_IP, "ep-01"), (TGT_IP, "ep-02"), (OTHER_IP, "ep-03"), ("192.168.50.10", "dc01"),
    ("::ffff:192.168.50.21", "ep-01"),                      # IPv4-mapped IPv6 is the same address
    ("", None), (None, None), ("   ", None), ("10.0.0.5", None), ("192.168.50.99", None),
    ("169.254.10.5", None), ("fe80::1", None), ("not an ip", None), ("127.0.0.1", None),
])
def test_source_host_of_maps_the_normalised_ip_to_the_lab_host_that_owns_it(ip, want):
    assert src.source_host_of(ip, P.lab_host_ips) == want


def test_subject_of_takes_the_source_host_from_the_ip_and_keeps_the_members():
    r = run(base())
    subj = src.subject_of(TGT, SRC_IP, r.hop.members, P)
    assert (subj.target_host, subj.source_host) == (TGT, SRC) and [m.uid for m in subj.members] == ["M1"]
    assert src.subject_of(TGT, "10.0.0.5", r.hop.members, P).source_host is None
    assert src.hop_subject(r.hop, P) == subj


def test_hosts_with_rows_counts_in_window_lookback_link_and_removed_rows():
    w = World()
    w.member("M1")
    w.events.append(sf.ev("A", "Security", 4624, host="ep-01", off=PRE, logon_type=3, target_logon_id=1))   # lookback
    w.events.append(sf.ev("B", "Security", 5145, host="ep-03", off=T))                                    # link row
    w.events.append(sf.ev("C", "Security", 5145, host="dc01", off=POST))                                  # removed
    r = run(w)
    assert src.hosts_with_rows(r.scan) == {"ep-01", "ep-02", "ep-03", "dc01"}
    assert src.hosts_with_rows(run(World()).scan) == set()


# ================================================================================================ target_only (ST-40, ST-49, STT-09)
def _target_only_world(ip: str | None, extra_host: str | None = None) -> World:
    w = World()
    w.member("M1", ip=ip)
    w.events.append(sf.ev("X1", "Sysmon", 3, host=SRC, off=T, process_guid="{Z}", initiated=1, destination_ip="1.2.3.4",
                          source_port=1))                                    # the source host has rows, just no evidence
    if extra_host:
        w.events.append(sf.ev("X2", "Sysmon", 3, host=extra_host, off=T, process_guid="{Y}", initiated=1,
                              destination_ip="1.2.3.4", source_port=2))
    return w


@pytest.mark.parametrize("ip", [None, "10.0.0.5", "169.254.10.5", "fe80::1", "192.168.50.99"])
def test_blank_unknown_or_link_local_source_ip_gives_source_host_unknown(ip):
    w = _target_only_world(ip)
    w.s1("S1", 95.0, "{G1}", S5000)                                # a command on a lab host naming the target
    w.e4648("F1", 95.0, S5000)
    r = run(w)
    links = r.links()
    assert links.source_host is None
    assert links.target_only_reason == "source_host_unknown"
    assert links.candidate_count_all == 0 and links.candidate_counts == {PORT: 0, E4648: 0, CMD: 0}
    (row,) = links.rows
    assert row.method == "target_only" and row.target_only_reason == "source_host_unknown"


def test_a_lab_ip_whose_host_has_no_rows_gives_source_host_no_logs():
    w = _target_only_world(OTHER_IP)
    r = run(w)
    links = r.links()
    assert links.source_host == "ep-03"
    assert links.target_only_reason == "source_host_no_logs"
    (row,) = links.rows
    assert (row.method, row.target_only_reason) == ("target_only", "source_host_no_logs")


def test_a_lab_host_with_rows_but_no_evidence_gives_no_evidence_in_range():
    w = _target_only_world(OTHER_IP, extra_host="ep-03")
    r = run(w)
    links = r.links()
    assert links.source_host == "ep-03" and links.target_only_reason == "no_evidence_in_range"


def test_a_host_with_only_a_row_outside_the_window_is_not_a_host_with_no_logs():
    w = _target_only_world(OTHER_IP)
    w.events.append(sf.ev("OUT", "Security", 5145, host="ep-03", off=POST))
    assert run(w).links().target_only_reason == "no_evidence_in_range"


def test_source_host_with_rows_and_no_evidence_in_range_reason_is_the_default():
    r = run(base())
    links = r.links()
    assert links.target_only_reason == "no_evidence_in_range"


def test_the_target_only_row_has_candidate_count_0_no_session_no_delta_and_the_member_uids():
    r = run(two_members())
    links = r.links()
    (row,) = links.rows
    assert row.method == "target_only" and row.candidate_count == 0 and row.candidate_count_all == 0
    assert row.session_key is None and row.source_session_id is None and row.source_session_id_hex == ""
    assert row.time_delta_ms is None and row.time_delta_raw_ms is None
    assert row.evidence_uids == [] and row.matched_member_count == 0
    assert set(row.supporting_event_uids) == {"M1", "M2"}
    assert row.target_only_reason == "no_evidence_in_range"


def test_a_hop_with_a_candidate_has_no_target_only_row_and_an_empty_reason():
    w = base()
    w.s1("S1", 95.0, "{G1}", S5000)
    links = run(w).links()
    assert links.target_only_reason == "" and all(r.method != "target_only" for r in links.rows)


def test_unresolved_rows_and_no_candidate_keep_both_the_unresolved_rows_and_one_target_only_row():
    w = base()
    w.s3("N1", 100.5, "{NOSUCH}")                                  # a process with no Sysmon 1
    links = run(w).links()
    kinds = [(r.method, r.session_unresolved_reason) for r in links.rows]
    assert kinds == [(PORT, "no_sysmon1_in_window"), ("target_only", "")]
    assert links.candidate_count_all == 0 and links.target_only_reason == "no_evidence_in_range"
    assert links.rows[0].session_key is None and links.rows[0].candidate_count == 0


def test_the_source_host_methods_run_when_the_source_host_has_no_logs_without_error():
    w = _target_only_world(OTHER_IP)
    links = run(w).links()
    assert links.candidate_counts == {PORT: 0, E4648: 0, CMD: 0}


# ================================================================================================ STT-04 port join
def test_port_join_one_sysmon3_can_match_two_members_and_the_join_is_per_member():
    w = two_members(port2=M_PORT)
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s3("N1", 101.0, "{G1}")
    r = run(w)
    res = r.port()
    (ev,) = res.evidence
    assert ev.session_key == skey(S5000) and ev.matched_member_uids == ["M1", "M2"]
    assert len(res.match_deltas_us) == 2                              # one entry per (Sysmon 3, member) match
    assert sorted(d for d, _ in res.match_deltas_us) == [0, 1_000_000]
    assert res.sessions == [skey(S5000)]
    links = r.links()
    (row,) = [x for x in links.rows if x.method == PORT]
    assert row.matched_member_count == 2 and row.candidate_count == 1


def test_port_join_members_with_different_ports_each_match_their_own_sysmon3():
    w = two_members(port2=50001)
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s1("S2", 91.0, "{G2}", S5001)
    w.src_logon("L5001", 0.0, S5001)
    w.s3("N1", 100.5, "{G1}", 50000)
    w.s3("N2", 101.5, "{G2}", 50001)
    r = run(w)
    res = r.port()
    by = {e.session_key: e for e in res.evidence}
    assert set(by) == {skey(S5000), skey(S5001)}
    assert by[skey(S5000)].matched_member_uids == ["M1"] and by[skey(S5001)].matched_member_uids == ["M2"]
    assert res.sessions == [skey(S5000), skey(S5001)]
    assert {x.matched_member_count for x in r.links().rows if x.method == PORT} == {1}


def test_port_join_candidate_count_counts_sessions_and_matched_member_count_counts_members():
    w = two_members(port2=M_PORT)
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s1("S2", 91.0, "{G2}", S5000)                                # a second process of the same session
    w.s3("N1", 100.5, "{G1}")
    w.s3("N2", 101.0, "{G2}")
    links = run(w).links()
    (row,) = [x for x in links.rows if x.method == PORT]
    assert row.candidate_count == 1 and row.matched_member_count == 2
    assert set(row.evidence_uids) == {"N1", "N2"}


def test_port_join_a_sysmon3_logged_on_another_host_with_the_same_destination_and_port_does_not_join():
    """Owner rule (048 item 5): only the source host's own log joins."""
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s1("S2", 90.0, "{G2}", 6000, host="ep-03")
    w.src_logon("L6000", 0.0, 6000, host="ep-03")
    w.s3("N_OTHER", 100.0, "{G2}", host="ep-03")                    # same destination, same port, wrong host
    w.s3("N_OTHER2", 100.0, "{G2}", host="dc01")
    r = run(w)
    res = r.port()
    assert res.evidence == [] and res.sessions == [] and res.match_deltas_us == []
    # with the right host's Sysmon 3 present too, only that one joins
    w.s3("N_OWN", 100.0, "{G1}")
    res2 = run(w).port()
    assert [e.evidence_uids for e in res2.evidence] == [["N_OWN"]] and res2.sessions == [skey(S5000)]


def test_port_join_initiated_0_does_not_join():
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s3("N1", 100.0, "{G1}", initiated=0)
    assert run(w).port().evidence == []
    w.s3("N2", 100.0, "{G1}", initiated=1)
    assert [e.evidence_uids for e in run(w).port().evidence] == [["N2"]]


@pytest.mark.parametrize("dip", [OTHER_IP, "192.168.50.220", "192.168.50.2", "10.9.9.9", "", None])
def test_port_join_a_wrong_destination_ip_does_not_join(dip):
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s3("N1", 100.0, "{G1}", dip=dip)
    assert run(w).port().evidence == []


def test_port_join_destination_ip_is_normalised_before_the_comparison():
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s3("N1", 100.0, "{G1}", dip="::ffff:" + TGT_IP)
    assert run(w).port().sessions == [skey(S5000)]


@pytest.mark.parametrize("member_port,s3_port", [(0, 0), (None, None), (None, 0), (0, None), (M_PORT, 0), (M_PORT, None),
                                                 (0, M_PORT), (None, M_PORT)])
def test_port_join_port_0_and_null_never_join(member_port, s3_port):
    w = World()
    w.member("M1", port=member_port)
    w.src_logon("L5000", 0.0, S5000)
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s3("N1", 100.0, "{G1}", s3_port)
    res = run(w).port()
    assert res.evidence == [] and res.match_deltas_us == []


@pytest.mark.parametrize("delta,joins", [
    (5.0, True), (-5.0, True), (4.999, True), (0.0, True),
    (5.001, False), (-5.001, False), (5.000001, False), (-5.000001, False), (30.0, False),
])
def test_port_join_five_seconds_joins_and_five_seconds_plus_a_tick_does_not(delta, joins):
    w = base()
    w.s1("S1", 50.0, "{G1}", S5000)
    w.s3("N1", T + delta, "{G1}")
    res = run(w).port()
    assert bool(res.evidence) is joins
    assert res.sessions == ([skey(S5000)] if joins else [])


def test_port_join_tolerance_follows_the_parameter():
    w = base()
    w.s1("S1", 50.0, "{G1}", S5000)
    w.s3("N1", T + 8.0, "{G1}")
    assert run(w).port().evidence == []
    assert run(w, replace(P, port_join_s=10.0)).port().sessions == [skey(S5000)]


def test_port_join_uses_corrected_times_a_raw_gap_of_18_s_with_offset_minus_18_s_joins(tmp_path):
    spec = cf.offsets_spec(ep_01=(-18000, "ok", True))
    offs, chg = clocks(tmp_path, spec)
    w = base()
    w.s1("S1", 50.0 - 18.0, "{G1}", S5000)
    w.s3("N1", T - 18.0, "{G1}")                                    # logged 18 s early; corrected = raw + 18 s
    res = run(w, offsets=offs, changes=chg).port()
    assert res.sessions == [skey(S5000)]
    ((corr, raw),) = res.match_deltas_us
    assert corr == 0 and raw == -18_000_000
    # the raw-time version (no correction) does not join
    assert run(w).port().evidence == []


def test_port_join_the_process_is_found_by_a_normalised_guid():
    w = base()
    w.s1("S1", 90.0, "{aaaaaaaa-0000-0000-0000-000000000001}", S5000)
    w.s3("N1", 100.0, "AAAAAAAA-0000-0000-0000-000000000001")
    assert run(w).port().sessions == [skey(S5000)]


def test_port_join_a_process_with_no_sysmon1_in_the_window_gives_an_empty_session_row_never_dropped():
    w = base()
    w.s3("N1", 100.0, "{NOSUCH}")
    r = run(w)
    res = r.port()
    (ev,) = res.evidence
    assert ev.session_key is None and ev.reason == "no_sysmon1_in_window" and not ev.is_candidate
    assert ev.evidence_uids == ["N1"] and ev.matched_member_uids == ["M1"]
    assert res.sessions == []
    (row,) = [x for x in r.links().rows if x.method == PORT]
    assert row.session_key is None and row.source_session_id is None and row.source_session_id_hex == ""
    assert row.session_unresolved_reason == "no_sysmon1_in_window" and row.candidate_count == 0
    assert row.session_methods == [] and row.matched_member_count == 1


def test_port_join_a_sysmon1_before_the_window_is_not_a_process_so_the_row_is_unresolved():
    w = base()
    w.s1("S1", PRE, "{G1}", S5000)
    w.s3("N1", 100.0, "{G1}")
    (ev,) = run(w).port().evidence
    assert ev.session_key is None and ev.reason == "no_sysmon1_in_window"


def test_port_join_a_null_guid_is_an_unresolved_row_too():
    w = base()
    w.s3("N1", 100.0, None)
    (ev,) = run(w).port().evidence
    assert ev.session_key is None and ev.reason == "no_sysmon1_in_window"


def test_port_join_a_system_process_gives_one_empty_session_system_process_row_and_no_candidate():
    w = base()
    w.s1("S1", 90.0, "{G9}", 999)
    w.s3("N1", 100.0, "{G9}")
    r = run(w)
    res = r.port()
    (ev,) = res.evidence
    assert ev.session_key is None and ev.reason == "system_process" and not ev.is_candidate
    assert res.sessions == [] and res.system_evidence == 1
    links = r.links()
    (row,) = [x for x in links.rows if x.method == PORT]
    assert row.session_unresolved_reason == "system_process" and row.session_key is None and row.candidate_count == 0
    assert links.system_session_evidence[PORT] == 1
    assert links.candidate_count_all == 0 and links.target_only_reason == "no_evidence_in_range"


@pytest.mark.parametrize("lid", [996, 997, 999])
def test_port_join_every_system_logon_id_is_a_system_process(lid):
    w = base()
    w.s1("S1", 90.0, "{G9}", lid)
    w.s3("N1", 100.0, "{G9}")
    res = run(w).port()
    assert res.sessions == [] and res.system_evidence == 1 and res.evidence[0].reason == "system_process"


def test_port_join_system_and_real_process_together_give_one_candidate_and_one_system_row():
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s1("S9", 90.0, "{G9}", 999)
    w.s3("N1", 100.0, "{G1}")
    w.s3("N9", 100.0, "{G9}")
    res = run(w).port()
    assert res.sessions == [skey(S5000)] and res.system_evidence == 1
    assert sorted(e.reason for e in res.evidence) == ["", "system_process"]


def test_port_join_a_null_logon_id_process_is_the_internal_no_session_id_reason():
    w = base()
    w.s1("S1", 90.0, "{G1}", None)
    w.s3("N1", 100.0, "{G1}")
    res = run(w).port()
    (ev,) = res.evidence
    assert ev.session_key is None and ev.reason == src.REASON_NO_SESSION_ID == "no_session_id" and not ev.is_candidate
    assert res.sessions == []


def test_port_join_with_an_unknown_source_host_finds_nothing():
    w = base(ip="10.0.0.5")
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s3("N1", 100.0, "{G1}")
    assert run(w).port().evidence == []


def test_port_join_two_sessions_are_two_candidates():
    w = base()
    w.src_logon("L5001", 0.0, S5001)
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s1("S2", 90.0, "{G2}", S5001)
    w.s3("N1", 100.0, "{G1}")
    w.s3("N2", 100.5, "{G2}")
    res = run(w).port()
    assert res.sessions == [skey(S5000), skey(S5001)]
    assert run(w).links().candidate_counts[PORT] == 2


def test_port_join_the_match_deltas_are_corrected_and_raw_per_individual_match():
    w = base()
    w.s1("S1", 50.0, "{G1}", S5000)
    w.s3("N1", T - 2.5, "{G1}")
    w.s3("N2", T + 1.25, "{G1}")
    res = run(w).port()
    assert res.match_deltas_us == [(-2_500_000, -2_500_000), (1_250_000, 1_250_000)]


# ================================================================================================ STT-05 4648 and command line
def _evidence(method: str, w: World, off: float, lid: int = S5000, *, uid: str = "EV") -> None:
    """Add one piece of `method` evidence at `off` seconds (naming the target) to the world."""
    if method == E4648:
        w.e4648(uid, off, lid)
    else:
        w.s1(uid, off, "{G-" + uid + "}", lid)


def _call(method: str, r: Run) -> src.MethodResult:
    return r.e4648() if method == E4648 else r.cmdline()


METHODS2 = [E4648, CMD]


@pytest.mark.parametrize("method", METHODS2)
@pytest.mark.parametrize("off", [T - 30.0, T + 1.0 + 15.0])
def test_evidence_exactly_at_first_minus_30_s_and_last_plus_15_s_is_a_candidate(method, off):
    w = two_members()
    _evidence(method, w, off)
    res = _call(method, run(w))
    assert res.sessions == [skey(S5000)], f"{method} at {off}"
    assert res.before_range == 0 and res.after_range == 0


@pytest.mark.parametrize("method", METHODS2)
@pytest.mark.parametrize("off,band", [(T - 30.0 - 0.001, "before"), (T + 1.0 + 15.0 + 0.001, "after"),
                                      (T - 30.0 - 0.000001, "before"), (T + 1.0 + 15.0 + 0.000001, "after")])
def test_evidence_one_tick_outside_is_not_a_candidate_and_is_counted(method, off, band):
    w = two_members()
    _evidence(method, w, off)
    res = _call(method, run(w))
    assert res.sessions == [] and res.evidence == []
    assert (res.before_range, res.after_range) == ((1, 0) if band == "before" else (0, 1))


@pytest.mark.parametrize("method", METHODS2)
def test_the_range_runs_from_the_first_member_to_the_last_member(method):
    """The after side is measured from the LAST member, the look-back from the FIRST."""
    w = two_members()
    _evidence(method, w, T + 14.0, uid="E_LATE_OK")             # 14 s after the first, 13 s after the last: inside
    _evidence(method, w, T + 1.0 + 16.0, uid="E_LATE_OUT")      # 16 s after the last: outside
    res = _call(method, run(w))
    assert res.sessions == [skey(S5000)] and res.after_range == 1


@pytest.mark.parametrize("method", METHODS2)
def test_range_edges_follow_the_parameters(method):
    w = two_members()
    _evidence(method, w, T - 45.0)
    assert _call(method, run(w)).sessions == []
    assert _call(method, run(w, replace(P, link_lookback_s=60.0))).sessions == [skey(S5000)]
    w2 = two_members()
    _evidence(method, w2, T + 1.0 + 8.0)
    assert _call(method, run(w2, replace(P, link_after_s=5.0))).sessions == []
    assert _call(method, run(w2, replace(P, link_after_s=5.0))).after_range == 1


@pytest.mark.parametrize("method", METHODS2)
def test_evidence_at_minus_60_s_is_counted_before_not_a_candidate(method):
    w = two_members()
    _evidence(method, w, T - 60.0)
    res = _call(method, run(w))
    assert res.sessions == [] and res.before_range == 1 and res.after_range == 0


@pytest.mark.parametrize("method", METHODS2)
def test_evidence_at_plus_20_s_is_counted_after_not_a_candidate(method):
    w = two_members()
    _evidence(method, w, T + 1.0 + 20.0)
    res = _call(method, run(w))
    assert res.sessions == [] and res.after_range == 1 and res.before_range == 0


@pytest.mark.parametrize("method", METHODS2)
@pytest.mark.parametrize("off", [T - 121.0, T + 1.0 + 31.0, T - 200.0, T + 1.0 + 300.0])
def test_evidence_beyond_120_s_before_or_30_s_after_is_not_counted_at_all(method, off):
    w = two_members()
    _evidence(method, w, off)
    res = _call(method, run(w))
    assert (res.sessions, res.before_range, res.after_range) == ([], 0, 0)


@pytest.mark.parametrize("method", METHODS2)
def test_the_out_of_range_bands_count_evidence_of_any_session(method):
    w = two_members()
    w.src_logon("L5001", 0.0, S5001)
    _evidence(method, w, T - 60.0, S5000, uid="B1")
    _evidence(method, w, T - 61.0, S5001, uid="B2")
    _evidence(method, w, T - 62.0, 999, uid="B3")              # a system session also counts
    _evidence(method, w, T + 1.0 + 20.0, S5001, uid="A1")
    res = _call(method, run(w))
    assert res.sessions == [] and res.before_range == 3 and res.after_range == 1


def test_the_subject_counts_add_the_4648_and_the_command_line_bands():
    w = two_members()
    w.e4648("B1", T - 60.0, S5000)
    w.s1("B2", T - 61.0, "{GB2}", S5000)
    w.e4648("A1", T + 1.0 + 20.0, S5000)
    links = run(w).links()
    assert links.evidence_before_range == 2 and links.evidence_after_range == 1
    assert links.target_only_reason == "no_evidence_in_range"
    assert links.methods[E4648].before_range == 1 and links.methods[CMD].before_range == 1


def test_a_collapsed_sysmon1_and_4688_counts_once_in_range():
    w = base()
    w.s1("S", 90.0, "{G1}", S5000, pid=777)
    w.e4688("E", 90.2, 777, S5000)
    res = run(w).cmdline()
    (ev,) = res.evidence
    assert ev.session_key == skey(S5000) and ev.evidence_uids == ["E", "S"]
    assert res.sessions == [skey(S5000)]
    (row,) = [x for x in run(w).links().rows if x.method == CMD]
    assert row.evidence_uids == ["E", "S"] and row.candidate_count == 1


def test_a_collapsed_sysmon1_and_4688_counts_once_in_the_band():
    w = base()
    w.s1("S", T - 60.0, "{G1}", S5000, pid=777)
    w.e4688("E", T - 59.8, 777, S5000)
    res = run(w).cmdline()
    assert res.before_range == 1 and res.evidence == []


def test_two_different_processes_in_the_band_count_twice():
    w = base()
    w.s1("S", T - 60.0, "{G1}", S5000, pid=777)
    w.s1("S2", T - 59.0, "{G2}", S5000, pid=778)
    assert run(w).cmdline().before_range == 2


def test_a_4688_only_process_is_command_evidence_with_its_session():
    w = base()
    w.e4688("E", 90.0, 4242, S5000)
    res = run(w).cmdline()
    assert res.sessions == [skey(S5000)] and res.evidence[0].evidence_uids == ["E"]


def test_a_command_evidence_uid_with_no_cmd_result_or_naming_another_target_does_not_count():
    w = base()
    w.s1("S_NONE", 90.0, "{G0}", S5000, cmd_target=None)                 # no CmdResult at all
    w.s1("S_OTHER", 91.0, "{G1}", S5001, cmd_target="ep-03")             # names another target
    w.s1("S_DC", 92.0, "{G2}", S5001, cmd_target="dc01")
    w.s1("S_NOTHING", 93.0, "{G3}", S5001)
    w.cmd["S_NOTHING"] = CmdResult("S_NOTHING", (), False, (), True)     # a result that names nothing
    res = run(w).cmdline()
    assert res.evidence == [] and res.before_range == 0 and res.after_range == 0


def test_a_command_result_naming_several_targets_counts_for_each_of_them():
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000, cmd_target=None)
    w.cmd["S1"] = cr("S1", "ep-02", "ep-03")
    assert run(w).cmdline().sessions == [skey(S5000)]


def test_command_evidence_on_another_host_than_the_source_does_not_count():
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000, host="ep-03")
    w.s1("S2", 90.0, "{G2}", S5000, host="dc01")
    assert run(w).cmdline().evidence == []


def test_command_evidence_matched_member_count_is_the_member_count():
    w = two_members()
    w.s1("S1", 95.0, "{G1}", S5000)
    r = run(w)
    (ev,) = r.cmdline().evidence
    assert ev.matched_member_uids == ["M1", "M2"]
    (row,) = [x for x in r.links().rows if x.method == CMD]
    assert row.matched_member_count == 2


def test_4648_matched_member_count_is_the_member_count():
    w = two_members()
    w.e4648("F1", 95.0, S5000)
    r = run(w)
    (ev,) = r.e4648().evidence
    assert ev.matched_member_uids == ["M1", "M2"]
    (row,) = [x for x in r.links().rows if x.method == E4648]
    assert row.matched_member_count == 2


def test_the_command_session_is_the_process_session_and_two_sessions_are_two_candidates():
    w = base()
    w.src_logon("L5001", 0.0, S5001)
    w.s1("S1", 95.0, "{G1}", S5000)
    w.s1("S2", 96.0, "{G2}", S5001)
    w.s1("S3", 97.0, "{G3}", S5001)
    res = run(w).cmdline()
    assert res.sessions == [skey(S5000), skey(S5001)]
    assert [e.evidence_uids for e in res.evidence] == [["S1"], ["S2", "S3"]]


def test_a_command_process_with_a_null_logon_id_is_the_internal_no_session_id_reason_not_a_candidate():
    w = base()
    w.s1("S1", 95.0, "{G1}", None)
    r = run(w)
    res = r.cmdline()
    (ev,) = res.evidence
    assert ev.session_key is None and ev.reason == "no_session_id" and not ev.is_candidate and res.sessions == []
    links = r.links()
    assert [(x.method, x.session_unresolved_reason) for x in links.rows] == [(CMD, "no_session_id"), ("target_only", "")]


def test_a_command_in_a_system_session_is_not_a_candidate_and_is_counted():
    w = base()
    w.s1("S1", 95.0, "{G1}", 999)
    w.s1("S2", 96.0, "{G2}", 997)
    r = run(w)
    res = r.cmdline()
    assert res.sessions == [] and res.evidence == [] and res.system_evidence == 2
    links = r.links()
    assert links.system_session_evidence[CMD] == 2 and links.target_only_reason == "no_evidence_in_range"


def test_a_command_before_the_window_is_not_evidence_of_a_hop_in_the_window():
    w = base()
    w.s1("S1", PRE, "{G1}", S5000)
    res = run(w).cmdline()
    assert res.evidence == [] and res.before_range == 0


# ---- 4648
@pytest.mark.parametrize("text", ["ep-02", "EP-02", "Ep-02", "ep-02.lab.local", "endpoint-02", "ENDPOINT-02.LAB", TGT_IP])
def test_a_4648_text_naming_the_target_is_evidence(text):
    w = base()
    w.e4648("F1", 95.0, S5000, texts=(text,))
    assert run(w).e4648().sessions == [skey(S5000)]


@pytest.mark.parametrize("text", ["ep-022", "ep-0", "ep-2", "ep-02x", "ep-021", "xep-02", "endpoint-022", "192.168.50.220",
                                  "192.168.50.2", "1192.168.50.22", "192.168.50.22.5", "ep-02.5", "ep-03", "dc01",
                                  "", "-"])
def test_a_4648_text_that_only_looks_like_the_target_is_not_evidence(text):
    w = base()
    w.e4648("F1", 95.0, S5000, texts=(text,))
    assert run(w).e4648().evidence == []


def test_a_4648_with_several_target_texts_matches_when_any_names_the_target():
    w = base()
    w.e4648("F1", 95.0, S5000, texts=("ep-03", TGT_IP))
    assert run(w).e4648().sessions == [skey(S5000)]


def test_a_4648_with_no_target_text_read_never_matches():
    w = base()
    w.e4648("F1", 95.0, S5000)
    r = run(w)
    assert src.by_4648(r.subject, r.scan, {}, r.index.sessions, P).evidence == []
    assert src.by_4648(r.subject, r.scan, {"F1": ()}, r.index.sessions, P).evidence == []


def test_the_4648_session_is_the_subject_logon_id_not_session_id():
    w = base()
    w.e4648("F1", 95.0, S5000, session_id=111)
    r = run(w)
    (ev,) = r.e4648().evidence
    assert ev.session_key == skey(S5000)


def test_a_4648_credential_account_is_kept_and_the_session_account_is_its_own_4624():
    w = base()
    w.e4648("F1", 95.0, S5000, cred="cred_acct", subj_account="subj_acct")
    r = run(w)
    (ev,) = r.e4648().evidence
    assert ev.credential_accounts == ["cred_acct"]
    links = r.links()
    data = links.sessions[skey(S5000)]
    assert data.credential_accounts == ("cred_acct",) and data.account == "src_acct"
    (row,) = links.rows
    assert row.credential_accounts == ["cred_acct"] and row.source_session_account == "src_acct"


def test_4648_credential_accounts_of_one_session_are_collected_without_repeats():
    w = base()
    w.e4648("F1", 95.0, S5000, cred="cred_a")
    w.e4648("F2", 96.0, S5000, cred="cred_b")
    w.e4648("F3", 97.0, S5000, cred="cred_a")
    (ev,) = run(w).e4648().evidence
    assert ev.credential_accounts == ["cred_a", "cred_b"] and len(ev.evidence_uids) == 3


def test_a_4648_with_a_system_subject_logon_id_is_not_a_candidate_and_is_counted():
    w = base()
    w.e4648("F1", 95.0, 999)
    w.e4648("F2", 96.0, 996)
    r = run(w)
    res = r.e4648()
    assert res.sessions == [] and res.evidence == [] and res.system_evidence == 2
    assert r.links().system_session_evidence[E4648] == 2


def test_a_4648_with_a_null_subject_logon_id_is_the_internal_no_session_id_reason():
    w = base()
    w.e4648("F1", 95.0, None)
    res = run(w).e4648()
    (ev,) = res.evidence
    assert ev.session_key is None and ev.reason == "no_session_id" and res.sessions == []


def test_a_4648_of_a_session_with_no_4624_in_the_rows_is_an_unknown_open_session_candidate():
    w = base()
    w.e4648("F1", 95.0, 8123)
    r = run(w)
    res = r.e4648()
    assert len(res.sessions) == 1 and res.sessions[0][:2] == (SRC, 8123)
    data = r.links().sessions[res.sessions[0]]
    assert data.account is None and data.logon_type is None and data.open_uids == () and data.open_known is False


def test_a_4648_on_another_host_does_not_count():
    w = base()
    w.e4648("F1", 95.0, S5000, host="ep-03")
    assert run(w).e4648().evidence == []


def test_a_4648_outside_the_window_is_in_no_structure():
    w = base()
    w.e4648("F1", PRE, S5000)
    w.e4648("F2", POST, S5000)
    r = run(w)
    res = r.e4648()
    assert res.evidence == [] and res.before_range == 0 and res.after_range == 0


# ================================================================================================ ST-44 / session_methods / counts
def test_system_sessions_are_never_candidates_by_any_method_and_are_counted():
    w = base()
    w.s1("S1", 95.0, "{G1}", 999)
    w.s1("SP", 90.0, "{G2}", 997)
    w.s3("N1", 100.0, "{G2}")
    w.e4648("F1", 95.0, 996)
    links = run(w).links()
    assert links.candidate_count_all == 0 and links.candidate_sessions == [] and links.sessions == {}
    assert links.system_session_evidence == {PORT: 1, E4648: 1, CMD: 2}   # two system processes name the target
    assert all(r.session_key is None for r in links.rows)


def test_a_session_found_by_two_methods_has_both_methods_on_both_rows():
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s3("N1", 100.0, "{G1}")
    links = run(w).links()
    assert links.session_methods == {skey(S5000): [PORT, CMD]}
    assert [(r.method, r.session_methods) for r in links.rows] == [(PORT, [PORT, CMD]), (CMD, [PORT, CMD])]
    assert links.candidate_count_all == 1


def test_candidate_count_per_method_versus_over_all_methods():
    w = base()
    w.src_logon("L5001", 0.0, S5001)
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s3("N1", 100.0, "{G1}")                                       # port: 5000
    w.e4648("F1", 95.0, S5001)                                      # 4648: 5001
    w.s1("S2", 96.0, "{G2}", S5001)                                 # cmd: 5000 (S1) and 5001 (S2)
    links = run(w).links()
    assert links.candidate_counts == {PORT: 1, E4648: 1, CMD: 2}
    assert links.candidate_count_all == 2
    assert links.session_methods == {skey(S5000): [PORT, CMD], skey(S5001): [E4648, CMD]}
    by = {(r.method, r.source_session_id): r for r in links.rows}
    assert set(by) == {(PORT, S5000), (E4648, S5001), (CMD, S5000), (CMD, S5001)}
    assert by[(PORT, S5000)].candidate_count == 1 and by[(CMD, S5000)].candidate_count == 2
    assert by[(E4648, S5001)].candidate_count == 1
    assert {r.candidate_count_all for r in links.rows} == {2}
    assert by[(E4648, S5001)].session_methods == by[(CMD, S5001)].session_methods == [E4648, CMD]
    assert by[(PORT, S5000)].session_methods == by[(CMD, S5000)].session_methods == [PORT, CMD]


def test_rows_are_in_methods_order_then_session_order_and_the_run_is_deterministic():
    w = base()
    w.src_logon("L5001", 0.0, S5001)
    w.s1("S2", 96.0, "{G2}", S5001)
    w.s1("S1", 90.0, "{G1}", S5000)
    w.e4648("F1", 95.0, S5001)
    a = run(w).links()
    assert [(r.method, r.source_session_id) for r in a.rows] == [(E4648, S5001), (CMD, S5000), (CMD, S5001)]
    b = run(w).links()
    assert [(r.method, r.source_session_id, r.evidence_uids) for r in a.rows] == \
           [(r.method, r.source_session_id, r.evidence_uids) for r in b.rows]


def test_the_same_session_by_three_methods_is_one_candidate_session():
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s3("N1", 100.0, "{G1}")
    w.e4648("F1", 95.0, S5000)
    links = run(w).links()
    assert links.candidate_count_all == 1 and links.candidate_sessions == [skey(S5000)]
    assert links.session_methods[skey(S5000)] == [PORT, E4648, CMD]


def test_account_is_never_a_join_condition_a_session_of_another_account_is_a_candidate():
    """Correction I / ST-45: the member's account (acct_a) differs from the session's (src_acct) and from the 4648
    credential: the candidate row is still written."""
    w = base(account="acct_a")
    w.s1("S1", 90.0, "{G1}", S5000)
    links = run(w).links()
    assert links.candidate_sessions == [skey(S5000)] and links.sessions[skey(S5000)].account == "src_acct"


# ================================================================================================ time_delta_ms
def test_time_delta_is_the_nearest_evidence_minus_the_first_member_with_the_sign():
    w = base()
    w.s1("S_BEFORE", 98.0, "{G1}", S5000, pid=1)
    w.s1("S_AFTER", 103.5, "{G2}", S5000, pid=2)
    w.e4648("F_AFTER", 101.5, S5000)
    w.e4648("F_FAR", 120.0, S5000)
    links = run(w).links()
    by = {r.method: r for r in links.rows}
    assert by[CMD].time_delta_ms == -2000 and by[CMD].time_delta_raw_ms == -2000
    assert by[E4648].time_delta_ms == 1500 and by[E4648].time_delta_raw_ms == 1500


def test_time_delta_is_measured_from_the_first_member_not_the_last():
    w = two_members()
    w.s1("S1", 103.0, "{G1}", S5000)
    (row,) = [r for r in run(w).links().rows if r.method == CMD]
    assert row.time_delta_ms == 3000                                 # from M1 at 100 s, not M2 at 101 s


def test_time_delta_of_the_port_join_is_the_nearest_sysmon3():
    w = base()
    w.s1("S1", 50.0, "{G1}", S5000)
    w.s3("N1", 102.0, "{G1}")
    w.s3("N2", 99.25, "{G1}")
    (row,) = [r for r in run(w).links().rows if r.method == PORT]
    assert row.time_delta_ms == -750


def test_time_delta_uses_corrected_times_and_the_raw_delta_uses_logged_times(tmp_path):
    offs, chg = clocks(tmp_path, cf.offsets_spec(ep_01=(-18000, "ok", True)))
    w = base()
    w.s1("S1", 80.0, "{G1}", S5000)                                  # corrected 98 s
    w.e4648("F1", 83.0, S5000)                                       # corrected 101 s
    r = run(w, offsets=offs, changes=chg)
    by = {x.method: x for x in r.links(offsets=offs).rows}
    assert (by[CMD].time_delta_ms, by[CMD].time_delta_raw_ms) == (-2000, -20000)
    assert (by[E4648].time_delta_ms, by[E4648].time_delta_raw_ms) == (1000, -17000)


def test_time_delta_ties_pick_the_smaller_uid_deterministically():
    w = base()
    w.e4648("F_B", 102.0, S5000)
    w.e4648("F_A", 98.0, S5000)
    (row,) = r_rows(run(w), E4648)
    assert row.time_delta_ms == -2000


def r_rows(r: Run, method: str) -> list:
    return [x for x in r.links().rows if x.method == method]


# ================================================================================================ ST-02 clock_unreliable
def test_a_row_with_a_flagged_evidence_event_gets_clock_unreliable_1(tmp_path):
    offs, chg = clocks(tmp_path, cf.offsets_spec(ep_01=(2000, "wide", True)))
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.e4648("F1", 95.0, S5000)
    r = run(w, offsets=offs, changes=chg)
    assert all(x.get("clock_unreliable") for x in r.scan.link_rows if x["host"] == SRC)
    links = r.links(offsets=None)                                    # the host part is off: only the event part
    assert links.host_clock_unreliable == 0
    assert [x.clock_unreliable for x in links.rows] == [1, 1]


def test_a_flagged_port_join_sysmon3_gives_the_row_clock_unreliable_1(tmp_path):
    offs, chg = clocks(tmp_path, cf.offsets_spec(ep_01=(2000, "wide", True)))
    w = base()
    w.s1("S1", 50.0, "{G1}", S5000)
    w.s3("N1", 100.0, "{G1}")
    r = run(w, offsets=offs, changes=chg)
    (row,) = [x for x in r.links(offsets=None).rows if x.method == PORT]
    assert row.clock_unreliable == 1


def test_a_wide_source_host_via_offsets_gives_clock_unreliable_1_on_every_row(tmp_path):
    offs, _ = clocks(tmp_path, cf.offsets_spec(ep_01=(2000, "wide", True)))
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.e4648("F1", 95.0, S5000)
    r = run(w)                                                       # events not flagged
    links = r.links(offsets=offs)
    assert links.host_clock_unreliable == 1
    assert [x.clock_unreliable for x in links.rows] == [1, 1]


def test_a_wide_target_host_gives_clock_unreliable_1_and_so_does_the_target_only_row(tmp_path):
    offs, _ = clocks(tmp_path, cf.offsets_spec(ep_02=(2000, "wide", True)))
    r = run(base())
    links = r.links(offsets=offs)
    (row,) = links.rows
    assert row.method == "target_only" and row.clock_unreliable == 1 and links.host_clock_unreliable == 1


@pytest.mark.parametrize("status", ["none", "stale"])
def test_none_and_stale_hosts_are_unreliable_too(tmp_path, status):
    offs, _ = clocks(tmp_path, cf.offsets_spec(ep_01=(None, status, True)))
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    assert [x.clock_unreliable for x in run(w).links(offsets=offs).rows] == [1]


def test_an_otherwise_clean_row_gets_clock_unreliable_0(tmp_path):
    offs, chg = clocks(tmp_path, cf.offsets_spec())
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.e4648("F1", 95.0, S5000)
    r = run(w, offsets=offs, changes=chg)
    links = r.links(offsets=offs)
    assert links.host_clock_unreliable == 0 and [x.clock_unreliable for x in links.rows] == [0, 0]
    assert [x.clock_unreliable for x in run(w).links().rows] == [0, 0]       # and with no offsets at all


def test_an_unrelated_host_being_wide_does_not_flag_the_row(tmp_path):
    offs, chg = clocks(tmp_path, cf.offsets_spec(ep_03=(2000, "wide", True)))
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    r = run(w, offsets=offs, changes=chg)
    assert [x.clock_unreliable for x in r.links(offsets=offs).rows] == [0]


# ================================================================================================ SessionData
def test_a_session_opened_inside_the_window_gives_its_own_4624_account_type_and_uid():
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    r = run(w)
    links = r.links()
    data = links.sessions[skey(S5000)]
    assert (data.account, data.logon_type, data.open_uids) == ("src_acct", 3, ("L5000",))
    assert data.logon_id == S5000 and data.logon_id_hex == "0x1388" and data.opened_before_window is False
    (row,) = links.rows
    assert (row.source_session_account, row.source_session_logon_type, row.source_session_logon_uids) == \
           ("src_acct", 3, ["L5000"])


def test_a_session_opened_before_the_window_gives_an_empty_account_type_and_uid_read_through_window_open():
    w = World()
    w.member("M1")
    w.src_logon("L_PRE", PRE, S5000, account="pre_acct", logon_type=10)
    w.s1("S1", 90.0, "{G1}", S5000)
    r = run(w)
    links = r.links()
    assert links.candidate_sessions == [skey(S5000)]                # still a candidate, with its real key
    data = links.sessions[skey(S5000)]
    assert data.account is None and data.logon_type is None and data.open_uids == ()
    assert data.opened_before_window is True
    (row,) = links.rows
    assert row.source_session_account is None and row.source_session_logon_type is None
    assert row.source_session_logon_uids == [] and row.source_session_id == S5000
    assert "L_PRE" not in {u for rr in links.rows for u in rr.supporting_event_uids}


def test_the_session_data_of_each_candidate_session_is_its_own():
    w = base()
    w.src_logon("L5001", 0.0, S5001, account="other_acct", logon_type=10)
    w.s1("S1", 90.0, "{G1}", S5000)
    w.s1("S2", 91.0, "{G2}", S5001)
    links = run(w).links()
    assert (links.sessions[skey(S5000)].account, links.sessions[skey(S5000)].logon_type) == ("src_acct", 3)
    assert (links.sessions[skey(S5001)].account, links.sessions[skey(S5001)].logon_type) == ("other_acct", 10)


# ================================================================================================ confirm (ST-47, STT-10)
def test_norm_logon_guid_strips_braces_and_lowercases_and_refuses_zero_and_null():
    assert norm_logon_guid(GUID) == GUID_NORM == norm_logon_guid(GUID_NORM) == norm_logon_guid(" " + GUID_NORM.upper() + " ")
    for bad in (None, "", "   ", ZERO_GUID, "{" + ZERO_GUID + "}", "0" * 32):
        assert norm_logon_guid(bad) is None


def _krb_world(member_guid, g4769, host="dc01", off4769=95.0) -> World:
    w = World()
    w.member("M1", guid=member_guid)
    if g4769 is not False:
        w.e4769("K1", off4769, g4769, host=host)
    return w


def test_the_logon_guid_matches_a_dc01_4769_in_the_link_rows_and_confirms_with_that_uid():
    r = run(_krb_world(GUID_NORM, GUID_NORM))
    assert kerberos_confirm(r.hop.members, r.scan.link_rows) == ["K1"]


@pytest.mark.parametrize("member,dc", [(GUID, GUID_NORM), (GUID_NORM, GUID), (GUID, GUID), (GUID_NORM.upper(), GUID_NORM),
                                       ("  " + GUID + "  ", GUID_NORM)])
def test_braces_and_upper_case_are_normalised_before_the_comparison(member, dc):
    r = run(_krb_world(member, dc))
    assert kerberos_confirm(r.hop.members, r.scan.link_rows) == ["K1"]


@pytest.mark.parametrize("member,dc", [(ZERO_GUID, ZERO_GUID), ("{" + ZERO_GUID + "}", ZERO_GUID), (None, None),
                                       (None, GUID_NORM), (GUID_NORM, None), ("", ""), (GUID_NORM, "ffffffff-0000-0000-0000-000000000000")])
def test_a_zero_null_or_different_guid_never_confirms(member, dc):
    r = run(_krb_world(member, dc))
    assert kerberos_confirm(r.hop.members, r.scan.link_rows) == []


def test_a_4769_on_a_non_dc_host_never_confirms():
    for host in ("ep-01", "ep-02", "ep-03"):
        r = run(_krb_world(GUID_NORM, GUID_NORM, host=host))
        assert kerberos_confirm(r.hop.members, r.scan.link_rows) == [], host
    r = run(_krb_world(GUID_NORM, GUID_NORM, host="ep-01"))
    assert kerberos_confirm(r.hop.members, r.scan.link_rows, dc_host="ep-01") == ["K1"]   # the DC host is a parameter


@pytest.mark.parametrize("off", [PRE, POST])
def test_a_4769_outside_the_window_is_not_in_the_link_rows_so_it_neither_confirms_nor_is_counted(off):
    r = run(_krb_world(GUID_NORM, GUID_NORM, off4769=off))
    assert r.scan.link_rows == []
    assert kerberos_confirm(r.hop.members, r.scan.link_rows) == []
    assert confirm_of(r.hop, r.scan.link_rows, build_artefacts(r.hs, r.scan, r.index.sessions, r.gate, P)) == ("none", [])


def test_a_4769_that_is_not_in_link_rows_does_not_confirm_even_when_it_exists():
    r = run(_krb_world(GUID_NORM, GUID_NORM))
    assert kerberos_confirm(r.hop.members, []) == []


def test_a_hand_built_4769_row_marked_out_of_the_window_is_refused_too():
    r = run(_krb_world(GUID_NORM, GUID_NORM))
    rows = [dict(x, in_window=False) for x in r.scan.link_rows]
    assert kerberos_confirm(r.hop.members, rows) == []


def test_every_matching_4769_uid_is_returned_sorted_with_its_near_duplicate_copies():
    w = World()
    w.member("M1", guid=GUID_NORM)
    w.e4769("K2", 96.0, GUID_NORM, record_id=900)
    w.e4769("K1", 96.0, GUID_NORM, record_id=900)                    # same record: a near duplicate of K2
    w.e4769("K3", 97.0, GUID_NORM)
    w.e4769("K_OTHER", 97.0, "11111111-1111-1111-1111-111111111111")
    r = run(w)
    assert kerberos_confirm(r.hop.members, r.scan.link_rows) == ["K1", "K2", "K3"]


def test_any_member_with_a_matching_guid_confirms_the_hop():
    w = World()
    w.member("M1", guid=None)
    w.member("M2", T + 1.0, M_LID + 1, guid=GUID_NORM)
    w.e4769("K1", 96.0, GUID_NORM)
    r = run(w)
    assert kerberos_confirm(r.hop.members, r.scan.link_rows) == ["K1"]


def test_the_kerberos_confirmation_never_sets_or_changes_a_candidate_session():
    """STT-10: identical links with and without the 4769."""
    def build(with_4769: bool):
        w = World()
        w.member("M1", guid=GUID_NORM)
        w.src_logon("L5000", 0.0, S5000)
        w.src_logon("L5001", 0.0, S5001)
        w.s1("S1", 90.0, "{G1}", S5000)
        w.e4648("F1", 95.0, S5001)
        if with_4769:
            w.e4769("K1", 96.0, GUID_NORM)
        return run(w)

    with_, without = build(True), build(False)
    assert kerberos_confirm(with_.hop.members, with_.scan.link_rows) == ["K1"]
    assert kerberos_confirm(without.hop.members, without.scan.link_rows) == []

    def view(links: src.SubjectLinks):
        return ([(r.method, r.session_key, r.session_unresolved_reason, r.session_methods, r.candidate_count,
                  r.candidate_count_all, r.time_delta_ms, r.evidence_uids, r.supporting_event_uids,
                  r.target_only_reason) for r in links.rows],
                links.candidate_counts, links.session_methods, links.target_only_reason)
    assert view(with_.links()) == view(without.links())


def test_a_hop_confirmed_by_kerberos_with_no_source_candidate_stays_target_only():
    w = _krb_world(GUID_NORM, GUID_NORM)
    w.src_logon("L5000", 0.0, S5000)                                 # the source host has rows
    r = run(w)
    links = r.links()
    assert kerberos_confirm(r.hop.members, r.scan.link_rows) == ["K1"]
    assert links.target_only_reason == "no_evidence_in_range" and links.candidate_count_all == 0


# ---- service_admin_write and confirm_of
def _four_hops_world() -> World:
    """Four hops on ep-02, 60 s apart. A: nothing. B: a Kerberos GUID with its 4769. C: an install tied to a copy made
    under another logon. D: both."""
    w = World()
    w.member("LA", 100.0, 2000, 40001, rule=R4)
    w.member("LB", 200.0, 2100, 40002, rule=R4, guid=GUID_NORM)
    w.e4769("K_B", 199.0, GUID_NORM)
    w.member("LC", 300.0, 2200, 40003, rule=R4)
    w.member("LD", 400.0, 2300, 40004, rule=R4, guid="22222222-2222-2222-2222-222222222222")
    w.e4769("K_D", 399.0, "22222222-2222-2222-2222-222222222222")
    w.member("LE", 50.0, 2400, 40005, rule=R4)                     # the copy is logged under this logon
    for uid, off, name, img in (("C", 300.5, "SvcC", r"C:\Windows\Cpay.exe"), ("D", 400.5, "SvcD", r"C:\Windows\Dpay.exe")):
        w.events.append(sf.ev(f"{uid}4697", "Security", 4697, host=TGT, off=off,
                              subject_logon_id={"C": 2200, "D": 2300}[uid], service_name=name, service_image_path=img))
        w.events.append(sf.ev(f"{uid}7045", "System", 7045, host=TGT, off=off, service_name=name, service_image_path=img))
    # copies of both binaries, written 0.2 s before their installs under the logon of hop E
    w.events.append(sf.ev("CP_C", "Security", 5145, host=TGT, off=300.3, subject_logon_id=2400,
                          share_name=r"\\*\ADMIN$", relative_target_name=r"Windows\Cpay.exe"))
    w.events.append(sf.ev("CP_D", "Security", 5145, host=TGT, off=400.3, subject_logon_id=2400,
                          share_name=r"\\*\ADMIN$", relative_target_name=r"Windows\Dpay.exe"))
    return w


def test_a_hop_owning_a_ties_install_gets_the_tie_uids_and_other_hops_get_none():
    r = run(_four_hops_world())
    art = build_artefacts(r.hs, r.scan, r.index.sessions, r.gate, P)
    hops = {m.uid: h for h in r.hs.hops for m in h.members}
    assert sorted(service_admin_write(hops["LC"].hop_id, art)) == ["C4697", "C7045", "CP_C"]
    assert sorted(service_admin_write(hops["LD"].hop_id, art)) == ["CP_D", "D4697", "D7045"]
    for name in ("LA", "LB", "LE"):                                  # E only holds the copy; the install is another hop's
        assert service_admin_write(hops[name].hop_id, art) == [], name
    assert service_admin_write("no-such-hop", art) == []


def test_confirm_of_covers_each_of_the_four_values_and_the_uids():
    r = run(_four_hops_world())
    art = build_artefacts(r.hs, r.scan, r.index.sessions, r.gate, P)
    hops = {m.uid: h for h in r.hs.hops for m in h.members}
    assert confirm_of(hops["LA"], r.scan.link_rows, art) == ("none", [])
    assert confirm_of(hops["LB"], r.scan.link_rows, art) == ("kerberos_logonguid", ["K_B"])
    label, uids = confirm_of(hops["LC"], r.scan.link_rows, art)
    assert label == "service_admin_write" and uids == ["C4697", "C7045", "CP_C"]
    label, uids = confirm_of(hops["LD"], r.scan.link_rows, art)
    assert label == "kerberos_logonguid;service_admin_write"
    assert uids == sorted({"K_D", "D4697", "D7045", "CP_D"})


def test_confirm_of_never_names_a_source_session():
    """The confirmation is only a label and event uids: nothing in it is a session, and no link row changes."""
    r = run(_four_hops_world())
    art = build_artefacts(r.hs, r.scan, r.index.sessions, r.gate, P)
    for h in r.hs.hops:
        label, uids = confirm_of(h, r.scan.link_rows, art)
        assert isinstance(label, str) and all(isinstance(u, str) for u in uids)


# ================================================================================================ ST-01
def test_evidence_outside_the_window_is_in_no_row():
    w = base()
    w.s1("S1", PRE, "{G1}", S5000)
    w.s3("N_PRE", PRE, "{G1}")
    w.e4648("F_POST", POST, S5000)
    links = run(w).links()
    assert links.candidate_count_all == 0
    assert all(not r.evidence_uids for r in links.rows)
    assert {u for r in links.rows for u in r.supporting_event_uids} == {"M1"}


def test_links_never_mutate_the_scan_rows():
    w = base()
    w.s1("S1", 90.0, "{G1}", S5000)
    w.e4648("F1", 95.0, S5000)
    r = run(w)
    before = [dict(x) for x in r.scan.in_window + r.scan.link_rows]
    r.links()
    assert [dict(x) for x in r.scan.in_window + r.scan.link_rows] == before
