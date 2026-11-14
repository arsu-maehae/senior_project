"""Tests for T7.3 task 5, fast part: the data limits (decision 048 item 13 as amended), `ScanResult.hosts_loaded`
(048 item 6 as amended), the record builders of `stitch.check_links` and a synthetic end-to-end run of the check CLI.

Written from the plan (task 5; sections 1, 5 C1 / C16), decision 048 (items 1, 6, 11, 13 as amended) and spec
03_stitch (STT-12, STT-13, section 2 "no part of a command line, no account name, no image in an output file"), not from
the implementation (the code was read only for public names, signatures and the fixed key lists of the records).

Accepted readings tested as stated by the coordinator:
- `data_limitation` is set only when source evidence on OTHER hosts names the host after its last kept Security event;
- in `t73_links.json`, lab IPs, target-side names and the schema's own key names are not command text.

World: target ep-02 (192.168.50.22), source ep-01 (192.168.50.21). Event times are seconds after 10:30:00
(`stitch_fixtures.at`), the window is 10:00-11:00 (2000 s is after it). Messages carry uids, counts and ids only; no fake
account or command text is ever put in an assertion message.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import replace
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stitch_fixtures as sf  # noqa: E402
from gate.classify import ip_kind  # noqa: E402
from gate.timeutil import delta_ms, to_us  # noqa: E402
from stitch import check_links as cl  # noqa: E402
from stitch import source as src  # noqa: E402
from stitch.artefacts import ArtefactRow, build_artefacts  # noqa: E402
from stitch.check_index import check_text  # noqa: E402
from stitch.cmdtext import CmdResult  # noqa: E402
from stitch.confirm import confirm_of  # noqa: E402
from stitch.hops import build_hops  # noqa: E402
from stitch.index import build_index  # noqa: E402
from stitch.inputs import GateRows  # noqa: E402
from stitch.links import HostLimit, LinkIndex, data_limits, link_counts  # noqa: E402
from stitch.params import StitchParams  # noqa: E402
from stitch.scan import scan_rows  # noqa: E402

TRIAL = sf.TRIAL
START_US, END_US = to_us(sf.WIN_START), to_us(sf.WIN_END)
P = StitchParams()
SRC, TGT, THIRD = "ep-01", "ep-02", "ep-03"
SRC_IP, TGT_IP, THIRD_IP = "192.168.50.21", "192.168.50.22", "192.168.50.23"
T = 100.0                # the member 4624
LAST = 110.0             # the last Security event of ep-02 (a 4634) in the data-limit worlds
POST = 2000.0            # after the window end (10:30:00 + 2000 s = 11:03:20)
PRE = -2000.0
PORT, E4648, CMD = src.METHOD_PORT, src.METHOD_4648, src.METHOD_CMD
LID = 7000


def cr(uid: str, *targets: str) -> CmdResult:
    """A hand-built command result naming `targets` (no text anywhere)."""
    return CmdResult(event_uid=uid, targets=tuple((t, "host_name", "plain") for t in sorted(targets)),
                     undecodable=False, names_found=(), has_command=True)


# ---------------------------------------------------------------------------------------------- the synthetic world
class W:
    """Events, gate rows, `CmdResult`s and 4648 target texts of one synthetic trial."""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.triggers: list[dict] = []
        self.unmatched: list[dict] = []
        self.cmd: dict[str, CmdResult] = {}
        self.t4648: dict[str, tuple] = {}

    def member(self, uid: str, off: float = T, lid: int = LID, port: int | None = 50000, *, ip: str = SRC_IP,
               account: str = "acct_a", rule: str | None = "R4_smb", host: str = TGT) -> str:
        self.events.append(sf.ev(uid, "Security", 4624, host=host, off=off, logon_type=3, target_logon_id=lid,
                                 account_name=account, source_ip=ip, source_port=port,
                                 authentication_package="NTLM"))
        row = {"trigger_id": f"{'t' if rule else 'u'}-{uid}", "host": host, "anchor_logon_uid": uid,
               "trigger_event_uid": uid, "target_logon_id": str(lid), "source_ip": ip, "ip_kind": ip_kind(ip),
               "machine_account": "0", "clock_unreliable": "0"}
        if rule:
            row["rule"] = rule
            self.triggers.append(row)
        else:
            self.unmatched.append(row)
        return uid

    def src_logon(self, uid: str, off: float, lid: int, *, host: str = SRC, account: str = "src_acct") -> str:
        self.events.append(sf.ev(uid, "Security", 4624, host=host, off=off, logon_type=3, target_logon_id=lid,
                                 account_name=account))
        return uid

    def logoff(self, uid: str, off: float, lid: int, *, host: str = TGT) -> str:
        self.events.append(sf.ev(uid, "Security", 4634, host=host, off=off, target_logon_id=lid))
        return uid

    def s3(self, uid: str, off: float, *, dip: str = TGT_IP, initiated: int = 1, host: str = SRC,
           sport: int | None = 50000, guid: str | None = None) -> str:
        self.events.append(sf.ev(uid, "Sysmon", 3, host=host, off=off, process_guid=guid, initiated=initiated,
                                 source_ip=SRC_IP, source_port=sport, destination_ip=dip, destination_port=445))
        return uid

    def e4648(self, uid: str, off: float, subj_lid: int, *, host: str = SRC, texts: tuple = (TGT,),
              cred: str = "cred_acct", subj_account: str = "subj_acct") -> str:
        self.events.append(sf.ev(uid, "Security", 4648, host=host, off=off, subject_logon_id=subj_lid,
                                 session_id=999999, account_name=cred, subject_account=subj_account,
                                 destination_host=texts[0]))
        self.t4648[uid] = tuple(texts)
        return uid

    def s1(self, uid: str, off: float, guid: str, lid: int, *, pid: int | None = None, host: str = SRC,
           target: str | None = TGT, image: str = "PLACEHOLDER-IMAGE") -> str:
        self.events.append(sf.ev(uid, "Sysmon", 1, host=host, off=off, process_guid=guid, process_id=pid,
                                 session_id=lid, image=image))
        if target is not None:
            self.cmd[uid] = cr(uid, target)
        return uid

    def e4688(self, uid: str, off: float, pid: int, lid: int, *, host: str = SRC, target: str | None = TGT) -> str:
        self.events.append(sf.ev(uid, "Security", 4688, host=host, off=off, process_id=pid, target_logon_id=lid))
        if target is not None:
            self.cmd[uid] = cr(uid, target)
        return uid

    def e22(self, uid: str, off: float, *, host: str) -> str:
        """A Sysmon 22 (DNS query): a kind the scan neither keeps nor counts."""
        self.events.append(sf.ev(uid, "Sysmon", 22, host=host, off=off))
        return uid


class Built:
    def __init__(self, w: W, params: StitchParams = P) -> None:
        self.w, self.params = w, params
        self.scan = scan_rows([dict(e) for e in w.events], START_US, END_US, None, ())
        self.index = build_index(TRIAL, self.scan, params)
        self.gate = GateRows(triggers=[dict(r) for r in w.triggers], unmatched=[dict(r) for r in w.unmatched],
                             supporting=[])
        self.hs = build_hops(TRIAL, self.gate, self.scan, self.index.sessions, params)

    def limits(self, params: StitchParams | None = None) -> dict[str, HostLimit]:
        return data_limits(self.scan, self.hs, self.index.processes, self.w.cmd, self.w.t4648, END_US,
                           self.params if params is None else params)


def limits_world() -> W:
    """Hop M1 (ep-01 -> ep-02) at 100 s; source session 5000 opened on ep-01 at 0 s; ep-02's last Security event is a
    4634 at 110 s. A second hop (another source IP) at 30 s on ep-02: last member 80 s before that event."""
    w = W()
    w.member("M1", T, LID)
    w.member("M0", 30.0, LID + 1, 50100, ip=THIRD_IP)
    w.src_logon("L5000", 0.0, 5000)
    w.logoff("X110", LAST, LID)
    return w


def lim(w: W, host: str = TGT, params: StitchParams | None = None) -> HostLimit:
    return Built(w).limits(params)[host]


# ================================================================================================ data_limits
def test_quiet_world_lists_hosts_with_security_rows_and_labels_none():
    got = Built(limits_world()).limits()
    assert sorted(got) == [SRC, TGT]
    for h, lm in got.items():
        assert isinstance(lm, HostLimit) and lm.host == h
        assert lm.data_limitation == 0 and lm.hops_near_end == []
        assert lm.evidence_after == {PORT: 0, E4648: 0, CMD: 0}
        assert lm.evidence_after_uids == {PORT: [], E4648: [], CMD: []}
    e2, e1 = got[TGT], got[SRC]
    assert e2.last_security_uid == "X110" and e1.last_security_uid == "L5000"
    assert e2.last_security_us_raw == e2.last_security_us == to_us(sf.at(LAST))
    assert e2.ms_before_window_end == delta_ms(END_US, to_us(sf.at(LAST)))
    assert e1.ms_before_window_end == delta_ms(END_US, to_us(sf.at(0.0)))


def test_sysmon3_naming_the_host_after_its_last_security_event_labels_it_and_lists_the_near_hop():
    w = limits_world()
    w.s3("N1", 120.0)
    lm = lim(w)
    assert lm.data_limitation == 1
    assert lm.evidence_after == {PORT: 1, E4648: 0, CMD: 0}
    assert lm.evidence_after_uids[PORT] == ["N1"]
    assert lm.evidence_after_uids[E4648] == [] and lm.evidence_after_uids[CMD] == []
    # M1 (last member 10 s before the event) is within LINK_AFTER_S (15 s); the second hop (80 s before) is not
    near = [h.hop_id for h in Built(w).hs.hops if h.members[-1].uid == "M1"]
    assert lm.hops_near_end == near and len(near) == 1
    assert Built(w).limits()[SRC].data_limitation == 0


def test_only_a_4648_naming_the_host_after_its_last_security_event_labels_it():
    w = limits_world()
    w.e4648("F1", 120.0, 5000)
    lm = lim(w)
    assert lm.data_limitation == 1
    assert lm.evidence_after == {PORT: 0, E4648: 1, CMD: 0}
    assert lm.evidence_after_uids[E4648] == ["F1"] and len(lm.hops_near_end) == 1


def test_only_a_command_naming_the_host_after_its_last_security_event_labels_it():
    w = limits_world()
    w.s1("S1", 120.0, "{G1}", 5000)
    lm = lim(w)
    assert lm.data_limitation == 1
    assert lm.evidence_after == {PORT: 0, E4648: 0, CMD: 1}
    assert lm.evidence_after_uids[CMD] == ["S1"] and len(lm.hops_near_end) == 1


def test_a_sysmon1_and_4688_of_one_process_count_once_and_both_uids_are_listed():
    w = limits_world()
    w.s1("S1", 120.0, "{G1}", 5000, pid=4242)
    w.e4688("B1", 120.5, 4242, 5000)
    lm = lim(w)
    assert lm.evidence_after[CMD] == 1
    assert lm.evidence_after_uids[CMD] == ["B1", "S1"]


def test_counts_are_per_method_and_per_event():
    w = limits_world()
    w.s3("N1", 120.0)
    w.s3("N2", 121.0)
    w.e4648("F1", 122.0, 5000)
    w.s1("S1", 123.0, "{G1}", 5000)
    lm = lim(w)
    assert lm.evidence_after == {PORT: 2, E4648: 1, CMD: 1} and lm.data_limitation == 1
    assert lm.evidence_after_uids[PORT] == ["N1", "N2"]


def test_evidence_before_the_last_security_event_does_not_label():
    w = limits_world()
    w.s3("N1", 105.0)
    w.e4648("F1", 106.0, 5000)
    w.s1("S1", 107.0, "{G1}", 5000)
    lm = lim(w)
    assert (lm.data_limitation, lm.hops_near_end) == (0, [])
    assert lm.evidence_after == {PORT: 0, E4648: 0, CMD: 0}


def test_evidence_must_be_strictly_after_the_event_one_millisecond_decides():
    w = limits_world()
    w.s3("EARLY", LAST - 0.001)
    assert lim(w).data_limitation == 0
    w = limits_world()
    w.s3("LATE", LAST + 0.001)
    assert lim(w).data_limitation == 1


def test_evidence_logged_on_the_host_itself_does_not_label_it():
    w = limits_world()
    w.s3("SELF3", 120.0, host=TGT, dip=TGT_IP)                       # the host's own Sysmon 3 naming itself
    w.s1("SELF1", 121.0, "{G9}", LID, host=TGT, target=TGT)          # its own command naming itself
    lm = lim(w)
    assert (lm.data_limitation, lm.hops_near_end) == (0, [])
    assert lm.evidence_after == {PORT: 0, E4648: 0, CMD: 0}


def test_evidence_after_the_window_does_not_label():
    w = limits_world()
    w.s3("N1", POST)
    w.e4648("F1", POST, 5000)
    w.s1("S1", POST, "{G1}", 5000)
    b = Built(w)
    assert all(r["event_uid"] not in {"N1", "F1", "S1"} for r in b.scan.in_window + b.scan.link_rows)
    lm = b.limits()[TGT]
    assert (lm.data_limitation, lm.hops_near_end) == (0, [])
    assert lm.evidence_after == {PORT: 0, E4648: 0, CMD: 0}


def test_evidence_before_the_window_does_not_label():
    w = limits_world()
    w.s3("N1", PRE)
    lm = lim(w)
    assert lm.data_limitation == 0 and lm.evidence_after[PORT] == 0


def test_a_sysmon3_that_is_not_initiated_or_names_another_host_does_not_label():
    w = limits_world()
    w.s3("N1", 120.0, initiated=0)
    w.s3("N2", 121.0, dip=THIRD_IP)
    w.s1("S1", 122.0, "{G1}", 5000, target=THIRD)                    # a command naming another host
    lm = lim(w)
    assert lm.data_limitation == 0 and lm.evidence_after == {PORT: 0, E4648: 0, CMD: 0}
    third = lim(w, host=SRC)                                         # ep-01 itself is named by nothing here
    assert third.data_limitation == 0


def test_a_4648_naming_another_host_does_not_label():
    w = limits_world()
    w.e4648("F1", 120.0, 5000, texts=(THIRD,))
    assert lim(w).data_limitation == 0


def test_a_labelled_host_lists_only_hops_whose_last_member_is_within_link_after_s_before_the_event():
    w = limits_world()
    w.s3("N1", 120.0)
    b = Built(w)
    near_default = b.limits()[TGT].hops_near_end
    far = [h.hop_id for h in b.hs.hops if h.members[-1].uid == "M0"]
    assert near_default and not set(near_default) & set(far)
    # the 10 s distance drops out when LINK_AFTER_S is 5 s (the list follows the parameter)
    assert b.limits(replace(P, link_after_s=5.0))[TGT].hops_near_end == []
    assert b.limits(replace(P, link_after_s=90.0))[TGT].hops_near_end == sorted(near_default + far)


def test_hops_near_end_is_empty_for_a_host_that_is_not_labelled():
    lm = lim(limits_world())
    assert lm.data_limitation == 0 and lm.hops_near_end == []


def test_data_limit_labels_follow_the_evidence_sum_only():
    w = limits_world()
    w.s3("N1", 120.0)
    for h, lm in Built(w).limits().items():
        assert lm.data_limitation == int(sum(lm.evidence_after.values()) > 0), h
        assert all(lm.evidence_after[m] == len(lm.evidence_after_uids[m]) for m in lm.evidence_after), h


# ================================================================================================ hosts_loaded
def test_hosts_loaded_holds_hosts_of_rows_of_any_kind_and_time():
    w = W()
    w.member("M1", T, LID, ip=THIRD_IP)
    w.e22("D1", 50.0, host=THIRD)                  # in-window Sysmon 22: neither kept nor counted by the scan
    scan = scan_rows([dict(e) for e in w.events], START_US, END_US, None, ())
    assert not [r for r in scan.in_window + scan.link_rows + scan.lookback if r["host"] == THIRD]
    assert scan.hosts_loaded == [THIRD, TGT] or scan.hosts_loaded == sorted([TGT, THIRD])
    assert THIRD in scan.hosts_loaded and TGT in scan.hosts_loaded


def test_hosts_loaded_includes_pre_and_post_window_rows_and_leaves_out_a_null_host():
    w = W()
    w.e22("D1", PRE, host="ep-03")
    w.e22("D2", POST, host="dc01")
    w.events.append(sf.ev("N0", "Sysmon", 22, host=None, off=1.0))
    scan = scan_rows([dict(e) for e in w.events], START_US, END_US, None, ())
    assert scan.hosts_loaded == ["dc01", "ep-03"]


def test_a_source_host_with_only_unkept_rows_is_not_source_host_no_logs():
    w = W()
    w.member("M1", T, LID, ip=THIRD_IP)            # the source is ep-03 ...
    w.e22("D1", 50.0, host=THIRD)                  # ... which has only a Sysmon 22
    b = Built(w)
    links = src.build_links(b.hs, b.scan, b.index, w.cmd, w.t4648, P)
    (sl,) = links.values()
    assert sl.source_host == THIRD
    assert sl.target_only_reason == "no_evidence_in_range"


def test_a_source_host_with_no_row_at_all_is_source_host_no_logs():
    w = W()
    w.member("M1", T, LID, ip=THIRD_IP)
    b = Built(w)
    (sl,) = src.build_links(b.hs, b.scan, b.index, w.cmd, w.t4648, P).values()
    assert sl.source_host == THIRD and sl.target_only_reason == "source_host_no_logs"


def test_a_source_host_whose_only_row_is_outside_the_window_is_not_source_host_no_logs():
    w = W()
    w.member("M1", T, LID, ip=THIRD_IP)
    w.e22("D1", POST, host=THIRD)
    b = Built(w)
    (sl,) = src.build_links(b.hs, b.scan, b.index, w.cmd, w.t4648, P).values()
    assert sl.target_only_reason == "no_evidence_in_range"


# ================================================================================================ record builders
FAKE_MEMBER = "FAKE_MEMBER_ACCT_ZQ7"
FAKE_SRC = "FAKE_SRC_ACCT_ZQ7"
FAKE_CRED = "FAKE_CRED_ACCT_ZQ7"
FAKE_SUBJ = "FAKE_SUBJ_ACCT_ZQ7"
FAKE_IMAGE = "C:\\FAKE\\IMAGE_PATH_ZQ7.exe"
FAKE_COMMAND = "FAKE-LONG-COMMAND-ZQ7 --password hunter2-ZQ7 --target ep-02 --payload 0123456789abcdef0123456789abcdef"
FAKE_TOKENS = ("FAKE_", "ZQ7", "hunter2", "IMAGE_PATH", "LONG-COMMAND", "0123456789abcdef", "--payload", "--password")

HOP_KEYS = ["hop_id", "target_host", "source_ip", "ip_kind", "source_host", "protocol", "rules", "is_seed", "first_utc",
            "first_utc_corrected", "last_utc_corrected", "member_count", "member_logon_uids", "member_logon_ids_hex",
            "member_ports", "mixed_account", "authentication_packages", "followup_logon_uids", "inside_gap_max_ms",
            "prev_gap_ms", "next_gap_ms", "gap_near_threshold", "splits_at_1s", "merges_at_3s", "shares_port_with_hops",
            "service_install_count", "supporting_span_ms", "confirm", "confirm_event_uids", "candidate_count_all",
            "evidence_before_range", "evidence_after_range", "target_only_reason", "clock_unreliable",
            "gate_clock_unreliable", "links"]
LINK_KEYS = ["method", "session_methods", "source_session_id_hex", "session_unresolved_reason", "candidate_count",
             "matched_member_count", "time_delta_ms", "time_delta_raw_ms", "supporting_event_uids", "clock_unreliable",
             "source_session_logon_type", "source_session_logon_uid", "names_found"]
ARTEFACT_KEYS = ["hop_id", "kind", "member_logon_uid", "logged_under_hop_id", "method", "candidate_count",
                 "time_delta_ms", "supporting_span_ms", "confidence_tier", "event_uids", "names",
                 "untied_same_name_bursts"]
LIMIT_KEYS = ["last_security_event_uid", "last_security_utc", "last_security_utc_corrected", "ms_before_window_end",
              "evidence_after", "evidence_after_event_uids", "data_limitation", "hops_near_end"]
# Words that would name a forbidden field (spec 2: no account, image or command text in an output file).
# Flags such as `mixed_account` and method names such as `cmdline_target` are no account or command text.
FORBIDDEN_KEY_PARTS = ("account_name", "subject_account", "session_account", "credential", "image", "command_line",
                       "password", "user_name", "username")
FORBIDDEN_KEYS = ("account", "accounts", "command", "cmd")


def rich_world() -> W:
    """A hop with two candidate sessions whose objects carry a fake account, 4648 credential, image and command."""
    w = W()
    w.member("M1", T, LID, 50000, account=FAKE_MEMBER)
    w.member("M2", T + 0.5, LID + 1, 50001, account=FAKE_MEMBER)
    w.src_logon("L5000", 0.0, 5000, account=FAKE_SRC)
    w.s1("S1", 95.0, "{G1}", 5000, image=FAKE_IMAGE)
    w.s3("N1", 100.2, guid="{G1}")
    w.e4648("F1", 96.0, 5000, cred=FAKE_CRED, subj_account=FAKE_SUBJ)
    w.logoff("X110", LAST, LID)
    return w


def make_link_index(w: W) -> tuple[LinkIndex, Built]:
    b = Built(w)
    arts = build_artefacts(b.hs, b.scan, b.index.sessions, b.gate, P)
    hop = b.hs.hops[0]
    # a hand-made artefact row carrying a target-side name (allowed) and a fake command (never allowed)
    arts.rows.append(ArtefactRow(hop_id=hop.hop_id, kind="share_burst", member_logon_uid="M1", logged_under_hop_id=hop.hop_id,
                                 method="logon_id", candidate_count=1, time_delta_ms=10, supporting_span_ms=20,
                                 confidence_tier="A", event_uids=["M1"], names=["Xpay.exe"],
                                 untied_same_name_bursts=[], ref_id="b1", first_us_raw=hop.first_us_raw,
                                 last_us_raw=hop.first_us_raw + 20))
    links = src.build_links(b.hs, b.scan, b.index, b.w.cmd, b.w.t4648, P)
    confirm = {h.hop_id: confirm_of(h, b.scan.link_rows, arts) for h in b.hs.hops}
    limits = b.limits()
    counts = link_counts(b.scan, b.hs, arts, links, confirm, limits)
    return LinkIndex(trial_id=TRIAL, hopset=b.hs, artefacts=arts, links=links, confirm=confirm, data_limits=limits,
                     counts=counts), b


def plant(obj: object) -> None:
    """Add a fake command attribute to a source object (also a frozen dataclass): a record built from an allowlist of
    keys must not show it."""
    object.__setattr__(obj, "command_line", FAKE_COMMAND)
    object.__setattr__(obj, "image", FAKE_IMAGE)
    object.__setattr__(obj, "account", FAKE_MEMBER)


def all_keys(value: object) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            out.append(str(k))
            out.extend(all_keys(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(all_keys(v))
    return out


def test_the_source_objects_really_carry_the_fake_account_credential_and_image():
    li, b = make_link_index(rich_world())
    h = li.hopset.hops[0]
    assert {m.account for m in h.members} == {FAKE_MEMBER}
    rows = li.links[h.hop_id].rows
    assert any(r.source_session_account == FAKE_SRC for r in rows)
    assert any(FAKE_CRED in r.credential_accounts for r in rows)
    assert any(r.method == PORT and r.session_key is not None for r in rows)
    assert any(r.method == E4648 and r.session_key is not None for r in rows)
    assert any(r.method == CMD and r.session_key is not None for r in rows)
    assert any(r["image"] == FAKE_IMAGE for r in b.scan.in_window)


def test_link_record_emits_exactly_its_fixed_key_list_and_no_account_or_command():
    li, _ = make_link_index(rich_world())
    h = li.hopset.hops[0]
    for r in li.links[h.hop_id].rows:
        plant(r)
        rec = cl.link_record(r)
        assert list(rec) == LINK_KEYS or sorted(rec) == sorted(LINK_KEYS)
        assert set(rec) == set(LINK_KEYS)
        text = json.dumps(rec)
        for tok in FAKE_TOKENS:
            assert tok not in text


def test_hop_record_emits_exactly_its_fixed_key_list_and_no_account_or_command():
    li, _ = make_link_index(rich_world())
    h = li.hopset.hops[0]
    plant(h)
    for m in h.members:
        plant(m)
    sl = li.links[h.hop_id]
    plant(sl)
    for r in sl.rows:
        plant(r)
    rec = cl.hop_record(h, sl, li)
    assert set(rec) == set(HOP_KEYS) and len(rec) == len(HOP_KEYS)
    assert len(rec["links"]) == len(sl.rows)
    assert rec["member_logon_uids"] == ["M1", "M2"] and rec["member_count"] == 2
    assert rec["member_logon_ids_hex"] == ["0x1b58", "0x1b59"]
    text = json.dumps(rec)
    for tok in FAKE_TOKENS:
        assert tok not in text


def test_artefact_record_emits_exactly_its_fixed_key_list_and_keeps_target_side_names_only():
    li, _ = make_link_index(rich_world())
    row = li.artefacts.rows[-1]
    plant(row)
    rec = cl.artefact_record(row)
    assert set(rec) == set(ARTEFACT_KEYS) and len(rec) == len(ARTEFACT_KEYS)
    assert rec["names"] == ["Xpay.exe"] and rec["event_uids"] == ["M1"]
    text = json.dumps(rec)
    for tok in FAKE_TOKENS:
        assert tok not in text


def test_limit_record_emits_exactly_its_fixed_key_list():
    w = rich_world()
    w.s3("N9", 130.0, guid="{G1}")
    li, _ = make_link_index(w)
    lm = li.data_limits[TGT]
    plant(lm)
    rec = cl.limit_record(lm)
    assert set(rec) == set(LIMIT_KEYS) and len(rec) == len(LIMIT_KEYS)
    assert rec["data_limitation"] == 1 and rec["evidence_after"][PORT] == 1
    assert rec["evidence_after_event_uids"][PORT] == ["N9"]
    assert rec["last_security_event_uid"] == "X110"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z", rec["last_security_utc"])
    text = json.dumps(rec)
    for tok in FAKE_TOKENS:
        assert tok not in text


def test_links_check_data_has_one_hop_record_per_hop_and_one_artefact_record_per_row():
    w = rich_world()
    w.member("M5", 400.0, LID + 5, 50500, ip=THIRD_IP)        # a second hop
    li, _ = make_link_index(w)
    data = cl.links_check_data(li, {"db": {"path": "x"}})
    assert data["trial_id"] == TRIAL and data["db"] == {"path": "x"}
    assert [h["hop_id"] for h in data["hops"]] == sorted(h.hop_id for h in li.hopset.hops)
    assert len(data["hops"]) == len(li.hopset.hops) == len({h["hop_id"] for h in data["hops"]}) == 2
    for rec in data["hops"]:
        assert len(rec["links"]) == len(li.links[rec["hop_id"]].rows)
    assert len(data["artefacts"]) == len(li.artefacts.rows)
    assert sorted(data["data_limits"]) == sorted(li.data_limits)
    assert data["counts"]["hops"] == 2
    assert json.loads(json.dumps(data)) == data                       # JSON-ready
    assert check_text(data) == check_text(cl.links_check_data(li, {"db": {"path": "x"}}))


def test_no_key_of_any_record_names_an_account_image_or_command_field():
    li, _ = make_link_index(rich_world())
    data = cl.links_check_data(li, {})
    keys = set(all_keys(data))
    bad = sorted(k for k in keys if k.lower() in FORBIDDEN_KEYS or any(p in k.lower() for p in FORBIDDEN_KEY_PARTS))
    assert bad == [], f"forbidden-looking key(s): {bad}"


def test_the_whole_check_text_holds_no_fake_account_credential_image_or_command():
    li, _ = make_link_index(rich_world())
    h = li.hopset.hops[0]
    for obj in [h, li.links[h.hop_id], *li.links[h.hop_id].rows, *h.members, *li.artefacts.rows,
                *li.data_limits.values()]:
        plant(obj)
    text = check_text(cl.links_check_data(li, {"parameters": {"lab_host_ips": dict(P.lab_host_ips)}}))
    for tok in FAKE_TOKENS:
        assert tok not in text
    for i in range(len(FAKE_COMMAND) - 11):
        assert FAKE_COMMAND[i:i + 12] not in text.replace(TGT, "")


# ================================================================================================ end to end, synthetic repo
PLANTED = ("Invoke-LongSyntheticCommandXQ9 -Secret hunter2XQ9 -Path C:\\Temp\\staging\\payloadXQ9.bin "
           "-ComputerName ep-02 -Credential SYNTHACCTXQ9")


def _write_gate_csv(path: Path, rows: list[dict]) -> None:
    fields: list[str] = []
    for r in rows:
        fields += [k for k in r if k not in fields]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields or ["event_uid"])
        w.writeheader()
        w.writerows(rows)


def synthetic_repo(tmp_path: Path):
    """A temp repo whose only trial (an allowlisted id) holds one remote logon with source evidence: a Sysmon 1 whose
    command line (a planted long text that names ep-02) is in the DB, a Sysmon 3 and a 4648."""
    w = W()
    w.member("M1", T, LID, 50000, account="SYNTHACCTXQ9")
    w.src_logon("L5000", 0.0, 5000, account="SYNTHACCTXQ9")
    w.s1("S1", 95.0, "{G1}", 5000, image="C:\\Windows\\System32\\SYNTHIMAGEXQ9.exe")
    w.s3("N1", 100.2, guid="{G1}")
    w.e4648("F1", 96.0, 5000, cred="SYNTHACCTXQ9")
    w.logoff("X110", LAST, LID)
    w.s3("N9", 130.0, guid="{G1}")                    # evidence after ep-02's last Security event
    rows = [dict(e) for e in w.events]
    for r in rows:
        if r["event_uid"] == "S1":
            r["command_line"] = PLANTED
        if r["event_uid"] == "F1":
            r["field_values_json"] = json.dumps({"TargetServerName": "ep-02"})
    fake = sf.make_repo(tmp_path, rows)
    _write_gate_csv(fake.paths.gate_dir / "triggers.csv", w.triggers)
    return fake


def test_synthetic_run_check_runs_end_to_end_and_the_planted_command_does_not_appear(tmp_path):
    fake = synthetic_repo(tmp_path)
    data = cl.run_check(fake.repo, fake.trial)
    text = check_text(data)
    assert data["trial_id"] == fake.trial and data["counts"]["hops"] == 1
    (hop,) = data["hops"]
    assert {r["method"] for r in hop["links"]} == {PORT, E4648, CMD}
    assert hop["target_only_reason"] == ""
    # the planted command: no substring of 12 characters (target-side names and lab IPs apart) in the output
    cmd = PLANTED.replace("ep-02", "\x00")
    hits = [i for i in range(len(cmd) - 11) if "\x00" not in cmd[i:i + 12] and cmd[i:i + 12] in text]
    assert hits == [], f"{len(hits)} planted 12-character substring(s) found in the output"
    for tok in ("SYNTHACCTXQ9", "SYNTHIMAGEXQ9", "hunter2XQ9", "payloadXQ9", "Invoke-LongSynthetic"):
        assert tok not in text
    # the data limit of ep-02: the Sysmon 3 N9 names it after its last Security event
    assert data["data_limits"][TGT]["data_limitation"] == 1
    assert data["data_limits"][TGT]["evidence_after_event_uids"][PORT] == ["N9"]


def test_synthetic_main_writes_one_file_twice_byte_identical_and_leaves_the_db_unchanged(tmp_path):
    fake = synthetic_repo(tmp_path)
    db_sha = sf.sha256_of(fake.paths.db)
    out = fake.repo / "out" / "stitch_check" / fake.trial / "t73_links.json"
    assert cl.main(["--trial", fake.trial, "--repo", str(fake.repo)]) == 0
    first = out.read_bytes()
    assert cl.main(["--trial", fake.trial, "--repo", str(fake.repo)]) == 0
    assert out.read_bytes() == first
    assert first.endswith(b"\n") and b"\r" not in first
    assert sf.sha256_of(fake.paths.db) == db_sha
    parsed = json.loads(first)
    assert parsed["db"]["sha256_before"] == parsed["db"]["sha256_after"] == db_sha
    assert [p.name for p in out.parent.iterdir()] == ["t73_links.json"]        # no temporary file left


def test_synthetic_main_refuses_a_non_development_trial_with_exit_2_and_writes_nothing(tmp_path, capsys):
    fake = synthetic_repo(tmp_path)
    before = sf.snapshot(fake.repo)
    assert cl.main(["--trial", "s02_t02", "--repo", str(fake.repo)]) == 2
    assert sf.snapshot(fake.repo) == before
    assert not (fake.repo / "out" / "stitch_check").exists()
    err = capsys.readouterr().err
    assert err.startswith("refused:")


def test_synthetic_main_refuses_a_broken_trial_with_exit_2_and_writes_nothing(tmp_path):
    fake = sf.make_repo(tmp_path, [sf.logon("E0", 1.0, 1000)], skip_gate_file="triggers.csv")
    before = sf.snapshot(fake.repo)
    assert cl.main(["--trial", fake.trial, "--repo", str(fake.repo)]) == 2
    assert sf.snapshot(fake.repo) == before
    assert not (fake.repo / "out" / "stitch_check").exists()


def test_synthetic_main_refuses_a_changed_db_hash_and_writes_nothing(tmp_path):
    fake = sf.make_repo(tmp_path, [sf.logon("E0", 1.0, 1000)], stats_db_sha_after="0" * 64)
    assert cl.main(["--trial", fake.trial, "--repo", str(fake.repo)]) == 2
    assert not (fake.repo / "out" / "stitch_check").exists()
