"""T7.4 task 1 tests for ``stitch.tiers``: account match, name check, tier and rank of a hop's candidate sessions.

Written from spec 03_stitch (ST-45, ST-46, ST-48, ST-50, STT-06, STT-07, STT-08) and decision 049 items 1-5, with
synthetic inputs only (fast). Inputs are built by hand from the T7.3 dataclasses.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Sequence

import pytest

from stitch import tiers
from stitch.artefacts import ArtefactRow
from stitch.hops import Hop, HopSet, RemoteLogon
from stitch.source import (METHOD_4648, METHOD_CMD, METHOD_PORT, REASON_RESOLVED, Evidence, MethodResult,
                           SessionData, SubjectLinks)

HOST = "ep-02"


# ------------------------------------------------------------------ builders

def sk(n: int, host: str = HOST) -> tuple:
    """A session key (host, logon id, boot epoch, ...) that sorts by n."""
    return (host, n, 0, 0)


def member(uid: str, account: str | None, us: int = 0, port: int | None = 50000) -> RemoteLogon:
    return RemoteLogon(uid=uid, event_uids=[uid], gate_uids=[], host="ep-03", us_raw=us, us=us,
                       source_ip="10.0.0.2", ip_kind="lab", source_port=port, account=account,
                       account_key=(account or "").lower() or None, logon_id=0x1000 + us,
                       logon_id_hex=hex(0x1000 + us), authentication_package="NTLM", logon_guid=None,
                       machine_account=0, rules=["R4"], trigger_ids=["t"], gate_clock_unreliable=0,
                       clock_unreliable=0, session_key=None)


def make_hop(hop_id: str, accounts: Sequence[str | None], *, ports: Sequence[int | None] | None = None) -> Hop:
    ports = list(ports) if ports is not None else [50000 + i for i in range(len(accounts))]
    members = [member(f"{hop_id}-m{i}", a, us=i * 1000, port=p)
               for i, (a, p) in enumerate(zip(accounts, ports))]
    return Hop(hop_id=hop_id, target_host="ep-03", source_ip="10.0.0.2", ip_kind="lab", members=members,
               protocol="smb", rules=["R4"], trigger_ids=["t"], authentication_packages=["NTLM"],
               mixed_account=int(len({(a or '').lower() for a in accounts}) > 1))


def sdata(key: tuple, account: str | None, creds: Sequence[str] = ()) -> SessionData:
    return SessionData(session_key=key, logon_id=key[1], logon_id_hex=hex(key[1]), open_uids=(), account=account,
                       logon_type=2, open_known=True, opened_before_window=False,
                       credential_accounts=tuple(creds), names_found=(), names_event_uids=())


def evidence(method: str, key: tuple | None, *, names_by_uid: dict[str, list[str]] | None = None,
             delta_ms: int | None = 0, uids: Sequence[str] = ("e",)) -> Evidence:
    return Evidence(method=method, session_key=key, reason=REASON_RESOLVED if key is not None else "x",
                    evidence_uids=list(uids), matched_member_uids=[], matched_member_event_uids=[],
                    time_delta_ms=delta_ms, time_delta_raw_ms=delta_ms, nearest_uid=uids[0], clock_unreliable=0,
                    names_by_uid=dict(names_by_uid or {}))


def method_result(method: str, evs: Sequence[Evidence]) -> MethodResult:
    return MethodResult(method=method, evidence=list(evs))


def links_of(hop: Hop, data: Sequence[SessionData],
             methods: dict[str, Sequence[Evidence]]) -> SubjectLinks:
    return SubjectLinks(
        target_host=hop.target_host, source_host=HOST, member_uids=[m.uid for m in hop.members], rows=[],
        target_only_reason="" if data else "no_evidence_in_range", candidate_counts={},
        candidate_count_all=len(data), session_methods={}, sessions={d.session_key: d for d in data},
        evidence_before_range=0, evidence_after_range=0, system_session_evidence={},
        methods={m: method_result(m, e) for m, e in methods.items()}, host_clock_unreliable=0)


def art(hop_id: str, kind: str, names: Sequence[str], logged_under: str | None = None) -> ArtefactRow:
    return ArtefactRow(hop_id=hop_id, kind=kind, member_logon_uid="m", logged_under_hop_id=logged_under or hop_id,
                       method="logon_id", candidate_count=1, time_delta_ms=0, supporting_span_ms=0,
                       confidence_tier="A", event_uids=["a"], names=list(names), untied_same_name_bursts=[],
                       ref_id="", first_us_raw=0, last_us_raw=0)


def cmd_evs(key_names: dict[tuple, dict[str, list[str]]], delta: dict[tuple, int] | None = None) -> list[Evidence]:
    return [evidence(METHOD_CMD, k, names_by_uid=n, delta_ms=(delta or {}).get(k, 0), uids=list(n) or ["c"])
            for k, n in key_names.items()]


RANK_FIELDS = {"link_rank", "tie", "rank_basis", "name_check", "name_check_names", "name_check_event_uids"}


# ------------------------------------------------------------------ constants

def test_constants() -> None:
    assert (tiers.ACCOUNT_DIRECT, tiers.ACCOUNT_4648, tiers.ACCOUNT_NONE) == ("direct", "4648", "none")
    assert tiers.TIERS == ("A", "B", "C", "D")
    assert tiers.RANK_BASES == ("only", "tier", "account_match", "name_check", "equal", "no_session",
                                "target_only")
    assert {tiers.NAME_MATCH, tiers.NAME_NO_MATCH, tiers.NAME_NO_NAMES} == {"match", "no_match", "no_names"}


# ------------------------------------------------------------------ STT-06 account match

def test_stt06_member_direct() -> None:
    assert tiers.account_match_member("svc_backup", "svc_backup", []) == "direct"


def test_stt06_member_4648() -> None:
    assert tiers.account_match_member("admin_it", "svc_backup", ["admin_it"]) == "4648"


def test_stt06_member_none() -> None:
    assert tiers.account_match_member("alice", "bob", ["carol"]) == "none"


def test_stt06_member_direct_beats_4648() -> None:
    assert tiers.account_match_member("svc_backup", "svc_backup", ["svc_backup"]) == "direct"


def test_stt06_member_case_insensitive() -> None:
    assert tiers.account_match_member("Admin_IT", "ADMIN_it", []) == "direct"
    assert tiers.account_match_member("ADMIN_IT", "svc", ["admin_it"]) == "4648"


@pytest.mark.parametrize("member_account, session_account, creds", [
    (None, None, []),
    (None, "bob", ["bob"]),
    ("", "", [""]),
    ("", None, [""]),
    ("bob", None, []),
    ("bob", "", [""]),
    (None, None, [None]),
])
def test_stt06_null_or_empty_never_matches(member_account: Any, session_account: Any, creds: Any) -> None:
    assert tiers.account_match_member(member_account, session_account, creds) == "none"


def test_stt06_best_account_match_order() -> None:
    assert tiers.best_account_match(["none", "4648", "direct"]) == "direct"
    assert tiers.best_account_match(["none", "4648"]) == "4648"
    assert tiers.best_account_match(["none", "none"]) == "none"
    assert tiers.best_account_match([]) == "none"


def test_stt06_is_consistent() -> None:
    assert tiers.is_consistent("direct") and tiers.is_consistent("4648")
    assert not tiers.is_consistent("none")


def test_stt06_none_candidate_is_still_a_verdict() -> None:
    hop = make_hop("h1", ["alice"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "bob")], {METHOD_CMD: cmd_evs({k: {}})})
    hv = tiers.hop_verdicts(hop, sl, [])
    assert set(hv.sessions) == {k}
    v = hv.sessions[k]
    assert v.account_match == "none"
    assert v.account_match_members == ("none",)
    assert v.account_match_member_count == 0
    assert v.confidence_tier == "D"
    assert hv.candidate_count_account == 0
    assert hv.best_tier == "D"


def test_stt06_mixed_account_hop_per_member_values() -> None:
    hop = make_hop("h1", ["admin_it", "svc_backup", "svc_backup"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "svc_backup", ["admin_it"])], {METHOD_CMD: cmd_evs({k: {}})})
    v = tiers.hop_verdicts(hop, sl, []).sessions[k]
    assert v.account_match_members == ("4648", "direct", "direct")
    assert v.account_match == "direct"
    assert v.account_match_member_count == 3


def test_stt06_mixed_account_hop_without_credentials() -> None:
    hop = make_hop("h1", ["admin_it", "svc_backup", "svc_backup"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "svc_backup")], {METHOD_CMD: cmd_evs({k: {}})})
    v = tiers.hop_verdicts(hop, sl, []).sessions[k]
    assert v.account_match_members == ("none", "direct", "direct")
    assert v.account_match_member_count == 2


def test_stt06_two_sessions_mixed_hop_are_told_apart_by_member_values() -> None:
    hop = make_hop("h1", ["admin_it", "svc_backup"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "svc_backup", ["admin_it"]), sdata(k2, "svc_backup")],
                  {METHOD_CMD: cmd_evs({k1: {}, k2: {}})})
    hv = tiers.hop_verdicts(hop, sl, [])
    assert hv.sessions[k1].account_match_members == ("4648", "direct")
    assert hv.sessions[k2].account_match_members == ("none", "direct")
    assert hv.sessions[k1].account_match == hv.sessions[k2].account_match == "direct"
    assert hv.sessions[k1].account_match_member_count == 2
    assert hv.sessions[k2].account_match_member_count == 1


def test_stt06_member_values_follow_member_order_not_input_order() -> None:
    hop = make_hop("h1", ["alice", "bob"])  # us_raw 0, 1000
    hop.members.reverse()
    k = sk(1)
    sl = links_of(hop, [sdata(k, "bob")], {METHOD_CMD: cmd_evs({k: {}})})
    v = tiers.hop_verdicts(hop, sl, []).sessions[k]
    assert v.account_match_members == ("none", "direct")


def test_stt06_null_member_account_in_hop_is_none() -> None:
    hop = make_hop("h1", [None, "bob"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, None)], {METHOD_CMD: cmd_evs({k: {}})})
    v = tiers.hop_verdicts(hop, sl, []).sessions[k]
    assert v.account_match_members == ("none", "none")
    assert v.confidence_tier == "D"


def test_stt06_candidate_count_account_counts_non_none_sessions() -> None:
    hop = make_hop("h1", ["alice"])
    k1, k2, k3 = sk(1), sk(2), sk(3)
    sl = links_of(hop, [sdata(k1, "alice"), sdata(k2, "bob", ["alice"]), sdata(k3, "bob")],
                  {METHOD_CMD: cmd_evs({k1: {}, k2: {}, k3: {}})})
    hv = tiers.hop_verdicts(hop, sl, [])
    assert hv.candidate_count_account == 2
    assert set(hv.sessions) == {k1, k2, k3}


# ------------------------------------------------------------------ hop_names

def test_hop_names_only_burst_and_install_of_this_hop() -> None:
    rows = [art("h1", "share_burst", ["Ypay.exe"]), art("h1", "service_install", ["Svc", "b.exe"]),
            art("h1", "winrm_host", ["ignored"]), art("h2", "share_burst", ["other.exe"])]
    assert tiers.hop_names("h1", rows) == ["b.exe", "Svc", "Ypay.exe"]


def test_hop_names_burst_moved_to_hop_counts() -> None:
    rows = [art("h2", "share_burst", ["Ypay.exe"], logged_under="h1"),   # moved to h2, logged under h1
            art("h1", "share_burst", ["own.exe"])]
    assert tiers.hop_names("h2", rows) == ["Ypay.exe"]
    assert tiers.hop_names("h1", rows) == ["own.exe"]


def test_hop_names_unique_and_sorted_case_insensitively() -> None:
    rows = [art("h1", "share_burst", ["b.exe", "Ypay.exe", "a.exe"]), art("h1", "service_install", ["a.exe"])]
    out = tiers.hop_names("h1", rows)
    assert out == ["a.exe", "b.exe", "Ypay.exe"]
    assert [n.lower() for n in out] == sorted(n.lower() for n in out)


def test_hop_names_none_gives_empty() -> None:
    assert tiers.hop_names("h1", []) == []
    assert tiers.hop_names("h1", [art("h1", "share_burst", [])]) == []


# ------------------------------------------------------------------ STT-07 name check

def test_stt07_no_names_gives_no_names() -> None:
    hop = make_hop("h1", ["a"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "a")], {METHOD_CMD: cmd_evs({k: {"u1": ["ypay.exe"]}})})
    assert tiers.name_check_of(k, sl, []) == ("no_names", [], [])


def test_stt07_match_returns_names_and_event_uids() -> None:
    hop = make_hop("h1", ["a"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "a")], {METHOD_CMD: cmd_evs({k: {"u2": ["ypay.exe"], "u1": ["ypay.exe", "z.exe"],
                                                                 "u3": ["unrelated.exe"]}})})
    check, names, uids = tiers.name_check_of(k, sl, ["Ypay.exe"])
    assert check == "match"
    assert [n.lower() for n in names] == ["ypay.exe"]
    assert uids == ["u1", "u2"]


def test_stt07_name_match_is_case_insensitive() -> None:
    hop = make_hop("h1", ["a"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "a")], {METHOD_CMD: cmd_evs({k: {"u1": ["YPAY.EXE"]}})})
    assert tiers.name_check_of(k, sl, ["ypay.exe"])[0] == "match"


def test_stt07_name_in_other_sessions_command_does_not_match() -> None:
    hop = make_hop("h1", ["a"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "a"), sdata(k2, "a")],
                  {METHOD_CMD: cmd_evs({k1: {"u1": ["other.exe"]}, k2: {"u2": ["ypay.exe"]}})})
    assert tiers.name_check_of(k1, sl, ["ypay.exe"]) == ("no_match", [], [])
    assert tiers.name_check_of(k2, sl, ["ypay.exe"])[0] == "match"


@pytest.mark.parametrize("method", [METHOD_PORT, METHOD_4648])
def test_stt07_name_in_non_cmdline_method_does_not_match(method: str) -> None:
    hop = make_hop("h1", ["a"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "a")], {method: [evidence(method, k, names_by_uid={"u1": ["ypay.exe"]})],
                                         METHOD_CMD: cmd_evs({k: {}})})
    assert tiers.name_check_of(k, sl, ["ypay.exe"]) == ("no_match", [], [])


def test_stt07_no_cmdline_method_at_all_gives_no_match() -> None:
    hop = make_hop("h1", ["a"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "a")], {METHOD_4648: [evidence(METHOD_4648, k)]})
    assert tiers.name_check_of(k, sl, ["ypay.exe"]) == ("no_match", [], [])


def test_stt07_uses_names_by_uid_exactly() -> None:
    hop = make_hop("h1", ["a"])
    k = sk(1)
    # name only inside a longer file name: the matcher (048) decides; here the found name is a different name
    sl = links_of(hop, [sdata(k, "a")], {METHOD_CMD: cmd_evs({k: {"u1": ["notypay.exe"]}})})
    assert tiers.name_check_of(k, sl, ["ypay.exe"]) == ("no_match", [], [])
    # an Evidence whose aggregate names_found holds the name but names_by_uid is empty gives no_match
    ev = evidence(METHOD_CMD, k, names_by_uid={})
    ev.names_found = ["ypay.exe"]
    ev.names_event_uids = ["u1"]
    sl2 = links_of(hop, [sdata(k, "a")], {METHOD_CMD: [ev]})
    assert tiers.name_check_of(k, sl2, ["ypay.exe"])[0] == "no_match"


def test_stt07_no_match_when_names_exist_but_none_found() -> None:
    hop = make_hop("h1", ["a"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "a")], {METHOD_CMD: cmd_evs({k: {}})})
    assert tiers.name_check_of(k, sl, ["ypay.exe"])[0] == "no_match"


def _two_consistent_sessions(names_for_first: dict[str, list[str]]) -> tuple[Hop, SubjectLinks, tuple, tuple]:
    hop = make_hop("h1", ["alice"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "alice"), sdata(k2, "alice")],
                  {METHOD_CMD: cmd_evs({k1: names_for_first, k2: {"u9": ["unrelated.exe"]}})})
    return hop, sl, k1, k2


def test_stt07_blanking_names_changes_only_rank_and_name_fields() -> None:
    hop, sl, k1, k2 = _two_consistent_sessions({"u1": ["ypay.exe"]})
    with_names = tiers.hop_verdicts(hop, sl, ["Ypay.exe"])
    blank = tiers.hop_verdicts(hop, sl, [])
    assert with_names.sessions[k1].name_check == "match"
    assert with_names.sessions[k2].name_check == "no_match"
    assert blank.sessions[k1].name_check == blank.sessions[k2].name_check == "no_names"
    for k in (k1, k2):
        a = dataclasses.asdict(with_names.sessions[k])
        b = dataclasses.asdict(blank.sessions[k])
        assert {f for f in a if a[f] != b[f]} <= RANK_FIELDS
        for f in ("confidence_tier", "account_match", "account_match_members", "account_match_member_count",
                  "session_key"):
            assert a[f] == b[f]
    assert with_names.candidate_count_account == blank.candidate_count_account
    assert with_names.best_tier == blank.best_tier
    # and the name check does move the rank: name match first, tied when blanked
    assert (with_names.sessions[k1].link_rank, with_names.sessions[k2].link_rank) == (1, 2)
    assert with_names.sessions[k1].rank_basis == with_names.sessions[k2].rank_basis == "name_check"
    assert (blank.sessions[k1].link_rank, blank.sessions[k2].link_rank) == (1, 1)
    assert blank.sessions[k1].tie == blank.sessions[k2].tie == 1


def test_stt07_names_never_lift_the_tier() -> None:
    hop = make_hop("h1", ["alice"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "alice"), sdata(k2, "alice")],
                  {METHOD_CMD: cmd_evs({k1: {"u1": ["ypay.exe"]}, k2: {}})})
    v = tiers.hop_verdicts(hop, sl, ["ypay.exe"]).sessions
    assert v[k1].name_check == "match" and v[k1].confidence_tier == "C"
    assert v[k2].confidence_tier == "C"


def test_stt07_none_account_session_with_name_match_stays_d_and_last() -> None:
    hop = make_hop("h1", ["alice"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "alice"), sdata(k2, "bob")],
                  {METHOD_CMD: cmd_evs({k1: {}, k2: {"u1": ["ypay.exe"]}})})
    v = tiers.hop_verdicts(hop, sl, ["ypay.exe"]).sessions
    assert v[k2].name_check == "match" and v[k2].confidence_tier == "D"
    assert v[k1].confidence_tier == "B"
    assert (v[k1].link_rank, v[k2].link_rank) == (1, 2)
    assert v[k1].rank_basis == v[k2].rank_basis == "tier"


def test_stt07_hop_level_no_session_name_check() -> None:
    hop = make_hop("h1", ["a"])
    sl = links_of(hop, [], {})
    assert tiers.hop_verdicts(hop, sl, []).no_session_name_check == "no_names"
    assert tiers.hop_verdicts(hop, sl, ["ypay.exe"]).no_session_name_check == "no_match"
    assert tiers.hop_verdicts(hop, sl, ["ypay.exe"]).names == ("ypay.exe",)


# ------------------------------------------------------------------ STT-08 tiers

@pytest.mark.parametrize("account, in_port, port_n, cons_n, expected", [
    ("direct", True, 1, 1, "A"),
    ("4648", True, 1, 1, "A"),
    ("direct", True, 2, 2, "C"),
    ("direct", False, 0, 1, "B"),
    ("4648", False, 0, 1, "B"),
    ("direct", False, 0, 2, "C"),
    ("direct", False, 1, 2, "C"),    # not port-found while another session is: consistent_count rules
    ("none", True, 1, 0, "D"),
    ("none", False, 0, 0, "D"),
    ("none", True, 2, 1, "D"),
])
def test_stt08_tier_of_table(account: str, in_port: bool, port_n: int, cons_n: int, expected: str) -> None:
    assert tiers.tier_of(account, in_port, port_n, cons_n) == expected


def test_stt08_a_single_port_session_consistent() -> None:
    hop = make_hop("h1", ["alice"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "alice")], {METHOD_PORT: [evidence(METHOD_PORT, k)]})
    hv = tiers.hop_verdicts(hop, sl, [])
    v = hv.sessions[k]
    assert v.confidence_tier == "A"
    assert (v.link_rank, v.tie, v.rank_basis) == (1, 0, "only")
    assert hv.best_tier == "A"


def test_stt08_port_found_by_two_methods_still_a() -> None:
    hop = make_hop("h1", ["alice"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "alice")], {METHOD_PORT: [evidence(METHOD_PORT, k)],
                                             METHOD_CMD: cmd_evs({k: {}})})
    assert tiers.hop_verdicts(hop, sl, []).sessions[k].confidence_tier == "A"


def test_stt08_several_port_sessions_are_c() -> None:
    hop = make_hop("h1", ["alice"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "alice"), sdata(k2, "alice")],
                  {METHOD_PORT: [evidence(METHOD_PORT, k1), evidence(METHOD_PORT, k2)]})
    hv = tiers.hop_verdicts(hop, sl, [])
    assert hv.sessions[k1].confidence_tier == hv.sessions[k2].confidence_tier == "C"
    assert hv.best_tier == "C"


def test_stt08_b_by_4648() -> None:
    hop = make_hop("h1", ["admin_it"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "svc_backup", ["admin_it"])], {METHOD_4648: [evidence(METHOD_4648, k)]})
    v = tiers.hop_verdicts(hop, sl, []).sessions[k]
    assert v.account_match == "4648"
    assert v.confidence_tier == "B"


def test_stt08_b_by_cmdline() -> None:
    hop = make_hop("h1", ["alice"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "alice")], {METHOD_CMD: cmd_evs({k: {}})})
    v = tiers.hop_verdicts(hop, sl, []).sessions[k]
    assert v.confidence_tier == "B"
    assert (v.link_rank, v.tie, v.rank_basis) == (1, 0, "only")


def test_stt08_two_consistent_sessions_are_both_c_tied_and_equal() -> None:
    hop = make_hop("h1", ["alice"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "alice"), sdata(k2, "alice")], {METHOD_CMD: cmd_evs({k1: {}, k2: {}})})
    hv = tiers.hop_verdicts(hop, sl, [])
    for k in (k1, k2):
        v = hv.sessions[k]
        assert (v.confidence_tier, v.link_rank, v.tie, v.rank_basis) == ("C", 1, 1, "equal")
    assert hv.best_tier == "C"


def test_stt08_consistent_over_all_methods_counts_once_per_session() -> None:
    hop = make_hop("h1", ["alice"])
    k = sk(1)
    # one session found by 4648 and command line: still the hop's only consistent session
    sl = links_of(hop, [sdata(k, "alice")], {METHOD_4648: [evidence(METHOD_4648, k)],
                                             METHOD_CMD: cmd_evs({k: {}})})
    assert tiers.hop_verdicts(hop, sl, []).sessions[k].confidence_tier == "B"


def test_stt08_direct_and_4648_rank_equal() -> None:
    hop = make_hop("h1", ["admin_it"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "admin_it"), sdata(k2, "svc_backup", ["admin_it"])],
                  {METHOD_CMD: cmd_evs({k1: {}, k2: {}})})
    v = tiers.hop_verdicts(hop, sl, []).sessions
    assert v[k1].account_match == "direct" and v[k2].account_match == "4648"
    for k in (k1, k2):
        assert (v[k].confidence_tier, v[k].link_rank, v[k].tie, v[k].rank_basis) == ("C", 1, 1, "equal")


def test_stt08_port_zero_hop_is_at_most_b() -> None:
    hop = make_hop("h1", ["alice"], ports=[0])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "alice")], {METHOD_4648: [evidence(METHOD_4648, k)],
                                             METHOD_CMD: cmd_evs({k: {}})})
    v = tiers.hop_verdicts(hop, sl, []).sessions[k]
    assert v.confidence_tier == "B"
    assert v.confidence_tier != "A"


def test_stt08_port_zero_hop_two_sessions_are_c() -> None:
    hop = make_hop("h1", ["alice"], ports=[0])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "alice"), sdata(k2, "alice")], {METHOD_4648: [evidence(METHOD_4648, k1),
                                                                                  evidence(METHOD_4648, k2)]})
    v = tiers.hop_verdicts(hop, sl, []).sessions
    assert v[k1].confidence_tier == v[k2].confidence_tier == "C"


def test_stt08_account_none_is_d_even_as_single_port_session() -> None:
    """049 item 1 reading, limitation L-ST4: the strongest technical link gets the lowest tier."""
    hop = make_hop("h1", ["alice"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "bob")], {METHOD_PORT: [evidence(METHOD_PORT, k)]})
    hv = tiers.hop_verdicts(hop, sl, [])
    v = hv.sessions[k]
    assert v.account_match == "none"
    assert v.confidence_tier == "D"
    assert hv.best_tier == "D"
    assert (v.link_rank, v.tie, v.rank_basis) == (1, 0, "only")


def test_stt08_port_session_a_and_cmdline_session_c() -> None:
    hop = make_hop("h1", ["alice"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "alice"), sdata(k2, "alice")],
                  {METHOD_PORT: [evidence(METHOD_PORT, k1)], METHOD_CMD: cmd_evs({k2: {}})})
    v = tiers.hop_verdicts(hop, sl, []).sessions
    assert v[k1].confidence_tier == "A"
    assert v[k2].confidence_tier == "C"
    assert (v[k1].link_rank, v[k2].link_rank) == (1, 2)


def test_stt08_best_tier_d_for_hop_with_no_session() -> None:
    hop = make_hop("h1", ["alice"])
    hv = tiers.hop_verdicts(hop, links_of(hop, [], {}), [])
    assert hv.sessions == {}
    assert hv.best_tier == "D"
    assert hv.candidate_count_account == 0


def test_stt08_best_tier_is_best_over_sessions() -> None:
    hop = make_hop("h1", ["alice"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "bob"), sdata(k2, "alice")], {METHOD_CMD: cmd_evs({k1: {}, k2: {}})})
    assert tiers.hop_verdicts(hop, sl, []).best_tier == "B"


def test_stt08_unresolved_evidence_is_not_a_session() -> None:
    hop = make_hop("h1", ["alice"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "alice")], {METHOD_PORT: [evidence(METHOD_PORT, None)],
                                             METHOD_CMD: cmd_evs({k: {}})})
    hv = tiers.hop_verdicts(hop, sl, [])
    assert set(hv.sessions) == {k}
    assert hv.sessions[k].confidence_tier == "B"


# ------------------------------------------------------------------ 049 item 3 rank

def test_rank_one_session_is_only() -> None:
    assert tiers.rank_sessions({sk(1): ("B", True, False)}) == {sk(1): (1, 0, "only")}


def test_rank_empty() -> None:
    assert tiers.rank_sessions({}) == {}


def test_rank_b_and_d_by_tier() -> None:
    r = tiers.rank_sessions({sk(1): ("B", True, False), sk(2): ("D", False, False)})
    assert r[sk(1)] == (1, 0, "tier")
    assert r[sk(2)] == (2, 0, "tier")


def test_rank_input_order_does_not_matter() -> None:
    a = tiers.rank_sessions({sk(1): ("B", True, False), sk(2): ("D", False, False)})
    b = tiers.rank_sessions({sk(2): ("D", False, False), sk(1): ("B", True, False)})
    assert a == b


def test_rank_same_tier_split_by_name_check() -> None:
    r = tiers.rank_sessions({sk(1): ("C", True, False), sk(2): ("C", True, True)})
    assert r[sk(2)] == (1, 0, "name_check")
    assert r[sk(1)] == (2, 0, "name_check")


def test_rank_same_tier_split_by_account_consistency() -> None:
    r = tiers.rank_sessions({sk(1): ("C", False, True), sk(2): ("C", True, False)})
    assert r[sk(2)] == (1, 0, "account_match")
    assert r[sk(1)] == (2, 0, "account_match")


def test_rank_account_consistency_outranks_name_check() -> None:
    r = tiers.rank_sessions({sk(1): ("C", False, True), sk(2): ("C", True, False)})
    assert r[sk(2)][0] < r[sk(1)][0]


def test_rank_tier_outranks_account_and_name() -> None:
    r = tiers.rank_sessions({sk(1): ("A", True, False), sk(2): ("B", True, True)})
    assert r[sk(1)] == (1, 0, "tier")
    assert r[sk(2)] == (2, 0, "tier")


def test_rank_equal_sessions_tie() -> None:
    r = tiers.rank_sessions({sk(1): ("C", True, False), sk(2): ("C", True, False), sk(3): ("C", True, False)})
    assert set(r.values()) == {(1, 1, "equal")}


def test_rank_tie_at_rank_one_with_lower_group() -> None:
    r = tiers.rank_sessions({sk(1): ("B", True, False), sk(2): ("B", True, False), sk(3): ("D", False, False)})
    assert r[sk(1)] == (1, 1, "tier")
    assert r[sk(2)] == (1, 1, "tier")
    assert r[sk(3)] == (2, 0, "tier")


def test_rank_is_dense() -> None:
    r = tiers.rank_sessions({sk(1): ("A", True, False), sk(2): ("B", True, False), sk(3): ("B", True, False),
                             sk(4): ("D", False, False)})
    assert [r[sk(i)][0] for i in (1, 2, 3, 4)] == [1, 2, 2, 3]
    assert [r[sk(i)][1] for i in (1, 2, 3, 4)] == [0, 0, 0, 0]  # tie only describes a shared rank 1


def test_rank_time_never_orders_sessions() -> None:
    hop = make_hop("h1", ["alice"])
    k1, k2 = sk(1), sk(2)
    for d1, d2 in ((-9000, 12000), (12000, -9000)):
        sl = links_of(hop, [sdata(k1, "alice"), sdata(k2, "alice")],
                      {METHOD_CMD: cmd_evs({k1: {}, k2: {}}, delta={k1: d1, k2: d2})})
        v = tiers.hop_verdicts(hop, sl, []).sessions
        for k in (k1, k2):
            assert (v[k].link_rank, v[k].tie, v[k].rank_basis) == (1, 1, "equal")


def test_hop_verdict_s04_like_two_tracks() -> None:
    """Spec section 6: two candidates, the account-consistent one is B and first, the other D."""
    hop = make_hop("h1", ["alice"])
    k1, k2 = sk(1), sk(2)
    sl = links_of(hop, [sdata(k1, "alice"), sdata(k2, "bob")],
                  {METHOD_CMD: cmd_evs({k1: {"u1": ["a.exe"]}, k2: {}})})
    hv = tiers.hop_verdicts(hop, sl, ["a.exe"])
    assert (hv.sessions[k1].confidence_tier, hv.sessions[k1].link_rank, hv.sessions[k1].rank_basis) == ("B", 1, "tier")
    assert (hv.sessions[k2].confidence_tier, hv.sessions[k2].link_rank, hv.sessions[k2].rank_basis) == ("D", 2, "tier")
    assert hv.sessions[k1].name_check == "match" and hv.sessions[k2].name_check == "no_match"
    assert hv.candidate_count_account == 1


# ------------------------------------------------------------------ errors

def test_unknown_account_value_raises() -> None:
    with pytest.raises(ValueError):
        tiers.best_account_match(["direct", "maybe"])
    with pytest.raises(ValueError):
        tiers.tier_of("maybe", False, 0, 1)


def test_unknown_tier_raises() -> None:
    with pytest.raises(ValueError):
        tiers.rank_sessions({sk(1): ("Z", True, False)})


# ------------------------------------------------------------------ all_verdicts

def test_all_verdicts_one_entry_per_hop_with_own_names() -> None:
    h1, h2, h3 = make_hop("h1", ["alice"]), make_hop("h2", ["alice"]), make_hop("h3", ["alice"])
    k = sk(1)
    links = {
        "h1": links_of(h1, [sdata(k, "alice")], {METHOD_CMD: cmd_evs({k: {"u1": ["ypay.exe"]}})}),
        "h2": links_of(h2, [sdata(k, "alice")], {METHOD_CMD: cmd_evs({k: {"u2": ["ypay.exe"]}})}),
        "h3": links_of(h3, [], {}),
    }
    rows = [art("h2", "share_burst", ["Ypay.exe"], logged_under="h1"), art("h1", "service_install", ["Other"])]
    out = tiers.all_verdicts(HopSet(trial_id="t", hops=[h1, h2, h3], followups=[], counts={}), links, rows)
    assert list(out) == ["h1", "h2", "h3"]
    assert out["h1"].names == ("Other",)
    assert out["h1"].sessions[k].name_check == "no_match"       # the moved burst is not h1's
    assert out["h2"].names == ("Ypay.exe",)
    assert out["h2"].sessions[k].name_check == "match"          # the moved burst is h2's
    assert out["h2"].sessions[k].name_check_event_uids == ("u2",)
    assert out["h3"].sessions == {} and out["h3"].best_tier == "D" and out["h3"].no_session_name_check == "no_names"
    assert out["h1"].hop_id == "h1"


def test_verdict_types_are_tuples_and_ints() -> None:
    hop = make_hop("h1", ["alice"])
    k = sk(1)
    sl = links_of(hop, [sdata(k, "alice")], {METHOD_CMD: cmd_evs({k: {"u1": ["a.exe"]}})})
    v = tiers.hop_verdicts(hop, sl, ["a.exe"]).sessions[k]
    assert isinstance(v.account_match_members, tuple) and isinstance(v.name_check_names, tuple)
    assert isinstance(v.name_check_event_uids, tuple)
    assert isinstance(v.link_rank, int) and isinstance(v.tie, int)
    assert v.rank_basis in tiers.RANK_BASES and v.confidence_tier in tiers.TIERS
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.link_rank = 5  # type: ignore[misc]
