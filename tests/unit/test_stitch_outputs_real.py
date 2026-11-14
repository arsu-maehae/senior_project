"""Real-data acceptance for T7.4 task 4 (spec 03_stitch ST-45..ST-50, ST-60..ST-64, STA-05, STA-08, STT-13 and sections
10.4, 10.6; decision 049) on the nine development trials. Slow; parametrised over `clock_offset.params.DEVELOPMENT_TRIALS`
only, never t02-t10.

Written from the spec, decision 049 and the approved t00 keys, not from the implementation (the code was read only for
public names, signatures and field names). The keys are read by the tests only; `src/stitch` never opens them.

Groups: 1 T7.3 reproduced; 2 tiers and ranks; 3 identity facts against `identity_expected`; 4 files; 5 STT-13 on the real
files. Assertion messages carry counts, hop ids, session ids in hex, column names and uids only, never command text, a
substring of one, or an account value that came from a command.

Writes: only through `stitch.__main__.main`, into `out/stitch/<development trial>/` (pipeline output, allowed). The
refused-trial test checks that nothing is written for `s02_t02`.
"""
from __future__ import annotations

import collections
import csv
import functools
import io
import json
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stitch_fixtures as sf  # noqa: E402
from answer_key.db import sha256_file  # noqa: E402
from clock_offset import params as co_params  # noqa: E402
from stitch import __main__ as stitch_main  # noqa: E402
from stitch import check_index as ci  # noqa: E402
from stitch import check_links as cl  # noqa: E402
from stitch import outputs as out  # noqa: E402
from stitch.inputs import trial_paths  # noqa: E402
from stitch.links import run_links  # noqa: E402
from stitch.params import StitchParams  # noqa: E402

pytestmark = pytest.mark.slow

DEV = list(co_params.DEVELOPMENT_TRIALS)
DEV_T00 = [t for t in DEV if t.endswith("_t00")]
APPROVED = REPO / "ground_truth" / "approved"
CHECK_REL = Path("out") / "stitch_check"
PARAMS = StitchParams()
ENDPOINTS = {h for h in PARAMS.lab_host_ips if h.startswith("ep-")}
TABLE_ORDER = ["s02_t00", "s02_t01", "s03_t00", "s03_t01", "s04_t00", "s05_t00", "s06_t00", "s06_t01", "s07_t00"]
PORT, E4648, CMD, TARGET_ONLY = "sysmon3_port", "source_4648", "cmdline_target", "target_only"
# T7.5: `python -m stitch` writes ten files (spec 03_stitch section 3)
TEN_FILES = ["hop_artefacts.csv", "hop_identity.csv", "hops.csv", "links.csv", "path_edges.csv", "path_nodes.csv",
             "paths.csv", "report.md", "run_info.json", "stats.json"]

# Row counts of 049 / task 3 (table order above).
LINK_ROWS = dict(zip(TABLE_ORDER, [27, 30, 25, 30, 27, 46, 46, 37, 33]))
IDENTITY_ROWS = dict(zip(TABLE_ORDER, [160, 51, 40, 37, 49, 147, 63, 39, 88]))


# ================================================================================================ shared helpers
@dataclass
class Run:
    trial: str
    li: Any
    before: str
    after: str
    links: list[dict[str, str]]
    arts: list[dict[str, str]]
    ids: list[dict[str, str]]


@functools.lru_cache(maxsize=None)
def _run(trial: str) -> Run | None:
    assert trial in DEV, trial                 # belt and braces: only development trials, ever
    paths = trial_paths(REPO, trial)
    if not paths.db.is_file() or not (paths.gate_dir / "stats.json").is_file():
        return None
    li, before, after = run_links(REPO, trial)
    return Run(trial, li, before, after, out.link_rows(li), out.artefact_rows(li), out.identity_rows(li))


def run_of(trial: str) -> Run:
    got = _run(trial)
    if got is None:
        pytest.skip(f"{trial}: trial DB or gate output missing")
    return got


def load_key(trial: str) -> dict:
    path = APPROVED / f"{trial}.yaml"
    if not path.is_file():
        pytest.skip(f"no approved key for {trial}")
    return json.loads(path.read_text(encoding="utf-8"))


def stitch_hop_of(li: Any, kh: dict) -> Any:
    """The stitch hop whose member 4624 is one of the key hop's `target_event_uids` (spec ST-25). If several hops hold
    one of those uids, the member must also carry the key's target logon ID."""
    uids = set(kh["target_event_uids"])
    hits = [h for h in li.hopset.hops if any(set(m.event_uids) & uids for m in h.members)]
    if len(hits) > 1:
        want = int(kh["target_logon_id"], 16)
        hits = [h for h in hits if any(m.logon_id == want and set(m.event_uids) & uids for m in h.members)]
    assert len(hits) == 1, f"{kh['hop_id']}: {len(hits)} stitch hops hold its target 4624 uid(s)"
    return hits[0]


def key_account(kh: dict) -> str:
    return (kh.get("logon_account") or kh["account"]).lower()


@functools.lru_cache(maxsize=None)
def keyed() -> tuple:
    """(trial, key hop dict, stitch hop) for the 15 keyed hops of the six t00 keys, background ones included."""
    out_: list = []
    for t in DEV_T00:
        r, key = run_of(t), load_key(t)
        for kh in key["hops"]:
            out_.append((t, kh, stitch_hop_of(r.li, kh)))
    return tuple(out_)


def is_user_e2e(host_src: str | None, host_tgt: str, account: str | None) -> bool:
    return (host_src in ENDPOINTS) and (host_tgt in ENDPOINTS) and bool(account) and not account.endswith("$")


def rows_of_hop(r: Run, hop_id: str) -> list[dict[str, str]]:
    return [x for x in r.links if x["hop_id"] == hop_id]


def sessions_of(r: Run):
    """(hop, session key, SessionVerdict, SubjectLinks) for every (hop, candidate session) of the trial."""
    for hop in r.li.hopset.hops:
        hv = r.li.verdicts[hop.hop_id]
        for key, sv in hv.sessions.items():
            yield hop, key, sv, r.li.links[hop.hop_id]


def hex_of(key: tuple) -> str:
    return hex(key[1])


# ================================================================================================ 1. T7.3 reproduced
def _row_tuple_csv(x: dict[str, str]) -> tuple:
    return (x["hop_id"], x["method"], x["source_host"], x["source_session_id"], x["source_session_id_hex"],
            x["session_unresolved_reason"], x["target_only_reason"], x["candidate_count"], x["candidate_count_all"],
            x["time_delta_ms"], x["supporting_event_uids"])


def _row_tuple_mem(hop_id: str, sl: Any, lr: Any) -> tuple:
    return (hop_id, lr.method, lr.source_host or "", "" if lr.source_session_id is None else str(lr.source_session_id),
            lr.source_session_id_hex or "", lr.session_unresolved_reason or "", lr.target_only_reason or "",
            str(lr.candidate_count), str(lr.candidate_count_all),
            "" if lr.time_delta_ms is None else str(lr.time_delta_ms), ";".join(lr.supporting_event_uids))


@pytest.mark.parametrize("trial", DEV)
def test_links_csv_rows_are_one_to_one_with_the_t73_link_rows(trial):
    r = run_of(trial)
    mem = collections.Counter(_row_tuple_mem(h, sl, lr) for h, sl in r.li.links.items() for lr in sl.rows)
    csv_ = collections.Counter(_row_tuple_csv(x) for x in r.links)
    assert sum(mem.values()) == sum(csv_.values()) == len(r.links), f"{trial}: row counts differ"
    assert mem == csv_, f"{trial}: {sum(((mem - csv_) + (csv_ - mem)).values())} row(s) differ"
    # no hop lost, none twice: every hop has rows, hop ids of the file are exactly the hops
    assert {x["hop_id"] for x in r.links} == {h.hop_id for h in r.li.hopset.hops}
    ids = [x["link_id"] for x in r.links]
    assert len(ids) == len(set(ids)), f"{trial}: duplicated link_id"
    assert r.before == r.after, f"{trial}: DB hash changed"


@pytest.mark.parametrize("trial", DEV)
def test_candidate_counts_columns_agree_with_the_link_index(trial):
    r = run_of(trial)
    bad = []
    for x in r.links:
        sl = r.li.links[x["hop_id"]]
        hv = r.li.verdicts[x["hop_id"]]
        if int(x["candidate_count_all"]) != sl.candidate_count_all or int(x["candidate_count_account"]) != hv.candidate_count_account:
            bad.append(x["link_id"])
        if x["method"] != TARGET_ONLY and int(x["candidate_count"]) != sl.candidate_counts.get(x["method"], -1):
            bad.append(x["link_id"])
    assert bad == [], f"{trial}: {len(bad)} row(s) with a count that differs from the index, e.g. {bad[:5]}"


@pytest.mark.parametrize("trial", DEV)
def test_hop_count_target_only_reasons_and_rows_per_method_equal_the_committed_t73_file(trial):
    r = run_of(trial)
    committed = REPO / CHECK_REL / trial / "t73_links.json"
    if not committed.is_file():
        pytest.skip(f"{trial}: no committed t73_links.json")
    d = json.loads(committed.read_text(encoding="utf-8"))
    hops = d["hops"]
    assert len({x["hop_id"] for x in r.links}) == len(hops), f"{trial}: hop count differs"
    want_reasons = collections.Counter(h["target_only_reason"] for h in hops if h["target_only_reason"])
    got_reasons = collections.Counter(x["target_only_reason"] for x in r.links if x["method"] == TARGET_ONLY)
    assert got_reasons == want_reasons, f"{trial}: target_only reasons {dict(got_reasons)} vs {dict(want_reasons)}"
    want_methods = collections.Counter(lk["method"] for h in hops for lk in h["links"])
    got_methods = collections.Counter(x["method"] for x in r.links)
    assert got_methods == want_methods, f"{trial}: rows per method {dict(got_methods)} vs {dict(want_methods)}"
    # per link: the same multiset of (hop, method, session, reason, candidate_count, time_delta_ms, uids)
    want = collections.Counter((h["hop_id"], lk["method"], lk["source_session_id_hex"], lk["session_unresolved_reason"],
                                lk["candidate_count"], h["candidate_count_all"], lk["time_delta_ms"],
                                ";".join(lk["supporting_event_uids"])) for h in hops for lk in h["links"])
    got = collections.Counter((x["hop_id"], x["method"], x["source_session_id_hex"], x["session_unresolved_reason"],
                               int(x["candidate_count"]), int(x["candidate_count_all"]),
                               None if x["time_delta_ms"] == "" else int(x["time_delta_ms"]),
                               x["supporting_event_uids"]) for x in r.links)
    assert got == want, f"{trial}: {sum(((got - want) + (want - got)).values())} link row(s) differ from t73_links.json"


@pytest.mark.parametrize("trial", DEV)
def test_t73_links_file_is_byte_identical_after_t74(trial):
    paths = trial_paths(REPO, trial)
    committed = REPO / CHECK_REL / trial / "t73_links.json"
    if not paths.db.is_file() or not committed.is_file():
        pytest.skip(f"{trial}: DB or committed t73_links.json missing")
    data = cl.run_check(REPO, trial)
    fresh = ci.check_text(data).encode("utf-8")
    old = committed.read_bytes()
    assert fresh == old, f"{trial}: t73_links.json differs ({len(fresh)} bytes now, {len(old)} committed)"
    assert data["db"]["sha256_before"] == data["db"]["sha256_after"] == sha256_file(paths.db)


@pytest.mark.parametrize("trial", DEV)
def test_t72_index_file_is_byte_identical_after_t74(trial):
    paths = trial_paths(REPO, trial)
    committed = REPO / CHECK_REL / trial / "t72_index.json"
    if not paths.db.is_file() or not committed.is_file():
        pytest.skip(f"{trial}: DB or committed t72_index.json missing")
    data = ci.run_check(REPO, trial)
    fresh = ci.check_text(data).encode("utf-8")
    old = committed.read_bytes()
    assert fresh == old, f"{trial}: t72_index.json differs ({len(fresh)} bytes now, {len(old)} committed)"
    assert data["db"]["sha256_before"] == data["db"]["sha256_after"] == sha256_file(paths.db)


# ================================================================================================ 2. tiers and ranks
def _protocol_group(h: Any) -> str:
    return "smb" if h.protocol in ("smb", "smb_service") else h.protocol


def _all_sessions() -> list[tuple[str, Any, tuple, Any, Any]]:
    return [(t, hop, key, sv, sl) for t in DEV for hop, key, sv, sl in sessions_of(run_of(t))]


def test_tiers_winrm_6_a_and_1_b_reported_apart_smb_9_b_and_2_d_no_c_no_tie():
    rows = _all_sessions()
    by = collections.defaultdict(collections.Counter)
    where = collections.defaultdict(list)
    for t, hop, key, sv, sl in rows:
        g = _protocol_group(hop)
        by[g][sv.confidence_tier] += 1
        where[(g, sv.confidence_tier)].append(f"{t}:{hop.hop_id}:{hex_of(key)}")
    print(f"tiers per protocol: { {g: dict(c) for g, c in by.items()} }")
    print(f"WinRM B: {where[('winrm', 'B')]}  SMB D: {where[('smb', 'D')]}")
    assert len(rows) == 18, f"{len(rows)} (hop, session) pairs"
    assert set(by) == {"winrm", "smb"}, f"sessions on protocols {sorted(by)}"
    assert dict(by["winrm"]) == {"A": 6, "B": 1}, f"WinRM tiers {dict(by['winrm'])}"
    assert dict(by["smb"]) == {"B": 9, "D": 2}, f"SMB tiers {dict(by['smb'])}"
    assert sum(1 for *_, sv, _ in rows if sv.confidence_tier == "C") == 0
    assert sum(1 for *_, sv, _ in rows if sv.tie) == 0
    # the same on the written columns: no tie = 1 anywhere, no tier C anywhere
    for t in DEV:
        r = run_of(t)
        assert not [x["link_id"] for x in r.links if x["tie"] == "1"], f"{t}: a row with tie = 1"
        assert not [x["link_id"] for x in r.links if x["confidence_tier"] == "C"], f"{t}: a tier C row"


def test_winrm_tier_a_hops_are_the_six_port_joined_ones_and_the_one_b_is_s06_t00_ep01_to_ep03_with_no_port_join():
    a, b = [], []
    for t, hop, key, sv, sl in _all_sessions():
        if hop.protocol != "winrm":
            continue
        methods = sl.session_methods[key]
        if sv.confidence_tier == "A":
            assert PORT in methods, f"{t} {hop.hop_id}: tier A without a port join"
            a.append(t)
        else:
            b.append((t, hop.hop_id, sl.source_host, hop.target_host, sorted(methods)))
    assert sorted(a) == ["s03_t00", "s03_t01", "s05_t00", "s06_t00", "s06_t01", "s06_t01"], f"tier A trials {sorted(a)}"
    assert len(b) == 1 and b[0][0] == "s06_t00", f"tier B WinRM {b}"
    _, hid, src_host, tgt_host, methods = b[0]
    assert (src_host, tgt_host) == ("ep-01", "ep-03") and PORT not in methods, f"{hid}: {src_host}->{tgt_host} {methods}"
    print(f"WinRM tier B: {hid} methods {methods}")


def test_where_the_port_join_and_the_command_line_both_find_a_session_it_is_the_same_session_6_of_6():
    both, same = [], []
    for t in DEV:
        r = run_of(t)
        for hop in r.li.hopset.hops:
            if hop.protocol != "winrm":
                continue
            rows = r.li.links[hop.hop_id].rows
            port = {x.session_key for x in rows if x.method == PORT and x.session_key is not None}
            cmd = {x.session_key for x in rows if x.method == CMD and x.session_key is not None}
            if port and cmd:
                both.append(hop.hop_id)
                if port == cmd:
                    same.append(hop.hop_id)
    assert len(both) == 6, f"{len(both)} WinRM hops found by both methods"
    assert sorted(same) == sorted(both), f"different sessions on {sorted(set(both) - set(same))}"


def _s04_pair() -> tuple[Any, Any, Any, Any]:
    r, key = run_of("s04_t00"), load_key("s04_t00")
    kh = {k["hop_id"]: k for k in key["hops"]}
    return r, stitch_hop_of(r.li, kh["s04-A-h1"]), stitch_hop_of(r.li, kh["s04-B-h1"]), key


def test_s04_each_key_hop_has_two_sessions_the_first_is_tier_b_direct_match_the_other_tier_d_rank_2():
    r, a, b, _ = _s04_pair()
    assert a.hop_id != b.hop_id
    firsts = {}
    for hop in (a, b):
        sess = r.li.verdicts[hop.hop_id].sessions
        assert len(sess) == 2, f"{hop.hop_id}: {len(sess)} sessions"
        ordered = sorted(sess.items(), key=lambda kv: kv[1].link_rank)
        (k1, s1), (k2, s2) = ordered
        assert (s1.link_rank, s2.link_rank) == (1, 2) and s1.tie == 0 and s2.tie == 0, f"{hop.hop_id}: ranks"
        assert (s1.confidence_tier, s1.account_match, s1.name_check, s1.rank_basis) == ("B", "direct", "match", "tier"), \
            f"{hop.hop_id}: rank 1 is {(s1.confidence_tier, s1.account_match, s1.name_check, s1.rank_basis)}"
        assert (s2.confidence_tier, s2.account_match) == ("D", "none") and s2.link_rank == 2, f"{hop.hop_id}: rank 2"
        firsts[hop.hop_id] = (k1, k2)
        # the written rows say the same
        for x in rows_of_hop(r, hop.hop_id):
            if x["method"] == TARGET_ONLY:
                continue
            want = s1 if x["source_session_id_hex"] == hex_of(k1) else s2
            assert (x["confidence_tier"], x["account_match"], x["link_rank"], x["tie"], x["rank_basis"]) == (
                want.confidence_tier, want.account_match, str(want.link_rank), "0", want.rank_basis), x["link_id"]
    (a1, a2), (b1, b2) = firsts[a.hop_id], firsts[b.hop_id]
    assert a1 != b1, "A and B share their rank-1 session"
    assert a1 == b2 and b1 == a2, "each hop's rank-1 session is not the other hop's rank-2 session"
    print(f"S04: A {a.hop_id} rank 1 {hex_of(a1)}, rank 2 {hex_of(a2)}; B {b.hop_id} rank 1 {hex_of(b1)}, rank 2 {hex_of(b2)}")


def test_s04_the_rank_1_session_of_each_key_hop_is_the_keys_source_session_for_the_attack_track():
    """The key names track B's source session only through the agent's own commands; track A's is `source_session_logon_id`.
    Here: A's rank-1 session is the key's 0xd6398."""
    r, a, b, key = _s04_pair()
    ka = next(k for k in key["hops"] if k["hop_id"] == "s04-A-h1")
    sess = r.li.verdicts[a.hop_id].sessions
    first = min(sess.items(), key=lambda kv: kv[1].link_rank)[0]
    assert hex_of(first) == ka["source_session_logon_id"].lower(), f"{a.hop_id}: rank 1 is {hex_of(first)}"


@pytest.mark.parametrize("trial", ["s06_t00", "s06_t01"])
def test_s06_winrm_hops_with_a_port_join_are_tier_a_with_account_match_4648(trial):
    r = run_of(trial)
    found = []
    for hop in r.li.hopset.hops:
        if hop.protocol != "winrm":
            continue
        sl = r.li.links[hop.hop_id]
        for key, sv in r.li.verdicts[hop.hop_id].sessions.items():
            if PORT in sl.session_methods[key]:
                found.append(hop.hop_id)
                assert (sv.confidence_tier, sv.account_match) == ("A", "4648"), \
                    f"{hop.hop_id}: {(sv.confidence_tier, sv.account_match)}"
    assert len(found) == (1 if trial == "s06_t00" else 2), f"{trial}: {len(found)} port-joined WinRM hops"


def test_s06_t00_winrm_hop_with_no_port_join_is_tier_b_and_the_keyed_winrm_hops_are_as_expected():
    r, key = run_of("s06_t00"), load_key("s06_t00")
    kh = {k["hop_id"]: k for k in key["hops"]}
    w1, w2 = stitch_hop_of(r.li, kh["s06-winrm-1"]), stitch_hop_of(r.li, kh["s06-winrm-2"])
    (s1,) = r.li.verdicts[w1.hop_id].sessions.values()
    (s2,) = r.li.verdicts[w2.hop_id].sessions.values()
    assert (s1.confidence_tier, s1.account_match) == ("A", "4648")
    assert s2.confidence_tier == "B" and s2.account_match in ("direct", "4648"), f"{w2.hop_id}: {s2.confidence_tier}"


def _mixed_hops(trial: str) -> list:
    r = run_of(trial)
    return [h for h in r.li.hopset.hops
            if h.mixed_account and h.protocol == "smb_service" and h.target_host in ENDPOINTS
            and r.li.links[h.hop_id].source_host in ENDPOINTS]


@pytest.mark.parametrize("trial", ["s06_t00", "s06_t01"])
def test_s06_mixed_smb_hop_has_member_values_4648_direct_direct_and_tier_b(trial):
    r = run_of(trial)
    mixed = _mixed_hops(trial)
    assert len(mixed) == 1, f"{trial}: {len(mixed)} mixed smb_service endpoint hops"
    hop = mixed[0]
    if trial == "s06_t00":
        key = load_key(trial)
        smb1 = stitch_hop_of(r.li, next(k for k in key["hops"] if k["hop_id"] == "s06-smb-1"))
        assert smb1.hop_id == hop.hop_id
    sessions = r.li.verdicts[hop.hop_id].sessions
    assert len(sessions) == 1, f"{hop.hop_id}: {len(sessions)} sessions"
    (sv,) = sessions.values()
    assert ";".join(sv.account_match_members) == "4648;direct;direct", f"{hop.hop_id}: {sv.account_match_members}"
    assert sv.account_match == "direct" and sv.account_match_member_count == 3
    assert sv.confidence_tier == "B", f"{hop.hop_id}: tier {sv.confidence_tier}"
    # the written rows (one per method) all carry the per-member text
    rows = [x for x in rows_of_hop(r, hop.hop_id) if x["method"] != TARGET_ONLY]
    assert rows and {x["account_match_members"] for x in rows} == {"4648;direct;direct"}
    assert {x["confidence_tier"] for x in rows} == {"B"}
    # independent check of the member values: members in time order; `direct` exactly where the member's account is the
    # session's own account, the first member (the 4648 credential) is the one that is not
    members = sorted(hop.members, key=lambda m: (m.us_raw, m.uid))
    session_account = {x["source_session_account"] for x in rows}
    assert len(session_account) == 1 and "" not in session_account, f"{hop.hop_id}: session account cells {len(session_account)}"
    (sa,) = session_account
    expect = ["direct" if (m.account_key or "") == sa.lower() else "4648" for m in members]
    assert expect == ["4648", "direct", "direct"], f"{hop.hop_id}: member accounts give {expect}"


def test_every_hop_with_no_candidate_has_exactly_one_target_only_row_tier_d_and_no_other_hop_has_one():
    n_no_cand = n_hops = 0
    for t in DEV:
        r = run_of(t)
        for hop in r.li.hopset.hops:
            n_hops += 1
            sl = r.li.links[hop.hop_id]
            rows = rows_of_hop(r, hop.hop_id)
            tonly = [x for x in rows if x["method"] == TARGET_ONLY]
            if sl.target_only_reason:
                n_no_cand += 1
                assert sl.candidate_count_all == 0, f"{hop.hop_id}: reason set with candidates"
                assert len(rows) == 1 and len(tonly) == 1, f"{hop.hop_id}: {len(rows)} rows, {len(tonly)} target_only"
                x = tonly[0]
                assert x["confidence_tier"] == "D" and x["candidate_count"] == "0" and x["link_rank"] == "" \
                    and x["tie"] == "0" and x["rank_basis"] == "target_only" and x["account_match"] == "none" \
                    and x["target_only_reason"] == sl.target_only_reason, f"{hop.hop_id}: target_only row {x['link_id']}"
            else:
                assert not tonly, f"{hop.hop_id}: a target_only row on a hop with candidates"
                assert sl.candidate_count_all >= 1
    print(f"hops {n_hops}, with no candidate {n_no_cand}")
    assert n_no_cand > 0


@pytest.mark.parametrize("trial", DEV)
def test_every_session_row_repeats_its_hop_session_verdict_and_the_rank_rules_hold(trial):
    r = run_of(trial)
    by_hop: dict[str, dict[str, list[dict]]] = collections.defaultdict(lambda: collections.defaultdict(list))
    for x in r.links:
        if x["method"] != TARGET_ONLY and x["source_session_id"]:
            by_hop[x["hop_id"]][x["source_session_id"]].append(x)
    for hop_id, sess in by_hop.items():
        verdicts = r.li.verdicts[hop_id].sessions
        assert len(sess) == len(verdicts), f"{hop_id}: {len(sess)} sessions in the file, {len(verdicts)} verdicts"
        for sid, rows in sess.items():
            tier_rank = {(x["confidence_tier"], x["link_rank"], x["tie"], x["rank_basis"], x["account_match"],
                          x["account_match_members"], x["name_check"], x["session_methods"]) for x in rows}
            assert len(tier_rank) == 1, f"{hop_id} {sid}: values differ across the rows of one session"
        ranks = sorted({int(next(iter(rows))["link_rank"]) for rows in sess.values()})
        assert ranks == list(range(1, len(ranks) + 1)), f"{hop_id}: ranks {ranks} are not dense from 1"
    # an unresolved-process row (no session) carries tier D, no rank
    for x in r.links:
        if x["session_unresolved_reason"]:
            assert x["confidence_tier"] == "D" and x["link_rank"] == "" and x["rank_basis"] == "no_session", x["link_id"]


def test_name_check_is_match_for_the_first_ranked_session_of_the_nine_named_smb_hops_and_no_names_on_winrm():
    match = no_names_winrm = 0
    for t in DEV:
        r = run_of(t)
        for hop in r.li.hopset.hops:
            hv = r.li.verdicts[hop.hop_id]
            if not hv.sessions:
                continue
            first = [sv for sv in hv.sessions.values() if sv.link_rank == 1]
            if hop.protocol == "winrm":
                assert all(sv.name_check == "no_names" for sv in hv.sessions.values()), f"{hop.hop_id}: names on WinRM"
                no_names_winrm += 1
            elif hv.names:
                assert all(sv.name_check == "match" for sv in first), f"{hop.hop_id}: first-ranked session without a match"
                match += 1
    assert (match, no_names_winrm) == (9, 7), f"matches {match}, WinRM hops with no names {no_names_winrm}"


# ================================================================================================ 3. identity facts
SYSTEM_ACCOUNTS = {"system", "network service", "local service"}


def is_system_read(row: Any) -> bool:
    a = (row.dump_account or "").lower()
    return a in SYSTEM_ACCOUNTS or a.endswith("$")


def _selected(rows: list, reads: str) -> list:
    reads_ = [x for x in rows if x.dump_event_uid]
    if reads == "all":
        return reads_
    nonsys = [x for x in reads_ if not is_system_read(x)]
    if reads == "nonsystem":
        return nonsys
    assert reads == "key_rule", reads
    ok = [x for x in nonsys if x.order_ok == 1]
    if not ok:
        return []
    # nearest before the move: the smallest non-negative gap (a small negative gap, inside the tolerance, ranks after)
    return [min(ok, key=lambda x: (x.gap_ms < 0, abs(x.gap_ms)))]


def deciding(rows: list, reads: str, counted: bool) -> list:
    out_ = []
    for x in _selected(rows, reads):
        uids = tuple(x.open_session_uids) + (tuple(x.end_unknown_session_uids) if counted else ())
        if x.order_ok == 1 and uids:
            out_.append(x)
    return out_


def value_of(rows: list, reads: str = "all", counted: bool = False) -> int:
    return int(bool(deciding(rows, reads, counted)))


VARIANTS = [(reads, counted) for reads in ("all", "nonsystem", "key_rule") for counted in (False, True)]


def _hop_rows(r: Run, hop_id: str, account: str) -> list:
    return [x for x in r.li.identity if x.hop_id == hop_id and x.account.lower() == account.lower()]


def test_every_q9_variant_equals_identity_expected_on_the_15_keyed_hops():
    bad: list[str] = []
    n = 0
    for t, kh, hop in keyed():
        rows = _hop_rows(run_of(t), hop.hop_id, key_account(kh))
        assert rows, f"{kh['hop_id']}: no identity rows for its account"
        assert all(not x.not_applicable for x in rows), f"{kh['hop_id']}: not_applicable set"
        n += 1
        for reads, counted in VARIANTS:
            v = value_of(rows, reads, counted)
            if v != kh["identity_expected"]:
                used = [x.dump_event_uid for x in _selected(rows, reads)]
                bad.append(f"{kh['hop_id']} ({hop.hop_id}) variant {reads}/end_unknown_{'counted' if counted else 'not_counted'}: "
                           f"value {v}, expected {kh['identity_expected']}, selected dump uids {used}")
    assert n == 15, f"{n} keyed hops"
    assert bad == [], f"{len(bad)} variant(s) disagree with the key: " + " | ".join(bad)


def test_value_1_keyed_hops_decide_at_least_38_s_after_the_dump_and_on_a_session_open_inside_the_window():
    gaps_all, gaps_key, no_pre = {}, {}, {}
    for t, kh, hop in keyed():
        if kh["identity_expected"] != 1:
            continue
        rows = _hop_rows(run_of(t), hop.hop_id, key_account(kh))
        d_all = deciding(rows, "all", False)
        d_key = deciding(rows, "key_rule", False)
        assert d_all and d_key, f"{kh['hop_id']}: no deciding row"
        gaps_all[kh["hop_id"]] = min(x.gap_ms for x in d_all)
        gaps_key[kh["hop_id"]] = min(x.gap_ms for x in d_key)
        no_pre[kh["hop_id"]] = any(x.session_open_before_window == 0 for x in d_all)
    print(f"deciding gaps, all reads: {gaps_all}")
    print(f"deciding gaps, key rule: {gaps_key}")
    assert len(gaps_all) == 8, f"{len(gaps_all)} value-1 keyed hops"   # 8 of the 15 keys expect 1
    low_all, low_key = min(gaps_all.values()), min(gaps_key.values())
    assert low_all >= 38000 and low_key >= 38000, f"smallest deciding gap {low_all} ms (all) / {low_key} ms (key rule)"
    assert min(gaps_key, key=gaps_key.get) == "s04-A-h1" and low_key == 38386, \
        f"smallest deciding gap {low_key} ms at {min(gaps_key, key=gaps_key.get)} (049: 38386, s04-A)"
    assert all(no_pre.values()), f"keyed hop(s) decided only by a pre-window session: {[k for k, v in no_pre.items() if not v]}"


def test_no_keyed_hop_row_is_within_the_tolerance_or_the_uncertainty_band():
    bad = []
    for t, kh, hop in keyed():
        for x in _hop_rows(run_of(t), hop.hop_id, key_account(kh)):
            if x.order_within_tolerance == 1 or x.order_within_uncertainty == 1:
                bad.append(f"{kh['hop_id']} {x.dump_event_uid}")
    assert bad == [], f"{len(bad)} keyed row(s) flagged: {bad}"


def _pairs() -> dict[tuple[str, str, str], dict]:
    """(trial, hop_id, account) -> {rows, target, source} over all nine trials."""
    out_: dict = {}
    for t in DEV:
        r = run_of(t)
        tgt = {h.hop_id: h.target_host for h in r.li.hopset.hops}
        for x in r.li.identity:
            p = out_.setdefault((t, x.hop_id, x.account), {"rows": [], "target": tgt[x.hop_id], "source": x.source_host,
                                                           "na": x.not_applicable})
            p["rows"].append(x)
    return out_


def test_user_endpoint_to_endpoint_pairs_give_value_1_for_11_and_0_for_12():
    ones, zeros = [], []
    for (t, hid, acct), p in _pairs().items():
        if is_user_e2e(p["source"], p["target"], acct) and not p["na"]:
            (ones if value_of(p["rows"]) else zeros).append((t, hid, acct))
    print(f"endpoint->endpoint pairs: {len(ones)} value 1, {len(zeros)} value 0")
    assert len(ones) + len(zeros) == 23, f"{len(ones) + len(zeros)} pairs"
    assert (len(ones), len(zeros)) == (11, 12), f"value 1: {len(ones)}, value 0: {len(zeros)}"


def test_the_pairs_decided_only_by_a_session_open_before_the_window_are_the_8_svc_backup_ep02_to_dc01_ones():
    pre = []
    for (t, hid, acct), p in _pairs().items():
        ones = [x for x in p["rows"] if x.dump_event_uid and x.order_ok == 1 and x.open_session_uids]
        if ones and all(x.session_open_before_window == 1 for x in ones):
            pre.append((t, hid, acct, p["source"], p["target"]))
    print(f"pre-window-only pairs: {[(t, h) for t, h, *_ in pre]}")
    assert len(pre) == 8, f"{len(pre)} pairs: {[(t, h) for t, h, *_ in pre]}"
    assert all(a.lower() == "svc_backup" and s == "ep-02" and tg == "dc01" for _, _, a, s, tg in pre), \
        f"unexpected pair(s): {[(t, h, a, s, tg) for t, h, a, s, tg in pre if not (a.lower() == 'svc_backup' and s == 'ep-02' and tg == 'dc01')]}"
    keyed_hops = {(t, hop.hop_id) for t, _, hop in keyed()}
    assert not [(t, h) for t, h, *_ in pre if (t, h) in keyed_hops], "a keyed hop is decided by a pre-window session"


def test_only_s02_t00_h0027_has_a_row_within_the_tolerance_and_it_is_not_keyed():
    flagged = collections.Counter()
    unc = collections.Counter()
    for t in DEV:
        for x in run_of(t).li.identity:
            if x.order_within_tolerance == 1:
                flagged[(t, x.hop_id)] += 1
            if x.order_within_uncertainty == 1:
                unc[(t, x.hop_id)] += 1
    print(f"order_within_tolerance rows per hop: {dict(flagged)}; order_within_uncertainty rows per hop: {dict(unc)}")
    assert set(flagged) == {("s02_t00", "s02_t00-h0027")}, f"hops with order_within_tolerance rows: {sorted(flagged)}"
    assert ("s02_t00", "s02_t00-h0027") not in {(t, hop.hop_id) for t, _, hop in keyed()}


def test_every_identity_row_of_a_hop_with_no_source_logs_or_machine_account_is_not_applicable_with_empty_dump_columns():
    reasons = collections.Counter()
    for t in DEV:
        for x in run_of(t).li.identity:
            if x.not_applicable:
                reasons[x.not_applicable] += 1
                assert x.dump_event_uid == "" or x.dump_event_uid is None, f"{x.hop_id}: dump on a not_applicable row"
                assert x.not_applicable in ("source_host_unknown", "source_host_no_logs", "machine_account"), x.hop_id
    print(f"not_applicable rows {dict(reasons)}")
    assert set(reasons) <= {"source_host_unknown", "source_host_no_logs", "machine_account"}


@pytest.mark.parametrize("trial", DEV)
def test_every_hop_has_an_identity_row_per_account_and_target_only_hops_are_not_skipped(trial):
    r = run_of(trial)
    for hop in r.li.hopset.hops:
        accounts = {m.account for m in hop.members if m.account}
        got = {x.account for x in r.li.identity if x.hop_id == hop.hop_id}
        assert accounts <= got, f"{hop.hop_id}: accounts without an identity row"


# ================================================================================================ 4. files
@functools.lru_cache(maxsize=None)
def _written(trial: str) -> dict | None:
    """Run `python -m stitch` twice (in process); return exit codes, both byte sets and the run_info of run 2."""
    paths = trial_paths(REPO, trial)
    if not paths.db.is_file() or not (paths.gate_dir / "stats.json").is_file():
        return None
    folder = REPO / "out" / "stitch" / trial
    names = ("links.csv", "hop_artefacts.csv", "hop_identity.csv")
    codes, got = [], []
    for _ in range(2):
        codes.append(stitch_main.main(["--trial", trial, "--repo", str(REPO)]))
        got.append({n: (folder / n).read_bytes() for n in names})
    info = json.loads((folder / "run_info.json").read_text(encoding="utf-8"))
    return {"codes": codes, "files": got, "info": info, "extra": sorted(p.name for p in folder.iterdir())}


def written(trial: str) -> dict:
    assert trial in DEV
    got = _written(trial)
    if got is None:
        pytest.skip(f"{trial}: trial DB or gate output missing")
    return got


@pytest.mark.parametrize("trial", DEV)
def test_main_twice_exits_0_and_the_three_csvs_are_byte_identical_and_equal_the_in_memory_text(trial):
    w, r = written(trial), run_of(trial)
    assert w["codes"] == [0, 0], f"{trial}: exit codes {w['codes']}"
    one, two = w["files"]
    for name in one:
        assert one[name] == two[name], f"{trial}: {name} differs between two runs"
    mem = {"links.csv": out.csv_text(out.LINKS_COLUMNS, r.links), "hop_artefacts.csv": out.csv_text(out.ARTEFACT_COLUMNS, r.arts),
           "hop_identity.csv": out.csv_text(out.IDENTITY_COLUMNS, r.ids)}
    for name, text in mem.items():
        assert one[name] == text.encode("utf-8"), f"{trial}: {name} differs from outputs.csv_text of the in-memory rows"
    assert w["extra"] == sorted(TEN_FILES), f"{trial}: files {w['extra']}"


@pytest.mark.parametrize("trial", DEV)
def test_run_info_db_hashes_equal_the_db_file_hash_and_file_facts_equal_the_files(trial):
    import hashlib
    w = written(trial)
    info, paths = w["info"], trial_paths(REPO, trial)
    sha = sha256_file(paths.db)
    assert info["db"]["sha256_before"] == info["db"]["sha256_after"] == sha, f"{trial}: DB hash in run_info"
    assert info["trial_id"] == trial
    for name, blob in w["files"][1].items():
        n = len(list(csv.reader(io.StringIO(blob.decode("utf-8"))))) - 1
        assert info["files"][name]["rows"] == n, f"{trial}: {name} rows {info['files'][name]['rows']} vs {n}"
        assert info["files"][name]["sha256"] == hashlib.sha256(blob).hexdigest(), f"{trial}: {name} sha256 in run_info"


def test_row_counts_of_links_and_identity_files_equal_the_expected_numbers():
    diffs = []
    for t in TABLE_ORDER:
        w = written(t)
        n_links = len(list(csv.reader(io.StringIO(w["files"][1]["links.csv"].decode("utf-8"))))) - 1
        n_id = len(list(csv.reader(io.StringIO(w["files"][1]["hop_identity.csv"].decode("utf-8"))))) - 1
        print(f"{t}: links {n_links} (expect {LINK_ROWS[t]}), identity {n_id} (expect {IDENTITY_ROWS[t]}), "
              f"artefacts {w['info']['files']['hop_artefacts.csv']['rows']}")
        if n_links != LINK_ROWS[t]:
            diffs.append(f"{t} links {n_links} != {LINK_ROWS[t]}")
        if n_id != IDENTITY_ROWS[t]:
            diffs.append(f"{t} identity {n_id} != {IDENTITY_ROWS[t]}")
    assert diffs == [], "row count differences: " + "; ".join(diffs)


def test_a_non_development_trial_is_refused_with_exit_2_and_nothing_is_written(capsys):
    target = REPO / "out" / "stitch" / "s02_t02"
    pre_existing = target.exists()
    assert pre_existing is False, "out/stitch/s02_t02 exists before the test (not created by this test)"
    code = stitch_main.main(["--trial", "s02_t02", "--repo", str(REPO)])
    err = capsys.readouterr().err
    assert code == 2, f"exit code {code}"
    assert "refused" in err
    assert not target.exists(), "out/stitch/s02_t02 was created"
    leftovers = sorted(p.name for p in (REPO / "out" / "stitch").iterdir() if p.name.startswith(".") or "s02_t02" in p.name)
    assert leftovers == [], f"leftover entries {leftovers}"


# ================================================================================================ 5. STT-13 on real files
BLANK = {"links.csv": {"source_session_account", "name_check_names"}, "hop_artefacts.csv": {"names"},
         "hop_identity.csv": {"dump_source_image", "dump_account", "account"}}
GRAM = 12


def _db(trial: str) -> sqlite3.Connection:
    p = trial_paths(REPO, trial).db
    con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _grams(text: str) -> set[str]:
    return {text[i:i + GRAM] for i in range(len(text) - GRAM + 1)}


def _read(blob: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(blob.decode("utf-8"))))


@pytest.mark.parametrize("trial", DEV)
def test_no_12_character_substring_of_a_command_line_is_in_any_csv_after_blanking_the_db_field_columns(trial):
    w = written(trial)
    where: dict[str, set[tuple[str, str]]] = collections.defaultdict(set)     # gram -> (file, column)
    for name, blob in w["files"][1].items():
        for row in _read(blob):
            for col, val in row.items():
                if col in BLANK[name] or not val:
                    continue
                for piece in val.split(";"):
                    for g in _grams(piece):
                        where[g].add((name, col))
    con = _db(trial)
    try:
        hit: dict[str, set[tuple[str, str]]] = {}
        n_lines = 0
        for (cl_,) in con.execute("select command_line from events_dedup where command_line is not null and command_line != ''"):
            n_lines += 1
            for g in _grams(cl_):
                if g in where:
                    hit[g] = where[g]
    finally:
        con.close()
    cols = collections.Counter(c for v in hit.values() for c in v)
    assert n_lines > 0, f"{trial}: no command line in the DB"
    assert not hit, f"{trial}: {len(hit)} twelve-character substring(s) of {n_lines} command lines found in the files, by (file, column): {dict(cols)}"


@pytest.mark.parametrize("trial", DEV)
def test_the_four_blanked_columns_equal_the_db_field_of_the_event_each_row_references(trial):
    w, r = written(trial), run_of(trial)
    files = {n: _read(b) for n, b in w["files"][1].items()}
    con = _db(trial)
    try:
        def field(uid: str, col: str):
            row = con.execute(f"select channel, event_id, {col} as v from events_dedup where event_uid = ?", (uid,)).fetchone()
            return None if row is None else (row["channel"], row["event_id"], row["v"])

        members = {h.hop_id: [u for m in h.members for u in m.event_uids] for h in r.li.hopset.hops}
        bad: list[str] = []
        case_only = 0
        n_img = n_acc = n_sess = 0
        for x in files["hop_identity.csv"]:
            # dump columns <- the Sysmon 10 row of dump_event_uid
            if x["dump_event_uid"]:
                img, acc = field(x["dump_event_uid"], "source_image"), field(x["dump_event_uid"], "account_name")
                if img is None or img[:2] != ("Sysmon", 10):
                    bad.append(f"{x['hop_id']} dump {x['dump_event_uid']}: not a Sysmon 10 in the DB")
                    continue
                n_img += 1
                if (img[2] or "") != x["dump_source_image"]:
                    bad.append(f"{x['hop_id']} dump {x['dump_event_uid']}: dump_source_image differs from DB source_image")
                if (acc[2] or "") != x["dump_account"]:
                    if (acc[2] or "").lower() == x["dump_account"].lower():
                        case_only += 1
                    else:
                        bad.append(f"{x['hop_id']} dump {x['dump_event_uid']}: dump_account differs from DB account_name")
            else:
                assert x["dump_source_image"] == "" and x["dump_account"] == "", f"{x['hop_id']}: dump text with no dump uid"
            # identity account <- account_name of a member 4624 of that hop
            names = {(field(u, "account_name") or (0, 0, None))[2] for u in members[x["hop_id"]]}
            n_acc += 1
            if x["account"] not in names:
                bad.append(f"{x['hop_id']}: account cell is no member 4624 account_name of the hop (uids {members[x['hop_id']][:3]}...)")
        for x in files["links.csv"]:
            if not x["source_session_account"]:
                continue
            uids = [u for u in x["source_session_logon_uid"].split(";") if u]
            if not uids:
                bad.append(f"{x['link_id']}: session account with no logon uid")
                continue
            n_sess += 1
            for u in uids:
                f = field(u, "account_name")
                if f is None or f[:2] != ("Security", 4624) or (f[2] or "") != x["source_session_account"]:
                    bad.append(f"{x['link_id']}: source_session_account differs from the 4624 {u}")
    finally:
        con.close()
    print(f"{trial}: dump rows checked {n_img}, identity accounts {n_acc}, session accounts {n_sess}, dump_account case-only differences {case_only}")
    assert bad == [], f"{len(bad)} cell(s) differ from their DB field: " + " | ".join(bad[:10])
    assert case_only == 0, f"{trial}: {case_only} dump_account value(s) equal the DB field only up to case"


# ================================================================================================ 5b. STT-13 over all ten files (T7.5)
ALL_BLANK = dict(BLANK, **{"hops.csv": {"member_accounts"}})        # 049 item 7 plus decision 050 item 8
WHOLE_TEXT = ("stats.json", "report.md", "run_info.json")
# Owner ruling: an IPv4 address is exempt from the scan only as a bare address (stitch_fixtures.non_exempt_hits): a
# command window that lies wholly inside a full dotted-quad token, bounded by a non-digit non-dot character, at every
# position where it occurs. Nothing is blanked in the output text for the IPs.


def _folder_bytes(trial: str) -> dict[str, bytes]:
    written(trial)                                             # runs `python -m stitch` (twice, in process)
    folder = REPO / "out" / "stitch" / trial
    return {p.name: p.read_bytes() for p in sorted(folder.iterdir())}


def _command_grams(trial: str) -> tuple[set[str], int]:
    con = _db(trial)
    try:
        grams: set[str] = set()
        n = 0
        for (c,) in con.execute("select command_line from events_dedup where command_line is not null and command_line != ''"):
            n += 1
            grams |= _grams(c.casefold())
    finally:
        con.close()
    return grams, n


@pytest.mark.parametrize("trial", DEV)
def test_all_ten_files_are_written_and_the_run_info_lists_the_other_nine(trial):
    import hashlib
    files = _folder_bytes(trial)
    assert sorted(files) == sorted(TEN_FILES), f"{trial}: files {sorted(files)}"
    info = json.loads(files["run_info.json"].decode("utf-8"))
    assert sorted(info["files"]) == sorted(n for n in TEN_FILES if n != "run_info.json")
    for n, f in info["files"].items():
        assert f["sha256"] == hashlib.sha256(files[n]).hexdigest(), f"{trial}: {n} sha256"
        if n in ("stats.json", "report.md"):
            assert f["rows"] is None, f"{trial}: {n} rows"
        else:
            assert f["rows"] == len(_read(files[n])), f"{trial}: {n} rows"


def _scan_files(files: dict[str, bytes], grams: set[str]) -> dict[tuple[str, str], int]:
    """(file, column) -> number of non-exempt command windows, over all files of one folder: CSVs cell piece by cell
    piece with the account / image / member_accounts columns blanked (049 item 7, 050 item 8), the text files line by
    line, nothing else blanked."""
    found: collections.Counter = collections.Counter()
    for name, blob in files.items():
        if name in WHOLE_TEXT:
            for line in blob.decode("utf-8").splitlines():
                n = len(sf.non_exempt_hits(line, grams))
                if n:
                    found[(name, "<text>")] += n
            continue
        if not name.endswith(".csv"):
            continue
        for row in _read(blob):
            for col, val in row.items():
                if col in ALL_BLANK.get(name, set()) or not val:
                    continue
                for piece in val.split(";"):
                    n = len(sf.non_exempt_hits(piece, grams))
                    if n:
                        found[(name, col)] += n
    return dict(found)


@pytest.mark.parametrize("trial", DEV)
def test_no_12_character_command_substring_in_any_of_the_ten_files_after_blanking(trial):
    files = _folder_bytes(trial)
    grams, n_lines = _command_grams(trial)
    assert n_lines > 0
    found = _scan_files(files, grams)
    assert not found, f"{trial}: non-exempt 12-character command windows of {n_lines} command lines, by (file, column): {found}"


def test_the_scan_fails_on_an_injected_ip_plus_share_string_in_a_temp_copy(tmp_path):
    """The real-data scan must catch an IP followed by a share path (a bare IP is exempt, an IP with a share path is
    not). The injection goes into a temp copy of the folder; out/ is never touched."""
    trial = "s02_t00"
    files = _folder_bytes(trial)
    grams, _n = _command_grams(trial)
    injected = r"\\192.168.50.22\ADMIN$".casefold()
    if not any(injected[i:i + 12] in grams for i in range(len(injected) - 11)):
        pytest.skip("no command line of the trial holds the injected string")
    assert _scan_files(files, grams) == {}, "baseline scan is not clean"
    copy = tmp_path / trial
    copy.mkdir()
    for n, blob in files.items():
        (copy / n).write_bytes(blob)
    (copy / "report.md").write_bytes(files["report.md"] + ("\n" + injected + "\n").encode("utf-8"))
    got = _scan_files({p.name: p.read_bytes() for p in copy.iterdir()}, grams)
    assert got.get(("report.md", "<text>"), 0) >= 1, f"injected string not caught: {got}"
    # a bare address on its own line is still exempt
    (copy / "report.md").write_bytes(files["report.md"] + b"\n192.168.50.22\n")
    assert _scan_files({p.name: p.read_bytes() for p in copy.iterdir()}, grams) == {}


@pytest.mark.parametrize("trial", DEV)
def test_hops_csv_member_accounts_are_the_account_name_of_each_member_4624(trial):
    files = _folder_bytes(trial)
    rows = _read(files["hops.csv"])
    con = _db(trial)
    bad: list[str] = []
    checked = 0
    try:
        for r in rows:
            uids = r["member_logon_uids"].split(";")
            accts = r["member_accounts"].split(";")
            if not (len(uids) == len(accts) == int(r["member_count"])):
                bad.append(f"{r['hop_id']}: {len(uids)} uids, {len(accts)} accounts, member_count {r['member_count']}")
                continue
            for uid, a in zip(uids, accts):
                row = con.execute("select channel, event_id, account_name from events_dedup where event_uid = ?", (uid,)).fetchone()
                checked += 1
                if row is None or (row["channel"], row["event_id"]) != ("Security", 4624) or (row["account_name"] or "") != a:
                    bad.append(f"{r['hop_id']}: member {uid} account cell differs from the 4624 account_name")
    finally:
        con.close()
    assert checked > 0
    assert bad == [], f"{trial}: {len(bad)} cell(s): " + " | ".join(bad[:10])


@pytest.mark.parametrize("trial", DEV)
def test_report_md_has_no_blanking_no_command_substring_and_no_account_or_image_text(trial):
    files = _folder_bytes(trial)
    report = files["report.md"].decode("utf-8").casefold()
    grams, n_lines = _command_grams(trial)
    hits = sum(1 for g in grams if g in report)
    assert n_lines > 0
    assert hits == 0, f"{trial}: {hits} twelve-character command substring(s) in report.md (count only)"
    cells: set[str] = set()
    for r in _read(files["hops.csv"]):
        cells |= {a for a in r["member_accounts"].split(";") if a}
    for r in _read(files["hop_identity.csv"]):
        cells |= {r["account"], r["dump_account"], r["dump_source_image"]} - {""}
    for r in _read(files["links.csv"]):
        cells |= {r["source_session_account"]} - {""}
        cells |= {n for n in r["name_check_names"].split(";") if n}
    for r in _read(files["hop_artefacts.csv"]):
        cells |= {n for n in r["names"].split(";") if n}
    assert cells
    leaked = sorted(c for c in cells if c.casefold() in report)
    assert leaked == [], f"{trial}: {len(leaked)} account / image / name cell value(s) appear in report.md (count only)"
