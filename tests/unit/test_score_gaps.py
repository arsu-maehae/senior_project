"""T9 score stage: the gaps listed after the first review and the attacker's open cases (spec 05_score SC-21, SC-21b,
SC-52, SC-54, section 3.5 stats; decision 067 items 4, 5; review cases ATK-SC-19, ATK-SC-20).

Written from the spec and decisions, not from the code. Synthetic (fast); the real-data stats check is in
`test_score_real.py`. Decision 069 items 1-3 (sibling boundary, per-account low / high, member account refusal).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import score.__main__ as sm  # noqa: E402
import score_fixtures as fx  # noqa: E402
from score.run import run_trial  # noqa: E402

NOW = "2026-11-18T00:00:00Z"


def run(tmp_path, world, name="r"):
    return run_trial(fx.build_repo(tmp_path / name, world), fx.TRIAL, generated_utc=NOW)


def rows(res, name):
    return fx.parse_text(res.files[name])


def full(res):
    return {r["path_id"]: r for r in rows(res, "ranked_paths.csv") if r["variant"] == "full"}


# ================================================================================================ L-ST5: host_time edge gaps in stats.json
def host_time_world():
    w = fx.base_world()
    w.edges = [fx.edge("p0006", "h6", "h7", link="host_time", delta="1234")]
    w.paths.append(fx.path("p0009", "h5;h2", hosts="ep-01>ep-03", edge_types="host_time:1"))
    w.edges.append(fx.edge("p0009", "h5", "h2", link="host_time", delta="99"))
    w.edges.append(fx.edge("p0009", "h2", "h5", link="session", delta="7"))         # a session edge: not a host_time gap
    return w


def test_stats_json_has_host_time_edge_gaps_count_min_max_and_sorted_values(tmp_path):
    res = run(tmp_path, host_time_world())
    gaps = json.loads(res.files["stats.json"])["host_time_edge_gaps_ms"]
    assert gaps == {"count": 2, "min": 99, "max": 1234, "values": [99, 1234]}


def test_stats_json_host_time_gaps_are_empty_without_host_time_edges(tmp_path):
    gaps = json.loads(run(tmp_path, fx.base_world()).files["stats.json"])["host_time_edge_gaps_ms"]
    assert gaps == {"count": 0, "min": None, "max": None, "values": []}


# ================================================================================================ SC-21: event times never order techniques inside a hop
def reversed_times(w):
    times = sorted({e["event_utc_corrected"] for e in w.events})
    swap = dict(zip(times, reversed(times)))
    for e in w.events:
        e["event_utc_corrected"] = swap[e["event_utc_corrected"]]
    return w


STEP_KEYS = ("path_id", "step", "from_technique", "to_technique", "from_tactic", "to_tactic", "tactic_score",
             "technique_score", "score_e", "basis", "method", "candidate_count")


def test_sc21_swapping_event_times_inside_hops_changes_no_sequence_score_or_basis(tmp_path):
    a = run(tmp_path, fx.base_world(), "a")
    b = run(tmp_path, reversed_times(fx.base_world()), "b")
    assert [e["event_utc_corrected"] for e in fx.base_world().events] != [e["event_utc_corrected"] for e in reversed_times(fx.base_world()).events]
    assert a.files["ranked_paths.csv"] == b.files["ranked_paths.csv"]                     # sequences, L, N, I, ranks
    for name in ("path_node_units.csv", "hop_identity_values.csv", "b0_ranked.csv"):
        assert a.files[name] == b.files[name], name
    sa, sb = rows(a, "path_steps.csv"), rows(b, "path_steps.csv")
    assert [{k: r[k] for k in STEP_KEYS} for r in sa] == [{k: r[k] for k in STEP_KEYS} for r in sb]
    full_a = full(a)
    assert full_a["p0001"]["technique_sequence"] == "T1021.002>T1570>T1569.002"          # template stage, not event time
    assert full_a["p0002"]["technique_sequence"] == "T1078>T1021.006"


def test_sc21_within_hop_transitions_have_no_time_delta_whatever_the_event_times(tmp_path):
    for world in (fx.base_world(), reversed_times(fx.base_world())):
        steps = rows(run(tmp_path, world, f"w{id(world)}"), "path_steps.csv")
        p1 = [s for s in steps if s["path_id"] == "p0001"]
        assert [s["time_delta_ms"] for s in p1] == ["", ""]
        assert [s["basis"] for s in p1] == ["direct", "direct"]


def test_sc21_one_hop_with_events_logged_in_reverse_stage_order_keeps_template_order(tmp_path):
    w = fx.base_world()
    times = {"u_s4697": "10:00:01", "u_s7045": "10:00:02", "u_cp": "10:00:03", "u_smb": "10:00:04"}   # exec first, SMB last
    for e in w.events:
        if e["event_uid"] in times:
            e["event_utc_corrected"] = f"2026-09-24T{times[e['event_uid']]}.000000Z"
    assert full(run(tmp_path, w))["p0001"]["technique_sequence"] == "T1021.002>T1570>T1569.002"


# ================================================================================================ decision 067 item 4: sibling hops
def sibling_world():
    """h1 (SMB) and h2 (WinRM) in one merged path with NO chain edge between them (siblings)."""
    w = fx.base_world()
    w.paths = [fx.path("p0010", "h1;h2", hosts="ep-01>ep-03", edge_types="")]
    w.edges = []
    w.nodes = [dict(n, path_id="p0010") for n in w.nodes if n["path_id"] in ("p0001", "p0002")]
    w.hops = [h for h in w.hops if h["hop_id"] in ("h1", "h2")]
    w.identity = [r for r in w.identity if r["hop_id"] in ("h1", "h2")]
    return w


def chained_world():
    """The same two hops with a real chain edge h1 -> h2 in path_edges."""
    w = sibling_world()
    w.edges = [fx.edge("p0010", "h1", "h2", link="host_time", delta="1000")]
    return w


def test_decision_069_item_1_sibling_boundary_without_a_chain_edge_is_scored_against_the_templates(tmp_path):
    """ATK-SC-17 (amends 067 item 4): no chain edge -> the boundary step is not hop_chain; execution -> initial-access has
    no template path, so it is `absent` (ScoreE = 0.5 * 0 + 0.5 * 0.01)."""
    res = run(tmp_path, sibling_world())
    steps = [s for s in rows(res, "path_steps.csv") if s["path_id"] == "p0010"]
    assert [s["basis"] for s in steps] == ["direct", "direct", "absent", "indirect"]
    boundary = steps[2]
    assert (boundary["from_technique"], boundary["to_technique"]) == ("T1569.002", "T1078")
    assert float(boundary["score_e"]) == pytest.approx(0.005) and float(boundary["tactic_score"]) == pytest.approx(0.0)
    assert boundary["time_delta_ms"] != ""                                              # the time gap is still reported
    r = full(res)["p0010"]
    assert r["technique_sequence"] == "T1021.002>T1570>T1569.002>T1078>T1021.006"
    assert float(r["edge_score"]) == pytest.approx((1 + 1 + 0.005 + 0.5) / 4)


def test_a_boundary_across_a_real_chain_edge_stays_hop_chain(tmp_path):
    res = run(tmp_path, chained_world())
    steps = [s for s in rows(res, "path_steps.csv") if s["path_id"] == "p0010"]
    assert [s["basis"] for s in steps] == ["direct", "direct", "hop_chain", "indirect"]
    assert float(steps[2]["score_e"]) == pytest.approx(1.0)
    assert float(full(res)["p0010"]["edge_score"]) == pytest.approx(0.875)


def test_a_chain_edge_raises_the_path_score_over_siblings_with_the_same_hops(tmp_path):
    sib = full(run(tmp_path, sibling_world(), "s"))["p0010"]
    chn = full(run(tmp_path, chained_world(), "c"))["p0010"]
    assert float(chn["length_score"]) > float(sib["length_score"]) and float(chn["score"]) > float(sib["score"])
    assert chn["technique_sequence"] == sib["technique_sequence"]


def test_sibling_hop_order_comes_from_time_then_hop_id_and_never_from_the_list(tmp_path):
    seqs = set()
    for lst in ("h1;h2", "h2;h1"):
        w = sibling_world()
        w.paths[0]["hop_ids"] = lst
        seqs.add(full(run(tmp_path, w, lst.replace(";", "")))["p0010"]["technique_sequence"])
    assert seqs == {"T1021.002>T1570>T1569.002>T1078>T1021.006"}                           # h1 (10:00:10) before h2 (10:05)


# ================================================================================================ ATK-SC-19 / ATK-SC-20 (open attacker cases)
def two_account_world(flagged_account_value_one=False):
    """One hop h1 with two applicable accounts: A exposed, unflagged (value 1); B a rejecting read inside the clock
    uncertainty (order_ok 0, order_within_uncertainty 1, value 0)."""
    w = fx.base_world()
    w.paths = [fx.path("p0020", "h1")]
    w.edges = []
    w.nodes = [dict(n, path_id="p0020") for n in w.nodes if n["path_id"] == "p0001"]
    w.hops = [dict(h, member_accounts="acctA;acctB") for h in w.hops if h["hop_id"] == "h1"]
    w.identity = [fx.ident("h1", "acctA", dump_event_uid="dA", open_session_uids="sA"),
                  fx.ident("h1", "acctB", dump_event_uid="dB", order_ok="0", order_margin_ms="-6000", gap_ms="-6000",
                           order_within_uncertainty="1", open_session_uids="sB", clock_unreliable="1")]
    return w


def test_two_account_hop_value_is_the_max_over_accounts_and_the_unflagged_exposed_account_decides(tmp_path):
    r = full(run(tmp_path, two_account_world()))["p0020"]
    assert (r["n_crossings"], r["n_crossings_coherent"]) == ("1", "1")
    assert float(r["identity_coherence"]) == 1.0 and float(r["identity_high"]) == 1.0


def test_atk_sc19_identity_low_is_one_when_an_unflagged_account_already_gives_the_hop_value_one(tmp_path):
    """Decision 069 item 2: low / high are decided per account (robust = value 1 and unflagged)."""
    r = full(run(tmp_path, two_account_world()))["p0020"]
    assert float(r["identity_low"]) == 1.0 and float(r["identity_coherence"]) == 1.0 and float(r["identity_high"]) == 1.0
    assert float(r["identity_low"]) <= float(r["identity_coherence"]) <= float(r["identity_high"])
    assert r["n_crossings_flagged"] == "1"


def test_atk_sc19_a_hop_whose_only_exposed_account_is_flagged_has_low_zero_and_high_one(tmp_path):
    w = two_account_world()
    w.identity = [fx.ident("h1", "acctA", dump_event_uid="dA", open_session_uids="sA", order_within_uncertainty="1",
                           clock_unreliable="1"),
                  fx.ident("h1", "acctB", dump_event_uid="dB", open_session_uids="")]       # B: no open session, value 0
    r = full(run(tmp_path, w))["p0020"]
    assert (float(r["identity_low"]), float(r["identity_coherence"]), float(r["identity_high"])) == (0.0, 1.0, 1.0)


def test_atk_sc19_two_flagged_rejecting_accounts_give_low_zero_coherence_zero_high_one(tmp_path):
    w = two_account_world()
    w.identity = [fx.ident("h1", a, dump_event_uid="d" + a, order_ok="0", order_margin_ms="-6000", gap_ms="-6000",
                           order_within_uncertainty="1", open_session_uids="s" + a, clock_unreliable="1")
                  for a in ("acctA", "acctB")]
    r = full(run(tmp_path, w))["p0020"]
    assert (float(r["identity_low"]), float(r["identity_coherence"]), float(r["identity_high"])) == (0.0, 0.0, 1.0)


def test_atk_sc20_score_refuses_a_member_account_with_no_identity_row(tmp_path, capsys):
    """Decision 069 item 3: a hops.csv member account without a hop_identity.csv row (it would silently leave the crossing
    and the denominator) is refused, exit 2, nothing written."""
    w = fx.base_world()
    w.paths = [fx.path("p0021", "h1")]
    w.edges = []
    w.nodes = [dict(n, path_id="p0021") for n in w.nodes if n["path_id"] == "p0001"]
    w.hops = [dict(h, member_accounts="svc;ghost") for h in w.hops if h["hop_id"] == "h1"]
    w.identity = [r for r in w.identity if r["hop_id"] == "h1"]                          # no row for `ghost`
    repo = fx.build_repo(tmp_path / "r", w)
    out = tmp_path / "out"
    assert sm.main(["--trial", fx.TRIAL, "--repo", str(repo), "--out", str(out)]) == 2
    assert capsys.readouterr().err.startswith("refused:") and not out.exists()


def test_a_world_whose_member_accounts_all_have_identity_rows_is_accepted(tmp_path):
    """Control for ATK-SC-20: the standard fixture is consistent (every hops.csv member account has a row)."""
    w = fx.base_world()
    ident = {(r["hop_id"], r["account"]) for r in w.identity}
    for h in w.hops:
        for acct in h["member_accounts"].split(";"):
            assert (h["hop_id"], acct) in ident, (h["hop_id"], acct)
    assert len(full(run(tmp_path, w))) == 6


def ghost_world(member_accounts, with_other_hop_ghost=False):
    w = fx.base_world()
    w.paths = [fx.path("p0021", "h1")]
    w.edges = []
    w.nodes = [dict(n, path_id="p0021") for n in w.nodes if n["path_id"] == "p0001"]
    w.hops = [dict(h, member_accounts=member_accounts) if h["hop_id"] == "h1" else h for h in w.hops]
    if with_other_hop_ghost:
        w.hops = [dict(h, member_accounts="svc2;ghost") if h["hop_id"] == "h5" else h for h in w.hops]     # not on a path
    return w


def test_atk_sc20_member_account_spelled_in_another_case_is_the_same_account(tmp_path):
    """The stitcher groups identity rows by the lower-cased member account, so SVC and svc are one account."""
    assert len(full(run(tmp_path, ghost_world("SVC"))))  == 1


def test_atk_sc20_only_hops_on_a_path_are_checked_and_an_empty_member_item_is_a_null_account(tmp_path):
    assert len(full(run(tmp_path, ghost_world("svc", with_other_hop_ghost=True), "a"))) == 1     # h5 is on no path here
    assert len(full(run(tmp_path, ghost_world("svc;"), "b"))) == 1                                # empty item: NULL account
