"""T9 score stage: the gaps listed after the first review and the attacker's open cases (spec 05_score SC-21, SC-21b,
SC-52, SC-54, section 3.5 stats; decision 067 items 4, 5; review cases ATK-SC-19, ATK-SC-20).

Written from the spec and decisions, not from the code. Synthetic (fast); the real-data stats check is in
`test_score_real.py`. The `xfail(strict=True)` tests are cases the current code is expected to fail: they must flip to
passing when the fix lands (a strict xfail that passes is a failure, so the marker has to be removed then).
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


def test_sibling_hops_without_a_chain_edge_are_joined_by_a_hop_chain_step(tmp_path):
    res = run(tmp_path, sibling_world())
    steps = [s for s in rows(res, "path_steps.csv") if s["path_id"] == "p0010"]
    assert [s["basis"] for s in steps] == ["direct", "direct", "hop_chain", "indirect"]   # h1: 2 direct; boundary; h2: 1
    boundary = steps[2]
    assert (boundary["from_technique"], boundary["to_technique"]) == ("T1569.002", "T1078")
    assert float(boundary["score_e"]) == pytest.approx(1.0) and float(boundary["tactic_score"]) == pytest.approx(1.0)
    assert full(res)["p0010"]["technique_sequence"] == "T1021.002>T1570>T1569.002>T1078>T1021.006"


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


@pytest.mark.xfail(strict=True, reason="ATK-SC-19: a flagged rejecting read of account B must not lower identity_low of a "
                                       "hop that account A (unflagged, value 1) already makes coherent")
def test_atk_sc19_identity_low_is_one_when_an_unflagged_account_already_gives_the_hop_value_one(tmp_path):
    r = full(run(tmp_path, two_account_world()))["p0020"]
    assert float(r["identity_low"]) == 1.0
    assert float(r["identity_low"]) <= float(r["identity_coherence"]) <= float(r["identity_high"])


@pytest.mark.xfail(strict=True, reason="ATK-SC-20: a hops.csv member account without a hop_identity.csv row must be refused "
                                       "(it would silently leave the crossing and the denominator)")
def test_atk_sc20_score_refuses_a_member_account_with_no_identity_row(tmp_path, capsys):
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
