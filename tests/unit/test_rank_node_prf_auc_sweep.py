"""Spec 06_evaluate section 10 (addendum D), pure / in-memory part: node P/R/F1/FNR (NP-01..05), pooled and per-trial
ROC-AUC (AUC-01, AUC-03) and the sweep's per-key MRR column (SW-01).

Written from the spec and decisions 065, 068, 070, not from the code. Every expected number is computed by hand in the
comment above it. Worlds are `rank_fixtures.RankWorld`s assembled by `results_fixtures.assemble` (pure assembly of
already-checked inputs); only development trial ids appear. Nothing is written under the real `out/`.

Components at the frozen parameters (lambda = 1/ln 2, w = 1/3 each): POS (seq_len 2, edge 1, N 0.25, I 1) scores full
0.666667, b1 0.5, b2 0.25; ZERO scores 0 everywhere. Key node set of `key1()` = {T_H1, a1, a2} (3 nodes).
"""
from __future__ import annotations

import csv
import dataclasses
import io
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import rank_fixtures as rf  # noqa: E402
import results_fixtures as R  # noqa: E402
from evaluate import __main__ as em  # noqa: E402
from evaluate import rank_metrics as rm  # noqa: E402
from evaluate import rank_report as rr  # noqa: E402
from evaluate import rank_run  # noqa: E402
from evaluate.inputs import EvalError  # noqa: E402

POS = R.POS
ZERO = R.ZERO


def prf(t) -> dict:
    return {p.variant: p for p in t.node_prf}


def assert_prf(p, covered, held, P, Rr, F1, FNR):
    assert p.covered == pytest.approx(covered, abs=1e-9)
    assert p.held == pytest.approx(held, abs=1e-9)
    for got, want in ((p.precision, P), (p.recall, Rr), (p.f1, F1), (p.fnr, FNR)):
        if want is None:
            assert got is None
        else:
            assert got == pytest.approx(want, abs=1e-9)


# ---------------------------------------------------------------- worlds
def world_distinct(trial: str = "s02_t00", b0=None) -> rf.RankWorld:
    """k = 1. P1 = {T_H1, a1, x1} and P2 = {T_H1, y1, y2, y3} score POS (full 0.666667, b1 0.5, b2 0.25: a 2-path tie
    at rank 1 for full and b1); P3 = {z1} has N 0.5 only (full 0.166667, b1 0.25, b2 0.5, so b2 ranks P3 alone first).
    P1 holds one labelled unit (a1) so the labelled budget differs from the all-node budget."""
    return R.one_key(trial, [
        rf.P("P1", ["H1"], nodes=["T_H1", "a1", "x1"], units=[("k1", ["a1"], 1)], **POS),
        rf.P("P2", ["H2"], nodes=["T_H1", "y1", "y2", "y3"], **POS),
        rf.P("P3", ["H3"], nodes=["z1"], seq_len=0, edge=0.0, node=0.5, ident=0.0)],
        b0=b0 if b0 is not None else [("u1", 4, ["a1", "a2"]), ("u2", 3, ["T_H1", "q1"])])


def world_tie3(trial: str) -> rf.RankWorld:
    """k = 1, all three paths POS: one tie group of 3 at rank 1, 1 slot. P1 {T_H1,a1,x1}, P2 {T_H1,y1,y2,y3}, P3 {z1}."""
    return R.one_key(trial, [
        rf.P("P1", ["H1"], nodes=["T_H1", "a1", "x1"], **POS),
        rf.P("P2", ["H2"], nodes=["T_H1", "y1", "y2", "y3"], **POS),
        rf.P("P3", ["H3"], nodes=["z1"], **POS)],
        b0=[("u1", 4, ["a1", "a2"]), ("u2", 3, ["T_H1", "q1"])])


def world_empty(trial: str) -> rf.RankWorld:
    """The top-1 path holds no `context` = 0 node at all: expected nodes held = 0 (P and F1 undefined)."""
    return R.one_key(trial, [rf.P("P1", ["H1"], nodes=[], **POS), rf.P("P2", ["H2"], nodes=["q1"], **ZERO)],
                     b0=[("u1", 4, ["a1"])])


# ================================================================================================ NP-01 / NP-02
def test_np01_ties_at_the_cut_are_read_by_expectation_all_three_paths_tied():
    """Hand: each of P1, P2, P3 is the top-1 with probability 1/3. P(node held): T_H1 (P1, P2) 2/3; a1, x1, y1, y2, y3,
    z1 1/3 each. Expected nodes held = 2/3 + 6/3 = 8/3. Covered key nodes = T_H1 2/3 + a1 1/3 + a2 0 = 1.
    R = 1/3, P = 1 / (8/3) = 3/8, F1 = 2PR/(P+R) = 6/17, FNR = 2/3. b1 and b2 tie the same way (all scores equal)."""
    t = R.assemble(world_tie3("s04_t00"))
    p = prf(t)
    assert set(p) == {"full", "b1", "b2", "b0"} and all(x.k == 1 and x.key_nodes == 3 for x in p.values())
    for v in ("full", "b1", "b2"):
        assert_prf(p[v], 1.0, 8 / 3, 3 / 8, 1 / 3, 6 / 17, 2 / 3)


def test_np01_a_clear_top_k_and_a_tie_at_the_cut_with_different_variants():
    """world_distinct, full and b1: P1 = P2 tie at rank 1 (2 paths, 1 slot), P3 at rank 3. Each of P1, P2 is the top-1
    w.p. 1/2: T_H1 1 (both hold it); a1, x1 1/2; y1, y2, y3 1/2. Held = 1 + 0.5 * 5 = 3.5; covered = 1 + 0.5 = 1.5.
    R = 1.5/3 = 0.5, P = 1.5/3.5 = 3/7, F1 = 6/13, FNR = 0.5.
    b2: P3 is alone at rank 1 (N 0.5): held 1, covered 0 -> P = R = 0, F1 = 0, FNR = 1."""
    p = prf(R.assemble(world_distinct()))
    for v in ("full", "b1"):
        assert_prf(p[v], 1.5, 3.5, 3 / 7, 0.5, 6 / 13, 0.5)
    assert_prf(p["b2"], 0.0, 1.0, 0.0, 0.0, 0.0, 1.0)


def test_np01_f1_is_zero_not_undefined_when_precision_and_recall_are_both_zero():
    p = prf(R.assemble(world_distinct()))["b2"]
    assert p.precision == 0.0 and p.recall == 0.0
    assert p.f1 == 0.0 and p.f1 is not None
    assert p.fnr == 1.0


def test_np01_k_is_the_number_of_key_attack_paths_and_the_top_k_may_hold_a_cut_group():
    """two_key_world: k = 2, six key nodes. full: P1 0.75 (rank 1), P2 0.333333 (rank 2) are above the cut: they hold
    T_H1, a1, a2, T_H2, c1, c2: covered 6, held 6, P = R = 1.  b2 = N: P1 = P2 = P3 = 0.5 tie (3 paths, 2 slots). Each
    path is in the top 2 w.p. 2/3; T_H2, c1, c2 are held by P2 and P3: 1 - C(1,2)/C(3,2) = 1. Held = 3 * 2/3 + 3 = 5,
    covered = 5 (all six key nodes: 2 + 3 = 5), R = 5/6, P = 1, F1 = 10/11."""
    t = R.assemble(R.two_key_world())
    p = prf(t)
    assert all(x.k == 2 and x.key_nodes == 6 for x in p.values())
    assert_prf(p["full"], 6.0, 6.0, 1.0, 1.0, 1.0, 0.0)
    assert_prf(p["b2"], 5.0, 5.0, 1.0, 5 / 6, 10 / 11, 1 / 6)


def test_np02_b0_at_the_all_node_budget_of_full_topk():
    """world_tie3: budget = full's expected nodes held = 8/3. b0 walks units by rank: u1 (level 4) holds {a1, a2}, both
    key nodes: held 2, covered 2. u2 (level 3) holds {T_H1, q1}: only 2/3 of a node of budget is left, so each of its two
    nodes gets 1/3: covered + 1/3 (T_H1 is a key node) = 7/3, held 8/3. R = 7/9, P = 7/8, F1 = 14/17, FNR = 2/9."""
    t = R.assemble(world_tie3("s04_t00"))
    p = prf(t)["b0"]
    assert_prf(p, 7 / 3, 8 / 3, 7 / 8, 7 / 9, 14 / 17, 2 / 9)
    assert p.held == pytest.approx(prf(t)["full"].held)                      # the same node budget as full's top-k


def test_np02_np05_b0_budget_is_the_all_node_budget_not_the_labelled_one():
    """world_distinct: full holds 3.5 context-0 nodes, but only a1 is a labelled node of its paths (the labelled budget is
    0.5). b0 is read at 3.5 (NP-05). u1 {a1, a2}: held 2, covered 2; u2 {T_H1, q1}: 1.5 left, 0.75 per node, covered
    2.75, held 3.5. R = 2.75/3, P = 2.75/3.5 = 11/14, F1 = 11/13, FNR = 1/12."""
    t = R.assemble(world_distinct())
    p = prf(t)["b0"]
    assert_prf(p, 2.75, 3.5, 11 / 14, 2.75 / 3, 11 / 13, 1 / 12)
    assert t.b0 is not None and t.b0.budget == pytest.approx(3.5) and t.b0.budget_labelled != pytest.approx(3.5)


def test_np02_b0_holding_fewer_nodes_than_the_budget_is_measured_on_what_it_holds():
    """b0 has only u1 = {a1}: it cannot fill the budget 3.5. Held = 1 (not 3.5), covered 1: P = 1, R = 1/3, F1 = 1/2,
    FNR = 2/3."""
    t = R.assemble(world_distinct(b0=[("u1", 4, ["a1"])]))
    p = prf(t)["b0"]
    assert_prf(p, 1.0, 1.0, 1.0, 1 / 3, 0.5, 2 / 3)
    assert p.held < prf(t)["full"].held


def test_np01_precision_and_f1_are_undefined_not_zero_when_expected_nodes_held_is_zero():
    """world_empty: full's top-1 holds no node. Held 0 -> P and F1 undefined (None); R = 0, FNR = 1. b0's budget is 0,
    so b0 holds nothing and has the same undefined P / F1."""
    p = prf(R.assemble(world_empty("s03_t00")))
    for v in ("full", "b1", "b2", "b0"):
        assert p[v].held == 0.0 and p[v].covered == 0.0
        assert p[v].precision is None and p[v].f1 is None, v
        assert p[v].recall == 0.0 and p[v].fnr == 1.0, v


def test_np01_st05_copies_are_merged_so_a_copy_is_not_counted_as_another_node():
    """The stitch hop H1 holds one 4624 as T_H1|T_H1c (representative | copy). P1 lists both T_H1 and T_H1c as nodes: one
    distinct node after the merge, so held = 3 (T_H1, a1, a2), covered 3, P = R = F1 = 1."""
    w = R.one_key("s02_t00", [rf.P("P1", ["H1"], nodes=["T_H1", "T_H1c", "a1", "a2"], **POS)])
    w.members = {"H1": [("T_H1|T_H1c", 0x100)]}
    p = prf(R.assemble(w))["full"]
    assert_prf(p, 3.0, 3.0, 1.0, 1.0, 1.0, 0.0)


def test_np01_covered_uids_are_the_key_nodes_held_with_a_share_above_zero():
    p = prf(R.assemble(world_distinct()))["full"]
    assert set(p.covered_uids) == {"T_H1", "a1"}                              # a2 is held by no top-k path


def test_np03_s06_and_unkeyed_trials_have_no_node_rows():
    assert R.benign_trial().node_prf == () and R.unkeyed_s06().node_prf == ()
    assert rr.trial_rows(R.benign_trial()) and not [r for r in rr.trial_rows(R.benign_trial())
                                                    if r["row_kind"] in ("node_prf", "auc_trial")]


# ================================================================================================ NP-03 macro means
def three_trials():
    """s02_t00 = world_distinct (full P 3/7, R 1/2, F1 6/13, FNR 1/2); s02_t01 = world_tie3 (P 3/8, R 1/3, F1 6/17, FNR 2/3);
    s03_t00 = world_empty (P, F1 undefined; R 0, FNR 1); plus a keyed S06 and an unkeyed trial that must not enter."""
    return [R.assemble(world_distinct("s02_t00")), R.assemble(world_tie3("s02_t01")),
            R.assemble(world_empty("s03_t00")), R.benign_trial("s06_t00"), R.unkeyed_s06("s06_t01")]


def total(rows, kind, variant, scenario=""):
    (r,) = [x for x in rows if x["row_kind"] == kind and x["variant"] == variant and x["scenario"] == scenario]
    return r


def test_np03_macro_mean_over_defined_trials_only_overall():
    rows = rr.total_rows(three_trials(), "development")
    r = total(rows, "node_prf", "full")
    # P: (3/7 + 3/8) / 2 over the 2 trials where it is defined; R: (1/2 + 1/3 + 0) / 3; F1: (6/13 + 6/17) / 2; FNR: (1/2 + 2/3 + 1) / 3
    assert r["attack_trials"] == "3"
    assert float(r["node_precision_mean"]) == pytest.approx((3 / 7 + 3 / 8) / 2, abs=1e-6)
    assert float(r["node_recall_mean"]) == pytest.approx((1 / 2 + 1 / 3 + 0) / 3, abs=1e-6)
    assert float(r["node_f1_mean"]) == pytest.approx((6 / 13 + 6 / 17) / 2, abs=1e-6)
    assert float(r["node_fnr_mean"]) == pytest.approx((1 / 2 + 2 / 3 + 1) / 3, abs=1e-6)
    assert (r["node_precision_trials"], r["node_recall_trials"], r["node_f1_trials"]) == ("2", "3", "2")
    assert r["scope_trial_ids"].split(";") == ["s02_t00", "s02_t01", "s03_t00"]           # no S06, no unkeyed trial


def test_np03_per_scenario_mean_and_a_scenario_whose_p_is_undefined_has_an_empty_mean():
    rows = rr.total_rows(three_trials(), "development")
    s02 = total(rows, "node_prf_scenario", "full", "s02")
    assert s02["attack_trials"] == "2"
    assert float(s02["node_precision_mean"]) == pytest.approx((3 / 7 + 3 / 8) / 2, abs=1e-6)
    assert float(s02["node_recall_mean"]) == pytest.approx((1 / 2 + 1 / 3) / 2, abs=1e-6)
    assert float(s02["node_f1_mean"]) == pytest.approx((6 / 13 + 6 / 17) / 2, abs=1e-6)
    assert float(s02["node_fnr_mean"]) == pytest.approx((1 / 2 + 2 / 3) / 2, abs=1e-6)
    s03 = total(rows, "node_prf_scenario", "full", "s03")
    assert s03["node_precision_mean"] == "" and s03["node_f1_mean"] == ""                   # undefined, not 0
    assert (s03["node_precision_trials"], s03["node_f1_trials"], s03["node_recall_trials"]) == ("0", "0", "1")
    assert float(s03["node_recall_mean"]) == 0.0 and float(s03["node_fnr_mean"]) == 1.0
    assert {r["scenario"] for r in rows if r["row_kind"] == "node_prf_scenario"} == {"s02", "s03"}   # S06 has no row


def test_np03_every_variant_has_an_overall_row_and_a_row_per_attack_scenario():
    rows = rr.total_rows(three_trials(), "development")
    for kind, n in (("node_prf", 4), ("node_prf_scenario", 8)):
        assert len([r for r in rows if r["row_kind"] == kind]) == n, kind
    assert {r["variant"] for r in rows if r["row_kind"] == "node_prf"} == {"full", "b1", "b2", "b0"}


def test_np03_the_new_rows_carry_no_threshold_comparator_or_verdict_columns():
    cols = set(rr.TOTAL_COLUMNS)
    assert not ({"verdict", "dev_check", "comparator", "threshold"} & cols)


# ================================================================================================ NP-04
def test_np04_a_difference_between_full_recall_and_the_h4_full_recall_refuses():
    t = R.assemble(world_distinct())
    assert t.b0 is not None
    rank_run.check_np04(t.trial_id, t.node_prf, t.b0)                         # consistent: no refusal
    bad = tuple(dataclasses.replace(p, recall=0.75, fnr=0.25) if p.variant == "full" else p for p in t.node_prf)
    with pytest.raises(EvalError) as exc:
        rank_run.check_np04(t.trial_id, bad, t.b0)
    assert str(exc.value).startswith("refused:") and "NP-04" in str(exc.value) and t.trial_id in str(exc.value)


def test_np04_a_run_whose_node_p_r_code_disagrees_with_h4_is_refused_and_writes_nothing(tmp_path, monkeypatch, capsys):
    root = tmp_path / "r"
    R.write_repo_with(root, world_distinct("s02_t00"))
    before = rf.snapshot(root)
    real = rm.topk_node_coverage

    def skewed(candidates, k, nodes, key_nodes):
        covered, held, uids = real(candidates, k, nodes, key_nodes)
        return covered + 0.25, held, uids                                      # the two codes now read different nodes

    monkeypatch.setattr(rm, "topk_node_coverage", skewed)
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 2
    assert capsys.readouterr().err.startswith("refused:")
    assert rf.snapshot(root) == before                                         # a refusal leaves the disk untouched


# ================================================================================================ rank.csv rows
def rank_csv_rows(trial) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(rr.trial_csv(trial), newline="")))


def test_np_rank_csv_has_four_node_prf_rows_per_attack_trial_with_six_decimals():
    rows = [r for r in rank_csv_rows(R.assemble(world_distinct())) if r["row_kind"] == "node_prf"]
    assert [r["variant"] for r in rows] == ["full", "b1", "b2", "b0"]
    full, b1, b2, b0 = rows
    assert (full["expected_key_nodes_covered"], full["expected_nodes_held"], full["node_precision"],
            full["node_recall"], full["node_f1"], full["node_fnr"]) == (
        "1.500000", "3.500000", "0.428571", "0.500000", "0.461538", "0.500000")
    assert (b2["node_precision"], b2["node_recall"], b2["node_f1"], b2["node_fnr"]) == (
        "0.000000", "0.000000", "0.000000", "1.000000")
    assert (b0["budget_nodes"], b0["node_precision"], b0["node_recall"], b0["node_f1"], b0["node_fnr"]) == (
        "3.500000", "0.785714", "0.916667", "0.846154", "0.083333")
    assert all(r["k"] == "1" and r["key_node_count"] == "3" for r in rows)


def test_np_rank_csv_leaves_precision_and_f1_empty_when_undefined():
    rows = [r for r in rank_csv_rows(R.assemble(world_empty("s03_t00"))) if r["row_kind"] == "node_prf"]
    for r in rows:
        assert r["node_precision"] == "" and r["node_f1"] == "", r["variant"]
        assert r["node_recall"] == "0.000000" and r["node_fnr"] == "1.000000"


def test_np_rank_csv_s06_and_unkeyed_trials_have_no_node_prf_or_auc_trial_rows():
    for t in (R.benign_trial(), R.unkeyed_s06()):
        assert not [r for r in rank_csv_rows(t) if r["row_kind"] in ("node_prf", "auc_trial")]


# ================================================================================================ AUC-01 / AUC-03
def test_auc_mann_whitney_with_ties_counted_half():
    """positives {3, 2}, negatives {2, 1, 1}: 3 beats all three (3), 2 ties the 2 (0.5) and beats the two 1s (2): 5.5 / 6."""
    assert rm.mann_whitney_auc([3.0, 2.0], [2.0, 1.0, 1.0]) == pytest.approx(5.5 / 6, abs=1e-12)
    assert rm.mann_whitney_auc([1.0], [1.0]) == 0.5 and rm.mann_whitney_auc([2.0], [1.0]) == 1.0
    assert rm.mann_whitney_auc([1.0], [2.0]) == 0.0


def test_auc_scores_are_compared_at_12_decimals():
    assert rm.mann_whitney_auc([0.5 + 1e-14], [0.5]) == 0.5                    # equal at 12 decimals: a tie
    assert rm.mann_whitney_auc([0.5 + 1e-11], [0.5]) == 1.0                    # 1e-11 apart: a win
    assert rm.mann_whitney_auc([0.5 - 4e-13], [0.5]) == 0.5                    # rounds to the same 12-decimal value


def test_auc_undefined_when_a_side_is_empty():
    assert rm.mann_whitney_auc([], [1.0]) is None and rm.mann_whitney_auc([1.0], []) is None
    assert rm.mann_whitney_auc([], []) is None


def auc_world(trial: str = "s02_t00") -> rf.RankWorld:
    """Key nodes {T_H1, a1, a2}. P1 = the key set (Jaccard 1), P2 = {T_H1, a1, x} (2/4 = 0.5, a match), P3 = {T_H1, y}
    (1/4, no), P4 = {q}. Positives P1, P2; negatives P3, P4.  full: P1 0.666667, P2 0.25, P3 0.666667, P4 0.
    b1 (L+N)/2: 0.5, 0.375, 0.5, 0.  b2 = N: 0.25, 0.25, 0.25, 0."""
    return R.one_key(trial, [
        rf.P("P1", ["H1"], nodes=["T_H1", "a1", "a2"], **POS),
        rf.P("P2", ["H2"], nodes=["T_H1", "a1", "x"], seq_len=1, edge=1.0, node=0.25, ident=0.0),
        rf.P("P3", ["H3"], nodes=["T_H1", "y"], **POS),
        rf.P("P4", ["H4"], nodes=["q"], **ZERO)])


def auc_row(t, variant):
    (r,) = [x for x in rank_csv_rows(t) if x["row_kind"] == "auc_trial" and x["variant"] == variant]
    return r


def test_auc_per_trial_by_hand_full_b1_b2():
    """full: P1 vs {P3 tie .5, P4 1} = 1.5; P2 (0.25) vs {P3 0, P4 1} = 1: 2.5 / 4 = 0.625. b1: P1 (.5) vs {P3 .5 tie, P4} =
    1.5; P2 (.375) vs {.5 -> 0, 0 -> 1} = 1: 0.625. b2: each 0.25 vs {0.25 tie .5, 0 -> 1} = 1.5, twice: 3 / 4 = 0.75."""
    t = R.assemble(auc_world())
    for variant, auc in (("full", "0.625000"), ("b1", "0.625000"), ("b2", "0.750000")):
        r = auc_row(t, variant)
        assert (r["auc"], r["auc_n_pos"], r["auc_n_neg"], r["auc_chance"]) == (auc, "2", "2", "0.500000"), variant
        assert r["match_reading"] == "node"
    assert {p for p in auc_row(t, "full")["matched_path_ids"].split(";")} == {"P1", "P2"}


def test_auc_per_trial_is_undefined_when_n_pos_is_zero():
    """No candidate matches the key (node reading): n_pos = 0, AUC empty. Also the hop-only world: the hop reading matches P1,
    the node reading does not, and AUC uses the node reading."""
    w = R.one_key("s03_t00", [rf.P("P1", ["H1"], nodes=["u1"], **POS), rf.P("P2", ["H2"], nodes=["u2"], **ZERO)])
    for t in (R.assemble(w), R.assemble(R.hop_only_world())):
        for v in ("full", "b1", "b2"):
            r = auc_row(t, v)
            assert r["auc"] == "" and r["auc_n_pos"] == "0" and r["auc_n_neg"] == "2", (t.trial_id, v)


def test_auc_per_trial_is_undefined_when_n_neg_is_zero():
    w = R.one_key("s04_t00", [rf.P("P1", ["H1"], nodes=["T_H1", "a1", "a2"], **POS)])
    for v in ("full", "b1", "b2"):
        r = auc_row(R.assemble(w), v)
        assert r["auc"] == "" and r["auc_n_pos"] == "1" and r["auc_n_neg"] == "0", v


def pooled_results():
    """attack trial (auc_world), keyed S06 (B1: full 0.25, b1 0.375, b2 0.5; B2 0) and an unkeyed S06 trial that must be
    left out."""
    return [R.assemble(auc_world("s02_t00")), R.benign_trial("s06_t00"), R.unkeyed_s06("s06_t01")]


def test_auc_pooled_includes_keyed_s06_negatives_and_leaves_unkeyed_trials_out():
    """full: positives {0.666667, 0.25}; negatives {P3 0.666667, P4 0, B1 0.25, B2 0}. 0.666667: tie .5 + 3 wins = 3.5;
    0.25: 0 + 1 + .5 + 1 = 2.5; (3.5 + 2.5) / 8 = 0.75, n_pos 2, n_neg 4. b1: pos {.5, .375}, neg {.5, 0, .375, 0}:
    (3.5 + 2.5) / 8 = 0.75. b2: pos {.25, .25}, neg {.25, 0, .5, 0}: 2.5 each: 5 / 8 = 0.625."""
    res = pooled_results()
    want = {"full": 0.75, "b1": 0.75, "b2": 0.625}
    for v, auc in want.items():
        got = rr.auc_values(res, v)
        assert got["auc"] == pytest.approx(auc, abs=1e-12), v
        assert (got["auc_n_pos"], got["auc_n_neg"], got["auc_trials"]) == (2, 4, 2), v
        assert "s06_t01" not in got["trial_ids"] and "s06_t00" in got["trial_ids"]


def test_auc_pooled_rows_in_rank_totals_have_counts_chance_and_no_verdict():
    rows = rr.total_rows(pooled_results(), "development")
    pooled = [r for r in rows if r["row_kind"] == "auc_pooled"]
    assert [r["variant"] for r in pooled] == ["full", "b1", "b2"]               # b0 ranks units, not paths: left out
    for r, auc in zip(pooled, ("0.750000", "0.750000", "0.625000")):
        assert (r["auc"], r["auc_n_pos"], r["auc_n_neg"], r["auc_chance"], r["auc_trials"]) == (auc, "2", "4", "0.500000", "2")
        assert r["status_note"].startswith("DEVELOPMENT")


def test_auc_pooled_is_undefined_when_there_is_no_positive():
    w = R.one_key("s03_t00", [rf.P("P1", ["H1"], nodes=["u1"], **POS), rf.P("P2", ["H2"], nodes=["u2"], **ZERO)])
    got = rr.auc_values([R.assemble(w), R.benign_trial("s06_t00")], "full")
    assert got["auc"] is None and got["auc_n_pos"] == 0 and got["auc_n_neg"] == 4
    rows = rr.total_rows([R.assemble(w), R.benign_trial("s06_t00")], "development")
    assert [r["auc"] for r in rows if r["row_kind"] == "auc_pooled"] == ["", "", ""]


# ================================================================================================ SW-01
def test_sw01_every_sweep_point_carries_mrr_per_key_expected():
    """two_key_world, default point (hop reading): K1 -> P1 at rank 1 (RR 1), K2 -> P2 at rank 2 (full 0.333333 below P1
    0.75; RR 0.5): per-key MRR = 0.75, per-trial MRR (first match of any key path) = 1.0. The node-only point (0, 1, 0):
    P1 = P2 = P3 tie at rank 1 (N 0.5 each, 3 paths), one hop match per key path: expected rank (3 + 1) / (1 + 1) = 2,
    RR 0.5 for both key paths: per-key MRR 0.5."""
    t = R.assemble(R.two_key_world())
    default, points, _check = rank_run.sweep_of([t])
    rows = rr.sweep_rows(default, points, "development")
    assert "mrr_per_key_expected" in rr.SWEEP_COLUMNS and rr.SWEEP_COLUMNS[-1] == "mrr_per_key_expected"
    assert len(rows) == 1 + 402 and all(r["mrr_per_key_expected"] != "" for r in rows)
    assert all(0.0 <= float(r["mrr_per_key_expected"]) <= 1.0 for r in rows)
    assert (rows[0]["point_kind"], rows[0]["mrr_per_key_expected"], rows[0]["mrr_expected"]) == ("default", "0.750000", "1.000000")
    node_only = [r for r in rows if r["point_kind"] == "grid" and (r["w1"], r["w2"], r["w3"]) == ("0.000000", "1.000000", "0.000000")]
    assert len(node_only) == 6 and {r["mrr_per_key_expected"] for r in node_only} == {"0.500000"}
