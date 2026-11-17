"""T9.5 stability sweep, pure part (spec 05_score section 5.2 step 2, SC-23, SC-40, SC-41; decisions 066, 068 item 6).

Written from the spec and decisions. The sweep recomputes L = (1 - e^(-seq_len / lambda)) * edge_score and the score
w1 L + w2 N + w3 I from the written columns; these tests compute the same numbers by hand with `math`.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import rank_fixtures as rf  # noqa: E402
from evaluate import rank_run  # noqa: E402
from evaluate import rank_sweep as sw  # noqa: E402
from evaluate.inputs import EvalError  # noqa: E402


def pc(pid, seq=1, edge=1.0, node=0.0, ident=0.0, score=0.0, rank=1, tie=1):
    return sw.PathComponents(pid, edge, seq, node, ident, score, rank, tie)


def test_length_score_is_one_minus_exp_over_lambda_times_edge_score():
    assert sw.length_score(2, 0.8, 1.0) == pytest.approx((1 - math.exp(-2)) * 0.8)
    assert sw.length_score(1, 1.0, 1 / math.log(2)) == pytest.approx(0.5)             # the default: one transition = 0.5
    assert sw.length_score(0, 0.9, 3.0) == 0.0
    assert sw.length_score(4, 0.5, 0.5) == pytest.approx((1 - math.exp(-8)) * 0.5)


def test_recompute_is_w1_L_plus_w2_N_plus_w3_I_at_any_lambda_and_w():
    p = pc("A", seq=2, edge=0.8, node=0.5, ident=1.0)
    for lam, w in ((1.0, (0.5, 0.25, 0.25)), (5.0, (0.1, 0.2, 0.7)), (0.5, (0.0, 0.0, 1.0)), (2.0, (1.0, 0.0, 0.0))):
        want = w[0] * (1 - math.exp(-2 / lam)) * 0.8 + w[1] * 0.5 + w[2] * 1.0
        assert sw.recompute([p], lam, w)["A"] == pytest.approx(want, abs=1e-12)


def test_rank_scores_are_competition_ranks_on_the_value_rounded_to_12_decimals():
    got = {c.path_id: (c.rank, c.tie_size) for c in sw.rank_scores({"A": 0.5, "B": 0.5 + 1e-14, "C": 0.3, "D": 0.5 - 1e-11})}
    assert got["A"] == got["B"] == (1, 2)                                             # 1e-14 apart: one tie group at 12 decimals
    assert got["D"] == (3, 1) and got["C"] == (4, 1)                                  # 1e-11 apart: distinct at 12 decimals
    assert [c.path_id for c in sw.rank_scores({"B": 1.0, "A": 1.0})] == ["A", "B"]    # path_id: display order only


def test_grid_has_402_points_six_lambdas_and_the_default_point_added():
    pts = sw.grid_points(1 / math.log(2), (1 / 3, 1 / 3, 1 / 3))
    grid = [p for p in pts if p[3] == "grid"]
    dflt = [p for p in pts if p[3] == "default_w"]
    assert len(grid) == 6 * 66 and len(dflt) == 6 and len(pts) == 402
    assert [lab for lab, _ in sw.LAMBDA_GRID] == ["0.5", "1", "1/ln2", "2", "3", "5"]
    assert {round(v, 6) for _, v in sw.LAMBDA_GRID} == {0.5, 1.0, round(1 / math.log(2), 6), 2.0, 3.0, 5.0}
    for _lab, lam, w, _k in pts:
        assert lam > 0 and all(x >= -1e-12 for x in w) and sum(w) == pytest.approx(1.0)
    # the 0.1 grid lacks 1/3 (decision 068 item 6): no grid point equals the default w
    assert not any(all(abs(a - 1 / 3) < 1e-9 for a in w) for _l, _lam, w, k in pts if k == "grid")
    assert all(all(abs(a - 1 / 3) < 1e-12 for a in w) for _l, _lam, w, k in pts if k == "default_w")


def test_default_lambda_is_used_unchanged_for_the_1_over_ln2_label():
    lam = 1.4426950408889634
    pts = sw.grid_points(lam, (1 / 3, 1 / 3, 1 / 3))
    assert {p[1] for p in pts if p[0] == "1/ln2"} == {lam}


def world_trials(w):
    sc = w.score_data()
    return [sw.SweepTrial(w.trial, sw.components_of(sc.ranked), (), keyed=False)]


def test_default_point_equals_the_written_full_scores_and_ranks():
    w = rf.tie_world()
    check = sw.check_default(world_trials(w), w.lam, w.w)
    assert check["paths"] == 5 and check["rank_mismatch"] == 0 and check["max_abs_diff"] <= 1e-6


def test_default_check_refuses_a_component_that_does_not_give_the_written_score():
    w = rf.tie_world()

    def bump(rows):
        for r in rows:
            if r["variant"] == "full" and r["path_id"] == "P3":
                r["node_score"] = "0.700000"              # written score stays 0.291667
    w.tamper = bump
    with pytest.raises(EvalError) as exc:
        sw.check_default(world_trials(w), w.lam, w.w)
    assert str(exc.value).startswith("refused:")


def test_default_check_refuses_ranks_that_differ_from_the_recomputed_order():
    w = rf.RankWorld()
    w.paths = [rf.P("A", ["H1"], seq_len=2, node=1.0, ident=1.0), rf.P("B", ["H2"], node=0.5), rf.P("C", ["H3"], node=0.1)]

    def swap(rows):
        for r in rows:
            if r["variant"] == "full" and r["path_id"] in ("B", "C"):
                r["rank"] = "3" if r["path_id"] == "B" else "2"          # consistent competition columns, wrong order
    w.tamper = swap
    with pytest.raises(EvalError):
        sw.check_default(world_trials(w), w.lam, w.w)


def test_default_check_refuses_when_the_run_used_other_lambda_than_the_one_given():
    w = rf.tie_world()
    with pytest.raises(EvalError):
        sw.check_default(world_trials(w), 5.0, w.w)


def keyed_trial(w):
    res = rank_run.rank_from_inputs(w.trial, "development", w.stitch_data(), w.score_data(), w.key_data())
    return res


def test_evaluate_point_at_the_default_reproduces_the_hop_reading_metrics():
    t = keyed_trial(rf.tie_world("s04_t00")).sweep_trial
    default = sw.evaluate_point([t], "default", rf.LAM, rf.W, "default")
    assert default.top1 == 0.5 and default.mrr == pytest.approx(1 / 1.5)
    assert default.key_ranks == (("s04_t00", "K1-path", 1.5),)


def test_a_point_that_changes_the_order_changes_the_expected_rank_and_is_reported_unstable():
    t = keyed_trial(rf.tie_world("s04_t00")).sweep_trial
    default = sw.evaluate_point([t], "default", rf.LAM, rf.W, "default")
    node_only = sw.evaluate_point([t], "x", rf.LAM, (0.0, 1.0, 0.0), "grid")           # P3 (N .625) and P5 beat P1 = P2
    assert node_only.key_ranks[0][2] == 3.5
    assert sw.changed_keys(node_only, default) == ["s04_t00:K1-path"]
    ident_only = sw.evaluate_point([t], "x", rf.LAM, (0.0, 0.0, 1.0), "grid")           # P1 = P2 only exposed: tie kept
    assert ident_only.key_ranks[0][2] == 1.5 and sw.changed_keys(ident_only, default) == []


def test_lambda_changes_length_and_can_break_a_tie_through_the_recomputation():
    """P1 (seq 2) and P2 (seq 2) stay tied at any lambda; a path with seq 1 and the same other terms ranks below."""
    t = keyed_trial(rf.tie_world("s04_t00")).sweep_trial
    for lam in (0.5, 1.0, 3.0, 5.0):
        scores = sw.recompute(t.paths, lam, (1.0, 0.0, 0.0))
        assert scores["P1"] == scores["P2"] == pytest.approx((1 - math.exp(-2 / lam)) * 1.0)
        assert scores["P3"] == pytest.approx((1 - math.exp(-1 / lam)) * 0.5)


def test_s06_inputs_of_a_point_are_highest_keyed_benign_score_and_lowest_key_attack_score():
    a = keyed_trial(rf.tie_world("s04_t00")).sweep_trial
    s6 = keyed_trial(rf.benign_world("s06_t00")).sweep_trial
    p = sw.evaluate_point([a, s6], "default", rf.LAM, rf.W, "default")
    assert p.s06_max == pytest.approx(0.25) and p.attack_min == pytest.approx(2 / 3)
    un = rank_run.rank_from_inputs("s02_t01", "development", rf.unkeyed_world().stitch_data(), rf.unkeyed_world().score_data(), None)
    p2 = sw.evaluate_point([a, s6, un.sweep_trial], "default", rf.LAM, rf.W, "default")
    assert p2.s06_max == p.s06_max and p2.top1 == p.top1                               # an unkeyed trial enters no metric


def test_stable_region_counts_and_radius():
    a = keyed_trial(rf.tie_world("s04_t00")).sweep_trial
    default, points, check = sw.run_sweep([a], rf.LAM, rf.W)
    assert len(points) == 402 and check["rank_mismatch"] == 0
    region = sw.stable_region(points, default)
    assert [r["lambda"] for r in region] == ["0.5", "1", "1/ln2", "2", "3", "5"]
    for r in region:
        assert r["grid_points"] == 66 and 0 < r["stable_points"] < 66
        assert r["default_w_stable"] is True
        # every grid point strictly closer to the default than the radius is stable
        if r["stable_radius"] is not None:
            for p in points:
                if p.lam_label == r["lambda"] and p.kind == "grid":
                    d = max(abs(x - y) for x, y in zip(p.w, default.w))
                    if d < r["stable_radius"] - 1e-12:
                        assert sw.changed_keys(p, default) == []


def test_run_sweep_never_modifies_its_inputs_or_the_frozen_parameters():
    from evaluate import rank_sweep
    a = keyed_trial(rf.tie_world("s04_t00")).sweep_trial
    before = (a, rf.LAM, rf.W)
    sw.run_sweep([a], rf.LAM, rf.W)
    assert before == (a, rf.LAM, rf.W)
    assert not hasattr(rank_sweep, "write_params")


def test_sweep_refuses_without_a_keyed_trial_and_with_mixed_parameters():
    un = rank_run.rank_from_inputs("s02_t01", "development", rf.unkeyed_world().stitch_data(), rf.unkeyed_world().score_data(), None)
    with pytest.raises(EvalError):
        rank_run.sweep_of([un])
    a = keyed_trial(rf.tie_world("s04_t00"))
    other = rf.tie_world("s02_t00")
    other.lam, other.w = 2.0, (0.5, 0.25, 0.25)
    b = keyed_trial(other)
    with pytest.raises(EvalError) as exc:
        rank_run.sweep_of([a, b])
    assert "different parameters" in str(exc.value)
