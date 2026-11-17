"""T9 score stage: NodeScore units (SC-30..33, SCT-30..34; decision 063), the score and the ranking (SC-40, SC-41, SCT-40..42;
decisions 018, 021, 065) and the variants of spec 3.6.

Written from the spec, not from the implementation.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from score import baselines as bl  # noqa: E402
from score import nodes as nd  # noqa: E402
from score import params as sp  # noqa: E402
from score import rank as rk  # noqa: E402
from score.errors import ScoreError  # noqa: E402
from score_fixtures import event, node  # noqa: E402

P = sp.ScoreParams()


def keys_of(*events):
    return nd.count_key_map(events)


# ------------------------------------------------------------------------------------------------ NodeScore units
def test_one_action_logged_twice_is_one_unit_with_both_uids():
    rows = [node("p", "h1", "e1", tech="T1569.002", level=1), node("p", "h1", "e2", tech="T1569.002", level=1)]
    keys = keys_of(event("e1", "K", 1), event("e2", "K", 1))
    units = nd.node_units(rows, keys)
    assert len(units) == 1 and units[0].count_key == "K" and units[0].event_uids == ("e1", "e2")
    assert nd.node_score(units) == pytest.approx(1 / 4)


def test_unit_level_is_the_maximum_over_its_nodes():
    rows = [node("p", "h1", "e1", tech="T1569.002", level=1), node("p", "h1", "e2", tech="T1569.002", level=3)]
    units = nd.node_units(rows, keys_of(event("e1", "K", 1), event("e2", "K", 3)))
    assert [u.level_value for u in units] == [3]
    assert nd.node_score(units) == pytest.approx(3 / 4)


def test_unit_level_is_the_maximum_over_rules_of_one_node_row():
    rows = [node("p", "h1", "e1", tech="T1003.001", level=3)]       # node row already holds the highest rule level
    units = nd.node_units(rows, keys_of(event("e1", "K", 3), event("e1", "K", 2)), contexts=("0",))
    assert units[0].level_value == 3


def test_node_score_is_mean_unit_level_over_four():
    keys = keys_of(event("a", "ka", 3), event("b", "kb", 2), event("c", "kc", 4), event("d", "kd", 0))
    rows = [node("p", "h", u, tech="T1078", level=l) for u, l in (("a", 3), ("b", 2))]
    assert nd.node_score(nd.node_units(rows, keys)) == pytest.approx(0.625)
    rows = [node("p", "h", "c", tech="T1078", level=4)]
    assert nd.node_score(nd.node_units(rows, keys)) == pytest.approx(1.0)
    rows = [node("p", "h", "d", tech="T1078", level=0)]            # informational 0: a unit, scoring 0
    us = nd.node_units(rows, keys)
    assert len(us) == 1 and nd.node_score(us) == 0.0


def test_a_path_with_no_labelled_unit_scores_zero_with_no_units():
    rows = [node("p", "h", "x", labelled="0"), node("p", "h", "y", labelled="0")]
    units = nd.node_units(rows, {})
    assert units == [] and nd.node_score(units) == 0.0
    assert nd.node_units([], {}) == [] and nd.node_score([]) == 0.0


def test_context_one_is_excluded_from_node_score_and_included_in_ctx1():
    rows = [node("p", "h", "a", tech="T1021.002", level=1), node("p", "h", "b", tech="T1570", level=1),
            node("p", "h", "d", tech="T1003.001", level=3, ctx="1")]
    keys = keys_of(event("a", "ka", 1), event("b", "kb", 1), event("d", "kd", 3))
    assert nd.node_score(nd.node_units(rows, keys)) == pytest.approx(0.25)
    assert nd.node_score(nd.node_units(rows, keys, ("0", "1"))) == pytest.approx((1 + 1 + 3) / 3 / 4)


def test_units_are_sorted_by_count_key_and_carry_hops_and_techniques():
    rows = [node("p", "h2", "b", tech="T1078", level=3), node("p", "h1", "a", tech="T1021.006", level=2)]
    units = nd.node_units(rows, keys_of(event("a", "zz", 2), event("b", "aa", 3)))
    assert [u.count_key for u in units] == ["aa", "zz"]
    assert units[0].hop_ids == ("h2",) and units[0].techniques == ("T1078",)


def test_node_score_refusals():
    with pytest.raises(ScoreError):                                 # one uid, two keys (LB-11)
        nd.count_key_map([event("a", "k1", 1), event("a", "k2", 1)])
    with pytest.raises(ScoreError):                                 # labelled node without an event_labels row
        nd.node_units([node("p", "h", "ghost", tech="T1078", level=1)], {})
    with pytest.raises(ScoreError):                                 # level outside 0..4
        nd.node_units([node("p", "h", "a", tech="T1078", level=7)], keys_of(event("a", "k", 1)))
    with pytest.raises(ScoreError):
        nd.node_units([node("p", "h", "a", tech="T1078", level="")], keys_of(event("a", "k", 1)))


# ------------------------------------------------------------------------------------------------ SC-40 / SC-41
def test_combine_is_the_fsum_of_weighted_components():
    w, c = (0.5, 0.3, 0.2), (0.1, 0.7, 0.3)
    assert rk.combine(w, c) == math.fsum([0.5 * 0.1, 0.3 * 0.7, 0.2 * 0.3])
    assert rk.combine(P_weights(), (0.75, 0.25, 1.0)) == pytest.approx(2 / 3)
    with pytest.raises(ValueError):
        rk.combine((1.0,), (1.0, 2.0))


def P_weights():
    return (P.w1, P.w2, P.w3)


def test_score_is_in_unit_interval_for_unit_components():
    for L in (0.0, 0.3, 1.0):
        for N in (0.0, 0.5, 1.0):
            for I in (0.0, 0.5, 1.0):
                assert 0.0 <= bl.variant_score("full", P, L, N, I) <= 1.0 + 1e-12


def test_equal_components_give_bit_equal_scores():
    a = bl.variant_score("full", P, 0.75, 0.25, 1.0)
    b = bl.variant_score("full", P, 0.75, 0.25, 1.0)
    assert a == b


@pytest.mark.parametrize("variant,expect", [("full", (1 / 3, 1 / 3, 1 / 3)), ("b1", (0.5, 0.5, 0.0)),
                                            ("b2", (0.0, 1.0, 0.0))])
def test_variant_weights(variant, expect):
    assert bl.variant_weights(variant, P) == pytest.approx(expect)


def test_variant_scores_on_hand_numbers():
    L, N, I = 0.25, 0.625, 0.0
    assert bl.variant_score("full", P, L, N, I) == pytest.approx((0.25 + 0.625) / 3)
    assert bl.variant_score("b1", P, L, N, I) == pytest.approx(0.4375)
    assert bl.variant_score("b2", P, L, N, I) == pytest.approx(0.625)
    assert bl.variant_score("b1", P, 0.0, 0.0, 1.0) == 0.0         # identity is invisible to b1 / b2
    assert bl.variant_score("b2", P, 1.0, 0.0, 1.0) == 0.0
    with pytest.raises(ValueError):
        bl.variant_weights("nonsense", P)


def test_b1_renormalises_when_weights_are_unequal():
    p = sp.ScoreParams(w1=0.2, w2=0.6, w3=0.2)
    assert bl.variant_weights("b1", p) == pytest.approx((0.25, 0.75, 0.0))


# ------------------------------------------------------------------------------------------------ ranking
def test_competition_ranking_with_shared_ranks_and_tie_size():
    got = rk.competition_ranks([("a", 0.9), ("b", 0.5), ("c", 0.5), ("d", 0.1), ("e", 0.5)])
    by = {r.item_id: r for r in got}
    assert (by["a"].rank, by["a"].tie_size) == (1, 1)
    assert [(by[x].rank, by[x].tie_size) for x in "bce"] == [(2, 3)] * 3
    assert (by["d"].rank, by["d"].tie_size) == (5, 1)               # 1, 2, 2, 2, 5
    assert [r.rank for r in got] == sorted(r.rank for r in got)
    assert [r.item_id for r in got] == ["a", "b", "c", "e", "d"]    # descending; display order in a tie = id


def test_every_item_appears_exactly_once_and_nothing_is_dropped():
    items = [(f"p{i}", 0.1 * (i % 4)) for i in range(11)]
    got = rk.competition_ranks(items)
    assert sorted(r.item_id for r in got) == sorted(i for i, _ in items)
    assert rk.competition_ranks([]) == []


def test_all_zero_scores_form_one_tie():
    got = rk.competition_ranks([("x", 0.0), ("y", 0.0), ("z", 0.0)])
    assert {(r.rank, r.tie_size) for r in got} == {(1, 3)}


def test_swapping_path_ids_changes_no_rank_or_score_only_display_order():
    scores = {"p1": 0.6, "p2": 0.6, "p3": 0.2, "p4": 0.9}
    swap = {"p1": "p2", "p2": "p1", "p3": "p4", "p4": "p3"}
    a = {r.item_id: (r.rank, r.tie_size, r.score) for r in rk.competition_ranks(scores.items())}
    b = {r.item_id: (r.rank, r.tie_size, r.score) for r in rk.competition_ranks((swap[k], v) for k, v in scores.items())}
    for k in scores:
        assert a[k] == b[swap[k]]


def test_rounding_boundary_tie_is_decided_at_12_decimals():
    x, y = 0.1 + 0.2, 0.3                                           # differ by ~5.5e-17
    assert x != y
    got = rk.competition_ranks([("a", x), ("b", y), ("c", 0.1)])
    assert {r.item_id: (r.rank, r.tie_size) for r in got} == {"a": (1, 2), "b": (1, 2), "c": (3, 1)}
    got = rk.competition_ranks([("a", 0.3 + 1e-9), ("b", 0.3)])      # a real difference above 1e-12 splits
    assert [(r.item_id, r.rank) for r in got] == [("a", 1), ("b", 2)]
    assert rk.tie_value(x) == rk.tie_value(y)


def test_fsum_makes_the_score_independent_of_component_order():
    comps = (0.1, 0.2, 0.3)
    a = rk.combine((1.0, 1.0, 1.0), comps)
    b = rk.combine((1.0, 1.0, 1.0), tuple(reversed(comps)))
    assert a == b == math.fsum(comps)


# ------------------------------------------------------------------------------------------------ b0 units
def test_b0_one_unit_per_count_key_any_host_any_context():
    rows = [event("u1", "K1", 3, tech="T1003.001", host="ep-01"), event("u1", "K1", 2, tech="T1003.001", host="ep-01"),
            event("u2", "K2", 1, tech="T1569.002", host="ep-02"), event("u3", "K2", 1, tech="T1569.002", host="ep-03"),
            event("u4", "K4", 4, tech="T1105", host="ep-09")]
    units = bl.b0_units(rows)
    assert [u.unit_id for u in units] == ["K1", "K2", "K4"]
    by = {u.unit_id: u for u in units}
    assert by["K1"].level_value == 3 and by["K1"].score == pytest.approx(0.75)
    assert by["K2"].event_uids == ("u2", "u3") and by["K2"].hosts == ("ep-02", "ep-03")
    assert by["K4"].score == 1.0
