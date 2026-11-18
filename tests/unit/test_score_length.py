"""T9 score stage: technique sequence, hop boundary and LengthScore (spec 05_score SC-20, SC-21, SC-21b, SC-23; SCT-20..23,
SCT-21b; decision 062 item 4, 067 items 2 and 4).

Written from the spec, not from the implementation. Default parameters: 1 - e^(-n/lambda) = 1 - 2^-n, so
    n = 1 -> 0.5, n = 2 -> 0.75, n = 3 -> 0.875, n = 4 -> 0.9375.
Real order table: stage T1078 0, T1003.001 0, T1021.002 1, T1021.001 / T1021.006 2 (R2/R5) -> but T1021.002 1,
T1570 2, T1569.002 3.
"""
from __future__ import annotations

import itertools
import math
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate.timeutil import to_us  # noqa: E402
from score import length as ln  # noqa: E402
from score import order as od  # noqa: E402
from score import params as sp  # noqa: E402
from score import sequence as sq  # noqa: E402
from score_fixtures import node  # noqa: E402

P = sp.ScoreParams()


@pytest.fixture(scope="module")
def ref():
    return od.build_reference(od.load_order_table())


def seq_of(ref, *techs, hop="h1"):
    return sq.technique_sequence([hop], {hop: {t: (f"u_{t}",) for t in techs}}, ref.stage)


# ------------------------------------------------------------------------------------------------ SC-20
def test_hop_technique_uids_keeps_only_labelled_context_zero_nodes_and_never_the_dump():
    rows = [node("p", "h1", "a", tech="T1021.002", level=1),
            node("p", "h1", "b", tech="T1003.001", level=3, ctx="1"),            # context 1: out
            node("p", "h1", "c", tech="T1003.001", level=3, ctx="0"),            # dump never enters, even at context 0
            node("p", "h1", "d", labelled="0"),                                  # unlabelled: out
            node("p", "h2", "e", tech="T1078", level=3),
            node("p", "h2", "f", tech="T1078", level=3)]
    got = sq.hop_technique_uids(rows)
    assert got == {"h1": {"T1021.002": ("a",)}, "h2": {"T1078": ("e", "f")}}


# ------------------------------------------------------------------------------------------------ SC-21 order
def test_within_hop_order_is_template_stage_not_attack_matrix_order(ref):
    got = sq.sort_techniques(["T1569.002", "T1570", "T1021.002"], ref.stage)
    assert got == ["T1021.002", "T1570", "T1569.002"]


def test_techniques_in_no_template_sort_after_the_templated_ones_by_id(ref):
    assert sq.sort_techniques(["T1550.002", "T1021.006", "T1105", "T1078"], ref.stage) == [
        "T1078", "T1021.006", "T1105", "T1550.002"]


def test_sequence_keeps_first_appearance_across_hops(ref):
    hop_techs = {"h6": {"T1021.002": ("a",), "T1570": ("b",), "T1569.002": ("c",)},
                 "h7": {"T1021.002": ("z",), "T1021.006": ("d",)}}
    seq = sq.technique_sequence(["h6", "h7"], hop_techs, ref.stage)
    assert [i.technique for i in seq] == ["T1021.002", "T1570", "T1569.002", "T1021.006"]
    assert [i.hop_id for i in seq] == ["h6", "h6", "h6", "h7"]
    assert seq[0].event_uids == ("a",)                                  # the first appearance's events, not h7's


def test_sequence_of_an_empty_path_is_empty(ref):
    assert sq.technique_sequence(["h1"], {}, ref.stage) == ()


# ------------------------------------------------------------------------------------------------ chain order
def test_chain_order_follows_edges_before_time():
    # h7 is earlier in time than h6, but the stitcher's chain edge says h6 -> h7
    order = sq.chain_order(["h7", "h6"], [("h6", "h7")], {"h6": 200, "h7": 100})
    assert order == ["h6", "h7"]


def test_chain_order_ties_by_time_then_hop_id_and_ignores_input_order():
    first = {"h1": 50, "h2": 10, "h3": 10, "h4": None}
    expect = ["h2", "h3", "h1", "h4"]                                   # time, then id; unknown time last
    for perm in itertools.permutations(["h1", "h2", "h3", "h4"]):
        assert sq.chain_order(perm, [], first) == expect


def test_chain_order_is_invariant_to_hop_list_and_edge_order():
    edges = [("a", "b"), ("b", "c"), ("a", "d")]
    first = {"a": 1, "b": 2, "c": 3, "d": 0}
    base = sq.chain_order(["a", "b", "c", "d"], edges, first)
    assert base.index("a") < base.index("b") < base.index("c") and base.index("a") < base.index("d")
    for hops in itertools.permutations(["a", "b", "c", "d"]):
        for es in (edges, list(reversed(edges))):
            assert sq.chain_order(hops, es, first) == base


def test_chain_order_terminates_on_a_cycle_and_returns_every_hop_once():
    out = sq.chain_order(["a", "b"], [("a", "b"), ("b", "a")], {"a": 1, "b": 2})
    assert sorted(out) == ["a", "b"]


# ------------------------------------------------------------------------------------------------ transitions
def test_single_technique_has_no_transition_and_length_zero(ref):
    steps = ln.transitions(seq_of(ref, "T1021.002"), ref, P, {})
    assert steps == []
    r = ln.length_score(steps, P.lam)
    assert (r.length_score, r.edge_score, r.seq_len) == (0.0, 0.0, 0)


def test_empty_sequence_has_length_zero(ref):
    r = ln.length_score(ln.transitions((), ref, P, {}), P.lam)
    assert (r.length_score, r.edge_score, r.seq_len) == (0.0, 0.0, 0)


def test_one_transition_smb_pair_eq7_length_one(ref):
    steps = ln.transitions(seq_of(ref, "T1021.002", "T1570"), ref, P, {})
    assert len(steps) == 1 and steps[0].score.basis == "direct" and steps[0].time_delta_ms is None
    r = ln.length_score(steps, P.lam)
    assert r.seq_len == 1 and r.edge_score == pytest.approx(1.0) and r.length_score == pytest.approx(0.5)


def test_smb_service_hop_two_direct_steps(ref):
    steps = ln.transitions(seq_of(ref, "T1569.002", "T1021.002", "T1570"), ref, P, {})
    assert [(s.src.technique, s.dst.technique) for s in steps] == [("T1021.002", "T1570"), ("T1570", "T1569.002")]
    assert [s.step for s in steps] == [1, 2]
    r = ln.length_score(steps, P.lam)
    assert r.seq_len == 2 and r.edge_score == pytest.approx(1.0) and r.length_score == pytest.approx(0.75)


def test_winrm_hop_indirect_step(ref):
    steps = ln.transitions(seq_of(ref, "T1021.006", "T1078"), ref, P, {})
    assert [(s.src.technique, s.dst.technique, s.score.basis) for s in steps] == [("T1078", "T1021.006", "indirect")]
    r = ln.length_score(steps, P.lam)
    assert r.edge_score == pytest.approx(0.5) and r.length_score == pytest.approx(0.25)


def test_hop_boundary_is_a_hop_chain_step_scored_direct_with_a_time_delta(ref):
    hop_techs = {"h6": {"T1021.002": ("w_smb",), "T1570": ("w_cp",), "T1569.002": ("w_svc",)},
                 "h7": {"T1078": ("w_4648b", "w_4648"), "T1021.006": ("w_wsm",)}}
    us = {"w_smb": to_us("2026-09-24T10:10:01Z"), "w_cp": to_us("2026-09-24T10:10:02Z"),
          "w_svc": to_us("2026-09-24T10:10:03Z"), "w_4648": to_us("2026-09-24T10:10:08.250000Z"),
          "w_4648b": to_us("2026-09-24T10:10:09Z"), "w_wsm": to_us("2026-09-24T10:10:10Z")}
    seq = sq.technique_sequence(["h6", "h7"], hop_techs, ref.stage)
    steps = ln.transitions(seq, ref, P, us, {("h6", "h7")})                  # a real chain edge h6 -> h7 (ST-72)
    assert [s.score.basis for s in steps] == ["direct", "direct", "hop_chain", "indirect"]
    assert [s.score.score_e for s in steps] == pytest.approx([1.0, 1.0, 1.0, 0.5])
    assert steps[2].time_delta_ms == 5250                       # first event of the next technique minus the previous
    assert steps[0].time_delta_ms is None and steps[3].time_delta_ms is None      # within a hop: empty (SC-21)
    r = ln.length_score(steps, P.lam)
    assert r.seq_len == 4 and r.edge_score == pytest.approx(0.875) and r.length_score == pytest.approx(0.9375 * 0.875)


def test_hop_boundary_across_a_chain_edge_into_initial_access_is_hop_chain_not_eps(ref):
    assert od.score_step(ref, "T1569.002", "T1078", P).score_e == pytest.approx(0.005)       # the trap
    hop_techs = {"a": {"T1569.002": ("x",)}, "b": {"T1078": ("y",)}}
    seq = sq.technique_sequence(["a", "b"], hop_techs, ref.stage)
    steps = ln.transitions(seq, ref, P, {}, {("a", "b")})
    assert steps[0].score.score_e == pytest.approx(1.0) and steps[0].score.basis == "hop_chain"


def test_decision_069_item_1_sibling_boundary_without_a_chain_edge_is_scored_against_the_templates(ref):
    """ATK-SC-17 (amends 067 item 4): no chain edge between the two hops -> the boundary step is scored like a within-hop
    step (here absent: execution -> initial-access has no template path, ScoreE = 0.5 * 0 + 0.5 * eps), never hop_chain;
    its time delta is still reported."""
    hop_techs = {"a": {"T1569.002": ("x",)}, "b": {"T1078": ("y",)}}
    seq = sq.technique_sequence(["a", "b"], hop_techs, ref.stage)
    us = {"x": to_us("2026-09-24T10:00:00Z"), "y": to_us("2026-09-24T10:00:07Z")}
    for edges in (None, set(), {("b", "a")}, {("a", "c")}):                                   # no edge a -> b
        steps = ln.transitions(seq, ref, P, us) if edges is None else ln.transitions(seq, ref, P, us, edges)
        assert steps[0].score.basis == "absent" and steps[0].score.score_e == pytest.approx(0.005), edges
        assert steps[0].score == od.score_step(ref, "T1569.002", "T1078", P)
        assert steps[0].time_delta_ms == 7000


def test_chain_edge_applies_only_to_the_boundary_it_joins_in_a_three_hop_sequence(ref):
    hop_techs = {"a": {"T1021.002": ("a1",), "T1570": ("a2",)}, "b": {"T1569.002": ("b1",)}, "c": {"T1078": ("c1",)}}
    seq = sq.technique_sequence(["a", "b", "c"], hop_techs, ref.stage)
    steps = ln.transitions(seq, ref, P, {}, {("a", "b")})                                    # a -> b chained, b -> c siblings
    assert [s.score.basis for s in steps] == ["direct", "hop_chain", "absent"]
    both = ln.transitions(seq, ref, P, {}, {("a", "b"), ("b", "c")})
    assert [s.score.basis for s in both] == ["direct", "hop_chain", "hop_chain"]


def test_a_sibling_boundary_lowers_length_score_against_a_chained_one(ref):
    hop_techs = {"a": {"T1569.002": ("x",)}, "b": {"T1078": ("y",)}}
    seq = sq.technique_sequence(["a", "b"], hop_techs, ref.stage)
    chained = ln.length_score(ln.transitions(seq, ref, P, {}, {("a", "b")}), P.lam)
    sibling = ln.length_score(ln.transitions(seq, ref, P, {}, set()), P.lam)
    assert chained.length_score == pytest.approx(0.5) and sibling.length_score == pytest.approx(0.5 * 0.005)


# ------------------------------------------------------------------------------------------------ Eq. 6 / 7
def fake_steps(ref, score_es):
    """Steps with chosen ScoreE values (only `score.score_e` is read by length_score)."""
    out = []
    item = sq.SeqItem("T1021.002", "h", ("u",))
    for i, e in enumerate(score_es, 1):
        out.append(ln.Step(i, item, item, od.StepScore("", "", 0.0, 0.0, e, "direct"), None))
    return out


def test_eq6_eq7_length_score_is_one_minus_exp_over_lambda_times_mean(ref):
    es = [1.0, 0.5, 0.01]
    r = ln.length_score(fake_steps(ref, es), P.lam)
    assert r.seq_len == 3 and r.edge_score == pytest.approx(sum(es) / 3)
    assert r.length_score == pytest.approx((1 - 2.0 ** -3) * sum(es) / 3)


def test_length_factor_depends_on_lambda(ref):
    r = ln.length_score(fake_steps(ref, [0.4, 0.6]), 1.0)
    assert r.length_score == pytest.approx((1 - math.exp(-2.0)) * 0.5)
    r2 = ln.length_score(fake_steps(ref, [0.4, 0.6]), 5.0)
    assert r2.length_score == pytest.approx((1 - math.exp(-2.0 / 5.0)) * 0.5)


def test_length_score_does_not_depend_on_step_order(ref):
    es = [0.9, 0.1, 0.5, 0.5, 0.25]
    a = ln.length_score(fake_steps(ref, es), P.lam)
    b = ln.length_score(fake_steps(ref, list(reversed(es))), P.lam)
    assert a.length_score == b.length_score and a.edge_score == b.edge_score


def test_length_score_stays_in_unit_interval(ref):
    for n in range(1, 8):
        r = ln.length_score(fake_steps(ref, [1.0] * n), P.lam)
        assert 0.0 < r.length_score < 1.0
