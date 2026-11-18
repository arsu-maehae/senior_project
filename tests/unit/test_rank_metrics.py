"""T9.5 ranking check, pure part (spec 05_score SCA-06 and section 7.3; decisions 065, 068; handoff 14.2).

Written from the spec and the decisions, not from the code (the code was read only for its public entry points in
`evaluate.rank_metrics` and `evaluate.rank_report`). Fast, synthetic. Tie formulas are checked against a brute-force
enumeration of every random order, so the expected values are derived here and not copied from the implementation.
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

import rank_fixtures as rf  # noqa: E402
from evaluate import rank_metrics as rm  # noqa: E402
from evaluate import rank_report as rr  # noqa: E402
from evaluate import rank_run  # noqa: E402
from evaluate.inputs import EvalError  # noqa: E402


def cands(spec):
    """spec: list of (path_id, rank, tie_size, score[, hops]) -> Candidates."""
    return [rm.Candidate(s[0], s[1], s[2], s[3], frozenset(s[4] if len(s) > 4 else [])) for s in spec]


def group_cands(r, t, extra_above=0):
    """`extra_above` singletons above, then one group of t at competition rank r = extra_above + 1."""
    out = [(f"A{i}", i + 1, 1, 1.0 - i * 0.01) for i in range(extra_above)]
    out += [(f"G{i}", extra_above + 1, t, 0.5) for i in range(t)]
    out += [(f"Z{i}", extra_above + t + 1 + i, 1, 0.1) for i in range(2)]
    return cands(out)


def brute(t, m):
    """Expected position (1-based, inside the group) of the first of m marked items among t in a uniform random order,
    and P(position 1 is marked)."""
    marked = set(range(m))
    firsts, top = [], 0
    perms = list(itertools.permutations(range(t)))
    for p in perms:
        pos = next(i for i, x in enumerate(p, start=1) if x in marked)
        firsts.append(pos)
        top += pos == 1
    return sum(firsts) / len(perms), top / len(perms)


# ================================================================================================ tie readings (065, 068 item 2)
def test_one_match_in_a_two_way_tie_at_the_top_is_rank_one_and_a_half():
    c = group_cands(1, 2)
    pl = rm.placement(c, {"G0"})
    assert (pl.rank_expected, pl.rank_optimistic, pl.rank_pessimistic) == (1.5, 1, 2)
    assert (pl.top1_expected, pl.top1_optimistic, pl.top1_pessimistic) == (0.5, 1.0, 0.0)
    assert pl.rr("expected") == pytest.approx(1 / 1.5)
    assert pl.rr("optimistic") == 1.0 and pl.rr("pessimistic") == 0.5


@pytest.mark.parametrize("r,t", [(1, 1), (1, 2), (1, 3), (1, 5), (2, 4), (3, 2), (4, 3)])
def test_m1_expected_rank_is_r_plus_t_minus_1_over_2(r, t):
    pl = rm.placement(group_cands(r, t, extra_above=r - 1), {"G0"})
    assert pl.first_rank == r and pl.tie_size == t
    assert pl.rank_expected == pytest.approx(r + (t - 1) / 2)
    assert (pl.rank_optimistic, pl.rank_pessimistic) == (r, r + t - 1)
    assert pl.top1_expected == pytest.approx(1 / t if r == 1 else 0.0)
    assert pl.top1_optimistic == (1.0 if r == 1 else 0.0)
    assert pl.top1_pessimistic == (1.0 if (r == 1 and t == 1) else 0.0)


@pytest.mark.parametrize("t,m", [(2, 2), (3, 2), (4, 2), (4, 3), (5, 2), (5, 3), (5, 5), (3, 1)])
@pytest.mark.parametrize("above", [0, 2])
def test_m_matches_in_one_tie_group_match_the_brute_force_expectation(t, m, above):
    """Decision 068 item 2: expected first-match rank r - 1 + (t+1)/(m+1), credit m/t at r = 1, pessimistic r+t-m."""
    r = above + 1
    c = group_cands(r, t, extra_above=above)
    pl = rm.placement(c, {f"G{i}" for i in range(m)})
    pos, top = brute(t, m)
    assert pl.rank_expected == pytest.approx(r - 1 + pos)
    assert pl.rank_expected == pytest.approx(r - 1 + (t + 1) / (m + 1))
    assert pl.rank_optimistic == r and pl.rank_pessimistic == r + t - m
    assert pl.top1_expected == pytest.approx(top if r == 1 else 0.0)
    assert pl.top1_expected == pytest.approx(m / t if r == 1 else 0.0)
    assert sorted(pl.first_group) == [f"G{i}" for i in range(m)]


def test_only_the_best_ranked_matching_group_counts_and_lower_matches_are_ignored():
    c = cands([("A", 1, 1, 0.9), ("B", 2, 2, 0.5), ("C", 2, 2, 0.5), ("D", 4, 1, 0.1)])
    pl = rm.placement(c, {"C", "D"})
    assert pl.first_group == ("C",) and pl.first_rank == 2 and pl.tie_size == 2
    assert pl.rank_expected == pytest.approx(2.5) and pl.rank_pessimistic == 3
    assert pl.first_score == 0.5


def test_no_match_gives_none_ranks_and_zero_credit():
    pl = rm.placement(group_cands(1, 2), set())
    assert (pl.first_rank, pl.rank_expected, pl.rank_optimistic, pl.rank_pessimistic) == (None,) * 4
    assert (pl.top1_expected, pl.top1_optimistic, pl.top1_pessimistic) == (0.0, 0.0, 0.0)
    assert pl.rr("expected") == pl.rr("optimistic") == pl.rr("pessimistic") == 0.0


def test_listing_order_inside_a_tie_never_changes_a_metric():
    """065 / ATK-SC-01: path_id order is never used. Renaming the tied paths gives the same numbers."""
    a = rm.placement(cands([("P1", 1, 2, 0.6), ("P2", 1, 2, 0.6), ("P3", 3, 1, 0.1)]), {"P1"})
    b = rm.placement(cands([("P1", 1, 2, 0.6), ("P2", 1, 2, 0.6), ("P3", 3, 1, 0.1)]), {"P2"})
    for f in ("rank_expected", "rank_optimistic", "rank_pessimistic", "top1_expected", "top1_pessimistic"):
        assert getattr(a, f) == getattr(b, f)


def test_ranks_must_be_competition_ranks_or_the_check_refuses():
    bad = [{"variant": "full", "path_id": "A", "rank": "1", "tie_size": "2", "score": "1", "hop_ids": ""},
           {"variant": "full", "path_id": "B", "rank": "2", "tie_size": "1", "score": "1", "hop_ids": ""}]
    with pytest.raises(EvalError):
        rm.candidates_of(bad, "full")
    bad2 = [{"variant": "full", "path_id": "A", "rank": "1", "tie_size": "1", "score": "1", "hop_ids": ""},
            {"variant": "full", "path_id": "B", "rank": "3", "tie_size": "1", "score": "0", "hop_ids": ""}]
    with pytest.raises(EvalError):
        rm.candidates_of(bad2, "full")


# ================================================================================================ chance line (065, 068 item 4)
@pytest.mark.parametrize("n,m", [(1, 1), (2, 1), (4, 1), (5, 1), (5, 2), (6, 3), (3, 3)])
def test_chance_line_matches_brute_force(n, m):
    ch = rm.chance_line(n, m)
    pos, _ = brute(n, m)
    assert ch["top1"] == pytest.approx(m / n)
    assert ch["rank"] == pytest.approx(pos) == pytest.approx((n + 1) / (m + 1))
    assert ch["rr"] == pytest.approx(1 / pos)                                  # chance_mrr = 1 / E[rank]
    firsts = [next(i for i, x in enumerate(p, 1) if x < m) for p in itertools.permutations(range(n))]
    assert ch["rr_mean"] == pytest.approx(sum(1 / f for f in firsts) / len(firsts))
    assert ch["rr_mean"] >= ch["rr"] - 1e-12                                   # E[1/X] >= 1/E[X]


def test_chance_line_hand_values_of_s04_t00_shape():
    ch = rm.chance_line(5, 1)
    assert (ch["top1"], ch["rank"]) == (0.2, 3.0)
    assert ch["rr"] == pytest.approx(1 / 3) and ch["rr_mean"] == pytest.approx((1 + 1 / 2 + 1 / 3 + 1 / 4 + 1 / 5) / 5)


def test_chance_line_without_candidates_or_matches_is_zero():
    for n, m in ((0, 0), (5, 0), (0, 1)):
        ch = rm.chance_line(n, m)
        assert ch["top1"] == 0.0 and ch["rr"] == 0.0 and ch["rank"] is None


# ================================================================================================ node set (068 item 1)
def test_key_hop_node_set_is_the_union_of_the_five_move_fields_only():
    kh = {"hop_id": "k", "target_event_uids": ["t1", "t2"], "agent_event_uids": ["a1"],
          "agent_corroboration_4688_uids": ["c1"], "port_join_event_uids": ["p1"], "credential_logon_uids": ["l1"],
          "related_logon_uids": ["rel1"], "identity_basis": ["dump1"], "candidates": ["cand1"],
          "steps": [{"uids": ["s1"]}]}
    assert rm.key_hop_node_uids(kh) == frozenset({"t1", "t2", "a1", "c1", "p1", "l1"})
    assert set(rm.KEY_NODE_FIELDS) == {"target_event_uids", "agent_event_uids", "agent_corroboration_4688_uids",
                                       "port_join_event_uids", "credential_logon_uids"}


def test_key_hop_with_missing_or_null_fields_and_with_a_malformed_field():
    assert rm.key_hop_node_uids({"target_event_uids": ["t"], "agent_event_uids": None}) == frozenset({"t"})
    assert rm.key_hop_node_uids({}) == frozenset()
    with pytest.raises(EvalError):
        rm.key_hop_node_uids({"hop_id": "k", "target_event_uids": "t1"})
    with pytest.raises(EvalError):
        rm.key_hop_node_uids({"hop_id": "k", "agent_event_uids": [1]})


def test_candidate_node_set_is_the_context_zero_uids_of_path_nodes():
    rows = [{"path_id": "P", "context": "0", "event_uid": "x"}, {"path_id": "P", "context": "1", "event_uid": "dump"},
            {"path_id": "P", "context": "0", "event_uid": ""}, {"path_id": "P", "context": "0", "event_uid": "x"},
            {"path_id": "Q", "context": "0", "event_uid": "y"}, {"path_id": "R", "context": "1", "event_uid": "z"}]
    assert rm.path_node_sets(rows) == {"P": frozenset({"x"}), "Q": frozenset({"y"})}


def test_key_path_node_set_unions_over_its_hops_and_excludes_benign_paths():
    w = rf.RankWorld()
    w.paths = [rf.P("P1", ["H1"]), rf.P("P2", ["H2"])]
    w.key_hops = [rf.KH("K1", "T_H1", 0x100, {"agent_event_uids": ["a1"], "identity_basis": ["d"]}),
                  rf.KH("K2", "T_H2", 0x101, {"credential_logon_uids": ["l2"]})]
    w.key_paths = [rf.KP("KA", "attack", ["K1", "K2"]), rf.KP("KB", "benign", ["K1"]),
                   rf.KP("KC", "attack_pair", ["K2"])]
    kps = rm.build_key_paths(w.key_json(), w.stitch_data().hops)
    assert [k.path_id for k in kps] == ["KA", "KC"]                            # benign never; attack and attack_pair
    assert kps[0].node_uids == frozenset({"T_H1", "a1", "T_H2", "l2"})
    assert kps[0].mapped_hop_ids == frozenset({"H1", "H2"}) and kps[1].mapped_hop_ids == frozenset({"H2"})


def test_key_path_naming_an_undefined_hop_is_refused():
    w = rf.RankWorld()
    w.paths = [rf.P("P1", ["H1"])]
    w.key_paths = [rf.KP("KA", "attack", ["K9"])]
    with pytest.raises(EvalError):
        rm.build_key_paths(w.key_json(), w.stitch_data().hops)


def test_unmatched_key_hop_is_reported_and_maps_to_no_stitch_hop():
    w = rf.RankWorld()
    w.paths = [rf.P("P1", ["H1"])]
    w.key_hops = [rf.KH("K1", "T_H1", 0x100), rf.KH("K2", "NOPE", 0x999)]
    w.key_paths = [rf.KP("KA", "attack", ["K1", "K2"])]
    (kp,) = rm.build_key_paths(w.key_json(), w.stitch_data().hops)
    assert kp.unmatched_key_hops == ("K2",) and kp.mapped_hop_ids == frozenset({"H1"})


def test_key_hop_maps_to_every_stitch_hop_holding_its_target_logon():
    w = rf.RankWorld()
    w.paths = [rf.P("P1", ["H1"]), rf.P("P2", ["H2"])]
    w.members = {"H1": [("T1", 0x100)], "H2": [("T1", 0x100)]}                # the same 4624 in two hops
    w.key_hops = [rf.KH("K1", "T1", 0x100)]
    w.key_paths = [rf.KP("KA", "attack", ["K1"])]
    (kp,) = rm.build_key_paths(w.key_json(), w.stitch_data().hops)
    assert kp.mapped_hop_ids == frozenset({"H1", "H2"})


# ================================================================================================ Jaccard >= 0.5 (hop and node readings)
def test_jaccard_basics():
    assert rm.jaccard(["a"], ["a"]) == 1.0
    assert rm.jaccard(["a", "b"], ["b", "c"]) == pytest.approx(1 / 3)
    assert rm.jaccard([], []) == 0.0 and rm.jaccard(["a"], []) == 0.0
    assert rm.MATCH_THRESHOLD == 0.5


def kp_of(mapped, nodes, targets=()):
    """A KeyPath; `targets` = its target logon uids (decision 069 item 7 anchor of the node reading)."""
    return rm.KeyPath("K", "attack", ("k",), frozenset(mapped), (), frozenset(nodes), (),
                      target_logon_uids=frozenset(targets))


def test_hop_reading_exactly_half_and_just_below():
    k = kp_of({"H1", "H2"}, set())
    assert "P" in rm.matches(k, cands([("P", 1, 1, 0.5, {"H1"})]), {}, rm.READING_HOP)             # 1/2
    k3 = kp_of({"H1", "H2", "H3"}, set())
    assert "P" not in rm.matches(k3, cands([("P", 1, 1, 0.5, {"H1"})]), {}, rm.READING_HOP)        # 1/3


def test_node_reading_exactly_half_matches_and_below_does_not():
    key = {"n1", "n2", "n3", "n4"}
    nodes = {"P": frozenset({"n1", "n2", "x1", "x2"}),        # inter 2, union 6 -> 1/3: no
             "Q": frozenset({"n1", "n2", "n3", "x1"}),        # inter 3, union 5 -> 0.6: yes
             "R": frozenset({"n1", "n2"}),                     # inter 2, union 4 -> 0.5: yes (>=)
             "S": frozenset()}
    c = cands([(p, i + 1, 1, 0.5) for i, p in enumerate("PQRS")])
    got = rm.matches(kp_of(set(), key, {"n1"}), c, nodes, rm.READING_NODE)         # n1 = the key's target logon uid
    assert sorted(got) == ["Q", "R"] and got["R"] == 0.5 and got["Q"] == pytest.approx(0.6)


def test_decision_069_item_7_node_match_also_needs_one_of_the_key_target_logon_uids():
    """ATK-SC-16: a candidate of artefacts / source events only (Jaccard high, no target 4624) must not match."""
    key = {"t1", "a1", "a2", "a3"}
    nodes = {"anchorless": frozenset({"a1", "a2", "a3"}),            # Jaccard 3/4, holds no target logon
             "anchored": frozenset({"t1", "a1", "a2"}),              # Jaccard 3/4, holds t1
             "other_target": frozenset({"t9", "a1", "a2", "a3"})}    # Jaccard 3/5, t9 is not the key's target
    c = cands([("anchorless", 1, 1, 0.5), ("anchored", 2, 1, 0.5), ("other_target", 3, 1, 0.5)])
    got = rm.matches(kp_of(set(), key, {"t1"}), c, nodes, rm.READING_NODE)
    assert sorted(got) == ["anchored"] and got["anchored"] == 0.75
    assert rm.matches(kp_of(set(), key, set()), c, nodes, rm.READING_NODE) == {}         # no target uid: matches nothing
    two = rm.matches(kp_of(set(), key, {"t1", "t9"}), c, nodes, rm.READING_NODE)           # any one of several targets
    assert sorted(two) == ["anchored", "other_target"]


def test_the_anchor_does_not_touch_the_hop_reading():
    c = cands([("P", 1, 1, 0.5, {"H1"})])
    assert "P" in rm.matches(kp_of({"H1"}, {"n"}, set()), c, {}, rm.READING_HOP)


def test_build_key_paths_target_logon_uids_are_the_key_target_events_that_are_stitch_member_logons():
    w = rf.RankWorld()
    w.paths = [rf.P("P1", ["H1"]), rf.P("P2", ["H2"])]
    w.key_hops = [rf.KH("K1", "T_H1", 0x100, {"target_event_uids": ["art1", "svc1"], "agent_event_uids": ["a1"]}),
                  rf.KH("K2", "T_H2", 0x101)]
    w.key_paths = [rf.KP("KA", "attack", ["K1"]), rf.KP("KB", "attack", ["K1", "K2"])]
    ka, kb = rm.build_key_paths(w.key_json(), w.stitch_data().hops)
    assert ka.target_logon_uids == frozenset({"T_H1"})                     # artefact uids and the agent are not target logons
    assert kb.target_logon_uids == frozenset({"T_H1", "T_H2"})
    assert {"art1", "svc1", "a1", "T_H1"} <= ka.node_uids                  # but they stay in the node set


def test_st05_copies_are_replaced_by_their_representative_on_both_sides():
    """Decision 069 item 7 / 055: a member_logon_uids item `rep|copy` is one 4624; the key may name the copy."""
    w = rf.RankWorld()
    w.paths = [rf.P("P1", ["H1"], nodes=["T1copy", "a1"]), rf.P("P2", ["H2"], nodes=["T1", "a1"])]
    w.members = {"H1": [("T1|T1copy", 0x100)], "H2": [("T9", 0x102)]}
    w.key_hops = [rf.KH("K1", "T1copy", 0x100, {"agent_event_uids": ["a1"]})]
    w.key_paths = [rf.KP("KA", "attack", ["K1"])]
    hops = w.stitch_data().hops
    alias = rm.copy_alias_map(hops)
    assert alias["T1copy"] == "T1" and alias["T1"] == "T1" and alias.get("T9", "T9") == "T9"
    assert rm.canonical(["T1copy", "x"], alias) == frozenset({"T1", "x"})
    (kp,) = rm.build_key_paths(w.key_json(), hops)
    assert kp.target_logon_uids == frozenset({"T1"}) and kp.node_uids == frozenset({"T1", "a1"})
    nodes = rm.path_node_sets(w.stitch_data().path_nodes, alias)
    assert nodes["P1"] == frozenset({"T1", "a1"}) and nodes["P2"] == frozenset({"T1", "a1"})
    cs = rm.candidates_of(w.score_data().ranked, "full")
    got = rm.matches(kp, cs, nodes, rm.READING_NODE)
    assert sorted(got) == ["P1", "P2"] and got["P1"] == 1.0                             # the copy no longer breaks the match


def test_node_reading_of_a_candidate_without_nodes_matches_nothing_and_unknown_reading_raises():
    c = cands([("P", 1, 1, 0.5)])
    assert rm.matches(kp_of(set(), {"a"}), c, {}, rm.READING_NODE) == {}
    with pytest.raises(ValueError):
        rm.matches(kp_of(set(), {"a"}), c, {}, "path_id")


def test_hop_and_node_readings_can_disagree_on_the_standard_world():
    w = rf.tie_world()
    kp = rm.build_key_paths(w.key_json(), w.stitch_data().hops)[0]
    cs = rm.candidates_of(w.score_data().ranked, "full")
    nodes = rm.path_node_sets(w.stitch_data().path_nodes)
    assert sorted(rm.matches(kp, cs, nodes, rm.READING_HOP)) == ["P1"]
    node = rm.matches(kp, cs, nodes, rm.READING_NODE)
    assert sorted(node) == ["P1", "P5"] and node["P1"] == 1.0 and node["P5"] == 0.5


# ================================================================================================ score gap
def test_score_gap_is_lowest_key_attack_score_minus_highest_other_score():
    c = cands([("A", 1, 1, 0.9), ("B", 2, 1, 0.5), ("C", 3, 1, 0.3), ("D", 4, 1, 0.3)])
    low, high, ids, gap = rm.score_gap([0.9], c, {"A"})
    assert (low, high, ids) == (0.9, 0.5, ("B",)) and gap == pytest.approx(0.4)


def test_score_gap_is_zero_for_an_attack_path_tied_with_a_benign_one_and_negative_below_it():
    c = cands([("A", 1, 2, 0.6), ("B", 1, 2, 0.6)])
    assert rm.score_gap([0.6], c, {"A"})[3] == 0.0
    c2 = cands([("B", 1, 1, 0.7), ("A", 2, 1, 0.4)])
    assert rm.score_gap([0.4], c2, {"A"})[3] == pytest.approx(-0.3)


def test_score_gap_uses_the_lowest_of_several_key_attack_paths_and_is_undefined_without_a_match():
    c = cands([("A", 1, 1, 0.9), ("A2", 2, 1, 0.6), ("B", 3, 1, 0.5)])
    assert rm.score_gap([0.9, 0.6], c, {"A", "A2"})[3] == pytest.approx(0.1)
    assert rm.score_gap([0.9, None], c, {"A"})[:1] == (None,) and rm.score_gap([0.9, None], c, {"A"})[3] is None
    allmatch = rm.score_gap([0.9], cands([("A", 1, 1, 0.9)]), {"A"})
    assert allmatch[1] is None and allmatch[3] is None


# ================================================================================================ distributions
def test_distribution_reports_n_range_zero_count_distinct_and_top_tie():
    d = rm.distribution(cands([("A", 1, 2, 0.6), ("B", 1, 2, 0.6), ("C", 3, 1, 0.0), ("D", 3, 2, 0.0)][:3]))
    assert d["n"] == 3 and d["max"] == 0.6 and d["min"] == 0.0 and d["n_zero"] == 1 and d["n_distinct"] == 2
    assert d["top_tie"] == 2 and d["mean"] == pytest.approx(0.4)
    assert rm.distribution([])["n"] == 0


# ================================================================================================ H4: b0 at an equal node budget
def test_inclusion_probabilities_split_the_tie_group_at_the_cut():
    c = cands([("P1", 1, 1, 0.9), ("P2", 2, 3, 0.5), ("P3", 2, 3, 0.5), ("P4", 2, 3, 0.5), ("P5", 5, 1, 0.1)])
    sure, cut, slots = rm.inclusion_probabilities(c, 2)
    assert sure == {"P1": 1.0} and cut == ["P2", "P3", "P4"] and slots == 1
    sure, cut, slots = rm.inclusion_probabilities(c, 1)                     # the cut falls between groups
    assert sure == {"P1": 1.0} and cut == [] and slots == 0
    sure, cut, slots = rm.inclusion_probabilities(c, 4)
    assert set(sure) == {"P1", "P2", "P3", "P4"} and cut == []


def test_expected_coverage_of_a_tie_group_at_the_cut_by_inclusion_probability():
    nodes = {"P1": frozenset({"a", "b"}), "P2": frozenset({"c", "d"}), "P3": frozenset({"e", "c"})}
    cov = rm.expected_coverage(nodes, ["P1"], ["P2", "P3"], 1)
    assert cov == {"a": 1.0, "b": 1.0, "c": 1.0, "d": 0.5, "e": 0.5}         # c is in both cut paths: held with prob 1
    cov2 = rm.expected_coverage(nodes, ["P1", "P2"], [], 0)
    assert cov2["d"] == 1.0 and "e" not in cov2
    three = {"A": frozenset({"x"}), "B": frozenset({"y"}), "C": frozenset({"z"})}
    cov3 = rm.expected_coverage(three, [], ["A", "B", "C"], 2)
    assert cov3 == {"x": pytest.approx(2 / 3), "y": pytest.approx(2 / 3), "z": pytest.approx(2 / 3)}   # 1 - C(2,2)/C(3,2)


def b0(rows):
    return [{"unit_id": u, "rank": str(r), "tie_size": str(t), "event_uids": ";".join(n)} for u, r, t, n in rows]


def test_b0_recall_whole_units_within_budget():
    rows = b0([("u1", 1, 1, ["a"]), ("u2", 2, 1, ["b"]), ("u3", 3, 1, ["c"])])
    rec, held = rm.b0_recall(rows, 2.0, frozenset({"a", "c"}))
    assert (rec, held) == (0.5, 2.0)


def test_b0_recall_with_a_tie_group_at_the_cut_is_read_at_node_level_by_expectation():
    rows = b0([("u1", 1, 1, ["a"]), ("u2", 2, 2, ["b"]), ("u3", 2, 2, ["c"]), ("u4", 4, 1, ["d"])])
    key = frozenset({"a", "b", "d"})
    rec, held = rm.b0_recall(rows, 2.0, key)                    # remaining budget 1 of 2 new nodes {b, c}: each 1/2
    assert held == 2.0 and rec == pytest.approx((1 + 0.5) / 3)
    rec, held = rm.b0_recall(rows, 3.0, key)                    # the whole group fits; d never held
    assert held == 3.0 and rec == pytest.approx(2 / 3)
    rec, _ = rm.b0_recall(rows, 1.5, key)                       # budget 0.5 of 2 new nodes: share 1/4 of b
    assert rec == pytest.approx((1 + 0.25) / 3)
    assert rm.b0_recall(rows, 0.0, key)[0] == 0.0


def test_b0_recall_counts_nodes_already_held_once_and_empty_key_is_zero():
    rows = b0([("u1", 1, 1, ["a", "b"]), ("u2", 2, 1, ["b", "c"])])
    rec, held = rm.b0_recall(rows, 3.0, frozenset({"b", "c"}))
    assert held == 3.0 and rec == 1.0
    assert rm.b0_recall(rows, 3.0, frozenset())[0] == 0.0


def test_b0_with_inconsistent_ranks_is_refused():
    with pytest.raises(EvalError):
        rm.b0_recall(b0([("u1", 1, 2, ["a"]), ("u2", 2, 1, ["b"])]), 1.0, frozenset({"a"}))


def test_h4_on_the_standard_world_by_hand():
    """tie_world: k = 1, full's top-1 is the tie group {P1, P2}: coverage 1/2 per node of either path."""
    w = rf.tie_world()
    res = rank_run.rank_from_inputs(w.trial, "development", w.stitch_data(), w.score_data(), w.key_data())
    b = res.b0
    assert (b.k, b.key_nodes) == (1, 3)
    assert b.budget == pytest.approx(2.5)                       # (3 + 2 nodes) * 1/2
    assert b.full_recall == pytest.approx(0.5)                  # 3 key nodes * 1/2 / 3
    assert b.b0_recall == pytest.approx(2 / 3)                  # u1 holds a1, a2 (2 nodes), 0.5 of u2's one node
    assert b.budget_labelled == pytest.approx(1.5)              # labelled nodes: P1 {a1, a2}, P2 {b1}: 3 * 1/2
    assert b.full_recall_labelled == pytest.approx(1 / 3)
    assert b.b0_recall_labelled == pytest.approx(0.5)


# ================================================================================================ the assembled check
def assemble(w):
    return rank_run.rank_from_inputs(w.trial, "development", w.stitch_data(), w.score_data(), w.key_data())


def reading(res, variant, kind):
    (r,) = [x for x in res.readings if x.variant == variant and x.reading == kind]
    return r


def test_standard_world_full_hop_reading_by_hand():
    res = assemble(rf.tie_world())
    r = reading(res, "full", "hop")
    assert r.n == 5 and r.trial.matched == ("P1",)
    pl = r.trial
    assert (pl.first_rank, pl.tie_size) == (1, 2) and pl.rank_expected == 1.5
    assert (pl.rank_optimistic, pl.rank_pessimistic, pl.top1_expected) == (1, 2, 0.5)
    assert r.low == pytest.approx(2 / 3) and r.high == pytest.approx(2 / 3) and r.gap == pytest.approx(0.0, abs=1e-9)
    assert r.high_ids == ("P2",)


def test_standard_world_variants_b1_and_b2_by_hand():
    res = assemble(rf.tie_world())
    b1 = reading(res, "b1", "hop").trial
    assert (b1.first_rank, b1.tie_size, b1.rank_expected) == (1, 2, 1.5)                  # P1 = P2 = 0.5 > P3 0.4375
    b2 = reading(res, "b2", "hop").trial
    assert (b2.first_rank, b2.tie_size, b2.rank_expected) == (3, 2, 3.5)                  # P3 .625, P5 .5, then P1 = P2
    assert (b2.rank_optimistic, b2.rank_pessimistic, b2.top1_expected) == (3, 4, 0.0)
    b2n = reading(res, "b2", "node").trial                                                 # node reading also matches P5
    assert (b2n.first_rank, b2n.rank_expected) == (2, 2.0) and b2n.matched == ("P1", "P5")


def test_standard_world_node_reading_matches_the_extra_candidate_and_chance_uses_two_matches():
    res = assemble(rf.tie_world())
    r = reading(res, "full", "node")
    assert r.trial.matched == ("P1", "P5") and r.trial.rank_expected == 1.5
    ch = rm.chance_line(r.n, len(r.trial.matched))
    assert ch["top1"] == pytest.approx(0.4) and ch["rank"] == pytest.approx(2.0) and ch["rr"] == pytest.approx(0.5)
    assert ch["rr_mean"] == pytest.approx(0.4 + 0.3 / 2 + 0.2 / 3 + 0.1 / 4)             # P(first at i) = (5-i)/10


def test_several_key_attack_paths_matching_one_tie_group_give_rank_one():
    w = rf.RankWorld()
    w.paths = [rf.P("X", ["H1"], seq_len=2, node=0.25, ident=1.0), rf.P("Y", ["H2"], seq_len=2, node=0.25, ident=1.0),
               rf.P("Z", ["H3"])]
    w.key_hops = [rf.KH("K1", "T_H1", 0x100), rf.KH("K2", "T_H2", 0x101)]
    w.key_paths = [rf.KP("KX", "attack", ["K1"]), rf.KP("KY", "attack", ["K2"])]
    res = assemble(w)
    r = reading(res, "full", "hop")
    assert r.trial.first_group == ("X", "Y") and r.trial.tie_size == 2
    assert r.trial.rank_expected == pytest.approx(1.0) and r.trial.top1_expected == 1.0
    assert r.trial.rank_pessimistic == 1
    for k in r.key_paths:                                                                  # per key path: 2-way tie, m = 1
        assert k.placement.rank_expected == 1.5 and k.placement.top1_expected == 0.5


def test_trial_metrics_use_the_first_candidate_matching_any_key_attack_path():
    w = rf.RankWorld()
    w.paths = [rf.P("X", ["H1"], node=1.0, seq_len=2, ident=1.0), rf.P("Y", ["H2"], node=0.4),
               rf.P("Z", ["H3"], node=0.1)]
    w.key_hops = [rf.KH("K1", "T_H1", 0x100), rf.KH("K2", "T_H2", 0x101)]
    w.key_paths = [rf.KP("KX", "attack", ["K1"]), rf.KP("KY", "attack_pair", ["K2"])]
    r = reading(assemble(w), "full", "hop")
    assert r.trial.first_rank == 1 and r.trial.rr("expected") == 1.0                       # KX at 1, KY lower: trial RR 1
    assert [k.placement.first_rank for k in r.key_paths] == [1, 2]


def test_keyed_trial_without_attack_paths_gets_no_reading_rows_and_unkeyed_gets_distribution_only():
    s06 = assemble(rf.benign_world())
    assert s06.keyed and not s06.attack and s06.readings == () and s06.b0 is None
    un = rank_run.rank_from_inputs("s02_t01", "development", rf.unkeyed_world().stitch_data(),
                                   rf.unkeyed_world().score_data(), None)
    assert not un.keyed and not un.attack and un.readings == ()
    assert set(un.distributions) == {"full", "b1", "b2"}


# ================================================================================================ S06 check (H5 reading)
def test_s06_check_compares_highest_benign_score_with_lowest_key_attack_score():
    attack, s06 = assemble(rf.tie_world("s04_t00")), assemble(rf.benign_world("s06_t00"))
    f = rr.s06_facts([attack, s06], "full", "hop")
    # B1 = (0.25 + 0.5 + 0) / 3 = 0.25 ; B2 = 0 ; key attack path P1 = 0.666667
    assert f["s06_trials"] == 1 and f["s06_max"] == pytest.approx(0.25) and f["low"] == pytest.approx(2 / 3)
    assert f["margin"] == pytest.approx(2 / 3 - 0.25) and f["held"] is True and f["share_above"] == 1.0


def test_s06_check_not_held_when_a_benign_path_scores_at_or_above_the_lowest_attack_score():
    attack, s06 = assemble(rf.tie_world("s04_t00")), assemble(rf.benign_world("s06_t00"))
    f = rr.s06_facts([attack, s06], "b2", "hop")              # b2: key path P1 = 0.25 vs B1 0.5 -> negative
    assert f["margin"] == pytest.approx(0.25 - 0.5) and f["held"] is False and f["share_above"] == 0.0
    equal = rr.s06_facts([attack, s06], "b1", "hop")           # b1: P1 0.5, B1 (0.25 + 0.5)/2 = 0.375: held
    assert equal["held"] is True


def test_s06_check_equal_scores_is_not_held_strict():
    w = rf.RankWorld(trial="s06_t00")
    w.paths = [rf.P("B1", ["G1"], seq_len=2, node=0.25, ident=1.0)]                      # score 0.666667
    w.key_paths = []
    a = assemble(rf.tie_world("s04_t00"))
    f = rr.s06_facts([a, assemble(w)], "full", "hop")
    assert f["margin"] == pytest.approx(0.0, abs=1e-9) and f["held"] is False


def test_s06_check_undefined_without_an_s06_trial_or_attack_trial():
    assert rr.s06_facts([assemble(rf.tie_world())], "full", "hop")["held"] is None
    assert rr.s06_facts([assemble(rf.benign_world())], "full", "hop")["held"] is None


def test_totals_rows_use_the_per_trial_means_and_chance_means():
    results = [assemble(rf.tie_world("s04_t00")), assemble(rf.tie_world("s02_t00")), assemble(rf.benign_world())]
    rows = rr.total_rows(results, "development")
    full_hop = next(r for r in rows if r["variant"] == "full" and r["match_reading"] == "hop")
    assert full_hop["attack_trials"] == "2" and full_hop["key_paths"] == "2" and full_hop["key_paths_matched"] == "2"
    assert float(full_hop["top1_expected"]) == pytest.approx(0.5) and float(full_hop["mrr_expected"]) == pytest.approx(2 / 3, abs=1e-6)
    assert float(full_hop["top1_optimistic"]) == 1.0 and float(full_hop["top1_pessimistic"]) == 0.0
    assert float(full_hop["mrr_pessimistic"]) == 0.5
    assert float(full_hop["chance_top1"]) == pytest.approx(0.2) and float(full_hop["chance_mrr"]) == pytest.approx(1 / 3, abs=1e-6)
    assert float(full_hop["chance_rr_mean"]) > float(full_hop["chance_mrr"])
    assert full_hop["s06_held"] == "1" and full_hop["trials_gap_positive"] == "0" and float(full_hop["score_gap_min"]) == pytest.approx(0.0, abs=1e-6)
    b0 = next(r for r in rows if r["row_kind"] == "b0_recall")
    assert b0["attack_trials"] == "2" and float(b0["full_recall_mean"]) == pytest.approx(0.5)


# ================================================================================================ decision 069 item 9: reported beside
def test_first_rr_mean_is_the_expected_reciprocal_position_inside_the_tie_group():
    for r, t, m in ((1, 2, 1), (1, 3, 2), (1, 4, 2), (3, 3, 1), (2, 1, 1)):
        firsts = [next(i for i, x in enumerate(p, 1) if x < m) for p in itertools.permutations(range(t))]
        want = sum(1 / (r - 1 + f) for f in firsts) / len(firsts)
        assert rm.first_rr_mean(r, t, m) == pytest.approx(want), (r, t, m)
    assert rm.first_rr_mean(1, 2, 0) == 0.0 and rm.first_rr_mean(1, 2, 3) == 0.0


def test_placement_rr_mean_beside_the_inverse_of_the_expected_rank():
    pl = rm.placement(group_cands(1, 2), {"G0"})
    assert pl.rr("expected") == pytest.approx(2 / 3) and pl.rr_mean() == pytest.approx(0.75)      # E[1/X] > 1/E[X]
    assert rm.placement(group_cands(1, 2), set()).rr_mean() == 0.0
    assert rm.placement(group_cands(1, 1), {"G0"}).rr_mean() == 1.0


def test_positive_ids_are_the_candidates_with_score_above_zero():
    c = cands([("A", 1, 1, 0.9), ("B", 2, 2, 0.0), ("C", 2, 2, 0.0), ("D", 4, 1, 0.1)])
    assert rm.positive_ids(c) == frozenset({"A", "D"})


def test_totals_report_per_key_mrr_e_one_over_rank_and_the_chance_line_over_positive_candidates():
    """tie_world x5 attack trials: 5 candidates, 4 with score > 0 (P4 = 0), key path K1 -> P1 in a 2-way tie at the top."""
    results = [assemble(rf.tie_world(t)) for t in ("s02_t00", "s03_t00", "s04_t00", "s05_t00", "s07_t00")]
    rows = {(r["variant"], r["match_reading"]): r for r in rr.total_rows(results, "development") if r["row_kind"] == "ranking"}
    hop = rows[("full", "hop")]
    assert float(hop["mrr_expected"]) == pytest.approx(2 / 3, abs=1e-6)
    assert float(hop["mrr_rr_mean_expected"]) == pytest.approx(0.75, abs=1e-6)                 # E[1/rank] inside the tie
    assert float(hop["mrr_per_key_expected"]) == pytest.approx(2 / 3, abs=1e-6)               # 5 key paths, each 1/1.5
    assert float(hop["mrr_per_key_rr_mean"]) == pytest.approx(0.75, abs=1e-6)
    # chance over the 4 candidates with score > 0, 1 match: top-1 1/4, rank 2.5, 1/rank 0.4, E[1/rank] = (1+1/2+1/3+1/4)/4
    assert float(hop["chance_pos_top1"]) == pytest.approx(0.25) and float(hop["chance_pos_mrr"]) == pytest.approx(0.4)
    assert float(hop["chance_pos_rr_mean"]) == pytest.approx((1 + 1 / 2 + 1 / 3 + 1 / 4) / 4, abs=1e-6)
    assert float(hop["chance_mrr"]) == pytest.approx(1 / 3, abs=1e-6)                         # the primary line is unchanged
    node = rows[("full", "node")]                                                                # 2 matches (P1, P5), both > 0
    assert float(node["chance_pos_top1"]) == pytest.approx(0.5) and float(node["chance_pos_mrr"]) == pytest.approx(0.6)
    assert float(node["chance_pos_rr_mean"]) == pytest.approx(0.5 + 2 / 6 / 2 + 1 / 6 / 3, abs=1e-6)


def test_per_key_mrr_differs_from_trial_mrr_when_two_key_paths_share_a_tie_group():
    w = rf.RankWorld(trial="s07_t00")
    w.paths = [rf.P("X", ["H1"], seq_len=2, node=0.25, ident=1.0), rf.P("Y", ["H2"], seq_len=2, node=0.25, ident=1.0),
               rf.P("Z", ["H3"], seq_len=0, edge=0.0)]
    w.key_hops = [rf.KH("K1", "T_H1", 0x100), rf.KH("K2", "T_H2", 0x101)]
    w.key_paths = [rf.KP("KX", "attack", ["K1"]), rf.KP("KY", "attack", ["K2"])]
    row = next(r for r in rr.total_rows([assemble(w)], "development") if r["variant"] == "full" and r["match_reading"] == "hop")
    assert float(row["mrr_expected"]) == 1.0 and float(row["mrr_per_key_expected"]) == pytest.approx(2 / 3, abs=1e-6)
    assert row["key_paths"] == "2" and row["attack_trials"] == "1"
    assert float(row["chance_pos_top1"]) == pytest.approx(2 / 2)             # 2 positive candidates, both matches


def test_total_rows_label_the_two_h4_recall_bases():
    results = [assemble(rf.tie_world())]
    b0 = next(r for r in rr.total_rows(results, "development") if r["row_kind"] == "b0_recall")
    assert b0["recall_basis"] == rr.RECALL_BASIS_ALL and b0["recall_basis_labelled"] == rr.RECALL_BASIS_LABELLED
    assert b0["recall_basis"] != b0["recall_basis_labelled"]
    assert float(b0["full_recall_mean"]) == pytest.approx(0.5) and float(b0["full_recall_labelled_mean"]) == pytest.approx(1 / 3, abs=1e-6)
