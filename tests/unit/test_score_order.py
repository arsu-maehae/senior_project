"""T9 score stage: the order reference and the edge score (spec 05_score SC-10, SC-22, SC-22a, SC-42; SCT-20..23, SCT-42
pin; decisions 062, 066, 067).

Written from the spec and decisions, not from the implementation (the code was read only for its public names).
Hand-computed on a small synthetic table (tactic-PT with consecutive repeats filtered, TPPR p. 5) and on the real
`order_table.json`.

Synthetic table. Techniques A..F, tactics t1..t4, templates
    P1 A B C D   (tactics t1 t2 t2 t3 -> collapsed t1 t2 t3)     P3 C D   (t2 t3)
    P2 A B D     (t1 t2 t3)                                      P4 A E   (t1 t4)
Technique-PT: A -> {B -> {C -> D, D}, E};  C' -> D'.   Tactic-PT: t1 -> {t2 -> t3, t4};  t2' -> t3'.
out(t1) = 2, out(t2) = 2 (two t2 nodes, one child each).
  t1->t2 = 1/2   t1->t3 = (1/2)/2   t1->t4 = 1/2   t2->t3 = 2/2 = 1   t3->t1 = 0   same tactic = b.
Without the collapse, t2->t3 would be 3.5/4 = 0.875 (checked below: the filter is what makes it 1).
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from score import order as od  # noqa: E402
from score import params as sp  # noqa: E402
from score.errors import ScoreError  # noqa: E402

P = sp.ScoreParams()


def table_bytes(templates, tactic_of) -> bytes:
    return json.dumps({"tactic_of": tactic_of, "templates": [
        {"id": f"P{i}", "techniques": t, "sources": ["synthetic"]} for i, t in enumerate(templates, 1)]}).encode()


SYN_TACTICS = {"A": "t1", "B": "t2", "C": "t2", "D": "t3", "E": "t4", "F": "t1"}
SYN_TEMPLATES = [["A", "B", "C", "D"], ["A", "B", "D"], ["C", "D"], ["A", "E"]]


@pytest.fixture(scope="module")
def syn():
    return od.build_reference(od.parse_order_table(table_bytes(SYN_TEMPLATES, SYN_TACTICS)))


@pytest.fixture(scope="module")
def real():
    return od.build_reference(od.load_order_table())


def leaf_paths(tree) -> set[tuple[str, ...]]:
    out = set()

    def walk(n, acc):
        kids = tree.children[n]
        if not kids:
            out.add(tuple(acc))
        for c in kids:
            walk(c, acc + [tree.labels[c]])
    walk(0, [])
    return out


# ------------------------------------------------------------------------------------------------ trees (SC-22a)
def test_technique_tree_merges_shared_prefixes(syn):
    t = syn.tech_tree
    assert leaf_paths(t) == {("A", "B", "C", "D"), ("A", "B", "D"), ("A", "E"), ("C", "D")}
    assert len(t.labels) - 1 == 8                       # A B C D D E C' D' : A and B shared by three templates


def test_tactic_tree_filters_consecutive_repeated_tactics_before_merging(syn):
    t = syn.tac_tree
    assert leaf_paths(t) == {("t1", "t2", "t3"), ("t1", "t4"), ("t2", "t3")}
    assert len(t.labels) - 1 == 6                       # t1 t2 t3 t4 t2' t3'


def test_collapse_repeats_unit():
    assert od.collapse_repeats(["a", "b", "b", "c"]) == ("a", "b", "c")
    assert od.collapse_repeats(["a", "a", "a"]) == ("a",)
    assert od.collapse_repeats([]) == ()
    assert od.collapse_repeats(["a", "b", "a"]) == ("a", "b", "a")      # only CONSECUTIVE repeats go


def test_without_the_filter_the_tactic_score_would_be_0875_so_the_filter_is_observable():
    raw = od.build_prefix_tree([[SYN_TACTICS[x] for x in t] for t in SYN_TEMPLATES])
    unfiltered = od.tactic_score(raw, "t2", "t3", 1.0)
    assert unfiltered == pytest.approx(0.875)
    filtered = od.tactic_score(od.tactic_tree(od.parse_order_table(table_bytes(SYN_TEMPLATES, SYN_TACTICS))),
                               "t2", "t3", 1.0)
    assert filtered == pytest.approx(1.0)


def test_out_degree_sums_children_over_all_nodes_with_the_label(syn):
    assert od.out_degree(syn.tac_tree, "t1") == 2
    assert od.out_degree(syn.tac_tree, "t2") == 2
    assert od.out_degree(syn.tac_tree, "t3") == 0


def test_path_lengths_start_from_any_node_with_the_label(syn):
    assert sorted(od.path_lengths(syn.tac_tree, "t2", "t3")) == [1, 1]
    assert od.path_lengths(syn.tac_tree, "t1", "t3") == [2]
    assert sorted(od.path_lengths(syn.tech_tree, "A", "D")) == [2, 3]
    assert od.path_lengths(syn.tech_tree, "D", "A") == []


# ------------------------------------------------------------------------------------------------ Eq. 2 / 3 / 5
@pytest.mark.parametrize("ta,tb,expect", [
    ("t1", "t2", 0.5), ("t1", "t3", 0.25), ("t1", "t4", 0.5), ("t2", "t3", 1.0),
    ("t3", "t1", 0.0),                     # no downward path
    ("t2", "t2", 1.0), ("t1", "t1", 1.0),  # same tactic = b (Fig. 6a reading)
    ("t3", "t3", 1.0),
])
def test_eq2_tactic_score(syn, ta, tb, expect):
    assert od.tactic_score(syn.tac_tree, ta, tb, 1.0) == pytest.approx(expect)


def test_eq2_tactic_score_scales_with_b_and_never_exceeds_it(syn):
    assert od.tactic_score(syn.tac_tree, "t1", "t2", 3.0) == pytest.approx(1.5)
    assert od.tactic_score(syn.tac_tree, "t2", "t2", 3.0) == pytest.approx(3.0)
    for a in ("t1", "t2", "t3", "t4"):
        for b in ("t1", "t2", "t3", "t4"):
            assert 0.0 <= od.tactic_score(syn.tac_tree, a, b, 1.0) <= 1.0


def test_eq2_unknown_or_empty_tactic_scores_zero(syn):
    assert od.tactic_score(syn.tac_tree, "", "", 1.0) == 0.0
    assert od.tactic_score(syn.tac_tree, "t1", "", 1.0) == 0.0
    assert od.tactic_score(syn.tac_tree, "zz", "t1", 1.0) == 0.0


@pytest.mark.parametrize("u,v,expect", [
    ("A", "B", 1.0), ("A", "E", 1.0), ("B", "C", 1.0), ("B", "D", 1.0), ("C", "D", 1.0),   # direct
    ("A", "C", 0.5), ("A", "D", 0.5),       # indirect: max over paths of 1/len, len >= 2 (A->D: 1/2 and 1/3)
    ("D", "A", 0.01), ("C", "B", 0.01),     # absent -> eps
])
def test_eq3_technique_score(syn, u, v, expect):
    assert od.technique_score(syn.tech_tree, u, v, 1.0, 0.01) == pytest.approx(expect)


def test_eq3_scale_a_and_eps_floor(syn):
    assert od.technique_score(syn.tech_tree, "A", "B", 2.0, 0.01) == pytest.approx(2.0)
    assert od.technique_score(syn.tech_tree, "D", "A", 2.0, 0.05) == pytest.approx(0.1)


# (u, v) -> (tactic_score, technique_score, score_e, basis)
SYN_STEPS = {
    ("A", "B"): (0.5, 1.0, 0.75, "direct"),
    ("A", "C"): (0.5, 0.5, 0.5, "indirect"),
    ("A", "D"): (0.25, 0.5, 0.375, "indirect"),
    ("A", "E"): (0.5, 1.0, 0.75, "direct"),
    ("B", "C"): (1.0, 1.0, 1.0, "direct"),          # direct wins over same tactic
    ("B", "D"): (1.0, 1.0, 1.0, "direct"),
    ("C", "D"): (1.0, 1.0, 1.0, "direct"),
    ("D", "A"): (0.0, 0.01, 0.005, "absent"),
    ("C", "B"): (1.0, 0.01, 0.505, "same_tactic"),  # no template path, same tactic: tactic b, technique eps
    ("A", "F"): (1.0, 0.01, 0.505, "absent"),       # F is in no template: absent, tactic from tactic_of still applies
    ("F", "A"): (1.0, 0.01, 0.505, "absent"),
    ("Q", "A"): (0.0, 0.01, 0.005, "absent"),       # unknown technique: no tactic at all
}


@pytest.mark.parametrize("uv,expect", sorted(SYN_STEPS.items()))
def test_eq5_score_step_and_basis(syn, uv, expect):
    s = od.score_step(syn, uv[0], uv[1], P)
    assert (s.tactic_score, s.technique_score) == pytest.approx(expect[:2])
    assert s.score_e == pytest.approx(expect[2])
    assert s.basis == expect[3]


def test_eq5_score_e_is_alpha_tactic_plus_beta_technique(syn):
    p = sp.ScoreParams(alpha=0.7, beta=0.3)
    s = od.score_step(syn, "A", "B", p)
    assert s.score_e == pytest.approx(0.7 * 0.5 + 0.3 * 1.0)


def test_hop_chain_step_is_direct_alpha_b_plus_beta_a(syn):
    s = od.hop_chain_step(syn, "T1569.002", "T1078", P)
    assert s.basis == "hop_chain" and s.score_e == pytest.approx(1.0)
    p = sp.ScoreParams(a=1.0, b=2.0)
    assert od.hop_chain_step(syn, "A", "B", p).score_e == pytest.approx(0.5 * 2.0 + 0.5 * 1.0)


def test_stage_positions_are_the_smallest_template_position(syn):
    st = syn.stage
    assert st["A"] == 0 and st["C"] == 0 and st["B"] == 1 and st["D"] == 1 and st["E"] == 1   # D: position 2 in P1, 1 in P3
    assert "F" not in st


# ------------------------------------------------------------------------------------------------ the real table
def test_real_stage_order_puts_execution_after_lateral_movement_by_template_position(real):
    st = real.stage
    assert st["T1021.002"] < st["T1570"] < st["T1569.002"]            # not ATT&CK tactic-id order (SC-21 order trap)
    assert st["T1078"] < st["T1021.006"]
    assert "T1550.002" not in st                                      # spec 5.1: in no template


def test_real_tactic_tree_is_the_filtered_templates(real):
    assert leaf_paths(real.tac_tree) == {("initial-access", "credential-access", "lateral-movement", "execution"),
                                         ("credential-access", "lateral-movement", "execution")}
    assert od.tactic_score(real.tac_tree, "lateral-movement", "execution", 1.0) == pytest.approx(1.0)   # LM->EX = b
    assert od.tactic_score(real.tac_tree, "initial-access", "lateral-movement", 1.0) == pytest.approx(0.5)


@pytest.mark.parametrize("u,v,score_e,basis", [
    ("T1021.002", "T1570", 1.0, "direct"),
    ("T1570", "T1569.002", 1.0, "direct"),
    ("T1021.002", "T1569.002", 1.0, "direct"),
    ("T1003.001", "T1021.002", 1.0, "direct"),
    ("T1078", "T1003.001", 1.0, "direct"),
    ("T1078", "T1021.006", 0.5, "indirect"),                 # WinRM hop: IA->LM 1/2, T1078>T1003>T1021.006 len 2
    ("T1078", "T1569.002", 1.0 / 3.0, "indirect"),           # len 3 both in technique and tactic trees
    ("T1021.006", "T1078", 0.005, "absent"),
    ("T1021.002", "T1021.006", 0.505, "same_tactic"),
    ("T1550.002", "T1021.002", 0.505, "absent"),             # in no template (spec 5.1 Q4): technique eps
    ("T1021.002", "T1550.002", 0.505, "absent"),
    ("T1569.002", "T1021.002", 0.005, "absent"),             # reverse of PsExec order
])
def test_real_table_step_scores(real, u, v, score_e, basis):
    s = od.score_step(real, u, v, P)
    assert s.score_e == pytest.approx(score_e)
    assert s.basis == basis


def test_every_template_cites_a_source_and_every_technique_has_a_tactic():
    obj = json.loads(sp.ORDER_TABLE_FILE.read_text(encoding="utf-8"))
    assert len(obj["templates"]) == 5
    for t in obj["templates"]:
        assert t["sources"], t["id"]
        assert all(x in obj["tactic_of"] for x in t["techniques"])
    assert obj["tactic_of"]["T1078"] == "initial-access" and obj["tactic_of"]["T1569.002"] == "execution"


# ------------------------------------------------------------------------------------------------ table validation
@pytest.mark.parametrize("bad", [
    b"not json", b"[]", json.dumps({"templates": [], "tactic_of": {}}).encode(),
    json.dumps({"tactic_of": {"A": "t"}, "templates": [{"id": "X", "techniques": ["A"]}]}).encode(),    # no sources
    json.dumps({"tactic_of": {}, "templates": [{"id": "X", "techniques": ["A"], "sources": ["s"]}]}).encode(),   # no tactic
    json.dumps({"tactic_of": {"A": "t"}, "templates": [{"id": "X", "techniques": ["A", "A"], "sources": ["s"]}]}).encode(),
])
def test_parse_order_table_refuses_malformed_tables(bad):
    with pytest.raises(ScoreError):
        od.parse_order_table(bad)


def test_load_order_table_refuses_a_changed_table(tmp_path):
    data = sp.ORDER_TABLE_FILE.read_bytes()
    changed = tmp_path / "order_table.json"
    obj = json.loads(data.decode("utf-8"))
    obj["templates"].append({"id": "R6", "techniques": ["T1078", "T1021.002"], "sources": ["x"]})
    changed.write_text(json.dumps(obj, indent=1), encoding="utf-8")
    with pytest.raises(ScoreError, match="refused"):
        od.load_order_table(changed)
    with pytest.raises(ScoreError, match="refused"):
        od.load_order_table(tmp_path / "missing.json")


def test_load_order_table_is_independent_of_line_ends(tmp_path):
    crlf = tmp_path / "t.json"
    crlf.write_bytes(sp.ORDER_TABLE_FILE.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert od.load_order_table(crlf).sha256 == sp.ORDER_TABLE_SHA256


# ------------------------------------------------------------------------------------------------ SC-42 / SCT-42 pin
def test_frozen_parameter_values_equal_decision_066():
    import math
    p = sp.ScoreParams()
    assert p.lam == pytest.approx(1.0 / math.log(2.0), rel=1e-12)
    assert 1.0 - math.exp(-1.0 / p.lam) == pytest.approx(0.5)          # one transition -> length factor 0.5
    assert (p.w1, p.w2, p.w3) == pytest.approx((1 / 3, 1 / 3, 1 / 3))
    assert math.fsum((p.w1, p.w2, p.w3)) == pytest.approx(1.0)
    assert (p.alpha, p.beta, p.a, p.b, p.eps) == (0.5, 0.5, 1.0, 1.0, 0.01)
    assert p.order_tol_s == 5.0


def test_order_table_hash_is_the_lf_normalised_file_hash_and_the_decision_067_value():
    data = sp.ORDER_TABLE_FILE.read_bytes()
    independent = hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()
    assert sp.ORDER_TABLE_SHA256 == independent
    assert od.lf_sha256(data) == independent
    text = (REPO / "docs" / "decisions" / "067-score-implementation-readings.md").read_text(encoding="utf-8")
    assert re.search(r"\b" + independent + r"\b", text), "decision 067 must state the pinned hash"


@pytest.mark.parametrize("kw", [dict(w1=0.5, w2=0.5, w3=0.5), dict(w1=-0.1, w2=0.6, w3=0.5), dict(alpha=0.6, beta=0.6),
                                dict(lam=0.0), dict(a=0.0), dict(eps=0.0)])
def test_score_params_refuse_values_the_spec_forbids(kw):
    with pytest.raises(ValueError):
        sp.ScoreParams(**kw)


def test_development_allowlist_is_the_nine_shared_trials():
    from clock_offset.params import DEVELOPMENT_TRIALS
    assert sp.ALLOWED_TRIALS == DEVELOPMENT_TRIALS
    assert len(DEVELOPMENT_TRIALS) == 9
    assert all(not t.endswith(("_t02", "_t03", "_t10")) for t in sp.ALLOWED_TRIALS)
