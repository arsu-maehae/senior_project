"""T10.A part A: the decision 070 / 071 readings in `evaluate --rank` (spec 06_evaluate EV-01..EV-08, section 6 edge cases
ATK-EV-01, -03, -05, -06, -12, -14, open question Q5; decisions 070, 071, 072).

Written from the spec, the decisions and the answer keys, not from the code (the pure assembly `rank_from_inputs`, the
`rank_report` row builders and the CLI `evaluate.__main__.main` are only the way to reach the files). Synthetic worlds come
from `results_fixtures` (hand-computed in its docstrings). Nothing under the real `out/`, `data/` or `ground_truth/` is
opened; the fake repos live in pytest tmp folders.

Test ids follow the spec: EVT-01 (primary MRR per key), EVT-02 (labelled recall, 071 denominator), EVT-03 (contested sets,
b0 after ST-05 merge, zero contested trials), EVT-04 (only positive candidate is a rival; paired reading), EVT-05 (per-key
chance line), EVT-06 (full and b1 sets differ), EVT-07 (row kinds and column compatibility), EVT-08 (denominator world),
Q5 (node reading decides, hop beside).
"""
from __future__ import annotations

import csv
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
from evaluate import rank_report as rr  # noqa: E402
from evaluate.params import DEVELOPMENT_TRIALS  # noqa: E402

# The column lists before spec 06 (committed at 893eff2): EV-07 "every other column ... unchanged".
OLD_RANK_COLUMNS = [
    "status_note", "trial_id", "split", "keyed", "row_kind", "variant", "match_reading", "key_path_id", "key_role",
    "key_hop_ids", "mapped_hop_ids", "unmatched_key_hops", "method", "threshold", "n_candidates", "candidate_count",
    "matched_path_ids", "matched_jaccards", "first_match_path_ids", "first_rank", "tie_size", "matches_in_tie",
    "rank_expected", "rank_optimistic", "rank_pessimistic", "rr_expected", "rr_optimistic", "rr_pessimistic",
    "rr_mean_expected", "top1_expected", "top1_optimistic", "top1_pessimistic", "chance_top1", "chance_rank_expected",
    "chance_rr", "chance_rr_mean", "n_candidates_positive", "chance_pos_top1", "chance_pos_rank_expected",
    "chance_pos_rr", "chance_pos_rr_mean", "first_match_score", "key_attack_score_min", "other_score_max",
    "other_max_path_ids", "score_gap", "key_node_count", "supporting_event_uids", "time_delta_ms", "k", "budget_nodes",
    "full_recall", "b0_recall", "budget_nodes_labelled", "full_recall_labelled", "b0_recall_labelled", "score_max",
    "score_min", "score_mean", "n_zero_score", "n_distinct_scores", "top_tie_size"]
OLD_TOTAL_COLUMNS = [
    "status_note", "split", "row_kind", "variant", "match_reading", "attack_trials", "key_paths", "key_paths_matched",
    "top1_expected", "top1_optimistic", "top1_pessimistic", "mrr_expected", "mrr_optimistic", "mrr_pessimistic",
    "mrr_rr_mean_expected", "mrr_per_key_expected", "mrr_per_key_rr_mean", "chance_top1", "chance_mrr",
    "chance_rr_mean", "chance_pos_top1", "chance_pos_mrr", "chance_pos_rr_mean", "score_gap_min",
    "trials_gap_positive", "s06_trials", "s06_max_score", "key_attack_score_min", "s06_margin", "s06_held",
    "share_attack_trials_above_s06", "recall_basis", "full_recall_mean", "b0_recall_mean", "recall_basis_labelled",
    "full_recall_labelled_mean", "b0_recall_labelled_mean", "trials_full_above_b0", "trials_full_above_b0_labelled"]
NOT_SCORED = "uncontested — key path not scored"
ONLY_SCORED = "uncontested — key path the only scored path"


def totals(trials, split="development"):
    return rr.total_rows(trials, split)


def pick(rows, **want):
    out = [r for r in rows if all(r[k] == v for k, v in want.items())]
    return out


def one(rows, **want):
    (r,) = pick(rows, **want)
    return r


def rank_rows(tr):
    return rr.trial_rows(tr)


def b0_row(tr):
    return one(rank_rows(tr), row_kind="b0_recall")


def trial_row(tr, variant="full", reading="node"):
    return one(rank_rows(tr), row_kind="trial", variant=variant, match_reading=reading)


# ================================================================================================ EVT-01 per-key MRR primary
def test_evt01_per_key_mrr_is_each_key_paths_own_expected_rr_averaged_over_key_paths_and_per_trial_mrr_is_beside():
    """Two key attack paths in one trial: K1 ranks 1 (RR 1.0), K2 ranks 2 (RR 0.5) -> per-key MRR 0.75; the per-trial MRR
    is the first match of either (rank 1, RR 1.0). Primary column `mrr_per_key_expected`, per-trial `mrr_expected` beside."""
    tr = R.assemble(R.two_key_world("s07_t00"))
    row = one(totals([tr]), row_kind="ranking", variant="full", match_reading="node")
    assert row["mrr_per_key_expected"] == "0.750000" and row["mrr_expected"] == "1.000000"
    assert row["key_paths"] == "2" and row["attack_trials"] == "1"
    assert row["primary_metric"] == "mrr_per_key_expected"
    keys = {r["key_path_id"]: r for r in rank_rows(tr) if r["row_kind"] == "key_path" and r["variant"] == "full"
            and r["match_reading"] == "node"}
    assert keys["K1-path"]["rr_expected"] == "1.000000" and keys["K2-path"]["rr_expected"] == "0.500000"


def test_evt01_a_two_way_tie_at_the_top_counts_rank_one_and_a_half_for_the_key_path_in_the_primary_reading():
    """s04-like: the key path ties a rival at rank 1 -> expected rank 1.5, RR 0.666667 in per-key MRR (065 tie rule)."""
    tr = R.assemble(rf.tie_world("s04_t00"))
    row = one(totals([tr]), row_kind="ranking", variant="full", match_reading="node")
    assert row["mrr_per_key_expected"] == "0.666667"
    assert [r for r in rank_rows(tr) if r["row_kind"] == "key_path" and r["variant"] == "full"
            and r["match_reading"] == "node"][0]["rank_expected"] == "1.500000"


# ================================================================================================ EVT-02 / EVT-08 071 denominator
def test_evt08_denominator_is_the_labelled_key_nodes_four_key_nodes_two_labelled_full_holds_both_gives_one():
    """ATK-EV-01 / 071: 4 key nodes, 2 of them inside a b0 unit; full's labelled top-1 path holds both -> labelled recall
    1.0 (the old denominator, all 4 key nodes, gave 0.5). b0 at the equal budget of 2 nodes takes u1 (a1) and u2 (x1)."""
    tr = R.assemble(R.labelled_world("s02_t00", labelled=True))
    b = b0_row(tr)
    assert b["key_node_count"] == "4" and b["key_nodes_labelled"] == "2"
    assert b["full_recall_labelled"] == "1.000000" and b["b0_recall_labelled"] == "0.500000"
    assert b["budget_nodes_labelled"] == "2.000000"
    # the all-node basis keeps its denominator (all key nodes) and is reported beside, unchanged
    assert b["full_recall"] == "1.000000" and b["b0_recall"] == "0.500000" and b["budget_nodes"] == "4.000000"


def test_evt02_trial_without_a_labelled_key_node_is_undefined_left_out_of_the_mean_and_the_count_is_reported():
    """No key node of the trial lies in a b0 unit: labelled recall undefined (empty cells), not 0; the mean is over the
    defined trials only; the count that entered the mean is in the totals row."""
    good = R.assemble(R.labelled_world("s02_t00", labelled=True))
    none = R.assemble(R.labelled_world("s03_t00", labelled=False))
    b = b0_row(none)
    assert b["key_nodes_labelled"] == "0" and b["full_recall_labelled"] == "" and b["b0_recall_labelled"] == ""
    assert b["full_recall"] == "1.000000"                    # the all-node basis is still defined for that trial
    row = one(totals([good, none]), row_kind="b0_recall")
    assert row["attack_trials"] == "2" and row["labelled_recall_trials"] == "1"
    assert row["full_recall_labelled_mean"] == "1.000000" and row["b0_recall_labelled_mean"] == "0.500000"
    assert row["trials_full_above_b0_labelled"] == "1"
    # the all-node means still run over both trials: full (1 + 1) / 2, b0 (0.5 + 0) / 2
    assert (row["full_recall_mean"], row["b0_recall_mean"]) == ("1.000000", "0.250000")


def test_evt02_all_trials_without_labelled_key_nodes_give_an_empty_labelled_mean_not_zero():
    none = R.assemble(R.labelled_world("s03_t00", labelled=False))
    row = one(totals([none]), row_kind="b0_recall")
    assert row["attack_trials"] == "1" and row["labelled_recall_trials"] == "0"
    assert row["full_recall_labelled_mean"] == "" and row["b0_recall_labelled_mean"] == ""


def test_evt02_h4_primary_metric_is_the_labelled_recall_and_the_all_node_recall_stays_beside():
    row = one(totals([R.assemble(R.labelled_world("s02_t00"))]), row_kind="b0_recall")
    assert "full_recall_labelled_mean" in row["primary_metric"] and "b0_recall_labelled_mean" in row["primary_metric"]
    assert row["reading_scope"] == "all"
    for col in ("full_recall_mean", "b0_recall_mean", "trials_full_above_b0", "trials_full_above_b0_labelled"):
        assert col in row


# ================================================================================================ EVT-03 contested sets
def test_evt03_contested_is_more_than_one_candidate_with_written_score_above_zero_per_variant():
    """tie_world: full 4 positive candidates, b1 4, b2 4 -> contested. solo_world: one positive in every variant."""
    tw = R.assemble(rf.tie_world("s04_t00"))
    solo = R.assemble(R.solo_world("s02_t00"))
    for variant in ("full", "b1", "b2"):
        assert trial_row(tw, variant)["contested"] == "1", variant
        assert trial_row(solo, variant)["contested"] == "0", variant
    assert b0_row(tw)["contested"] == "1" and b0_row(solo)["contested"] == "0"


def test_evt03_contested_rows_cover_the_contested_trials_only_and_sit_beside_the_primary_rows():
    tw = R.assemble(rf.tie_world("s04_t00"))
    solo = R.assemble(R.solo_world("s02_t00"))
    rows = totals([solo, tw])
    prim = one(rows, row_kind="ranking", variant="full", match_reading="node")
    cont = one(rows, row_kind="ranking_contested", variant="full", match_reading="node", contested_set="full")
    assert prim["attack_trials"] == "2" and prim["reading_scope"] == "all"
    assert cont["attack_trials"] == "1" and cont["reading_scope"] == "contested"
    # solo: top-1 1.0, tie_world: 0.5 -> primary 0.75; contested only tie_world -> 0.5; primary is never replaced
    assert prim["top1_expected"] == "0.750000" and cont["top1_expected"] == "0.500000"
    assert cont["mrr_per_key_expected"] == "0.666667"


def test_evt03_b0_counted_after_st05_copies_are_merged_one_unit_not_two():
    """ATK-EV-14: two b0 units with score 1.0 that hold the representative T_H1 and its ST-05 copy T_H1c are one labelled
    unit after the merge -> not contested, n_positive_units 1. Two units that hold different nodes are contested."""
    merged = R.assemble(R.copy_world("s02_t00", distinct=False))
    b = b0_row(merged)
    assert b["n_positive_units"] == "1" and b["contested"] == "0"
    split = R.assemble(R.copy_world("s03_t00", distinct=True))
    b = b0_row(split)
    assert b["n_positive_units"] == "2" and b["contested"] == "1"
    rows = totals([merged, split])
    assert one(rows, row_kind="b0_recall_contested", contested_set="b0")["attack_trials"] == "1"


def test_evt03_zero_contested_trials_writes_the_row_with_attack_trials_zero_and_empty_metrics():
    solo = R.assemble(R.solo_world("s02_t00"))
    rows = totals([solo])
    for variant in ("full", "b1", "b2"):
        r = one(rows, row_kind="ranking_contested", variant=variant, match_reading="node", contested_set=variant)
        assert r["attack_trials"] == "0", variant
        for col in ("top1_expected", "mrr_expected", "mrr_per_key_expected", "chance_top1", "chance_per_key_mrr"):
            assert r[col] == "", (variant, col)
    b = one(rows, row_kind="b0_recall_contested", contested_set="b0")
    assert b["attack_trials"] == "0" and b["full_recall_labelled_mean"] == "" and b["b0_recall_labelled_mean"] == ""


def test_evt03_trials_left_out_are_listed_with_the_reason_in_rank_md(tmp_path):
    root = tmp_path / "r"
    R.write_repo_with(root, R.solo_world("s02_t00"))
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 0
    md = (root / "out" / "evaluate" / "development" / "rank.md").read_text(encoding="utf-8")
    left = [ln for ln in md.splitlines() if "s02_t00" in ln and "uncontested" in ln]
    assert left, "s02_t00 is uncontested and must be listed with a reason"
    assert any(ONLY_SCORED in ln for ln in left)
    assert not [ln for ln in md.splitlines() if "uncontested" in ln and "s04_t00" in ln]      # tie_world is contested


# ================================================================================================ EVT-04 rival-only and pairing
def test_evt04_only_positive_candidate_is_a_rival_is_named_uncontested_key_path_not_scored():
    """ATK-EV-05: the key path P1 scores 0 in every variant and the only positive candidate is the rival P2."""
    tr = R.assemble(R.rival_only_world("s03_t00"))
    for variant in ("full", "b1", "b2"):
        assert trial_row(tr, variant)["contested"] == "0"
    reasons = {(r["variant"], r["match_reading"]): r["reason"] for r in rr.uncontested_rows([tr]) if r["variant"] != "b0"}
    assert len(reasons) == 6 and set(reasons.values()) == {NOT_SCORED}
    # and the failure is still visible in the primary reading: the key path is not first
    assert trial_row(tr, "full")["top1_expected"] == "0.000000"


def test_evt04_rival_only_trial_is_named_in_rank_md_and_a_solo_trial_gets_the_other_reason(tmp_path):
    root = tmp_path / "r"
    R.write_repo_with(root, R.rival_only_world("s03_t00"), R.solo_world("s02_t00"))
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 0
    md = (root / "out" / "evaluate" / "development" / "rank.md").read_text(encoding="utf-8")
    assert any(NOT_SCORED in ln and "s03_t00" in ln for ln in md.splitlines())
    assert not any(NOT_SCORED in ln and "s02_t00" in ln for ln in md.splitlines())
    assert any(ONLY_SCORED in ln and "s02_t00" in ln for ln in md.splitlines())


def test_evt04_b0_contested_reading_covers_the_h4_recall_only_no_path_metric_row_for_b0():
    rows = totals([R.assemble(rf.tie_world("s04_t00"))])
    assert not pick(rows, row_kind="ranking_contested", variant="b0")
    assert not pick(rows, row_kind="ranking", variant="b0")
    b = one(rows, row_kind="b0_recall_contested", contested_set="b0")
    assert b["variant"] == "full_vs_b0" and "top1_expected" in b and b["top1_expected"] == ""
    assert b["mrr_per_key_expected"] == "" and b["full_recall_labelled_mean"] != ""


# ================================================================================================ EVT-05 per-key chance line
def test_evt05_per_key_chance_line_uses_m_k_per_key_path_not_the_per_trial_union_n_six_two_key_paths():
    """ATK-EV-03, n = 6: K1 is matched by 1 candidate, K2 by 2 (the union has 3). chance_line(6, m): RR = 2/(7)... =
    1 / ((n + 1) / (m + 1)): m = 1 -> 2/7 = 0.285714, m = 2 -> 3/7 = 0.428571, m = 3 -> 4/7 = 0.571429. The per-key chance
    is the mean of the first two (0.357143), not the union's 0.571429. Over the 3 scored candidates: m_k 1 and 2 ->
    0.5 and 0.75 -> 0.625 (the union m = 3 would give 1.0)."""
    tr = R.assemble(R.two_key_world("s07_t00"))
    row = one(totals([tr]), row_kind="ranking", variant="full", match_reading="node")
    assert row["chance_per_key_mrr"] == "0.357143"
    assert row["chance_mrr"] == "0.571429"                                    # per-trial union, reported beside
    assert row["chance_pos_per_key_mrr"] == "0.625000" and row["chance_pos_mrr"] == "1.000000"
    keys = {r["key_path_id"]: r for r in rank_rows(tr) if r["row_kind"] == "key_path" and r["variant"] == "full"
            and r["match_reading"] == "node"}
    assert keys["K1-path"]["candidate_count"] == "1" and keys["K2-path"]["candidate_count"] == "2"
    assert keys["K1-path"]["chance_rr"] == "0.285714" and keys["K2-path"]["chance_rr"] == "0.428571"
    assert keys["K1-path"]["chance_pos_rr"] == "0.500000" and keys["K2-path"]["chance_pos_rr"] == "0.750000"


def test_evt05_contested_rows_carry_the_chance_line_over_the_contested_trials_only():
    """solo (chance MRR 2/3 over 2 candidates, one match) and tie_world (n = 5, one match, hop reading 1/3; node reading
    matches 2 -> 0.5): the contested chance line is tie_world's alone."""
    solo = R.assemble(R.solo_world("s02_t00"))
    tw = R.assemble(rf.tie_world("s04_t00"))
    rows = totals([solo, tw])
    prim = one(rows, row_kind="ranking", variant="full", match_reading="node")
    cont = one(rows, row_kind="ranking_contested", variant="full", match_reading="node", contested_set="full")
    assert cont["chance_mrr"] == "0.500000" and cont["chance_top1"] == "0.400000"
    assert prim["chance_mrr"] != cont["chance_mrr"]
    assert cont["chance_pos_mrr"] != "" and cont["chance_per_key_mrr"] != "" and cont["chance_pos_per_key_mrr"] != ""


def md_tables(md: str) -> list[tuple[str, list[str]]]:
    """(header line, body lines) of every Markdown table in `md`."""
    lines = md.splitlines()
    out = []
    for i, ln in enumerate(lines[:-1]):
        if ln.startswith("| ") and lines[i + 1].startswith("|---"):
            body = []
            for nxt in lines[i + 2:]:
                if not nxt.startswith("|"):
                    break
                body.append(nxt)
            out.append((ln, body))
    return out


def test_evt05_every_rank_md_table_with_a_ranking_metric_shows_both_chance_lines(tmp_path):
    """EV-05: a table that shows top-1 / MRR / reciprocal rank shows the chance line over all candidates and over those with
    score > 0 (columns chance_* and chance_pos_*, or a per-key n_pos column that the pos chance is computed from)."""
    root = tmp_path / "r"
    rf.development_repo(root)
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 0
    md = (root / "out" / "evaluate" / "development" / "rank.md").read_text(encoding="utf-8")
    ranking_tables = [h for h, _b in md_tables(md)
                      if any(w in h for w in ("top1", "mrr", "rr_exp", "rr_opt")) and "recall" not in h]
    assert len(ranking_tables) >= 4, ranking_tables
    for header in ranking_tables:
        assert "chance" in header and "chance_pos" in header, header


# ================================================================================================ EVT-06 sets differ
@pytest.fixture(scope="module")
def sets_differ():
    a = R.assemble(R.half_contested_world("s02_t00"))      # full contested, b1 and b2 not
    b = R.assemble(rf.tie_world("s04_t00"))                # contested in every variant
    return [a, b]


def test_evt06_full_and_b1_contested_sets_differ(sets_differ):
    a, b = sets_differ
    assert trial_row(a, "full")["contested"] == "1" and trial_row(a, "b1")["contested"] == "0"
    assert trial_row(a, "b2")["contested"] == "0"
    assert rr.contested_ids(sets_differ, "full") == ("s02_t00", "s04_t00")
    assert rr.contested_ids(sets_differ, "b1") == ("s04_t00",)


def test_evt06_paired_comparison_uses_fulls_set_for_both_sides_and_each_own_set_is_beside(sets_differ):
    rows = totals(sets_differ)
    full = one(rows, row_kind="ranking_contested", variant="full", match_reading="node", contested_set="full")
    b1_paired = one(rows, row_kind="ranking_contested", variant="b1", match_reading="node", contested_set="full")
    b1_own = one(rows, row_kind="ranking_contested", variant="b1", match_reading="node", contested_set="b1")
    b2_own = one(rows, row_kind="ranking_contested", variant="b2", match_reading="node", contested_set="b2")
    assert full["attack_trials"] == b1_paired["attack_trials"] == "2"
    assert b1_paired["scope_trial_ids"] == full["scope_trial_ids"] == "s02_t00;s04_t00"
    assert b1_own["attack_trials"] == "1" and b1_own["scope_trial_ids"] == "s04_t00"
    assert b2_own["attack_trials"] == "1"
    # per-key MRR by hand: full A 1.0, B 0.666667 -> 0.833333; b1 on the same two trials 1.0 and 0.666667 -> 0.833333;
    # b1's own set (B only) -> 0.666667 (a different number: the own set is not the paired set)
    assert full["mrr_per_key_expected"] == b1_paired["mrr_per_key_expected"] == "0.833333"
    assert b1_own["mrr_per_key_expected"] == "0.666667"
    # H4 likewise: full's set (A, B) paired, b0's own set beside
    h4_full = one(rows, row_kind="b0_recall_contested", contested_set="full")
    h4_b0 = one(rows, row_kind="b0_recall_contested", contested_set="b0")
    assert h4_full["attack_trials"] == "2" and h4_b0["attack_trials"] == "1"


def test_evt06_results_contested_rows_are_paired_on_fulls_set_own_sets_beside_and_never_carry_a_verdict(sets_differ):
    from evaluate.results_report import results_files
    files = results_files(sets_differ, "development")
    rows = list(csv.DictReader(io.StringIO(files["results.csv"])))
    contested = [r for r in rows if r["reading_scope"] == "contested"]
    assert contested and all(r["dev_check"] == "" for r in contested)
    diff = [r for r in contested if r["table"] == "H3" and r["variant"] == "full_vs_b1"]
    assert len(diff) == 1 and diff[0]["n_trials"] == "2" and diff[0]["observed"] == "0.000000"
    own = [r for r in contested if r["table"] == "H3" and r["variant"] == "b1" and r["n_trials"] == "1"]
    assert len(own) == 1 and own[0]["observed"] == "0.666667"
    h4 = [r for r in contested if r["table"] == "H4" and r["metric"] == "recall_labelled_mean_difference"]
    assert sorted(r["n_trials"] for r in h4) == ["1", "1"] or {r["n_trials"] for r in h4} <= {"1", "2"}
    primary = [r for r in rows if r["is_primary"] == "1"]
    assert all(r["reading_scope"] == "all" for r in primary)


# ================================================================================================ EVT-07 row kinds
def test_evt07_new_row_kinds_leave_the_existing_ranking_and_b0_recall_rows_and_counts_unchanged(tmp_path):
    root = tmp_path / "r"
    rf.development_repo(root)
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 0
    with open(root / "out" / "evaluate" / "development" / "rank_totals.csv", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        header = list(reader.fieldnames or [])
        rows = list(reader)
    assert header[:len(OLD_TOTAL_COLUMNS)] == OLD_TOTAL_COLUMNS            # earlier columns kept in place
    assert {"reading_scope", "primary_metric"} <= set(header)
    ranking = pick(rows, row_kind="ranking")
    assert len(ranking) == 6                                               # 3 path variants x 2 readings
    assert {(r["variant"], r["match_reading"]) for r in ranking} == {(v, m) for v in ("full", "b1", "b2")
                                                                      for m in ("hop", "node")}
    assert all(r["reading_scope"] == "all" for r in ranking)
    assert all(r["primary_metric"] == "mrr_per_key_expected" for r in ranking)
    assert len(pick(rows, row_kind="b0_recall")) == 1 and pick(rows, row_kind="b0_recall")[0]["reading_scope"] == "all"
    kinds = {r["row_kind"] for r in rows}
    # spec 06 section 10 (D-A, D-B) appends row kinds; every earlier kind keeps exactly its rows (the old set is a subset,
    # and the new kinds are only the three the addendum names)
    old_kinds = {"ranking", "b0_recall", "ranking_contested", "b0_recall_contested"}
    assert old_kinds <= kinds
    assert kinds - old_kinds <= {"node_prf", "node_prf_scenario", "auc_pooled"}
    assert len(pick(rows, row_kind="ranking_contested")) == 8 and len(pick(rows, row_kind="b0_recall_contested")) == 2
    assert {r["reading_scope"] for r in rows if r["row_kind"].endswith("_contested")} == {"contested"}


def test_evt07_rank_csv_keeps_every_earlier_column_in_place_and_adds_contested_and_n_positive_units(tmp_path):
    root = tmp_path / "r"
    rf.development_repo(root)
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 0
    for t in DEVELOPMENT_TRIALS:
        with open(root / "out" / "evaluate" / t / "rank.csv", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            header = list(reader.fieldnames or [])
            rows = list(reader)
        assert header[:len(OLD_RANK_COLUMNS)] == OLD_RANK_COLUMNS, t
        assert {"contested", "n_positive_units"} <= set(header)
        for r in rows:
            if r["row_kind"] in ("trial", "b0_recall"):
                assert r["contested"] in ("0", "1"), (t, r["row_kind"])
            else:
                assert r["contested"] == "", (t, r["row_kind"])             # empty elsewhere (spec 3.1)
            if r["row_kind"] != "b0_recall":
                assert r["n_positive_units"] == ""
            else:
                assert r["n_positive_units"].isdigit()


def test_evt07_s06_and_unkeyed_trials_get_no_contested_flag(tmp_path):
    root = tmp_path / "r"
    rf.development_repo(root)
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 0
    for t in ("s06_t00", "s02_t01", "s03_t01", "s06_t01"):
        with open(root / "out" / "evaluate" / t / "rank.csv", newline="", encoding="utf-8") as fh:
            assert {r["contested"] for r in csv.DictReader(fh)} == {""}, t


def test_evt07_the_primary_numbers_of_the_standard_world_are_unchanged_by_the_new_columns(tmp_path):
    """EV-07: tie rule, chance formulas, S06 check as before (the by-hand numbers of test_rank_stage)."""
    root = tmp_path / "r"
    rf.development_repo(root)
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 0
    with open(root / "out" / "evaluate" / "development" / "rank_totals.csv", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    full = one(rows, row_kind="ranking", variant="full", match_reading="hop")
    assert (full["top1_expected"], full["mrr_expected"], full["chance_top1"], full["chance_mrr"]) == (
        "0.500000", "0.666667", "0.200000", "0.333333")
    assert (full["s06_margin"], full["s06_held"]) == ("0.416667", "1")


# ================================================================================================ Q5 node reading decides
def test_q5_hop_and_node_readings_differ_and_the_verdict_uses_the_node_reading():
    """The hop reading matches P1 (top-1 1.0 -> H1 would be held); the node reading matches nothing (top-1 0.0). The H
    verdict (results.csv dev_check) follows the node reading; the hop reading stays in rank_totals beside it."""
    from evaluate.results_report import results_files
    tr = R.assemble(R.hop_only_world("s02_t00"))
    rows = totals([tr])
    assert one(rows, row_kind="ranking", variant="full", match_reading="hop")["top1_expected"] == "1.000000"
    assert one(rows, row_kind="ranking", variant="full", match_reading="node")["top1_expected"] == "0.000000"
    files = results_files([tr], "development")
    res = list(csv.DictReader(io.StringIO(files["results.csv"])))
    (h1,) = [r for r in res if r["table"] == "H1" and r["is_primary"] == "1"]
    assert h1["observed"] == "0.000000" and h1["dev_check"] == "not held"
    (h2,) = [r for r in res if r["table"] == "H2" and r["is_primary"] == "1"]
    assert h2["observed"] == "0.000000" and h2["dev_check"] == "not held"
    # the opposite direction: the hop value (1.0) appears nowhere as an H1 / H2 observed value
    assert not [r for r in res if r["table"] in ("H1", "H2") and r["reading_scope"] == "all" and r["observed"] == "1.000000"
                and r["metric"] in ("top1_expected", "mrr_per_key_expected", "mrr_expected")]
