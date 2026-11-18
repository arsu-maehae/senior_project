"""T9.5 `python -m evaluate --rank` / `--rank-sweep` end to end on a synthetic fake repo (spec 05_score SCA-06, section
5.2, section 7.3; decisions 054, 065, 066, 068; spec 05 SC-60 style refusals).

Written from the spec and decisions, not from the code (the CLI entry point `evaluate.__main__.main` and the file names
only). The fake repo (`rank_fixtures.development_repo`) holds all nine development trials so `--development` runs; its
every number is computed by hand in `rank_fixtures`. Nothing under the real `out/`, `data/` or `ground_truth/` is
opened (the `--repo` option points into a pytest tmp folder).
"""
from __future__ import annotations

import ast
import csv
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import rank_fixtures as rf  # noqa: E402
from evaluate import __main__ as em  # noqa: E402
from evaluate.params import DEVELOPMENT_TRIALS  # noqa: E402

NOTE = "DEVELOPMENT numbers, not results"


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def cli(repo: Path, *args: str) -> int:
    return em.main([*args, "--repo", str(repo)])


@pytest.fixture(scope="module")
def dev_repo(tmp_path_factory):
    root = tmp_path_factory.mktemp("rank_dev")
    rf.development_repo(root)
    return root


@pytest.fixture(scope="module")
def swept(tmp_path_factory):
    """A fake repo after `--rank-sweep --development` (read-only afterwards)."""
    root = tmp_path_factory.mktemp("rank_swept")
    rf.development_repo(root)
    assert cli(root, "--rank-sweep", "--development") == 0
    return root


def summary(root: Path) -> Path:
    return root / "out" / "evaluate" / "development"


def fresh_repo(tmp_path: Path, name: str = "r") -> Path:
    root = tmp_path / name
    rf.development_repo(root)
    return root


# ================================================================================================ contract: files and columns
def test_development_sweep_writes_one_rank_csv_per_trial_and_the_summary_files(swept, capsys):
    for t in DEVELOPMENT_TRIALS:
        assert (swept / "out" / "evaluate" / t / "rank.csv").is_file(), t
        assert [p.name for p in (swept / "out" / "evaluate" / t).iterdir()] == ["rank.csv"]
    assert sorted(p.name for p in summary(swept).iterdir()) == ["rank.md", "rank_sweep.csv", "rank_totals.csv"]


def test_rank_csv_columns_status_note_and_trial_ids(swept):
    cols = None
    for t in DEVELOPMENT_TRIALS:
        rows = read_csv(swept / "out" / "evaluate" / t / "rank.csv")
        assert rows
        cols = cols or list(rows[0])
        assert list(rows[0]) == cols
        assert {r["trial_id"] for r in rows} == {t} and {r["status_note"] for r in rows} == {NOTE}
        assert {r["split"] for r in rows} == {"development"}
    for c in ("row_kind", "variant", "match_reading", "key_path_id", "method", "threshold", "n_candidates",
              "candidate_count", "first_rank", "tie_size", "rank_expected", "rank_optimistic", "rank_pessimistic",
              "top1_expected", "chance_top1", "chance_rr", "chance_rr_mean", "score_gap", "supporting_event_uids",
              "budget_nodes", "full_recall", "b0_recall"):
        assert c in cols, c


def test_attack_trial_rows_by_hand(swept):
    rows = read_csv(swept / "out" / "evaluate" / "s04_t00" / "rank.csv")
    kinds = {(r["row_kind"], r["variant"], r["match_reading"]) for r in rows}
    for v in ("full", "b1", "b2"):
        for reading in ("hop", "node"):
            assert ("key_path", v, reading) in kinds and ("trial", v, reading) in kinds
        assert ("distribution", v, "") in kinds
    assert ("b0_recall", "full_vs_b0", "") in kinds
    (hop,) = [r for r in rows if r["row_kind"] == "trial" and r["variant"] == "full" and r["match_reading"] == "hop"]
    assert (hop["first_rank"], hop["tie_size"], hop["matches_in_tie"]) == ("1", "2", "1")
    assert (hop["rank_expected"], hop["rank_optimistic"], hop["rank_pessimistic"]) == ("1.500000", "1", "2")
    assert (hop["top1_expected"], hop["top1_optimistic"], hop["top1_pessimistic"]) == ("0.500000", "1.000000", "0.000000")
    assert hop["rr_expected"] == "0.666667" and hop["n_candidates"] == "5" and hop["candidate_count"] == "1"
    assert (hop["chance_top1"], hop["chance_rank_expected"], hop["chance_rr"]) == ("0.200000", "3.000000", "0.333333")
    assert hop["chance_rr_mean"] == "0.456667"
    assert (hop["key_attack_score_min"], hop["other_score_max"], hop["score_gap"]) == ("0.666667", "0.666667", "0.000000")
    assert hop["other_max_path_ids"] == "P2" and hop["matched_path_ids"] == "P1" and hop["threshold"] == "0.500000"
    assert hop["method"] == "hop_jaccard_any_key_attack_path"
    (node,) = [r for r in rows if r["row_kind"] == "trial" and r["variant"] == "full" and r["match_reading"] == "node"]
    assert node["matched_path_ids"] == "P1;P5" and node["candidate_count"] == "2" and node["method"] == "node_jaccard_any_key_attack_path"
    assert (node["chance_top1"], node["chance_rank_expected"], node["chance_rr"]) == ("0.400000", "2.000000", "0.500000")
    (b2,) = [r for r in rows if r["row_kind"] == "trial" and r["variant"] == "b2" and r["match_reading"] == "hop"]
    assert (b2["first_rank"], b2["rank_expected"], b2["rank_pessimistic"]) == ("3", "3.500000", "4")
    (b0,) = [r for r in rows if r["row_kind"] == "b0_recall"]
    assert (b0["k"], b0["key_node_count"], b0["budget_nodes"]) == ("1", "3", "2.500000")
    assert (b0["full_recall"], b0["b0_recall"]) == ("0.500000", "0.666667")


def test_key_path_row_carries_method_candidate_count_supporting_uids_and_jaccards(swept):
    rows = read_csv(swept / "out" / "evaluate" / "s04_t00" / "rank.csv")
    (hop,) = [r for r in rows if r["row_kind"] == "key_path" and r["variant"] == "full" and r["match_reading"] == "hop"]
    assert hop["key_path_id"] == "K1-path" and hop["key_role"] == "attack" and hop["key_hop_ids"] == "K1"
    assert hop["mapped_hop_ids"] == "H1" and hop["unmatched_key_hops"] == ""
    assert hop["method"] == "hop_jaccard" and hop["candidate_count"] == "1" and hop["matched_jaccards"] == "P1=1.000000"
    assert hop["supporting_event_uids"] == "T_H1"                    # the key target 4624 that anchors the mapping
    (node,) = [r for r in rows if r["row_kind"] == "key_path" and r["variant"] == "full" and r["match_reading"] == "node"]
    assert node["matched_jaccards"] == "P1=1.000000;P5=0.500000" and node["key_node_count"] == "3"
    assert node["supporting_event_uids"] == "T_H1;a1;a2"             # key nodes held by the first-match group (P1)


def test_s06_and_unkeyed_trials_get_distribution_rows_only(swept):
    for t in ("s06_t00", "s02_t01", "s03_t01", "s06_t01"):
        rows = read_csv(swept / "out" / "evaluate" / t / "rank.csv")
        assert {r["row_kind"] for r in rows} == {"distribution"}, t
        assert {r["variant"] for r in rows} == {"full", "b1", "b2"}
    s06 = read_csv(swept / "out" / "evaluate" / "s06_t00" / "rank.csv")
    assert {r["keyed"] for r in s06} == {"1"} and {r["keyed"] for r in read_csv(swept / "out" / "evaluate" / "s02_t01" / "rank.csv")} == {"0"}


def test_totals_and_s06_check_by_hand(swept):
    rows = read_csv(summary(swept) / "rank_totals.csv")
    assert {r["status_note"] for r in rows} == {NOTE} and {r["split"] for r in rows} == {"development"}
    full = next(r for r in rows if r["variant"] == "full" and r["match_reading"] == "hop")
    assert (full["attack_trials"], full["key_paths"], full["key_paths_matched"]) == ("5", "5", "5")
    assert (full["top1_expected"], full["mrr_expected"]) == ("0.500000", "0.666667")
    assert (full["top1_optimistic"], full["top1_pessimistic"], full["mrr_pessimistic"]) == ("1.000000", "0.000000", "0.500000")
    assert (full["chance_top1"], full["chance_mrr"]) == ("0.200000", "0.333333")
    assert (full["s06_trials"], full["s06_max_score"], full["key_attack_score_min"]) == ("1", "0.250000", "0.666667")
    assert (full["s06_margin"], full["s06_held"]) == ("0.416667", "1") and full["share_attack_trials_above_s06"] == "1.000000"
    b2 = next(r for r in rows if r["variant"] == "b2" and r["match_reading"] == "hop")
    assert b2["s06_held"] == "0" and b2["s06_margin"] == "-0.250000"      # key P1 0.25 vs benign B1 0.5
    assert b2["top1_expected"] == "0.000000" and b2["mrr_expected"] == "0.285714"
    assert b2["trials_gap_positive"] == "0"
    b0 = next(r for r in rows if r["row_kind"] == "b0_recall")
    assert (b0["attack_trials"], b0["full_recall_mean"], b0["b0_recall_mean"]) == ("5", "0.500000", "0.666667")
    assert b0["trials_full_above_b0"] == "0"


def test_sweep_file_default_row_first_402_points_and_default_equals_the_written_scores(swept):
    rows = read_csv(summary(swept) / "rank_sweep.csv")
    assert len(rows) == 1 + 402
    d = rows[0]
    assert d["point_kind"] == "default" and d["same_ranks_as_default"] == "1" and d["n_key_paths_changed"] == "0"
    assert d["lambda"] == "1.442695" and d["w1"] == d["w2"] == d["w3"] == "0.333333"
    assert (d["top1_expected"], d["mrr_expected"], d["s06_max_score"], d["key_attack_score_min"]) == (
        "0.500000", "0.666667", "0.250000", "0.666667")
    assert {r["status_note"] for r in rows} == {NOTE}
    kinds = [r["point_kind"] for r in rows[1:]]
    assert kinds.count("grid") == 396 and kinds.count("default_w") == 6
    # the default point recomputed from the columns equals the written full score: the default-w row at 1/ln2 is stable
    dw = [r for r in rows if r["point_kind"] == "default_w" and r["lambda_label"] == "1/ln2"]
    assert len(dw) == 1 and dw[0]["same_ranks_as_default"] == "1" and dw[0]["top1_expected"] == d["top1_expected"]
    # a node-only point (w = 0, 1, 0) at any lambda moves the key path from 1.5 to 3.5 (hand: P3 .625, P5 .5 above)
    node_only = [r for r in rows if r["point_kind"] == "grid" and (r["w1"], r["w2"], r["w3"]) == ("0.000000", "1.000000", "0.000000")]
    assert len(node_only) == 6 and all(r["same_ranks_as_default"] == "0" and "s04_t00:K1-path=3.500000" in r["key_path_ranks"] for r in node_only)


def test_rank_md_header_sections_and_wording(swept):
    text = (summary(swept) / "rank.md").read_text(encoding="utf-8")
    assert text.splitlines()[0] == "# DEVELOPMENT — not a result (decision 019)"
    sections = [ln for ln in text.splitlines() if ln.startswith("### ")]
    assert len(sections) >= 6
    assert text.count(f"**{NOTE}.**") == len(sections)                     # every table is headed with the note
    low = text.lower()
    for bad in ("reduces false positives", "detects stolen", "identifies the attacker", "confidence %"):
        assert bad not in low
    assert "not a probability" in low and "expected, to be measured" in low
    assert "Stability sweep" in text and "never changes a parameter" in text


def test_plain_rank_development_drops_an_older_sweep_file_and_keeps_other_evaluations(tmp_path):
    root = fresh_repo(tmp_path)
    assert cli(root, "--rank-sweep", "--development") == 0
    link = summary(root) / "link_accuracy_summary.md"
    link.write_text("# other evaluation\n", encoding="utf-8")                # carried over by --rank (RANK_SUMMARY_KEEP)
    assert cli(root, "--rank", "--development") == 0
    assert sorted(p.name for p in summary(root).iterdir()) == ["link_accuracy_summary.md", "rank.md", "rank_totals.csv"]
    assert "Stability sweep" not in (summary(root) / "rank.md").read_text(encoding="utf-8")


def test_rank_keeps_label_recall_and_link_files_of_a_trial_folder(tmp_path):
    root = fresh_repo(tmp_path)
    folder = root / "out" / "evaluate" / "s04_t00"
    folder.mkdir(parents=True)
    (folder / "label_recall.csv").write_text("trial_id,x\ns04_t00,1\n", encoding="utf-8")
    (folder / "link_accuracy.json").write_text(json.dumps({"trial_id": "s04_t00"}), encoding="utf-8")
    assert cli(root, "--rank", "--development") == 0
    assert (folder / "label_recall.csv").read_text(encoding="utf-8") == "trial_id,x\ns04_t00,1\n"
    assert json.loads((folder / "link_accuracy.json").read_text(encoding="utf-8")) == {"trial_id": "s04_t00"}
    assert (folder / "rank.csv").is_file()


def test_a_kept_file_of_another_trial_refuses_the_whole_run_and_writes_nothing(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    folder = root / "out" / "evaluate" / "s04_t00"
    folder.mkdir(parents=True)
    (folder / "label_recall.csv").write_text("trial_id,x\ns09_t00,1\n", encoding="utf-8")
    before = rf.snapshot(root)
    assert cli(root, "--rank", "--development") == 2
    assert capsys.readouterr().err.startswith("refused:")
    assert rf.snapshot(root) == before


# ================================================================================================ determinism
def test_two_runs_are_byte_identical_and_do_not_read_a_clock(tmp_path):
    a, b = fresh_repo(tmp_path, "a"), fresh_repo(tmp_path, "b")
    assert cli(a, "--rank-sweep", "--development") == 0 and cli(b, "--rank-sweep", "--development") == 0
    assert cli(a, "--rank-sweep", "--development") == 0                       # and a rerun over its own output
    sa, sb = rf.snapshot(a / "out" / "evaluate"), rf.snapshot(b / "out" / "evaluate")
    assert sa == sb and any(k.endswith("rank_sweep.csv") for k in sa)


def test_single_trial_run_is_byte_identical_and_writes_only_rank_csv(tmp_path):
    root = fresh_repo(tmp_path)
    o1, o2 = tmp_path / "o1", tmp_path / "o2"
    before = rf.snapshot(root)
    assert cli(root, "--rank", "--trial", "s04_t00", "--out", str(o1)) == 0
    assert cli(root, "--rank", "--trial", "s04_t00", "--out", str(o2)) == 0
    assert cli(root, "--rank", "--trial", "s04_t00", "--out", str(o2)) == 0   # rebuilds its own folder
    assert [p.name for p in o1.iterdir()] == ["rank.csv"] == [p.name for p in o2.iterdir()]
    assert (o1 / "rank.csv").read_bytes() == (o2 / "rank.csv").read_bytes()
    assert rf.snapshot(root) == before                                         # inputs untouched, nothing in the repo
    assert (o1 / "rank.csv").read_bytes() == (swept_rank_csv(tmp_path)).read_bytes()


def swept_rank_csv(tmp_path: Path) -> Path:
    root = fresh_repo(tmp_path, "viaDev")
    assert cli(root, "--rank", "--development") == 0
    return root / "out" / "evaluate" / "s04_t00" / "rank.csv"


def test_inputs_are_not_modified_by_any_rank_run(tmp_path):
    root = fresh_repo(tmp_path)
    ins = {k: v for k, v in rf.snapshot(root).items() if not k.startswith("out/evaluate")}
    assert cli(root, "--rank-sweep", "--development") == 0
    assert {k: v for k, v in rf.snapshot(root).items() if not k.startswith("out/evaluate")} == ins


# ================================================================================================ refusals (exit 2, nothing written)
def refused(root: Path, capsys, *args: str) -> str:
    before = rf.snapshot(root.parent)
    assert cli(root, *args) == 2, args
    err = capsys.readouterr().err
    assert err.startswith("refused:"), err
    assert rf.snapshot(root.parent) == before, args
    return err


@pytest.mark.parametrize("trial", ["s02_t05", "s04_t10", "s01_t00", "s07_t02", "bogus", "../s02_t00"])
@pytest.mark.parametrize("flag", ["--rank", "--rank-sweep"])
def test_test_trials_and_malformed_ids_are_refused_before_any_file_is_opened(tmp_path, capsys, flag, trial):
    root = tmp_path / "empty"
    root.mkdir()                                       # no inputs at all: the allowlist must refuse first
    refused(root, capsys, flag, "--trial", trial, "--out", str(tmp_path / "o"))
    assert not (tmp_path / "o").exists()


def test_rank_sweep_with_trial_is_refused_even_for_a_development_trial(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    err = refused(root, capsys, "--rank-sweep", "--trial", "s04_t00", "--out", str(tmp_path / "o"))
    assert "development" in err and not (tmp_path / "o").exists()


def test_development_with_out_is_refused(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    for flag in ("--rank", "--rank-sweep"):
        refused(root, capsys, flag, "--development", "--out", str(tmp_path / "o"))
    assert not (tmp_path / "o").exists() and not (root / "out" / "evaluate").exists()


def test_rank_with_label_recall_or_stitch_dir_is_refused(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    refused(root, capsys, "--rank", "--label-recall", "--trial", "s04_t00")
    refused(root, capsys, "--rank", "--trial", "s04_t00", "--stitch-dir", str(root / "out" / "stitch" / "s04_t00"))


@pytest.mark.parametrize("rel", ["src", "docs", "ground_truth/approved", "data", ".", "out", "out/stitch/s04_t00"])
def test_out_inside_the_repo_but_not_strictly_below_out_or_over_inputs_is_refused_and_tree_unchanged(tmp_path, capsys, rel):
    root = fresh_repo(tmp_path)
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "keep.py").write_text("x = 1\n", encoding="utf-8")
    (root / "docs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(root / rel))
    assert (root / "src" / "keep.py").is_file() and (root / "ground_truth" / "approved" / "s04_t00.yaml").is_file()


def test_out_naming_a_file_or_a_folder_with_foreign_files_is_refused_and_left_alone(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(f))
    assert f.read_text(encoding="utf-8") == "x"
    d = tmp_path / "mine"
    d.mkdir()
    (d / "notes.txt").write_text("keep", encoding="utf-8")
    err = refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(d))
    assert "notes.txt" in err


def test_out_folder_holding_only_evaluation_files_is_accepted_and_they_are_carried_over(tmp_path):
    root = fresh_repo(tmp_path)
    d = tmp_path / "mine"
    d.mkdir()
    (d / "label_recall.csv").write_text("trial_id,x\ns04_t00,1\n", encoding="utf-8")
    (d / "rank.csv").write_text("trial_id\ns04_t00\n", encoding="utf-8")
    assert cli(root, "--rank", "--trial", "s04_t00", "--out", str(d)) == 0
    assert sorted(p.name for p in d.iterdir()) == ["label_recall.csv", "rank.csv"]
    assert "status_note" in (d / "rank.csv").read_text(encoding="utf-8")
    below = root / "out" / "evaluate_alt" / "s04_t00"
    assert cli(root, "--rank", "--trial", "s04_t00", "--out", str(below)) == 0 and (below / "rank.csv").is_file()


def corrupt(root: Path, stage: str, trial: str, name: str, fn) -> None:
    p = root / "out" / stage / trial / name
    p.write_bytes(fn(p.read_bytes()))


@pytest.mark.parametrize("flag", ["--rank", "--rank-sweep"])
def test_a_ranked_file_changed_after_the_score_run_is_refused_and_nothing_is_written(tmp_path, capsys, flag):
    root = fresh_repo(tmp_path)
    corrupt(root, "score", "s04_t00", "ranked_paths.csv", lambda b: b + b"\n")
    refused(root, capsys, flag, "--development")


def test_stitch_files_changed_after_the_score_run_are_refused(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    corrupt(root, "stitch", "s04_t00", "path_nodes.csv", lambda b: b + b"\n")
    # the stitch run_info still lists the old hash: refused as a stitch/score or stitch-file mismatch
    refused(root, capsys, "--rank", "--development")


def test_a_variant_that_misses_a_stitch_path_is_refused_sc04(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    w = rf.tie_world("s04_t00")
    w.tamper = lambda rows: rows.remove(next(r for r in rows if r["variant"] == "b1" and r["path_id"] == "P4"))
    w.write(root)
    refused(root, capsys, "--rank", "--development")


def test_a_key_built_from_another_db_is_refused(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    p = root / "ground_truth" / "approved" / "s04_t00.yaml"
    key = json.loads(p.read_text(encoding="utf-8"))
    key["db_sha256"] = "b" * 64
    p.write_text(json.dumps(key), encoding="utf-8")
    refused(root, capsys, "--rank", "--development")


def test_a_draft_key_is_never_read_so_a_keyed_development_trial_without_an_approved_key_is_refused(tmp_path, capsys):
    """Decision 069 item 8 (ATK-SC-25): the six keyed development trials (t00 of S02-S07) must have an approved key; a
    draft in ground_truth/drafts does not count and is never read."""
    root = fresh_repo(tmp_path)
    p = root / "ground_truth" / "approved" / "s04_t00.yaml"
    (root / "ground_truth" / "drafts").mkdir(parents=True)
    (root / "ground_truth" / "drafts" / "s04_t00.yaml").write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    p.unlink()
    err = refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o"))
    assert "s04_t00" in err and "keyed" in err and not (tmp_path / "o").exists()


@pytest.mark.parametrize("trial", ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00"])
def test_atk_sc25_every_keyed_development_trial_without_a_key_refuses_development_runs_and_writes_nothing(tmp_path, capsys, trial):
    root = fresh_repo(tmp_path)
    (root / "ground_truth" / "approved" / f"{trial}.yaml").unlink()
    for flag in ("--rank", "--rank-sweep"):
        err = refused(root, capsys, flag, "--development")
        assert trial in err
    assert not (root / "out" / "evaluate").exists()


@pytest.mark.parametrize("trial", ["s02_t01", "s03_t01", "s06_t01"])
def test_the_unkeyed_development_trials_need_no_key(tmp_path, trial):
    root = fresh_repo(tmp_path)
    assert not (root / "ground_truth" / "approved" / f"{trial}.yaml").exists()
    assert cli(root, "--rank", "--trial", trial, "--out", str(tmp_path / "o")) == 0
    assert {r["row_kind"] for r in read_csv(tmp_path / "o" / "rank.csv")} == {"distribution"}


def test_sweep_refuses_when_the_written_full_scores_do_not_follow_from_the_columns(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    w = rf.tie_world("s04_t00")

    def bump(rows):
        for r in rows:
            if r["variant"] == "full" and r["path_id"] == "P3":
                r["node_score"] = "0.900000"
    w.tamper = bump
    w.write(root)
    refused(root, capsys, "--rank-sweep", "--development")
    assert cli(root, "--rank", "--development") == 0                           # the plain check does not recompute


def test_a_score_run_with_other_than_the_frozen_parameters_is_refused_by_rank_and_by_the_sweep(tmp_path, capsys):
    """Decision 069 item 6 (ATK-SC-18): lambda = 2 and w = (0.5, 0.25, 0.25) are not the decision 066 values."""
    root = fresh_repo(tmp_path)
    w = rf.tie_world("s04_t00")
    w.lam, w.w = 2.0, (0.5, 0.25, 0.25)
    w.write(root)
    for flag in ("--rank", "--rank-sweep"):
        err = refused(root, capsys, flag, "--development")
        assert "frozen" in err and "parameters" in err
    err = refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o"))
    assert "frozen" in err and not (tmp_path / "o").exists()


# ================================================================================================ ATK-SC-18 pins (069 item 6)
def rewrite_score_info(root: Path, trial: str, fn) -> None:
    p = root / "out" / "score" / trial / "run_info.json"
    info = json.loads(p.read_text(encoding="utf-8"))
    fn(info)
    p.write_text(json.dumps(info, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def test_the_unmodified_fixture_passes_every_pin(tmp_path):
    root = fresh_repo(tmp_path)
    assert cli(root, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o")) == 0


def test_atk_sc18_a_label_file_changed_after_the_score_run_is_refused(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    p = root / "out" / "label" / "s04_t00" / "node_labels.csv"
    p.write_bytes(p.read_bytes() + b"\n")
    err = refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o"))
    assert "node_labels.csv" in err and not (tmp_path / "o").exists()
    refused(root, capsys, "--rank", "--development")


def test_atk_sc18_a_label_file_that_is_missing_is_refused(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    (root / "out" / "label" / "s04_t00" / "event_labels.csv").unlink()
    err = refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o"))
    assert "event_labels.csv" in err


def test_atk_sc18_a_score_run_that_records_no_label_hashes_or_a_path_is_refused(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    rewrite_score_info(root, "s04_t00", lambda i: i["inputs"].update(label={}))
    refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o"))
    root2 = fresh_repo(tmp_path, "r2")
    rewrite_score_info(root2, "s04_t00", lambda i: i["inputs"].update(label={"../../x.csv": "0" * 64}))
    refused(root2, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o2"))


def test_atk_sc18_another_order_table_hash_is_refused(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    rewrite_score_info(root, "s04_t00", lambda i: i.update(order_table_sha256="0" * 64))
    err = refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o"))
    assert "order_table_sha256" in err and not (tmp_path / "o").exists()
    root2 = fresh_repo(tmp_path, "r2")
    rewrite_score_info(root2, "s04_t00", lambda i: i.pop("order_table_sha256"))
    refused(root2, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o2"))


@pytest.mark.parametrize("name,value", [("w1", 0.5), ("w2", 0.25), ("lam", 1.5), ("alpha", 0.6), ("beta", 0.4), ("a", 2.0),
                                        ("b", 0.5), ("eps", 0.02), ("lam", 1.0 / 0.6931471805599453 + 1e-9)])
def test_atk_sc18_every_frozen_parameter_is_pinned(tmp_path, capsys, name, value):
    root = fresh_repo(tmp_path)
    rewrite_score_info(root, "s04_t00", lambda i: i["parameters"].update({name: value}))
    err = refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o"))
    assert f"parameters.{name}" in err


def test_atk_sc18_a_missing_or_non_numeric_parameter_is_refused_and_a_1e_13_wobble_is_not(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    rewrite_score_info(root, "s04_t00", lambda i: i["parameters"].pop("eps"))
    refused(root, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o"))
    root2 = fresh_repo(tmp_path, "r2")
    rewrite_score_info(root2, "s04_t00", lambda i: i["parameters"].update(w3="x"))
    refused(root2, capsys, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o2"))
    root3 = fresh_repo(tmp_path, "r3")
    rewrite_score_info(root3, "s04_t00", lambda i: i["parameters"].update(lam=i["parameters"]["lam"] + 1e-13))
    assert cli(root3, "--rank", "--trial", "s04_t00", "--out", str(tmp_path / "o3")) == 0


# ================================================================================================ decision 069 item 9 in the files
def test_rank_csv_has_the_beside_columns_by_hand_and_the_primary_columns_unchanged(swept):
    rows = read_csv(swept / "out" / "evaluate" / "s04_t00" / "rank.csv")
    (hop,) = [r for r in rows if r["row_kind"] == "trial" and r["variant"] == "full" and r["match_reading"] == "hop"]
    assert hop["rank_expected"] == "1.500000" and hop["chance_rr"] == "0.333333" and hop["chance_top1"] == "0.200000"
    assert hop["rr_mean_expected"] == "0.750000"                                   # E[1/rank] inside the 2-way tie
    assert (hop["n_candidates_positive"], hop["chance_pos_top1"], hop["chance_pos_rank_expected"]) == ("4", "0.250000", "2.500000")
    assert (hop["chance_pos_rr"], hop["chance_pos_rr_mean"]) == ("0.400000", "0.520833")
    (node,) = [r for r in rows if r["row_kind"] == "trial" and r["variant"] == "full" and r["match_reading"] == "node"]
    assert (node["chance_pos_top1"], node["chance_pos_rr"], node["chance_pos_rr_mean"]) == ("0.500000", "0.600000", "0.722222")


def test_rank_totals_and_rank_md_report_per_key_mrr_e_one_over_rank_and_the_positive_chance_line(swept):
    t = next(r for r in read_csv(summary(swept) / "rank_totals.csv") if r["variant"] == "full" and r["match_reading"] == "hop")
    assert (t["mrr_expected"], t["mrr_rr_mean_expected"], t["mrr_per_key_expected"]) == ("0.666667", "0.750000", "0.666667")
    assert (t["chance_pos_top1"], t["chance_pos_mrr"], t["chance_pos_rr_mean"]) == ("0.250000", "0.400000", "0.520833")
    md = (summary(swept) / "rank.md").read_text(encoding="utf-8")
    for needle in ("mrr_per_key_expected", "chance_pos_mrr", "E[1/rank]", "chance_E[1/rank]", "n_pos", "Reported beside",
                   "ATK-SC-15", "ATK-SC-21", rr_basis_all(), rr_basis_labelled()):
        assert needle in md, needle


def rr_basis_all() -> str:
    return "all context-0 nodes (reported beside, 070)"                      # spec 06 section 3.1 (decision 070)


def rr_basis_labelled() -> str:
    return "labelled nodes only (b0-reachable, primary, 070/071)"


def test_rank_md_opens_with_the_primary_readings_h4_is_labelled_first_and_the_sweep_is_called_not_informative(swept):
    """Spec 06 section 3.1 (decision 070 / 071): "Primary readings (decision 070)" is the first section; the H4 tables show
    the labelled basis (primary) before the all-node basis (beside)."""
    md = (summary(swept) / "rank.md").read_text(encoding="utf-8")
    heads = [ln for ln in md.splitlines() if ln.startswith("## ")]
    assert heads[0] == "## Primary readings (decision 070)", heads
    assert heads.index("## Reported beside (decision 070)") > 0
    assert md.count(rr_basis_labelled()) >= 2 and rr_basis_all() in md
    h4 = [ln for ln in md.splitlines() if ln.startswith("| trial | k |")]
    assert h4, "per-trial H4 table missing"
    assert h4[0].index(rr_basis_labelled()) < h4[0].index(rr_basis_all())          # labelled columns first
    assert "not informative on development data" in md and "it never moves a value" in md


def test_totals_recall_bases_are_named_in_the_totals_file(swept):
    b0 = next(r for r in read_csv(summary(swept) / "rank_totals.csv") if r["row_kind"] == "b0_recall")
    assert b0["recall_basis"] == rr_basis_all() and b0["recall_basis_labelled"] == rr_basis_labelled()
    assert (b0["full_recall_mean"], b0["b0_recall_mean"]) == ("0.500000", "0.666667")
    # decision 071: all three key nodes (T_H1 in unit u3, a1 and a2 in u1) are inside a b0 unit, so the labelled
    # denominator is 3 = all key nodes in this world and the mean is unchanged by hand: full 1/3, b0 1/2.
    assert (b0["full_recall_labelled_mean"], b0["b0_recall_labelled_mean"]) == ("0.333333", "0.500000")
    rows = read_csv(swept / "out" / "evaluate" / "s04_t00" / "rank.csv")
    (r,) = [x for x in rows if x["row_kind"] == "b0_recall"]
    assert r["key_nodes_labelled"] == "3" and r["key_node_count"] == "3"


# ================================================================================================ independence and no side effects
def test_evaluate_imports_neither_score_nor_stitch_statically():
    bad = []
    for f in sorted((REPO / "src" / "evaluate").glob("*.py")):
        for n in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""] if isinstance(n, ast.ImportFrom) and n.level == 0 else []
            bad += [(f.name, m) for m in mods if m.split(".")[0] in ("score", "stitch")]
    assert not bad, bad


def test_importing_the_evaluate_cli_loads_no_score_or_stitch_module():
    code = ("import sys; sys.path.insert(0, %r); import evaluate.__main__; "
            "print(sorted(m for m in sys.modules if m.split('.')[0] in ('score', 'stitch')))" % str(REPO / "src"))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=True)
    assert out.stdout.strip() == "[]", out.stdout


def test_the_sweep_never_writes_score_parameters_or_any_src_file(tmp_path):
    def src_hash() -> str:
        h = hashlib.sha256()
        for p in sorted((REPO / "src" / "score").rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                h.update(p.relative_to(REPO).as_posix().encode() + p.read_bytes())
        return h.hexdigest()
    before = src_hash()
    root = fresh_repo(tmp_path)
    assert cli(root, "--rank-sweep", "--development") == 0
    assert src_hash() == before
    assert not (root / "src").exists()
    # and no evaluate rank module writes a params file: no open() for writing and no params path in its sources
    for f in sorted((REPO / "src" / "evaluate").glob("rank_*.py")):
        text = f.read_text(encoding="utf-8")
        assert "open(" not in text and "write_text" not in text and "write_bytes" not in text, f.name
        assert "score/params" not in text.replace("\\", "/"), f.name


def test_rank_modules_open_no_database_and_no_ground_truth_path_by_themselves():
    for f in sorted((REPO / "src" / "evaluate").glob("rank_*.py")):
        text = f.read_text(encoding="utf-8")
        assert "sqlite3" not in text and "ground_truth" not in text.replace("approved", ""), f.name
