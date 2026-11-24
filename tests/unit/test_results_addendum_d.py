"""Spec 06_evaluate section 10 (addendum D), written-file part: the new `results.md` / `results.csv` tables (D-A, D-B,
D-D: SW-01..03, NP-05, AUC-01..03) and the evaluate half of AB-06 (`--results` refuses a development stitch run that
disabled a method).

Written from the spec, not from the code. The fake development repo is `rank_fixtures.development_repo` (five attack
worlds = the tie world, one keyed S06, three unkeyed); its numbers are derived by hand in the comments. Only development
trial ids appear; everything is written under pytest tmp folders (the root conftest forbids writes under the real `out/`).

Hand values of the tie world (k = 1; key nodes {T_H1, a1, a2}; full: P1 = P2 = 0.666667 tie at rank 1, P3 0.291667,
P5 0.166667, P4 0): P1 / P2 each the top-1 w.p. 1/2, so held = 0.5 * 3 + 0.5 * 2 = 2.5, covered = 1.5: P 0.6, R 0.5, F1
6/11 = 0.545455, FNR 0.5. b0 at budget 2.5: u1 {a1, a2} covered 2, then u2 {b1} gets the 0.5 left: P 2 / 2.5 = 0.8,
R 2/3, F1 8/11 = 0.727273, FNR 1/3. b2 (N): P3 {T_H1x, y, z3} alone first: P 0, R 0, F1 0, FNR 1. Per-trial AUC full:
positives P1 (0.666667) and P5 (0.166667); negatives P2 (0.666667), P3 (0.291667), P4 (0): (2.5 + 1) / 6 = 0.583333.
Pooled with the keyed S06 trial (B1 0.25, B2 0): (5 * 14.5 + 5 * 6) / (10 * 17) = 0.602941, n_pos 10, n_neg 17.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import rank_fixtures as rf  # noqa: E402
from evaluate import __main__ as em  # noqa: E402
from evaluate.params import DEVELOPMENT_TRIALS  # noqa: E402

NOTE = "DEVELOPMENT — not a result"
NEW_TABLES = ("reconstruction", "auc", "sensitivity")


def cli(repo: Path, *args: str) -> int:
    return em.main([*args, "--repo", str(repo)])


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def summary(root: Path) -> Path:
    return root / "out" / "evaluate" / "development"


def section(text: str, title_prefix: str) -> str:
    """The `## <title_prefix>...` section of a Markdown text, up to the next `## ` heading."""
    parts = re.split(r"(?m)^## ", text)
    (s,) = [p for p in parts if p.startswith(title_prefix)]
    return s


@pytest.fixture(scope="module")
def swept(tmp_path_factory):
    """Fake development repo after `--rank-sweep` and `--results` (read-only afterwards)."""
    root = tmp_path_factory.mktemp("addendum_d")
    rf.development_repo(root)
    assert cli(root, "--rank-sweep", "--development") == 0
    assert cli(root, "--results", "--development") == 0
    return root


@pytest.fixture(scope="module")
def md(swept) -> str:
    return (summary(swept) / "results.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def rows(swept):
    return read_csv(summary(swept) / "results.csv")


def of(rows, table, **want):
    return [r for r in rows if r["table"] == table and all(r[k] == v for k, v in want.items())]


def one(rows, table, **want):
    (r,) = of(rows, table, **want)
    return r


# ================================================================================================ D-A in results
def test_np_results_reconstruction_rows_by_hand(rows):
    got = {(r["variant"], r["metric"]): r["observed"] for r in of(rows, "reconstruction")
           if r["source"].startswith("rank_totals.csv node_prf/") and "/-/all/-:" in r["source"]}
    want = {"full": ("0.600000", "0.500000", "0.545455", "0.500000"), "b1": ("0.600000", "0.500000", "0.545455", "0.500000"),
            "b2": ("0.000000", "0.000000", "0.000000", "1.000000"), "b0": ("0.800000", "0.666667", "0.727273", "0.333333")}
    for v, (p, rec, f1, fnr) in want.items():
        assert (got[(v, "node_precision_mean")], got[(v, "node_recall_mean")], got[(v, "node_f1_mean")],
                got[(v, "node_fnr_mean")]) == (p, rec, f1, fnr), v
    assert len(got) == 16                                                       # 4 variants x 4 measures, overall


def test_np_results_md_reconstruction_section_is_headed_development_and_has_overall_and_scenario_rows(md):
    s = section(md, "Reconstruction quality")
    assert NOTE in s
    assert re.search(r"\| overall \| full \| 0\.600000 \| 0\.500000 \| 0\.545455 \| 0\.500000 \|", s)
    assert re.search(r"\| s04 \| b0 \| 0\.800000 \| 0\.666667 \| 0\.727273 \| 0\.333333 \|", s)
    assert not re.search(r"\| s06 \|", s)                                       # S06 has no key nodes (NP-03)


def test_np05_p_counts_events_the_key_does_not_list_as_not_in_key_never_a_false_positive_rate(swept, md):
    s = section(md, "Reconstruction quality")
    assert "not in key" in s
    assert "ST-05" in s and "member_logon_uids" in s                           # the merge is stated with its limit
    for path in [summary(swept) / n for n in ("results.md", "results.csv", "rank.md", "rank_totals.csv")] + [
            swept / "out" / "evaluate" / t / "rank.csv" for t in DEVELOPMENT_TRIALS]:
        text = path.read_text(encoding="utf-8").lower()
        assert not re.search(r"false[- ]positive[- ]rate|\bfpr\b", text), path.name
        assert "reduces false positives" not in text and "detects stolen" not in text and "identifies the attacker" not in text


# ================================================================================================ D-B in results
def test_auc_results_pooled_and_per_trial_rows_by_hand(rows):
    pooled = one(rows, "auc", variant="full", metric="auc_pooled")
    assert pooled["observed"] == "0.602941" and pooled["chance_all"] == "0.500000"
    assert one(rows, "auc", variant="full", metric="auc_n_pos")["observed"] == "10"
    assert one(rows, "auc", variant="full", metric="auc_n_neg")["observed"] == "17"
    per_trial = of(rows, "auc", variant="full", metric="auc_trial")
    assert len(per_trial) == 5 and {r["observed"] for r in per_trial} == {"0.583333"}
    assert {r["variant"] for r in of(rows, "auc")} == {"full", "b1", "b2"}      # b0 ranks units, not paths


def test_auc_results_md_shows_pooled_beside_per_trial_with_counts_and_states_the_limits(md):
    s = section(md, "Pooled ROC-AUC")
    assert NOTE in s
    assert "0.602941" in s and "n_pos 10, n_neg 17" in s
    for t in ("s02_t00", "s03_t00", "s04_t00", "s05_t00", "s07_t00"):
        assert re.search(rf"trial {t}; n_pos 2, n_neg 3", s), t
    low = s.lower()
    assert "not a probability" in low and "correction j" in low                  # AUC-02
    assert "n_pos or n_neg = 0" in s and "undefined" in low                       # AUC-03
    assert "unkeyed" in low and "b0" in s


# ================================================================================================ D-D in results (SW-02, SW-03)
def test_sw03_sensitivity_section_never_says_stable_and_says_same_ranks_as_at_the_default_weights(md):
    s = section(md, "Weight sensitivity")
    assert NOTE in s
    assert not re.search(r"(?i)\bstable\b|\bstability\b", s)
    m = re.search(r"(?i)same ranks as at the default weights: (\d+) of (\d+) points", s)
    assert m and int(m.group(2)) == 396 and 0 <= int(m.group(1)) <= 396


def test_sw03_sensitivity_section_names_the_hop_reading_and_the_informativeness_sentence(md):
    s = section(md, "Weight sensitivity")
    assert "hop reading" in s
    assert re.search(r"(?i)informative", s)
    assert "never moves a value" in s


def test_sw03_sensitivity_section_has_no_s06_held_count_only_min_and_max_margin(md, rows):
    s = section(md, "Weight sensitivity")
    assert not re.search(r"(?i)\bheld\b", s)
    assert "S06 margin" in s and "min" in s and "max" in s
    assert not [r for r in of(rows, "sensitivity") if "held" in r["metric"] or "s06_held" in r["source"]]
    assert {r["metric"] for r in of(rows, "sensitivity") if r["metric"].startswith("s06")} == {
        "s06_margin_default", "s06_margin_min", "s06_margin_max"}


def test_sw02_sensitivity_rows_agree_with_rank_sweep_csv(swept, rows):
    sweep = read_csv(summary(swept) / "rank_sweep.csv")
    grid = [r for r in sweep if r["point_kind"] == "grid"]
    assert len(grid) == 396 and len(sweep) == 1 + 396 + 6
    assert one(rows, "sensitivity", metric="sweep_points")["observed"] == "396"
    assert one(rows, "sensitivity", metric="same_ranks_points")["observed"] == str(
        sum(1 for r in grid if r["same_ranks_as_default"] == "1"))
    margins = [float(r["s06_margin"]) for r in grid]
    assert one(rows, "sensitivity", metric="s06_margin_min")["observed"] == f"{min(margins):.6f}"
    assert one(rows, "sensitivity", metric="s06_margin_max")["observed"] == f"{max(margins):.6f}"
    for col, metric in (("top1_expected", "top1_expected"), ("mrr_expected", "mrr_expected"),
                        ("mrr_per_key_expected", "mrr_per_key_expected")):
        vals = [float(r[col]) for r in grid]
        assert one(rows, "sensitivity", metric=f"{metric}_min")["observed"] == f"{min(vals):.6f}"
        assert one(rows, "sensitivity", metric=f"{metric}_max")["observed"] == f"{max(vals):.6f}"
        assert one(rows, "sensitivity", metric=f"{metric}_default")["observed"] == sweep[0][col]


def test_sw03_per_key_chance_is_shown_beside_per_key_mrr_at_the_default_point(rows):
    """Tie world: n = 5 candidates, m = 1 match (hop reading): chance expected rank (5 + 1) / 2 = 3, RR 1/3; over the 4
    candidates with a score above 0 it is (4 + 1) / 2 = 2.5, RR 0.4. Default per-key MRR = 1 / 1.5 = 0.666667."""
    r = one(rows, "sensitivity", metric="mrr_per_key_expected_default")
    assert (r["observed"], r["chance_all"], r["chance_pos"]) == ("0.666667", "0.333333", "0.400000")


def test_sw01_rank_sweep_csv_has_per_key_mrr_for_every_point_and_the_default_by_hand(swept):
    sweep = read_csv(summary(swept) / "rank_sweep.csv")
    assert all(re.fullmatch(r"[01]\.\d{6}", r["mrr_per_key_expected"]) for r in sweep)
    assert sweep[0]["point_kind"] == "default" and sweep[0]["mrr_per_key_expected"] == "0.666667"
    with open(summary(swept) / "rank_sweep.csv", newline="", encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    assert header[-1] == "mrr_per_key_expected" and header[:3] == ["status_note", "point_kind", "lambda_label"]


def test_sw01_a_sweep_never_moves_a_value_rank_files_are_the_same_with_and_without_it(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    rf.development_repo(a)
    rf.development_repo(b)
    assert cli(a, "--rank", "--development") == 0
    assert cli(b, "--rank-sweep", "--development") == 0
    for t in DEVELOPMENT_TRIALS:
        assert (a / "out/evaluate" / t / "rank.csv").read_bytes() == (b / "out/evaluate" / t / "rank.csv").read_bytes()
    assert (summary(a) / "rank_totals.csv").read_bytes() == (summary(b) / "rank_totals.csv").read_bytes()


# ================================================================================================ no verdict in the new tables
def test_new_results_rows_have_no_threshold_comparator_or_dev_check(rows):
    new = [r for r in rows if r["table"] in NEW_TABLES]
    assert {r["table"] for r in new} == set(NEW_TABLES)
    for r in new:
        assert r["threshold"] == "" and r["comparator"] == "" and r["dev_check"] == "", (r["table"], r["metric"])
        assert r["is_primary"] == "0" and r["status_note"] == NOTE and r["split"] == "development"
        assert "verdict" not in r["note"].lower() or "no verdict" in r["note"].lower()


def test_new_results_md_sections_are_headed_development_and_carry_no_verdict_column(md):
    for title in ("Reconstruction quality", "Pooled ROC-AUC", "Weight sensitivity"):
        s = section(md, title)
        assert NOTE in s.split("\n\n")[1] or NOTE in s[:200], title             # the banner opens the section
        for line in s.splitlines():
            if line.startswith("| ") and "variant" in line.lower() or line.startswith("| metric") or line.startswith("| scenario"):
                assert not re.search(r"dev_check|comparator|threshold|verdict", line), (title, line)
        assert "No verdict" in s, title


def test_new_rank_totals_rows_have_no_threshold_or_verdict_values(swept):
    tot = read_csv(summary(swept) / "rank_totals.csv")
    new = [r for r in tot if r["row_kind"] in ("node_prf", "node_prf_scenario", "auc_pooled")]
    assert len(new) == 4 + 4 * 5 + 3                                            # 4 variants; 4 x 5 attack scenarios; 3 variants
    for r in new:
        assert r["primary_metric"] == "" and r["s06_held"] == "" and r["status_note"].startswith("DEVELOPMENT")


# ================================================================================================ AB-06 (evaluate half)
def set_disabled(root: Path, trial: str, value) -> None:
    """Rewrite the trial's stitch run_info.json with `disabled_methods` = value (absent when value is None) and keep the
    score run's recorded hash of that file consistent, so that nothing but AB-06 can refuse the run."""
    p = root / "out" / "stitch" / trial / "run_info.json"
    info = json.loads(p.read_text(encoding="utf-8"))
    if value is None:
        info.pop("disabled_methods", None)
    else:
        info["disabled_methods"] = value
    text = json.dumps(info, sort_keys=True, indent=1) + "\n"
    p.write_text(text, encoding="utf-8", newline="\n")
    sp = root / "out" / "score" / trial / "run_info.json"
    s_info = json.loads(sp.read_text(encoding="utf-8"))
    s_info["inputs"]["stitch"]["run_info.json"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    sp.write_text(json.dumps(s_info, sort_keys=True, indent=1) + "\n", encoding="utf-8", newline="\n")


@pytest.fixture()
def fresh(tmp_path):
    root = tmp_path / "r"
    rf.development_repo(root)
    assert cli(root, "--rank", "--development") == 0
    return root


@pytest.mark.parametrize("trial", ["s04_t00", "s06_t00", "s02_t01"])
@pytest.mark.parametrize("value", [["cmdline_target"], "cmdline_target"])
def test_ab06_results_refuses_a_development_stitch_run_with_disabled_methods_and_writes_nothing(fresh, capsys, trial, value):
    set_disabled(fresh, trial, value)
    before = rf.snapshot(fresh.parent)
    assert cli(fresh, "--results", "--development") == 2
    err = capsys.readouterr().err
    assert err.startswith("refused:") and "disabled_methods" in err and trial in err
    assert rf.snapshot(fresh.parent) == before
    assert not (summary(fresh) / "results.md").exists() and not (summary(fresh) / "results.csv").exists()


@pytest.mark.parametrize("value", [None, [], ""])
def test_ab06_an_absent_or_empty_disabled_methods_is_a_default_run_and_is_not_refused(fresh, value):
    for t in DEVELOPMENT_TRIALS:
        set_disabled(fresh, t, value)
    assert cli(fresh, "--results", "--development") == 0
    assert (summary(fresh) / "results.csv").is_file()


def test_ab06_no_stage_reads_out_ablation_results_are_the_same_with_a_folder_there(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    for root in (a, b):
        rf.development_repo(root)
    junk = b / "out" / "ablation" / "no_cmdline"
    (junk / "stitch" / "s04_t00").mkdir(parents=True)
    (junk / "stitch" / "s04_t00" / "run_info.json").write_text(json.dumps({"disabled_methods": ["cmdline_target"]}))
    (junk / "ablation.csv").write_text("not,a,result\n")
    for root in (a, b):
        assert cli(root, "--rank-sweep", "--development") == 0
        assert cli(root, "--results", "--development") == 0
    for name in ("results.md", "results.csv", "rank_totals.csv", "rank_sweep.csv", "rank.md"):
        assert (summary(a) / name).read_bytes() == (summary(b) / name).read_bytes(), name
