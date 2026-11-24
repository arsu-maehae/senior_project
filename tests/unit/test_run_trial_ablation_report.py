"""Spec 06_evaluate section 10, the ablation report and the `run_trial.ablation` driver: AB-02, AB-03, AB-08, AB-09, AB-10,
AB-11 (fast, synthetic). Written from the spec, not from the code (names and signatures only).

Rules tested:
- AB-03 / AB-09: `ablation.md` / `ablation.csv` hold default and ablated values side by side with no threshold,
  comparator or verdict column, the banner on the title and on every table section, and no forbidden wording; the
  texts are deterministic (no timestamp).
- AB-08: the hop reading comes first and is the headline; the node reading is shown beside it labelled "key built from the
  same command-line evidence ... node recall falls by construction".
- AB-10: per-trial denominators (key nodes, labelled key nodes, b0 units, budgets) of both runs are shown; a move is stated.
- AB-02 / AB-09 / AB-11 (driver): refuses when a default stitch run_info has `disabled_methods`, when an ablated one lacks
  it, when `results.*` would be copied; the swap replaces the whole folder; DR-06's tree check excludes exactly
  `out/ablation/no_cmdline/`; the scratch repo is deleted on every path. The heavy steps of `main` are replaced by a fake
  scratch run that writes the ablated side by hand; nothing real is read and nothing is written under the real `out/`.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ablation_fixtures as fx  # noqa: E402
from run_trial import ablation as ab  # noqa: E402
from run_trial import ablation_report as ar  # noqa: E402
from run_trial import dryrun  # noqa: E402
from run_trial import params as p  # noqa: E402
from test_run_trial_dryrun import synthetic_repo  # noqa: E402

TRIALS = ("s98_t00", "s97_t00")
DEV = tuple(p.DEVELOPMENT_TRIALS)
CMD = "cmdline_target"
BANNER = "ABLATION (cmdline_target disabled) — DEVELOPMENT, not a result"


def side(trials=TRIALS, ablated=False, **kw) -> ar.Side:
    blobs = fx.side_blobs(trials, ablated, **kw)
    return ar.parse_side(blobs, fx.shas(blobs), trials)


@pytest.fixture(scope="module")
def pair():
    return side(ablated=False), side(ablated=True)


@pytest.fixture(scope="module")
def rows(pair):
    return ar.all_rows(pair[0], pair[1], TRIALS)


@pytest.fixture(scope="module")
def md(rows):
    return ar.ablation_md(rows, TRIALS)


def section(text: str, title_prefix: str) -> str:
    (s,) = [x for x in re.split(r"(?m)^## ", text) if x.startswith(title_prefix)]
    return s


# ================================================================================================ AB-09 no verdict anywhere
def test_ab09_banner_constants_are_the_spec_text():
    assert ar.BANNER == BANNER
    assert "falls by construction" in ar.NODE_LABEL and "020" in ar.NODE_LABEL


def test_ab09_no_threshold_comparator_or_verdict_column_in_ablation_csv(rows):
    text = ar.ablation_csv(rows)
    header = next(csv.reader(io.StringIO(text)))
    for banned in ("threshold", "comparator", "verdict", "dev_check", "held"):
        assert not [c for c in header if banned in c.lower()], banned
    assert header == list(ar.COLUMNS)


def test_ab09_no_threshold_comparator_or_verdict_cell_in_any_markdown_table_header(md):
    for line in md.splitlines():
        if line.startswith("| ") and "---" not in line and not line.startswith("| s9"):
            cells = [c.strip().lower() for c in line.strip().strip("|").split("|")]
            if "metric" in cells or "variant" in cells or "trial" in cells or "best_tier" in cells:
                assert not {"threshold", "comparator", "verdict", "dev_check", "pass", "fail"} & set(cells), line


def test_ab09_csv_writer_refuses_a_banned_column(monkeypatch, rows):
    monkeypatch.setattr(ar, "COLUMNS", (*ar.COLUMNS, "verdict"))
    with pytest.raises(ValueError):
        ar.ablation_csv(rows)


def test_ab09_csv_writer_refuses_a_row_with_other_keys(rows):
    bad = dict(rows[0])
    bad["verdict"] = "held"
    with pytest.raises(ValueError):
        ar.ablation_csv([bad])


def test_ab09_banner_is_on_the_title_and_on_every_table_section(md):
    assert md.splitlines()[0] == f"# {BANNER}"
    sections = [s for s in re.split(r"(?m)^## ", md)[1:] if "| ---" in s or "|---" in s]
    assert len(sections) >= 8
    for s in sections:
        assert f"**{BANNER}.**" in s, s.splitlines()[0]


def test_ab09_every_csv_row_carries_the_banner_as_status_note(rows):
    assert rows and all(r["status_note"] == BANNER for r in rows)


def test_ab09_wording_scan_finds_no_forbidden_claim_and_no_results_reference_as_a_verdict(md, rows):
    assert ar.text_problems({"ablation.md": md, "ablation.csv": ar.ablation_csv(rows)}) == []
    low = md.lower()
    for w in ("stolen", "detects", "probability", "reduces false positives", "identifies the attacker"):
        assert w not in low


def test_ab09_text_problems_flags_a_missing_banner_and_forbidden_wording():
    assert ar.text_problems({"x.md": "no banner here"}) == ["x.md lacks the banner"]
    got = ar.text_problems({"x.md": f"# {BANNER}\nthis detects the attacker"})
    assert len(got) == 1 and "detects" in got[0]
    assert ar.text_problems({"x.csv": "detects"})[0].startswith("x.csv would contain forbidden wording")


def test_ab09_difference_is_plain_arithmetic_not_a_comparison(rows):
    assert ar.difference("0.877451", "0.400000") == "-0.477451"
    assert ar.difference("3", "5") == "2"
    assert ar.difference("0.5", "0.5") == "0.000000"
    assert ar.difference("", "0.5") == "" and ar.difference("a", "b") == ""
    for r in rows:
        assert not re.search(r"\b(pass|fail|held|not held|above|below)\b", r["difference"])


# ================================================================================================ AB-08 hop reading first
def test_ab08_hop_reading_comes_first_and_the_node_reading_after(md):
    """The opening comparison shows the hop columns before the node columns, and the hop-reading table comes before every
    node table (the hop reading is the headline, the node reading is beside it)."""
    heads = re.findall(r"(?m)^## (.*)$", md)
    i_hop = next(i for i, h in enumerate(heads) if h.startswith("Hop reading (headline"))
    node_idx = [i for i, h in enumerate(heads) if h.startswith("Node ")]
    assert node_idx and all(i_hop < i for i in node_idx)
    first = heads[0].lower()
    assert "hop" in first and "node" in first and first.index("hop") < first.index("node")
    opening = section(md, heads[0])
    header = next(l for l in opening.splitlines() if l.startswith("| variant"))
    assert header.index("hop default") < header.index("node default")


def test_ab08_hop_headline_rows_are_hop_reading_and_carry_the_hop_note(rows):
    head = [r for r in rows if r["table"] == "headline_hop" and r["match_reading"] == "hop"]
    assert head and {r["variant"] for r in head} == {"full", "b1", "b2"}
    assert all(r["note"].startswith("hop reading") or r["note"].startswith("S06 margin") for r in head)
    top1 = next(r for r in head if r["variant"] == "full" and r["metric"] == "top1_expected")
    assert (top1["default"], top1["ablated"], top1["difference"]) == ("0.900000", "0.900000", "0.000000")
    assert top1["chance_all_default"] == "0.248333" and top1["chance_pos_ablated"] == "0.900000"


def test_ab08_node_reading_is_labelled_as_falling_by_construction(md, rows):
    node_section = section(md, "Node reading (beside the headline)")
    assert "falls by construction" in node_section and "key built from the same command-line evidence" in node_section
    prf = section(md, "Node P/R/F1/FNR and pooled AUC")
    assert "falls by construction" in prf
    node = [r for r in rows if r["table"] == "node_reading"]
    assert node and all("falls by construction" in r["note"] for r in node)
    head_node = [r for r in rows if r["table"] == "headline_hop" and r["match_reading"] == "node"]
    assert head_node and all("falls by construction" in r["note"] for r in head_node)


def test_ab08_node_recall_values_default_and_ablated_are_shown_side_by_side(rows):
    r = next(x for x in rows if x["table"] == "headline_hop" and x["variant"] == "full"
             and x["metric"] == "node_recall_mean")
    assert (r["default"], r["ablated"], r["difference"]) == ("0.877451", "0.400000", "-0.477451")
    r = next(x for x in rows if x["table"] == "headline_hop" and x["variant"] == "b0"
             and x["metric"] == "node_recall_mean")
    assert r["default"] == "0.877451" and r["variant"] == "b0"


def test_ab08_pooled_auc_is_shown_with_n_pos_n_neg_and_its_chance_line(rows):
    auc = next(x for x in rows if x["table"] == "headline_hop" and x["variant"] == "full" and x["metric"] == "auc")
    assert (auc["default"], auc["ablated"], auc["chance_all_default"]) == ("0.972222", "0.900000", "0.500000")
    n = {x["metric"]: (x["default"], x["ablated"]) for x in rows
         if x["table"] == "headline_hop" and x["variant"] == "full" and x["metric"] in ("auc_n_pos", "auc_n_neg")}
    assert n == {"auc_n_pos": ("6", "6"), "auc_n_neg": ("27", "27")}


def test_ab08_contested_reading_rows_are_present_for_the_hop_reading(rows):
    c = [r for r in rows if r["table"] == "contested_hop"]
    assert c and {r["contested_set"] for r in c} == {"paired"}
    assert any(r["metric"] == "contested_trial_ids" and r["default"] == "s98_t00" for r in c)


def test_ab08_key_attack_hop_tier_change_is_listed_in_the_key_hop_table(md, rows):
    changed = ar.changed_key_hops(rows)
    assert changed == ["s98_t00 k-h1: B -> D"]
    assert "Key attack hops whose best_tier changed: s98_t00 k-h1: B -> D." in section(md, "Key attack hops in both runs")


# ================================================================================================ AB-10 denominators
def test_ab10_per_trial_denominators_are_shown_for_both_runs(rows):
    h4 = [r for r in rows if r["table"] == "h4_denominators" and r["trial_id"] == "s98_t00"]
    got = {r["metric"]: (r["default"], r["ablated"]) for r in h4}
    for m, want in (("key_node_count", "21"), ("key_nodes_labelled", "3"), ("n_positive_units", "4"),
                    ("budget_nodes", "19.500000"), ("budget_nodes_labelled", "2.0")):
        assert got[m] == (want, want), m


def test_ab10_denominators_in_markdown_with_the_statement_that_none_moved(md):
    s = section(md, "H4 recall, both bases, with denominators (AB-10)")
    for m in ("key_node_count", "key_nodes_labelled", "n_positive_units", "budget_nodes", "budget_nodes_labelled"):
        assert m in s
    assert "No denominator moved" in s and "s98_t00" in s


def test_ab10_a_moved_denominator_is_stated(pair):
    d = pair[0]
    a = side(ablated=True)
    # rewrite the ablated rank.csv so n_positive_units moves from 4 to 3
    blobs = fx.side_blobs(TRIALS, True)
    text = blobs["evaluate/s98_t00/rank.csv"].decode().replace(",4,19.500000", ",3,19.500000")
    assert text != blobs["evaluate/s98_t00/rank.csv"].decode()
    blobs["evaluate/s98_t00/rank.csv"] = text.encode()
    a = ar.parse_side(blobs, fx.shas(blobs), TRIALS)
    rws = ar.all_rows(d, a, TRIALS)
    moves = ar.denominator_moves(rws)
    assert len(moves) == 1 and moves[0].startswith("s98_t00") and moves[0].endswith("n_positive_units 4 -> 3")
    s = section(ar.ablation_md(rws, TRIALS), "H4 recall, both bases, with denominators (AB-10)")
    assert "moved with the stitch output" in s and moves[0] in s and "No denominator moved" not in s


def test_ab10_no_denominator_moves_when_both_sides_are_equal(rows):
    assert ar.denominator_moves(rows) == []


# ================================================================================================ AB-03 per-method link counts
def test_ab03_link_counts_per_method_show_no_cmdline_row_in_the_ablated_run(rows):
    lm = {(r["trial_id"], r["item"]): (r["default"], r["ablated"]) for r in rows if r["table"] == "link_methods"}
    assert lm[("s98_t00", CMD)] == ("1", "0")
    assert lm[("all", CMD)] == ("2", "0")
    assert lm[("s98_t00", "target_only")] == ("1", "2")
    assert lm[("s98_t00", ar.SESSION_CMD_ITEM)][1] == "0"


def test_ab03_best_tier_counts_per_trial_and_total(rows):
    t = {(r["trial_id"], r["item"]): (r["default"], r["ablated"]) for r in rows if r["table"] == "best_tier"}
    assert t[("s98_t00", "B")] == ("1", "0") and t[("s98_t00", "D")] == ("1", "2")
    assert t[("all", "B")] == ("2", "0")


def test_ab03_no_hop_is_lost_between_the_two_sides(pair):
    d, a = pair
    for t in TRIALS:
        assert [h["hop_id"] for h in d.hops[t]] == [h["hop_id"] for h in a.hops[t]]


def test_ab03_trial_tables_skip_trials_without_key_rows(rows):
    per_trial = [r for r in rows if r["table"] in ("trial_hop", "key_path_hop", "h4_denominators") and r["trial_id"]]
    assert per_trial and {r["trial_id"] for r in per_trial} == {"s98_t00"}


def test_ab03_every_side_value_is_traceable_to_a_source_cell(rows):
    assert all(r["source"] for r in rows if r["table"] not in ("key_attack_hops",) or r["source"])


# ================================================================================================ determinism
def test_the_texts_are_deterministic_and_carry_no_timestamp(pair):
    r1 = ar.all_rows(pair[0], pair[1], TRIALS)
    r2 = ar.all_rows(pair[0], pair[1], TRIALS)
    assert r1 == r2
    t1, t2 = ar.ablation_md(r1, TRIALS), ar.ablation_md(r2, TRIALS)
    c1, c2 = ar.ablation_csv(r1), ar.ablation_csv(r2)
    assert (t1, c1) == (t2, c2)
    for text in (t1, c1, ar.readme_md(TRIALS, ["a", "b"], {"control": "passed", "ablated": "ok"})):
        assert not re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", text)
        assert "\r" not in text and text.endswith("\n")


def test_readme_carries_the_banner_and_says_it_is_not_a_result_and_no_verdict():
    text = ar.readme_md(TRIALS, ["ablation.md", "evaluate/"], {"control": "passed", "ablated": "ok"})
    assert text.splitlines()[0] == f"# {BANNER}"
    assert "not a result" in text and "no verdict" in text and "No stage reads this folder" in text
    assert "`ablation.md`" in text and "`evaluate/`" in text


# ================================================================================================ AB-05 / AB-06 input refusals
def test_ab05_a_default_side_whose_stitch_run_info_has_disabled_methods_is_refused():
    blobs = fx.side_blobs(TRIALS, False)
    info = json.loads(blobs["stitch/s98_t00/run_info.json"])
    info["disabled_methods"] = [CMD]
    blobs["stitch/s98_t00/run_info.json"] = json.dumps(info).encode()
    s = ar.parse_side(blobs, fx.shas(blobs), TRIALS)
    got = ar.disabled_problems(s, (), "default")
    assert len(got) == 1 and "s98_t00" in got[0] and "disabled_methods" in got[0]


def test_ab05_a_clean_default_side_has_no_problem(pair):
    assert ar.disabled_problems(pair[0], (), "default") == []


def test_ab06_an_ablated_side_whose_stitch_run_info_lacks_disabled_methods_is_refused():
    blobs = fx.side_blobs(TRIALS, True)
    info = json.loads(blobs["stitch/s97_t00/run_info.json"])
    del info["disabled_methods"]
    blobs["stitch/s97_t00/run_info.json"] = json.dumps(info).encode()
    s = ar.parse_side(blobs, fx.shas(blobs), TRIALS)
    got = ar.disabled_problems(s, ar.DISABLED, "ablated")
    assert len(got) == 1 and "s97_t00" in got[0]


def test_ab06_an_ablated_side_with_a_wrong_value_is_refused():
    blobs = fx.side_blobs(TRIALS, True)
    info = json.loads(blobs["stitch/s98_t00/run_info.json"])
    info["disabled_methods"] = ["source_4648"]
    blobs["stitch/s98_t00/run_info.json"] = json.dumps(info).encode()
    s = ar.parse_side(blobs, fx.shas(blobs), TRIALS)
    assert ar.disabled_problems(s, ar.DISABLED, "ablated")


def test_ab06_a_clean_ablated_side_has_no_problem(pair):
    assert ar.disabled_problems(pair[1], ar.DISABLED, "ablated") == []
    assert ar.DISABLED == (CMD,)


def test_ab07_an_ablated_side_that_still_has_a_cmdline_link_row_is_refused(pair):
    d = pair[0]                                   # the default side has cmdline rows: used as a bad "ablated" side
    got = ar.cmdline_link_problems(d, "ablated")
    assert got and all("cmdline_target" in g for g in got)
    assert ar.cmdline_link_problems(pair[1], "ablated") == []


def test_ab03_hash_chain_a_mismatch_between_evaluate_and_stitch_files_is_refused(pair):
    assert ar.chain_problems(pair[0], "default") == [] and ar.chain_problems(pair[1], "ablated") == []
    blobs = fx.side_blobs(TRIALS, True)
    blobs["stitch/s98_t00/links.csv"] += b"x\n"                 # the stitch file changed after evaluate named it
    s = ar.parse_side(blobs, fx.shas(blobs), TRIALS)
    got = ar.chain_problems(s, "ablated")
    assert len(got) == 1 and "links.csv" in got[0] and "s98_t00" in got[0]


def test_ab03_the_two_files_of_a_side_must_agree_on_the_key_hop_tier(pair):
    assert ar.tier_problems(pair[0], "default") == [] and ar.tier_problems(pair[1], "ablated") == []
    blobs = fx.side_blobs(TRIALS, True)
    summ = blobs["evaluate/development/link_accuracy_summary.csv"].decode().replace(",D,", ",B,", 1)
    blobs["evaluate/development/link_accuracy_summary.csv"] = summ.encode()
    s = ar.parse_side(blobs, fx.shas(blobs), TRIALS)
    assert ar.tier_problems(s, "ablated")


def test_ab09_results_files_in_the_scratch_summary_are_refused():
    assert ab.summary_problems(["results.md"]) and ab.summary_problems(["results.csv"])
    got = ab.summary_problems(["rank.md", "results.md", "results.csv", "rank_totals.csv"])
    assert len(got) == 2 and all("AB-09" in g for g in got)
    assert ab.summary_problems(["rank.md", "rank_totals.csv", "rank_sweep.csv", "link_accuracy_summary.csv"]) == []
    assert ab.summary_problems([]) == []
    assert set(ab.FORBIDDEN_SUMMARY_FILES) == {"results.md", "results.csv"}


# ================================================================================================ AB-02 / AB-11 helpers
def test_ab02_runner_argv_is_the_development_run_with_the_stitch_flag(tmp_path):
    argv = ab.runner_argv("py", tmp_path / "s")
    assert argv[:4] == ["py", "-m", "run_trial", "--development"]
    assert argv[4:6] == ["--repo", (tmp_path / "s").as_posix()]
    assert argv[6:] == ["--stitch-disable-method", CMD]


def test_ab02_copy_plan_has_four_stages_per_trial_then_the_development_summary():
    plan = [x.as_posix() for x in ab.copy_plan(DEV)]
    assert plan[:-1] == [f"{s}/{t}" for s in ("stitch", "label", "score", "evaluate") for t in DEV]
    assert plan[-1] == "evaluate/development"
    assert not [x for x in plan if "results" in x or "gate" in x or "run_trial" in x]


def test_ab11_exclude_ablation_drops_exactly_the_ablation_folder():
    tree = {"out/stitch/a": "1", "out/ablation/no_cmdline/x": "2", "out/ablation/no_cmdline/sub/y": "3",
            "out/ablation/no_cmdline_x/z": "4", "out/ablation/other/w": "5", "out/ablation/no_cmdline": "6"}
    got = ab.exclude_ablation(tree)
    assert sorted(got) == ["out/ablation/no_cmdline", "out/ablation/no_cmdline_x/z", "out/ablation/other/w",
                           "out/stitch/a"]


def test_ab11_swap_in_replaces_the_whole_folder_and_leaves_no_temporary_or_old_folder(tmp_path):
    base = tmp_path / "out" / "ablation"
    target, tmp = base / "no_cmdline", base / ab.TMP_NAME
    target.mkdir(parents=True)
    (target / "stale.txt").write_text("old", encoding="utf-8")
    tmp.mkdir()
    (tmp / "new.txt").write_text("new", encoding="utf-8")
    ab.swap_in(tmp, target)
    assert sorted(f.name for f in target.iterdir()) == ["new.txt"]
    assert not tmp.exists() and not (base / ab.OLD_NAME).exists()


def test_ab11_swap_in_without_an_existing_target_just_moves_the_folder_in(tmp_path):
    base = tmp_path / "ablation"
    base.mkdir()
    tmp = base / ab.TMP_NAME
    tmp.mkdir()
    (tmp / "a").write_text("x", encoding="utf-8")
    ab.swap_in(tmp, base / "no_cmdline")
    assert (base / "no_cmdline" / "a").read_text(encoding="utf-8") == "x" and not tmp.exists()


def test_ab11_swap_in_puts_the_old_folder_back_if_the_second_rename_fails(tmp_path):
    base = tmp_path / "ablation"
    target = base / "no_cmdline"
    target.mkdir(parents=True)
    (target / "keep.txt").write_text("keep", encoding="utf-8")
    missing = base / ab.TMP_NAME                               # does not exist: the second rename fails
    with pytest.raises(OSError):
        ab.swap_in(missing, target)
    assert (target / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_ab03_run_info_lists_inputs_copies_outputs_banner_and_the_disabled_set():
    arms = [ab.ArmStatus("control", "passed", 0, {"identical": 3}), ab.ArmStatus("ablated", "ok", 0)]
    info = ab.run_info(["t"], arms, {"out/a": "1"}, {"b": "2"}, {"c": "3"}, {"m": "5"}, {"d": "4"},
                       "2026-11-25T00:00:00Z")
    assert info["banner"] == BANNER and info["disabled_methods"] == [CMD] and info["trials"] == ["t"]
    assert info["inputs"] == {"default": {"out/a": "1"}, "ablated": {"b": "2"}}
    assert info["copied_files_sha256"] == {"c": "3"} and info["outputs_sha256"] == {"d": "4"}
    assert "--stitch-disable-method cmdline_target" in info["arms"]["ablated"]["command"]
    assert "--stitch-disable-method" not in info["arms"]["control"]["command"]


def test_ab03_side_files_list_covers_each_trial_and_the_development_summary():
    files = ar.side_files(TRIALS)
    assert files[:2] == ["evaluate/development/rank_totals.csv", "evaluate/development/link_accuracy_summary.csv"]
    for t in TRIALS:
        for f in (f"evaluate/{t}/rank.csv", f"evaluate/{t}/run_info.json", f"stitch/{t}/hops.csv",
                  f"stitch/{t}/links.csv", f"stitch/{t}/run_info.json"):
            assert f in files
    assert len(files) == 2 + 5 * len(TRIALS) and len(set(files)) == len(files)
    assert not [f for f in files if "results" in f]




def test_ab02_runner_argv_with_no_disabled_method_is_the_plain_development_run(tmp_path):
    argv = ab.runner_argv("py", tmp_path / "s", ())
    assert argv == ["py", "-m", "run_trial", "--development", "--repo", (tmp_path / "s").as_posix()]


def test_ab11_settle_leftovers_restores_an_old_folder_when_the_target_is_missing_and_never_deletes_it(tmp_path):
    base = tmp_path / "ablation"
    (base / ab.OLD_NAME).mkdir(parents=True)
    (base / ab.OLD_NAME / "keep.txt").write_text("previous run", encoding="utf-8")
    notes = ab.settle_leftovers(base)
    assert len(notes) == 1 and (base / "no_cmdline" / "keep.txt").read_text(encoding="utf-8") == "previous run"
    assert not (base / ab.OLD_NAME).exists()


def test_ab11_settle_leftovers_deletes_an_old_folder_beside_a_live_target_and_a_tmp_only_at_start(tmp_path):
    base = tmp_path / "ablation"
    for n in ("no_cmdline", ab.OLD_NAME, ab.TMP_NAME):
        (base / n).mkdir(parents=True)
    ab.settle_leftovers(base, include_tmp=False)                 # during the swap the tmp folder is the pending copy
    assert (base / "no_cmdline").exists() and (base / ab.TMP_NAME).exists() and not (base / ab.OLD_NAME).exists()
    ab.settle_leftovers(base)
    assert (base / "no_cmdline").exists() and not (base / ab.TMP_NAME).exists()


# ================================================================================================ the driver, end to end (fake arms)
def put(root: Path, blobs: dict[str, bytes]) -> None:
    for rel, data in blobs.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)


def committed_tree(repo: Path) -> dict[str, str]:
    return ab.exclude_ablation(dryrun.hash_files(repo, dryrun.tree_files(repo, DEV)))


class Driver:
    """A synthetic repo with a default side under out/. The control arm is replaced by a stub (its comparison is the dry
    run's, tested elsewhere); the ablated arm runs for real except for the child process, replaced by a fake that writes
    an ablated side into the scratch repo (optionally broken in one way)."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, default_has_disabled: bool = False,
                 ablated_lacks_disabled: bool = False, results_file: str | None = None, exit_code: int = 0,
                 control: str = "passed") -> None:
        self.tmp_path = tmp_path
        self.repo = synthetic_repo(tmp_path / "repo")
        self.argv: list[list[str]] = []
        self.scratches: list[Path] = []
        dflt = fx.side_blobs(DEV, False, keyed=DEV[:1])
        if default_has_disabled:
            info = json.loads(dflt[f"stitch/{DEV[0]}/run_info.json"])
            info["disabled_methods"] = [CMD]
            dflt[f"stitch/{DEV[0]}/run_info.json"] = json.dumps(info).encode()
        put(self.repo / "out", dflt)
        for t in DEV:                                            # label / score folders exist in the on-disk out/
            for stage in ("label", "score"):
                put(self.repo / "out", {f"{stage}/{t}/x.csv": b"d\n1\n"})
        self.ablated = fx.side_blobs(DEV, True, keyed=DEV[:1])
        if ablated_lacks_disabled:
            info = json.loads(self.ablated[f"stitch/{DEV[0]}/run_info.json"])
            del info["disabled_methods"]
            self.ablated[f"stitch/{DEV[0]}/run_info.json"] = json.dumps(info).encode()
        self.results_file, self.exit_code, self.control = results_file, exit_code, control
        monkeypatch.setattr(p, "REPO", self.repo)
        monkeypatch.setattr(ab, "make_scratch", self.make_scratch)
        monkeypatch.setattr(ab, "_run", self.fake_run)
        monkeypatch.setattr(ab, "_control_arm", self.fake_control)
        import tempfile
        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path / "systmp"))

    def make_scratch(self, repo: Path, prefix: str) -> Path:
        path = self.tmp_path / f"scratch{len(self.scratches)}"
        path.mkdir()
        self.scratches.append(path)
        return path

    def fake_control(self, repo, scratch, holder, trials):
        problems = [] if self.control == "passed" else ["s98_t00/links.csv: different"]
        return ab.ArmStatus("control", self.control, 0, {"identical": 5}, problems)

    def fake_run(self, argv, holder, capture):
        self.argv.append(list(argv))
        if self.exit_code:
            return self.exit_code, "", ""
        scratch = Path(argv[argv.index("--repo") + 1])
        put(scratch / "out", self.ablated)
        for t in DEV:
            for stage in ("label", "score"):
                put(scratch / "out", {f"{stage}/{t}/x.csv": b"d\n1\n"})
        put(scratch / "out", {"evaluate/development/rank.md": b"# rank\n"})
        if self.results_file:
            put(scratch / "out", {f"evaluate/development/{self.results_file}": b"x\n"})
        return 0, "", ""

    @property
    def target(self) -> Path:
        return self.repo / "out" / "ablation" / "no_cmdline"


def test_ab02_driver_happy_path_writes_the_folder_and_deletes_every_scratch_repo(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch)
    stale = d.target / "stale.txt"
    stale.parent.mkdir(parents=True)
    stale.write_text("old run", encoding="utf-8")
    before = committed_tree(d.repo)
    code = ab.main([])
    out = capsys.readouterr().out
    assert code == 0 and "ablation: DONE" in out
    assert len(d.argv) == 1 and d.argv[0][-2:] == ["--stitch-disable-method", CMD] and "--development" in d.argv[0]
    assert d.scratches and all(not s.exists() for s in d.scratches)          # DR-05
    assert not stale.exists()                                                # AB-11: the whole folder is replaced
    names = {f.name for f in d.target.iterdir()}
    assert {"README.md", "ablation.md", "ablation.csv", "run_info.json", "stitch", "label", "score",
            "evaluate"} <= names
    assert not [f for f in d.target.rglob("*") if f.name in ("results.md", "results.csv")]   # AB-09
    assert not (d.repo / "out" / "ablation" / ab.TMP_NAME).exists()
    assert committed_tree(d.repo) == before                                  # DR-06: nothing else changed
    info = json.loads((d.target / "run_info.json").read_text(encoding="utf-8"))
    assert info["disabled_methods"] == [CMD] and info["banner"] == BANNER and info["trials"] == list(DEV)
    for name in ("ablation.md", "ablation.csv", "README.md"):                # written hashes equal the files
        assert info["outputs_sha256"][name] == hashlib.sha256((d.target / name).read_bytes()).hexdigest()
    assert (d.target / "ablation.md").read_text(encoding="utf-8").startswith(f"# {BANNER}")
    assert (d.target / "stitch" / DEV[0] / "run_info.json").is_file()


def test_ab09_every_markdown_and_marker_file_of_the_folder_carries_the_banner(tmp_path, monkeypatch):
    d = Driver(tmp_path, monkeypatch)
    assert ab.main([]) == 0
    for f in ("README.md", "ablation.md"):
        assert BANNER in (d.target / f).read_text(encoding="utf-8")
    markers = list(d.target.rglob(ab.MARKER))
    assert len(markers) == len(ab.copy_plan(DEV))                            # one in every copied folder
    assert all(BANNER in m.read_text(encoding="utf-8") for m in markers)


def test_ab02_driver_rerun_replaces_the_folder_again_and_gives_identical_tables(tmp_path, monkeypatch):
    d = Driver(tmp_path, monkeypatch)
    assert ab.main([]) == 0
    first = {n: (d.target / n).read_bytes() for n in ("ablation.md", "ablation.csv", "README.md")}
    (d.target / "extra.txt").write_text("x", encoding="utf-8")
    d.scratches.clear()
    assert ab.main([]) == 0
    assert not (d.target / "extra.txt").exists()
    assert {n: (d.target / n).read_bytes() for n in first} == first          # deterministic tables


def assert_refused(d: Driver, capsys, needle: str, *, kept_stale: bool) -> None:
    code = ab.main([])
    cap = capsys.readouterr()
    assert code == 1 and "ablation: FAILED" in cap.out
    assert needle in cap.err
    assert all(not s.exists() for s in d.scratches)
    assert not (d.repo / "out" / "ablation" / ab.TMP_NAME).exists()
    assert (d.target / "stale.txt").exists() is kept_stale
    if not kept_stale:
        assert not d.target.exists()


def test_ab05_driver_refuses_when_a_default_stitch_run_info_has_disabled_methods(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch, default_has_disabled=True)
    assert_refused(d, capsys, "disabled_methods", kept_stale=False)
    assert d.argv == [] and d.scratches == []                                 # refused before any scratch run


def test_ab06_driver_refuses_when_a_copied_ablated_run_info_lacks_disabled_methods(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch, ablated_lacks_disabled=True)
    d.target.mkdir(parents=True)
    (d.target / "stale.txt").write_text("old", encoding="utf-8")
    assert_refused(d, capsys, "disabled_methods", kept_stale=True)            # the old folder is untouched


@pytest.mark.parametrize("name", ["results.md", "results.csv"])
def test_ab09_driver_refuses_when_results_files_would_be_copied(tmp_path, monkeypatch, capsys, name):
    d = Driver(tmp_path, monkeypatch, results_file=name)
    assert_refused(d, capsys, "AB-09", kept_stale=False)
    assert not list(d.repo.rglob(name))


def test_ab02_driver_fails_and_copies_nothing_when_the_ablated_scratch_run_fails(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch, exit_code=1)
    assert_refused(d, capsys, "exit 1", kept_stale=False)


def test_ab11_driver_refuses_and_swaps_nothing_when_the_control_arm_does_not_reproduce_out(tmp_path, monkeypatch,
                                                                                         capsys):
    d = Driver(tmp_path, monkeypatch, control="failed")
    d.target.mkdir(parents=True)
    (d.target / "stale.txt").write_text("old", encoding="utf-8")
    assert_refused(d, capsys, "control arm", kept_stale=True)
    assert d.argv == []                                                       # the ablated arm never ran


def test_ab02_driver_warns_about_a_leftover_scratch_folder_and_never_deletes_it(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch)
    left = tmp_path / "systmp" / "run_trial_ablation_old1"
    left.mkdir(parents=True)
    assert ab.main([]) == 0
    assert "leftover" in capsys.readouterr().out and left.exists()
    assert d.target.is_dir()
