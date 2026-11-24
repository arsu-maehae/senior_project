"""Spec 06_evaluate section 10, runner half of the ablation switch and the timing tables: AB-02, AB-06, AB-09, PT-01, PT-02
(fast, synthetic). Written from the spec, not from the code.

Rules tested:
- AB-02 / AB-09: `trial_steps(t, R)` without the flag is exactly the old argv (pinned literally below); with the flag
  only the stitch step gains `--disable-method cmdline_target`; `summary_steps(with_results=False)` leaves out
  `evaluate --development --results` and changes nothing else.
- AB-06: `--stitch-disable-method` with the real repository is refused (exit 2) before any stage starts and before any
  log is written; an unknown method name is refused the same way.
- PT-01 / PT-02: `run_log.md` has a per-scenario table with n trials and mean and min-max per stage and in total, and
  a db_MB column with its unit (MB = 10^6 bytes) beside each trial's time.
Nothing real is opened; nothing is written under the real `out/` (root conftest guard).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_trial import __main__ as rt_main  # noqa: E402
from run_trial import params as p  # noqa: E402
from run_trial import runlog  # noqa: E402
from run_trial.execute import StepRecord  # noqa: E402
from run_trial.steps import Step, summary_steps, trial_steps  # noqa: E402
from test_run_trial_runner import FakeRun, T, boom_run, make_repo, read_log, tree  # noqa: E402

CMD = "cmdline_target"
DEV = tuple(p.DEVELOPMENT_TRIALS)
KEYED = tuple(t for t in DEV if t in p.KEYED_DEVELOPMENT_TRIALS)
UNKEYED = tuple(t for t in DEV if t not in p.KEYED_DEVELOPMENT_TRIALS)
FAKE_REPO = Path("D:/scratch_repo_for_argv")        # a path that is never opened: only the argv text is built


def shape(steps: list[Step]) -> list[tuple[str, str, tuple[str, ...]]]:
    return [(s.name, s.module, s.args) for s in steps]


def old_argv(trial: str, repo: Path) -> list[tuple[str, str, tuple[str, ...]]]:
    """The argv of the pre-ablation runner (spec 06 RT-03), written out by hand."""
    gate_out = (repo / "out" / "gate").as_posix()
    rows = [("gate", "gate", ("--trial", trial, "--out", gate_out)),
            ("stitch", "stitch", ("--trial", trial)),
            ("label", "label", ("--trial", trial)),
            ("score", "score", ("--trial", trial)),
            ("evaluate", "evaluate", ("--trial", trial))]
    if trial in p.KEYED_DEVELOPMENT_TRIALS:
        rows.append(("evaluate_label_recall", "evaluate", ("--trial", trial, "--label-recall")))
    rows.append(("evaluate_rank", "evaluate", ("--trial", trial, "--rank")))
    return rows


# ================================================================================================ AB-02 trial_steps
@pytest.mark.parametrize("trial", DEV)
def test_ab02_trial_steps_without_the_flag_is_exactly_the_old_argv(trial):
    assert shape(trial_steps(trial, FAKE_REPO)) == old_argv(trial, FAKE_REPO)
    assert shape(trial_steps(trial, FAKE_REPO, ())) == old_argv(trial, FAKE_REPO)
    assert shape(trial_steps(trial, FAKE_REPO, [])) == old_argv(trial, FAKE_REPO)


@pytest.mark.parametrize("trial", DEV)
def test_ab02_with_the_flag_only_the_stitch_step_gains_disable_method(trial):
    base, abl = trial_steps(trial, FAKE_REPO), trial_steps(trial, FAKE_REPO, (CMD,))
    assert [s.name for s in base] == [s.name for s in abl]
    for b, a in zip(base, abl):
        if a.name == "stitch":
            assert a.args == (*b.args, "--disable-method", CMD)
        else:
            assert a == b, a.name
        assert a.outputs == b.outputs                      # the files each step must write do not change


def test_ab02_the_flag_is_given_once_even_if_repeated_and_in_a_fixed_order():
    (stitch,) = [s for s in trial_steps(T, FAKE_REPO, (CMD, CMD)) if s.name == "stitch"]
    assert stitch.args == ("--trial", T, "--disable-method", CMD)


def test_ab02_keyed_and_unkeyed_trials_keep_their_own_step_lists():
    names = {t: [s.name for s in trial_steps(t, FAKE_REPO, (CMD,))] for t in DEV}
    for t in KEYED:
        assert "evaluate_label_recall" in names[t]
    for t in UNKEYED:
        assert "evaluate_label_recall" not in names[t]


# ================================================================================================ AB-09 summary_steps
def test_ab09_summary_steps_default_has_four_steps_ending_with_results():
    steps = summary_steps()
    assert [s.name for s in steps][-1] == "evaluate_development_results"
    assert ("--development", "--results") in [s.args for s in steps]
    assert len(steps) == 4
    assert shape(summary_steps(DEV)) == shape(steps)


def test_ab09_summary_steps_without_results_omits_only_the_results_step():
    full, part = summary_steps(), summary_steps(with_results=False)
    assert [s.name for s in part] == [s.name for s in full][:-1]
    assert all("--results" not in s.args for s in part)
    assert part == full[:-1]


def test_ab09_summary_steps_with_results_true_is_the_default():
    assert summary_steps(with_results=True) == summary_steps()


# ================================================================================================ AB-06 refusals
def run_log_files(root: Path) -> list[str]:
    base = root / "out" / "run_trial"
    return sorted(f.relative_to(base).as_posix() for f in base.rglob("*") if f.is_file()) if base.is_dir() else []


@pytest.mark.parametrize("argv", [["--development"], ["--trial", T]])
def test_ab06_the_real_repo_is_refused_before_any_stage_and_no_log_is_written(argv, capsys):
    before = run_log_files(REPO)
    code = rt_main.main([*argv, "--repo", str(REPO), "--stitch-disable-method", CMD], run_fn=boom_run)
    assert code == p.EXIT_REFUSED == 2
    assert "refused" in capsys.readouterr().err
    assert run_log_files(REPO) == before


@pytest.mark.parametrize("argv", [["--development"], ["--trial", T]])
def test_ab06_no_repo_argument_means_the_real_repo_and_is_refused(argv, capsys):
    before = run_log_files(REPO)
    assert rt_main.main([*argv, "--stitch-disable-method", CMD], run_fn=boom_run) == 2
    assert "refused" in capsys.readouterr().err
    assert run_log_files(REPO) == before


def test_ab06_a_folder_inside_the_real_repo_is_refused(capsys):
    assert rt_main.main(["--development", "--repo", str(REPO / "docs"), "--stitch-disable-method", CMD],
                        run_fn=boom_run) == 2


def test_ab06_run_trial_and_run_development_functions_refuse_the_real_repo_too(capsys):
    before = run_log_files(REPO)
    log, code = rt_main.run_trial(T, REPO, ".", boom_run, stitch_disabled=(CMD,))
    assert (log, code) == ({}, 2)
    log, code = rt_main.run_development(REPO, ".", boom_run, stitch_disabled=(CMD,))
    assert (log, code) == ({}, 2)
    assert run_log_files(REPO) == before


@pytest.mark.parametrize("name", ["source_4648", "sysmon3_port", "bogus"])
def test_ab01_unknown_method_is_refused_before_any_stage_in_a_scratch_repo(tmp_path, capsys, name):
    repo = make_repo(tmp_path / "r")
    before = tree(repo)
    code = rt_main.main(["--development", "--repo", str(repo), "--stitch-disable-method", name], run_fn=boom_run)
    err = capsys.readouterr().err
    assert code == 2 and "refused" in err and name in err
    assert tree(repo) == before                            # no run_trial folder, nothing created


def test_ab06_a_scratch_repo_is_accepted_and_every_stitch_step_gets_the_flag(tmp_path):
    repo = make_repo(tmp_path / "r", DEV)
    fk = FakeRun(write_outputs=True)
    code = rt_main.main(["--development", "--repo", str(repo), "--stitch-disable-method", CMD], run_fn=fk)
    assert code == 0
    stitch_calls = [a for m, _t, a in fk.calls if m == "stitch"]
    assert len(stitch_calls) == len(DEV)
    assert all(a[-2:] == ("--disable-method", CMD) for a in stitch_calls)
    other = [a for m, _t, a in fk.calls if m != "stitch"]
    assert all("--disable-method" not in a for a in other)
    assert all("--results" not in a for a in other)         # AB-09: --results is not run
    log = read_log(repo, "development")
    assert log["stitch_disabled_methods"] == [CMD]
    md = (repo / "out" / "run_trial" / "development" / "run_log.md").read_text(encoding="utf-8")
    assert "ABLATION" in md and CMD in md


def test_ab06_without_the_flag_the_development_chain_is_unchanged(tmp_path):
    repo = make_repo(tmp_path / "r", DEV)
    fk = FakeRun(write_outputs=True)
    assert rt_main.main(["--development", "--repo", str(repo)], run_fn=fk) == 0
    assert all("--disable-method" not in a for _m, _t, a in fk.calls)
    assert ("evaluate", "", ("--development", "--results")) in fk.calls
    log = read_log(repo, "development")
    assert "stitch_disabled_methods" not in log
    md = (repo / "out" / "run_trial" / "development" / "run_log.md").read_text(encoding="utf-8")
    assert "ABLATION" not in md


# ================================================================================================ PT-01 / PT-02 run_log.md
def rec(step: str, ms: int | None, result: str = p.STATUS_OK) -> StepRecord:
    return StepRecord(step=step, argv=[], exit_code=0, wall_ms=ms, stderr_tail="", result=result)


def ok_trial(trial: str, walls: dict[str, int]) -> dict[str, Any]:
    return runlog.trial_log(trial, ".", [rec(s, walls[s]) for s in runlog.STAGE_COLUMNS if s in walls],
                            "2026-11-25T00:00:00Z")


WALLS_A = dict(gate=100, stitch=200, label=50, score=60, evaluate=10, evaluate_label_recall=5, evaluate_rank=7)
WALLS_B = dict(gate=300, stitch=400, label=70, score=80, evaluate=30, evaluate_label_recall=15, evaluate_rank=9)
WALLS_C = dict(gate=11, stitch=22, label=33, score=44, evaluate=55, evaluate_rank=66)        # an unkeyed trial


def synthetic_dev_md() -> tuple[dict[str, Any], str]:
    logs = [ok_trial("s98_t00", WALLS_A), ok_trial("s98_t01", WALLS_B), ok_trial("s97_t00", WALLS_C)]
    sizes = {"s98_t00": 2_500_000, "s98_t01": 1_000_000, "s97_t00": None}
    dev = runlog.development_log(".", logs, [], [rec("evaluate_development", 3)], "2026-11-25T00:00:00Z",
                                 db_sizes=sizes)
    return dev, runlog.development_md(dev)


def table_after(md: str, heading: str) -> list[list[str]]:
    """Cells of the data rows of the first Markdown table after the `## heading` line."""
    lines = md.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith(f"## {heading}"))
    rows = []
    for l in lines[start + 1:]:
        if l.startswith("## "):
            break
        if l.startswith("|") and not set(l) <= set("|-"):
            rows.append([c.strip() for c in l.strip().strip("|").split("|")])
    return rows[1:]                                          # drop the header row


def header_after(md: str, heading: str) -> list[str]:
    lines = md.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith(f"## {heading}"))
    for l in lines[start + 1:]:
        if l.startswith("|"):
            return [c.strip() for c in l.strip().strip("|").split("|")]
    raise AssertionError("no table")


def test_pt01_scenario_table_exists_with_one_row_per_scenario_and_n_trials():
    _dev, md = synthetic_dev_md()
    rows = table_after(md, "Processing time per scenario")
    assert [(r[0], r[1]) for r in rows] == [("s98", "2"), ("s97", "1")]


def test_pt01_scenario_table_header_has_every_stage_and_a_total():
    _dev, md = synthetic_dev_md()
    head = header_after(md, "Processing time per scenario")
    assert head[:2] == ["scenario", "n_trials"]
    for stage in runlog.STAGE_COLUMNS:
        assert stage in head
    assert head[-1] == "total_ms"


def test_pt01_pt02_mean_and_min_max_per_stage_and_in_total_for_a_two_trial_scenario():
    """gate 100 and 300: mean 200, min 100, max 300. total: 432 and 904 -> mean 668, min 432, max 904."""
    _dev, md = synthetic_dev_md()
    head = header_after(md, "Processing time per scenario")
    (row,) = [r for r in table_after(md, "Processing time per scenario") if r[0] == "s98"]
    gate, total = row[head.index("gate")], row[head.index("total_ms")]
    assert "200" in gate and "100" in gate and "300" in gate
    assert "668" in total and "432" in total and "904" in total
    stitch = row[head.index("stitch")]
    assert "300" in stitch and "200" in stitch and "400" in stitch


def test_pt01_a_one_trial_scenario_shows_its_own_value_as_mean_min_and_max():
    _dev, md = synthetic_dev_md()
    head = header_after(md, "Processing time per scenario")
    (row,) = [r for r in table_after(md, "Processing time per scenario") if r[0] == "s97"]
    assert row[1] == "1"
    assert row[head.index("gate")].startswith("11")
    assert row[head.index("total_ms")].startswith("231")          # 11 + 22 + 33 + 44 + 55 + 66


def test_pt01_a_stage_a_scenario_did_not_run_shows_a_dash_or_a_k_of_n_note():
    """The unkeyed trial never ran label recall: its cell is '-', not 0 (a zero would pull a mean down)."""
    _dev, md = synthetic_dev_md()
    head = header_after(md, "Processing time per scenario")
    (row,) = [r for r in table_after(md, "Processing time per scenario") if r[0] == "s97"]
    assert row[head.index("evaluate_label_recall")] == "-"


def test_pt02_scenario_rows_function_gives_n_mean_min_max():
    dev, _md = synthetic_dev_md()
    rows = {r["scenario"]: r for r in runlog.scenario_rows(dev["trials"])}
    g = rows["s98"]["gate"]
    assert (g["n"], g["mean"], g["min"], g["max"]) == (2, 200.0, 100, 300)
    t = rows["s98"]["total_ms"]
    assert (t["n"], t["mean"], t["min"], t["max"]) == (2, 668.0, 432, 904)
    assert rows["s98"]["n_trials"] == 2 and rows["s97"]["n_trials"] == 1


def test_pt02_db_mb_column_is_beside_each_trial_with_its_unit_stated():
    _dev, md = synthetic_dev_md()
    assert "db_MB" in md and "10^6" in md                          # the unit: 1 MB = 10^6 bytes
    trial_rows = [l for l in md.splitlines() if l.startswith("| s98_t00 |") or l.startswith("| s98_t01 |")
                  or l.startswith("| s97_t00 |")]
    first_table = [l for l in trial_rows if "ok" in l.split("|")[2]]
    assert len(first_table) == 3
    cells = {l.split("|")[1].strip(): [c.strip() for c in l.strip().strip("|").split("|")] for l in first_table}
    table_head = next(l for l in md.splitlines() if l.startswith("| trial_id |"))
    cols = [c.strip() for c in table_head.strip().strip("|").split("|")]
    i = cols.index("db_MB")
    assert cols[i - 1] == "status"
    assert cells["s98_t00"][i] == "2.5" and cells["s98_t01"][i] == "1.0" and cells["s97_t00"][i] == "-"


def test_pt02_db_mb_uses_decimal_megabytes():
    assert runlog.db_mb(1_000_000) == "1.0"
    assert runlog.db_mb(1_048_576) == "1.0"                        # 1 MiB is 1.05 MB: one decimal gives 1.0
    assert runlog.db_mb(2_500_000) == "2.5"
    assert runlog.db_mb(None) == "-"
    assert p.DB_MB == 1_000_000


def test_pt01_the_timing_table_is_machine_dependent_and_says_it_is_not_copied_into_results():
    _dev, md = synthetic_dev_md()
    assert "machine-dependent" in md.lower() or "machine dependent" in md.lower()
    assert "never copied into results" in md


def test_pt01_run_log_md_is_deterministic_for_one_log():
    dev, md = synthetic_dev_md()
    assert runlog.development_md(dev) == md
    assert json.loads(runlog.json_text(dev))["db_size_bytes"]["s98_t00"] == 2_500_000


def test_pt01_a_stopped_trial_does_not_pull_a_scenario_mean_down():
    failed = runlog.trial_log("s98_t01", ".", [rec("gate", 5, p.STATUS_FAILED)], "2026-11-25T00:00:00Z")
    rows = {r["scenario"]: r for r in runlog.scenario_rows([ok_trial("s98_t00", WALLS_A), failed])}
    assert rows["s98"]["n_trials"] == 1 and rows["s98"]["gate"]["mean"] == 100.0
