"""Spec 06_evaluate section 10 D-H (built-code review, ATK-EV-37..46): AB-12, AB-13, AB-15, AB-16, NP-06, SW-05
(fast, synthetic; the on-disk `out/` files are read only, and only when present). Written from the spec, not from the code
(names and signatures only).

Rules tested:
- AB-15 refusal guards: label / score / evaluate refuse a stitch run_info.json with a non-empty `disabled_methods` when the
  repository is the real one (simulated: `real_repo` = a pytest tmp folder), accept it in a scratch repo, and accept a default
  run_info (no key) everywhere; the stitch and runner refusals resolve `<repo>/out/stitch`, `<repo>/out/stitch/<trial>` and
  `--out` through directory junctions / symlinks (created in tmp folders; skipped if neither can be made).
- AB-12: a failing no-flag control arm exits 1, copies nothing, swaps nothing, leaves an existing `out/ablation/no_cmdline`
  untouched and records nothing as passed; `control_status` passes only with exit 0, no mismatch and no folder problem.
- AB-13: with `cmdline_target` disabled a name check that would have run is `not_run`, never `no_match`; the default run
  never writes `not_run`.
- AB-16: the swap comes only after the final tree check; a leftover `.no_cmdline.old` without `no_cmdline` is restored; the
  README says labels, the answer key and process nodes of port / 4648 linked sessions still carry command text.
- NP-06 / SW-05: wording of ablation.md, results.md and rank.md.
Nothing real is written; the real `out/` is never written (root conftest guard). No test-split trial id is used.
"""
from __future__ import annotations

import csv
import importlib
import io
import json
import os
import re
import subprocess
import sys
from functools import partial
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ablation_fixtures as fx  # noqa: E402
import test_stitch_outputs as tso  # noqa: E402
import test_stitch_source as tss  # noqa: E402
from evaluate import __main__ as em  # noqa: E402
from evaluate import rank_report as rr  # noqa: E402
from evaluate import rank_sweep as sw  # noqa: E402
from evaluate import results_report as res_rep  # noqa: E402
from evaluate.results_run import real_repo_ablation_refusal  # noqa: E402
from label import inputs as label_inputs  # noqa: E402
from label import run as label_run  # noqa: E402
from label.errors import LabelError  # noqa: E402
from run_trial import ablation as ab  # noqa: E402
from run_trial import ablation_report as ar  # noqa: E402
from run_trial import params as p  # noqa: E402
from run_trial.checks import ablation_refusal  # noqa: E402
from run_trial.dryrun_compare import DIFFERS, EOL_ONLY, EQUAL_NORMALISED, IDENTICAL, MISSING, NEW, FileResult  # noqa: E402
from score import inputs as score_inputs  # noqa: E402
from score.errors import ScoreError  # noqa: E402
from stitch import tiers  # noqa: E402
from stitch.params import StitchParams  # noqa: E402
from test_run_trial_ablation_report import DEV, Driver, committed_tree  # noqa: E402

sm = importlib.import_module("stitch.__main__")

CMD = "cmdline_target"
TRIAL = "s04_t00"
ORIG_CONTROL = ab._control_arm                           # the real control arm (Driver replaces it by a stub)
ABLATED_INFO = {"disabled_methods": [CMD], "tool_version": "stitch test"}
DEFAULT_INFO = {"tool_version": "stitch test"}


def write_info(root: Path, info: dict, trial: str = TRIAL) -> Path:
    folder = root / "out" / "stitch" / trial
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "run_info.json").write_text(json.dumps(info), encoding="utf-8")
    return folder


def tree_listing(root: Path) -> dict[str, bytes]:
    return {f.relative_to(root).as_posix(): f.read_bytes() for f in sorted(root.rglob("*")) if f.is_file()}


# ================================================================================================ AB-15 guards: label
@pytest.mark.parametrize("value", [[CMD], (CMD,), CMD])
def test_ab15_label_refuses_a_non_empty_disabled_methods_in_the_real_repo(tmp_path, value):
    with pytest.raises(LabelError, match="disabled_methods"):
        label_inputs.check_not_ablated({"disabled_methods": value}, tmp_path, real_repo=tmp_path)


def test_ab15_label_accepts_the_same_run_info_in_a_scratch_repo(tmp_path):
    real, scratch = tmp_path / "real", tmp_path / "scratch"
    real.mkdir(), scratch.mkdir()
    label_inputs.check_not_ablated(ABLATED_INFO, scratch, real_repo=real)


@pytest.mark.parametrize("info", [{}, DEFAULT_INFO, {"disabled_methods": []}, {"disabled_methods": None}])
def test_ab15_label_accepts_a_default_run_info_everywhere(tmp_path, info):
    real, scratch = tmp_path / "real", tmp_path / "scratch"
    real.mkdir(), scratch.mkdir()
    label_inputs.check_not_ablated(info, real, real_repo=real)
    label_inputs.check_not_ablated(info, scratch, real_repo=real)


def test_ab15_label_trial_calls_the_guard_after_loading_the_stitch_run(tmp_path, monkeypatch):
    """Wiring: `label_trial` refuses in the real repo before any later step (the later steps are stubs that fail the
    test if reached). The real repo is simulated by changing the guard's default `real_repo`."""
    root, other = tmp_path / "real", tmp_path / "scratch"
    root.mkdir(), other.mkdir()
    monkeypatch.setattr(label_inputs.check_not_ablated, "__defaults__", (root,))
    state = {"info": ABLATED_INFO}

    class Reached(Exception):
        pass

    def boom(*a, **k):
        raise Reached()
    monkeypatch.setattr(label_run, "trial_paths", lambda repo, t: object())
    monkeypatch.setattr(label_run, "check_allowed", lambda paths: object())
    monkeypatch.setattr(label_run, "load_stitch", lambda folder: SimpleNamespace(run_info=state["info"]))
    monkeypatch.setattr(label_run, "check_stitch_fresh", boom)
    with pytest.raises(LabelError, match="disabled_methods"):
        label_run.label_trial(root, TRIAL)
    with pytest.raises(Reached):                                       # scratch repo: the guard lets it through
        label_run.label_trial(other, TRIAL)
    state["info"] = DEFAULT_INFO
    with pytest.raises(Reached):                                       # default run_info, real repo: lets it through
        label_run.label_trial(root, TRIAL)


# ================================================================================================ AB-15 guards: score
@pytest.mark.parametrize("value", [[CMD], (CMD,), CMD])
def test_ab15_score_refuses_a_non_empty_disabled_methods_in_the_real_repo(tmp_path, value):
    with pytest.raises(ScoreError, match="disabled_methods"):
        score_inputs.check_not_ablated({"disabled_methods": value}, tmp_path, real_repo=tmp_path)


def test_ab15_score_accepts_the_same_run_info_in_a_scratch_repo(tmp_path):
    real, scratch = tmp_path / "real", tmp_path / "scratch"
    real.mkdir(), scratch.mkdir()
    score_inputs.check_not_ablated(ABLATED_INFO, scratch, real_repo=real)


@pytest.mark.parametrize("info", [{}, DEFAULT_INFO, {"disabled_methods": []}, {"disabled_methods": None}])
def test_ab15_score_accepts_a_default_run_info_everywhere(tmp_path, info):
    real, scratch = tmp_path / "real", tmp_path / "scratch"
    real.mkdir(), scratch.mkdir()
    score_inputs.check_not_ablated(info, real, real_repo=real)
    score_inputs.check_not_ablated(info, scratch, real_repo=real)


def test_ab15_score_load_inputs_refuses_before_reading_any_other_stitch_file(tmp_path, monkeypatch):
    root, other = tmp_path / "real", tmp_path / "scratch"
    monkeypatch.setattr(score_inputs.check_not_ablated, "__defaults__", (root,))
    write_info(root, ABLATED_INFO)
    write_info(other, ABLATED_INFO)
    with pytest.raises(ScoreError, match="disabled_methods"):
        score_inputs.load_inputs(root, TRIAL)
    with pytest.raises(ScoreError) as scratch_err:                      # scratch: goes on, fails later on a missing file
        score_inputs.load_inputs(other, TRIAL)
    assert "disabled_methods" not in str(scratch_err.value)
    write_info(root, DEFAULT_INFO)
    with pytest.raises(ScoreError) as default_err:                      # default run_info in the real repo: same
        score_inputs.load_inputs(root, TRIAL)
    assert "disabled_methods" not in str(default_err.value)


# ================================================================================================ AB-15 guards: evaluate
DEV_TRIALS = tuple(p.DEVELOPMENT_TRIALS)


def test_ab15_evaluate_refusal_text_in_the_real_repo_and_empty_elsewhere(tmp_path):
    real, scratch = tmp_path / "real", tmp_path / "scratch"
    write_info(real, ABLATED_INFO)
    write_info(scratch, ABLATED_INFO)
    text = real_repo_ablation_refusal(real, DEV_TRIALS, real_repo=real)
    assert text.startswith("refused") and "disabled_methods" in text and TRIAL in text
    assert real_repo_ablation_refusal(scratch, DEV_TRIALS, real_repo=real) == ""


@pytest.mark.parametrize("info", [DEFAULT_INFO, {"disabled_methods": []}])
def test_ab15_evaluate_accepts_a_default_run_info_in_the_real_repo(tmp_path, info):
    real = tmp_path / "real"
    for t in DEV_TRIALS:
        write_info(real, info, t)
    assert real_repo_ablation_refusal(real, DEV_TRIALS, real_repo=real) == ""


def test_ab15_evaluate_reads_only_the_trials_it_is_given(tmp_path):
    real = tmp_path / "real"
    write_info(real, ABLATED_INFO, "s02_t00")
    write_info(real, DEFAULT_INFO, TRIAL)
    assert real_repo_ablation_refusal(real, (TRIAL,), real_repo=real) == ""
    assert real_repo_ablation_refusal(real, ("s02_t00",), real_repo=real) != ""


def test_ab15_evaluate_checks_an_explicit_stitch_dir_in_the_real_repo(tmp_path):
    real = tmp_path / "real"
    write_info(real, DEFAULT_INFO, TRIAL)
    other = write_info(tmp_path / "elsewhere", ABLATED_INFO, TRIAL)
    assert real_repo_ablation_refusal(real, (TRIAL,), [other], real_repo=real) != ""
    assert real_repo_ablation_refusal(real, (TRIAL,), [], real_repo=real) == ""


def test_ab15_a_junction_to_the_real_repo_counts_as_the_real_repo(tmp_path):
    real = tmp_path / "real"
    write_info(real, ABLATED_INFO)
    via = tmp_path / "via"
    make_link(via, real)
    assert real_repo_ablation_refusal(via, DEV_TRIALS, real_repo=real) != ""


EVAL_MODES = [["--development"], ["--trial", TRIAL], ["--development", "--label-recall"], ["--trial", TRIAL, "--label-recall"],
              ["--development", "--rank"], ["--trial", TRIAL, "--rank"], ["--development", "--rank-sweep"],
              ["--development", "--results"]]


@pytest.fixture
def real_as_tmp(tmp_path, monkeypatch):
    """The evaluate CLI with `tmp/real` standing in for the real repository (the guard's `real_repo` argument is set)."""
    real = tmp_path / "real"
    real.mkdir()
    monkeypatch.setattr(em, "real_repo_ablation_refusal", partial(real_repo_ablation_refusal, real_repo=real))
    return real


@pytest.mark.parametrize("mode", EVAL_MODES, ids=lambda m: " ".join(m))
def test_ab15_evaluate_cli_refuses_an_ablated_stitch_run_in_the_real_repo_and_writes_nothing(real_as_tmp, mode, capsys):
    for t in DEV_TRIALS:
        write_info(real_as_tmp, ABLATED_INFO, t)
    before = tree_listing(real_as_tmp)
    code = em.main([*mode, "--repo", str(real_as_tmp)])
    err = capsys.readouterr().err
    assert code == 2 and err.startswith("refused") and "disabled_methods" in err
    assert tree_listing(real_as_tmp) == before


def test_ab15_evaluate_cli_refuses_an_ablated_explicit_stitch_dir_in_the_real_repo(real_as_tmp, tmp_path, capsys):
    write_info(real_as_tmp, DEFAULT_INFO, TRIAL)
    other = write_info(tmp_path / "elsewhere", ABLATED_INFO, TRIAL)
    code = em.main(["--trial", TRIAL, "--stitch-dir", str(other), "--repo", str(real_as_tmp)])
    err = capsys.readouterr().err
    assert code == 2 and "disabled_methods" in err


@pytest.mark.parametrize("mode", [m for m in EVAL_MODES if "--results" not in m], ids=lambda m: " ".join(m))
def test_ab15_evaluate_cli_does_not_refuse_for_that_reason_a_default_run_info_or_a_scratch_repo(
        tmp_path, monkeypatch, mode, capsys):
    """Accepted here means: the guard is silent. The run then stops on its own later refusal (no stitch files in this
    tmp repo), which never names `disabled_methods`."""
    real, scratch = tmp_path / "real", tmp_path / "scratch"
    real.mkdir()
    monkeypatch.setattr(em, "real_repo_ablation_refusal", partial(real_repo_ablation_refusal, real_repo=real))
    for t in DEV_TRIALS:
        write_info(scratch, ABLATED_INFO, t)
        write_info(real, DEFAULT_INFO, t)
    for repo in (scratch, real):
        code = em.main([*mode, "--repo", str(repo)])
        assert "disabled_methods" not in capsys.readouterr().err
        assert code in (0, 2)


# ================================================================================================ AB-15 write targets (links)
def make_link(link: Path, target: Path) -> None:
    """A directory symlink or, on Windows, a junction (`mklink /J`); skips the test if neither can be made."""
    target.mkdir(parents=True, exist_ok=True)
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
        if done.returncode == 0 and link.exists():
            return
    pytest.skip("neither a symlink nor a junction can be created here")


def scratch_pair(tmp_path: Path) -> tuple[Path, Path]:
    """(fake real repository, scratch repository) with real folders `data/`, `out/` in both."""
    real, scratch = tmp_path / "fakereal", tmp_path / "scratch"
    for root in (real, scratch):
        (root / "data").mkdir(parents=True)
        (root / "out").mkdir()
    (real / "out" / "stitch" / TRIAL).mkdir(parents=True)
    return real.resolve(), scratch.resolve()


def test_ab15_plain_scratch_repo_is_accepted_by_both_refusals(tmp_path):
    real, scratch = scratch_pair(tmp_path)
    assert sm.disable_refusal([CMD], scratch, None, real_repo=real, trial=TRIAL) is None
    assert ablation_refusal([CMD], scratch, real_repo=real, trials=(TRIAL,)) is None


def test_ab15_stitch_refuses_when_out_stitch_is_a_link_into_the_real_repository(tmp_path):
    real, scratch = scratch_pair(tmp_path)
    make_link(scratch / "out" / "stitch", real / "out" / "stitch")
    text = sm.disable_refusal([CMD], scratch, None, real_repo=real)
    assert text and "real repository" in text
    assert sm.disable_refusal([], scratch, None, real_repo=real) is None            # no flag: not this refusal's business


def test_ab15_stitch_refuses_when_out_stitch_trial_is_a_link_into_the_real_repository(tmp_path):
    real, scratch = scratch_pair(tmp_path)
    (scratch / "out" / "stitch").mkdir()
    make_link(scratch / "out" / "stitch" / TRIAL, real / "out" / "stitch" / TRIAL)
    assert sm.disable_refusal([CMD], scratch, None, real_repo=real, trial=TRIAL)
    assert sm.disable_refusal([CMD], scratch, None, real_repo=real, trial="s02_t00") is None   # another trial: no link


def test_ab15_stitch_refuses_when_out_resolves_into_the_real_repository_by_a_link(tmp_path):
    real, scratch = scratch_pair(tmp_path)
    make_link(scratch / "linked_out", real / "out" / "stitch" / TRIAL)
    assert sm.disable_refusal([CMD], scratch, scratch / "linked_out", real_repo=real)
    assert sm.disable_refusal([CMD], scratch, scratch / "plain_out", real_repo=real) is None
    assert sm.disable_refusal([CMD], scratch, real / "out" / "ablation" / "x", real_repo=real)


def test_ab15_runner_refuses_when_out_stitch_is_a_link_into_the_real_repository(tmp_path):
    real, scratch = scratch_pair(tmp_path)
    make_link(scratch / "out" / "stitch", real / "out" / "stitch")
    text = ablation_refusal([CMD], scratch, real_repo=real, trials=())
    assert text and text.startswith("refused")
    assert ablation_refusal([], scratch, real_repo=real, trials=()) is None


def test_ab15_runner_refuses_when_out_stitch_trial_is_a_link_into_the_real_repository(tmp_path):
    real, scratch = scratch_pair(tmp_path)
    (scratch / "out" / "stitch").mkdir()
    make_link(scratch / "out" / "stitch" / TRIAL, real / "out" / "stitch" / TRIAL)
    assert ablation_refusal([CMD], scratch, real_repo=real, trials=(TRIAL,))
    assert ablation_refusal([CMD], scratch, real_repo=real, trials=("s02_t00",)) is None


def test_ab15_runner_and_stitch_refuse_a_repo_that_is_a_link_to_the_real_repository(tmp_path):
    real, _scratch = scratch_pair(tmp_path)
    via = tmp_path / "via"
    make_link(via, real)
    assert ablation_refusal([CMD], via, real_repo=real, trials=())
    assert sm.disable_refusal([CMD], via, None, real_repo=real)


# ================================================================================================ AB-12 control_status
def fr(status: str, folder: str = "out/stitch/s98_t00", name: str = "links.csv") -> FileResult:
    return FileResult("stitch", folder, name, status)


def test_ab12_control_status_passes_only_with_exit_0_matching_files_and_no_folder_problem():
    arm = ab.control_status(0, [fr(IDENTICAL), fr(EQUAL_NORMALISED, name="run_info.json")], [])
    assert arm.status == "passed" and arm.exit_code == 0 and arm.problems == []
    assert arm.counts == {IDENTICAL: 1, EQUAL_NORMALISED: 1}


@pytest.mark.parametrize("code", [1, 2, 3, -1])
def test_ab12_control_status_fails_on_a_non_zero_exit_even_when_every_file_matches(code):
    arm = ab.control_status(code, [fr(IDENTICAL)], [])
    assert arm.status == "failed" and arm.exit_code == code and arm.problems


@pytest.mark.parametrize("bad", [DIFFERS, MISSING, NEW, EOL_ONLY])
def test_ab12_control_status_fails_on_any_differing_missing_or_new_file(bad):
    arm = ab.control_status(0, [fr(IDENTICAL), fr(bad, name="hops.csv")], [])
    assert arm.status == "failed"
    assert any("hops.csv" in line for line in arm.problems)


def test_ab12_control_status_fails_on_a_folder_problem():
    arm = ab.control_status(0, [fr(IDENTICAL)], ["committed folder missing: out/label/s98_t00"])
    assert arm.status == "failed" and "committed folder missing: out/label/s98_t00" in arm.problems


def test_ab12_control_status_fails_when_nothing_was_compared():
    assert ab.control_status(0, [], []).status == "failed"


# ================================================================================================ AB-12 driver with the real control arm
def real_control(monkeypatch, results=None, problems=None):
    """Put the real `_control_arm` back (Driver stubs it); the dry-run comparison is replaced by `results`."""
    monkeypatch.setattr(ab, "_control_arm", ORIG_CONTROL)
    monkeypatch.setattr(ab, "compare_all", lambda repo, scratch, trials: list(results or []))
    monkeypatch.setattr(ab, "folder_problems", lambda repo, scratch, trials, res: list(problems or []))


def with_stale_target(d: Driver) -> dict[str, bytes]:
    d.target.mkdir(parents=True)
    (d.target / "stale.txt").write_text("previous ablation", encoding="utf-8")
    (d.target / "sub").mkdir()
    (d.target / "sub" / "x.csv").write_text("a\n1\n", encoding="utf-8")
    return tree_listing(d.target)


@pytest.mark.parametrize("bad", [DIFFERS, MISSING, NEW])
def test_ab12_a_failing_control_arm_exits_1_copies_nothing_swaps_nothing_and_records_nothing_as_passed(
        tmp_path, monkeypatch, capsys, bad):
    d = Driver(tmp_path, monkeypatch)
    real_control(monkeypatch, [fr(IDENTICAL), fr(bad, name="hops.csv")])
    kept = with_stale_target(d)
    before_tree = committed_tree(d.repo)
    swaps: list[tuple] = []
    monkeypatch.setattr(ab, "swap_in", lambda *a, **k: swaps.append(a))
    code = ab.main([])
    cap = capsys.readouterr()
    assert code == 1 and "ablation: FAILED" in cap.out and "control arm" in cap.err
    assert len(d.argv) == 1 and "--stitch-disable-method" not in d.argv[0]      # only the no-flag arm ran
    assert len(d.scratches) == 1 and all(not s.exists() for s in d.scratches)   # the ablated scratch repo never existed
    assert swaps == []
    assert tree_listing(d.target) == kept                                       # the old folder is untouched
    assert not (d.target / "run_info.json").exists()                            # nothing recorded
    assert "control arm: passed" not in cap.out and "control arm: failed" in cap.out
    assert not (d.repo / "out" / "ablation" / ab.TMP_NAME).exists()             # nothing copied
    assert sorted(f.name for f in (d.repo / "out" / "ablation").iterdir()) == ["no_cmdline"]
    assert committed_tree(d.repo) == before_tree


def test_ab12_a_control_run_with_a_non_zero_exit_stops_before_any_comparison(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch, exit_code=1)
    compared: list[int] = []
    real_control(monkeypatch, [fr(IDENTICAL)])
    monkeypatch.setattr(ab, "compare_all", lambda *a: compared.append(1) or [fr(IDENTICAL)])
    kept = with_stale_target(d)
    code = ab.main([])
    cap = capsys.readouterr()
    assert code == 1 and "control arm" in cap.err and compared == []
    assert len(d.argv) == 1 and tree_listing(d.target) == kept


def test_ab12_a_folder_problem_in_the_control_arm_fails_the_whole_run(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch)
    real_control(monkeypatch, [fr(IDENTICAL)], ["scratch folder not expected: out/score/s99_t00"])
    kept = with_stale_target(d)
    assert ab.main([]) == 1
    assert "control arm" in capsys.readouterr().err
    assert len(d.argv) == 1 and tree_listing(d.target) == kept


def test_ab12_a_passing_control_arm_lets_the_run_finish_and_records_both_arms(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch)
    real_control(monkeypatch, [fr(IDENTICAL), fr(EQUAL_NORMALISED, name="run_info.json")])
    assert ab.main([]) == 0
    assert "ablation: DONE" in capsys.readouterr().out
    assert len(d.argv) == 2 and "--stitch-disable-method" not in d.argv[0] and "--stitch-disable-method" in d.argv[1]
    arms = json.loads((d.target / "run_info.json").read_text(encoding="utf-8"))["arms"]
    assert arms["control"]["status"] == "passed" and arms["control"]["exit_code"] == 0
    assert arms["ablated"]["status"] == "ok"
    assert "control passed" in (d.target / "README.md").read_text(encoding="utf-8")


# ================================================================================================ AB-16
def test_ab16_the_swap_comes_only_after_the_final_tree_check_passes(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch)
    events: list[str] = []
    real_tree, real_swap = ab._tree, ab.swap_in
    monkeypatch.setattr(ab, "_tree", lambda *a: events.append("tree") or real_tree(*a))
    monkeypatch.setattr(ab, "swap_in", lambda *a: events.append("swap") or real_swap(*a))
    assert ab.main([]) == 0
    assert events == ["tree", "tree", "swap", "tree"]            # before / final check / swap / after-swap check
    assert d.target.is_dir()


def test_ab16_a_tree_change_before_the_swap_exits_1_and_swaps_nothing(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch)
    kept = with_stale_target(d)
    real_tree = ab._tree
    calls: list[int] = []
    swaps: list[tuple] = []

    def changing(repo, trials):
        files, listed = real_tree(repo, trials)
        calls.append(1)
        if len(calls) >= 2:                                      # the check right before the swap sees a changed file
            files = {**files, "out/gate/unexpected.csv": "0" * 64}
        return files, listed
    monkeypatch.setattr(ab, "_tree", changing)
    monkeypatch.setattr(ab, "swap_in", lambda *a: swaps.append(a))
    code = ab.main([])
    cap = capsys.readouterr()
    assert code == 1 and "ablation: FAILED" in cap.out and "tree changed" in cap.err
    assert swaps == [] and len(calls) == 2                       # no swap and no after-swap tree check
    assert tree_listing(d.target) == kept                        # the old folder stays whole
    assert not (d.repo / "out" / "ablation" / ab.TMP_NAME).exists()
    assert all(not s.exists() for s in d.scratches)


def test_ab16_a_changed_file_listing_before_the_swap_also_stops_the_swap(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch)
    kept = with_stale_target(d)
    real_tree = ab._tree
    calls: list[int] = []

    def changing(repo, trials):
        files, listed = real_tree(repo, trials)
        calls.append(1)
        if len(calls) >= 2:
            listed = {**listed, "data/processed/extra.db": (1, 1)}
        return files, listed
    monkeypatch.setattr(ab, "_tree", changing)
    assert ab.main([]) == 1
    assert "nothing swapped" in capsys.readouterr().err
    assert tree_listing(d.target) == kept


def test_ab16_a_leftover_old_folder_with_no_target_is_restored_not_deleted(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch, exit_code=1)              # the run itself fails, so only the start-up settle acts
    old = d.target.parent / ab.OLD_NAME
    old.mkdir(parents=True)
    (old / "keep.txt").write_text("previous ablation", encoding="utf-8")
    assert ab.main([]) == 1
    assert (d.target / "keep.txt").read_text(encoding="utf-8") == "previous ablation"
    assert not old.exists()


def test_ab16_a_leftover_old_folder_with_a_live_target_does_not_replace_it(tmp_path, monkeypatch, capsys):
    d = Driver(tmp_path, monkeypatch, exit_code=1)
    kept = with_stale_target(d)
    (d.target.parent / ab.OLD_NAME).mkdir()
    assert ab.main([]) == 1
    assert tree_listing(d.target) == kept


def contents_of(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def readme_sentences(text: str) -> None:
    flat = contents_of(text).lower()
    assert "no_cmdline" in flat and "command-line source-session method" in flat
    for needle in ("label", "field_values_json", "answer key", "process nodes", "port", "4648", "command text"):
        assert needle in flat, needle


def test_ab16_the_readme_states_what_still_carries_command_text():
    readme_sentences(ar.readme_md(DEV, ["README.md"], {"control": "passed", "ablated": "ok"}))


def test_ab16_the_written_readme_of_the_driver_states_it(tmp_path, monkeypatch):
    d = Driver(tmp_path, monkeypatch)
    assert ab.main([]) == 0
    readme_sentences((d.target / "README.md").read_text(encoding="utf-8"))


def test_ab16_the_on_disk_readme_states_it():
    path = REPO / "out" / "ablation" / "no_cmdline" / "README.md"
    if not path.is_file():
        pytest.skip("out/ablation/no_cmdline/README.md not present")
    readme_sentences(path.read_text(encoding="utf-8"))


# ================================================================================================ AB-13
@pytest.fixture(scope="module")
def stitch_pair(tmp_path_factory):
    d = tso.build_repo(tmp_path_factory.mktemp("dh_default"), "repo")
    a = tso.build_repo(tmp_path_factory.mktemp("dh_off"), "repo")
    assert sm.main(["--trial", d.trial, "--repo", str(d.repo)]) == 0
    assert sm.main(["--trial", a.trial, "--repo", str(a.repo), "--disable-method", CMD]) == 0
    return d, a


def links_of(fake) -> list[dict[str, str]]:
    return tso.read_csv(tso.out_folder(fake) / "links.csv")


def test_ab13_default_run_never_writes_not_run(stitch_pair):
    d, _a = stitch_pair
    values = {r["name_check"] for r in links_of(d)}
    assert "not_run" not in values and values & {"match", "no_match"}              # the world does have name checks


def test_ab13_every_link_row_of_a_hop_with_names_is_not_run_when_the_method_is_disabled(stitch_pair):
    d, a = stitch_pair
    named = {r["hop_id"] for r in links_of(d) if r["name_check"] in ("match", "no_match")}
    assert named, "the default world must hold at least one hop with names"
    rows = links_of(a)
    assert {r["hop_id"] for r in rows} >= named                                    # no hop lost
    for r in rows:
        if r["hop_id"] in named:
            assert r["name_check"] == "not_run", r
        assert r["name_check"] != "no_match"


def test_ab13_a_hop_without_names_stays_no_names_in_both_runs(stitch_pair):
    d, a = stitch_pair
    unnamed = {r["hop_id"] for r in links_of(d) if r["name_check"] == "no_names"}
    for r in links_of(a):
        if r["hop_id"] in unnamed:
            assert r["name_check"] == "no_names"


def test_ab13_hop_verdicts_write_not_run_for_every_session_and_for_the_unlinked_row():
    names = ["payloadxq.exe"]
    built = tss.run(_cmd_world(), StitchParams())
    sl = built.links()
    on = tiers.hop_verdicts(built.hop, sl, names)
    off = tiers.hop_verdicts(built.hop, sl, names, name_check_run=False)
    assert on.sessions and all(v.name_check != "not_run" for v in on.sessions.values())
    assert on.no_session_name_check == "no_match"
    assert off.sessions and all(v.name_check == "not_run" for v in off.sessions.values())
    assert off.no_session_name_check == "not_run"
    assert all(v.name_check_names == () and v.name_check_event_uids == () for v in off.sessions.values())
    noname = tiers.hop_verdicts(built.hop, sl, [], name_check_run=False)
    assert noname.no_session_name_check == "no_names"
    assert all(v.name_check == "no_names" for v in noname.sessions.values())


def _cmd_world() -> tss.World:
    w = tss.World()
    w.member("M1")
    w.src_logon("L5000", 0.0, tss.S5000, account="acct_a")
    w.s1("S1", 90.0, "{G1}", tss.S5000)
    return w


def test_ab13_a_disabled_run_has_no_session_so_the_unlinked_row_carries_not_run():
    built = tss.run(_cmd_world(), StitchParams(disabled_methods=frozenset({CMD})))
    off = tiers.hop_verdicts(built.hop, built.links(), ["payloadxq.exe"], name_check_run=False)
    assert off.sessions == {} and off.no_session_name_check == "not_run"
    default = tiers.hop_verdicts(built.hop, built.links(), ["payloadxq.exe"])
    assert default.no_session_name_check == "no_match"


# ================================================================================================ NP-06 ablation.md
def sections(text: str) -> list[str]:
    return re.split(r"(?m)^## ", text)


def md_tables(text: str) -> list[tuple[list[str], list[list[str]]]]:
    out, cur = [], None
    for line in text.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cur is None:
                cur = (cells, [])
            elif not set("".join(cells)) <= set("-"):
                cur[1].append(cells)
        else:
            if cur is not None:
                out.append(cur)
            cur = None
    if cur is not None:
        out.append(cur)
    return out


def difference_rows(text: str) -> list[dict[str, str]]:
    rows = []
    for header, body in md_tables(text):
        if "difference" in header and "trials (default / ablated)" in header:
            rows += [dict(zip(header, r)) for r in body]
    return rows


def check_ablation_md(text: str) -> int:
    """NP-06 on every metric row of an ablation.md; returns the number of P / F1 rows seen."""
    seen = 0
    for r in difference_rows(text):
        n = [x.strip() for x in r["trials (default / ablated)"].split("/")]
        if "node_precision" in r["metric"] or "node_f1" in r["metric"]:
            seen += 1
            assert "ratio of expectations" in r["metric"], r
            assert re.fullmatch(r"\d+ / \d+", r["trials (default / ablated)"]), r      # a trial count beside each mean
        if len(n) == 2 and n[0] != n[1] and re.fullmatch(r"\d+", n[0]) and re.fullmatch(r"\d+", n[1]):
            assert r["difference"] == "n/a: different trial sets", r
        elif len(n) == 2 and n[0] == n[1] and r["default"] not in ("", "-") and r["ablated"] not in ("", "-"):
            assert r["difference"] != "n/a: different trial sets", r
    return seen


PRF_VARIANTS = ("full", "b1", "b2", "b0")
TRIALS2 = ("s98_t00", "s97_t00")


def read_rows(data: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(data.decode("utf-8"))))


def add_prf(blobs: dict[str, bytes], trials=TRIALS2, undefined=()) -> dict[str, bytes]:
    """Node P/R/F1/FNR facts the report reads to learn which trials a mean averages over: `scope_trial_ids` on the
    rank_totals node_prf rows and one per-trial rank.csv node_prf row per (trial, variant). `undefined` = pairs
    (trial, variant) whose P and F1 are blank (undefined, left out of the mean)."""
    out = dict(blobs)
    key = "evaluate/development/rank_totals.csv"
    rows = read_rows(out[key])
    for r in rows:
        if r["row_kind"] == "node_prf":
            r["scope_trial_ids"] = ";".join(trials)
            gone = sum(1 for t in trials if (t, r["variant"]) in undefined)
            r["node_recall_trials"] = str(len(trials))
            r["node_precision_trials"] = r["node_f1_trials"] = str(len(trials) - gone)
    out[key] = fx.csv_bytes(rows)
    for t in trials:
        rk = f"evaluate/{t}/rank.csv"
        rows = read_rows(out[rk])
        for v in PRF_VARIANTS:
            blank = (t, v) in undefined
            rows.append(dict(row_kind="node_prf", variant=v, match_reading="",
                             node_precision="" if blank else "0.500000", node_recall="0.600000",
                             node_f1="" if blank else "0.545455", node_fnr="0.400000"))
        out[rk] = fx.csv_bytes(rows)
    return out


def sides(default_blobs: dict[str, bytes], ablated_blobs: dict[str, bytes], trials=TRIALS2):
    left = ar.parse_side(default_blobs, fx.shas(default_blobs), trials)
    right = ar.parse_side(ablated_blobs, fx.shas(ablated_blobs), trials)
    return left, right


@pytest.fixture(scope="module")
def trial_sets():
    """P and F1 of `full` average over 2 trials by default and over 1 trial when ablated (the other is undefined)."""
    d = add_prf(fx.side_blobs(TRIALS2, False))
    a = add_prf(fx.side_blobs(TRIALS2, True), undefined=[("s97_t00", "full")])
    rows = ar.all_rows(*sides(d, a), TRIALS2)
    return rows, ar.ablation_md(rows, TRIALS2)


def test_np06_synthetic_p_and_f1_are_labelled_with_the_trial_count_beside_each_mean(trial_sets):
    _rows, md = trial_sets
    assert check_ablation_md(md) >= 8                                               # P and F1 of full, b1, b2, b0 (+ per scenario)


def test_np06_synthetic_a_difference_over_different_trial_sets_is_not_printed(trial_sets):
    rows, md = trial_sets
    by = {(r["variant"], r["metric"]): r for r in rows if r["table"] == "headline_hop" and r["match_reading"] == "node"}
    assert by[("full", "node_precision_mean")]["difference"] == "n/a: different trial sets"
    assert by[("full", "node_f1_mean")]["difference"] == "n/a: different trial sets"
    assert by[("full", "node_recall_mean")]["difference"] not in ("n/a: different trial sets", "")   # R still 5 / 5
    assert by[("b1", "node_precision_mean")]["difference"] not in ("n/a: different trial sets", "")  # b1 still 5 / 5
    assert "n/a: different trial sets" in md


def test_np06_synthetic_same_trial_sets_print_a_numeric_difference():
    d, a = add_prf(fx.side_blobs(TRIALS2, False)), add_prf(fx.side_blobs(TRIALS2, True))
    rows = ar.all_rows(*sides(d, a), TRIALS2)
    md = ar.ablation_md(rows, TRIALS2)
    assert "n/a: different trial sets" not in chr(10).join(l for l in md.splitlines() if l.startswith("|"))
    assert check_ablation_md(md) >= 8
    p_row = next(r for r in rows if r["metric"] == "node_precision_mean" and r["variant"] == "full"
                 and r["table"] == "headline_hop")
    assert float(p_row["difference"]) == pytest.approx(0.300000 - 0.795192, abs=1e-6)


def set_counts(blobs: dict[str, bytes], **cols: str) -> dict[str, bytes]:
    """Overwrite trial-count columns of the rank_totals node_prf rows of `full`."""
    key = "evaluate/development/rank_totals.csv"
    rows = read_rows(blobs[key])
    for r in rows:
        if r["row_kind"] == "node_prf" and r["variant"] == "full":
            r.update(cols)
    out = dict(blobs)
    out[key] = fx.csv_bytes(rows)
    return out


def p_row_of(d: dict[str, bytes], a: dict[str, bytes], trials=("s98_t00", "s97_t00")) -> dict[str, str]:
    rows = ar.all_rows(*sides(d, a, trials), trials)
    return next(r for r in rows if r["metric"] == "node_precision_mean" and r["variant"] == "full"
                and r["table"] == "headline_hop")


def test_np06_counts_that_differ_are_not_a_difference_even_when_no_trial_ids_are_readable():
    trials = ("s98_t00", "s97_t00")
    d = fx.side_blobs(trials, False)
    a = set_counts(fx.side_blobs(trials, True), node_precision_trials="4")
    row = p_row_of(d, a)
    assert (row["n_default"], row["n_ablated"]) == ("5", "4")
    assert row["difference"] == "n/a: different trial sets"


def test_np06_equal_counts_with_no_readable_trial_ids_give_a_numeric_difference():
    trials = ("s98_t00", "s97_t00")
    row = p_row_of(fx.side_blobs(trials, False), fx.side_blobs(trials, True))
    assert (row["n_default"], row["n_ablated"]) == ("5", "5")
    assert float(row["difference"]) == pytest.approx(0.300000 - 0.795192, abs=1e-6)


def test_np06_ids_readable_on_one_side_only_the_counts_decide():
    d = add_prf(fx.side_blobs(TRIALS2, False))                                      # ids readable; counts 2
    a_plain = fx.side_blobs(TRIALS2, True)                                         # no ids; counts 5
    assert p_row_of(d, a_plain)["difference"] == "n/a: different trial sets"
    a_same = set_counts(a_plain, node_precision_trials="2")
    row = p_row_of(d, a_same)
    assert (row["n_default"], row["n_ablated"]) == ("2", "2")
    assert float(row["difference"]) == pytest.approx(0.300000 - 0.795192, abs=1e-6)
    row = p_row_of(a_same, d)                                                      # the same with the sides swapped
    assert float(row["difference"]) == pytest.approx(0.795192 - 0.300000, abs=1e-6)


@pytest.mark.parametrize("unknown", ["", "-"])
def test_np06_an_unknown_count_gives_n_a(unknown):
    trials = ("s98_t00", "s97_t00")
    d = fx.side_blobs(trials, False)
    assert p_row_of(d, set_counts(fx.side_blobs(trials, True), node_precision_trials=unknown))["difference"]         == "n/a: different trial sets"
    assert p_row_of(set_counts(d, node_precision_trials=unknown), fx.side_blobs(trials, True))["difference"]         == "n/a: different trial sets"
    assert p_row_of(set_counts(d, node_precision_trials=unknown),
                    set_counts(fx.side_blobs(trials, True), node_precision_trials=unknown))["difference"]         == "n/a: different trial sets"                                              # unknown on both: still not comparable


def test_np06_on_disk_ablation_md_and_csv_label_p_and_f1_and_count_trials():
    path = REPO / "out" / "ablation" / "no_cmdline" / "ablation.md"
    if not path.is_file():
        pytest.skip("out/ablation/no_cmdline/ablation.md not present")
    assert check_ablation_md(path.read_text(encoding="utf-8")) >= 8
    with open(path.with_name("ablation.csv"), newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["metric"] in ("node_precision_mean", "node_f1_mean"):
                assert "ratio of expectations" in r["note"], r
                assert r["n_default"] and r["n_ablated"]
                if r["n_default"] != r["n_ablated"]:
                    assert r["difference"] == "n/a: different trial sets"


# ================================================================================================ NP-06 results.md
def recon_rows(n_r: str = "5", n_p: str = "5", n_f1: str = "5") -> list[dict[str, str]]:
    rows = []
    for where in ("node_prf/full/-/all/-", "node_prf_scenario/full/-/all/-/s02"):
        for metric, n in (("node_precision_mean", n_p), ("node_recall_mean", n_r), ("node_f1_mean", n_f1),
                          ("node_fnr_mean", n_r)):
            rows.append(dict(table=res_rep.TABLE_RECON, source=f"rank_totals.csv {where}:{metric}", variant="full",
                             metric=metric, observed="0.500000", n_trials=n))
    return rows


def test_np06_results_md_reconstruction_headers_say_ratio_of_expectations_and_counts_trials():
    text = "\n".join(res_rep._reconstruction_md(recon_rows(n_r="5", n_p="4", n_f1="3")))
    (header, body), = md_tables(text)[:1]
    assert "P (ratio of expectations)" in header and any("ratio of expectations" in h and h.startswith("F1") for h in header)
    cells = {h: i for i, h in enumerate(header)}
    assert body and all(r[cells["trials (R / P / F1)"]] == "5 / 4 / 3" for r in body)


def test_np06_on_disk_results_md_labels_p_and_f1_and_counts_trials():
    path = REPO / "out" / "evaluate" / "development" / "results.md"
    if not path.is_file():
        pytest.skip("results.md not present")
    (sec,) = [s for s in sections(path.read_text(encoding="utf-8")) if s.startswith("Reconstruction quality")]
    (header, body), = md_tables(sec)[:1]
    assert any(h.startswith("P") and "ratio of expectations" in h for h in header)
    assert any(h.startswith("F1") and "ratio of expectations" in h for h in header)
    assert "trials (R / P / F1)" in header and body
    assert all(re.fullmatch(r"\d+ / \d+ / \d+", r[header.index("trials (R / P / F1)")]) for r in body)


# ================================================================================================ SW-05 rank.md
def point(lam: str, w: tuple[float, float, float], kind: str, top1: float, mrr: float, per_key: float,
          s06_max: float, attack_min: float) -> sw.SweepPoint:
    return sw.SweepPoint(lam_label=lam, lam=1.0, w=w, kind=kind, top1=top1, mrr=mrr,
                         key_ranks=((TRIAL, "k1", 1.0),), s06_max=s06_max, attack_min=attack_min, mrr_per_key=per_key)


def synthetic_sweep_md() -> str:
    pts = []
    for lab, _v in sw.LAMBDA_GRID:
        pts += [point(lab, (0.5, 0.25, 0.25), "grid", 0.8, 0.9, 0.7, 0.2, 0.5),        # margin > 0
                point(lab, (0.1, 0.1, 0.8), "grid", 1.0, 0.95, 0.9, 0.6, 0.5),         # margin < 0
                point(lab, (1 / 3, 1 / 3, 1 / 3), "default_w", 0.9, 0.93, 0.83, 0.2, 0.5)]
    default = point("default", (1 / 3, 1 / 3, 1 / 3), "default", 0.9, 0.93, 0.83, 0.2, 0.5)
    chance = {"chance_top1": "0.25", "chance_mrr": "0.38", "chance_pos_top1": "0.9", "chance_pos_mrr": "0.93"}
    facts = {"attack_trials": 5, "all_rivals_zero": (TRIAL,), "tie_every_weight": ()}
    check = {"paths": 10, "max_abs_diff": 0.0, "rank_mismatch": 0}
    return "\n".join(rr._sweep_section(default, pts, check, facts, chance))


def check_sweep_text(text: str) -> None:
    assert "points with S06 margin > 0" in text
    assert "development sensitivity, not an H5 verdict" in text
    assert not re.search(r"(?i)s06[^\n]{0,60}held|held[^\n]{0,60}s06|s06_held", text)
    assert not re.search(r"(?i)\bheld\b", text), "the sweep section never counts what 'held'"
    tables = [(h, b) for h, b in md_tables(text) if "per_key_mrr_min" in h]
    assert len(tables) == 1
    header, body = tables[0]
    for col in ("mrr_min", "mrr_max", "per_key_mrr_min", "per_key_mrr_max", "points with S06 margin > 0"):
        assert col in header, col
    assert body and all(re.fullmatch(r"\d+/\d+", r[header.index("points with S06 margin > 0")]) for r in body)


def test_sw05_synthetic_sweep_section_wording_and_per_key_min_max():
    text = synthetic_sweep_md()
    check_sweep_text(text)
    header, body = next((h, b) for h, b in md_tables(text) if "per_key_mrr_min" in h)
    row = dict(zip(header, body[0]))
    assert (row["per_key_mrr_min"], row["per_key_mrr_max"]) == ("0.700000", "0.900000")
    assert (row["mrr_min"], row["mrr_max"]) == ("0.900000", "0.950000")
    assert row["points with S06 margin > 0"] == "1/2"                               # 1 of the 2 grid points of this lambda


def test_sw05_on_disk_rank_md_sweep_section_wording_and_per_key_min_max():
    path = REPO / "out" / "evaluate" / "development" / "rank.md"
    if not path.is_file():
        pytest.skip("rank.md not present")
    (sec,) = [s for s in sections(path.read_text(encoding="utf-8")) if s.startswith("Stability sweep")]
    check_sweep_text(sec)


def test_sw05_rank_sweep_csv_columns_are_the_068_columns_plus_only_the_sw01_column():
    path = REPO / "out" / "evaluate" / "development" / "rank_sweep.csv"
    if not path.is_file():
        pytest.skip("rank_sweep.csv not present")
    with open(path, newline="", encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    assert "mrr_per_key_expected" in header
    assert "points with S06 margin > 0" not in header                               # that is an rank.md column only
