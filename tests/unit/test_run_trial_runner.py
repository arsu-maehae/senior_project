"""Spec 06_evaluate part B (runner, RT-01..RT-11): unit tests RTT-01..RTT-07 (section 7.2), written from the spec and
decisions 072 / 074, not from the code. Synthetic repos in pytest tmp folders only: nothing is written under the real
`out/` (root conftest guard) and no real trial DB is opened.

Two kinds of fake stage:
- an in-process `RunFn` (no subprocess) for the flow tests (order, stop, development summary);
- fake stage *modules* (`gate.py`, `stitch.py`, ... in a tmp folder that is the child's cwd, so `python -m gate`
  finds them first) run through the real `execute.run_step`, so exit codes, the post-check, `wall_ms` and the
  `<repo>` redaction are exercised end to end.

Test ids: RTT-01 allowlist first, RTT-02 presence pre-check, RTT-03/04 stop at first failure, RTT-05 argv per step,
RTT-06 `--development`, RTT-07 tree check and log writer.
"""
from __future__ import annotations

import builtins
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

import clock_offset.params as co_params  # noqa: E402
from evaluate.params import KEYED_DEVELOPMENT_TRIALS  # noqa: E402
from run_trial import __main__ as rt_main  # noqa: E402
from run_trial import checks, params as p  # noqa: E402
from run_trial.execute import StepRecord, not_run_record, run_step  # noqa: E402
from run_trial.runlog import write_log  # noqa: E402
from run_trial.steps import Step, display_argv, summary_steps, trial_steps  # noqa: E402

DEV = tuple(co_params.DEVELOPMENT_TRIALS)
KEYED = tuple(t for t in DEV if t in KEYED_DEVELOPMENT_TRIALS)
UNKEYED = tuple(t for t in DEV if t not in KEYED_DEVELOPMENT_TRIALS)
T = DEV[0]                      # a keyed development trial
WINDOW_HEADER = "trial_id,start_utc,end_utc\n"
STAGES = ("gate", "stitch", "label", "score", "evaluate")


# ------------------------------------------------------------------------------------------------ fixtures

def make_repo(root: Path, trials: tuple[str, ...] = (T,), window_rows: tuple[str, ...] | None = None) -> Path:
    """A synthetic repo: data/processed with a DB and both clock files per trial (zero bytes: the runner only checks
    presence), data/trial_windows.csv with one row per trial (or `window_rows`), an empty out/."""
    (root / "data" / "processed").mkdir(parents=True)
    (root / "out").mkdir()
    for t in trials:
        for suf in (p.DB_SUFFIX, p.OFFSETS_SUFFIX, p.CHANGES_SUFFIX):
            (root / "data" / "processed" / f"{t}{suf}").write_bytes(b"")
    rows = trials if window_rows is None else window_rows
    (root / "data" / "trial_windows.csv").write_text(WINDOW_HEADER + "".join(f"{r},a,b\n" for r in rows),
                                                     encoding="utf-8")
    return root.resolve()


def tree(root: Path) -> dict[str, tuple[int, int]]:
    """rel path -> (size, mtime_ns) of every file under root."""
    return {f.relative_to(root).as_posix(): (f.stat().st_size, f.stat().st_mtime_ns)
            for f in root.rglob("*") if f.is_file()}


def read_log(repo: Path, name: str) -> dict[str, Any]:
    return json.loads((repo / "out" / "run_trial" / name / "run_log.json").read_text(encoding="utf-8"))


class FakeRun:
    """In-process RunFn: records every call; `stop` maps (trial or '', step name) -> (result, exit code)."""

    def __init__(self, stop: dict[tuple[str, str], tuple[str, int]] | None = None, write_outputs: bool = False):
        self.stop = stop or {}
        self.calls: list[tuple[str, str, tuple[str, ...]]] = []
        self.write_outputs = write_outputs

    def __call__(self, step: Step, repo_abs: Path) -> StepRecord:
        args = step.args
        trial = args[args.index("--trial") + 1] if "--trial" in args else ""
        self.calls.append((step.module, trial, args))
        result, code = self.stop.get((trial, step.name), (p.STATUS_OK, 0))
        if self.write_outputs and result == p.STATUS_OK:
            for rel in step.outputs:
                (repo_abs / rel).parent.mkdir(parents=True, exist_ok=True)
                (repo_abs / rel).write_text("x", encoding="utf-8")
        return StepRecord(step=step.name, argv=display_argv(step, repo_abs), exit_code=code, wall_ms=7,
                          stderr_tail="boom" if result != p.STATUS_OK else "", result=result)


def boom_run(step: Step, repo_abs: Path) -> StepRecord:
    raise AssertionError(f"a stage was started: {step.name}")


# ------------------------------------------------------------------------------------------------ RT-11 / list

def test_rt11_development_list_is_imported_not_copied() -> None:
    assert p.DEVELOPMENT_TRIALS is co_params.DEVELOPMENT_TRIALS
    sources = "\n".join(f.read_text(encoding="utf-8") for f in (REPO / "src" / "run_trial").glob("*.py"))
    for t in DEV:
        assert t not in sources, f"development trial id {t} is written out in src/run_trial"


# ------------------------------------------------------------------------------------------------ RTT-01

TEST_IDS = ["s99_t00", "s02_t02", "s05_t10", "s01_t00", "S02_T00", "s02_t00 ", "../s02_t00", ""]


@pytest.mark.parametrize("trial", TEST_IDS)
def test_rtt01_allowlist_first_refusal_in_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                  capsys: pytest.CaptureFixture[str], trial: str) -> None:
    """RT-01: refused (exit 2) with the allowlist message before any file of the trial is opened, before presence is
    checked and before any process starts; nothing created under out/ (RT-08)."""
    if not trial or "/" in trial:
        repo = make_repo(tmp_path / "r")
    else:
        repo = make_repo(tmp_path / "r", (trial,))             # DB, clock files and a window row all present
    before = tree(repo)
    opened: list[str] = []
    real_open = builtins.open

    def spy_open(file: Any, *a: Any, **k: Any):
        opened.append(str(file))
        return real_open(file, *a, **k)

    def no_popen(*a: Any, **k: Any):
        raise AssertionError("a subprocess was started")

    def no_connect(*a: Any, **k: Any):
        raise AssertionError("sqlite3.connect called")

    def no_presence(*a: Any, **k: Any):
        raise AssertionError("the presence check ran before the allowlist")

    monkeypatch.setattr(builtins, "open", spy_open)
    monkeypatch.setattr(subprocess, "Popen", no_popen)
    monkeypatch.setattr(sqlite3, "connect", no_connect)
    monkeypatch.setattr(checks, "presence_facts", no_presence)
    monkeypatch.setattr(rt_main, "presence_facts", no_presence)
    code = rt_main.main(["--trial", trial, "--repo", str(repo)], run_fn=boom_run)
    monkeypatch.undo()
    err = capsys.readouterr().err
    assert code == 2
    assert "RT-01" in err and "not in the development allowlist" in err
    assert "RT-02" not in err
    assert not [o for o in opened if trial and "processed" in o and trial in o]
    assert tree(repo) == before                                 # DB, clock files, window file untouched
    assert not (repo / "out" / "run_trial").exists()
    for s in STAGES:
        assert not (repo / "out" / s).exists()


def test_rtt01_allowlist_first_cli_subprocess(tmp_path: Path) -> None:
    """The same through `python -m run_trial` (a real process): exit 2, message, DB (zero bytes) unchanged, no
    out/<stage>/<t>, no out/run_trial/<t> (ATK-EV-08)."""
    t = "s02_t02"
    repo = make_repo(tmp_path / "r", (t,))
    db = repo / "data" / "processed" / f"{t}.sqlite3"
    before = (db.stat().st_size, db.stat().st_mtime_ns, tree(repo))
    r = subprocess.run([sys.executable, "-m", "run_trial", "--trial", t, "--repo", str(repo)], cwd=str(REPO),
                       capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 2
    assert "not in the development allowlist" in r.stderr and "RT-01" in r.stderr
    assert (db.stat().st_size, db.stat().st_mtime_ns, tree(repo)) == before
    assert not (repo / "out" / "run_trial").exists()
    assert not any((repo / "out" / s / t).exists() for s in STAGES)


def test_rtt01_every_development_trial_passes_the_allowlist() -> None:
    for t in DEV:
        assert checks.allowlist_refusal(t) is None


# ------------------------------------------------------------------------------------------------ RTT-02

def _expect_refused_presence(tmp_path: Path, capsys: pytest.CaptureFixture[str], repo: Path,
                             trial: str = T) -> tuple[str, dict[str, Any]]:
    run = FakeRun()
    code = rt_main.main(["--trial", trial, "--repo", str(repo)], run_fn=run)
    err = capsys.readouterr().err
    assert code == 2
    assert run.calls == []                                      # no stage started
    log = read_log(repo, trial)
    assert log["status"] == "refused"
    assert log["steps"][0]["step"] == "presence"
    assert log["steps"][0]["result"] == "refused"
    expected = [s.name for s in trial_steps(trial, repo)]
    assert [s["step"] for s in log["steps"][1:]] == expected
    for s in log["steps"][1:]:
        assert s["result"] == "not run" and s["exit_code"] is None
    return err, log


def test_rtt02_db_missing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = make_repo(tmp_path / "r")
    (repo / "data" / "processed" / f"{T}.sqlite3").unlink()
    err, _ = _expect_refused_presence(tmp_path, capsys, repo)
    assert "RT-02" in err
    assert f"python -m data_layout.batch --only {T}" in err
    assert "python -m clock_offset" not in err and "python -m trial_window" not in err


@pytest.mark.parametrize("suffix", [p.OFFSETS_SUFFIX, p.CHANGES_SUFFIX])
def test_rtt02_clock_file_missing(tmp_path: Path, capsys: pytest.CaptureFixture[str], suffix: str) -> None:
    repo = make_repo(tmp_path / "r")
    (repo / "data" / "processed" / f"{T}{suffix}").unlink()
    err, _ = _expect_refused_presence(tmp_path, capsys, repo)
    assert f"python -m clock_offset --trials {T}" in err
    assert "python -m data_layout.batch" not in err and "python -m trial_window" not in err


def test_rtt02_window_row_missing_lists_every_existing_trial_sorted(tmp_path: Path,
                                                                    capsys: pytest.CaptureFixture[str]) -> None:
    """trial_window rewrites the whole file, so the command names every trial already in it plus t, sorted."""
    repo = make_repo(tmp_path / "r", (T,), window_rows=("s07_t00", "s03_t01", "s02_t01"))
    err, _ = _expect_refused_presence(tmp_path, capsys, repo)
    want = " ".join(sorted({"s07_t00", "s03_t01", "s02_t01", T}))
    assert f"python -m trial_window --trials {want}" in err
    assert "python -m data_layout.batch" not in err and "python -m clock_offset" not in err


def test_rtt02_duplicate_window_rows(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = make_repo(tmp_path / "r", (T,), window_rows=(T, "s03_t00", T))
    err, _ = _expect_refused_presence(tmp_path, capsys, repo)
    assert re.search(rf"python -m trial_window --trials {T} s03_t00(?!\S)", err), err
    assert err.count(f" {T} ") + err.count(f" {T}\n") + err.count(f" {T} s03") >= 1
    assert f"{T} {T}" not in err                                # listed once, not twice


def test_rtt02_window_file_missing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = make_repo(tmp_path / "r")
    (repo / "data" / "trial_windows.csv").unlink()
    err, _ = _expect_refused_presence(tmp_path, capsys, repo)
    assert f"python -m trial_window --trials {T}" in err


def test_rtt02_everything_missing_prints_all_three_commands_in_order(tmp_path: Path,
                                                                     capsys: pytest.CaptureFixture[str]) -> None:
    repo = make_repo(tmp_path / "r", (T,), window_rows=("s03_t00",))
    for suf in (p.DB_SUFFIX, p.OFFSETS_SUFFIX, p.CHANGES_SUFFIX):
        (repo / "data" / "processed" / f"{T}{suf}").unlink()
    err, _ = _expect_refused_presence(tmp_path, capsys, repo)
    i = err.index("python -m data_layout.batch")
    j = err.index("python -m clock_offset")
    k = err.index("python -m trial_window")
    assert i < j < k


def test_rtt02_all_present_runs_the_stages(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r", (T,), window_rows=(T, "s03_t00"))
    run = FakeRun(write_outputs=True)
    assert rt_main.main(["--trial", T, "--repo", str(repo)], run_fn=run) == 0
    assert len(run.calls) == len(trial_steps(T, repo))


def test_rt08_repo_without_data_or_out_is_refused_and_nothing_created(tmp_path: Path,
                                                                      capsys: pytest.CaptureFixture[str]) -> None:
    for sub in ("nope", "bare"):
        target = tmp_path / sub
        if sub == "bare":
            target.mkdir()
        run = FakeRun()
        code = rt_main.main(["--trial", T, "--repo", str(target)], run_fn=run)
        assert code == 2 and run.calls == []
        assert "RT-08" in capsys.readouterr().err
    assert not (tmp_path / "nope").exists()
    assert list((tmp_path / "bare").iterdir()) == []


# ------------------------------------------------------------------------------------------------ fake stage modules

FAKE_STAGE = '''
import json, os, sys
from pathlib import Path
argv = sys.argv[1:]
mod = Path(sys.argv[0]).stem
def val(flag):
    return argv[argv.index(flag) + 1] if flag in argv else ""
trial, repo = val("--trial"), val("--repo")
flags = ",".join(sorted(f for f in argv if f in {"--label-recall", "--rank", "--development", "--rank-sweep",
                                                  "--results"}))
key = f"{mod}|{trial}|{flags}"
cfg = json.loads(Path(os.environ["FAKE_CFG"]).read_text(encoding="utf-8"))
with open(cfg["calls"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps({"key": key, "argv": argv}) + "\\n")
ov = cfg["overrides"].get(key, {})
if ov.get("write", True):
    for rel in cfg["outputs"].get(key, []):
        path = Path(repo) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
if ov.get("stderr"):
    text = ov["stderr"].replace("{repo_bs}", repo.replace("/", chr(92))).replace("{repo}", repo)
    sys.stderr.write(text + "\\n")
sys.exit(ov.get("exit", 0))
'''


def step_key(step: Step) -> str:
    args = step.args
    trial = args[args.index("--trial") + 1] if "--trial" in args else ""
    flags = ",".join(sorted(a for a in args if a in {"--label-recall", "--rank", "--development", "--rank-sweep",
                                                      "--results"}))
    return f"{step.module}|{trial}|{flags}"


class FakeStages:
    """Fake stage executables on disk + a RunFn that starts them through the real `run_step`."""

    def __init__(self, base: Path, repo: Path, trials: tuple[str, ...], overrides: dict[str, dict[str, Any]]):
        self.dir = base / "fake_stages"
        self.dir.mkdir()
        for m in STAGES:
            (self.dir / f"{m}.py").write_text(FAKE_STAGE, encoding="utf-8")
        self.calls_file = base / "calls.jsonl"
        outputs: dict[str, list[str]] = {}
        for t in trials:
            for s in trial_steps(t, repo):
                outputs[step_key(s)] = list(s.outputs)
        for s in summary_steps(trials):
            outputs[step_key(s)] = list(s.outputs)
        cfg = {"calls": str(self.calls_file), "outputs": outputs, "overrides": overrides}
        self.cfg_file = base / "cfg.json"
        self.cfg_file.write_text(json.dumps(cfg), encoding="utf-8")
        self.env = dict(os.environ, FAKE_CFG=str(self.cfg_file))

    def run_fn(self, step: Step, repo_abs: Path) -> StepRecord:
        return run_step(step, repo_abs, cwd=self.dir, env=self.env)

    def calls(self) -> list[dict[str, Any]]:
        if not self.calls_file.exists():
            return []
        return [json.loads(x) for x in self.calls_file.read_text(encoding="utf-8").splitlines()]


def run_with_fakes(tmp_path: Path, overrides: dict[str, dict[str, Any]], trial: str = T) -> tuple[int, Path, FakeStages]:
    repo = make_repo(tmp_path / "r", (trial,))
    fk = FakeStages(tmp_path, repo, (trial,), overrides)
    code = rt_main.main(["--trial", trial, "--repo", str(repo)], run_fn=fk.run_fn)
    return code, repo, fk


def key_of(trial: str, name: str) -> str:
    repo = Path("X")
    return next(step_key(s) for s in trial_steps(trial, repo) if s.name == name)


# ------------------------------------------------------------------------------------------------ RTT-03 / RTT-04

def test_rtt03_all_ok_exit_0_and_log(tmp_path: Path) -> None:
    code, repo, fk = run_with_fakes(tmp_path, {})
    assert code == 0
    log = read_log(repo, T)
    assert log["status"] == "ok" and log["refused_step"] == ""
    assert log["trial_id"] == T and log["tool_version"] and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",
                                                                         log["generated_utc"])
    assert [s["step"] for s in log["steps"]] == [s.name for s in trial_steps(T, repo)]
    for s in log["steps"]:
        assert s["exit_code"] == 0 and isinstance(s["wall_ms"], int) and s["wall_ms"] > 0        # RT-07
        assert set(s) >= {"step", "argv", "exit_code", "wall_ms", "stderr_tail"}


def test_rtt04_exit_2_is_refused_and_later_steps_not_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ov = {key_of(T, "stitch"): {"exit": 2, "stderr": "refused: label stale at {repo}/out/label"}}
    code, repo, fk = run_with_fakes(tmp_path, ov)
    # an output of an earlier run sits in a later step's folder; the runner must not touch it (RT-05)
    assert code == 2
    log = read_log(repo, T)
    assert log["status"] == "refused" and log["refused_step"] == "stitch"
    by = {s["step"]: s for s in log["steps"]}
    assert by["gate"]["result"] == "ok" and by["stitch"]["exit_code"] == 2
    later = [s.name for s in trial_steps(T, repo)][2:]
    for n in later:
        assert by[n]["result"] == "not run" and by[n]["exit_code"] is None
        assert "earlier run" in by[n]["note"]                    # RT-10: earlier outputs remain
    assert [c["key"].split("|")[0] for c in fk.calls()] == ["gate", "stitch"]
    err = capsys.readouterr().err
    assert "stitch" in err and "exit 2" in err                   # step name and exit code printed (RT-04)
    assert "label stale" in err                                  # the stage's stderr tail


def test_rtt04_stderr_tail_has_repo_path_replaced(tmp_path: Path) -> None:
    """RT-08: the repo path (slashes or backslashes) in a stage's stderr is written as <repo>; argv too."""
    ov = {key_of(T, "label"): {"exit": 2, "stderr": "refused: stale file {repo}/out/stitch\nand {repo_bs}\\x"}}
    code, repo, _ = run_with_fakes(tmp_path, ov)
    assert code == 2
    log = read_log(repo, T)
    tail = next(s for s in log["steps"] if s["step"] == "label")["stderr_tail"]
    assert "<repo>" in tail
    assert str(repo).lower() not in tail.lower() and repo.as_posix().lower() not in tail.lower()
    for s in log["steps"]:
        blob = (json.dumps(s["argv"]) + s["stderr_tail"]).lower()
        assert repo.as_posix().lower() not in blob and str(repo).lower().replace("\\", "\\\\") not in blob
        assert s["argv"][0] == "python" and s["argv"][-2:] == ["--repo", "<repo>"]


@pytest.mark.parametrize("step_name,exit_code", [("label", 1), ("score", 3), ("evaluate_rank", 1)])
def test_rtt04_other_nonzero_exit_is_failed_and_passed_through(tmp_path: Path, step_name: str, exit_code: int) -> None:
    ov = {key_of(T, step_name): {"exit": exit_code, "stderr": "Traceback ... Error"}}
    code, repo, fk = run_with_fakes(tmp_path, ov)
    assert code == exit_code
    log = read_log(repo, T)
    assert log["status"] == "failed" and log["refused_step"] == ""
    names = [s.name for s in trial_steps(T, repo)]
    stop_at = names.index(step_name)
    for s in log["steps"]:
        i = names.index(s["step"])
        assert s["result"] == ("ok" if i < stop_at else "failed" if i == stop_at else "not run")
    assert len(fk.calls()) == stop_at + 1


def test_rtt04_exit_2_with_usage_message_is_failed_exit_1(tmp_path: Path) -> None:
    ov = {key_of(T, "score"): {"exit": 2, "stderr": "usage: score [-h] --trial TRIAL\nscore: error: bad flag"}}
    code, repo, _ = run_with_fakes(tmp_path, ov)
    assert code == 1
    log = read_log(repo, T)
    assert log["status"] == "failed" and log["refused_step"] == ""


def test_rt09_exit_0_but_outputs_not_rewritten_is_failed(tmp_path: Path) -> None:
    """ATK-EV-11: stale files from an earlier run exist, the stage exits 0 and writes nothing."""
    repo = make_repo(tmp_path / "r", (T,))
    stitch = next(s for s in trial_steps(T, repo) if s.name == "stitch")
    old = 1_000_000_000
    for rel in stitch.outputs:
        f = repo / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("OLD", encoding="utf-8")
        os.utime(f, (old, old))
    fk = FakeStages(tmp_path, repo, (T,), {key_of(T, "stitch"): {"write": False}})
    code = rt_main.main(["--trial", T, "--repo", str(repo)], run_fn=fk.run_fn)
    assert code == 1
    log = read_log(repo, T)
    assert log["status"] == "failed"
    by = {s["step"]: s for s in log["steps"]}
    assert by["stitch"]["result"] == "failed" and by["stitch"]["exit_code"] == 0
    assert by["label"]["result"] == "not run"
    assert all((repo / rel).read_text(encoding="utf-8") == "OLD" for rel in stitch.outputs)   # RT-05: untouched


def test_rt09_exit_0_with_missing_output_is_failed(tmp_path: Path) -> None:
    code, repo, _ = run_with_fakes(tmp_path, {key_of(T, "gate"): {"write": False}})
    assert code == 1
    assert read_log(repo, T)["steps"][0]["result"] == "failed"


def test_rt05_runner_does_not_delete_earlier_outputs_after_a_stop(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r", (T,))
    stale = repo / "out" / "score" / T / "ranked_paths.csv"
    stale.parent.mkdir(parents=True)
    stale.write_text("OLD", encoding="utf-8")
    fk = FakeStages(tmp_path, repo, (T,), {key_of(T, "stitch"): {"exit": 1}})
    assert rt_main.main(["--trial", T, "--repo", str(repo)], run_fn=fk.run_fn) == 1
    assert stale.read_text(encoding="utf-8") == "OLD"


# ------------------------------------------------------------------------------------------------ RTT-05

@pytest.mark.parametrize("trial", [KEYED[0], KEYED[-1], UNKEYED[0]])
def test_rtt05_argv_per_step_as_started(tmp_path: Path, trial: str) -> None:
    code, repo, fk = run_with_fakes(tmp_path, {}, trial)
    assert code == 0
    calls = fk.calls()
    keyed = trial in KEYED_DEVELOPMENT_TRIALS
    mods_flags = [(c["key"].split("|")[0], c["key"].split("|")[2]) for c in calls]
    want = [("gate", ""), ("stitch", ""), ("label", ""), ("score", ""), ("evaluate", "")]
    if keyed:
        want.append(("evaluate", "--label-recall"))
    want.append(("evaluate", "--rank"))
    assert mods_flags == want
    for c in calls:
        a = c["argv"]
        assert a.count("--repo") == 1
        got = Path(a[a.index("--repo") + 1])
        assert got.is_absolute() and got == repo                     # explicit and absolute
        assert a[a.index("--trial") + 1] == trial
        assert "--development" not in a
    gate = calls[0]["argv"]
    out = gate[gate.index("--out") + 1]
    assert Path(out).is_absolute() and Path(out) == repo / "out" / "gate"
    assert all("--out" not in c["argv"] for c in calls[1:])


def test_rtt05_steps_pure_listing_never_runs_upstream_tools() -> None:
    repo = Path("/abs/repo") if os.name != "nt" else Path("C:/abs/repo")
    for t in DEV:
        steps = trial_steps(t, repo)
        assert [s.module for s in steps][:5] == list(STAGES)
        assert [s.name for s in steps][-1] == "evaluate_rank"
        assert ("evaluate_label_recall" in [s.name for s in steps]) == (t in KEYED_DEVELOPMENT_TRIALS)
        for s in steps:
            assert s.module in STAGES
            assert "--development" not in s.args
            assert s.outputs, f"{s.name} documents no output files"
    banned = ("clock_offset", "trial_window", "data_layout", "ingest", "evtx_pipeline", "normal")
    for s in [x for t in DEV for x in trial_steps(t, repo)] + summary_steps(DEV):
        assert not any(b in s.module or any(b in a for a in s.args) for b in banned)


def test_rtt05_summary_steps_exact() -> None:
    steps = summary_steps(DEV)
    assert [(s.module, s.args) for s in steps] == [
        ("evaluate", ("--development",)),
        ("evaluate", ("--development", "--label-recall")),
        ("evaluate", ("--development", "--rank-sweep")),
        ("evaluate", ("--development", "--results")),
    ]


def test_rtt05_stage_output_counts_match_spec_rt09() -> None:
    """RT-09: gate 7, stitch 10, label 7, score 8 documented files."""
    steps = {s.name: s for s in trial_steps(T, Path("/r"))}
    assert [len(steps[n].outputs) for n in ("gate", "stitch", "label", "score")] == [7, 10, 7, 8]


# ------------------------------------------------------------------------------------------------ RTT-06

def _dev_repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "r", DEV)


def test_rtt06_development_all_ok_runs_nine_trials_then_four_summary_steps(tmp_path: Path) -> None:
    repo = _dev_repo(tmp_path)
    run = FakeRun(write_outputs=True)
    code = rt_main.main(["--development", "--repo", str(repo)], run_fn=run)
    assert code == 0
    trial_order = [t for t in dict.fromkeys(c[1] for c in run.calls) if t]
    assert trial_order == list(DEV)
    summary = [c for c in run.calls if not c[1]]
    assert [c[2] for c in summary] == [("--development",), ("--development", "--label-recall"),
                                       ("--development", "--rank-sweep"), ("--development", "--results")]
    assert run.calls[-4:] == summary                              # the summary comes after every trial
    dev = read_log(repo, "development")
    assert [t["trial_id"] for t in dev["trials"]] == list(DEV)
    assert not dev["stopped_at"]
    assert len(dev["summary_steps"]) == 4 and all(s["result"] == "ok" for s in dev["summary_steps"])
    assert (repo / "out" / "run_trial" / "development" / "run_log.md").is_file()
    assert all((repo / "out" / "run_trial" / t / "run_log.json").is_file() for t in DEV)


@pytest.mark.parametrize("idx,step,result,code,want_exit", [(1, "score", "failed", 1, 1),
                                                            (2, "stitch", "refused", 2, 2),
                                                            (0, "gate", "refused", 2, 2)])
def test_rtt06_development_stops_at_first_failing_trial(tmp_path: Path, capsys: pytest.CaptureFixture[str],
                                                        idx: int, step: str, result: str, code: int,
                                                        want_exit: int) -> None:
    repo = _dev_repo(tmp_path)
    bad = DEV[idx]
    run = FakeRun({(bad, step): (result, code)}, write_outputs=True)
    got = rt_main.main(["--development", "--repo", str(repo)], run_fn=run)
    assert got == want_exit
    seen = {c[1] for c in run.calls}
    assert seen == set(DEV[: idx + 1])                            # no later trial started
    assert all(c[1] for c in run.calls), "a summary step ran after a stop"
    err = capsys.readouterr().err
    assert bad in err and step in err                             # names trial and step
    dev = read_log(repo, "development")
    assert dev["stopped_at"] == {"trial": bad, "step": step}
    assert [t["trial_id"] for t in dev["trials"]] == list(DEV[: idx + 1])
    assert dev["not_run_trials"] == list(DEV[idx + 1:])
    assert [s["result"] for s in dev["summary_steps"]] == ["not run"] * 4
    assert not (repo / "out" / "evaluate" / "development" / "results.md").exists()   # not regenerated (RT-10)
    assert not (repo / "out" / "run_trial" / DEV[-1]).exists() or idx == len(DEV) - 1


def test_rtt06_summary_step_failure_is_reported(tmp_path: Path) -> None:
    repo = _dev_repo(tmp_path)
    run = FakeRun({("", "evaluate_development_rank_sweep"): ("failed", 1)}, write_outputs=True)
    assert rt_main.main(["--development", "--repo", str(repo)], run_fn=run) == 1
    dev = read_log(repo, "development")
    assert dev["stopped_at"]["step"] == "evaluate_development_rank_sweep"
    assert [s["result"] for s in dev["summary_steps"]] == ["ok", "ok", "failed", "not run"]


# ------------------------------------------------------------------------------------------------ RTT-07

def test_rtt07_log_writer_refuses_paths_outside_out_run_trial(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r")
    for bad in ("..", "../escape", "../../etc", "a/../..", str(tmp_path / "elsewhere")):
        with pytest.raises(ValueError):
            write_log(repo, bad, {"run_log.json": "{}"})
    with pytest.raises(ValueError):
        write_log(repo, T, {"../../evil.json": "{}"})
    assert not (repo / "out" / "evil.json").exists() and not (repo / "out" / "run_trial" / "evil.json").exists()
    assert not (tmp_path / "elsewhere").exists()
    ok = write_log(repo, T, {"run_log.json": "{}"})
    assert ok == repo / "out" / "run_trial" / T and (ok / "run_log.json").read_text(encoding="utf-8") == "{}"


def test_rtt07_runner_itself_writes_only_under_out_run_trial(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r", DEV)
    before = tree(repo)
    run = FakeRun(write_outputs=False)                            # the fake stages write nothing
    rt_main.main(["--development", "--repo", str(repo)], run_fn=run)
    after = tree(repo)
    assert {k for k in before if before[k] != after.get(k)} == set()
    new = set(after) - set(before)
    assert new and all(k.startswith("out/run_trial/") for k in new)


def test_rtt07_tree_check_detects_a_change_in_the_fake_real_tree(tmp_path: Path) -> None:
    """DR-06 (ATK-EV-07): SHA-256 trees before and after; a step that writes the committed tree is caught."""
    from run_trial import dryrun
    real = make_repo(tmp_path / "real", DEV)
    (real / "out" / "gate" / T).mkdir(parents=True)
    (real / "out" / "gate" / T / "triggers.csv").write_text("a\n", encoding="utf-8")
    (real / "ground_truth" / "approved").mkdir(parents=True)
    (real / "ground_truth" / "approved" / f"{T}.yaml").write_text("k: 1\n", encoding="utf-8")
    before = dryrun.hash_files(real, dryrun.tree_files(real))
    assert any(k.startswith("out/gate") for k in before) and any(k.startswith("ground_truth") for k in before)
    assert any(k.startswith("data/") for k in before)
    assert dryrun.tree_diff(before, dryrun.hash_files(real, dryrun.tree_files(real))) == []
    # a "step" without --repo writes into the committed out/
    (real / "out" / "gate" / T / "triggers.csv").write_text("b\n", encoding="utf-8")
    diff = dryrun.tree_diff(before, dryrun.hash_files(real, dryrun.tree_files(real)))
    assert diff == [f"changed: out/gate/{T}/triggers.csv"]
    (real / "out" / "stitch" / T).mkdir(parents=True)
    (real / "out" / "stitch" / T / "hops.csv").write_text("z", encoding="utf-8")
    (real / "ground_truth" / "approved" / f"{T}.yaml").unlink()
    (real / "data" / "trial_windows.csv").write_text("changed\n", encoding="utf-8")
    diff = dryrun.tree_diff(before, dryrun.hash_files(real, dryrun.tree_files(real)))
    assert f"added: out/stitch/{T}/hops.csv" in diff
    assert f"removed: ground_truth/approved/{T}.yaml" in diff
    assert "changed: data/trial_windows.csv" in diff


def test_rtt07_tree_check_never_lists_test_trial_dbs(tmp_path: Path) -> None:
    from run_trial import dryrun
    real = make_repo(tmp_path / "real", DEV + ("s02_t02", "s05_t10"))
    files = [f.as_posix() for f in dryrun.tree_files(real)]
    assert not any("s02_t02" in f or "s05_t10" in f for f in files)
    for t in DEV:
        assert f"data/processed/{t}.sqlite3" in files
