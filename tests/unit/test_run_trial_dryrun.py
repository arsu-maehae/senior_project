"""Spec 06 B2 (dry run, DR-01..DR-07, as amended by decision 074): scratch location, input copy, negative cases and
the always-delete rule (RTT-08). Written from the spec and decisions 072 / 074, not from the code. Synthetic repos in
pytest tmp folders; the dry run's own `main` is exercised with its heavy steps monkeypatched, so nothing reads the real
`out/` or any trial DB here. The real dry run is RTA-01 (test_run_trial_real.py, slow).
"""
from __future__ import annotations

import builtins
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from run_trial import dryrun  # noqa: E402
from run_trial import params as p  # noqa: E402

DEV = tuple(p.DEVELOPMENT_TRIALS)
T = DEV[0]
HEADER = "trial_id,start_utc,end_utc,rule\n"


def synthetic_repo(root: Path, trials: tuple[str, ...] = DEV, extra: tuple[str, ...] = (),
                   content: bytes = b"DATA") -> Path:
    """data/processed with DB + clock files (content `content`), data/trial_windows.csv, data/manifest.csv,
    ground_truth/approved/<t>.yaml for every id, an empty out/."""
    proc = root / "data" / "processed"
    proc.mkdir(parents=True)
    (root / "out").mkdir()
    for t in (*trials, *extra):
        for suf in (p.DB_SUFFIX, p.OFFSETS_SUFFIX, p.CHANGES_SUFFIX):
            (proc / f"{t}{suf}").write_bytes(content + t.encode())
    (root / "data" / "trial_windows.csv").write_text(HEADER + "".join(f"{t},a,b,r\n" for t in trials),
                                                     encoding="utf-8")
    (root / "data" / "manifest.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    keys = root / "ground_truth" / "approved"
    keys.mkdir(parents=True)
    for t in (*trials, *extra):
        (keys / f"{t}.yaml").write_text(f"trial: {t}\n", encoding="utf-8")
    return root.resolve()


def files_of(root: Path) -> set[str]:
    return {f.relative_to(root).as_posix() for f in root.rglob("*") if f.is_file()}


# ------------------------------------------------------------------------------------------------ DR-01

def test_dr01_is_under() -> None:
    a = Path(tempfile.gettempdir())
    assert dryrun.is_under(a, a)
    assert dryrun.is_under(a / "x" / "y", a)
    assert not dryrun.is_under(str(a) + "2", a)                         # a sibling sharing a name prefix
    assert not dryrun.is_under(a, a / "x")
    if os.name == "nt":
        assert dryrun.is_under(str(a / "X").upper(), str(a).lower())    # case-insensitive on Windows


def test_dr01_scratch_is_outside_the_repository_with_the_prefix() -> None:
    path = dryrun.make_scratch(REPO)
    try:
        assert path.is_dir() and path.name.startswith("run_trial_dryrun_") and dryrun.PREFIX == "run_trial_dryrun_"
        assert not dryrun.is_under(path, REPO)
    finally:
        dryrun.delete_tree(path)
    assert not path.exists()


def test_dr01_scratch_under_the_repository_is_refused_and_removed(tmp_path: Path,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    sys_tmp = tmp_path / "systmp"
    sys_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(sys_tmp))
    fake_repo = tmp_path                                                # the "system temp" lies under the repo
    with pytest.raises(RuntimeError, match="DR-01"):
        dryrun.make_scratch(fake_repo)
    assert list(sys_tmp.iterdir()) == []                                # the folder was deleted again
    elsewhere = tmp_path / "other_repo"
    elsewhere.mkdir()
    ok = dryrun.make_scratch(elsewhere)
    assert ok.parent == sys_tmp.resolve() or dryrun.is_under(ok, sys_tmp)
    dryrun.delete_tree(ok)


def test_dr05_leftover_folders_are_listed(tmp_path: Path) -> None:
    (tmp_path / "run_trial_dryrun_abc").mkdir()
    (tmp_path / "run_trial_dryrun_def").mkdir()
    (tmp_path / "run_trial_dryrun_file").write_text("x", encoding="utf-8")     # a file is not a folder
    (tmp_path / "other_abc").mkdir()
    left = dryrun.leftover_dirs(str(tmp_path))
    assert [Path(x).name for x in left] == ["run_trial_dryrun_abc", "run_trial_dryrun_def"]


# ------------------------------------------------------------------------------------------------ DR-02

def test_dr02_copies_development_inputs_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tests_ids = ("s02_t02", "s05_t05", "s07_t10", "s01_t00")
    real = synthetic_repo(tmp_path / "real", DEV, extra=tests_ids)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    opened: list[str] = []
    real_open = builtins.open

    def spy(file: Any, *a: Any, **k: Any):
        opened.append(str(file))
        return real_open(file, *a, **k)

    monkeypatch.setattr(builtins, "open", spy)
    copied = dryrun.copy_inputs(real, scratch)
    monkeypatch.undo()
    got = files_of(scratch)
    want = {f"data/processed/{t}{suf}" for t in DEV for suf in (p.DB_SUFFIX, p.OFFSETS_SUFFIX, p.CHANGES_SUFFIX)}
    want |= {"data/trial_windows.csv"} | {f"ground_truth/approved/{t}.yaml" for t in DEV}
    assert got == want
    assert sorted(copied) == sorted(want)
    assert not any(t in f for f in got for t in tests_ids)
    assert not any(t in o for o in opened for t in tests_ids)           # not even opened
    assert (scratch / "out").is_dir() and files_of(scratch / "out") == set()
    assert "data/manifest.csv" not in got                               # no stage reads it (decision 074 item 6)
    for rel in want:
        assert (scratch / rel).read_bytes() == (real / rel).read_bytes()


# ------------------------------------------------------------------------------------------------ DR-04

def scratch_for_negatives(tmp_path: Path) -> Path:
    scratch = synthetic_repo(tmp_path / "scratch")
    return scratch


def test_dr04a_allowlist_refusal_with_zero_byte_db_and_fake_window_row(tmp_path: Path) -> None:
    scratch = scratch_for_negatives(tmp_path)
    holder = dryrun.Child()
    chk = dryrun.negative_allowlist(scratch, holder)
    assert chk.ok, chk.problems
    assert dryrun.NEGATIVE_TRIAL == "s02_t02" and dryrun.NEGATIVE_TRIAL not in DEV
    db = scratch / "data" / "processed" / "s02_t02.sqlite3"
    assert db.is_file() and db.stat().st_size == 0                      # zero bytes, unchanged
    windows = (scratch / "data" / "trial_windows.csv").read_text(encoding="utf-8")
    assert any(line.startswith("s02_t02,") for line in windows.splitlines())     # the fake window row
    assert not (scratch / "out" / "run_trial" / "s02_t02").exists()
    for s in dryrun.COMPARED_STAGES:
        assert not (scratch / "out" / s / "s02_t02").exists()


def test_dr04a_refuses_a_development_trial_as_negative(tmp_path: Path) -> None:
    scratch = scratch_for_negatives(tmp_path)
    chk = dryrun.negative_allowlist(scratch, dryrun.Child(), trial=T)
    assert not chk.ok


def test_dr04b_missing_clock_file_is_refused_by_rt02_with_commands(tmp_path: Path) -> None:
    scratch = scratch_for_negatives(tmp_path)
    holder = dryrun.Child()
    chk = dryrun.negative_presence(scratch, holder, T)
    assert chk.ok, chk.problems
    assert not (scratch / "data" / "processed" / f"{T}{p.CHANGES_SUFFIX}").exists()
    log = (scratch / "out" / "run_trial" / T / "run_log.json").read_text(encoding="utf-8")
    assert '"status": "refused"' in log and "presence" in log
    for s in dryrun.COMPARED_STAGES:
        assert not (scratch / "out" / s / T).exists()                   # no stage started


def test_dr04_both_negatives_in_the_same_scratch_repo(tmp_path: Path) -> None:
    scratch = scratch_for_negatives(tmp_path)
    holder = dryrun.Child()
    a = dryrun.negative_allowlist(scratch, holder)
    b = dryrun.negative_presence(scratch, holder, DEV[0])
    assert a.ok and b.ok, (a.problems, b.problems)


# ------------------------------------------------------------------------------------------------ DR-05 / RTT-08

def test_dr05_delete_tree_clears_read_only_flags(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    (scratch / "a" / "b").mkdir(parents=True)
    f = scratch / "a" / "b" / "ro.csv"
    f.write_text("x", encoding="utf-8")
    os.chmod(f, stat.S_IREAD)
    g = scratch / "ro_top.txt"
    g.write_text("y", encoding="utf-8")
    os.chmod(g, stat.S_IREAD)
    assert dryrun.delete_tree(scratch) is None
    assert not scratch.exists()


def test_dr05_delete_tree_retries_then_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "f").write_text("x", encoding="utf-8")
    import shutil
    real_rmtree = shutil.rmtree
    attempts: list[int] = []

    def flaky(path: Any, *a: Any, **k: Any):
        attempts.append(1)
        if len(attempts) < 3:
            raise PermissionError("locked by a child that just exited")
        return real_rmtree(path, *a, **k)

    monkeypatch.setattr(shutil, "rmtree", flaky)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    assert dryrun.delete_tree(scratch) is None
    assert len(attempts) == 3 and not scratch.exists()


def test_dr05_delete_tree_reports_the_error_when_it_never_succeeds(tmp_path: Path,
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    import shutil

    def locked(path: Any, *a: Any, **k: Any):
        raise PermissionError("still locked")

    monkeypatch.setattr(shutil, "rmtree", locked)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    err = dryrun.delete_tree(scratch, retries=3)
    assert err and "locked" in err
    assert scratch.exists()


class _Boom(Exception):
    pass


def _patch_main_to_fail_in(monkeypatch: pytest.MonkeyPatch, scratch: Path, exc: BaseException) -> list[Any]:
    """Make dryrun.main use `scratch`, skip hashing the real tree, then raise `exc` inside the dry run."""
    holders: list[Any] = []

    class Holder(dryrun.Child):
        def __init__(self) -> None:
            super().__init__()
            holders.append(self)

    def fake_scratch(repo: Path) -> Path:
        scratch.mkdir()
        (scratch / "sub").mkdir()
        ro = scratch / "sub" / "readonly.csv"
        ro.write_text("x", encoding="utf-8")
        os.chmod(ro, stat.S_IREAD)
        return scratch

    def explode(*a: Any, **k: Any):
        raise exc

    monkeypatch.setattr(dryrun, "Child", Holder)
    monkeypatch.setattr(dryrun, "make_scratch", fake_scratch)
    monkeypatch.setattr(dryrun, "tree_files", lambda *a, **k: [])
    monkeypatch.setattr(dryrun, "hash_files", lambda *a, **k: {})
    monkeypatch.setattr(dryrun, "copy_inputs", explode)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    return holders


@pytest.mark.parametrize("exc", [_Boom("forced failure"), KeyboardInterrupt()])
def test_dr05_scratch_deleted_after_a_forced_failure_inside_the_dry_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                                        capsys: pytest.CaptureFixture[str],
                                                                        exc: BaseException) -> None:
    scratch = tmp_path / "scratch_repo"
    _patch_main_to_fail_in(monkeypatch, scratch, exc)
    code = dryrun.main([])
    assert code != 0                                                    # a failed run never exits 0
    out = capsys.readouterr()
    assert not scratch.exists()                                         # deletion verified, read-only file included
    assert f"scratch repo {scratch} deleted" in out.out.replace("\\\\", "\\")
    assert "FAILED" in out.out


def test_dr05_running_child_is_terminated_before_deletion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = tmp_path / "scratch_repo"
    holders = _patch_main_to_fail_in(monkeypatch, scratch, KeyboardInterrupt())
    child: list[subprocess.Popen] = []

    def start_child_then_interrupt(*a: Any, **k: Any):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], cwd=str(scratch))
        child.append(proc)
        holders[0].proc = proc
        raise KeyboardInterrupt()

    monkeypatch.setattr(dryrun, "copy_inputs", start_child_then_interrupt)
    try:
        code = dryrun.main([])
        assert code != 0
        assert child and child[0].poll() is not None                    # terminated and waited for
        assert not scratch.exists()                                     # its cwd no longer blocks the deletion
    finally:
        for c in child:
            if c.poll() is None:
                c.kill()
                c.wait()


def test_dr05_failed_deletion_is_reported_and_exits_non_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                             capsys: pytest.CaptureFixture[str]) -> None:
    scratch = tmp_path / "scratch_repo"
    _patch_main_to_fail_in(monkeypatch, scratch, _Boom("x"))
    monkeypatch.setattr(dryrun, "delete_tree", lambda path, *a, **k: "PermissionError: locked")
    code = dryrun.main([])
    err = capsys.readouterr().err
    assert code != 0
    assert "NOT deleted" in err and "locked" in err


def test_dr05_warns_about_leftover_folders_at_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    systmp = tmp_path / "systmp"
    (systmp / "run_trial_dryrun_old1").mkdir(parents=True)
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(systmp))
    _patch_main_to_fail_in(monkeypatch, tmp_path / "scratch_repo", _Boom("x"))
    dryrun.main([])
    out = capsys.readouterr().out
    assert "leftover" in out and "run_trial_dryrun_old1" in out
    assert (systmp / "run_trial_dryrun_old1").exists()                  # a warning only; never deleted by the tool


def test_dr05_deleted_message_is_the_spec_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                               capsys: pytest.CaptureFixture[str]) -> None:
    scratch = tmp_path / "scratch_repo"
    _patch_main_to_fail_in(monkeypatch, scratch, _Boom("x"))
    dryrun.main([])
    assert f"scratch repo {scratch} deleted" in capsys.readouterr().out
