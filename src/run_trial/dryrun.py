"""Dry run of the runner in a scratch copy of the repository (spec 06 section 4 B2, DR-01..DR-07):

    python -m run_trial.dryrun

1. Warn about leftover ``run_trial_dryrun_*`` folders from a hard kill; create the scratch repo with
   ``tempfile.mkdtemp`` in the system temp folder and refuse if it resolves under the repository (DR-01).
2. Hash the committed tree (DR-06): every file under ``out/`` and ``ground_truth/``, the development DBs and clock
   files, and the top-level ``data/*.csv``. WHY not all of ``data/``: that would read the bytes of the t02-t10 DBs,
   which nothing in the development part may open (019, RT-01).
3. Copy the development inputs (DR-02): the 9 DBs and their clock files, ``data/trial_windows.csv`` and
   ``ground_truth/approved/``. No stage of the chain reads ``data/manifest.csv`` (only clock_offset, trial_window
   and answer_key do), and the label rules and order table are package data, so nothing else is copied.
4. Run ``python -m run_trial --development --repo <scratch>`` as a subprocess, then compare every trial folder of
   gate, stitch, label, score, evaluate and ``out/evaluate/development/`` with the committed ``out/``
   (``dryrun_compare``; DR-03, DR-06, DR-07).
   A file only in scratch (``new``) is a mismatch unless listed in ``dryrun_compare.ALLOWED_NEW`` (empty); every
   compared folder must hold at least one matching file, and the folder set on both sides must be exactly the 9
   trials x 5 stages plus ``out/evaluate/development`` (ATK-EV-17).
5. Negative cases (DR-04): (a) a zero-byte ``s02_t02.sqlite3`` (the scratch repo's own file) plus a fake window row
   must be refused by RT-01; (b) a removed clock file must be refused by RT-02 with the create commands.
   Isolation proof (ATK-EV-18): (c) one changed byte in a scratch clock file must make gate refuse (its clock-hash
   check), which proves gate reads the scratch ``data/``; (d) a comment line appended to a scratch approved key must
   reach evaluate (the new key SHA-256 in its ``run_info.json``) or make evaluate refuse, which proves evaluate reads
   the scratch ``ground_truth/``.
6. Check the committed tree again (DR-06): the hashes must be unchanged, and so must a listing (names, sizes,
   modification times; contents never read) of every file under the real ``data/processed/`` and ``docs/``. In
   ``finally``: terminate a running child, delete the scratch repo with retries and verify it is gone (DR-05); a
   second Ctrl-C during this clean-up is ignored until the deletion has finished.

Hard-kill limit (ATK-EV-25): a kill that skips Python's ``finally`` (``taskkill /F``, closing the console window,
power loss) cannot clean up. The scratch folder then stays in the temp folder (the next run warns about it, step 1)
and a stage started by the runner may keep running until it ends on its own; neither touches the real repository.

Exit 0 only if every compared file matched, all negative cases held, the tree is unchanged and the scratch repo
was deleted. Normalised values: the one list ``dryrun_compare.NORMALISED`` with its chained proof (decision 074).
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from . import params as p
from .checks import is_under as _is_under
from .dryrun_compare import NEW, PASSING, FileResult, disk_comparer, is_match
from .execute import child_env, kill_tree

__all__ = ["PREFIX", "NEGATIVE_TRIAL", "COMPARED_STAGES", "is_under", "leftover_dirs", "make_scratch",
           "dev_input_files", "tree_files", "hash_files", "copy_inputs", "compare_all", "negative_allowlist",
           "negative_presence", "negative_clock_perturbation", "negative_key_perturbation", "expected_folders",
           "folder_problems", "stat_listing", "listing_diff", "delete_tree", "main"]

PREFIX = "run_trial_dryrun_"
# DR-04a: a test-shaped id outside DEVELOPMENT_TRIALS; only a zero-byte file of the scratch repo carries it.
NEGATIVE_TRIAL = "s02_t02"
COMPARED_STAGES: tuple[str, ...] = ("gate", "stitch", "label", "score", "evaluate")
DELETE_RETRIES = 6


# ---------------------------------------------------------------- DR-01 scratch location

def is_under(path: Path | str, root: Path | str) -> bool:
    """True iff ``path`` equals or lies under ``root`` after ``os.path.realpath`` (case-insensitive on Windows,
    ``normcase``). Pure apart from resolving links."""
    return _is_under(path, root)


def leftover_dirs(temp_dir: str, prefix: str = PREFIX) -> list[str]:
    """Folders with the dry-run prefix (or the ablation's, ``prefix``) in the temp folder (from a hard kill,
    ATK-EV-09)."""
    return sorted(d for d in glob.glob(os.path.join(temp_dir, prefix + "*")) if os.path.isdir(d))


def make_scratch(repo: Path, prefix: str = PREFIX) -> Path:
    """Create the scratch repo in the system temp folder; delete it again and raise if it lies under ``repo``.
    ``prefix`` lets the ablation (``run_trial.ablation``, AB-02) reuse the same DR-01 rule under its own name."""
    path = tempfile.mkdtemp(prefix=prefix)
    if is_under(path, repo):
        shutil.rmtree(path, ignore_errors=True)
        raise RuntimeError(f"refused: scratch folder {path} lies under the repository {repo} (DR-01)")
    return Path(os.path.realpath(path))


# ---------------------------------------------------------------- DR-02 / DR-06 file lists

def dev_input_files(trials: Sequence[str] = p.DEVELOPMENT_TRIALS) -> list[Path]:
    """Repo-relative paths of the development DBs and clock files. Built from the ids, never from a folder listing,
    so no t02-t10 name is even listed (RT-01)."""
    return [p.PROCESSED_REL / f"{t}{suf}" for t in trials for suf in (p.DB_SUFFIX, p.OFFSETS_SUFFIX,
                                                                       p.CHANGES_SUFFIX)]


def tree_files(repo: Path, trials: Sequence[str] = p.DEVELOPMENT_TRIALS) -> list[Path]:
    """Repo-relative paths hashed for DR-06: all of ``out/`` and ``ground_truth/``, the development inputs, and the
    top-level ``data/*.csv``."""
    repo = Path(repo)
    files: list[Path] = []
    for top in ("out", "ground_truth"):
        root = repo / top
        if root.is_dir():
            files += [f.relative_to(repo) for f in root.rglob("*") if f.is_file()]
    files += [f for f in dev_input_files(trials) if (repo / f).is_file()]
    files += [f.relative_to(repo) for f in (repo / "data").glob("*.csv") if f.is_file()]
    return sorted(set(files))


def _sha256(path: Path) -> str:
    """SHA-256 of a file, read in 1 MiB blocks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def hash_files(repo: Path, rels: Sequence[Path]) -> dict[str, str]:
    """POSIX rel path -> SHA-256 of each file."""
    return {r.as_posix(): _sha256(Path(repo) / r) for r in rels}


def tree_diff(before: dict[str, str], after: dict[str, str]) -> list[str]:
    """One line per added, removed or changed file between two hash trees. Pure."""
    out = [f"added: {k}" for k in sorted(set(after) - set(before))]
    out += [f"removed: {k}" for k in sorted(set(before) - set(after))]
    out += [f"changed: {k}" for k in sorted(set(before) & set(after)) if before[k] != after[k]]
    return out


def copy_inputs(repo: Path, scratch: Path, trials: Sequence[str] = p.DEVELOPMENT_TRIALS) -> list[str]:
    """DR-02: copy the development inputs, the window file and the approved keys; create an empty ``out/``.
    Returns the copied repo-relative paths. Approved keys are copied only for development trial ids."""
    copied: list[str] = []
    rels = dev_input_files(trials) + [p.WINDOWS_REL]
    keys = Path("ground_truth/approved")
    rels += [keys / f.name for f in sorted((repo / keys).glob("*.yaml")) if f.stem in trials]
    for rel in rels:
        dst = scratch / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo / rel, dst)
        copied.append(rel.as_posix())
    (scratch / "out").mkdir(exist_ok=True)
    return copied


# ---------------------------------------------------------------- DR-03 comparison

def compare_all(repo: Path, scratch: Path, trials: Sequence[str]) -> list[FileResult]:
    """Every trial folder of the compared stages and the evaluate summary folder, both directions, with one
    Comparer (so each run_info.json pair of the chained proof is compared once)."""
    cmp = disk_comparer(repo, scratch)
    results: list[FileResult] = []
    for t in trials:
        for stage in COMPARED_STAGES:
            results += cmp.compare_folder(stage, t)
    results += cmp.compare_folder("evaluate_dev", p.DEVELOPMENT_DIR_NAME)
    return results


def expected_folders(trials: Sequence[str]) -> set[str]:
    """The compared folder set (ATK-EV-17): ``out/<stage>/<t>`` for the 5 stages x the trials, plus
    ``out/evaluate/development``. Built from the lists, not from the disk. Pure."""
    out = {(p.STAGE_OUT_REL[s] / t).as_posix() for s in COMPARED_STAGES for t in trials}
    out.add(p.EVAL_SUMMARY_DIR.as_posix())
    return out


def _present_folders(root: Path) -> set[str]:
    """The trial (and summary) folders that exist under ``out/<stage>/`` of the compared stages (dot folders, the
    stages' temporary swap folders, are ignored)."""
    out: set[str] = set()
    for s in COMPARED_STAGES:
        base = root / p.STAGE_OUT_REL[s]
        if base.is_dir():
            out |= {(p.STAGE_OUT_REL[s] / d.name).as_posix() for d in base.iterdir()
                    if d.is_dir() and not d.name.startswith(".")}
    return out


def folder_problems(repo: Path, scratch: Path, trials: Sequence[str], results: Sequence[FileResult]) -> list[str]:
    """ATK-EV-17 folder checks: the folder set on each side equals ``expected_folders`` (a missing committed or
    scratch folder, or an extra one, is a problem), and every expected folder holds at least one file that is
    identical or equal after normalising."""
    want = expected_folders(trials)
    problems: list[str] = []
    for side, root in (("committed", repo), ("scratch", scratch)):
        have = _present_folders(root)
        problems += [f"{side} folder missing: {f}" for f in sorted(want - have)]
        problems += [f"{side} folder not expected: {f}" for f in sorted(have - want)]
    matched = {r.folder for r in results if r.status in PASSING}
    problems += [f"no identical or normalised-equal file in {f}" for f in sorted(want - matched)]
    return problems


def stat_listing(repo: Path, tops: Sequence[str] = ("data/processed", "docs")) -> dict[str, tuple[int, int]]:
    """rel path -> (size, mtime_ns) of every file under ``tops`` (ATK-EV-18). Stat only: no file is opened, so the
    t02-t10 DBs are never read."""
    out: dict[str, tuple[int, int]] = {}
    for top in tops:
        root = Path(repo) / top
        if root.is_dir():
            for f in root.rglob("*"):
                if f.is_file():
                    st = f.stat()
                    out[f.relative_to(repo).as_posix()] = (st.st_size, st.st_mtime_ns)
    return out


def _shown(rel: str, trials: Sequence[str]) -> str:
    """A path for the report; a file under data/processed that is not a development file is not named (RT-01)."""
    if rel.startswith("data/processed/") and not any(Path(rel).name.startswith(f"{t}.") for t in trials):
        return "<a non-development file under data/processed>"
    return rel


def listing_diff(before: dict[str, tuple[int, int]], after: dict[str, tuple[int, int]],
                 trials: Sequence[str]) -> list[str]:
    """One line per added, removed or changed (size / mtime) file between two listings. Pure."""
    out = [f"added: {_shown(k, trials)}" for k in sorted(set(after) - set(before))]
    out += [f"removed: {_shown(k, trials)}" for k in sorted(set(before) - set(after))]
    out += [f"changed (size/mtime): {_shown(k, trials)}" for k in sorted(set(before) & set(after))
            if before[k] != after[k]]
    return out


# ---------------------------------------------------------------- child processes

@dataclass
class Child:
    """The one running child (if any), so ``finally`` can terminate it (DR-05)."""
    proc: subprocess.Popen | None = None


def _run(argv: Sequence[str], holder: Child, capture: bool) -> tuple[int, str, str]:
    """Run a child from the code location, keep it in ``holder`` while it runs; returns (exit, stdout, stderr)."""
    pipe = subprocess.PIPE if capture else None
    holder.proc = subprocess.Popen(list(argv), cwd=str(p.REPO), env=child_env(os.environ), stdout=pipe,
                                   stderr=pipe, text=True, encoding="utf-8", errors="replace")
    out, err = holder.proc.communicate()
    code = holder.proc.returncode
    holder.proc = None
    return code, out or "", err or ""


def _runner(scratch: Path, *args: str) -> list[str]:
    """argv of ``python -m run_trial <args> --repo <scratch>``."""
    return [sys.executable, "-m", "run_trial", *args, "--repo", scratch.as_posix()]


# ---------------------------------------------------------------- DR-04 negative cases

@dataclass
class Check:
    """A named negative case: ok, plus the reasons it failed (empty when ok)."""
    name: str
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True iff no problem was found."""
        return not self.problems


def _snapshot(folder: Path) -> dict[str, tuple[int, int]]:
    """rel path -> (size, mtime_ns) of every file under ``folder``."""
    if not folder.is_dir():
        return {}
    return {f.relative_to(folder).as_posix(): (f.stat().st_size, f.stat().st_mtime_ns)
            for f in folder.rglob("*") if f.is_file()}


def _append_fake_window_row(windows: Path, trial: str) -> None:
    """Add a row for ``trial`` to the scratch window file (columns as in its header; values are placeholders)."""
    with open(windows, newline="", encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    row = {c: "fake-dryrun" for c in header}
    row["trial_id"] = trial
    with open(windows, "a", newline="", encoding="utf-8") as fh:
        csv.DictWriter(fh, fieldnames=header, lineterminator="\n").writerow(row)


def negative_allowlist(scratch: Path, holder: Child, trial: str = NEGATIVE_TRIAL) -> Check:
    """DR-04a (ATK-EV-08): a zero-byte DB, zero-byte clock files and a fake window row for a test-shaped id make
    RT-02 pass, so only RT-01 can refuse; the run must give exit 2 with the RT-01 text, leave the DB unchanged and
    create no ``out/<stage>/<trial>`` and no ``out/run_trial/<trial>``."""
    chk = Check(f"DR-04a {trial} refused by RT-01")
    if trial in p.DEVELOPMENT_TRIALS:
        chk.problems.append(f"{trial} is a development trial; pick another id")
        return chk
    proc = scratch / p.PROCESSED_REL
    for suf in (p.DB_SUFFIX, p.OFFSETS_SUFFIX, p.CHANGES_SUFFIX):
        (proc / f"{trial}{suf}").write_bytes(b"")
    _append_fake_window_row(scratch / p.WINDOWS_REL, trial)
    db = proc / f"{trial}{p.DB_SUFFIX}"
    before = (db.stat().st_size, db.stat().st_mtime_ns, _sha256(db))
    code, _out, err = _run(_runner(scratch, "--trial", trial), holder, capture=True)
    if code != p.EXIT_REFUSED:
        chk.problems.append(f"exit {code}, expected 2")
    if "not in the development allowlist" not in err or "RT-01" not in err:
        chk.problems.append(f"stderr lacks the RT-01 message: {err.strip()[:300]!r}")
    if "RT-02" in err:
        chk.problems.append("stderr carries the RT-02 message")
    if (db.stat().st_size, db.stat().st_mtime_ns, _sha256(db)) != before:
        chk.problems.append("the zero-byte DB changed")
    for folder in [*(scratch / p.STAGE_OUT_REL[s] / trial for s in COMPARED_STAGES),
                   scratch / p.RUN_TRIAL_OUT_REL / trial]:
        if folder.exists():
            chk.problems.append(f"created {folder.relative_to(scratch).as_posix()}")
    return chk


def negative_presence(scratch: Path, holder: Child, trial: str) -> Check:
    """DR-04b: with the trial's copied clock_changes file removed, the run must be refused by RT-02 (exit 2), print
    the create commands, start no stage (every step ``not run`` in the log) and leave every stage folder of the
    trial untouched."""
    chk = Check(f"DR-04b {trial} without clock_changes refused by RT-02")
    (scratch / p.PROCESSED_REL / f"{trial}{p.CHANGES_SUFFIX}").unlink()
    snaps = {s: _snapshot(scratch / p.STAGE_OUT_REL[s] / trial) for s in COMPARED_STAGES}
    code, _out, err = _run(_runner(scratch, "--trial", trial), holder, capture=True)
    if code != p.EXIT_REFUSED:
        chk.problems.append(f"exit {code}, expected 2")
    for needle in ("RT-02", f"python -m clock_offset --trials {trial}"):
        if needle not in err:
            chk.problems.append(f"stderr lacks {needle!r}")
    if "python -m data_layout.batch" in err or "python -m trial_window" in err:
        chk.problems.append("stderr names a create command for an input that is present")
    log_path = scratch / p.RUN_TRIAL_OUT_REL / trial / p.RUN_LOG_JSON
    try:
        log = json.loads(log_path.read_text(encoding="utf-8"))
        ran = [s["step"] for s in log["steps"] if s["result"] not in (p.RESULT_NOT_RUN,)
               and s["step"] != p.PRESENCE_STEP]
        if ran or log["status"] != p.STATUS_REFUSED or log["refused_step"] != p.PRESENCE_STEP:
            chk.problems.append(f"log shows steps run {ran} / status {log['status']} / {log['refused_step']}")
    except (OSError, KeyError, ValueError) as exc:
        chk.problems.append(f"run_log.json unreadable: {exc}")
    for s in COMPARED_STAGES:
        if _snapshot(scratch / p.STAGE_OUT_REL[s] / trial) != snaps[s]:
            chk.problems.append(f"out/{s}/{trial} changed")
    return chk


def _read_log(scratch: Path, trial: str) -> dict[str, Any]:
    """The scratch run_log.json of a trial ({} if missing or unreadable)."""
    try:
        return json.loads((scratch / p.RUN_TRIAL_OUT_REL / trial / p.RUN_LOG_JSON).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# A descriptive column of clock_offsets.csv that no check reads back (the pair time span): changing one of its digits
# leaves the file valid, so the only thing gate can notice is the file's SHA-256.
PERTURB_COLUMN = "pair_span_s"


def _flip_digit(path: Path, column: str = PERTURB_COLUMN) -> None:
    """Change exactly one byte of a CSV: the last digit of the first non-empty ``column`` cell becomes another
    digit (same length, still a number). WHY that column and not any byte: a byte inside a hash column would trip a
    different gate check first (seen in the dry run of 2026-11-18), and the proof wants the clock-hash refusal."""
    data = path.read_bytes()
    lines = data.split(b"\n")
    header = lines[0].decode("utf-8").rstrip("\r").split(",")
    col = header.index(column)
    offset = len(lines[0]) + 1
    for line in lines[1:]:
        cells = line.split(b",")
        if len(cells) == len(header) and cells[col].strip().isdigit():
            pos = offset + sum(len(c) + 1 for c in cells[:col]) + len(cells[col]) - 1
            buf = bytearray(data)
            buf[pos] = 0x30 + (buf[pos] - 0x30 + 1) % 10
            path.write_bytes(bytes(buf))
            return
        offset += len(line) + 1
    raise ValueError(f"{path.name} has no numeric {column} cell to change")


def negative_clock_perturbation(scratch: Path, holder: Child, trial: str) -> Check:
    """ATK-EV-18 (c): one changed byte in the scratch ``clock_offsets.csv`` of ``trial`` must make gate refuse
    (window ``offsets_sha256`` != file SHA-256). If gate read the real ``data/`` instead, it would pass."""
    chk = Check(f"ATK-EV-18c {trial} clock file changed in scratch -> gate refuses")
    _flip_digit(scratch / p.PROCESSED_REL / f"{trial}{p.OFFSETS_SUFFIX}")
    code, _out, err = _run(_runner(scratch, "--trial", trial), holder, capture=True)
    log = _read_log(scratch, trial)
    if code != p.EXIT_REFUSED:
        chk.problems.append(f"exit {code}, expected 2")
    if log.get("refused_step") != "gate":
        chk.problems.append(f"refused_step {log.get('refused_step')!r}, expected 'gate'")
    if "SHA-256" not in err:
        chk.problems.append(f"stderr lacks gate's clock-hash refusal: {err.strip()[-300:]!r}")
    return chk


def negative_key_perturbation(scratch: Path, holder: Child, trial: str) -> Check:
    """ATK-EV-18 (d): a YAML comment line appended to the scratch approved key of ``trial`` changes its SHA-256;
    the rerun must either be refused at an evaluate step or write the new key SHA-256 (and not the old one) into
    ``out/evaluate/<trial>/run_info.json``. If evaluate read the real ``ground_truth/``, neither would happen."""
    chk = Check(f"ATK-EV-18d {trial} approved key changed in scratch -> evaluate sees it")
    key = scratch / "ground_truth" / "approved" / f"{trial}.yaml"
    old_sha = _sha256(key)
    with open(key, "ab") as fh:
        fh.write(b"\n# run_trial dry run perturbation (ATK-EV-18)\n")
    new_sha = _sha256(key)
    code, _out, err = _run(_runner(scratch, "--trial", trial), holder, capture=True)
    log = _read_log(scratch, trial)
    if code == p.EXIT_REFUSED and str(log.get("refused_step", "")).startswith("evaluate"):
        return chk
    if code != 0:
        chk.problems.append(f"exit {code} at step {log.get('refused_step') or log.get('failed_step')!r}: "
                            f"{err.strip()[-300:]!r}")
        return chk
    info = (scratch / p.STAGE_OUT_REL["evaluate"] / trial / "run_info.json").read_text(encoding="utf-8")
    if new_sha not in info or old_sha in info:
        chk.problems.append("evaluate run_info.json does not carry the changed key's SHA-256")
    return chk


# ---------------------------------------------------------------- DR-05 deletion

def _clear_readonly(func: Callable[..., Any], path: str, _exc: Any) -> None:
    """rmtree error handler: clear the read-only flag and retry the failed call once."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def delete_tree(path: Path, retries: int = DELETE_RETRIES) -> str | None:
    """Delete ``path`` with retries (Windows may hold a file a moment after a child exits); None when the folder is
    gone, else the last error text."""
    err = ""
    for attempt in range(retries):
        try:
            if path.exists():
                shutil.rmtree(path, onerror=_clear_readonly)
        except OSError as exc:
            err = str(exc)
        if not path.exists():
            return None
        time.sleep(1.0 + attempt)
    return err or f"{path} still exists"


# ---------------------------------------------------------------- report

def _wall_table(log: dict[str, Any]) -> list[str]:
    """Per-stage wall time lines from the scratch development log."""
    lines = []
    for t in log.get("trials", []):
        cells = ", ".join(f"{s['step']}={s['wall_ms']}" for s in t["steps"])
        lines.append(f"  {t['trial_id']}: {t['status']}; {cells}")
    for s in log.get("summary_steps", []):
        lines.append(f"  summary {s['step']}: {s['result']}, {s['wall_ms']} ms")
    return lines


def _report(results: Sequence[FileResult]) -> tuple[list[str], bool]:
    """Per-folder summary lines and whether every file matched."""
    lines: list[str] = []
    folders: dict[str, list[FileResult]] = {}
    for r in results:
        folders.setdefault(r.folder, []).append(r)
    for folder, rs in folders.items():
        counts: dict[str, int] = {}
        for r in rs:
            counts[r.status] = counts.get(r.status, 0) + 1
        lines.append(f"  {folder}: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
        for r in rs:
            if not is_match(r) or r.status == NEW or r.substitutions:
                subs = ", ".join(f"{k}: {n} replaced/{r.differing.get(k, 0)} differing"
                                 for k, n in r.substitutions.items())
                lines.append(f"    {r.name}: {r.status}" + (f" [{subs}]" if subs else "")
                             + (f" -- {r.detail}" if r.detail else ""))
    return lines, all(is_match(r) for r in results)


def _ignore_sigint() -> Any:
    """Ignore Ctrl-C (main thread only); returns the previous handler, or None if it could not be changed."""
    try:
        return signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        return None


def _restore_sigint(old: Any) -> None:
    """Put back the Ctrl-C handler saved by ``_ignore_sigint``."""
    if old is not None:
        try:
            signal.signal(signal.SIGINT, old)
        except (ValueError, OSError):
            pass


def _cleanup(holder: Child, scratch: Path | None) -> bool:
    """DR-05: terminate a running child, delete the scratch repo, verify it is gone. Ctrl-C is ignored meanwhile
    (ATK-EV-25); if one still arrives (signal not changeable), the clean-up is simply retried. True iff deleted."""
    old = _ignore_sigint()
    try:
        while True:
            try:
                if holder.proc is not None:
                    kill_tree(holder.proc)
                    holder.proc = None
                if scratch is None:
                    return True
                err = delete_tree(scratch)
                break
            except KeyboardInterrupt:
                print("Ctrl-C ignored until the scratch repo is deleted", file=sys.stderr)
    finally:
        _restore_sigint(old)
    if err is None:
        print(f"scratch repo {scratch} deleted")
        return True
    print(f"scratch repo {scratch} NOT deleted: {err}", file=sys.stderr)
    return False


def main(argv: Sequence[str] | None = None) -> int:
    """Run the dry run; see the module docstring. Exit 0 only if everything matched and the scratch repo is gone."""
    ap = argparse.ArgumentParser(prog="run_trial.dryrun", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    a = ap.parse_args(argv)
    repo, trials = p.REPO, tuple(p.DEVELOPMENT_TRIALS)
    for d in leftover_dirs(tempfile.gettempdir()):
        print(f"warning: leftover dry-run folder from an earlier run: {d} (delete it by hand)")
    holder = Child()
    scratch: Path | None = None
    ok, deleted_ok = False, False
    try:
        scratch = make_scratch(repo)
        print(f"scratch repo {scratch}")
        before = hash_files(repo, tree_files(repo, trials))
        listed_before = stat_listing(repo)
        print(f"committed tree: {len(before)} files hashed, {len(listed_before)} files listed")
        copied = copy_inputs(repo, scratch, trials)
        print(f"copied {len(copied)} files into the scratch repo")
        code, _o, _e = _run(_runner(scratch, "--development"), holder, capture=False)
        print(f"run_trial --development exit {code}")
        log_path = scratch / p.RUN_TRIAL_OUT_REL / p.DEVELOPMENT_DIR_NAME / p.RUN_LOG_JSON
        dev_log = json.loads(log_path.read_text(encoding="utf-8")) if log_path.is_file() else {}
        results = compare_all(repo, scratch, trials)
        lines, files_ok = _report(results)
        fproblems = folder_problems(repo, scratch, trials, results)
        keyed = [t for t in trials if t in p.KEYED_DEVELOPMENT_TRIALS and t != trials[0]]
        neg = [negative_allowlist(scratch, holder), negative_presence(scratch, holder, trials[0]),
               negative_clock_perturbation(scratch, holder, trials[1]),
               negative_key_perturbation(scratch, holder, keyed[1])]
        after = hash_files(repo, tree_files(repo, trials))
        tdiff = tree_diff(before, after) + listing_diff(listed_before, stat_listing(repo), trials)
        print("\n== per-stage wall time (ms), scratch run_log.json ==")
        print("\n".join(_wall_table(dev_log)) or "  (no development log)")
        print("\n== comparison with the committed out/ ==")
        print("\n".join(lines))
        print(f"  folders: {len(expected_folders(trials))} expected; "
              + ("all present on both sides, each with a matching file" if not fproblems
                 else "PROBLEMS:\n    " + "\n    ".join(fproblems)))
        print("\n== negative cases ==")
        for c in neg:
            print(f"  {c.name}: {'held' if c.ok else 'FAILED: ' + '; '.join(c.problems)}")
        print("\n== committed tree (DR-06) ==")
        print(f"  {len(after)} files hashed, {len(listed_before)} listed; "
              + ("unchanged" if not tdiff else "CHANGED:\n    " + "\n    ".join(tdiff)))
        ok = code == 0 and files_ok and not fproblems and all(c.ok for c in neg) and not tdiff
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
    except Exception as exc:  # report and fall through to the deletion; the exit code says it failed
        print(f"dry run error: {type(exc).__name__}: {exc}", file=sys.stderr)
    finally:
        deleted_ok = _cleanup(holder, scratch) and scratch is not None
    verdict = ok and deleted_ok
    print(f"\ndry run: {'PASSED' if verdict else 'FAILED'}")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
