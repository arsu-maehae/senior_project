"""The cmdline_target ablation of the development trials (spec 06 section 10 D-F / D-G, AB-01..AB-11; ATK-EV-37..44;
decision 020):

    python -m run_trial.ablation

1. Read the default side from the on-disk ``out/`` (git-ignored; the files of ``ablation_report.side_files``,
   SHA-256 of the exact bytes parsed) and refuse if any default stitch ``run_info.json`` carries
   ``disabled_methods`` (AB-05), if evaluate names other stitch files than those read, or if the two link files
   disagree on a key hop's tier.
2. Restore or remove a leftover swap folder of an earlier crash (``_settle_leftovers``: an ``.no_cmdline.old``
   without ``no_cmdline`` is put back, never deleted; ATK-EV-43), then hash the tree (DR-06) with exactly
   ``out/ablation/no_cmdline/`` left out (AB-11).
3. **Control arm** (ATK-EV-37): a scratch repo outside the repository, the dry run's input copy, ``python -m
   run_trial --development --repo <scratch>`` with no flag, then the dry run's comparison with the on-disk ``out/``
   (same normalisation list, chained proof, folder-set check: ``dryrun.compare_all`` / ``folder_problems``). Unless
   every file matches and the folder set is exact, the ablation stops: nothing is copied and nothing is swapped.
   This proves, in the same invocation, that the default side is what the code reproduces.
4. **Ablated arm**: a second scratch repo, ``... --stitch-disable-method cmdline_target`` (AB-02; the runner leaves
   out ``--results``, AB-09). Refuse if the scratch ``out/evaluate/development`` holds ``results.md`` /
   ``results.csv``. Copy the scratch ``out/{stitch,label,score,evaluate}/<t>/`` of the 9 trials and
   ``out/evaluate/development`` into ``out/ablation/.no_cmdline.tmp/`` (same layout as ``out/``) and write
   ``ABLATION.txt`` (the banner) into every copied folder (ATK-EV-42).
5. Read the ablated side from that copy; refuse unless every copied stitch ``run_info.json`` carries
   ``disabled_methods`` == ``["cmdline_target"]``, the hash chain holds, the tiers agree and no ablated link row uses
   cmdline_target. Write ``ablation.md``, ``ablation.csv``, ``README.md`` and ``run_info.json`` (both arms' status)
   into the copy.
6. Tree check before the swap (ATK-EV-43): the tree must equal step 2's, leaving out ``out/ablation/no_cmdline/``
   and the pending ``out/ablation/.no_cmdline.tmp/``. Only then swap the copy in as ``out/ablation/no_cmdline/`` (a
   re-run replaces the whole folder; a crash never leaves a mix, AB-11), and check the tree again with exactly
   ``out/ablation/no_cmdline/`` left out. In ``finally``: terminate a running child, delete both scratch repos,
   verify they are gone (DR-05), and delete a temporary swap folder that is still there.

Exit 0 only if both arms ran, the control arm matched, every check held, the swap was made, the tree is unchanged
and both scratch repos were deleted; 1 otherwise. No t02-t10 file is named, copied or opened (RT-01; every copy
list comes from ids).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import ablation_report as ar
from . import params as p
from .checks import is_under
from .dryrun import (Child, _cleanup, _run, compare_all, copy_inputs, delete_tree, folder_problems, hash_files,
                     leftover_dirs, listing_diff, make_scratch, stat_listing, tree_diff, tree_files)
from .dryrun_compare import FileResult, is_match

__all__ = ["PREFIX", "ABLATION_REL", "TMP_NAME", "OLD_NAME", "COPIED_STAGES", "FORBIDDEN_SUMMARY_FILES",
           "OUTPUT_FILES", "MARKER", "ArmStatus", "exclude_paths", "exclude_ablation", "runner_argv", "copy_plan",
           "summary_problems", "control_status", "read_side", "settle_leftovers", "swap_in", "run_info", "main"]

PREFIX = "run_trial_ablation_"
ABLATION_REL = Path("out/ablation/no_cmdline")
TMP_NAME, OLD_NAME = ".no_cmdline.tmp", ".no_cmdline.old"
COPIED_STAGES: tuple[str, ...] = ("stitch", "label", "score", "evaluate")
# AB-09: results tables are never produced or copied for the ablation.
FORBIDDEN_SUMMARY_FILES: tuple[str, ...] = tuple(p.RESULTS_FILES)
ABLATION_MD, ABLATION_CSV, README_MD, RUN_INFO = "ablation.md", "ablation.csv", "README.md", "run_info.json"
OUTPUT_FILES: tuple[str, ...] = (README_MD, ABLATION_MD, ABLATION_CSV, RUN_INFO)
MARKER = "ABLATION.txt"
TOOL_VERSION = "run_trial.ablation 0.2.0"


@dataclass
class ArmStatus:
    """What one arm did, for run_info.json and README.md (ATK-EV-37)."""
    name: str
    status: str = "not run"
    exit_code: int | None = None
    counts: dict[str, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        """JSON object of the arm."""
        return {"status": self.status, "exit_code": self.exit_code, "file_counts": dict(sorted(self.counts.items())),
                "problems": list(self.problems)}


# ---------------------------------------------------------------- pure helpers

def exclude_paths(tree: Mapping[str, Any], rels: Sequence[Path]) -> dict[str, Any]:
    """The tree without exactly the files under each of ``rels`` (a sibling such as ``out/ablation/no_cmdline_x``
    stays in). Pure."""
    prefixes = tuple(r.as_posix().rstrip("/") + "/" for r in rels)
    return {k: v for k, v in tree.items() if not k.startswith(prefixes)}


def exclude_ablation(tree: Mapping[str, Any], rel: Path = ABLATION_REL) -> dict[str, Any]:
    """AB-11: the DR-06 tree without exactly ``out/ablation/no_cmdline/`` and nothing else. Pure."""
    return exclude_paths(tree, [rel])


def runner_argv(python: str, scratch: Path, disabled: Sequence[str] = ar.DISABLED) -> list[str]:
    """``python -m run_trial --development --repo <scratch>`` plus ``--stitch-disable-method`` per name (AB-02);
    with ``disabled`` empty, the control arm's command (ATK-EV-37)."""
    args = [a for m in disabled for a in ("--stitch-disable-method", m)]
    return [python, "-m", "run_trial", "--development", "--repo", Path(scratch).as_posix(), *args]


def copy_plan(trials: Sequence[str]) -> list[Path]:
    """Out-relative folders copied from the scratch run: ``<stage>/<t>`` for the 4 stages x the trials, then
    ``evaluate/development``. Built from the ids, never from a listing. Pure."""
    out = [Path(s) / t for s in COPIED_STAGES for t in trials]
    return out + [Path("evaluate") / p.DEVELOPMENT_DIR_NAME]


def summary_problems(names: Sequence[str]) -> list[str]:
    """AB-09: a refusal line for each results file present in the scratch ``out/evaluate/development``. Pure."""
    return [f"scratch out/evaluate/development holds {n} (AB-09: --results must not run in the ablation)"
            for n in sorted(set(names) & set(FORBIDDEN_SUMMARY_FILES))]


def control_status(code: int, results: Sequence[FileResult], fproblems: Sequence[str]) -> ArmStatus:
    """ATK-EV-37: the control arm passes only with exit 0, every compared file identical or equal after normalising
    (the dry run's ``is_match``; ``new`` counts as a mismatch) and no folder problem. Pure."""
    arm = ArmStatus("control", exit_code=code)
    for r in results:
        arm.counts[r.status] = arm.counts.get(r.status, 0) + 1
    arm.problems = [f"{r.folder}/{r.name}: {r.status}" + (f" -- {r.detail}" if r.detail else "")
                    for r in results if not is_match(r)] + list(fproblems)
    if code != 0:
        arm.problems.insert(0, f"run_trial --development exit {code}")
    arm.status = "passed" if not arm.problems and results else "failed"
    return arm


def run_info(trials: Sequence[str], arms: Sequence[ArmStatus], default_sha: Mapping[str, str],
             ablated_sha: Mapping[str, str], copied_sha: Mapping[str, str], marker_sha: Mapping[str, str],
             outputs_sha: Mapping[str, str], generated_utc: str) -> dict[str, Any]:
    """run_info.json of the ablation folder: both arms' status (ATK-EV-37), the SHA-256 of every file read on both
    sides (repo-relative), of every copied file, of the markers and of the three written texts, and
    ``generated_utc``. Pure."""
    return {"banner": ar.BANNER, "tool_version": TOOL_VERSION, "generated_utc": generated_utc,
            "default_side": ar.DEFAULT_SIDE,
            "arms": {a.name: dict(a.as_dict(), command=(
                "python -m run_trial --development --repo <scratch>" if a.name == "control" else
                "python -m run_trial --development --repo <scratch> --stitch-disable-method cmdline_target"))
                for a in arms},
            "disabled_methods": list(ar.DISABLED), "trials": list(trials),
            "inputs": {"default": dict(sorted(default_sha.items())), "ablated": dict(sorted(ablated_sha.items()))},
            "copied_files_sha256": dict(sorted(copied_sha.items())),
            "marker_files_sha256": dict(sorted(marker_sha.items())),
            "outputs_sha256": dict(sorted(outputs_sha.items()))}


# ---------------------------------------------------------------- disk

def _sha(data: bytes) -> str:
    """SHA-256 of bytes."""
    return hashlib.sha256(data).hexdigest()


def read_side(root: Path, trials: Sequence[str]) -> tuple[ar.Side, dict[str, bytes]]:
    """Read ``side_files`` under ``root`` once (FileNotFoundError when one is missing) and parse the same bytes that
    are hashed, so no value can come from a file other than the hashed one."""
    blobs = {rel: (root / rel).read_bytes() for rel in ar.side_files(trials)}
    sha = {rel: _sha(b) for rel, b in blobs.items()}
    return ar.parse_side(blobs, sha, trials), blobs


def _repo_rel(prefix: Path, sha: Mapping[str, str]) -> dict[str, str]:
    """Out-relative keys turned into repo-relative POSIX keys under ``prefix``."""
    return {(prefix / k).as_posix(): v for k, v in sha.items()}


def _copy_outputs(scratch_out: Path, tmp: Path, trials: Sequence[str]) -> tuple[dict[str, str], dict[str, str]]:
    """Copy the ``copy_plan`` folders into ``tmp`` (dot folders skipped) and write ``MARKER`` into each; returns
    (out-relative path -> SHA-256 of every copied file, the same for the markers). FileNotFoundError when a planned
    folder is missing in the scratch run."""
    copied: dict[str, str] = {}
    markers: dict[str, str] = {}
    marker = ar.marker_text().encode("utf-8")
    for rel in copy_plan(trials):
        src = scratch_out / rel
        if not src.is_dir():
            raise FileNotFoundError(f"scratch out/{rel.as_posix()} is missing")
        shutil.copytree(src, tmp / rel, ignore=shutil.ignore_patterns(".*"))
        for f in sorted((tmp / rel).rglob("*")):
            if f.is_file():
                copied[f.relative_to(tmp).as_posix()] = _sha(f.read_bytes())
        (tmp / rel / MARKER).write_bytes(marker)
        markers[(rel / MARKER).as_posix()] = _sha(marker)
    return copied, markers


def settle_leftovers(base: Path, include_tmp: bool = True) -> list[str]:
    """Clean up after a crashed run (ATK-EV-43): an ``.no_cmdline.old`` with no ``no_cmdline`` is the previous
    ablation folder caught mid-swap, so it is renamed back (never deleted); an ``.old`` beside a ``no_cmdline`` and,
    with ``include_tmp`` (at start only; never during the swap, where it is the pending copy), a leftover
    ``.no_cmdline.tmp`` are deleted. Returns one line per action."""
    notes: list[str] = []
    target, old, tmp = base / ABLATION_REL.name, base / OLD_NAME, base / TMP_NAME
    if old.exists() and not target.exists():
        os.replace(old, target)
        notes.append(f"restored {target} from the leftover {old}")
    for d in ((old, tmp) if include_tmp else (old,)):
        if d.exists():
            err = delete_tree(d)
            notes.append(f"removed leftover {d}" if err is None else f"could not remove leftover {d}: {err}")
    return notes


def swap_in(tmp: Path, target: Path) -> None:
    """Replace ``target`` by ``tmp`` whole (AB-11): leftovers settled first, the old folder renamed aside, the new
    one renamed in, the old one deleted. If the second rename fails the old folder is put back, so a reader sees the
    old or the new folder, never a mix."""
    for note in settle_leftovers(target.parent, include_tmp=False):
        print(note)
    old = target.parent / OLD_NAME
    if target.exists():
        os.replace(target, old)
    try:
        os.replace(tmp, target)
    except OSError:
        if old.exists() and not target.exists():
            os.replace(old, target)
        raise
    if old.exists():
        err = delete_tree(old)
        if err:
            raise OSError(f"new folder in place, but the old copy {old} was not deleted: {err}")


def _write(folder: Path, files: Mapping[str, str]) -> dict[str, str]:
    """Write UTF-8 texts with ``\\n`` line ends; returns name -> SHA-256 of the bytes written."""
    out: dict[str, str] = {}
    for name, text in files.items():
        data = text.encode("utf-8")
        (folder / name).write_bytes(data)
        out[name] = _sha(data)
    return out


def _utc_now() -> str:
    """Current UTC instant (run_info.json only; the tables carry no time)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tree(repo: Path, trials: Sequence[str]) -> tuple[dict[str, str], dict[str, tuple[int, int]]]:
    """DR-06 hash tree and stat listing of the real repository."""
    return hash_files(repo, tree_files(repo, trials)), stat_listing(repo)


# ---------------------------------------------------------------- report lines

def _side_lines(rows: Sequence[Mapping[str, str]]) -> list[str]:
    """Console lines of the side-by-side readings (hop first) and the node P/R/F1 / pooled AUC."""
    hop = {(r["variant"], r["metric"]): r for r in rows if r["table"] == "headline_hop" and r["match_reading"] == "hop"}
    node = {(r["variant"], r["metric"]): r for r in rows if r["table"] == "node_reading"}
    out = []
    for (v, m), h in hop.items():
        if m in ("top1_expected", "mrr_expected", "mrr_per_key_expected", "s06_margin"):
            n = node.get((v, m), {})
            out.append(f"  {v:<4} {m:<22} hop {h['default'] or '-'} -> {h['ablated'] or '-'}   node "
                       f"{n.get('default') or '-'} -> {n.get('ablated') or '-'}")
    for r in rows:
        if r["table"] == "headline_hop" and r["match_reading"] == "node" and r["metric"] in (
                "node_precision_mean", "node_recall_mean", "node_f1_mean", "auc", "auc_n_pos"):
            out.append(f"  {r['variant']:<4} {r['metric']:<22} {r['default'] or '-'} -> {r['ablated'] or '-'} "
                       f"(trials {r['n_default'] or '-'}/{r['n_ablated'] or '-'}; diff {r['difference'] or '-'})")
    return out


def _auc_trial_lines(rows: Sequence[Mapping[str, str]]) -> list[str]:
    """Console lines of the per-trial AUC (full only, both arms, with n_pos / n_neg)."""
    by: dict[str, dict[str, Mapping[str, str]]] = {}
    for r in rows:
        if r["table"] == "auc_trial" and r["variant"] == "full":
            by.setdefault(r["trial_id"], {})[r["metric"]] = r
    return [f"  {t}: auc {c['auc']['default'] or '-'} -> {c['auc']['ablated'] or '-'} (n_pos "
            f"{c['auc_n_pos']['default']}->{c['auc_n_pos']['ablated']}, n_neg {c['auc_n_neg']['default']}->"
            f"{c['auc_n_neg']['ablated']})" for t, c in by.items()]


def _count_lines(rows: Sequence[Mapping[str, str]], table: str) -> list[str]:
    """Console lines of the per-trial count tables, non-zero items only."""
    out: dict[str, list[str]] = {}
    for r in rows:
        if r["table"] == table and (r["default"] != "0" or r["ablated"] != "0"):
            out.setdefault(r["trial_id"], []).append(f"{r['item']} {r['default']}->{r['ablated']}")
    return [f"  {t}: " + ", ".join(v) for t, v in out.items()]


# ---------------------------------------------------------------- arms

def _control_arm(repo: Path, scratch: Path, holder: Child, trials: Sequence[str]) -> ArmStatus:
    """ATK-EV-37: run the default chain (no flag) in ``scratch`` and compare it with the on-disk ``out/`` under the
    dry-run rules (DR-03, DR-07, decision 074, ATK-EV-17)."""
    copy_inputs(repo, scratch, trials)
    code, _o, _e = _run(runner_argv(sys.executable, scratch, ()), holder, capture=False)
    print(f"control arm: run_trial --development (no flag) exit {code}")
    results = compare_all(repo, scratch, trials) if code == 0 else []
    fproblems = folder_problems(repo, scratch, trials, results) if code == 0 else []
    return control_status(code, results, fproblems)


def _ablated_arm(repo: Path, scratch: Path, holder: Child, trials: Sequence[str]) -> ArmStatus:
    """AB-02: run the ablated chain in ``scratch``; AB-09: refuse a results file in its summary folder."""
    arm = ArmStatus("ablated")
    copy_inputs(repo, scratch, trials)
    arm.exit_code, _o, _e = _run(runner_argv(sys.executable, scratch), holder, capture=False)
    print(f"ablated arm: run_trial --development --stitch-disable-method cmdline_target exit {arm.exit_code}")
    if arm.exit_code != 0:
        arm.problems.append(f"run_trial exit {arm.exit_code}")
    dev = scratch / "out" / "evaluate" / p.DEVELOPMENT_DIR_NAME
    arm.problems += summary_problems([f.name for f in dev.iterdir()] if dev.is_dir() else [])
    arm.status = "ok" if not arm.problems else "failed"
    return arm


# ---------------------------------------------------------------- main

def main(argv: Sequence[str] | None = None) -> int:
    """Run the ablation; see the module docstring."""
    ap = argparse.ArgumentParser(prog="run_trial.ablation", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args(argv)
    repo, trials = p.REPO, tuple(p.DEVELOPMENT_TRIALS)
    out_root, target = repo / "out", repo / ABLATION_REL
    tmp = target.parent / TMP_NAME
    tmp_rel = ABLATION_REL.parent / TMP_NAME
    if not is_under(target, out_root) or is_under(out_root, target):
        print(f"refused: ablation folder {target} is not inside {out_root}", file=sys.stderr)
        return 1
    for d in leftover_dirs(tempfile.gettempdir(), PREFIX):
        print(f"warning: leftover ablation scratch folder from an earlier run: {d} (delete it by hand)")
    holder = Child()
    scratches: list[Path] = []
    ok = False
    try:
        default, _blobs = read_side(out_root, trials)
        problems = ar.disabled_problems(default, (), "default") + ar.chain_problems(default, "default")
        problems += ar.tier_problems(default, "default")
        if problems:
            raise RuntimeError("refused: " + "; ".join(problems))
        target.parent.mkdir(parents=True, exist_ok=True)
        for note in settle_leftovers(target.parent):
            print(note)
        tree0, listed0 = _tree(repo, trials)
        before = exclude_ablation(tree0)
        print(f"tree: {len(before)} files hashed (out/ablation/no_cmdline/ excluded), {len(listed0)} files listed")

        scratches.append(make_scratch(repo, PREFIX + "control_"))
        print(f"control scratch repo {scratches[-1]}")
        control = _control_arm(repo, scratches[-1], holder, trials)
        print(f"control arm: {control.status}; files {dict(sorted(control.counts.items()))}")
        if control.status != "passed":
            raise RuntimeError("refused: the no-flag control arm does not reproduce the on-disk out/ (ATK-EV-37); "
                               "nothing copied, nothing swapped: " + "; ".join(control.problems[:20]))

        scratches.append(make_scratch(repo, PREFIX + "ablated_"))
        print(f"ablated scratch repo {scratches[-1]}")
        ablated_arm = _ablated_arm(repo, scratches[-1], holder, trials)
        if ablated_arm.status != "ok":
            raise RuntimeError("refused: ablated arm: " + "; ".join(ablated_arm.problems))
        tmp.mkdir()
        copied, markers = _copy_outputs(scratches[-1] / "out", tmp, trials)
        ablated, _ablobs = read_side(tmp, trials)
        problems = ar.disabled_problems(ablated, ar.DISABLED, "ablated") + ar.chain_problems(ablated, "ablated")
        problems += ar.tier_problems(ablated, "ablated") + ar.cmdline_link_problems(ablated, "ablated")
        if problems:
            raise RuntimeError("refused: " + "; ".join(problems))
        rows = ar.all_rows(default, ablated, trials)
        arms = {"control": control.status, "ablated": ablated_arm.status}
        contents = list(OUTPUT_FILES) + sorted({f"{r.as_posix()}/" for r in copy_plan(trials)})
        texts = {ABLATION_MD: ar.ablation_md(rows, trials), ABLATION_CSV: ar.ablation_csv(rows),
                 README_MD: ar.readme_md(trials, contents, arms)}
        problems = ar.text_problems(texts)
        if problems:
            raise RuntimeError("refused: " + "; ".join(problems))
        outputs = _write(tmp, texts)
        info = run_info(trials, [control, ablated_arm], _repo_rel(Path("out"), default.sha256),
                        _repo_rel(ABLATION_REL, ablated.sha256), _repo_rel(ABLATION_REL, copied),
                        _repo_rel(ABLATION_REL, markers), outputs, _utc_now())
        (tmp / RUN_INFO).write_bytes((json.dumps(info, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))

        tree1, listed1 = _tree(repo, trials)
        pre = (tree_diff(exclude_paths(tree0, [ABLATION_REL, tmp_rel]), exclude_paths(tree1, [ABLATION_REL, tmp_rel]))
               + listing_diff(listed0, listed1, trials))
        print("\n== tree before the swap (DR-06; out/ablation/no_cmdline/ and the pending temporary folder excluded) ==")
        print(f"  {len(tree1)} files hashed; " + ("unchanged" if not pre else "CHANGED:\n    " + "\n    ".join(pre)))
        if pre:
            raise RuntimeError("refused: the tree changed during the run; nothing swapped (ATK-EV-43)")
        swap_in(tmp, target)
        print(f"written {ABLATION_REL.as_posix()}/ ({len(copied)} copied files, {len(markers)} {MARKER} markers, "
              f"{', '.join(OUTPUT_FILES)})")
        tree2, listed2 = _tree(repo, trials)
        post = tree_diff(before, exclude_ablation(tree2)) + listing_diff(listed0, listed2, trials)

        print("\n== hop and node readings side by side (default -> ablated) ==")
        print("\n".join(_side_lines(rows)))
        print("\n== per-trial AUC, full (default -> ablated) ==")
        print("\n".join(_auc_trial_lines(rows)))
        print("\n== link rows per method (non-zero), default->ablated ==")
        print("\n".join(_count_lines(rows, "link_methods")))
        print("\n== best_tier counts (non-zero), default->ablated ==")
        print("\n".join(_count_lines(rows, "best_tier")))
        print("\n== key attack hops whose best_tier changed ==")
        print("\n".join(f"  {c}" for c in ar.changed_key_hops(rows)) or "  none")
        print("\n== denominators that moved (AB-10, ATK-EV-40) ==")
        print("\n".join(f"  {m}" for m in ar.denominator_moves(rows)) or "  none")
        print("\n== tree after the swap (DR-06, exactly out/ablation/no_cmdline/ excluded) ==")
        print(f"  {len(tree2)} files hashed, {len(listed2)} listed; "
              + ("unchanged" if not post else "CHANGED:\n    " + "\n    ".join(post)))
        ok = not post
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
    except Exception as exc:  # report and fall through to the deletion; the exit code says it failed
        print(f"ablation error: {type(exc).__name__}: {exc}", file=sys.stderr)
    finally:
        deleted = [_cleanup(holder, s) for s in scratches] if scratches else [False]
        if tmp.exists():
            err = delete_tree(tmp)
            print(f"temporary folder {tmp} " + ("deleted" if err is None else f"NOT deleted: {err}"))
    done = ok and all(deleted) and len(scratches) == 2
    print(f"\nablation: {'DONE' if done else 'FAILED'}")
    return 0 if done else 1


if __name__ == "__main__":
    sys.exit(main())
