"""Stitch stage CLI: ``python -m stitch --trial <id> [--repo PATH] [--out PATH]``; run from the repository root
after ``pip install -e .`` (see README).

Runs ``links.run_links_checked`` (ST-00 with the development allowlist first, decision 046; every spec 2 refusal;
then one read-only hash bracket around the scan, the command facts and the assembly), builds the T7.5 paths,
nodes and notes (``nodes.build_path_outputs``, pure) and writes every file of spec 03_stitch section 3 to
``out/stitch/<trial_id>/``, or to the folder given with ``--out`` (decision 054; mirrors ``python -m evaluate --out``):

- ``links.csv``, ``hop_artefacts.csv``, ``hop_identity.csv`` (T7.4) and ``hops.csv``, ``paths.csv``,
  ``path_edges.csv``, ``path_nodes.csv`` (T7.5): text from ``stitch.outputs``, pure;
- ``stats.json`` and ``report.md`` (``stitch.report``, pure; no timestamp, so byte-identical between runs);
- ``run_info.json``: tool version, trial id, parameters, DB path and SHA-256 before / after, gate stats SHA-256,
  window summary, and every other file written with its SHA-256 and row count (data rows for a CSV; ``null`` for
  ``stats.json`` and ``report.md``, which are not tables). It is the only file with a timestamp
  (``generated_utc``), because spec 3 exempts it from byte-identity.

A run replaces the whole folder with these ten files. A ``--out`` folder is checked after ST-00 and before anything
is written (``outdir.check_out_target``): inside the repository it must lie below ``out/``, and an existing folder
may hold only these ten names, because the swap below deletes the old folder (the default folder is rebuilt
whatever it holds, spec 3). The bytes of every file except
``run_info.json`` do not depend on the folder.

WHY build everything first and write last: on any refusal nothing may be written and an existing folder must stay
untouched (spec 2), so the texts are complete before the disk is touched. WHY a temporary sibling folder and two
renames: the spec says the folder is rebuilt on every run, and a reader must never see a mix of old and new files
or a half-written file. ``out/stitch/.<trial>.tmp`` is filled, the old folder is renamed to ``.<trial>.old``, the
new one renamed in, and the old one deleted. A DB whose SHA-256 after the read differs from before is refused
too (spec 2, ``check_db_unchanged``). A refusal prints ``refused: <reason>`` to stderr and exits 2.

Ablation (spec 06 AB-01, AB-05, AB-06): ``--disable-method cmdline_target`` switches off every use of command-line
evidence (``StitchParams.disabled_methods``); no other name is accepted. It is refused when ``--repo`` (or ``--out``)
resolves into the real repository, so an ablated stitch output can only exist in a scratch repo. The disabled set
is written to run_info.json and stats.json (top-level ``disabled_methods`` and in ``parameters``) only when
non-empty, so a default run is byte-identical to the pre-ablation code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from gate.run import display_path

from .check_index import REPO, _reason, window_summary
from .errors import StitchError
from .index import jsonable, params_dict
from .inputs import CheckedInputs, TrialPaths
from .links import LinkIndex, run_links_checked
from .nodes import PathNode, build_path_outputs
from .outdir import check_out_target
from .outputs import (ARTEFACT_COLUMNS, ARTEFACT_FILE, EDGES_COLUMNS, EDGES_FILE, HOPS_COLUMNS, HOPS_FILE,
                      IDENTITY_COLUMNS, IDENTITY_FILE, LINKS_COLUMNS, LINKS_FILE, NODES_COLUMNS, NODES_FILE,
                      PATHS_COLUMNS, PATHS_FILE, artefact_rows, csv_text, edge_rows, hop_rows, identity_rows,
                      link_rows, node_rows, path_rows)
from .params import DISABLEABLE_METHODS, STITCH_OUT_REL, TOOL_VERSION, StitchParams
from .paths import PathSet
from .report import disabled_block, report_md, stats_dict

__all__ = ["RUN_INFO_FILE", "STATS_FILE", "REPORT_FILE", "OUTPUT_FILES", "check_db_unchanged", "csv_files",
           "path_csv_files", "file_facts", "run_info", "run_info_text", "json_text", "build_files", "out_dir",
           "replace_folder", "is_under", "disable_refusal", "main"]

RUN_INFO_FILE = "run_info.json"
STATS_FILE, REPORT_FILE = "stats.json", "report.md"
# The ten files of spec 3, sorted: the only names an existing ``--out`` folder may hold (decision 054).
OUTPUT_FILES: tuple[str, ...] = tuple(sorted((LINKS_FILE, ARTEFACT_FILE, IDENTITY_FILE, HOPS_FILE, PATHS_FILE,
                                              EDGES_FILE, NODES_FILE, STATS_FILE, REPORT_FILE, RUN_INFO_FILE)))


def csv_files(li: LinkIndex) -> dict[str, tuple[str, int]]:
    """File name -> (CSV text, data row count) of the three T7.4 CSVs. Pure."""
    out: dict[str, tuple[str, int]] = {}
    for name, columns, rows in ((LINKS_FILE, LINKS_COLUMNS, link_rows(li)),
                                (ARTEFACT_FILE, ARTEFACT_COLUMNS, artefact_rows(li)),
                                (IDENTITY_FILE, IDENTITY_COLUMNS, identity_rows(li))):
        out[name] = (csv_text(columns, rows), len(rows))
    return out


def path_csv_files(li: LinkIndex, pathset: PathSet, nodes: Sequence[PathNode]) -> dict[str, tuple[str, int]]:
    """File name -> (CSV text, data row count) of the four T7.5 CSVs. Pure. ``pathset`` carries the notes."""
    out: dict[str, tuple[str, int]] = {}
    for name, columns, rows in ((HOPS_FILE, HOPS_COLUMNS, hop_rows(li, pathset)),
                                (PATHS_FILE, PATHS_COLUMNS, path_rows(pathset)),
                                (EDGES_FILE, EDGES_COLUMNS, edge_rows(li, pathset)),
                                (NODES_FILE, NODES_COLUMNS, node_rows(nodes))):
        out[name] = (csv_text(columns, rows), len(rows))
    return out


def file_facts(files: Mapping[str, tuple[str, int | None]]) -> dict[str, dict[str, Any]]:
    """File name -> {sha256 of its UTF-8 bytes, rows}. WHY the hash of the exact bytes written: a reader can check
    the folder against run_info.json, and two runs can be compared without opening the CSVs. ``rows`` is None
    for a file that is not a table (``stats.json``, ``report.md``)."""
    return {name: {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "rows": n}
            for name, (text, n) in sorted(files.items())}


def check_db_unchanged(sha_before: str, sha_after: str) -> None:
    """Spec 2: the DB's SHA-256 before the read must equal the SHA-256 after it. Raises StitchError otherwise.

    WHY refuse and not only record: the outputs must describe exactly the DB the gate read; a DB that changed
    during the run means the rows may mix two states, so nothing may be written (spec 2 refusal rule). Pure.
    """
    if sha_before != sha_after:
        raise StitchError(f"refused: DB SHA-256 changed during the run (before {sha_before!r}, "
                          f"after {sha_after!r})")


def run_info(trial_id: str, params: StitchParams, db_display: str, sha_before: str, sha_after: str,
             checked: CheckedInputs, files: Mapping[str, tuple[str, int | None]], generated_utc: str
             ) -> dict[str, Any]:
    """The run_info.json dict (JSON-ready, keys sorted). Pure: the timestamp is an argument, so a test can fix it.
    The window is the summary of ``check_index.window_summary`` (its ``rule`` text names an image and is left
    out, as in the check files)."""
    return jsonable({
        **disabled_block(params),              # spec 06 AB-05: only an ablation run has this key
        "tool_version": TOOL_VERSION,
        "trial_id": trial_id,
        "generated_utc": generated_utc,
        "parameters": params_dict(params),
        "db": {"path": db_display, "sha256_before": sha_before, "sha256_after": sha_after},
        "gate_stats_sha256": checked.gate_stats_sha256,
        "window": window_summary(checked.window_row),
        "files": file_facts(files),
    })


def json_text(data: Mapping[str, Any]) -> str:
    """Sorted keys, indent 1, one trailing newline (the check files' JSON style). WHY one function: run_info.json
    and stats.json must be spelled the same way, and sorted keys keep stats.json byte-identical between runs."""
    return json.dumps(data, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def run_info_text(info: Mapping[str, Any]) -> str:
    """The run_info.json text (``json_text``)."""
    return json_text(info)


def build_files(repo: Path, li: LinkIndex, checked: CheckedInputs, paths: TrialPaths, sha_before: str,
                sha_after: str, params: StitchParams, generated_utc: str) -> dict[str, str]:
    """File name -> exact text of every file of the folder. Pure (no disk access); ``repo`` only shapes the DB
    display path, so the bytes do not depend on where the repo lives.

    Order: the T7.4 CSVs (unchanged text), the T7.5 paths / nodes / notes and their CSVs, ``stats.json`` (row
    counts of the seven CSVs), ``report.md``, then ``run_info.json`` listing every other file. WHY the T7.4 CSVs
    from the same ``csv_files`` as before: T7.5 must not change their bytes (decision 050 consequences).
    """
    csvs = csv_files(li)
    pathset, nodes = build_path_outputs(li, params)
    csvs.update(path_csv_files(li, pathset, nodes))
    stats = stats_dict(li, pathset, nodes, {name: n for name, (_t, n) in csvs.items()}, params, sha_before,
                       sha_after)
    files: dict[str, tuple[str, int | None]] = dict(csvs)
    files[STATS_FILE] = (json_text(stats), None)
    files[REPORT_FILE] = (report_md(stats, li, pathset), None)
    info = run_info(li.trial_id, params, display_path(paths.db, repo), sha_before, sha_after, checked, files,
                    generated_utc)
    out = {name: text for name, (text, _n) in files.items()}
    out[RUN_INFO_FILE] = run_info_text(info)
    return out


def out_dir(repo: Path, trial_id: str) -> Path:
    """``out/stitch/<trial_id>`` under the repo (spec 3 location)."""
    return Path(repo) / STITCH_OUT_REL / trial_id


def _remove(path: Path) -> None:
    """Delete a leftover folder or file of an earlier interrupted run (ours by name only)."""
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def replace_folder(target: Path, files: Mapping[str, str]) -> None:
    """Write ``files`` into a fresh ``.<name>.tmp`` sibling, then swap it in for ``target``.

    Steps: remove leftovers of an interrupted run (``.tmp``, ``.old``); write every file (UTF-8, ``\\n``); rename
    the existing ``target`` to ``.<name>.old``; rename the new folder to ``target``; delete ``.old``. If the
    second rename fails the old folder is renamed back, so ``target`` is never left missing by this function.
    """
    target = Path(target)
    parent = target.parent
    tmp = parent / f".{target.name}.tmp"
    old = parent / f".{target.name}.old"
    parent.mkdir(parents=True, exist_ok=True)
    _remove(tmp)
    _remove(old)
    tmp.mkdir()
    for name, text in sorted(files.items()):
        with open(tmp / name, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    had_old = target.exists()
    if had_old:
        target.rename(old)
    try:
        tmp.rename(target)
    except OSError:
        if had_old:
            old.rename(target)
        raise
    if had_old:
        shutil.rmtree(old)


def is_under(path: Path | str, root: Path | str) -> bool:
    """True iff ``path`` equals or lies under ``root`` after ``os.path.realpath`` (links and junctions resolved;
    case-insensitive on Windows). The same test as ``run_trial.checks.is_under``, kept here so the stage does not
    import the runner."""
    a = os.path.normcase(os.path.realpath(path))
    b = os.path.normcase(os.path.realpath(root))
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def disable_refusal(disabled: Sequence[str], repo: Path, out: Path | None, real_repo: Path = REPO,
                    trial: str | None = None) -> str | None:
    """Spec 06 AB-01 / AB-06: the refusal text for ``--disable-method``, or None.

    Refused: any name outside ``DISABLEABLE_METHODS``; and, when any method is disabled, a ``--repo`` that is or lies
    inside the real repository, whose ``out/`` or ``data/`` resolves into it, or a ``--out`` that resolves into it.
    ATK-EV-42: the real write targets are resolved too: ``<repo>/out/stitch`` and, with ``trial``,
    ``<repo>/out/stitch/<trial>`` (a junction or link there would otherwise write the real folder). Resolving a
    path opens no file, so this may run before the allowlist. WHY: an ablated stitch folder in the committed ``out/`` would feed label, score and evaluate as if it were the
    default run; only a scratch repo may hold one. Pure apart from resolving links."""
    bad = sorted(set(disabled) - set(DISABLEABLE_METHODS))
    if bad:
        return (f"--disable-method accepts only {', '.join(DISABLEABLE_METHODS)} (spec 06 AB-01); got "
                f"{', '.join(bad)}")
    if not disabled:
        return None
    targets = [repo, repo / "out", repo / "data", repo / STITCH_OUT_REL]
    if trial:
        targets.append(repo / STITCH_OUT_REL / trial)
    hits = [str(x) for x in targets if is_under(x, real_repo)]
    if out is not None and is_under(out, real_repo):
        hits.append(f"--out {out}")
    if hits:
        return ("--disable-method runs only in a scratch repository outside the real repository (spec 06 AB-06); "
                "resolved into the real repository: " + "; ".join(hits))
    return None


def _utc_now() -> str:
    """Current UTC instant for run_info.json only (never in a CSV)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run, write. Exit 0 on success (prints the folder), 2 on a refusal (reason on stderr,
    nothing written, an existing folder left untouched). ``--out`` replaces the default ``out/stitch/<trial>``
    folder (decision 054); it is checked only after ST-00, so a refused trial id still touches no file (046)."""
    ap = argparse.ArgumentParser(prog="stitch", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trial", required=True)
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--out", type=Path, default=None,
                    help="output folder (default out/stitch/<trial>); replaced whole on every run")
    ap.add_argument("--disable-method", action="append", default=[], metavar="METHOD",
                    help="ablation only (spec 06 AB-01): switch off a source method; only cmdline_target is "
                         "accepted, and only in a scratch repo outside the real repository (AB-06)")
    a = ap.parse_args(argv)
    repo = a.repo.resolve()
    refusal = disable_refusal(a.disable_method, repo, None if a.out is None else a.out.resolve(), trial=a.trial)
    if refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 2
    params = StitchParams(disabled_methods=frozenset(a.disable_method))
    try:
        li, checked, paths, before, after = run_links_checked(repo, a.trial, params)
        check_db_unchanged(before, after)
        target = out_dir(repo, a.trial)
        if a.out is not None:                  # decision 054: the default folder is rebuilt as before (spec 3)
            target = a.out.resolve()
            check_out_target(target, repo, OUTPUT_FILES)
    except StitchError as exc:
        print(f"refused: {_reason(exc)}", file=sys.stderr)
        return 2
    files = build_files(repo, li, checked, paths, before, after, params, _utc_now())
    replace_folder(target, files)
    print(display_path(target, repo))
    return 0


if __name__ == "__main__":
    sys.exit(main())
