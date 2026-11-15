"""Command line: python -m data_layout.cli {map,copy,manifest,batch,archive-v1,archive-verify,retire-failed} ...
(PYTHONPATH=src)."""
from __future__ import annotations

import argparse
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional, Sequence

from data_layout import archive, batch
from data_layout import layout as L


def _cmd_map(a: argparse.Namespace) -> int:
    scen = None
    if a.scenario_from == "arg":
        if not a.scenario:
            print("error: --scenario-from arg requires --scenario s0N", file=sys.stderr)
            return 2
        scen = a.scenario.lower()
    ov = L.read_overrides(Path(a.overrides)) if a.overrides else {}
    try:
        rows = L.build_mapping(Path(a.source), a.trial, scen, ov)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    L.write_rows(Path(a.out), L.MAP_COLUMNS, (asdict(r) for r in rows))
    n_copy = sum(r.action == "copy" for r in rows)
    print(f"{len(rows)} files: {n_copy} copy, {len(rows) - n_copy} ignore -> {a.out}")
    return 0


def _cmd_copy(a: argparse.Namespace) -> int:
    rows = L.read_mapping(Path(a.mapping))
    copied, ignored, errors = L.copy_all(Path(a.source), rows, Path(a.raw_root))
    print(f"copied={copied} ignored={ignored} errors={len(errors)}")
    for e in errors:
        print(f"ERROR {e}", file=sys.stderr)
    return 1 if errors else 0


def _cmd_manifest(a: argparse.Namespace) -> int:
    rows = L.read_mapping(Path(a.mapping))
    added, skipped = L.append_manifest(Path(a.raw_root), rows, Path(a.out))
    print(f"manifest {a.out}: added={added} already_listed={skipped}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="data_layout.cli",
        description="Put EVTX files into data/raw/<scenario>/<trial>/<host>/<channel>.evtx")
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("map", help="write a mapping CSV (read-only on SOURCE)")
    m.add_argument("--source", required=True)
    m.add_argument("--scenario-from", choices=["folder", "arg"], default="folder")
    m.add_argument("--scenario", help="s0N, used when --scenario-from arg")
    m.add_argument("--trial", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--overrides", help="CSV: source_path,action,reason[,dest_path]")
    m.set_defaults(fn=_cmd_map)
    c = sub.add_parser("copy", help="copy action=copy rows into raw-root (never overwrites)")
    c.add_argument("--source", required=True)
    c.add_argument("--mapping", required=True)
    c.add_argument("--raw-root", required=True)
    c.set_defaults(fn=_cmd_copy)
    f = sub.add_parser("manifest", help="append new files to the manifest (idempotent)")
    f.add_argument("--raw-root", required=True)
    f.add_argument("--mapping", required=True)
    f.add_argument("--out", required=True)
    f.set_defaults(fn=_cmd_manifest)
    b = sub.add_parser("batch", help="batch ingest (--source x10 | x10_v2): incoming -> raw -> manifest -> JSONL -> SQLite")
    batch.add_arguments(b)
    b.set_defaults(fn=batch.run)
    add_archive_commands(sub)
    return p


def positive_int(text: str) -> int:
    """argparse type for --attempt: a positive integer, nothing else (no sign tricks, no path text)."""
    if not text.isascii() or not text.isdigit() or int(text) < 1:
        raise argparse.ArgumentTypeError(f"must be a positive integer, got {text!r}")
    return int(text)


def _repo_default() -> Path:
    return Path(__file__).resolve().parents[2]


def _cmd_archive_v1(a: argparse.Namespace) -> int:
    return archive.run_spec(a.repo, archive.V1, a.execute)


def _cmd_archive_verify(a: argparse.Namespace) -> int:
    """Verify V1, or one failed attempt when --scenario, --trial and --attempt are all given."""
    given = [a.scenario, a.trial, a.attempt]
    if any(x is not None for x in given) and not all(x is not None for x in given):
        print("error: --scenario, --trial and --attempt must be given together", file=sys.stderr)
        return 2
    try:
        spec = archive.V1 if a.attempt is None else archive.failed_attempt_spec(a.scenario, a.trial, a.attempt)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return archive.run_verify(a.repo, spec)


def _cmd_retire_failed(a: argparse.Namespace) -> int:
    try:
        spec = archive.failed_attempt_spec(a.scenario, a.trial, a.attempt)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return archive.run_spec(a.repo, spec, a.execute)


def add_archive_commands(sub: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """archive-v1, archive-verify and retire-failed (all dry-run by default; --execute moves files)."""
    v = sub.add_parser("archive-v1", help="archive the old S04/S07 t01-t10 copies (dry run unless --execute)")
    v.add_argument("--repo", type=Path, default=_repo_default())
    v.add_argument("--execute", action="store_true", help="really copy, record and delete (default: dry run)")
    v.set_defaults(fn=_cmd_archive_v1)
    c = sub.add_parser("archive-verify", help="re-hash the archive from its journal (read-only)")
    c.add_argument("--repo", type=Path, default=_repo_default())
    c.add_argument("--scenario", help="with --trial and --attempt: verify one retired failed attempt")
    c.add_argument("--trial")
    c.add_argument("--attempt", type=positive_int)
    c.set_defaults(fn=_cmd_archive_verify)
    r = sub.add_parser("retire-failed", help="move the ingested copies of a failed x10_v2 attempt off the normal "
                                             "paths (dry run unless --execute)")
    r.add_argument("--repo", type=Path, default=_repo_default())
    r.add_argument("--scenario", required=True)
    r.add_argument("--trial", required=True)
    r.add_argument("--attempt", required=True, type=positive_int)
    r.add_argument("--execute", action="store_true", help="really copy, record and delete (default: dry run)")
    r.set_defaults(fn=_cmd_retire_failed)


def main(argv: Optional[Sequence[str]] = None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
