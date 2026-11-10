"""Command line: python -m data_layout.cli {map,copy,manifest,batch} ... (PYTHONPATH=src)."""
from __future__ import annotations

import argparse
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional, Sequence

from data_layout import batch
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
    b = sub.add_parser("batch", help="x10 batch ingest: incoming -> raw -> manifest -> JSONL -> SQLite")
    batch.add_arguments(b)
    b.set_defaults(fn=batch.run)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
