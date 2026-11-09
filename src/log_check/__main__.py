"""CLI: python -m log_check --db <path> --trial <scenario_tNN> [--out] [--windows] [--keys]

Run from the repo root with PYTHONPATH=src. Writes out/log_check/<trial_id>/ only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .runner import LogCheckError, run_log_check

DEFAULT_WINDOWS = Path("docs/research/provisional_windows.csv")
DEFAULT_KEYS = Path("ground_truth/approved")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="log_check", description="Read-only log check of one trial DB (T4).")
    parser.add_argument("--db", required=True, type=Path, help="trial SQLite DB (opened read-only)")
    parser.add_argument("--trial", required=True, help="trial id, e.g. s04_t00")
    parser.add_argument("--out", type=Path, default=Path("out/log_check"), help="output root")
    parser.add_argument("--windows", type=Path, default=DEFAULT_WINDOWS, help="provisional window override CSV")
    parser.add_argument("--keys", type=Path, default=DEFAULT_KEYS, help="approved answer-key folder")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # Windows consoles are cp1252; never crash on ≥ or →
    try:
        out = run_log_check(args.db, args.trial, args.out, args.windows, args.keys)
    except LogCheckError as exc:
        print(f"log_check: {exc}", file=sys.stderr)
        return 2
    for name, check in out.report["checks"].items():
        print(f"{name:7} {check['status']:15} {check['summary']}")
    for path in out.files:
        print(f"wrote {path.as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
