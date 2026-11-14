"""CLI: ``python -m gate --trial T [--db PATH] [--windows PATH] [--out DIR] [--repo PATH] [--offsets PATH]
[--clock-changes PATH]``; run from the repository root after ``pip install -e .`` (see README).

Writes ``out/gate/<trial_id>/`` (spec 02_gate section 3). Reads the trial DB read-only (view
``events_dedup``, hash before = after), the trial's row of ``data/trial_windows.csv`` and the trial's
``data/processed/<trial>.clock_offsets.csv`` / ``.clock_changes.csv`` (T6b.2, decision 043). A
refusal or input error exits 2 with the reason on stderr and writes nothing.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .inputs import GateError
from .params import PROCESSED_REL, WINDOWS_REL
from .run import REPO, run_gate


def default_db(repo: Path, trial: str) -> Path:
    """One DB per trial under data/processed (NF-09)."""
    return Path(repo) / PROCESSED_REL / f"{trial}.sqlite3"


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and run. Exit 0 on success, 2 on GateError (reason printed to stderr)."""
    ap = argparse.ArgumentParser(prog="gate", description=__doc__)
    ap.add_argument("--trial", required=True)
    ap.add_argument("--db", type=Path, default=None)
    ap.add_argument("--windows", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None, help="output root (default out/gate)")
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--offsets", type=Path, default=None,
                    help="clock offsets file (default data/processed/<trial>.clock_offsets.csv)")
    ap.add_argument("--clock-changes", type=Path, default=None,
                    help="clock changes file (default data/processed/<trial>.clock_changes.csv)")
    a = ap.parse_args(argv)
    repo = a.repo.resolve()
    db = a.db or default_db(repo, a.trial)
    windows = a.windows or repo / WINDOWS_REL
    out_root = a.out or repo / "out" / "gate"
    try:
        result = run_gate(a.trial, db, windows, out_root, repo=repo, offsets_csv=a.offsets,
                          changes_csv=a.clock_changes)
    except GateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    s = result["stats"]
    print(f"{a.trial}: {s['triggers']['total']} trigger row(s), {s['unmatched_remote']['total']} unmatched remote, "
          f"{s['supporting']['total']} supporting, {len(result['dispositions'])} disposition row(s)")
    print(f"wrote {result['out_dir']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
