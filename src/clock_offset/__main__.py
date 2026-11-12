"""CLI: ``python -m clock_offset [--trials T ...] [--repo PATH]`` (cwd=src).

Writes ``data/processed/<trial>.clock_offsets.csv``, ``data/processed/<trial>.clock_changes.csv`` and
``out/clock_offset/<trial>/`` (spec 08 section 3; owner D5, D6). Reads the trial DBs (read-only, hash
before = after), ``data/manifest.csv`` and, for the CO-19 scan, the decoded JSONL exports (read-only).
The export scan always runs: there is no ``--no-scan`` (review SF-3), because a scan-less
clock_changes.csv would look complete to the window step and the gate.
A missing DB for an allowed trial is a hard error (exit 2, nothing written); refused trials
(CO-01) are reported as REFUSED.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import params
from .run import REPO, ClockOffsetError, run
from .scan import summary_line


def report_lines(result: Mapping[str, Any]) -> list[str]:
    """One line per host row (status, offset, pairs), one CO-10 line per trial, one per refused trial."""
    lines = []
    for trial, rows in result["rows"].items():
        st = result["stats"][trial]
        for r in rows:
            lines.append(f"{trial}  {r['host']:<5}  {r['offset_status']:<9}  offset_ms={r['offset_ms']}  "
                         f"n_pairs={r['n_pairs']}  loo_shift_ms={r['loo_shift_ms']}  "
                         f"has_events={str(r['host_has_events']).lower()}")
        s = st["check"]["summary"]
        lines.append(f"{trial}  role={st['trial_role']}  clock_flag={st['clock_flag']}  CO-10: groups={s['groups']} "
                     f"pairs={s['pairs']} worst_raw_ms={s['worst_raw_abs_ms']} "
                     f"worst_corrected_ms={s['worst_corrected_abs_ms']} review={s['review_count']} "
                     f"kill={s['kill_count']} ambiguous={s['ambiguous_count']}")
        lines.append(summary_line(trial, st["clock_change_scan"]))
    for trial, reason in result["refused"].items():
        lines.append(f"{trial}  REFUSED: {reason}")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run, print the report. Exit 0 when the run finished, 2 on ClockOffsetError."""
    ap = argparse.ArgumentParser(prog="clock_offset", description=__doc__)
    ap.add_argument("--trials", nargs="+", default=list(params.DEFAULT_TRIALS))
    ap.add_argument("--repo", type=Path, default=REPO)
    a = ap.parse_args(argv)
    try:
        result = run(a.repo.resolve(), a.trials)
    except ClockOffsetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for line in report_lines(result):
        print(line)
    print(f"wrote {len(result['rows'])} offsets file(s); refused {len(result['refused'])}")
    incomplete = sorted(t for t, st in result["stats"].items() if st["clock_scan"] != "complete")
    if incomplete:
        print("warning: clock-change scan incomplete (clock_scan = incomplete; trial_window and the gate refuse "
              "these trials): " + ", ".join(incomplete))
    return 0


if __name__ == "__main__":
    sys.exit(main())
