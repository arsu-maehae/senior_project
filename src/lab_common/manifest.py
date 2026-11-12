"""Export span of a trial's host files, read from data/manifest.csv (decision 026 amendment).

WHY here: both the draft key builder and the trial window step clip to the same export span;
one shared reader keeps them identical and lets the window step avoid importing the key
builder's command-line module (decision 041, spec 02_gate GTT-14). Standard library only.
"""
from __future__ import annotations

import csv
from pathlib import Path


def read_manifest_rows(repo: Path, trial: str) -> list[dict]:
    """The trial's rows of data/manifest.csv that have both a first and a last event time ([] if none).

    WHY the rows and not only the span: on the corrected time basis each file's span must be shifted by
    its own host's clock offset before the min/max is taken (owner, T6b.2), so the window step needs
    the host of every file. The rows are returned as read (all values text, file order).
    """
    p = Path(repo) / "data" / "manifest.csv"
    if not p.exists():
        return []
    scenario, tr = trial.split("_", 1)
    with open(p, newline="", encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh) if r["scenario"] == scenario and r["trial"] == tr
                and r.get("first_event_utc") and r.get("last_event_utc")]


def read_manifest_span(repo: Path, trial: str) -> dict | None:
    """Min first / max last event time over the trial's host files in data/manifest.csv (export spans).

    Raw logged times, compared as the manifest's text (one fixed ``...ffffffZ`` format); used by the key
    builder, the clock offset step and the raw-basis window, so its behaviour must not change.
    """
    rows = read_manifest_rows(repo, trial)
    if not rows:
        return None
    return {"start_utc": min(r["first_event_utc"] for r in rows), "end_utc": max(r["last_event_utc"] for r in rows),
            "source": "data/manifest.csv", "files": len(rows)}
