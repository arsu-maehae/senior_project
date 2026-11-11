"""Export span of a trial's host files, read from data/manifest.csv (decision 026 amendment).

WHY here: both the draft key builder and the trial window step clip to the same export span;
one shared reader keeps them identical and lets the window step avoid importing the key
builder's command-line module (decision 041, spec 02_gate GTT-14).
"""
from __future__ import annotations

import csv
from pathlib import Path


def read_manifest_span(repo: Path, trial: str) -> dict | None:
    """Min first / max last event time over the trial's host files in data/manifest.csv (export spans)."""
    p = repo / "data" / "manifest.csv"
    if not p.exists():
        return None
    scenario, tr = trial.split("_", 1)
    with open(p, newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r["scenario"] == scenario and r["trial"] == tr
                and r.get("first_event_utc") and r.get("last_event_utc")]
    if not rows:
        return None
    return {"start_utc": min(r["first_event_utc"] for r in rows), "end_utc": max(r["last_event_utc"] for r in rows),
            "source": "data/manifest.csv", "files": len(rows)}
