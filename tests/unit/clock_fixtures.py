"""Shared synthetic clock files for the gate and trial_window tests (T6b.2, decision 043).

Written from docs/specs/08_clock_offset.md section 3 (file headers) and docs/specs/02_gate.md section 2 / 2.1, not
from the implementation. The header lists below are literal copies of the spec; a test in test_gate.py compares
them with the code's lists so a drift fails loudly.

Offsets are described as `{host: (offset_ms, status, host_has_events)}`. The default is ZERO offsets for dc01 (status
`reference`) and the three endpoints (status `ok`), every host with events, so a rule test written before the
correction keeps its meaning.
"""
from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from typing import Mapping, Sequence

OFFSETS_COLUMNS = [
    "trial_id", "host", "offset_ms", "offset_status", "offset_unc_ms", "n_pairs", "n_dropped_far",
    "n_pairs_lab_ip", "late_gap_s", "min_ms", "q1_ms", "median_ms", "q3_ms", "max_ms", "loo_shift_ms",
    "pair_span_s", "host_has_events", "method", "search_start_utc", "search_end_utc", "db_sha256", "tool_version",
]
CHANGES_COLUMNS = [
    "trial_id", "host", "channel", "event_id", "change_utc", "previous_time", "new_time", "shift_ms", "counted",
    "classification", "last_boot_before_utc", "source", "event_uid_or_record", "source_sha256",
]
PROCESSED = ("data", "processed")
OFFSETS_SUFFIX = ".clock_offsets.csv"
CHANGES_SUFFIX = ".clock_changes.csv"
HOSTS = ("dc01", "ep-01", "ep-02", "ep-03")

Spec = Mapping[str, tuple]


def default_offsets() -> dict[str, tuple]:
    """Zero offsets, every host with events."""
    return {"dc01": (0, "reference", True), "ep-01": (0, "ok", True), "ep-02": (0, "ok", True),
            "ep-03": (0, "ok", True)}


def offsets_spec(**overrides: tuple) -> dict[str, tuple]:
    """The default spec with some hosts replaced; keys use `_` for `-` (ep_02=(7000, "ok", True))."""
    spec = default_offsets()
    for key, value in overrides.items():
        spec[key.replace("_", "-")] = value
    return spec


def sha256_bytes(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def offsets_path(repo: Path, trial: str) -> Path:
    return Path(repo).joinpath(*PROCESSED, f"{trial}{OFFSETS_SUFFIX}")


def changes_path(repo: Path, trial: str) -> Path:
    return Path(repo).joinpath(*PROCESSED, f"{trial}{CHANGES_SUFFIX}")


def write_offsets(path: Path, trial: str, db_sha: str, spec: Spec | None = None) -> str:
    """Write an offsets file with the spec 08 section 3 header; returns the SHA-256 of the file."""
    spec = default_offsets() if spec is None else spec
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=OFFSETS_COLUMNS, lineterminator="\n")
        w.writeheader()
        for host, (offset_ms, status, has_events) in spec.items():
            row = dict.fromkeys(OFFSETS_COLUMNS, "")
            none_like = status in ("none", "stale") and offset_ms is None
            row.update(trial_id=trial, host=host, offset_ms="" if none_like or offset_ms is None else offset_ms,
                       offset_status=status, offset_unc_ms="" if none_like else 0,
                       host_has_events="true" if has_events else "false", db_sha256=db_sha,
                       method="synthetic", tool_version="clock_offset test")
            w.writerow(row)
    return sha256_bytes(path)


def change(trial: str, host: str, change_utc: str, *, previous_time: str | None = None,
           new_time: str | None = None, shift_ms: int | None = 8480, counted: bool = True,
           classification: str = "expected_before_first_pair", last_boot_before_utc: str | None = None,
           channel: str = "Security", event_id: int = 4616, source: str = "export") -> dict:
    """One clock_changes row (spec 08 section 3 / CO-15). `change_utc` is the recorded time of the change."""
    return {"trial_id": trial, "host": host, "channel": channel, "event_id": event_id, "change_utc": change_utc,
            "previous_time": previous_time or "", "new_time": new_time or "",
            "shift_ms": "" if shift_ms is None else shift_ms, "counted": "true" if counted else "false",
            "classification": classification, "last_boot_before_utc": last_boot_before_utc or "",
            "source": source, "event_uid_or_record": "synthetic-1", "source_sha256": ""}


def write_changes(path: Path, rows: Sequence[Mapping] | None = None) -> str:
    """Write a clock_changes file (header only by default); returns the SHA-256 of the file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CHANGES_COLUMNS, lineterminator="\n")
        w.writeheader()
        for r in rows or ():
            w.writerow(r)
    return sha256_bytes(path)


def write_clock_files(repo: Path, trial: str, db_sha: str, spec: Spec | None = None,
                      rows: Sequence[Mapping] | None = None) -> tuple[str, str]:
    """Both files next to the DB under data/processed; returns (offsets sha256, clock_changes sha256)."""
    return (write_offsets(offsets_path(repo, trial), trial, db_sha, spec),
            write_changes(changes_path(repo, trial), rows))
