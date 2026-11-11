"""Pure functions that compute a trial's time window (spec 02_gate 2.1, 2.2; decisions 026, 039, 040).

WHY this exists: the gate must clip each trial to its own run without reading the answer key
(ATK-12). The window is therefore computed from the trial's own logs: the Caldera agent process
tree (Sysmon 1 under C:\\Users\\Public\\splunkd.exe) plus the export span in data/manifest.csv,
which must overlap the window. Quarantined (decision 030), split-excluded (decision 019) and
clock-refused (decision 039) trials get no window. Nothing here opens a file except ``write_csv``
and ``read_operator_times``, which take explicit paths.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Collection, Iterable, Mapping, Sequence

from answer_key.agent_tree import TRIAL_GAP_S, agent_roots, run_start_ts
from answer_key.timeutil import fmt_utc, parse_utc

from . import params


class TrialWindowError(Exception):
    """Hard error that stops the run before any output is written (e.g. a needed trial DB is missing).

    WHY a hard error and not a skip: a missing DB for an allowed trial means the inputs are
    incomplete, and a window file silently lacking that trial would look like a valid result.
    """


@dataclass(frozen=True)
class WindowResult:
    """One trial window, with the events that set its edges so the window is traceable.

    ``raw_*`` are the edges before the manifest clip; ``clipped_by_manifest_*`` say which edge the
    export span moved. Edge uids are None for operator windows (no event sets them).
    """
    start_utc: str
    end_utc: str
    start_event_uid: str | None
    end_event_uid: str | None
    raw_start_utc: str
    raw_end_utc: str
    clipped_by_manifest_start: bool
    clipped_by_manifest_end: bool


def _is_sysmon1(row: Mapping) -> bool:
    """Only Sysmon 1 carries the ProcessGuid parent chain, so only Sysmon 1 builds the tree."""
    return row["channel"] == "Sysmon" and row["event_id"] == 1 and bool(row["process_guid"])


def _guid(value: str | None) -> str:
    """Guids are compared case-insensitively: Sysmon writes them in braces with varying case."""
    return (value or "").strip().lower()


def _fmt_ts(ts: float) -> str:
    """Epoch seconds to the ms ``...Z`` text; same conversion the key builder uses, so edges agree."""
    return fmt_utc(datetime.fromtimestamp(ts, tz=timezone.utc))


def _parse_ts(text: str) -> float:
    """ISO ``...Z`` text to epoch seconds (parsed instants, never compared as text)."""
    return parse_utc(text).timestamp()


def run_roots(rows: Sequence[Mapping], run_start: float) -> list[Mapping]:
    """Agent roots (splunkd children, by parent image or 4688 tie) of the latest run, sorted by time.

    WHY ``ts >= run_start``: older roots in the same DB belong to earlier runs or trials of the
    same day (decision 026); ``run_start_ts`` already walked back to the first root of this run.
    """
    seen: set[str] = set()
    out: list[Mapping] = []
    for row, _link in agent_roots(rows):
        if row["ts"] >= run_start and row["event_uid"] not in seen:
            seen.add(row["event_uid"])
            out.append(row)
    out.sort(key=lambda r: (r["ts"], r["event_uid"]))
    return out


def agent_tree(rows: Sequence[Mapping], run_start: float) -> dict[str, Mapping]:
    """guid -> Sysmon 1 row for the run roots and all their Sysmon 1 descendants at any depth.

    WHY a walk by ``parent_process_guid``: attack commands are grandchildren of splunkd
    (``powershell.exe`` -> ``cmd /c`` -> ``sc.exe``), so only following the guid chain finds the
    last command of the run. Rows outside the tree never set the window end.
    """
    by_parent: dict[str, list[Mapping]] = {}
    for row in rows:
        if _is_sysmon1(row):
            by_parent.setdefault(_guid(row["parent_process_guid"]), []).append(row)
    tree: dict[str, Mapping] = {}
    stack: list[Mapping] = list(run_roots(rows, run_start))
    while stack:
        row = stack.pop()
        guid = _guid(row["process_guid"])
        if guid in tree:
            continue
        tree[guid] = row
        stack.extend(by_parent.get(guid, []))
    return tree


def clip_to_manifest(lo: float, hi: float, manifest_span: Mapping | None) -> tuple[float, float, bool, bool]:
    """Clip (lo, hi) to the export span, only if they still overlap; return flags for each edge moved.

    WHY: the export files never held events outside their span, so edges beyond it are empty time.
    If the window and span do not overlap, the window is kept unclipped (same outer clip as the key
    builder) rather than collapsing to nothing.
    """
    if not manifest_span:
        return lo, hi, False, False
    m_lo = _parse_ts(manifest_span["start_utc"])
    m_hi = _parse_ts(manifest_span["end_utc"])
    if max(lo, m_lo) < min(hi, m_hi):
        return max(lo, m_lo), min(hi, m_hi), m_lo > lo, m_hi < hi
    return lo, hi, False, False


def manifest_coverage_reason(result: WindowResult, manifest_span: Mapping | None,
                             trial_id: str = "the trial") -> str | None:
    """Reason text if the export span cannot support the window, else None (owner 2026-11-12).

    WHY: the window must lie (at least partly) inside the time the export files cover. No span
    means the trial's exports are unknown; a span that misses the raw (unclipped) window means
    the window describes time with no exported events, so no row is written. A partial overlap
    is fine and is clipped (decision 026 amendment).
    """
    if not manifest_span:
        return f"no export span for {trial_id} in data/manifest.csv"
    m_lo, m_hi = _parse_ts(manifest_span["start_utc"]), _parse_ts(manifest_span["end_utc"])
    lo, hi = _parse_ts(result.raw_start_utc), _parse_ts(result.raw_end_utc)
    if max(lo, m_lo) < min(hi, m_hi):
        return None
    return (f"manifest export span {manifest_span['start_utc']}..{manifest_span['end_utc']} does not overlap "
            f"the computed window {result.raw_start_utc}..{result.raw_end_utc}")


def _result(lo: float, hi: float, manifest_span: Mapping | None,
            start_uid: str | None, end_uid: str | None) -> WindowResult:
    """Apply the manifest clip and package the edges with their provenance."""
    c_lo, c_hi, by_start, by_end = clip_to_manifest(lo, hi, manifest_span)
    return WindowResult(_fmt_ts(c_lo), _fmt_ts(c_hi), start_uid, end_uid, _fmt_ts(lo), _fmt_ts(hi), by_start, by_end)


def computed_window(rows: Sequence[Mapping], manifest_span: Mapping | None,
                    margin_start_s: float = params.MARGIN_START_S,
                    margin_end_s: float = params.MARGIN_END_S) -> WindowResult | None:
    """Window of the agent run: first run root - 60 s .. last Sysmon 1 in the agent tree + 300 s.

    WHY: these are the only events that prove the agent was acting (decision 040); the margins
    leave room for target-side events logged just before the first root or after the last command.
    Returns None when the DB holds no agent root (no agent activity, e.g. S01).
    """
    run_start = run_start_ts(rows, TRIAL_GAP_S)
    if run_start is None:
        return None
    roots = run_roots(rows, run_start)
    tree = agent_tree(rows, run_start)
    timed = [r for r in tree.values() if r["t_utc"]]
    last = max(timed, key=lambda r: (r["ts"], r["event_uid"]))
    return _result(run_start - margin_start_s, last["ts"] + margin_end_s, manifest_span,
                   roots[0]["event_uid"], last["event_uid"])


def operator_window(start_utc: str, end_utc: str, manifest_span: Mapping | None,
                    margin_start_s: float = params.MARGIN_START_S,
                    margin_end_s: float = params.MARGIN_END_S) -> WindowResult:
    """Window from the operator's recorded start/end (trials with no agent, S01), same margins and clip."""
    return _result(_parse_ts(start_utc) - margin_start_s, _parse_ts(end_utc) + margin_end_s,
                   manifest_span, None, None)


def _repo_parts(db_path: Path, repo: Path | None) -> tuple[str, ...]:
    """Path parts below the repo, so a repo that itself lives under a folder named ``quarantine``
    is not refused; a path outside the repo (or no repo given) is judged on all its parts."""
    path = Path(db_path)
    if repo is not None:
        try:
            return path.resolve().relative_to(Path(repo).resolve()).parts
        except ValueError:
            pass
    return path.parts


def is_quarantined(trial_id: str, db_path: Path | None = None, repo: Path | None = None) -> bool:
    """Quarantined trials (decision 030) are refused by id prefix or by a ``quarantine/`` path part
    below the repo."""
    if trial_id.lower().startswith(params.QUARANTINE_PREFIX):
        return True
    if db_path is None:
        return False
    return params.QUARANTINE_DIR in (p.lower() for p in _repo_parts(db_path, repo))


def refusal(trial_id: str, start_utc: str | None, *,
            excluded_trials: Collection[str] = params.EXCLUDED_TRIALS,
            clock_correction_available: bool = params.CLOCK_CORRECTION_AVAILABLE,
            raw_time_cutoff_date: date = params.RAW_TIME_CUTOFF_DATE) -> str | None:
    """Reason text if the trial may not get a window, else None (spec 2.2; decisions 019, 030, 039).

    WHY: quarantined (030) and split-excluded (019) trials never get a window, whatever the
    clock. Until decision 032's clock correction exists, raw-time windows are only trusted on t00
    trials collected before ep-01 drifted (2026-10-26); the date is taken from the window start.
    ``start_utc`` may be None to run only the checks that need no window (before opening a DB).
    """
    if is_quarantined(trial_id):
        return f"quarantined trial id ({params.QUARANTINE_PREFIX}*, decision 030)"
    if trial_id.lower() in {t.lower() for t in excluded_trials}:
        return "excluded from the data split (decision 019: S01 t00 is target side only)"
    if clock_correction_available:
        return None
    trial_part = trial_id.split("_", 1)[1] if "_" in trial_id else ""
    if trial_part != "t00":
        return "clock correction not available: only t00 trials are allowed (spec 2.2, decision 039)"
    if start_utc is not None and parse_utc(start_utc).date() >= raw_time_cutoff_date:
        return (f"clock correction not available: window start {start_utc} is on or after "
                f"{raw_time_cutoff_date.isoformat()} (decision 032)")
    return None


def window_row(trial_id: str, result: WindowResult, window_source: str, rule: str, db_sha256: str,
               time_basis: str = params.TIME_BASIS) -> dict:
    """One CSV row with exactly ``params.COLUMNS``; margins as integers (60, 300)."""
    return {"trial_id": trial_id, "start_utc": result.start_utc, "end_utc": result.end_utc,
            "window_source": window_source, "margin_start_s": int(params.MARGIN_START_S),
            "margin_end_s": int(params.MARGIN_END_S), "rule": rule, "db_sha256": db_sha256,
            "time_basis": time_basis}


def write_csv(rows: Iterable[Mapping], path: Path) -> None:
    """Write rows sorted by trial_id, UTF-8 without BOM, ``\\n`` endings, so reruns are byte-identical."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(rows, key=lambda r: r["trial_id"])
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(params.COLUMNS), lineterminator="\n", extrasaction="raise")
        w.writeheader()
        for row in ordered:
            w.writerow({k: row[k] for k in params.COLUMNS})


def read_operator_times(path: Path) -> dict[str, tuple[str, str]]:
    """trial_id -> (start_utc, end_utc) from the optional operator file; {} if it does not exist.

    WHY optional: only trials without agent activity (S01) need it, and it is not written yet.
    Rows with an empty start or end are ignored (the gate refuses empty edges, spec 2).
    """
    path = Path(path)
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return {r["trial_id"].strip(): (r["start_utc"].strip(), r["end_utc"].strip())
                for r in csv.DictReader(fh)
                if (r.get("trial_id") or "").strip() and (r.get("start_utc") or "").strip()
                and (r.get("end_utc") or "").strip()}
