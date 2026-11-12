"""Pure functions that compute a trial's time window (spec 02_gate 2.1, 2.2; decisions 026, 039, 040).

WHY this exists: the gate must clip each trial to its own run without reading the answer key
(ATK-12). The window is therefore computed from the trial's own logs: the Caldera agent process
tree (Sysmon 1 under C:\\Users\\Public\\splunkd.exe) plus the export span in data/manifest.csv,
which must overlap the window. Quarantined (decision 030), split-excluded (decision 019), clock-only
(decision 034) and clock-refused (spec 2.2 as amended in T6b.2, decision 043) trials get no window.

Time basis (T6b.2, decision 043): every row's time is corrected by its host's offset with the one shared
function ``clock_offset.correct.corrected_us`` before the agent tree is walked, so the edges are corrected
times. A raw-basis window (no offsets) exists only for the GTA-06 test. Nothing here opens a file except
``write_csv``, ``read_operator_times`` and ``load_clock_files``, which take explicit paths.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Collection, Iterable, Mapping, Sequence

from answer_key.agent_tree import TRIAL_GAP_S, agent_roots, run_start_ts
from answer_key.timeutil import fmt_utc, parse_utc
from clock_offset import changes as _co_changes
from clock_offset import params as _co_params
from clock_offset.correct import (ClockChanges, Offsets, co17_refusal, corrected_us, load_clock_changes, load_offsets,
                                  trial_clock_change_flag)
from gate.timeutil import fmt_us, to_us

from . import params

# WHY checked at import: params.py cannot import clock_offset (cycle), so it keeps copies; if they ever
# drift, the window would refuse or accept other trials than the clock step measures, or look for the
# offsets under another name.
if tuple(params.CLOCK_ONLY_TRIALS) != tuple(_co_params.CLOCK_ONLY_TRIALS):
    raise ImportError(f"CLOCK_ONLY_TRIALS {params.CLOCK_ONLY_TRIALS} disagrees with clock_offset.params "
                      f"{_co_params.CLOCK_ONLY_TRIALS}")
if params.OFFSETS_SUFFIX != _co_params.OFFSETS_SUFFIX or params.CLOCK_CHANGES_SUFFIX != _co_changes.CHANGES_SUFFIX:
    raise ImportError("offsets / clock-changes file suffixes disagree with clock_offset")


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


@dataclass(frozen=True)
class ClockFiles:
    """The trial's offsets and clock-changes files as the window step and the gate need them.

    ``offsets`` / ``changes`` are None when the file does not exist; the paths are kept so a refusal can
    name the missing file. WHY a holder and not two arguments: the refusal must tell "file missing" from
    "not checked yet" (None for the whole holder means not checked yet).
    """
    offsets_path: Path
    changes_path: Path
    offsets: Offsets | None
    changes: ClockChanges | None


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


def corrected_row(row: Mapping, offsets: Offsets) -> dict:
    """Copy of an event row whose ``t_utc``/``ts`` are its corrected time (spec 08 CO-09, spec 2.1).

    WHY rewrite ``t_utc`` and ``ts`` both: the agent-tree code (shared with the key builder) reads both,
    and it must see one consistent clock. ``t_utc`` becomes the ``...ffffffZ`` text of the corrected µs;
    ``ts`` is that instant in epoch seconds. A row without a time, or on a host whose offset is not
    applied (none/stale/unknown), keeps its instant (``corrected_us`` returns the raw one).
    """
    out = dict(row)
    if not row.get("t_utc"):
        return out
    us = corrected_us(to_us(row["t_utc"]), str(row.get("host")), offsets)
    out["t_utc"] = fmt_us(us)
    out["ts"] = us / 1_000_000
    return out


def corrected_rows(rows: Sequence[Mapping], offsets: Offsets) -> list[dict]:
    """Every row with its corrected time (``corrected_row``); the input rows are not changed."""
    return [corrected_row(r, offsets) for r in rows]


def edge_hosts(rows: Iterable[Mapping], result: WindowResult) -> tuple[str, str]:
    """(start_host, end_host): hosts of the events that set the window edges; "" for an operator window.

    WHY (spec 2.1, decision 043): the clip compares every event with edges taken on one host's clock; a
    consumer must know which host, so the gate can mark rows ``clock_unreliable`` when that clock is.
    """
    wanted = {u for u in (result.start_event_uid, result.end_event_uid) if u is not None}
    by_uid = {r["event_uid"]: r for r in rows if r.get("event_uid") in wanted}

    def host(uid: str | None) -> str:
        return str(by_uid[uid].get("host") or "") if uid in by_uid else ""

    return host(result.start_event_uid), host(result.end_event_uid)


def norm_host(value: object) -> str:
    """Host name as the DB and the offsets file write it (``dc01``, ``ep-01``): stripped, lower-case."""
    return str(value or "").strip().lower()


def _extreme(cands: Sequence[tuple[int, str]], latest: bool) -> tuple[int, str]:
    """Earliest (or latest) (µs, host); a tie between hosts goes to the alphabetically first host."""
    best = max(us for us, _ in cands) if latest else min(us for us, _ in cands)
    return best, min(h for us, h in cands if us == best)


def corrected_manifest_span(manifest_rows: Sequence[Mapping], offsets: Offsets) -> dict | None:
    """Export span on the corrected basis: each file's first/last time shifted by ITS host's offset, then
    min start / max end taken as instants (owner, T6b.2). None when there are no rows.

    WHY per host: the files' spans are each in their own host's raw clock; clipping corrected edges to a
    raw span would cut by the file host's offset (e.g. s04_t00 end, an ep-02 file, 1.66 s). A host whose
    offset is not applied (none/stale) or that the offsets file does not know stays raw (``corrected_us``);
    unknown hosts are listed in ``unmapped_hosts`` so they are reported, never silently treated as fine.
    ``start_host``/``end_host`` are the hosts of the files that set each end of the span.
    """
    if not manifest_rows:
        return None
    starts, ends, unmapped = [], [], set()
    for r in manifest_rows:
        host = norm_host(r.get("host"))
        if host not in offsets.hosts:
            unmapped.add(host)
        starts.append((corrected_us(to_us(r["first_event_utc"]), host, offsets), host))
        ends.append((corrected_us(to_us(r["last_event_utc"]), host, offsets), host))
    lo, lo_host = _extreme(starts, latest=False)
    hi, hi_host = _extreme(ends, latest=True)
    return {"start_utc": fmt_us(lo), "end_utc": fmt_us(hi), "source": "data/manifest.csv, corrected per host",
            "files": len(manifest_rows), "start_host": lo_host, "end_host": hi_host,
            "unmapped_hosts": sorted(unmapped)}


def raw_manifest_span_hosts(manifest_rows: Sequence[Mapping], span: Mapping | None) -> tuple[str, str]:
    """(start_host, end_host) of the files that set the raw span's ends ("" when there is no span).

    WHY: the raw span itself comes unchanged from ``read_manifest_span`` (GTA-06 must reproduce the
    baseline); only the edge hosts are added, so a manifest-clipped edge names the clock it came from.
    """
    if not span or not manifest_rows:
        return "", ""
    lo, hi = to_us(span["start_utc"]), to_us(span["end_utc"])
    starts = [(to_us(r["first_event_utc"]), norm_host(r.get("host"))) for r in manifest_rows]
    ends = [(to_us(r["last_event_utc"]), norm_host(r.get("host"))) for r in manifest_rows]
    return (min((h for us, h in starts if us == lo), default=""), min((h for us, h in ends if us == hi), default=""))


def window_edge_hosts(rows: Iterable[Mapping], result: WindowResult, span: Mapping | None) -> tuple[str, str]:
    """(start_host, end_host) of what set each final edge: the agent-tree event, or, when the manifest clip
    moved that edge, the host of the export file that set the span end (spec 2.1: the hosts of the events
    that set the window edges, i.e. whose clock the GT-01 clip compares against)."""
    start_host, end_host = edge_hosts(rows, result)
    if result.clipped_by_manifest_start and span:
        start_host = str(span.get("start_host") or "")
    if result.clipped_by_manifest_end and span:
        end_host = str(span.get("end_host") or "")
    return start_host, end_host


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


def id_refusal(trial_id: str, *, excluded_trials: Collection[str] = params.EXCLUDED_TRIALS,
               clock_only_trials: Collection[str] = params.CLOCK_ONLY_TRIALS) -> str | None:
    """Refusals decided by the trial id alone: quarantine (030), split exclusion (019), clock-only (034).

    WHY separate: they need no DB and no file, so a refused trial is never opened and never raises for a
    missing DB. Clock-only trials (s04_t01, s07_t01) were measured for the offset method only (spec 08
    COA-04) and are never windowed or gated, on either time basis.
    """
    if is_quarantined(trial_id):
        return f"quarantined trial id ({params.QUARANTINE_PREFIX}*, decision 030)"
    if trial_id.lower() in {t.lower() for t in excluded_trials}:
        return "excluded from the data split (decision 019: S01 t00 is target side only)"
    if trial_id.lower() in {t.lower() for t in clock_only_trials}:
        return ("clock-only trial: measured for the clock offset method only, never gated "
                "(decision 034, spec 08 COA-04)")
    return None


def clock_refusal(clock: ClockFiles, start_utc: str | None = None, db_sha256: str | None = None,
                  co17_date: date = params.RAW_TIME_CUTOFF_DATE) -> str | None:
    """Clock-file refusals of spec 2 / 2.2 (T6b.2, decision 043; spec 08 section 4.1 item 3), else None.

    In order: offsets file missing; clock-changes file missing; offsets ``db_sha256`` differs from the DB
    (only when ``db_sha256`` is given, i.e. once the DB is hashed); CO-17 on the window start (only when
    ``start_utc`` is given). WHY: corrected times are only meaningful with the offsets computed from this
    very DB, and on or after 2026-10-26 an uncorrected host may be up to 27 s wrong (decision 032).
    """
    if clock.offsets is None:
        return f"clock offsets file missing: {clock.offsets_path.name} (spec 08 section 3; run clock_offset first)"
    if clock.changes is None:
        return f"clock changes file missing: {clock.changes_path.name} (spec 08 section 3; run clock_offset first)"
    if db_sha256 is not None and clock.offsets.db_sha256.strip().lower() != db_sha256.strip().lower():
        return (f"offsets db_sha256 {clock.offsets.db_sha256} differs from the trial DB SHA-256 {db_sha256} "
                f"(offsets computed from another DB version)")
    if start_utc is not None:
        return co17_refusal(clock.offsets, to_us(start_utc), co17_date)
    return None


def refusal(trial_id: str, start_utc: str | None = None, *,
            excluded_trials: Collection[str] = params.EXCLUDED_TRIALS,
            clock_only_trials: Collection[str] = params.CLOCK_ONLY_TRIALS,
            clock: ClockFiles | None = None, db_sha256: str | None = None,
            co17_date: date = params.RAW_TIME_CUTOFF_DATE) -> str | None:
    """Reason text if the trial may not get a window (or be gated), else None (spec 2, 2.2; decisions 019,
    030, 034, 043).

    WHY one function for the window step and the gate: both must refuse exactly the same trials. The id
    checks always run; the clock-file checks run only when ``clock`` is given (None = not checked yet, e.g.
    before the DB is opened, or a raw-basis window for GTA-06). The t00-only and 2026-10-26 refusals of
    decision 039 are removed (T6b.2): the date now only enters through CO-17.
    """
    reason = id_refusal(trial_id, excluded_trials=excluded_trials, clock_only_trials=clock_only_trials)
    if reason or clock is None:
        return reason
    return clock_refusal(clock, start_utc, db_sha256, co17_date)


def offsets_path(repo: Path, trial_id: str) -> Path:
    """``data/processed/<trial>.clock_offsets.csv`` (spec 08 section 3), next to the DB."""
    return Path(repo) / params.PROCESSED_REL / f"{trial_id}{params.OFFSETS_SUFFIX}"


def clock_changes_path(repo: Path, trial_id: str) -> Path:
    """``data/processed/<trial>.clock_changes.csv`` (spec 08 section 3), next to the offsets file."""
    return Path(repo) / params.PROCESSED_REL / f"{trial_id}{params.CLOCK_CHANGES_SUFFIX}"


def load_clock_files(offsets_file: Path, changes_file: Path) -> ClockFiles:
    """Read the two clock files if they exist (a missing one is None, refused by ``clock_refusal``).

    A file that exists but cannot be parsed raises ValueError: that is wrong data, not a refusal.
    """
    o, c = Path(offsets_file), Path(changes_file)
    return ClockFiles(o, c, load_offsets(o) if o.is_file() else None,
                      load_clock_changes(c) if c.is_file() else None)


def clock_columns(clock: ClockFiles | None) -> dict[str, str]:
    """The four clock columns of the window row (spec 2.1, decision 043); all empty on the raw basis.

    ``clock_flag`` = hosts none/wide/stale with events, ``;``-joined (CO-08); ``clock_change_in_window``
    = ``true``/``false`` from the clock-changes classifications (CO-19 as amended).
    """
    if clock is None or clock.offsets is None or clock.changes is None:
        return {"offsets_sha256": "", "clock_changes_sha256": "", "clock_flag": "", "clock_change_in_window": ""}
    return {"offsets_sha256": clock.offsets.file_sha256, "clock_changes_sha256": clock.changes.file_sha256,
            "clock_flag": ";".join(clock.offsets.clock_flag),
            "clock_change_in_window": "true" if trial_clock_change_flag(clock.changes) else "false"}


def window_row(trial_id: str, result: WindowResult, window_source: str, rule: str, db_sha256: str,
               time_basis: str = params.TIME_BASIS, clock: Mapping[str, str] | None = None,
               start_host: str = "", end_host: str = "") -> dict:
    """One CSV row with exactly ``params.COLUMNS``; margins as integers (60, 300).

    ``clock`` is the output of ``clock_columns`` (None = the four clock columns empty, e.g. the raw basis).
    """
    row = {"trial_id": trial_id, "start_utc": result.start_utc, "end_utc": result.end_utc,
           "window_source": window_source, "margin_start_s": int(params.MARGIN_START_S),
           "margin_end_s": int(params.MARGIN_END_S), "rule": rule, "db_sha256": db_sha256,
           "time_basis": time_basis}
    row.update(clock_columns(None))
    row.update(clock or {})
    row.update({"start_host": start_host, "end_host": end_host})
    return row


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
