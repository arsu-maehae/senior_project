"""Run the clock offset step on trials: CO-01 refusals, raw agent window, pairing, estimate, CO-10, outputs.

WHY compute every trial in memory before writing: a missing DB for an allowed trial is a hard
error before anything is written, and a failure in one trial must not leave a half-written set of
offsets files. The DB is opened read-only through ``answer_key.db.guarded`` (hash before = after);
the answer-key folder is never opened.

The CO-19 export scan (scan.py) runs as part of the step (``scan=True``, owner D6). It reads the decoded
exports and the JSONL lines of DB clock-change rows, both read-only, and its files are written together
with the offsets, so a rerun never deletes them (``write_outputs`` empties the folder first).
"""
from __future__ import annotations

import hashlib
import platform
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from answer_key import db
from gate.timeutil import US_PER_MS, to_us
from lab_common.manifest import read_manifest_span
from trial_window.window import WindowResult, computed_window, is_quarantined, manifest_coverage_reason

from . import changes as ch
from . import check, estimate, outputs, params
from . import scan as co19  # CO-19 scan; ``scan`` is the run() flag name (owner D6)
from .correct import co17_refusal, offsets_from_rows
from .common import s_to_us, us_to_s
from .pairs import HostPairs, pair_trial

REPO = Path(__file__).resolve().parents[2]
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class ClockOffsetError(Exception):
    """Hard error that stops the run before any output is written (missing DB, event without a time).

    WHY not a skip: an allowed trial without its DB means the inputs are incomplete; an offsets set
    silently lacking that trial would look like a valid result.
    """


# ---------------------------------------------------------------- paths and roles

def db_path(repo: Path, trial: str) -> Path:
    """Trial DB location: one DB per trial under data/processed (NF-09)."""
    return Path(repo) / params.PROCESSED_REL / f"{trial}.sqlite3"


def offsets_path(repo: Path, trial: str) -> Path:
    """``data/processed/<trial>.clock_offsets.csv``, next to the DB as decision 032 asks."""
    return Path(repo) / params.PROCESSED_REL / f"{trial}{params.OFFSETS_SUFFIX}"


def changes_path(repo: Path, trial: str) -> Path:
    """``data/processed/<trial>.clock_changes.csv``, next to the offsets file (owner D5)."""
    return Path(repo) / params.PROCESSED_REL / f"{trial}{ch.CHANGES_SUFFIX}"


def out_dir(repo: Path, trial: str) -> Path:
    """``out/clock_offset/<trial>/`` (CLAUDE.md data rules)."""
    return Path(repo) / params.OUT_REL / trial


def display_path(path: Path, repo: Path) -> str:
    """Repo-relative POSIX path when below the repo, so stats.json does not depend on where the repo is."""
    p = Path(path).resolve()
    try:
        return p.relative_to(Path(repo).resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def trial_role(trial: str) -> str:
    """``development`` / ``clock-only`` / ``other`` (COA-04: clock-only trials are labelled, never gated)."""
    t = trial.lower()
    if t in params.DEVELOPMENT_TRIALS:
        return "development"
    return "clock-only" if t in params.CLOCK_ONLY_TRIALS else "other"


def refusal(repo: Path, trial: str) -> str | None:
    """CO-01: quarantined (decision 030) and split-excluded s01_t00 (decision 019) trials are refused.

    WHY only these: measuring is not gating; every other trial may be measured.
    """
    if is_quarantined(trial, db_path(repo, trial), repo):
        return "quarantined trial (decision 030)"
    if trial.lower() in {t.lower() for t in params.EXCLUDED_TRIALS}:
        return "excluded from the data split (decision 019: S01 t00 is target side only)"
    return None


def require_dbs(repo: Path, trials: Sequence[str]) -> None:
    """Raise ClockOffsetError if any allowed trial has no DB (checked before anything is read or written)."""
    missing = [str(db_path(repo, t)) for t in trials if refusal(repo, t) is None and not db_path(repo, t).exists()]
    if missing:
        raise ClockOffsetError("trial DB not found: " + ", ".join(missing))


# ---------------------------------------------------------------- loading

def with_instants(rows: Sequence[Mapping]) -> list[dict]:
    """Rows with ``us`` = event_utc as integer microseconds (decision 010: event_utc is the instant).

    WHY a hard error on a missing time: an event without event_utc cannot be placed on any clock,
    and dropping it silently could remove a pair or a restart.
    """
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["us"] = to_us(d["event_utc"])
        except (TypeError, ValueError, KeyError) as exc:
            raise ClockOffsetError(f"event {d.get('event_uid')} has no valid event_utc ({exc})") from exc
        out.append(d)
    return out


def load_trial(path: Path) -> tuple[list[dict], str, str]:
    """(events_dedup rows with ``us``, sha256 before, sha256 after) via the read-only guarded opener."""
    with db.guarded(path) as (con, sha_before):
        rows = db.load_events(con)
    sha_after = db.sha256_file(path)
    return with_instants(rows), sha_before, sha_after


# ---------------------------------------------------------------- pure trial computation

def fmt_ms(us: int) -> str:
    """Microsecond instant to ``YYYY-MM-DDTHH:MM:SS.mmmZ`` (same text form as the window file)."""
    dt = _EPOCH + timedelta(microseconds=us)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def hosts_with_events(events: Sequence[Mapping], start_us: int, end_excl_us: int) -> dict[str, bool]:
    """host -> any event of any channel in the trial window (CO-08 ``host_has_events``)."""
    seen = {e["host"] for e in events if start_us <= e["us"] < end_excl_us}
    return {h: h in seen for h in params.HOSTS}


def params_sha256() -> str:
    """SHA-256 of params.py with CRLF normalised to LF, written into stats.json so every output names the
    frozen parameters (COT-17). WHY normalised: a Windows checkout with CRLF must give the hash recorded in
    decision 043."""
    return hashlib.sha256(Path(params.__file__).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def params_dict() -> dict[str, Any]:
    """Spec 08 section 5 values (and the lab constants they rely on) as JSON-ready values."""
    return {"PAIR_PAD_S": params.PAIR_PAD_S, "DC_EDGE_S": params.DC_EDGE_S, "MIN_PAIRS": params.MIN_PAIRS,
            "MAX_LOO_SHIFT_S": params.MAX_LOO_SHIFT_S, "READING_AGREE_S": params.READING_AGREE_S,
            "CHECK_PORTS": list(params.CHECK_PORTS), "MAX_PAIR_DELTA_S": params.MAX_PAIR_DELTA_S,
            "CHECK_JOIN_S": params.CHECK_JOIN_S, "CHECK_REVIEW_S": params.CHECK_REVIEW_S,
            "CHECK_KILL_S": params.CHECK_KILL_S, "MIN_CLOCK_STEP_MS": params.MIN_CLOCK_STEP_MS,
            "MARGIN_END_S": params.MARGIN_END_S,
            "BOOT_EVENT_IDS": sorted(params.BOOT_EVENT_IDS),
            "CLOCK_CHANGE_EVENTS": [list(x) for x in sorted(params.CLOCK_CHANGE_EVENTS)],
            "LAB_HOST_IPS": dict(sorted(params.LAB_HOST_IPS.items())), "CO17_DATE": params.CO17_DATE.isoformat(),
            "params_sha256": params_sha256()}


def evidence_stats(host_pairs: Mapping[str, HostPairs], n_tickets: int) -> dict[str, Any]:
    """Counts of GUID-bearing 4624/4769 and of every pair removed, per host, with the removed uids."""
    per_host = {}
    for h, hp in sorted(host_pairs.items()):
        per_host[h] = {"n_4624_guid": hp.n_4624_guid, "n_4624_with_candidate": hp.n_4624_with_candidate,
                       "mutual_pairs": len(hp.mutual), "dropped_by_mutual_nearest": hp.dropped_by_mutual_nearest,
                       "n_dropped_far": len(hp.dropped_far),
                       "dropped_far_pairs": [outputs.pair_brief(p) for p in hp.dropped_far],
                       "n_dropped_before_change": len(hp.dropped_before_change),
                       "dropped_before_change_pairs": [outputs.pair_brief(p) for p in hp.dropped_before_change],
                       "change_cut_event_uid": hp.cut_event_uid, "stale_event_uids": list(hp.stale_event_uids),
                       "expected_clock_change_uids": list(hp.expected_change_uids),
                       "routine_clock_change_uids": list(hp.routine_change_uids),
                       "n_pairs": len(hp.kept)}
    return {"dc01_4769_guid": n_tickets, "per_host": per_host}


def late_gap_clipped(host_pairs: Mapping[str, HostPairs], end_us: int) -> dict[str, int | None]:
    """host -> (manifest-clipped window end - 300 s) - last kept 4624, whole s (audit, stats.json only).

    WHY reported next to ``late_gap_s``: the spec 10.7 table measured the gap from the clipped window
    end - 300 s. Where the export span cuts the window end, that point lies before the true last
    agent event, which ``late_gap_s`` uses; both are shown so the step-2 limit (Q11) is set on a
    known definition.
    """
    ref = end_us - s_to_us(params.MARGIN_END_S)
    return {h: (us_to_s(ref - max(p.e4624["us"] for p in hp.kept)) if hp.kept else None)
            for h, hp in sorted(host_pairs.items())}


def window_stats(win: WindowResult, last_agent_utc: str | None, span: Mapping | None) -> dict[str, Any]:
    """The raw agent window used (decision 040), with the events that set its edges."""
    return {"start_utc": win.start_utc, "end_utc": win.end_utc, "raw_start_utc": win.raw_start_utc,
            "raw_end_utc": win.raw_end_utc, "start_event_uid": win.start_event_uid,
            "end_event_uid": win.end_event_uid, "clipped_by_manifest_start": win.clipped_by_manifest_start,
            "clipped_by_manifest_end": win.clipped_by_manifest_end, "last_agent_event_utc": last_agent_utc,
            "manifest_span": dict(span) if span else None, "time_basis": "raw"}


def compute_trial(trial: str, events: Sequence[Mapping], span: Mapping | None, db_sha: str, db_text: str,
                  sha_after: str | None = None, *, shifts: Mapping[str, ch.ShiftInfo] | None = None,
                  export: "co19.ExportScan | None" = None, win: WindowResult | None = None) -> dict[str, Any]:
    """Offsets rows, pairs rows, CO-10 check, clock changes and stats for one trial; ``refused`` is set
    instead when the trial has no agent root (the search span needs the agent window; S01 operator windows
    are out of scope here). Pure: ``events`` must carry ``us``.

    ``shifts`` resolves the DB clock-change rows (D2; None -> unknown -> counted). ``export`` holds the CO-19
    export hits (None: the scan was not run, so the clock-change outputs cover the DB only). ``win`` may be
    passed when the caller already computed the raw agent window.
    """
    win = win if win is not None else computed_window(events, span)
    if win is None:
        return {"refused": "no agent roots in the trial DB (the raw agent window bounds the pair search)"}
    start_us, end_us = to_us(win.start_utc), to_us(win.end_utc)
    end_excl = end_us + US_PER_MS            # window convention: start <= t < end + 1 ms (as the gate)
    pad = s_to_us(params.PAIR_PAD_S)
    lo, hi = start_us - pad, end_us + pad
    last_agent = next((e for e in events if e["event_uid"] == win.end_event_uid), None)
    last_agent_us = last_agent["us"] if last_agent else None
    has_events = hosts_with_events(events, start_us, end_excl)
    host_pairs, tickets = pair_trial(events, lo, hi, end_excl, shifts=shifts)
    common = estimate.common_columns(fmt_ms(lo), fmt_ms(hi), db_sha)
    rows = estimate.offsets_rows(trial, host_pairs, has_events, last_agent_us, common)
    offsets = offsets_from_rows(rows)
    pair_rows = [outputs.pair_row(p) for h in sorted(host_pairs) for p in host_pairs[h].kept]
    pairs_text = outputs.csv_text(pair_rows, params.PAIRS_COLUMNS)
    clock = co19.build_clock_outputs(trial, events, win.start_utc, win.end_utc, {"path": db_text, "sha256": db_sha},
                                     export, shifts, ch.pair_bounds(pair_rows), co19.pairs_source_of(trial, pairs_text))
    check_rows, unjoined = check.check_pairs(events, offsets, start_us, end_excl, changes=clock["changes"])
    stats = {
        "trial_id": trial, "trial_role": trial_role(trial), "method": params.METHOD,
        "tool_version": params.TOOL_VERSION,
        "db": {"path": db_text, "sha256_before": db_sha, "sha256_after": sha_after or db_sha},
        "window": window_stats(win, last_agent["event_utc"] if last_agent else None, span),
        "manifest_coverage_note": manifest_coverage_reason(win, span, trial),
        "search_span": {"start_utc": fmt_ms(lo), "end_utc": fmt_ms(hi), "dc01_4769_edge_s": params.DC_EDGE_S},
        "evidence": evidence_stats(host_pairs, len(tickets)),
        "late_gap_clipped_end_s": late_gap_clipped(host_pairs, end_us),
        "offsets": {r["host"]: {k: r[k] for k in ("offset_status", "offset_ms", "offset_unc_ms", "n_pairs",
                                                  "host_has_events")} for r in rows},
        "clock_flag": estimate.clock_flag(rows),
        # owner D3: a counted clock step after a host's first pair, or on a host without pairs (scan.py)
        "clock_change_in_window": clock["flag"],
        "clock_change_scan": clock["summary"],
        "co17_refusal_preview": co17_refusal(offsets, start_us),
        "check": {"rows": check_rows, "summary": check.check_summary(check_rows, unjoined)},
        "parameters": params_dict(),
        "pairs_total": len(pair_rows),
    }
    return {"refused": None, "rows": rows, "pairs": pair_rows, "stats": stats, "clock": clock}


def trial_files(result: Mapping[str, Any]) -> dict[str, str]:
    """Text of every out/clock_offset/<trial>/ file; run_info.json is the only one not byte-compared.

    The CO-19 files (clock_events.csv, clock_scan.json) are included when the scan ran, so
    ``write_outputs``, which empties the folder first, writes them in the same pass (owner D6).
    """
    clock = result.get("clock")
    files = {"pairs.csv": outputs.csv_text(result["pairs"], params.PAIRS_COLUMNS),
             "stats.json": outputs.json_text(result["stats"]),
             "report.md": outputs.report_md(result["stats"], result["rows"],
                                            clock["pre_steps"] if clock else None),
             "run_info.json": outputs.json_text(run_info())}
    if clock:
        files.update(co19.clock_texts(clock))
    return files


def run_info(now: datetime | None = None) -> dict[str, str]:
    """Run time and versions (kept out of the byte-compared files)."""
    now = now or datetime.now(timezone.utc)
    return {"run_utc": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "tool_version": params.TOOL_VERSION,
            "python_version": platform.python_version()}


# ---------------------------------------------------------------- orchestration

def run(repo: Path, trials: Sequence[str] = params.DEFAULT_TRIALS, write: bool = True,
        scan: bool = True) -> dict[str, Any]:
    """Measure every trial, then write its files; return {"rows", "pairs", "stats", "clock", "refused"}.

    ``scan`` runs the CO-19 export scan (about 90 s on the 11 default trials); ``scan=False`` skips it, so
    clock_changes.csv then holds the DB clock changes only and stats.json says ``export_scan_run: false``.
    Raises ClockOffsetError (nothing written) when an allowed trial has no DB or an event has no time.
    Refused trials keep their reason and get no file.
    """
    repo = Path(repo)
    wanted = list(dict.fromkeys(trials))          # de-duplicate, keep order
    require_dbs(repo, wanted)
    results: dict[str, dict[str, Any]] = {}
    refused: dict[str, str] = {}
    for trial in wanted:
        reason = refusal(repo, trial)
        if reason:
            refused[trial] = reason
            continue
        path = db_path(repo, trial)
        events, sha_before, sha_after = load_trial(path)
        if sha_after != sha_before:
            raise ClockOffsetError(f"DB changed while read: {path}")
        mspan = read_manifest_span(repo, trial)
        win = computed_window(events, mspan)
        shifts = co19.resolve_db_shifts(repo, trial, events)
        export = None
        if scan and win is not None:
            sp = co19.span_from_window(win.start_utc, win.end_utc, None)
            export = co19.collect_export(repo, trial, sp["lo_us"], sp["hi_us"])
        res = compute_trial(trial, events, mspan, sha_before, display_path(path, repo), sha_after,
                            shifts=shifts, export=export, win=win)
        if res["refused"]:
            refused[trial] = res["refused"]
        else:
            results[trial] = res
    if write:
        for trial, res in results.items():
            outputs.write_text(offsets_path(repo, trial), outputs.csv_text(res["rows"], params.OFFSETS_COLUMNS))
            outputs.write_text(changes_path(repo, trial), co19.changes_text(res["clock"]))
            outputs.write_outputs(out_dir(repo, trial), trial_files(res))
    return {"rows": {t: r["rows"] for t, r in results.items()}, "pairs": {t: r["pairs"] for t, r in results.items()},
            "stats": {t: r["stats"] for t, r in results.items()},
            "clock": {t: r["clock"] for t, r in results.items()}, "refused": refused}
