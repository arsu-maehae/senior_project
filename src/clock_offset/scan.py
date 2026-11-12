"""CO-19: read-only scan of the trials' decoded exports for clock-change events, and the clock-change report
(spec 08 CO-15, CO-18, CO-19; owner decisions D1-D6, 2026-11-12).

WHY a scan of the exports: the trial DBs ingested before CO-18 do not hold Security 4616 or the System
Kernel-General time-change event, so a clock step inside a trial cannot be seen from the DB. The decoded
full exports (``data/processed/jsonl/<trial>/per_file/<host>/{security,system}.jsonl``) hold every EVTX
record before the DB filter, so the scan looks there. For DBs ingested after CO-18, the 4616 / System 1
rows have no previous/new time column, so their shift is read from the JSONL line the row points to
(``source_relative_path`` + ``source_line``, NF-09), read-only (D2).

The report (``clock_events.csv``, ``clock_scan.json``) and the trial flag ``clock_change_in_window`` (D3)
are a data-quality signal: the scan derives no parameter and is never used to tune (CO-19 scope).

Layout: pure functions (records -> hits; hits + DB rows -> changes, rows, report) first, then the file
reading, then the standalone CLI ``python -m clock_offset.scan [--trials ...]`` (cwd=src), which writes only
the two files under ``out/clock_offset/<trial>/``. run.py calls the same pure builder as part of the step.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Mapping, Sequence

from gate.timeutil import US_PER_MS, to_us
from lab_common.manifest import read_manifest_span
from trial_window.window import computed_window

from . import changes as ch
from . import outputs, params
from . import pairs as pairs_mod
from . import run as co_run  # module import, attributes used at call time, so run.py may import this module
from .changes import SCAN_COMPLETE, SCAN_INCOMPLETE, ClockChange, ShiftInfo, parse_instant_us
from .common import s_to_us

# ---------------------------------------------------------------- constants (params.py is frozen)

# Kernel-General is the System provider that logs event 1 for a system time change (amended CO-18);
# event id 1 is reused by other System providers (e.g. Power-Troubleshooter, resume from sleep).
KERNEL_GENERAL_PROVIDER = "microsoft-windows-kernel-general"
# (channel lower-case, event id text) of the clock-change events the scan looks for.
SECURITY_TIME_CHANGE = ("security", "4616")
SYSTEM_TIME_CHANGE = ("system", "1")
# Channels (file stems) scanned; also the manifest ``channel`` values.
SCAN_CHANNELS: tuple[str, ...] = ("security", "system")
# event_data names of the logged previous/new time, per (channel, event id).
TIME_FIELDS: Mapping[tuple[str, str], tuple[str, str]] = {
    SECURITY_TIME_CHANGE: ("PreviousTime", "NewTime"),
    SYSTEM_TIME_CHANGE: ("OldTime", "NewTime"),
}

JSONL_REL = "data/processed/jsonl"
MANIFEST_REL = "data/manifest.csv"
EVENTS_FILE = "clock_events.csv"
SCAN_FILE = "clock_scan.json"
PAIRS_FILE = "pairs.csv"
SCAN_FILES: tuple[str, ...] = (EVENTS_FILE, SCAN_FILE)
SCAN_METHOD = "jsonl_export_scan_4616_kernelgeneral1"
# event_uid prefix of an export hit used as a change row (SF-1): ``export:<source_sha256>:<record_index>``.
EXPORT_UID_PREFIX = ch.EXPORT_REF_PREFIX
# DB channel spelling of the scanned channels (the DB writes ``Security`` / ``System``, params.CLOCK_CHANGE_EVENTS).
DB_CHANNEL: Mapping[str, str] = {"security": "Security", "system": "System"}

EVENTS_COLUMNS: tuple[str, ...] = (
    "host", "channel", "event_id", "provider", "timestamp_raw", "previous_time", "new_time", "shift_ms",
    "counted", "classification", "record_index", "source_sha256",
)

PairBounds = Mapping[str, tuple[int, int]]


@dataclass(frozen=True)
class Hit:
    """One clock-change record of an export inside the search span, traceable to its file and record."""
    host: str
    channel: str
    event_id: str
    provider: str | None
    timestamp_raw: str
    us: int
    previous_time: str | None
    new_time: str | None
    shift_ms: int | None
    record_index: int | None
    source_sha256: str | None


@dataclass(frozen=True)
class FileScan:
    """Result of one pass over a file's records: the sha256 values seen, counts, and the hits.

    WHY collected together: the file is read once; whether its hits may be used depends on the
    sha256 check, which can only be decided after every record has been seen.
    """
    sha256_values: frozenset[str]
    n_records: int
    n_missing_sha: int
    n_candidates_out_of_span: int
    n_candidates_bad_time: int
    hits: tuple[Hit, ...]


@dataclass(frozen=True)
class ExportScan:
    """Everything read from one trial's exports: the usable hits and the per-file accounting.

    Each ``files_skipped`` entry carries ``manifest_listed``: True when data/manifest.csv lists that
    trial/host/channel, so the skip leaves a hole in the evidence (SF-4); an export the manifest does not
    know is reported but leaves no hole.
    """
    hits: tuple[Hit, ...]
    files_read: tuple[dict, ...]
    files_skipped: tuple[dict, ...]
    records_without_time: int


# ---------------------------------------------------------------- pure: record fields

def _system(record: Mapping) -> Mapping:
    """The record's ``system`` block, or an empty mapping (a malformed record never raises here)."""
    s = record.get("system")
    return s if isinstance(s, Mapping) else {}


def _source(record: Mapping) -> Mapping:
    """The record's ``source`` block, or an empty mapping."""
    s = record.get("source")
    return s if isinstance(s, Mapping) else {}


def event_id_text(record: Mapping) -> str:
    """Event id as stripped text (the export stores it as a string; ints are accepted for synthetic input)."""
    v = _system(record).get("event_id")
    return "" if v is None else str(v).strip()


def channel_key(record: Mapping) -> str:
    """Record channel lower-case: the clock events are told apart by channel + id (System 1 vs Sysmon 1)."""
    v = _system(record).get("channel")
    return "" if v is None else str(v).strip().lower()


def is_clock_change_record(record: Mapping) -> bool:
    """Security 4616, or System 1 whose provider is Microsoft-Windows-Kernel-General (case-insensitive).

    WHY the provider check on System 1: event id 1 is used by other System providers too, and the
    amended CO-18 counts only the Kernel-General time change; a System 1 without a provider is not one.
    """
    key = (channel_key(record), event_id_text(record))
    if key == SECURITY_TIME_CHANGE:
        return True
    if key == SYSTEM_TIME_CHANGE:
        provider = _system(record).get("provider")
        return provider is not None and str(provider).strip().lower() == KERNEL_GENERAL_PROVIDER
    return False


def event_data_value(record: Mapping, name: str) -> str | None:
    """Value of the first ``event_data`` item called ``name`` (exact name), or None when absent or blank."""
    items = record.get("event_data")
    if not isinstance(items, list):
        return None
    for item in items:
        if isinstance(item, Mapping) and item.get("name") == name:
            v = item.get("value")
            return None if v is None or not str(v).strip() else str(v).strip()
    return None


def record_index(record: Mapping) -> int | None:
    """``source.record_index`` as int (the position of the record in its EVTX file), or None."""
    v = _source(record).get("record_index")
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def record_sha256(record: Mapping) -> str | None:
    """``source.sha256`` lower-case (the hash of the EVTX file the record was decoded from), or None."""
    v = _source(record).get("sha256")
    return str(v).strip().lower() if v else None


def logged_times(record: Mapping) -> tuple[str | None, str | None]:
    """(previous, new) time text as the event logs them (4616: PreviousTime/NewTime; KG 1: OldTime/NewTime)."""
    names = TIME_FIELDS.get((channel_key(record), event_id_text(record)))
    if names is None:
        return None, None
    return event_data_value(record, names[0]), event_data_value(record, names[1])


def make_hit(record: Mapping, host: str, us: int) -> Hit:
    """Hit from a clock-change record already known to be inside the span."""
    prev_text, new_text = logged_times(record)
    sysb = _system(record)
    provider = sysb.get("provider")
    return Hit(host=host, channel=str(sysb.get("channel")).strip(), event_id=event_id_text(record),
               provider=None if provider is None else str(provider),
               timestamp_raw=str(sysb.get("timestamp_raw")).strip(), us=us,
               previous_time=prev_text, new_time=new_text,
               shift_ms=ch.shift_between(parse_instant_us(prev_text), parse_instant_us(new_text)),
               record_index=record_index(record), source_sha256=record_sha256(record))


def shift_from_record(record: Mapping, row: Mapping) -> ShiftInfo:
    """Previous/new time of a DB clock-change row from its JSONL record (D2), after checking that the record
    is that row (same channel, event id and EVTX sha256); otherwise the shift is unknown, with the reason."""
    if channel_key(record) != str(row.get("channel") or "").lower() or event_id_text(record) != str(row.get("event_id")):
        return ShiftInfo(None, None, None, "JSONL line is not the row's channel/event id")
    row_sha = str(row.get("source_sha256") or "").strip().lower()
    if row_sha and record_sha256(record) != row_sha:
        return ShiftInfo(None, None, None, "JSONL line source.sha256 differs from the row's source_sha256")
    prev_text, new_text = logged_times(record)
    shift = ch.shift_between(parse_instant_us(prev_text), parse_instant_us(new_text))
    return ShiftInfo(prev_text, new_text, shift, None if shift is not None else "previous/new time not readable")


# ---------------------------------------------------------------- pure: scanning

def scan_records(records: Iterable[Mapping], host: str, lo_us: int, hi_us: int) -> FileScan:
    """One pass over a file's records: collect every sha256 and the clock-change hits in [lo, hi].

    The span is inclusive on both ends, as the pair search span (pairs.in_span). A clock-change
    record whose timestamp cannot be parsed cannot be placed in the span, so it is counted
    (``n_candidates_bad_time``), never silently dropped.
    """
    shas: set[str] = set()
    n = missing = out_of_span = bad_time = 0
    hits: list[Hit] = []
    for rec in records:
        n += 1
        sha = record_sha256(rec)
        if sha is None:
            missing += 1
        else:
            shas.add(sha)
        if not is_clock_change_record(rec):
            continue
        us = parse_instant_us(_system(rec).get("timestamp_raw"))
        if us is None:
            bad_time += 1
        elif lo_us <= us <= hi_us:
            hits.append(make_hit(rec, host, us))
        else:
            out_of_span += 1
    return FileScan(frozenset(shas), n, missing, out_of_span, bad_time, tuple(hits))


def file_skip_reason(scan: FileScan, manifest_shas: Iterable[str]) -> str | None:
    """Why a file's hits may not be used, or None: every record must carry ONE sha256 that the
    manifest lists for the same trial/host/channel (CO-19).

    WHY: the export must be provably decoded from the EVTX copy the manifest records; a file built
    from another copy (or a mix) could report events that are not in the trial's evidence.
    """
    allowed = {s.lower() for s in manifest_shas}
    if scan.n_records == 0:
        return "no records (sha256 cannot be checked)"
    if scan.n_missing_sha:
        return f"{scan.n_missing_sha} record(s) without source.sha256"
    if len(scan.sha256_values) != 1:
        return "records carry several source.sha256 values: " + ", ".join(sorted(scan.sha256_values))
    (sha,) = scan.sha256_values
    if not allowed:
        return "no data/manifest.csv row for this trial/host/channel"
    if sha not in allowed:
        return f"source.sha256 {sha} is not the manifest sha256 for this trial/host/channel"
    return None


def sort_hits(hits: Iterable[Hit]) -> list[Hit]:
    """CSV order (timestamp, host, record_index), then channel/sha so equal keys still sort the same way."""
    return sorted(hits, key=lambda h: (h.us, h.host, -1 if h.record_index is None else h.record_index,
                                       h.channel, h.source_sha256 or ""))


def hit_change(hit: Hit) -> ClockChange:
    """The hit as a ClockChange (source ``export``, ref = record_index) so it is counted and classified
    exactly like a DB row (D1, D3)."""
    return ch.make_change(host=hit.host, channel=hit.channel, event_id=int(hit.event_id), change_us=hit.us,
                          previous_time=hit.previous_time, new_time=hit.new_time, source=ch.SOURCE_EXPORT,
                          ref="" if hit.record_index is None else str(hit.record_index),
                          source_sha256=hit.source_sha256, shift_ms=hit.shift_ms)


def hit_row(hit: Hit, bounds: PairBounds | None) -> dict[str, Any]:
    """clock_events.csv row of one hit, with ``counted`` (D1) and its classification (D3)."""
    c = hit_change(hit)
    return {"host": hit.host, "channel": hit.channel, "event_id": hit.event_id, "provider": hit.provider,
            "timestamp_raw": hit.timestamp_raw, "previous_time": hit.previous_time, "new_time": hit.new_time,
            "shift_ms": hit.shift_ms, "counted": c.counted, "classification": ch.classify(c, bounds),
            "record_index": hit.record_index, "source_sha256": hit.source_sha256}


def hit_rows(hits: Iterable[Hit], bounds: PairBounds | None) -> list[dict[str, Any]]:
    """Every hit as a row, in CSV order."""
    return [hit_row(h, bounds) for h in sort_hits(hits)]


def export_uid(hit: Hit) -> str:
    """``export:<source_sha256>:<record_index>``: a uid that names the EVTX file and record of the hit (SF-1),
    so a cut or stale status set by an export step stays traceable in stats.json."""
    return ch.export_ref(hit.source_sha256, hit.record_index)


def hit_change_row(hit: Hit) -> dict[str, Any]:
    """The hit as a pair-cut change row ``{host, channel, event_id, us, event_uid}`` (SF-1).

    WHY ``us`` = the record's own logged time: DB rows are placed by ``event_utc``, which is the same
    recorded instant, so DB and export changes are ordered against the pairs on one basis. The channel is
    written as the DB writes it so ``pairs.is_clock_change`` treats both alike.
    """
    chan = DB_CHANNEL.get(hit.channel.strip().lower(), hit.channel)
    return {"host": hit.host, "channel": chan, "event_id": int(hit.event_id), "us": hit.us,
            "event_uid": export_uid(hit)}


def hit_shift(hit: Hit) -> ShiftInfo:
    """ShiftInfo of a hit from its logged previous/new time, as ``shift_from_record`` resolves a DB row (D2):
    an unreadable time gives an unknown shift (which counts, D1) with the reason."""
    return ShiftInfo(hit.previous_time, hit.new_time, hit.shift_ms,
                     None if hit.shift_ms is not None else "previous/new time not readable")


def export_change_inputs(export: ExportScan | None) -> tuple[list[dict[str, Any]], dict[str, ShiftInfo]]:
    """(change rows, uid -> ShiftInfo) of every export hit, for ``pairs.pair_trial`` (SF-1); empty without a
    scan. Hits of skipped files are not in ``export.hits``, so they never feed the cut."""
    if export is None:
        return [], {}
    hits = sort_hits(export.hits)
    return [hit_change_row(h) for h in hits], {export_uid(h): hit_shift(h) for h in hits}


def manifest_holes(export: ExportScan) -> list[dict]:
    """Skipped files that data/manifest.csv lists for the trial (SF-4): their clock changes are unknown."""
    return [f for f in export.files_skipped if f.get("manifest_listed")]


def scan_status(export: ExportScan | None) -> str:
    """``complete`` | ``incomplete`` (SF-4, owner 2026-11-12).

    Incomplete when the scan was not run, a manifest-listed security/system export was skipped (missing,
    no records, a record without or with another sha256, mixed sha256), or a clock-change record has no
    parseable time. WHY any record without a time and not only in-span ones: without a time the record
    cannot be placed, so it may lie in the span. A host/channel the manifest does not list is no hole.
    """
    if export is None or manifest_holes(export) or export.records_without_time > 0:
        return SCAN_INCOMPLETE
    return SCAN_COMPLETE


def pairs_source_of(trial: str, text: str) -> dict[str, str]:
    """Provenance of the pair bounds: the repo-relative pairs.csv path and the SHA-256 of its text.

    WHY from text and a fixed relative path: run.py holds the pairs.csv text in memory before writing it,
    so both entry points (run.py and this CLI) record the same provenance and write identical bytes.
    """
    return {"path": f"{params.OUT_REL}/{trial}/{PAIRS_FILE}", "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def bounds_from_pairs_text(text: str) -> dict[str, tuple[int, int]]:
    """host -> (first, last) kept-pair 4624 instant from pairs.csv text (not the classification bounds since
    owner 2026-11-12: those are the original pairs, ``pairs.original_bounds``)."""
    return ch.pair_bounds(csv.DictReader(io.StringIO(text, newline="")))


def span_from_window(window_start_utc: str, window_end_utc: str, db: Mapping[str, Any] | None) -> dict[str, Any]:
    """The raw search span of run.compute_trial: (clipped) agent window -/+ PAIR_PAD_S, in µs and text.

    WHY the same arithmetic as run.compute_trial: the scan must cover exactly the span the pairs were
    searched in (CO-19 "agent window +- PAIR_PAD_S").
    """
    pad = s_to_us(params.PAIR_PAD_S)
    lo, hi = to_us(window_start_utc) - pad, to_us(window_end_utc) + pad
    return {"lo_us": lo, "hi_us": hi, "start_utc": co_run.fmt_ms(lo), "end_utc": co_run.fmt_ms(hi),
            "window_start_utc": window_start_utc, "window_end_utc": window_end_utc,
            "db": dict(db) if db else None}


# ---------------------------------------------------------------- pure: the clock-change report (D1-D5)

def build_clock_outputs(trial: str, events: Sequence[Mapping], window_start_utc: str, window_end_utc: str,
                        db: Mapping[str, Any] | None, export: ExportScan | None,
                        shifts: Mapping[str, ShiftInfo] | None, bounds: PairBounds | None,
                        pairs_source: Mapping[str, Any] | None) -> dict[str, Any]:
    """All clock-change outputs of one trial from in-memory inputs (pure; ``events`` carry ``us``).

    Returns ``changes`` (DB + export ClockChange, records of the same change merged into one by
    ``changes.merge_changes`` (owner 2026-11-12), with the last boot before each), ``changes_rows``
    (clock_changes.csv), ``events_rows`` (clock_events.csv, None without an export scan), ``scan``
    (clock_scan.json, None without an export scan), ``pre_steps`` (D4), ``flag`` (D3: True / False; None
    when the exports were not scanned and the DB alone does not flag, and always None on an incomplete scan,
    SF-4), ``clock_scan`` (``complete`` | ``incomplete``, SF-4) and ``summary`` (for stats.json).
    """
    span = span_from_window(window_start_utc, window_end_utc, db)
    lo, hi = span["lo_us"], span["hi_us"]
    win_start, win_end_excl = to_us(window_start_utc), to_us(window_end_utc) + US_PER_MS
    db_list = ch.db_changes(events, shifts, lo, hi)
    ex_list = [hit_change(h) for h in export.hits] if export is not None else []
    # one row / one count per physical change (owner 2026-11-12); db_clock_changes and export_hits stay raw
    all_changes = ch.sort_changes(ch.with_last_boot(ch.merge_changes(db_list + ex_list), ch.boot_times(events)))
    counts = ch.class_counts(all_changes, bounds)
    flag_known = ch.flags_trial(all_changes, bounds)
    status = scan_status(export)
    flag: bool | None
    if export is not None:
        flag = flag_known if status == SCAN_COMPLETE else None   # SF-4: unknown, never "no change"
    else:
        flag = flag_known if flag_known else None
    steps = ch.pre_steps(events, all_changes, win_start, win_end_excl)
    unresolved = sorted(({"event_uid": uid, "reason": info.reason} for uid, info in (shifts or {}).items()
                         if info.shift_ms is None), key=lambda d: d["event_uid"])
    summary = {"export_scan_run": export is not None, "clock_change_in_window": flag, "clock_scan": status,
               "min_clock_step_ms": params.MIN_CLOCK_STEP_MS, "db_clock_changes": len(db_list),
               "export_hits": None if export is None else len(export.hits),
               "counted_count": sum(1 for c in all_changes if c.counted), **counts,
               "counted_steps_in_window": len(steps), "db_shift_unresolved": unresolved,
               "coverage_complete": None if export is None else not export.files_skipped,
               "files_read": None if export is None else len(export.files_read),
               "files_skipped": None if export is None else len(export.files_skipped)}
    scan_doc = None
    events_rows = None
    if export is not None:
        events_rows = hit_rows(export.hits, bounds)
        scan_doc = {"trial_id": trial, "method": SCAN_METHOD, "tool_version": params.TOOL_VERSION,
                    "search_span": {k: span[k] for k in ("start_utc", "end_utc", "window_start_utc", "window_end_utc")},
                    "db": span["db"], "pairs_source": dict(pairs_source) if pairs_source else None,
                    "classification_bounds": "original pairs: mutual nearest after the far drop, before the "
                                             "change cut (owner 2026-11-12)",
                    "files_read": list(export.files_read), "files_skipped": list(export.files_skipped),
                    "coverage_complete": not export.files_skipped,
                    "clock_scan": status, "manifest_files_skipped": len(manifest_holes(export)),
                    "clock_change_records_without_time": export.records_without_time,
                    "hits": len(export.hits), "db_clock_changes": len(db_list),
                    "min_clock_step_ms": params.MIN_CLOCK_STEP_MS,
                    "counts_cover": "clock changes in the search span (export hits + DB clock-change rows), "
                                    "records of the same host, channel, event id and instant counted once",
                    "counted_count": summary["counted_count"], **counts,
                    "clock_change_in_window": flag, "db_shift_unresolved": unresolved, "pre_step": steps}
    return {"changes": all_changes, "changes_rows": ch.change_rows(trial, all_changes, bounds),
            "events_rows": events_rows, "scan": scan_doc, "pre_steps": steps, "flag": flag, "clock_scan": status,
            "summary": summary}


def clock_texts(clock: Mapping[str, Any]) -> dict[str, str]:
    """Text of clock_events.csv and clock_scan.json (empty when the exports were not scanned)."""
    if clock["scan"] is None:
        return {}
    return {EVENTS_FILE: outputs.csv_text(clock["events_rows"], EVENTS_COLUMNS),
            SCAN_FILE: outputs.json_text(clock["scan"])}


def changes_text(clock: Mapping[str, Any]) -> str:
    """Text of ``<trial>.clock_changes.csv`` (UTF-8, ``\\n``, byte-identical on the same inputs)."""
    return outputs.csv_text(clock["changes_rows"], ch.CLOCK_CHANGES_COLUMNS)


# ---------------------------------------------------------------- I/O: reading only

def iter_jsonl(path: Path) -> Iterator[dict]:
    """Decoded records of one JSONL export, one per non-blank line (read-only)."""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def split_trial(trial: str) -> tuple[str, str]:
    """``s02_t00`` -> (``s02``, ``t00``), the manifest's scenario/trial columns."""
    scenario, tr = trial.lower().split("_", 1)
    return scenario, tr


def manifest_shas(repo: Path, trial: str) -> dict[tuple[str, str], set[str]]:
    """(host, channel) -> manifest sha256 values for the trial's security/system files."""
    path = Path(repo) / MANIFEST_REL
    out: dict[tuple[str, str], set[str]] = {}
    if not path.exists():
        return out
    scenario, tr = split_trial(trial)
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["scenario"].lower() == scenario and r["trial"].lower() == tr and r["channel"].lower() in SCAN_CHANNELS:
                out.setdefault((r["host"].lower(), r["channel"].lower()), set()).add(r["sha256"].strip().lower())
    return out


def jsonl_path(repo: Path, trial: str, host: str, channel: str) -> Path:
    """``data/processed/jsonl/<trial>/per_file/<host>/<channel>.jsonl``."""
    return Path(repo) / JSONL_REL / trial / "per_file" / host / f"{channel}.jsonl"


def jsonl_from_pointer(repo: Path, trial: str, relative_path: str) -> Path | None:
    """JSONL file of a DB row's ``source_relative_path`` (``ep-02/security.evtx`` -> ``.../ep-02/security.jsonl``);
    None for a path that is absolute or climbs out of the trial folder."""
    rel = PurePosixPath(str(relative_path).replace("\\", "/"))
    if rel.is_absolute() or ".." in rel.parts or not rel.parts:
        return None
    return Path(repo) / JSONL_REL / trial / "per_file" / rel.with_suffix(".jsonl")


def read_lines(path: Path, wanted: Iterable[int]) -> dict[int, str]:
    """{1-based line number: text} for the wanted lines, splitting on ``\\n`` only (as the importer, NF-16)."""
    want = set(wanted)
    out: dict[int, str] = {}
    if not want:
        return out
    last = max(want)
    with open(path, "rb") as fh:
        for number, raw in enumerate(fh, 1):
            if number in want:
                out[number] = raw.decode("utf-8")
            if number >= last:
                break
    return out


def resolve_db_shifts(repo: Path, trial: str, events: Sequence[Mapping]) -> dict[str, ShiftInfo]:
    """event_uid -> ShiftInfo for every DB clock-change row (D2), read from its JSONL line (read-only).

    A row without a pointer, a missing file or line, or a line that is not the row gives an unknown shift
    with the reason; an unknown shift counts (D1). Existing DBs hold no such row, so nothing is read.
    """
    out: dict[str, ShiftInfo] = {}
    by_file: dict[Path, list[tuple[int, Mapping]]] = {}
    for e in events:
        if not ch.is_clock_change_row(e):
            continue
        uid = str(e["event_uid"])
        rel, line = e.get("source_relative_path"), e.get("source_line")
        path = jsonl_from_pointer(repo, trial, rel) if rel else None
        if path is None or line is None:
            out[uid] = ShiftInfo(None, None, None, "no usable source_relative_path/source_line pointer (NF-09)")
            continue
        by_file.setdefault(path, []).append((int(line), e))
    for path in sorted(by_file):
        wanted = by_file[path]
        if not path.is_file():
            for _, e in wanted:
                out[str(e["event_uid"])] = ShiftInfo(None, None, None, "JSONL file of the pointer not found")
            continue
        found = read_lines(path, (n for n, _ in wanted))
        for n, e in wanted:
            text = found.get(n)
            if text is None or not text.strip():
                out[str(e["event_uid"])] = ShiftInfo(None, None, None, f"JSONL line {n} not found")
                continue
            try:
                out[str(e["event_uid"])] = shift_from_record(json.loads(text), e)
            except json.JSONDecodeError:
                out[str(e["event_uid"])] = ShiftInfo(None, None, None, f"JSONL line {n} is not JSON")
    return out


def files_to_scan(repo: Path, trial: str, shas: Mapping[tuple[str, str], set[str]]) -> list[tuple[str, str]]:
    """(host, channel) of every security/system export present on disk or listed in the manifest, sorted.

    WHY the union: a manifest file without its export is reported as skipped (the scan would miss it),
    and an export the manifest does not know is read and then refused by the sha256 check.
    """
    keys = set(shas)
    base = Path(repo) / JSONL_REL / trial / "per_file"
    if base.is_dir():
        for host_dir in base.iterdir():
            for c in SCAN_CHANNELS:
                if host_dir.is_dir() and (host_dir / f"{c}.jsonl").is_file():
                    keys.add((host_dir.name.lower(), c))
    return sorted(keys)


def collect_export(repo: Path, trial: str, lo_us: int, hi_us: int) -> ExportScan:
    """Read the trial's security/system exports and keep the hits of files that pass the sha256 check; every
    skipped file says whether the manifest lists it (SF-4)."""
    shas = manifest_shas(repo, trial)
    read: list[dict] = []
    skipped: list[dict] = []
    hits: list[Hit] = []
    unplaced = 0
    for host, c in files_to_scan(repo, trial, shas):
        path = jsonl_path(repo, trial, host, c)
        shown = co_run.display_path(path, repo)
        listed = (host, c) in shas
        if not path.is_file():
            skipped.append({"path": shown, "reason": "export not found (data/manifest.csv lists this host/channel)",
                            "manifest_listed": listed})
            continue
        fs = scan_records(iter_jsonl(path), host, lo_us, hi_us)
        reason = file_skip_reason(fs, shas.get((host, c), set()))
        if reason:
            skipped.append({"path": shown, "reason": reason, "manifest_listed": listed})
            continue
        (sha,) = fs.sha256_values
        read.append({"path": shown, "source_sha256": sha, "records": fs.n_records, "hits": len(fs.hits),
                     "clock_change_records_outside_span": fs.n_candidates_out_of_span,
                     "clock_change_records_without_time": fs.n_candidates_bad_time})
        hits.extend(fs.hits)
        unplaced += fs.n_candidates_bad_time
    return ExportScan(tuple(sort_hits(hits)), tuple(read), tuple(skipped), unplaced)


# ---------------------------------------------------------------- standalone orchestration

def scan_one(repo: Path, trial: str) -> dict[str, Any] | None:
    """Standalone scan of one allowed trial (DB read-only for the window and the DB rows); None without an
    agent root. The pairs are recomputed through ``run.trial_pairs`` (the step's own path), so the
    classification uses the same original-pair bounds as the step and the provenance names the same pairs.csv
    text the step writes (owner 2026-11-12)."""
    path = co_run.db_path(repo, trial)
    events, sha_before, sha_after = co_run.load_trial(path)
    if sha_after != sha_before:
        raise co_run.ClockOffsetError(f"DB changed while read: {path}")
    win = computed_window(events, read_manifest_span(repo, trial))
    if win is None:
        return None
    span = span_from_window(win.start_utc, win.end_utc, None)
    export = collect_export(repo, trial, span["lo_us"], span["hi_us"])
    shifts = resolve_db_shifts(repo, trial, events)
    host_pairs = co_run.trial_pairs(events, win, shifts, export)[0]
    pair_rows = [outputs.pair_row(p) for h in sorted(host_pairs) for p in host_pairs[h].kept]
    bounds = pairs_mod.original_bounds(host_pairs)
    source = pairs_source_of(trial, outputs.csv_text(pair_rows, params.PAIRS_COLUMNS))
    return build_clock_outputs(trial, events, win.start_utc, win.end_utc,
                               {"path": co_run.display_path(path, repo), "sha256": sha_before},
                               export, shifts, bounds, source)


def run_scan(repo: Path, trials: Sequence[str] = params.DEFAULT_TRIALS, write: bool = True) -> dict[str, Any]:
    """Scan every allowed trial, then write clock_events.csv and clock_scan.json under out/clock_offset/<trial>/.

    Returns {"results": trial -> clock outputs, "refused": trial -> reason}. CO-01 refusals as in run.py;
    a missing DB for an allowed trial is a ClockOffsetError before anything is written. Writes nothing else
    (clock_changes.csv is written by run.py only).
    """
    repo = Path(repo)
    wanted = list(dict.fromkeys(trials))
    co_run.require_dbs(repo, wanted)
    results: dict[str, dict[str, Any]] = {}
    refused: dict[str, str] = {}
    for trial in wanted:
        reason = co_run.refusal(repo, trial)
        if reason:
            refused[trial] = reason
            continue
        res = scan_one(repo, trial)
        if res is None:
            refused[trial] = "no agent roots in the trial DB (the raw agent window bounds the scan span)"
            continue
        results[trial] = res
    if write:
        for trial, res in results.items():
            for name, text in clock_texts(res).items():
                outputs.write_text(co_run.out_dir(repo, trial) / name, text)
    return {"results": results, "refused": refused}


def summary_line(trial: str, s: Mapping[str, Any]) -> str:
    """One summary line of a trial's clock-change summary (also used by the run.py CLI)."""
    by = s["by_classification"]
    return (f"{trial}  clock_change_in_window={s['clock_change_in_window']} export_hits={s['export_hits']} "
            f"db_changes={s['db_clock_changes']} counted={s['counted_count']} routine={by['routine']} "
            f"expected={s['expected_count']} unexpected={s['unexpected_count']} "
            f"steps_in_window={s['counted_steps_in_window']} files_read={s['files_read']} "
            f"files_skipped={s['files_skipped']} clock_scan={s.get('clock_scan')}")


def report_lines(result: Mapping[str, Any]) -> list[str]:
    """One summary line per scanned trial, one per hit, one per skipped file and per refused trial."""
    lines = []
    for trial, res in result["results"].items():
        lines.append(summary_line(trial, res["summary"]))
        for r in res["events_rows"] or []:
            lines.append(f"  hit {r['host']} {r['channel']} {r['event_id']} {r['timestamp_raw']} "
                         f"shift_ms={r['shift_ms']} counted={str(r['counted']).lower()} {r['classification']}")
        for sk in (res["scan"] or {}).get("files_skipped", []):
            lines.append(f"  skipped {sk['path']}: {sk['reason']}")
    for trial, reason in result["refused"].items():
        lines.append(f"{trial}  REFUSED: {reason}")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry: scan, write, print. Exit 0 when the run finished, 2 on ClockOffsetError."""
    ap = argparse.ArgumentParser(prog="clock_offset.scan", description=__doc__.splitlines()[0])
    ap.add_argument("--trials", nargs="+", default=list(params.DEFAULT_TRIALS))
    ap.add_argument("--repo", type=Path, default=co_run.REPO)
    a = ap.parse_args(argv)
    try:
        result = run_scan(a.repo.resolve(), a.trials)
    except co_run.ClockOffsetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for line in report_lines(result):
        print(line)
    print(f"wrote {len(result['results'])} scan(s); refused {len(result['refused'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
