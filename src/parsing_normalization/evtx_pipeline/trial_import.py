"""Per-trial import: Phase 1 JSONL of ONE trial -> one analysis SQLite file.

Spec 01_normalise_fixes (NF-01, NF-02, NF-07..NF-09, NF-15..NF-20) and
decisions 006/007.  The old ``full_import.py`` is not used or changed; this
module owns its own DDL because the trial schema has a nullable ``raw_event``
and extra columns.  Counts are kept as independent counters, never derived by
subtraction (NF-17).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from .normalize import _event_id, _values, canonical_channel, to_int
from .schema import EVENT_COLUMNS
from .trial_normalize import HOSTS, is_relevant, normalize_trial_event

BATCH_SIZE = 1000

# NF-16 / NF-14 / NF-04: trial schema = old columns, raw_event nullable, plus new columns.
TRIAL_EVENT_COLUMNS: dict[str, str] = {
    **{k: v for k, v in EVENT_COLUMNS.items() if k != "raw_event"},
    "raw_event": "TEXT",
    "trial_id": "TEXT NOT NULL", "source_line": "INTEGER NOT NULL", "account_name": "TEXT",
    "domain_short": "TEXT", "target_linked_logon_id": "INTEGER", "source_image": "TEXT",
    "granted_access": "TEXT", "target_process_guid": "TEXT", "initiated": "INTEGER",
    "sysmon_logon_guid": "TEXT", "relative_target_name": "TEXT", "event_utc": "TEXT",
}
COLUMN_NAMES: tuple[str, ...] = tuple(TRIAL_EVENT_COLUMNS)
_LOGON_ID_COLUMNS = ("session_id", "subject_logon_id", "target_logon_id", "target_linked_logon_id")

_EVENT_DDL = ",\n    ".join(f'"{n}" {t}' for n, t in TRIAL_EVENT_COLUMNS.items())
_HEX_COLUMNS = ",\n    ".join(
    f"CASE WHEN {c} IS NULL THEN NULL ELSE printf('0x%x', {c}) END AS {c}_hex" for c in _LOGON_ID_COLUMNS)
_SELECT_COLUMNS = ", ".join(f'"{n}"' for n in COLUMN_NAMES)

TABLE_DDL = f"""
CREATE TABLE trial_run (
    scenario_id TEXT NOT NULL, trial_id TEXT NOT NULL, started_utc TEXT NOT NULL, completed_utc TEXT,
    jsonl_dir TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, status TEXT NOT NULL
);
CREATE TABLE source_files (
    relative_path TEXT PRIMARY KEY, jsonl_path TEXT NOT NULL, jsonl_sha256 TEXT NOT NULL,
    evtx_sha256 TEXT, emitted_event_count INTEGER NOT NULL, lines_read INTEGER NOT NULL,
    kept INTEGER NOT NULL, excluded_not_relevant INTEGER NOT NULL, excluded_bad_event_id INTEGER NOT NULL,
    blank_lines INTEGER NOT NULL
);
CREATE TABLE events (
    {_EVENT_DDL}
);
CREATE TABLE normalization_errors (
    normalization_error_id INTEGER PRIMARY KEY, source_relative_path TEXT, source_line INTEGER,
    severity TEXT NOT NULL CHECK(severity IN ('info','warning','error')),
    field_name TEXT, error_type TEXT NOT NULL, message TEXT NOT NULL
);
CREATE TABLE duplicate_events (
    duplicate_id INTEGER PRIMARY KEY, event_uid TEXT NOT NULL, duplicate_of_event_uid TEXT NOT NULL,
    duplicate_kind TEXT NOT NULL, duplicate_digest TEXT NOT NULL, decision TEXT NOT NULL,
    UNIQUE(event_uid, duplicate_of_event_uid, duplicate_kind)
);
CREATE TABLE validation_results (
    validation_result_id INTEGER PRIMARY KEY, check_name TEXT NOT NULL, result_status TEXT NOT NULL,
    numerator INTEGER, denominator INTEGER, details_json TEXT NOT NULL, created_utc TEXT NOT NULL
);
"""

INDEX_DDL = """
CREATE INDEX idx_events_dedup ON events(duplicate_content_sha256, source_relative_path, source_line);
CREATE INDEX idx_events_host_session ON events(host, session_id);
CREATE INDEX idx_events_host_srcip_srcport ON events(host, source_ip, source_port);
CREATE INDEX idx_events_process_guid ON events(process_guid);
CREATE INDEX idx_events_logon_guid ON events(logon_guid);
CREATE INDEX idx_events_target_logon_guid ON events(target_logon_guid);
CREATE INDEX idx_events_account_time ON events(account_name, timestamp_utc);
CREATE INDEX idx_events_eventid_channel ON events(event_id, channel);
CREATE INDEX idx_events_trial_host_time ON events(scenario_id, trial_id, host, timestamp_utc);
CREATE INDEX idx_events_eventid_host_eventutc ON events(event_id, host, event_utc);
CREATE INDEX idx_events_source_line ON events(source_relative_path, source_line);
"""

VIEW_DDL = f"""
CREATE VIEW events_dedup AS
SELECT {_SELECT_COLUMNS} FROM (
    SELECT e.*, row_number() OVER (PARTITION BY duplicate_content_sha256
                                   ORDER BY source_relative_path, source_line) AS _rn
    FROM events e) WHERE _rn = 1;
CREATE VIEW events_display AS
SELECT e.*,
    {_HEX_COLUMNS}
FROM events e;
"""


class TrialImportError(RuntimeError):
    """Raised for any condition that must abort the import (NF-17)."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    """Hash a file in chunks (stored for provenance, NF-16)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_trial_args(jsonl_dir: Path, manifest: dict[str, Any], scenario: str, trial: str) -> None:
    """NF-01/NF-15: CLI scenario/trial must equal the folder name and the manifest input root.

    WHY: a wrong argument would silently label a whole trial with the wrong ids.
    """
    if jsonl_dir.name.lower() != f"{scenario}_{trial}".lower():
        raise TrialImportError(f"JSONL folder {jsonl_dir.name!r} does not match --scenario/--trial {scenario}_{trial}")
    parts = PurePosixPath(str(manifest.get("input_root", "")).replace("\\", "/")).parts
    if len(parts) < 2 or tuple(p.lower() for p in parts[-2:]) != (scenario.lower(), trial.lower()):
        raise TrialImportError(f"manifest input_root {manifest.get('input_root')!r} does not end in {scenario}/{trial}")


def check_manifest(manifest: dict[str, Any], parse_errors_path: Path) -> list[dict[str, Any]]:
    """NF-17: require a full, clean Phase 1 run; return the selected inputs."""
    if manifest.get("run_mode") != "full":
        raise TrialImportError(f"manifest run_mode is {manifest.get('run_mode')!r}, need 'full'")
    if manifest.get("failures"):
        raise TrialImportError(f"manifest lists failures: {manifest['failures'][:3]}")
    if not parse_errors_path.exists() or parse_errors_path.stat().st_size != 0:
        raise TrialImportError("parse_errors.jsonl is missing or not empty")
    inputs = manifest.get("selected_inputs") or []
    if not inputs:
        raise TrialImportError("manifest has no selected_inputs")
    for item in inputs:
        if item.get("status") != "ok":
            raise TrialImportError(f"input {item.get('relative_path')} has status {item.get('status')!r}")
        host = PurePosixPath(str(item["relative_path"]).replace("\\", "/")).parts[0].lower()
        if host not in HOSTS:
            raise TrialImportError(f"host folder {host!r} of {item['relative_path']} not in HOSTS")
    return list(inputs)


def peek_channel_event_id(event: Any) -> tuple[str | None, int | None]:
    """Cheap (channel, event_id) so irrelevant rows are skipped before full normalisation."""
    if not isinstance(event, dict):
        return None, None
    system = event.get("system") if isinstance(event.get("system"), dict) else {}
    source = event.get("source") if isinstance(event.get("source"), dict) else {}
    channel = canonical_channel(system.get("channel"), str(source.get("relative_path") or ""))
    event_id = to_int(system.get("event_id"))
    if not event_id:
        event_id = _event_id(system, _values(event))
    return channel, event_id


def iter_physical_lines(path: Path) -> Iterator[tuple[int, bytes, str]]:
    """Yield (1-based line number, raw bytes, text) splitting on b'\\n' only (NF-16/NF-20).

    WHY: str.splitlines also splits on U+2028 etc., which would shift
    ``source_line`` away from the physical line a reader of the file sees.
    """
    with path.open("rb") as handle:
        for number, raw in enumerate(handle, 1):
            yield number, raw, raw.decode("utf-8")


def new_counters() -> dict[str, int]:
    return {"lines_read": 0, "kept": 0, "excluded_not_relevant": 0, "excluded_bad_event_id": 0, "blank_lines": 0}


def check_accounting(relative_path: str, counters: dict[str, int], emitted: int) -> None:
    """NF-17: independent counters must reconcile with each other and with the manifest."""
    line_sum = (counters["kept"] + counters["excluded_not_relevant"] + counters["excluded_bad_event_id"]
                + counters["blank_lines"])
    event_sum = counters["kept"] + counters["excluded_not_relevant"] + counters["excluded_bad_event_id"]
    if counters["lines_read"] != line_sum:
        raise TrialImportError(f"{relative_path}: lines_read {counters['lines_read']} != categories {line_sum}")
    if event_sum != emitted:
        raise TrialImportError(f"{relative_path}: events accounted {event_sum} != manifest emitted {emitted}")


def row_values(row: dict[str, Any]) -> tuple[Any, ...]:
    """Order a normalised row by the table columns; unknown keys are a bug, so fail loudly."""
    extra = set(row) - set(COLUMN_NAMES)
    if extra:
        raise TrialImportError(f"normalised row has columns missing from the schema: {sorted(extra)}")
    return tuple(row.get(name) for name in COLUMN_NAMES)


_INSERT_SQL = f"INSERT INTO events ({_SELECT_COLUMNS}) VALUES ({','.join('?' * len(COLUMN_NAMES))})"


def flush(connection: sqlite3.Connection, batch: list[tuple[Any, ...]]) -> None:
    connection.executemany(_INSERT_SQL, batch)
    batch.clear()


def import_file(connection: sqlite3.Connection, item: dict[str, Any], jsonl_path: Path, *,
                scenario: str, trial: str) -> dict[str, Any]:
    """Stream one JSONL file into ``events``; return its accounting row (NF-09, NF-17)."""
    relative_path = str(item["relative_path"])
    counters = new_counters()
    digest = hashlib.sha256()
    batch: list[tuple[Any, ...]] = []
    for number, raw, text in iter_physical_lines(jsonl_path):
        digest.update(raw)
        counters["lines_read"] += 1
        if not text.strip():
            counters["blank_lines"] += 1
            continue
        event = json.loads(text)
        channel, event_id = peek_channel_event_id(event)
        if event_id is None:
            counters["excluded_bad_event_id"] += 1
            connection.execute(
                "INSERT INTO normalization_errors(source_relative_path,source_line,severity,field_name,error_type,message)"
                " VALUES(?,?,?,?,?,?)",
                (relative_path, number, "error", "event_id", "invalid_event_id", "event id missing or not an integer; row excluded"))
            continue
        if not is_relevant(channel, event_id):
            counters["excluded_not_relevant"] += 1
            continue
        row = normalize_trial_event(event, scenario_id=scenario, trial_id=trial, line_number=number)
        batch.append(row_values(row))
        counters["kept"] += 1
        if len(batch) >= BATCH_SIZE:
            flush(connection, batch)
    if batch:
        flush(connection, batch)
    emitted = int(item["emitted_event_count"])
    check_accounting(relative_path, counters, emitted)
    connection.execute(
        "INSERT INTO source_files VALUES(?,?,?,?,?,?,?,?,?,?)",
        (relative_path, str(jsonl_path), digest.hexdigest(), item.get("post_run_sha256"), emitted,
         counters["lines_read"], counters["kept"], counters["excluded_not_relevant"],
         counters["excluded_bad_event_id"], counters["blank_lines"]))
    return {"relative_path": relative_path, "emitted_event_count": emitted, **counters,
            "jsonl_sha256": digest.hexdigest()}


def build_duplicate_ledger(connection: sqlite3.Connection) -> tuple[int, int]:
    """NF-08/NF-19: list exact and near duplicates; the survivor is the lowest (path, line).

    WHY: exact duplicates (same content digest) are hidden by ``events_dedup``;
    near duplicates (same host/channel/event/record id, different payload) stay
    visible in the view and are only listed here for review.
    """
    connection.execute("""
        INSERT INTO duplicate_events(event_uid,duplicate_of_event_uid,duplicate_kind,duplicate_digest,decision)
        SELECT event_uid, first_uid, 'exact_content_candidate', duplicate_content_sha256, 'hidden_in_events_dedup'
        FROM (SELECT event_uid, duplicate_content_sha256,
                     first_value(event_uid) OVER w AS first_uid, row_number() OVER w AS rn
              FROM events WINDOW w AS (PARTITION BY duplicate_content_sha256 ORDER BY source_relative_path, source_line))
        WHERE rn > 1""")
    connection.execute("CREATE INDEX idx_tmp_identity ON events(host,channel,event_id,record_id)")
    connection.execute("""
        INSERT OR IGNORE INTO duplicate_events(event_uid,duplicate_of_event_uid,duplicate_kind,duplicate_digest,decision)
        SELECT event_uid, first_uid, 'near_duplicate_conflict', duplicate_content_sha256, 'kept_in_events_dedup'
        FROM (SELECT event_uid, duplicate_content_sha256,
                     first_value(event_uid) OVER w AS first_uid,
                     first_value(duplicate_content_sha256) OVER w AS first_digest
              FROM events
              WHERE record_id IS NOT NULL AND (host,channel,event_id,record_id) IN (
                    SELECT host,channel,event_id,record_id FROM events WHERE record_id IS NOT NULL
                    GROUP BY host,channel,event_id,record_id HAVING COUNT(DISTINCT duplicate_content_sha256) > 1)
              WINDOW w AS (PARTITION BY host,channel,event_id,record_id ORDER BY source_relative_path, source_line))
        WHERE duplicate_content_sha256 <> first_digest""")
    connection.execute("DROP INDEX idx_tmp_identity")
    counts = dict(connection.execute("SELECT duplicate_kind, COUNT(*) FROM duplicate_events GROUP BY duplicate_kind"))
    return counts.get("exact_content_candidate", 0), counts.get("near_duplicate_conflict", 0)


def run_checks(connection: sqlite3.Connection, accounting: list[dict[str, Any]]) -> list[tuple[str, bool, int, int]]:
    """Post-load checks from spec section 7; each is (name, passed, numerator, denominator)."""
    q = lambda sql: int(connection.execute(sql).fetchone()[0] or 0)
    events, dedup = q("SELECT COUNT(*) FROM events"), q("SELECT COUNT(*) FROM events_dedup")
    kept = sum(a["kept"] for a in accounting)
    zero_ids = sum(q(f"SELECT COUNT(*) FROM events WHERE {c} = 0") for c in _LOGON_ID_COLUMNS)
    integrity = [r[0] for r in connection.execute("PRAGMA integrity_check")]
    return [
        ("events_equal_kept", events == kept, events, kept),
        ("dedup_le_events", dedup <= events, dedup, events),
        ("raw_event_all_null", q("SELECT COUNT(*) FROM events WHERE raw_event IS NOT NULL") == 0, 0, events),
        ("source_line_present", q("SELECT COUNT(*) FROM events WHERE source_line IS NULL") == 0, 0, events),
        ("no_zero_logon_ids", zero_ids == 0, zero_ids, events),
        ("timestamp_present", q("SELECT COUNT(*) FROM events WHERE timestamp_utc IS NULL") == 0, 0, events),
        ("hosts_in_host_set", q("SELECT COUNT(*) FROM events WHERE host NOT IN (%s)" % ",".join(f"'{h}'" for h in HOSTS)) == 0, 0, events),
        ("integrity_check", integrity == ["ok"], 0, 1),
    ]


def cleanup_temp(temp_path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        Path(str(temp_path) + suffix).unlink(missing_ok=True)


def build_report(scenario: str, trial: str, database: Path, events: int, dedup: int, exact: int, near: int,
                 accounting: list[dict[str, Any]], checks: list[tuple[str, bool, int, int]],
                 started: float) -> dict[str, Any]:
    """Assemble the JSON report (pure; duration is measured up to this call)."""
    duration = time.perf_counter() - started
    return {"scenario": scenario, "trial": trial, "database": str(database), "events": events,
            "events_dedup": dedup, "duplicates_exact": exact, "duplicates_near": near,
            "duration_seconds": round(duration, 2), "events_per_second": round(events / max(duration, 1e-9), 1),
            "per_file": accounting, "checks": {name: passed for name, passed, _, _ in checks}}


def write_report(report_dir: Path, report: dict[str, Any]) -> Path:
    """Write out/normalise/<scenario>_<trial>/import_report.json."""
    out_dir = report_dir / f"{report['scenario']}_{report['trial']}"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "import_report.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path


def verify_published_journal_mode(database: Path) -> None:
    """NF-26: a published DB must be in journal_mode 'delete' (no -wal/-shm sidecars); else remove and fail."""
    connection = sqlite3.connect(database)
    try:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        connection.close()
    if str(mode).lower() != "delete":
        for suffix in ("", "-wal", "-shm"):
            Path(str(database) + suffix).unlink(missing_ok=True)
        raise TrialImportError(f"published database journal_mode is {mode!r}, expected 'delete'; file removed")


def run_trial_import(jsonl_dir: Path, scenario: str, trial: str, database: Path,
                     report_dir: Path = Path("out/normalise")) -> dict[str, Any]:
    """Import one trial. Any failure removes the temp DB and raises; the target is never overwritten (NF-02/NF-17)."""
    started = time.perf_counter()
    jsonl_dir = jsonl_dir.resolve(strict=True)
    if database.exists():
        raise FileExistsError(f"refusing to overwrite existing database: {database}")
    manifest_path = jsonl_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    check_trial_args(jsonl_dir, manifest, scenario, trial)
    inputs = check_manifest(manifest, jsonl_dir / "parse_errors.jsonl")
    database.parent.mkdir(parents=True, exist_ok=True)
    temp_path = database.with_name(database.name + ".tmp")
    cleanup_temp(temp_path)
    connection = sqlite3.connect(temp_path)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=OFF")
        connection.executescript(TABLE_DDL)
        connection.execute("INSERT INTO trial_run VALUES(?,?,?,?,?,?,?)",
                           (scenario, trial, utc_now(), None, str(jsonl_dir), sha256_file(manifest_path), "running"))
        accounting = []
        for item in inputs:
            jsonl_path = jsonl_dir / str(item["output_relative_path"])
            accounting.append(import_file(connection, item, jsonl_path, scenario=scenario, trial=trial))
            connection.commit()
        connection.executescript(INDEX_DDL)
        exact, near = build_duplicate_ledger(connection)
        connection.executescript(VIEW_DDL)
        checks = run_checks(connection, accounting)
        for name, passed, num, den in checks:
            connection.execute("INSERT INTO validation_results(check_name,result_status,numerator,denominator,details_json,created_utc)"
                               " VALUES(?,?,?,?,?,?)", (name, "PASS" if passed else "FAIL", num, den, "{}", utc_now()))
        events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        dedup = connection.execute("SELECT COUNT(*) FROM events_dedup").fetchone()[0]
        report = build_report(scenario, trial, database, events, dedup, exact, near, accounting, checks, started)
        failed = [name for name, passed, _, _ in checks if not passed]
        if failed:
            # NF-26: the report with the FAIL rows must survive the temp-DB cleanup.
            report["status"] = "FAIL"
            write_report(report_dir, report)
            raise TrialImportError(f"validation failed: {failed}")
        connection.execute("UPDATE trial_run SET completed_utc=?, status='complete'", (utc_now(),))
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.close()
        # NF-26: report is written BEFORE the rename, so a report failure never leaves a published DB.
        report["status"] = "PASS"
        write_report(report_dir, report)
    except BaseException:
        try:
            connection.close()
        finally:
            cleanup_temp(temp_path)
        raise
    if database.exists():
        cleanup_temp(temp_path)
        raise FileExistsError(f"database appeared during import: {database}")
    temp_path.rename(database)
    verify_published_journal_mode(database)
    return report
