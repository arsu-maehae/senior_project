"""Versioned SQLite schema for normalized Phase 2A events."""
from __future__ import annotations

import sqlite3
import json
from datetime import datetime, timezone

from .normalize import _raw_first, _values, classify_guid, normalize_guid

SCHEMA_VERSION = "2.3.0"

EVENT_COLUMNS = {
    "scenario_id": "TEXT", "scenario_hint_raw": "TEXT", "event_uid": "TEXT PRIMARY KEY", "timestamp_utc": "TEXT",
    "epoch_ms": "INTEGER", "host": "TEXT", "host_hint_raw": "TEXT", "export_host": "TEXT", "source_host": "TEXT",
    "destination_host": "TEXT", "channel": "TEXT", "channel_raw": "TEXT", "event_id": "INTEGER",
    "record_id": "INTEGER", "account": "TEXT", "subject_account": "TEXT", "target_account": "TEXT",
    "domain": "TEXT", "session_id": "INTEGER", "subject_logon_id": "INTEGER", "target_logon_id": "INTEGER",
    "logon_guid": "TEXT", "target_logon_guid": "TEXT", "logon_guid_state": "TEXT",
    "target_logon_guid_state": "TEXT", "logon_type": "INTEGER",
    "authentication_package": "TEXT", "source_ip": "TEXT", "source_port": "INTEGER",
    "destination_ip": "TEXT", "destination_port": "INTEGER", "workstation_name": "TEXT",
    "client_name": "TEXT", "session_name": "TEXT", "process_guid": "TEXT",
    "parent_process_guid": "TEXT", "process_id": "INTEGER", "parent_process_id": "INTEGER",
    "image": "TEXT", "parent_image": "TEXT", "command_line": "TEXT", "target_image": "TEXT",
    "target_filename": "TEXT", "share_name": "TEXT", "share_path": "TEXT", "service_name": "TEXT",
    "service_image_path": "TEXT", "spn": "TEXT", "winrm_activity_id": "TEXT",
    "powershell_host_application": "TEXT", "source_file_id": "TEXT", "source_relative_path": "TEXT",
    "source_sha256": "TEXT", "machine_account": "INTEGER NOT NULL DEFAULT 0",
    "predefined_session": "INTEGER NOT NULL DEFAULT 0", "field_values_json": "TEXT NOT NULL",
    "raw_event": "TEXT NOT NULL CHECK(json_valid(raw_event))", "raw_event_sha256": "TEXT NOT NULL",
    "duplicate_content_sha256": "TEXT NOT NULL",
}

_EVENT_DDL = ",\n        ".join(f'"{name}" {kind}' for name, kind in EVENT_COLUMNS.items())

DDL = f"""
CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    applied_utc TEXT NOT NULL,
    description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scenario_runs (
    run_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    started_utc TEXT NOT NULL,
    completed_utc TEXT,
    input_root TEXT NOT NULL,
    phase1_manifest_path TEXT NOT NULL,
    sampling_rule TEXT NOT NULL,
    input_file_count INTEGER NOT NULL DEFAULT 0,
    input_event_count INTEGER NOT NULL DEFAULT 0,
    inserted_event_count INTEGER NOT NULL DEFAULT 0,
    run_status TEXT NOT NULL,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS source_files (
    source_file_id TEXT PRIMARY KEY,
    scenario_run_id TEXT NOT NULL REFERENCES scenario_runs(run_id),
    relative_path TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    source_size_bytes INTEGER NOT NULL,
    channel TEXT,
    host_hint TEXT,
    scenario_id TEXT,
    phase1_status TEXT NOT NULL,
    selected_for_smoke INTEGER NOT NULL DEFAULT 0,
    phase1_event_count INTEGER NOT NULL DEFAULT 0,
    imported_event_count INTEGER NOT NULL DEFAULT 0,
    normalization_error_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(scenario_run_id, relative_path)
);
CREATE TABLE IF NOT EXISTS events (
        {_EVENT_DDL},
    FOREIGN KEY(source_file_id) REFERENCES source_files(source_file_id)
);
CREATE TABLE IF NOT EXISTS parse_errors (
    parse_error_id INTEGER PRIMARY KEY,
    scenario_run_id TEXT NOT NULL REFERENCES scenario_runs(run_id),
    source_file_id TEXT REFERENCES source_files(source_file_id),
    relative_path TEXT,
    record_id INTEGER,
    error_type TEXT NOT NULL,
    message TEXT,
    raw_error_json TEXT CHECK(raw_error_json IS NULL OR json_valid(raw_error_json))
);
CREATE TABLE IF NOT EXISTS normalization_errors (
    normalization_error_id INTEGER PRIMARY KEY,
    scenario_run_id TEXT NOT NULL REFERENCES scenario_runs(run_id),
    source_file_id TEXT REFERENCES source_files(source_file_id),
    event_uid TEXT,
    severity TEXT NOT NULL CHECK(severity IN ('info','warning','error')),
    field_name TEXT,
    error_type TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS duplicate_events (
    duplicate_id INTEGER PRIMARY KEY,
    scenario_run_id TEXT NOT NULL REFERENCES scenario_runs(run_id),
    event_uid TEXT NOT NULL REFERENCES events(event_uid),
    duplicate_of_event_uid TEXT NOT NULL REFERENCES events(event_uid),
    duplicate_kind TEXT NOT NULL,
    duplicate_digest TEXT NOT NULL,
    decision TEXT NOT NULL,
    UNIQUE(event_uid, duplicate_of_event_uid, duplicate_kind)
);
CREATE TABLE IF NOT EXISTS validation_results (
    validation_result_id INTEGER PRIMARY KEY,
    scenario_run_id TEXT NOT NULL REFERENCES scenario_runs(run_id),
    check_name TEXT NOT NULL,
    result_status TEXT NOT NULL,
    numerator INTEGER,
    denominator INTEGER,
    result_value REAL,
    details_json TEXT NOT NULL CHECK(json_valid(details_json)),
    created_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_scenario_timestamp ON events(scenario_id, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_scenario_host_timestamp ON events(scenario_id, host, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_scenario_host_session ON events(scenario_id, host, session_id);
CREATE INDEX IF NOT EXISTS idx_events_scenario_logon_guid ON events(scenario_id, logon_guid);
CREATE INDEX IF NOT EXISTS idx_events_scenario_process_guid ON events(scenario_id, process_guid);
CREATE INDEX IF NOT EXISTS idx_events_scenario_parent_process_guid ON events(scenario_id, parent_process_guid);
CREATE INDEX IF NOT EXISTS idx_events_scenario_account_timestamp ON events(scenario_id, account, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_scenario_source_destination_ip ON events(scenario_id, source_ip, destination_ip);
CREATE INDEX IF NOT EXISTS idx_events_scenario_channel_event_id ON events(scenario_id, channel, event_id);
CREATE INDEX IF NOT EXISTS idx_events_source_file_record_id ON events(source_file_id, record_id);
CREATE INDEX IF NOT EXISTS idx_events_scenario_target_logon_guid ON events(scenario_id, target_logon_guid);
CREATE INDEX IF NOT EXISTS idx_source_files_run_path ON source_files(scenario_run_id, relative_path);
CREATE INDEX IF NOT EXISTS idx_duplicate_events_run_digest ON duplicate_events(scenario_run_id, duplicate_digest);
"""

_INDEX_START = DDL.index("CREATE INDEX IF NOT EXISTS idx_events_scenario_timestamp")
INDEX_DDL = DDL[_INDEX_START:]
TABLE_DDL = DDL[:_INDEX_START]


def create_schema(connection: sqlite3.Connection, *, create_indexes: bool = True) -> None:
    """Create the schema safely on a new or already initialized database."""
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.executescript(TABLE_DDL)
    event_columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
    for name in ("logon_guid_state", "target_logon_guid_state"):
        if name not in event_columns:
            connection.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
    source_columns = {row[1] for row in connection.execute("PRAGMA table_info(source_files)")}
    for name in ("phase1_event_count", "imported_event_count", "normalization_error_count"):
        if name not in source_columns:
            connection.execute(f"ALTER TABLE source_files ADD COLUMN {name} INTEGER NOT NULL DEFAULT 0")
    # Backfill state flags and ensure zero GUIDs are represented as NULL in old smoke rows.
    rows = connection.execute("SELECT event_uid, raw_event FROM events WHERE logon_guid_state IS NULL OR target_logon_guid_state IS NULL OR (channel='Security' AND event_id=4624 AND target_logon_guid_state='missing')").fetchall()
    for event_uid, raw_json in rows:
        try:
            event = json.loads(raw_json)
            values = _values(event)
            present, raw_logon = _raw_first(values, "LogonGuid", "LogonGUID")
            target_present, raw_target = _raw_first(values, "TargetLogonGuid", "TargetLogonGUID")
            system = event.get("system") if isinstance(event.get("system"), dict) else {}
            channel = str(system.get("channel") or "").casefold()
            event_id = system.get("event_id")
            try:
                is_4624 = int(event_id) == 4624 and "security" in channel
            except (ValueError, TypeError):
                is_4624 = False
            if is_4624 and (not target_present or classify_guid((target_present, raw_target)) in {"missing", "empty", "placeholder"}):
                target_present, raw_target = present, raw_logon
            logon_state = classify_guid((present, raw_logon))
            target_state = classify_guid((target_present, raw_target))
            connection.execute("UPDATE events SET logon_guid=?,target_logon_guid=?,logon_guid_state=?,target_logon_guid_state=? WHERE event_uid=?",
                               (normalize_guid(raw_logon), normalize_guid(raw_target), logon_state, target_state, event_uid))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    if create_indexes:
        connection.executescript(INDEX_DDL)
    connection.execute("PRAGMA user_version = 203")
    applied_utc = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    connection.execute(
        "INSERT OR IGNORE INTO schema_version(version, applied_utc, description) VALUES(?,?,?)",
        (SCHEMA_VERSION, applied_utc, "Versioned normalized event schema for full import; no graph outputs"),
    )
    connection.commit()


def table_names(connection: sqlite3.Connection) -> set[str]:
    return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}

