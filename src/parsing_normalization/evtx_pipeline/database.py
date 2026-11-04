"""SQLite persistence helpers for Phase 2A."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterable, Iterator

from .normalize import exact_duplicate_digest
from .schema import EVENT_COLUMNS


@contextmanager
def transaction(connection: sqlite3.Connection) -> Iterator[None]:
    """A transaction boundary that rolls back all writes on any exception."""
    connection.execute("BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def connect(path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def insert_scenario_run(connection: sqlite3.Connection, row: dict[str, Any]) -> None:
    connection.execute(
        """INSERT INTO scenario_runs(run_id,schema_version,started_utc,completed_utc,input_root,
           phase1_manifest_path,sampling_rule,input_file_count,input_event_count,inserted_event_count,run_status,notes)
           VALUES(:run_id,:schema_version,:started_utc,:completed_utc,:input_root,:phase1_manifest_path,
           :sampling_rule,:input_file_count,:input_event_count,:inserted_event_count,:run_status,:notes)""", row)


def insert_source_file(connection: sqlite3.Connection, row: dict[str, Any]) -> None:
    connection.execute(
        """INSERT INTO source_files(source_file_id,scenario_run_id,relative_path,source_sha256,source_size_bytes,
           channel,host_hint,scenario_id,phase1_status,selected_for_smoke,phase1_event_count,imported_event_count,
           normalization_error_count)
           VALUES(:source_file_id,:scenario_run_id,:relative_path,:source_sha256,:source_size_bytes,
           :channel,:host_hint,:scenario_id,:phase1_status,:selected_for_smoke,:phase1_event_count,
           :imported_event_count,:normalization_error_count)""",
        {"phase1_event_count": 0, "imported_event_count": 0, "normalization_error_count": 0, **row})


def insert_parse_error(connection: sqlite3.Connection, run_id: str, row: dict[str, Any]) -> None:
    connection.execute(
        """INSERT INTO parse_errors(scenario_run_id,source_file_id,relative_path,record_id,error_type,message,raw_error_json)
           VALUES(?,?,?,?,?,?,?)""",
        (run_id, row.get("source_file_id"), row.get("source") or row.get("relative_path"),
         row.get("record_index"), row.get("error_type", "Phase1ParseError"), row.get("message"),
         json.dumps(row, ensure_ascii=False, separators=(",", ":"))),
    )


def record_normalization_error(connection: sqlite3.Connection, run_id: str, *, severity: str,
                               field_name: str | None, error_type: str, message: str,
                               source_file_id: str | None = None, event_uid: str | None = None) -> None:
    connection.execute(
        """INSERT INTO normalization_errors(scenario_run_id,source_file_id,event_uid,severity,field_name,error_type,message)
           VALUES(?,?,?,?,?,?,?)""",
        (run_id, source_file_id, event_uid, severity, field_name, error_type, message),
    )


def insert_event(connection: sqlite3.Connection, run_id: str, event: dict[str, Any]) -> None:
    """Insert one event without dropping duplicates; record duplicate candidates."""
    digest = exact_duplicate_digest(event)
    prior = connection.execute(
        "SELECT event_uid FROM events WHERE duplicate_content_sha256 = ? ORDER BY event_uid LIMIT 1",
        (digest,),
    ).fetchone()
    values = dict(event)
    values["duplicate_content_sha256"] = digest
    columns = list(EVENT_COLUMNS)
    placeholders = ",".join("?" for _ in columns)
    connection.execute(
        f"INSERT INTO events({','.join(columns)}) VALUES({placeholders})",
        [values.get(column) for column in columns],
    )
    if prior and prior["event_uid"] != event["event_uid"]:
        connection.execute(
            """INSERT OR IGNORE INTO duplicate_events(scenario_run_id,event_uid,duplicate_of_event_uid,
               duplicate_kind,duplicate_digest,decision) VALUES(?,?,?,?,?,?)""",
            (run_id, event["event_uid"], prior["event_uid"], "exact_content_candidate", digest,
             "retain_both_pending_final_cross_export_review"),
        )
    identity = (event.get("scenario_id"), event.get("host"), event.get("channel"),
                event.get("event_id"), event.get("record_id"))
    if all(value is not None for value in identity):
        conflict = connection.execute(
            """SELECT event_uid FROM events WHERE scenario_id=? AND host=? AND channel=? AND event_id=? AND record_id=?
               AND event_uid<>? AND duplicate_content_sha256<>? LIMIT 1""",
            (*identity, event["event_uid"], digest),
        ).fetchone()
        if conflict:
            record_normalization_error(connection, run_id, severity="warning", field_name="record_id",
                                       error_type="same_identity_different_raw_content",
                                       message="Same scenario/host/channel/event/record identity has different raw content; both rows retained.",
                                       source_file_id=event.get("source_file_id"), event_uid=event["event_uid"])


def insert_events_atomic(connection: sqlite3.Connection, run_id: str,
                          events: Iterable[dict[str, Any]]) -> int:
    count = 0
    with transaction(connection):
        for event in events:
            insert_event(connection, run_id, event)
            count += 1
    return count

