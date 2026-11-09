"""Shared types and data loaders used by several checks.

Why shared loaders: LC-02/03/04/06/07 all start from the same remote 4624 set and LC-04,
LC-08 and LC-09 all need the process rows. Loading them once through `Db.query` (cached)
keeps the numbers consistent between checks while each check still records the SQL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .db import Db
from .params import Params
from .timeutil import parse_utc, seconds, to_db
from .window import Window

OK, PROBLEM, INFO, NOT_MEASURABLE = "OK", "PROBLEM", "INFO", "NOT_MEASURABLE"
PREDEFINED_LOGON_IDS = frozenset({996, 997, 998, 999})  # 0x3e4 … 0x3e7 (NF-13)


@dataclass
class Context:
    """Everything a check needs; passed explicitly so no check reads hidden global state."""

    db: Db
    trial_id: str
    scenario: str
    params: Params
    window: Window
    secrets: frozenset[str] = frozenset()


@dataclass
class CheckResult:
    """One entry of report.json `checks` (LC-11/LC-12); SQL is attached by the report."""

    check_id: str
    title: str
    status: str
    summary: str
    effect: str
    result: dict[str, Any] = field(default_factory=dict)


def reference_only(ctx: Context) -> str | None:
    """Reason text if this trial cannot answer source-host/dump checks (decision 001)."""
    return ctx.params.reference_only_trials.get(ctx.trial_id)


def gated_status(ctx: Context, status: str, summary: str) -> tuple[str, str]:
    """For reference-only trials a source-host/dump check is NOT_MEASURABLE, with the reason."""
    reason = reference_only(ctx)
    if reason is None:
        return status, summary
    return NOT_MEASURABLE, f"{reason}; {summary}"


def hex_id(value: int | None) -> str | None:
    """Logon ids: integers for joins, hex for display (decision D1)."""
    return None if value is None else f"0x{int(value):x}"


def with_time(rows: list[dict[str, Any]], column: str = "event_utc") -> list[dict[str, Any]]:
    """Copy rows and add a parsed `t`; copies keep the Db cache unmodified."""
    out = []
    for row in rows:
        copy = dict(row)
        copy["t"] = parse_utc(row[column]) if row.get(column) else None
        out.append(copy)
    return out


def base_name(path: str | None) -> str:
    """Lower-case file name of a Windows path (`C:\\X\\sc.exe` → `sc.exe`)."""
    if not path:
        return ""
    return path.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].strip('"').lower()


def account_from_subject(subject: str | None) -> str | None:
    """`lab\\admin_it` → `admin_it` (same rule as NF-04 for account_name)."""
    if not subject:
        return None
    return subject.rsplit("\\", 1)[-1].split("@", 1)[0].lower()


def is_lab_ipv4(ip: str | None, params: Params) -> bool:
    return bool(ip) and ip.startswith(params.lab_ipv4_prefix)


def ip_category(ip: str | None, params: Params) -> str:
    """LC-02 categories: loopback, link-local, lab IPv4, other."""
    if not ip:
        return "none"
    low = ip.lower()
    if low in ("::1", "127.0.0.1") or low.startswith("127."):
        return "loopback"
    if low.startswith("fe80:"):
        return "link_local"
    if is_lab_ipv4(low, params):
        return "lab_ipv4"
    return "other"


# --- loaders ------------------------------------------------------------------------------

REMOTE_4624_SQL = """
    SELECT event_uid, host, event_utc, account_name, domain_short, source_ip, source_port,
           logon_type, authentication_package, logon_guid, target_logon_id,
           target_linked_logon_id
    FROM events_dedup
    WHERE channel = 'Security' AND event_id = 4624
      AND logon_type IN (3, 10) AND source_ip IS NOT NULL
      AND event_utc >= ? AND event_utc <= ?
    ORDER BY event_utc, event_uid
"""

ALL_4624_SQL = """
    SELECT event_uid, host, event_utc, account_name, logon_type, source_ip, source_port,
           authentication_package, logon_guid, target_logon_id, target_linked_logon_id
    FROM events_dedup
    WHERE channel = 'Security' AND event_id = 4624
    ORDER BY host, event_utc, event_uid
"""

COMMANDS_SQL = """
    SELECT event_uid, host, channel, event_id, event_utc, session_id, process_id,
           process_guid, parent_process_guid, image, account_name, subject_account,
           command_line
    FROM events_dedup
    WHERE ((channel = 'Sysmon' AND event_id = 1) OR (channel = 'Security' AND event_id = 4688))
      AND event_utc >= ? AND event_utc <= ?
    ORDER BY host, event_utc, event_uid
"""

SESSIONS_WITH_PROCESSES_SQL = """
    SELECT DISTINCT host, session_id
    FROM events_dedup
    WHERE ((channel = 'Sysmon' AND event_id = 1) OR (channel = 'Security' AND event_id = 4688))
      AND session_id IS NOT NULL
"""


def load_remote_4624(ctx: Context, check_id: str) -> list[dict[str, Any]]:
    """Remote 4624 (type 3/10, source IP set) in the window, all hosts and IP categories."""
    rows = ctx.db.query(check_id, REMOTE_4624_SQL, (ctx.window.start_db, ctx.window.end_db))
    return with_time(rows)


def load_all_4624(ctx: Context, check_id: str) -> list[dict[str, Any]]:
    """Every 4624 in the DB: sessions can start days before the window (SESSION_LOOKBACK_S)."""
    return with_time(ctx.db.query(check_id, ALL_4624_SQL))


def command_range(ctx: Context) -> tuple[str, str]:
    """Window widened by the largest LC-04d look-back/look-ahead and the LC-08b 10 min."""
    p = ctx.params
    before = max((p.cmd_before_s, *p.cmd_before_grid))
    after = max((p.cmd_after_s, *p.cmd_after_grid, p.post_dump_cmd_s))
    return to_db(ctx.window.start - seconds(before)), to_db(ctx.window.end + seconds(after))


def load_commands(ctx: Context, check_id: str) -> list[dict[str, Any]]:
    """Sysmon 1 + 4688 rows around the window (the LC-04 look-back may leave the window)."""
    return with_time(ctx.db.query(check_id, COMMANDS_SQL, command_range(ctx)))


def load_process_sessions(ctx: Context, check_id: str) -> set[tuple[str, int]]:
    """(host, session_id) pairs that ran at least one process anywhere in the DB (LC-07)."""
    rows = ctx.db.query(check_id, SESSIONS_WITH_PROCESSES_SQL)
    return {(r["host"], int(r["session_id"])) for r in rows}


def logons_by_host_id(logons: list[dict[str, Any]]) -> dict[tuple[str, int], list[dict[str, Any]]]:
    """Index 4624 rows by (host, TargetLogonId) for session lookups.

    The linked (elevated twin) id is deliberately not indexed here: the twin has its own
    4624, and indexing both ids would attach one session to two logons.
    """
    index: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in logons:
        if row.get("target_logon_id") is not None:
            index.setdefault((row["host"], int(row["target_logon_id"])), []).append(row)
    return index


def session_logon(index: dict[tuple[str, int], list[dict[str, Any]]], host: str,
                  session_id: int, before: Any) -> dict[str, Any] | None:
    """Latest 4624 that created `session_id` on `host` at or before `before` (ids get reused)."""
    rows = [r for r in index.get((host, session_id), []) if r["t"] is not None and r["t"] <= before]
    return max(rows, key=lambda r: r["t"]) if rows else None
