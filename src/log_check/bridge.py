"""LC-04e: the 4648 explicit-credential bridge.

A source session can open a hop with other credentials (S06: the svc_backup agent session
runs `New-PSCredential admin_it`). The target 4624 then shows admin_it while the session
belongs to svc_backup, and the plain account filter drops the true session. Security 4648
on the source host records exactly this: SubjectLogonId (the session), TargetUserName
(credentials used, `account_name`) and TargetServerName (where they were used).
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Any

from .common import Context, with_time
from .matching import names_target
from .params import Params
from .timeutil import seconds, to_db

EXPLICIT_SQL = """
    SELECT event_uid, host, event_utc, account_name, subject_account, session_id,
           subject_logon_id, destination_host, destination_ip, source_ip, field_values_json
    FROM events_dedup
    WHERE channel = 'Security' AND event_id = 4648
      AND event_utc >= ? AND event_utc <= ?
    ORDER BY host, event_utc, event_uid
"""

_JSON_TARGET_KEYS = ("targetservername", "targetinfo", "ipaddress")


def target_texts(row: dict[str, Any]) -> list[str]:
    """Every field of a 4648 that can name the target server.

    `destination_host` is the normalised TargetServerName; the raw TargetServerName,
    TargetInfo (`HOST/Endpoint-02.lab.local`) and IpAddress come from field_values_json.
    `source_ip` is included because the normaliser maps the 4648 IpAddress (the server's
    address, e.g. 192.168.50.22:445 for SMB) into that column.
    """
    texts = [row.get(k) for k in ("destination_host", "destination_ip", "source_ip")]
    try:
        fields = json.loads(row.get("field_values_json") or "{}")
    except json.JSONDecodeError:
        fields = {}
    for key in _JSON_TARGET_KEYS:
        value = fields.get(key)
        texts.extend(value if isinstance(value, list) else [value])
    return [t for t in texts if t and t != "-"]


def session_of(row: dict[str, Any]) -> int | None:
    """4648 session = SubjectLogonId (NF-11 puts it in session_id; subject_logon_id is the fallback)."""
    value = row.get("session_id") if row.get("session_id") is not None else row.get("subject_logon_id")
    return None if value is None else int(value)


def bridges(rows: list[dict[str, Any]], forms: tuple[str, ...], account: str, t: datetime,
            before_s: float, after_s: float) -> dict[int, list[str]]:
    """Sessions with a 4648 in [t − before, t + after] naming the target with `account`'s
    credentials → the supporting 4648 event_uids."""
    lo, hi = t - seconds(before_s), t + seconds(after_s)
    out: dict[int, list[str]] = defaultdict(list)
    for r in rows:
        sid = session_of(r)
        if sid is None or r.get("account_name") != account or not (lo <= r["t"] <= hi):
            continue
        if any(names_target(text, forms) for text in target_texts(r)):
            out[sid].append(r["event_uid"])
    return dict(out)


def load_explicit(ctx: Context, check_id: str) -> dict[str, list[dict[str, Any]]]:
    """4648 rows around the window, grouped by host (same widened range as the commands)."""
    p: Params = ctx.params
    before = max((p.cmd_before_s, *p.cmd_before_grid))
    after = max((p.cmd_after_s, *p.cmd_after_grid))
    rng = (to_db(ctx.window.start - seconds(before)), to_db(ctx.window.end + seconds(after)))
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in with_time(ctx.db.query(check_id, EXPLICIT_SQL, rng)):
        by_host[r["host"]].append(r)
    return dict(by_host)
