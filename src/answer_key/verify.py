"""Existence check for a draft key (AK-15, PLAN 5.5).

Independent of the builder: shares only the read-only DB opener (``db.py``). It reads the
draft and the DB, nothing else. Checks: DB hash equals the draft's ``db_sha256``; every
uid exists in ``events_dedup``; host, channel, event id, record id and time agree with the
content key stored in the draft (so an existing-but-wrong uid is caught); out-of-window
uids are counted, not failed; counts per kind are reported.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .db import open_ro, sha256_file

LIST_KEYS = ("event_uids", "agent_event_uids", "target_event_uids", "dump_event_uids", "stray_target_side_event_uids",
             "agent_corroboration_4688_uids", "sysmon3_event_uids", "command_event_uids", "target_events_tied_by_name")


def load_draft(path: Path) -> dict:
    """Drafts are JSON-compatible YAML (see __main__), so the stdlib parser reads them."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def uids_with_context(node, where: str = "") -> list[tuple[str, str]]:
    """(uid, location) for every uid referenced in the draft, excluding the event_keys table."""
    out: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "event_keys":
                continue
            loc = f"{where}/{k}"
            if k in LIST_KEYS and isinstance(v, list):
                out += [(u, loc) for u in v if isinstance(u, str)]
            elif k in ("event_uid", "dump_event_uid", "session_logon_uid", "uid") and isinstance(v, str):
                out.append((v, loc))
            else:
                out += uids_with_context(v, loc)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += uids_with_context(v, f"{where}[{i}]")
    return out


def _fetch(con, uid: str):
    return con.execute("SELECT host, channel, event_id, record_id, COALESCE(event_utc, timestamp_utc) AS t "
                       "FROM events_dedup WHERE event_uid = ?", (uid,)).fetchone()


def verify(draft: dict, db_path: Path) -> dict:
    """Return the verification report (a dict); ``ok`` is False on any failure."""
    report: dict = {"trial_id": draft.get("trial_id"), "db_sha256_draft": draft.get("db_sha256"),
                    "db_sha256_now": sha256_file(db_path), "failures": [], "out_of_window": 0, "checked": 0,
                    "per_kind": {}}
    if report["db_sha256_draft"] != report["db_sha256_now"]:
        report["failures"].append({"type": "db_hash_mismatch"})
        report["ok"] = False
        return report
    keys = draft.get("event_keys", {})
    win = draft.get("window", {})
    lo, hi = win.get("start_utc"), win.get("end_utc")
    kinds: Counter = Counter()
    con = open_ro(db_path)
    try:
        refs = uids_with_context(draft)
        for uid, loc in refs:
            report["checked"] += 1
            row = _fetch(con, uid)
            if row is None:
                report["failures"].append({"type": "missing_uid", "uid": uid, "at": loc})
                continue
            key = keys.get(uid)
            if key is None:
                report["failures"].append({"type": "no_content_key", "uid": uid, "at": loc})
                continue
            got = {"host": row["host"], "channel": row["channel"], "event_id": row["event_id"],
                   "record_id": row["record_id"], "time_utc": row["t"]}
            bad = [f for f in got if got[f] != key.get(f)]
            if bad:
                report["failures"].append({"type": "content_key_mismatch", "uid": uid, "at": loc, "fields": bad})
            kinds[f"{row['channel']} {row['event_id']}"] += 1
            if lo and hi and not (lo <= row["t"] <= hi):
                report["out_of_window"] += 1
    finally:
        con.close()
    report["per_kind"] = dict(sorted(kinds.items()))
    report["ok"] = not report["failures"]
    if sha256_file(db_path) != report["db_sha256_now"]:
        report["failures"].append({"type": "db_changed_during_verify"})
        report["ok"] = False
    return report


def to_markdown(rep: dict) -> str:
    """Short human-readable verify report."""
    lines = [f"# Verify {rep['trial_id']}", "", f"- ok: {rep['ok']}", f"- uid references checked: {rep['checked']}",
             f"- out-of-window (counted, not failed): {rep['out_of_window']}",
             f"- failures: {len(rep['failures'])}", "", "## Per kind", ""]
    lines += [f"- {k}: {v}" for k, v in rep["per_kind"].items()]
    if rep["failures"]:
        lines += ["", "## Failures", ""] + [f"- {json.dumps(f)}" for f in rep["failures"][:50]]
    return "\n".join(lines) + "\n"
