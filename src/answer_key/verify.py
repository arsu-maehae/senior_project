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

from datetime import datetime

from .db import open_ro, sha256_file

LIST_KEYS = ("event_uids", "agent_event_uids", "target_event_uids", "dump_event_uids", "stray_target_side_event_uids",
             "agent_corroboration_4688_uids", "sysmon3_event_uids", "command_event_uids", "target_events_tied_by_name",
             "logon_uids", "credential_logon_uids", "related_logon_uids", "port_join_event_uids")

# Event kinds a uid may have, by the key it is stored under (channel, event id). ``None`` = not checked
# (``event_uids`` of a step is a mixed list). Written here, not imported from the builder (independence).
_TARGET_SIDE = {("Security", 4624), ("Security", 5140), ("Security", 5145), ("Security", 4697), ("System", 7045),
                ("WinRM", 91)}
_PROCESS = {("Sysmon", 1), ("Security", 4688)}
EXPECTED_KINDS: dict[str, set[tuple[str, int]]] = {
    "dump_event_uid": {("Sysmon", 10)}, "dump_event_uids": {("Sysmon", 10)},
    "target_event_uids": _TARGET_SIDE, "target_events_tied_by_name": _TARGET_SIDE,
    "stray_target_side_event_uids": {("Security", 5140), ("Security", 5145), ("Security", 4697), ("System", 7045)},
    "agent_event_uids": _PROCESS, "command_event_uids": _PROCESS,
    "agent_corroboration_4688_uids": {("Security", 4688)}, "sysmon3_event_uids": {("Sysmon", 3)},
    "port_join_event_uids": {("Sysmon", 3)},
    "logon_uids": {("Security", 4624)}, "credential_logon_uids": {("Security", 4624)},
    "related_logon_uids": {("Security", 4624)}, "session_logon_uid": {("Security", 4624)},
}
# a wsmprovhost start (WinRM session artefact) is a process event stored in target_event_uids
_WSMPROV = {"target_event_uids"}


def parse_time(text: str) -> datetime:
    """ISO-8601 UTC (``...Z``) to an aware datetime, so times compare as instants, not as strings."""
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


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
    return con.execute("SELECT host, channel, event_id, record_id, image, COALESCE(event_utc, timestamp_utc) AS t "
                       "FROM events_dedup WHERE event_uid = ?", (uid,)).fetchone()


def kind_ok(key: str, row) -> bool:
    """True when the stored event has an event type allowed at this location of the draft."""
    allowed = EXPECTED_KINDS.get(key)
    if allowed is None:
        return True
    kind = (row["channel"], row["event_id"])
    if kind in allowed:
        return True
    return (key in _WSMPROV and kind in _PROCESS and (row["image"] or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
            == "wsmprovhost.exe")


def _same_time(a: str | None, b: str | None) -> bool:
    """Equal instants (string formats may differ)."""
    try:
        return a is not None and b is not None and parse_time(a) == parse_time(b)
    except ValueError:
        return a == b


def lock_status(draft: dict) -> dict:
    """Lock readiness (informational), owner rule: (a) every hop has a role; (b) no non-excluded
    attack/benign hop is unconfirmed; (c) every non-excluded background hop is ``reviewed``;
    (d) every excluded hop has a non-empty ``excluded_reason``.

    WHY: background hops can never be confirmed by design, so the owner's review replaces confirmation.
    """
    blockers = []
    for h in draft.get("hops", []):
        hid, role, excluded = h.get("hop_id"), h.get("role"), bool(h.get("excluded"))
        if role not in ("attack", "benign", "background"):
            blockers.append({"hop_id": hid, "reason": f"role missing or invalid: {role}"})
        if excluded and not (h.get("excluded_reason") or "").strip():
            blockers.append({"hop_id": hid, "reason": "excluded without excluded_reason"})
        if excluded:
            continue
        if role in ("attack", "benign") and h.get("status") != "confirmed":
            blockers.append({"hop_id": hid, "reason": f"status {h.get('status')}: {h.get('reason')}"})
        if role == "background" and not h.get("reviewed"):
            blockers.append({"hop_id": hid, "reason": "background hop not reviewed"})
    return {"lock_ready": not blockers, "lock_blockers": blockers}


def verify(draft: dict, db_path: Path) -> dict:
    """Return the verification report (a dict); ``ok`` is False on any failure."""
    report: dict = {"trial_id": draft.get("trial_id"), "db_sha256_draft": draft.get("db_sha256"),
                    "db_sha256_now": sha256_file(db_path), "failures": [], "out_of_window": 0, "checked": 0,
                    "per_kind": {}, **lock_status(draft)}
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
            bad = [f for f in got if not (_same_time(got[f], key.get(f)) if f == "time_utc" else got[f] == key.get(f))]
            if bad:
                report["failures"].append({"type": "content_key_mismatch", "uid": uid, "at": loc, "fields": bad})
            if not kind_ok(loc.rsplit("/", 1)[-1].split("[")[0], row):
                report["failures"].append({"type": "wrong_event_type", "uid": uid, "at": loc,
                                           "found": f"{row['channel']} {row['event_id']}"})
            kinds[f"{row['channel']} {row['event_id']}"] += 1
            if lo and hi and not (parse_time(lo) <= parse_time(row["t"]) <= parse_time(hi)):
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
             f"- failures: {len(rep['failures'])}", f"- lock_ready: {rep['lock_ready']}", "", "## Per kind", ""]
    lines += [f"- {k}: {v}" for k, v in rep["per_kind"].items()]
    if rep["lock_blockers"]:
        lines += ["", "## Lock blockers (informational)", ""] + [f"- {b['hop_id']}: {b['reason']}" for b in rep["lock_blockers"]]
    if rep["failures"]:
        lines += ["", "## Failures", ""] + [f"- {json.dumps(f)}" for f in rep["failures"][:50]]
    return "\n".join(lines) + "\n"
