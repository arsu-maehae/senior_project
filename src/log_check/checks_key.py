"""LC-10 and WN-05: answer-key anchors and the answer-key window.

No approved key exists yet and the key format (T5) is not fixed, and PyYAML is not a
dependency. So the key is read with two narrow text rules instead of a YAML parser:
every 64-hex token is an event_uid, and `start_utc:` / `end_utc:` lines give the window.
T5 should confirm or replace this when the key schema is approved.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from .common import NOT_MEASURABLE, OK, PROBLEM, CheckResult, Context
from .db import in_list
from .timeutil import parse_utc

UID_RE = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)
WINDOW_RE = {k: re.compile(rf"^\s*{k}\s*:\s*['\"]?([0-9T:.\-]+Z?)['\"]?\s*$", re.MULTILINE)
             for k in ("start_utc", "end_utc")}

PRESENT_SQL = "SELECT event_uid FROM events_dedup WHERE event_uid IN {uids}"


def key_path(keys_dir: Path | None, trial_id: str) -> Path | None:
    """`ground_truth/approved/<trial_id>.yaml` if it exists."""
    if keys_dir is None:
        return None
    path = keys_dir / f"{trial_id}.yaml"
    return path if path.is_file() else None


def key_uids(text: str) -> list[str]:
    """All event_uids listed in a key, in order, without duplicates."""
    return list(dict.fromkeys(m.group(0).lower() for m in UID_RE.finditer(text)))


def key_window(text: str) -> tuple[datetime, datetime] | None:
    """(start, end) from the first `start_utc:` and `end_utc:` lines, if both exist."""
    found = {k: rx.search(text) for k, rx in WINDOW_RE.items()}
    if not all(found.values()):
        return None
    return parse_utc(found["start_utc"].group(1)), parse_utc(found["end_utc"].group(1))


def load_key_window(keys_dir: Path | None, trial_id: str) -> tuple[datetime, datetime] | None:
    path = key_path(keys_dir, trial_id)
    return key_window(path.read_text(encoding="utf-8")) if path else None


def run_lc10(ctx: Context, keys_dir: Path | None) -> CheckResult:
    """LC-10: every event the key lists is present in events_dedup."""
    path = key_path(keys_dir, ctx.trial_id)
    effect = "Answer-key anchors must exist in the DB before T7.6/T10 can evaluate."
    if path is None:
        return CheckResult("LC-10", "Answer-key anchors present", NOT_MEASURABLE, "no key yet", effect,
                           {"key_path": None})
    uids = key_uids(path.read_text(encoding="utf-8"))
    present: set[str] = set()
    if uids:
        rows = ctx.db.query("LC-10", PRESENT_SQL.format(uids=in_list(uids)), uids)
        present = {r["event_uid"] for r in rows}
    missing = [u for u in uids if u not in present]
    status = OK if uids and not missing else PROBLEM
    return CheckResult("LC-10", "Answer-key anchors present", status,
                       f"{len(uids) - len(missing)}/{len(uids)} key event_uids present", effect,
                       {"key_path": str(path), "listed": len(uids), "missing": missing})
