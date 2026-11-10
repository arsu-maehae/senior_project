"""Trial overlap and shared-background checks (owner decision 2026-11-10).

Trials of one day share a DB's day-level background (e.g. the 07:05:15 admin_it logon is in
the s05, s06 and s07 DBs). A background (leftover) hop is therefore flagged ``shared_with_trial``
when the same event content (``duplicate_content_sha256`` of its target 4624) also exists in
another trial DB. Other DBs are opened read-only through ``db.open_ro``; nothing is written
to them. Pure helpers take plain dicts; the DB lookups are isolated in ``shas_in_db``.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence

from .db import VIEW, open_ro

SHARED_FLAG = "shared_with_trial"


def _t(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def intervals_overlap(a: Mapping, b: Mapping) -> bool:
    """True when two {start_utc, end_utc} intervals share any instant."""
    return _t(a["start_utc"]) < _t(b["end_utc"]) and _t(b["start_utc"]) < _t(a["end_utc"])


def overlapping_pairs(intervals: Mapping[str, Mapping | None]) -> list[dict]:
    """Every pair of trials whose run intervals overlap (trials without an interval are skipped)."""
    ids = sorted(k for k, v in intervals.items() if v)
    return [{"trials": [x, y], "intervals": [intervals[x], intervals[y]]}
            for i, x in enumerate(ids) for y in ids[i + 1:] if intervals_overlap(intervals[x], intervals[y])]


def shas_in_db(db_path: Path, shas: Sequence[str]) -> set[str]:
    """Which of ``shas`` occur as ``duplicate_content_sha256`` in the DB view ``events_dedup`` (read-only)."""
    if not shas:
        return set()
    con = open_ro(db_path)
    try:
        marks = ",".join("?" for _ in shas)
        return {r[0] for r in con.execute(
            f"SELECT DISTINCT duplicate_content_sha256 FROM {VIEW} WHERE event_id = 4624 AND "
            f"duplicate_content_sha256 IN ({marks})", tuple(shas))}
    finally:
        con.close()


def shared_trials(processed: Path, own_trial: str, shas: Sequence[str]) -> dict[str, list[str]]:
    """sha -> other trial ids whose DB holds the same event content."""
    out: dict[str, list[str]] = {s: [] for s in shas}
    for dbp in sorted(processed.glob("*.sqlite3")):
        trial = dbp.name[: -len(".sqlite3")]
        if trial == own_trial:
            continue
        for sha in shas_in_db(dbp, shas):
            out[sha].append(trial)
    return out


def annotate_shared(draft: dict, processed: Path) -> None:
    """Flag background hops whose target 4624 content also exists in another trial DB (in place)."""
    bg = [h for h in draft["hops"] if h.get("role") == "background" and h.get("target_4624_content_sha256")]
    found = shared_trials(processed, draft["trial_id"], sorted({h["target_4624_content_sha256"] for h in bg}))
    for h in bg:
        others = found.get(h["target_4624_content_sha256"], [])
        h["shared_with_trials"] = others
        if others and SHARED_FLAG not in h["flags"]:
            h["flags"].append(SHARED_FLAG)


def overlap_report(drafts: Mapping[str, dict]) -> dict:
    """Overlapping run intervals plus every background hop and the trials sharing its content."""
    intervals = {t: (d.get("agent") or {}).get("run_interval") for t, d in drafts.items()}
    shared = [{"trial": t, "hop_id": h["hop_id"], "move_time_utc": h.get("move_time_utc"),
               "shared_with_trials": h.get("shared_with_trials", [])}
              for t, d in sorted(drafts.items()) for h in d["hops"]
              if h.get("role") == "background" and h.get("shared_with_trials")]
    return {"run_intervals": intervals, "overlapping_pairs": overlapping_pairs(intervals),
            "shared_background_hops": shared}


def to_markdown(rep: Mapping) -> str:
    """Short human-readable overlap report."""
    lines = ["# Trial overlap", "", "## Run intervals", ""]
    lines += [f"- {t}: {v['start_utc']} .. {v['end_utc']}" if v else f"- {t}: none" for t, v in rep["run_intervals"].items()]
    lines += ["", f"## Overlapping pairs: {len(rep['overlapping_pairs'])}", ""]
    lines += [f"- {p['trials'][0]} / {p['trials'][1]}" for p in rep["overlapping_pairs"]]
    lines += ["", f"## Background hops shared with another trial DB: {len(rep['shared_background_hops'])}", ""]
    lines += [f"- {s['trial']} {s['hop_id']} ({s['move_time_utc']}): also in {', '.join(s['shared_with_trials'])}"
              for s in rep["shared_background_hops"]]
    return "\n".join(lines) + "\n"
