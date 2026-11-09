"""Provisional trial window (WN-01 … WN-05).

Each DB holds days of host history, so the counts need a scope. Until the T5 answer keys
exist, the scope is derived from attack signatures (anchors). That makes the window
circular for evaluation, hence the WN-03b warning in every report.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .db import Db
from .params import Params
from .timeutil import day_bounds, parse_utc, seconds, to_db, to_display

WN03B_WARNING = (
    "anchor-derived window — built from attack signatures; must NOT be used for evaluation "
    "(T7.6/T10 use T5 answer-key windows)"
)

ANCHOR_SQL = """
    SELECT event_uid, host, channel, event_id, event_utc, source_image, target_image,
           service_name, service_image_path, account_name
    FROM events_dedup
    WHERE event_utc >= ? AND event_utc < ?
      AND (
            (channel = 'Sysmon' AND event_id = 10
             AND lower(source_image) LIKE '%rundll32.exe' AND lower(target_image) LIKE '%lsass.exe')
         OR (channel = 'System' AND event_id = 7045)
         OR (channel = 'Security' AND event_id = 4697)
         OR (channel = 'WinRM' AND event_id = 91)
      )
    ORDER BY event_utc, event_uid
"""

ANCHOR_TYPES = {"a": "lsass_dump", "b": "service_windows_root_exe", "c": "winrm_scenario_account"}

_WINDOWS_ROOT_EXE = re.compile(r"^c:\\windows\\[^\\]+\.exe$", re.IGNORECASE)
_ROOT_ALIASES = (r"%systemroot%", r"%windir%", r"\systemroot")


@dataclass(frozen=True)
class Anchor:
    """One attack-signature event; `type` is the WN-02 letter (a, b or c)."""

    event_uid: str
    host: str
    time: datetime
    type: str
    detail: str

    def to_json(self) -> dict:
        return {"event_uid": self.event_uid, "host": self.host, "time": to_display(self.time),
                "type": self.type, "kind": ANCHOR_TYPES[self.type], "detail": self.detail}


@dataclass
class Window:
    """The window used to scope in-window counts, with everything needed to audit it."""

    start: datetime
    end: datetime
    status: str
    source: str                      # answer_key | override_csv | anchors | run_day
    flags: list[str] = field(default_factory=list)
    clusters: list[list[Anchor]] = field(default_factory=list)
    anchors: list[Anchor] = field(default_factory=list)
    note: str = ""

    @property
    def start_db(self) -> str:
        return to_db(self.start)

    @property
    def end_db(self) -> str:
        return to_db(self.end)

    def to_json(self) -> dict:
        return {
            "start_utc": to_display(self.start), "end_utc": to_display(self.end),
            "status": self.status, "source": self.source, "flags": list(self.flags),
            "clusters": [_cluster_json(i, c) for i, c in enumerate(self.clusters)],
            "anchors": [a.to_json() for a in self.anchors], "note": self.note,
            "warning": WN03B_WARNING,
        }


def _cluster_json(index: int, cluster: list[Anchor]) -> dict:
    """Clusters are summarised (span, types, size); their members are in `anchors`."""
    return {"index": index, "start": to_display(cluster[0].time), "end": to_display(cluster[-1].time),
            "size": len(cluster), "types": sorted({a.type for a in cluster}),
            "event_uids": [a.event_uid for a in cluster]}


def scenario_of(trial_id: str) -> str:
    """`s04_t00` → `s04`."""
    return trial_id.split("_", 1)[0]


def normalise_image_path(path: str | None) -> str:
    """Strip quotes/arguments and expand %SystemRoot% so WN-02(b) sees a plain file path."""
    if not path:
        return ""
    text = path.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        text = text[1:end] if end > 0 else text[1:]
    else:
        lower = text.lower()
        exe_at = lower.find(".exe")
        if exe_at >= 0:
            text = text[: exe_at + 4]
    lower = text.lower()
    for alias in _ROOT_ALIASES:
        if lower.startswith(alias):
            text = "C:\\Windows" + text[len(alias):]
            break
    return text


def is_windows_root_exe(path: str | None) -> bool:
    """WN-02(b): an .exe directly under C:\\Windows\\ (not system32, drivers or Program Files)."""
    return bool(_WINDOWS_ROOT_EXE.match(normalise_image_path(path)))


def classify_anchor(row: dict, params: Params) -> Anchor | None:
    """Turn a candidate row into an anchor, or None if it is not a WN-02 signature."""
    time = parse_utc(row["event_utc"])
    if row["channel"] == "Sysmon" and row["event_id"] == 10:
        return Anchor(row["event_uid"], row["host"], time, "a", f"{row['source_image']} -> lsass")
    if row["event_id"] in (7045, 4697) and is_windows_root_exe(row.get("service_image_path")):
        return Anchor(row["event_uid"], row["host"], time, "b",
                      f"{row['event_id']} {row.get('service_name')} {row.get('service_image_path')}")
    if row["channel"] == "WinRM" and row["event_id"] == 91 and \
            (row.get("account_name") or "") in params.scenario_accounts:
        return Anchor(row["event_uid"], row["host"], time, "c", f"WinRM 91 {row['account_name']}")
    return None


def cluster_anchors(anchors: list[Anchor], gap_s: float) -> list[list[Anchor]]:
    """WN-03: a gap > CLUSTER_GAP_S between consecutive anchors starts a new cluster."""
    ordered = sorted(anchors, key=lambda a: (a.time, a.event_uid))
    clusters: list[list[Anchor]] = []
    for anchor in ordered:
        if clusters and (anchor.time - clusters[-1][-1].time).total_seconds() <= gap_s:
            clusters[-1].append(anchor)
        else:
            clusters.append([anchor])
    return clusters


def choose_cluster(clusters: list[list[Anchor]]) -> tuple[int, bool]:
    """Index of the cluster that defines the window and whether it holds a dump anchor.

    Latest cluster with an (a)-type anchor wins; without dumps the largest cluster wins
    (ties → the latest, which matches "latest such cluster" for the dump case).
    """
    dump_idx = [i for i, c in enumerate(clusters) if any(a.type == "a" for a in c)]
    if dump_idx:
        return dump_idx[-1], True
    best = max(range(len(clusters)), key=lambda i: (len(clusters[i]), i))
    return best, False


def compute_window(anchors: list[Anchor], run_day: str, params: Params) -> Window:
    """WN-03/WN-04 from anchors only (no override, no key)."""
    day_start, day_end = day_bounds(run_day)
    if not anchors:
        return Window(day_start, day_end, "RUN_DAY_ONLY", "run_day", ["no_anchor", "no_dump"])
    clusters = cluster_anchors(anchors, params.cluster_gap_s)
    index, has_dump = choose_cluster(clusters)
    chosen = clusters[index]
    flags = [] if has_dump else ["no_dump"]
    if len(clusters) > 1:
        flags.append("multiple_clusters")
    return Window(chosen[0].time - seconds(params.margin_before_s),
                  chosen[-1].time + seconds(params.margin_after_s),
                  "PROVISIONAL", "anchors", flags, clusters, list(chosen),
                  note=f"cluster {index} of {len(clusters)}")


def load_override(csv_path: Path | None, trial_id: str) -> dict | None:
    """Row of provisional_windows.csv for this trial, if the file and row exist (WN-04)."""
    if csv_path is None or not csv_path.is_file():
        return None
    with csv_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if (row.get("trial_id") or "").strip() == trial_id:
                return row
    return None


def apply_override(window: Window, row: dict) -> Window:
    """Replace start/end/status with the CSV row; computed anchors stay listed for audit."""
    flags = [f for f in window.flags if f != "no_anchor"] + ["override_csv"]
    return Window(parse_utc(row["start_utc"]), parse_utc(row["end_utc"]),
                  (row.get("status") or "PROVISIONAL_OVERRIDE").strip(), "override_csv",
                  flags, window.clusters, window.anchors,
                  note=f"override: {row.get('anchors', '')}; {row.get('note', '')}".strip())


def apply_key_window(window: Window, start: datetime, end: datetime) -> Window:
    """WN-05: an approved answer-key window replaces any provisional one."""
    return Window(start, end, "ANSWER_KEY", "answer_key", window.flags + ["answer_key"],
                  window.clusters, window.anchors, note="answer-key window (T5)")


def fetch_anchors(db: Db, run_day: str, params: Params) -> list[Anchor]:
    """WN-02 anchors on the run day only (earlier days hold other campaigns)."""
    day_start, day_end = day_bounds(run_day)
    rows = db.query("WINDOW", ANCHOR_SQL, (to_db(day_start), to_db(day_end)))
    return [a for a in (classify_anchor(r, params) for r in rows) if a is not None]


def build_window(db: Db, trial_id: str, params: Params, override_csv: Path | None,
                 key_window: tuple[datetime, datetime] | None) -> Window:
    """Precedence: answer key (WN-05) > override CSV (WN-04) > anchors (WN-03) > run day."""
    run_day = params.run_day[scenario_of(trial_id)]
    window = compute_window(fetch_anchors(db, run_day, params), run_day, params)
    row = load_override(override_csv, trial_id)
    if row is not None:
        window = apply_override(window, row)
    if key_window is not None:
        window = apply_key_window(window, *key_window)
    return window
