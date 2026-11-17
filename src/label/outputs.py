"""Writer side of the label CSVs (spec 04_label section 3.4; LB-09, LB-11, LB-13).

WHY built field by field from named columns: the only text columns are uids, hosts, channels, rule ids and titles,
technique and tactic ids, levels and the method name, so no command line, script block, ContextInfo, Payload or
service image path can reach a file (LB-09). ``csv_text`` (the stitcher's, ``stitch.outputs``) refuses a row whose
keys differ from the column list, so a column cannot be added or dropped silently. Pure: no file is opened.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Sequence

from gate.timeutil import fmt_us
from stitch.outputs import csv_text

from .labels import Match
from .params import METHOD

__all__ = ["EVENT_LABELS_FILE", "NODE_LABELS_FILE", "HOP_LABELS_FILE", "RULES_MANIFEST_FILE", "STATS_FILE",
           "REPORT_FILE", "RUN_INFO_FILE", "OUTPUT_FILES", "EVENT_COLUMNS", "NODE_COLUMNS", "HOP_COLUMNS",
           "event_label_row", "event_label_rows", "table", "csv_text"]

EVENT_LABELS_FILE, NODE_LABELS_FILE, HOP_LABELS_FILE = "event_labels.csv", "node_labels.csv", "hop_labels.csv"
RULES_MANIFEST_FILE, STATS_FILE, REPORT_FILE, RUN_INFO_FILE = ("rules_manifest.csv", "stats.json", "report.md",
                                                               "run_info.json")
# The seven files of spec 3.4, sorted: the only names an existing ``--out`` folder may hold (decision 054 style).
OUTPUT_FILES: tuple[str, ...] = tuple(sorted((EVENT_LABELS_FILE, NODE_LABELS_FILE, HOP_LABELS_FILE,
                                              RULES_MANIFEST_FILE, STATS_FILE, REPORT_FILE, RUN_INFO_FILE)))

# Spec 3.4, in spec order. No tier columns: a label row links no events (decision 045 scope, Q8).
EVENT_COLUMNS: tuple[str, ...] = (
    "trial_id", "event_uid", "dup_uids", "host", "channel", "event_id", "record_id", "event_utc",
    "event_utc_corrected", "rule_id", "rule_title", "rule_source", "sigma_id", "technique", "techniques", "tactics",
    "level", "level_value", "count_key", "method", "clock_unreliable",
)
NODE_COLUMNS: tuple[str, ...] = (
    "path_id", "hop_id", "role", "context", "host", "event_uid", "labelled", "rule_ids", "techniques",
    "max_level_value",
)
HOP_COLUMNS: tuple[str, ...] = (
    "hop_id", "in_path", "n_node_events", "n_labelled_node_events", "techniques", "dump_event_uids", "dump_labelled",
    "dump_rule_ids", "dump_max_level_value",
)


def event_label_row(trial_id: str, m: Match, count_key: str) -> dict[str, str]:
    """One ``event_labels.csv`` row. Times as the stitcher writes them (microseconds, ``Z``; LB-13): the logged time
    and the corrected time (CO-09)."""
    e, r = m.event, m.rule
    return {
        "trial_id": trial_id, "event_uid": e.uid, "dup_uids": "|".join(e.dup_uids), "host": e.host,
        "channel": e.channel, "event_id": str(e.event_id), "record_id": "" if e.record_id is None else str(e.record_id),
        "event_utc": fmt_us(e.us_raw), "event_utc_corrected": fmt_us(e.us), "rule_id": r.rule_id,
        "rule_title": r.title, "rule_source": r.source, "sigma_id": r.sigma_id, "technique": r.technique,
        "techniques": ";".join(r.techniques), "tactics": ";".join(r.tactics), "level": r.level,
        "level_value": str(r.level_value), "count_key": count_key, "method": METHOD,
        "clock_unreliable": str(e.clock_unreliable),
    }


def event_label_rows(trial_id: str, matches: Sequence[Match], keys: Mapping[str, str]) -> list[dict[str, str]]:
    """Every label row in LB-13 order (corrected time, uid, rule id); ``count_key`` from ``events.count_keys``."""
    return [event_label_row(trial_id, m, keys.get(m.event.uid, m.event.uid))
            for m in sorted(matches, key=Match.sort_key)]


def table(columns: Sequence[str], rows: Iterable[Mapping[str, str]]) -> tuple[str, int]:
    """(CSV text, data row count)."""
    rows = list(rows)
    return csv_text(columns, rows), len(rows)
