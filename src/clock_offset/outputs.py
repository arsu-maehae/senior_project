"""Rows, text and files of the clock offset step (spec 08 section 3; CO-14 byte-identical reruns).

WHY all formatting here: the byte-identical rule is easiest to keep when one module owns the
column order, NULL -> empty cell, booleans as ``true``/``false``, line endings and JSON layout.
Everything except ``write_text`` and ``write_outputs`` is pure; those two only write what they get.
"""
from __future__ import annotations

import csv
import io
import json
import shutil
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import params
from .common import us_to_ms
from .pairs import Pair

Row = dict[str, Any]


def cell(value: Any) -> Any:
    """CSV cell form: None -> empty, bool -> ``true``/``false`` (spec 3 ``host_has_events`` is bool)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def csv_text(rows: Iterable[Mapping], columns: Sequence[str]) -> str:
    """CSV with ``\\n`` line endings, columns in the given order; a missing or extra key is an error."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(columns), lineterminator="\n", extrasaction="raise")
    w.writeheader()
    for row in rows:
        w.writerow({c: cell(row[c]) for c in columns})
    return buf.getvalue()


def json_text(obj: Any) -> str:
    """Stable JSON: sorted keys, indent 2, UTF-8 characters kept, final newline."""
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def pair_row(p: Pair) -> Row:
    """One pairs.csv row; ``time_delta_ms`` = ``delta_ms`` (spec 3), times are the original event_utc text."""
    d = us_to_ms(p.delta_us)
    return {"host": p.host, "event_uid_4624": p.e4624["event_uid"], "event_uid_4769": p.e4769["event_uid"],
            "logon_guid": p.guid, "t_4624_utc": p.e4624["event_utc"], "t_4769_utc": p.e4769["event_utc"],
            "delta_ms": d, "logon_type": p.e4624.get("logon_type"), "account_name": p.e4624.get("account_name"),
            "service_name": p.e4769.get("service_name"), "method": params.METHOD,
            "candidate_count": p.candidate_count, "time_delta_ms": d}


def pair_brief(p: Pair) -> dict[str, Any]:
    """Short form of a dropped pair for stats.json, so every removal stays traceable to its uids."""
    return {"event_uid_4624": p.e4624["event_uid"], "event_uid_4769": p.e4769["event_uid"],
            "t_4624_utc": p.e4624["event_utc"], "delta_ms": us_to_ms(p.delta_us)}


def _fmt(v: Any) -> str:
    """Report cell: None -> ``-``, booleans as ``true``/``false`` (as in the CSV files)."""
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def clock_change_lines(stats: Mapping[str, Any], pre_steps: Sequence[Mapping] | None) -> list[str]:
    """Report section for the clock changes (owner D1-D4): counts by classification and one line per
    counted step inside the agent window, with its pre-step event counts."""
    s = stats.get("clock_change_scan")
    if not s:
        return []
    by = s["by_classification"]
    lines = ["", "## Clock changes (CO-15/CO-18/CO-19; counted when |shift| >= "
             f"{s['min_clock_step_ms']} ms or shift unknown)", "",
             f"- export scan run: {str(s['export_scan_run']).lower()}; export hits {_fmt(s['export_hits'])}, "
             f"DB clock-change rows {s['db_clock_changes']}; files read {_fmt(s['files_read'])}, "
             f"skipped {_fmt(s['files_skipped'])}; clock scan {_fmt(s.get('clock_scan'))}",
             "- by classification: " + ", ".join(f"{k} {v}" for k, v in by.items()),
             f"- expected {s['expected_count']}, unexpected {s['unexpected_count']}, routine {s['routine_count']}; "
             f"clock_change_in_window: {_fmt(s['clock_change_in_window'])}"]
    if s["db_shift_unresolved"]:
        lines.append(f"- DB clock-change rows with unknown shift (counted): {len(s['db_shift_unresolved'])}")
    if pre_steps:
        lines += ["", "Counted steps inside the agent window (D4: (a) logged before the step with real time "
                  "in the window; (b) recorded in [window start, step)):", "",
                  "| host | step (UTC) | source | previous_time | new_time | shift_ms | last boot before | "
                  "logged before | (a) | (b) |", "|---|---|---|---|---|---|---|---|---|---|"]
        for p in pre_steps:
            lines.append("| " + " | ".join(_fmt(p[k]) for k in (
                "host", "step_utc", "source", "previous_time", "new_time", "shift_ms", "last_boot_before_utc",
                "logged_before_count", "a_real_time_in_window_count", "b_literal_in_window_before_step_count"))
                + " |")
    return lines


def report_md(stats: Mapping[str, Any], rows: Sequence[Mapping], pre_steps: Sequence[Mapping] | None = None) -> str:
    """Short human-readable summary built only from stats.json, the offsets rows and the D4 pre-step data
    (deterministic)."""
    w = stats["window"]
    lines = [f"# Clock offset report: {stats['trial_id']} ({stats['trial_role']})", "",
             f"- DB: `{stats['db']['path']}` sha256 `{stats['db']['sha256_before']}` (after: same = "
             f"{str(stats['db']['sha256_before'] == stats['db']['sha256_after']).lower()})",
             f"- Agent window (raw): {w['start_utc']} .. {w['end_utc']}; last agent event {w['last_agent_event_utc']}",
             f"- Search span: {stats['search_span']['start_utc']} .. {stats['search_span']['end_utc']} "
             f"(dc01 4769 +-{stats['parameters']['DC_EDGE_S']:g} s more)",
             f"- Method: `{stats['method']}`", "",
             "## Offsets (host - dc01)", "",
             "| host | status | offset_ms | unc_ms | n_pairs | dropped far | lab-IP pairs | median_ms | "
             "loo_shift_ms | pair_span_s | late_gap_s | has events |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| " + " | ".join(_fmt(r[k]) for k in (
            "host", "offset_status", "offset_ms", "offset_unc_ms", "n_pairs", "n_dropped_far", "n_pairs_lab_ip",
            "median_ms", "loo_shift_ms", "pair_span_s", "late_gap_s")) + f" | {str(r['host_has_events']).lower()} |")
    lines += ["", f"- clock_flag: {', '.join(stats['clock_flag']) or 'none'}",
              f"- clock_change_in_window (CO-19 scan): {_fmt(stats['clock_change_in_window'])}",
              f"- CO-17 preview on the raw window start: {stats['co17_refusal_preview'] or 'no refusal'}", "",
              "## Evidence", "", f"- dc01 4769 with a LogonGuid in the edge-widened span: "
              f"{stats['evidence']['dc01_4769_guid']}", "",
              "| host | 4624 with GUID | with a 4769 partner | mutual pairs | lost mutual-nearest | dropped far | "
              "dropped before change | kept |", "|---|---|---|---|---|---|---|---|"]
    for host, e in sorted(stats["evidence"]["per_host"].items()):
        lines.append(f"| {host} | {e['n_4624_guid']} | {e['n_4624_with_candidate']} | {e['mutual_pairs']} | "
                     f"{e['dropped_by_mutual_nearest']} | {e['n_dropped_far']} | {e['n_dropped_before_change']} | "
                     f"{e['n_pairs']} |")
    s = stats["check"]["summary"]
    lines += ["", "## Independent check (CO-10, raw-time IpPort join; never used in the estimate)", "",
              f"- groups {s['groups']}, pairs {s['pairs']}, worst |raw| {_fmt(s['worst_raw_abs_ms'])} ms, "
              f"worst |corrected| {_fmt(s['worst_corrected_abs_ms'])} ms",
              f"- above review level ({stats['parameters']['CHECK_REVIEW_S']:g} s): {s['review_count']}; "
              f"above kill level ({stats['parameters']['CHECK_KILL_S']:g} s): {s['kill_count']}; "
              f"ambiguous: {s['ambiguous_count']}; not correctable: {s['uncorrected_count']}; "
              f"Sysmon 3 without a target 4624: {s['unjoined_sysmon3']}"]
    for g in s["per_group"]:
        lines.append(f"  - {g['group']}: {g['pairs']} pair(s), worst |raw| {g['worst_raw_abs_ms']} ms -> "
                     f"worst |corrected| {_fmt(g['worst_corrected_abs_ms'])} ms; net effect "
                     + ", ".join(f"{k} {v}" for k, v in g["net_effect"].items()))
    lines += clock_change_lines(stats, pre_steps)
    lines += ["", "Limits: dc01 is the reference clock, not true time; one offset per host per trial, so a clock "
              "step inside the trial is not modelled (spec 08 section 9).", ""]
    return "\n".join(lines)


def write_text(path: Path, text: str) -> None:
    """Write one file as UTF-8 without BOM with ``\\n`` endings (byte-identical reruns)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def write_outputs(out_dir: Path, files: Mapping[str, str]) -> None:
    """Empty ``out_dir`` (rebuilt on every run) and write each file with ``write_text``."""
    out_dir = Path(out_dir)
    if out_dir.exists():
        for child in out_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        write_text(out_dir / name, text)
