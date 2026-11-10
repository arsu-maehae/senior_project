"""Write report.json, report.md and hop_candidates.csv (spec §3).

All three files are rendered from the same CheckResult list, so the markdown can never
disagree with the JSON. A final masking pass replaces every harvested secret literal in
every output (LC-13), as a second line of defence after per-field masking.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Iterable

from .common import CheckResult
from .window import WN03B_WARNING, Window

CSV_COLUMNS = [
    "trial_id", "protocol", "hop_id", "target_host", "target_event_uids", "target_time_utc",
    "account_name", "source_ip", "source_port", "source_host", "method",
    "candidate_count_sessions_before_account", "candidate_count_sessions_after_account",
    "candidate_count_rows", "time_delta_ms", "confidence_tier", "candidate_session_id",
    "candidate_account", "candidate_logon_type", "zero_reason", "supporting_event_uids",
    "candidate_count_sessions_after_4648_bridge",  # LC-04e, appended at the end
]

CHECK_ORDER = ["LC-01", "LC-02", "LC-03", "LC-04", "LC-04b", "LC-04c", "LC-04d", "LC-04h", "LC-05",
               "LC-06", "LC-07", "LC-08", "LC-08b", "LC-09", "LC-10", "LC-11"]


def scrub(text: str, secrets: Iterable[str]) -> str:
    """Replace secret literals anywhere in a rendered output."""
    for secret in sorted(set(secrets), key=len, reverse=True):
        text = text.replace(secret, "***")
    return text


def build_json(trial_id: str, db_path: str, db_sha256: str, window: Window,
               checks: list[CheckResult], sql_log: dict[str, list[str]], window_used: str) -> dict[str, Any]:
    """report.json structure of spec §3 (title/summary added for readability)."""
    ordered = sorted(checks, key=lambda c: CHECK_ORDER.index(c.check_id) if c.check_id in CHECK_ORDER else 99)
    return {
        "trial_id": trial_id, "db_path": db_path, "db_sha256": db_sha256,
        "window": {**window.to_json(), "window_used": window_used},
        "window_sql": sql_log.get("WINDOW", []),
        "checks": {c.check_id: {"title": c.title, "status": c.status, "summary": c.summary,
                                "effect": c.effect, "result": c.result,
                                "sql": sql_log.get(c.check_id, [])} for c in ordered},
    }


def _md_escape(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _hop_table(hops: list[dict]) -> list[str]:
    lines = ["| hop | protocol | target | account | source | t (first 4624) | port | rows | sessions before / after / after 4648 bridge | zero reason |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for h in hops:
        lines.append(f"| {h['hop_id']} | {h['protocol']} | {h['target_host']} | {h['account_name']} | "
                     f"{h['source_host'] or h['source_ip']} | {h['t_first_4624']} | {h['source_port']} | "
                     f"{h['candidate_count_rows']} | {h['candidate_count_sessions_before_account']} / "
                     f"{h['candidate_count_sessions_after_account']} / "
                     f"{h['candidate_count_sessions_after_4648_bridge']} | {h['zero_reason'] or ''} |")
        for c in h["candidates"]:
            lines.append(f"|  | ↳ {c['session_id']} | {c['account']} ({c['account_source']}) | "
                         f"type {c['logon_type']} | start {c['logon_start']} | first cmd {c['first_command_time']} | "
                         f"Δ {c['time_delta_ms']} ms | {c['processes']} proc | system={c['predefined_system']} | "
                         f"`{_md_escape(c['first_command'])[:120]}` |")
    return lines


def _dump_lines(result: dict) -> list[str]:
    lines = []
    for d in result["dumps"]:
        lines.append(f"- **{d['host']} {d['time']}** {d['source_image']} as {d['account_name']} "
                     f"({', '.join(map(str, d['granted_access']))}); 4624 sessions by state "
                     f"{d['sessions_4624_by_state']}")
        for s in d["sessions"]:
            if s["state"] == "open" or s["category"] in ("predefined", "unknown"):
                lines.append(f"  - {s['session_hex']} {s['account_name']} type {s['logon_type']} "
                             f"({s['category']}) start {s['start']} — {s['state']}")
        unknown = sum(1 for s in d["sessions"] if s["state"] == "end_unknown" and s["category"] not in ("predefined", "unknown"))
        if unknown:
            lines.append(f"  - plus {unknown} 4624 sessions with end_unknown (see report.json)")
    return lines


def _coverage_lines(result: dict) -> list[str]:
    """LC-04h: one line per hop, then one per 4648 session (session, accounts, cmdline match)."""
    lines = []
    for h in result["hops"]:
        lines.append(f"- {h['hop_id']} {h['protocol']} {h['account_name']}@{h['target_host']} from "
                     f"{h['source_host']}: n_4648 {h['n_4648']}, sessions {h['n_sessions']} "
                     f"(account match {h['account_match_counts']}), credentials {h['credentials_accounts']}, "
                     f"cmdline {h['cmdline_sessions_account_consistent']} → {h['comparison']}"
                     + (f" ({h['reason']})" if h["reason"] else ""))
        for s in h["sessions"]:
            lines.append(f"  - {s['session_id']} subject {s['subject_account']} creds {s['credentials_accounts']} "
                         f"(match {s['account_match']}, tier {s['confidence_tier']}) type {s['logon_type']} n {s['n_4648']} "
                         f"Δ {s['time_delta_ms']} ms servers {s['target_servers']}")
    for scope, block in result["summary"].items():
        lines.append(f"- summary ({scope}): with {len(block['with_naming_4648'])}, without "
                     f"{len(block['without_naming_4648'])}, differs {block['session_differs_from_cmdline']}, "
                     f"no cmdline session {block['naming_4648_but_no_cmdline_session']}")
    return lines


def _detail(c: CheckResult) -> list[str]:
    lines = [f"### {c.check_id} — {c.title}", "", f"**{c.status}** — {_md_escape(c.summary)}", "",
             f"Effect: {c.effect}", ""]
    r = c.result
    if c.check_id == "LC-04":
        lines += _hop_table(r["hops"]) + [""]
        for h in r["hops"]:
            for m in h["mismatch_table"]:
                lines.append(f"- mismatch {h['hop_id']}: session {m['session_id']} account {m['account']} "
                             f"≠ {m['hop_account']} (first cmd {m['first_command_time']})")
        lines.append(f"- excluded 4624: {r['excluded_4624']}")
    elif c.check_id == "LC-08":
        lines += _dump_lines(r)
    elif c.check_id == "LC-08b":
        for d in r["dumps"]:
            lines.append(f"- {d['host']} {d['time']}: " + ("; ".join(
                f"{e['account_name']} {e['session_id']} type {e['logon_type']} {e['state']} "
                f"cmd≤10min={e['ran_command_within_10min']}" for e in d["sessions"]) or "none"))
        if "s04_a" in r:
            lines.append(f"- **S04-A answer:** {r['s04_a']['answer']}")
    elif c.check_id == "LC-09":
        for key in ("kerberos_vs_dc01_ms", "security4688_minus_sysmon1_ms", "sysmon_record_gap_s"):
            lines.append(f"- {key}:")
            for host, stats in r[key].items():
                lines.append(f"  - {host}: {stats}")
        lines.append(f"- flags: {r['flags']}")
    elif c.check_id == "LC-04c":
        for s in r["services"]:
            if not s["system_binary"]:
                lines.append(f"- {s['host']} {s['time']} {s['service_name']} `{s['image_path']}` → "
                             f"{s['match']} {s['admin_write_sessions']} hops {s['hops']}; 4697 subject "
                             f"{s['subject_logon_ids_4697']} {s['subject_hops_4697']}")
        lines.append(f"- service match counts: {r['service_match_counts']}; SMB hops with port 0: "
                     f"{r['smb_hops_port0']}/{r['smb_hops']}")
    elif c.check_id == "LC-04h":
        lines += _coverage_lines(r)
    elif c.check_id == "LC-06":
        for h in r["winrm_hops"]:
            lines.append(f"- {h['hop_id']} {h['account_name']}@{h['target_host']} from {h['source_host']}: "
                         f"joins {len(h['port_joins'])}, WinRM91 {len(h['winrm91'])}, wsmprovhost "
                         f"{len(h['wsmprovhost'])}, source sessions {h['source_sessions']}")
    else:
        for key, value in r.items():
            if isinstance(value, (int, float, str, bool)) or value is None:
                lines.append(f"- {key}: {value}")
            elif isinstance(value, dict) and len(json.dumps(value)) < 400:
                lines.append(f"- {key}: `{json.dumps(value)}`")
    lines.append("")
    return lines


def build_markdown(report: dict[str, Any], checks: list[CheckResult]) -> str:
    """Check table first, then the WN-03b warning and window, then per-check detail (§3)."""
    w = report["window"]
    ordered = sorted(checks, key=lambda c: CHECK_ORDER.index(c.check_id) if c.check_id in CHECK_ORDER else 99)
    lines = [f"# Log check — {report['trial_id']}", "",
             f"DB `{report['db_path']}` · sha256 `{report['db_sha256']}`", "",
             "| check | result | status | effect on stitching / identity |", "|---|---|---|---|"]
    for c in ordered:
        lines.append(f"| {c.check_id} {_md_escape(c.title)} | {_md_escape(c.summary)} | {c.status} | {_md_escape(c.effect)} |")
    lines += ["", f"> **Warning (WN-03b):** {WN03B_WARNING}", "",
              f"**Window used ({w['window_used']}):** {w['start_utc']} → {w['end_utc']} · status `{w['status']}` · "
              f"flags {w['flags']} · {w['note']}", ""]
    for cl in w["clusters"]:
        lines.append(f"- cluster {cl['index']}: {cl['start']} → {cl['end']}, {cl['size']} anchors, types {cl['types']}")
    for a in w["anchors"]:
        lines.append(f"  - anchor ({a['type']}) {a['host']} {a['time']} {a['detail']} `{a['event_uid'][:12]}…`")
    lines += ["", "## Per-check detail", ""]
    for c in ordered:
        lines += _detail(c)
    return "\n".join(lines) + "\n"


def build_csv(rows: list[dict[str, Any]]) -> str:
    """hop_candidates.csv with exactly the spec §3 columns, in that order."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n", extrasaction="raise")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: ("" if row.get(k) is None else row.get(k)) for k in CSV_COLUMNS})
    return buffer.getvalue()


def write_outputs(out_dir: Path, report: dict[str, Any], markdown: str, csv_text: str,
                  secrets: Iterable[str]) -> list[Path]:
    """Create/overwrite the three files in out/log_check/<trial_id>/ only (LC-11)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    secrets = list(secrets)
    files = {
        "report.json": scrub(json.dumps(report, indent=2, ensure_ascii=False, default=str), secrets),
        "report.md": scrub(markdown, secrets),
        "hop_candidates.csv": scrub(csv_text, secrets),
    }
    written = []
    for name, text in files.items():
        path = out_dir / name
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(path)
    return written
