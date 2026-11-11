"""Turn rule drafts into the spec 02_gate section 3 rows, dispositions, stats and report; write them.

WHY all formatting here: the byte-identical rule (GTT-08) is easiest to keep when one module
owns sorting, NULL -> empty cell, line endings and JSON layout. Everything except ``write_outputs``
is pure; ``write_outputs`` only writes what it is given.
"""
from __future__ import annotations

import csv
import io
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import classify
from .classify import Suppression, ip_kind, ip_text, logon_hex, logon_id
from .params import DISPOSITIONS
from .rules import TriggerDraft
from .timeutil import delta_ms

Row = dict[str, Any]


# ---------------------------------------------------------------- trigger rows

def time_delta(d: TriggerDraft) -> int | None:
    """Earliest of (trigger if it is not the anchor, supporting events) - anchor, in ms; None without
    an anchor or when the anchor is the only event (decision 041)."""
    if d.anchor is None:
        return None
    others = list(d.supporting)
    if d.trigger["event_uid"] != d.anchor["event_uid"]:
        others.append(d.trigger)
    if not others:
        return None
    return delta_ms(min(e["us"] for e in others), d.anchor["us"])


def draft_sort_key(d: TriggerDraft) -> tuple:
    """(event_utc instant, trigger uid, rule) as the spec says; anchor uid breaks the remaining tie
    (one R6/R8 row per anchor shares the other three keys)."""
    return (d.trigger["us"], d.trigger["event_uid"], d.rule, d.anchor["event_uid"] if d.anchor else "")


def trigger_row(d: TriggerDraft, trigger_id: str, window_source: str, time_basis: str,
                near_dup: set[str]) -> Row:
    """One triggers.csv row. Account and logon columns come from the anchor (decision 027: the moving
    account); empty when the row has no anchor. ``source_ip``/``ip_kind`` come from ``ip_event``."""
    a = d.anchor or {}
    account = a.get("account_name")
    ip_src = (d.ip_event or {}).get("source_ip")
    lid = logon_id(a.get("target_logon_id"))
    return {
        "trigger_id": trigger_id, "rule": d.rule, "host": d.trigger["host"],
        "event_utc": d.trigger["event_utc"], "event_utc_raw": d.trigger["event_utc"],
        "trigger_event_uid": d.trigger["event_uid"], "anchor_logon_uid": a.get("event_uid"),
        "target_logon_id": lid, "target_logon_id_hex": logon_hex(lid), "logon_type": a.get("logon_type"),
        "source_ip": ip_text(ip_src), "ip_kind": ip_kind(ip_src), "account_name": account,
        "domain_short": a.get("domain_short"), "authentication_package": a.get("authentication_package"),
        "machine_account": int(isinstance(account, str) and account.endswith("$")),
        "supporting_event_uids": ";".join(s["event_uid"] for s in d.supporting),
        "method": d.method, "candidate_count": d.candidate_count, "time_delta_ms": time_delta(d),
        "gate_tier": d.tier, "near_duplicate": int(d.trigger["event_uid"] in near_dup),
        "window_source": window_source, "time_basis": time_basis,
    }


def unmatched_drafts(remote: Sequence[Mapping], drafts: Sequence[TriggerDraft]) -> list[TriggerDraft]:
    """GT-15: remote 4624s that are neither a trigger nor an anchor of any row; each is its own anchor
    (method none, tier A, candidate_count 1, no supporting event)."""
    fired = {d.trigger["event_uid"] for d in drafts} | {d.anchor["event_uid"] for d in drafts if d.anchor}
    return [TriggerDraft("unmatched", r, r, (), "none", "A", 1, r) for r in remote if r["event_uid"] not in fired]


def numbered_rows(drafts: Sequence[TriggerDraft], trial_id: str, letter: str, window_source: str,
                  time_basis: str, near_dup: set[str], columns: Sequence[str]) -> list[Row]:
    """Sort drafts, number them ``<trial_id>-<letter><NNNN>`` (1-based) and keep only ``columns``."""
    out = []
    for i, d in enumerate(sorted(drafts, key=draft_sort_key), start=1):
        row = trigger_row(d, f"{trial_id}-{letter}{i:04d}", window_source, time_basis, near_dup)
        out.append({c: row[c] for c in columns})
    return out


def supporting_rows(signals: Iterable[tuple[str, Mapping]]) -> list[Row]:
    """supporting.csv rows sorted by (instant, uid, rule)."""
    ordered = sorted(signals, key=lambda p: (p[1]["us"], p[1]["event_uid"], p[0]))
    return [{"rule": rule, "event_uid": e["event_uid"], "host": e["host"], "event_utc": e["event_utc"],
             "account_name": e.get("account_name"), "session_id": e.get("session_id")} for rule, e in ordered]


# ---------------------------------------------------------------- dispositions

def _roles(drafts: Sequence[TriggerDraft]) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, set[str]]]:
    """uid -> rules where it is trigger/anchor, uid -> rules where it is supporting, uid -> anchor uids."""
    as_trigger: dict[str, set[str]] = {}
    as_support: dict[str, set[str]] = {}
    anchors_of: dict[str, set[str]] = {}

    def note(uid: str, table: dict[str, set[str]], rule: str, anchor: str | None) -> None:
        table.setdefault(uid, set()).add(rule)
        if anchor:
            anchors_of.setdefault(uid, set()).add(anchor)

    for d in drafts:
        anchor = d.anchor["event_uid"] if d.anchor else None
        note(d.trigger["event_uid"], as_trigger, d.rule, anchor)
        if anchor:
            note(anchor, as_trigger, d.rule, anchor)
        for s in d.supporting:
            note(s["event_uid"], as_support, d.rule, anchor)
    return as_trigger, as_support, anchors_of


def _pair_detail(uid: str, service_pairs: Mapping[str, str]) -> list[str]:
    """For a 7045 paired with a 4697: ``service_name_time`` and the 4697 uid (decision 041)."""
    return ["service_name_time", f"paired_4697={service_pairs[uid]}"] if uid in service_pairs else []


def disposition_for(ev: Mapping, suppressed: Mapping[str, Suppression], as_trigger: Mapping[str, set[str]],
                    as_support: Mapping[str, set[str]], anchors_of: Mapping[str, set[str]],
                    unmatched: set[str], service_pairs: Mapping[str, str],
                    r5_reverse: Mapping[str, int]) -> tuple[str, str, str]:
    """(disposition, reason_detail, anchor_logon_uid) in the spec 3 precedence order, first match wins."""
    uid = ev["event_uid"]
    anchors = ";".join(sorted(anchors_of.get(uid, set())))
    if uid in suppressed:
        return suppressed[uid].disposition, suppressed[uid].detail, ""
    if uid in as_trigger:
        parts = _pair_detail(uid, service_pairs) + [f"rules={','.join(sorted(as_trigger[uid]))}"]
        if uid in r5_reverse:
            parts.append(f"r5_reverse_count={r5_reverse[uid]}")
        return "trigger", ";".join(parts), anchors
    if uid in as_support:
        parts = _pair_detail(uid, service_pairs) + [f"rules={','.join(sorted(as_support[uid]))}"]
        return "supporting", ";".join(parts), anchors
    if uid in unmatched:
        return "unmatched_remote", f"logon_type={ev.get('logon_type')}", uid
    return "no_rule", "", ""


def disposition_rows(events: Sequence[Mapping], suppressed: Mapping[str, Suppression],
                     drafts: Sequence[TriggerDraft], unmatched: Sequence[TriggerDraft],
                     signals: Sequence[tuple[str, Mapping]], service_pairs: Mapping[str, str],
                     r5_reverse: Mapping[str, int]) -> list[Row]:
    """Exactly one row per in-window trigger-type event (spec 3), sorted by (instant, uid).

    ``supporting`` covers both supporting_event_uids and supporting.csv entries (R8_parent).
    """
    as_trigger, as_support, anchors_of = _roles(drafts)
    for rule, ev in signals:
        as_support.setdefault(ev["event_uid"], set()).add(rule)
    unmatched_uids = {d.trigger["event_uid"] for d in unmatched}
    out = []
    for ev in sorted((e for e in events if classify.is_trigger_type(e)), key=lambda e: (e["us"], e["event_uid"])):
        disp, detail, anchor = disposition_for(ev, suppressed, as_trigger, as_support, anchors_of,
                                               unmatched_uids, service_pairs, r5_reverse)
        out.append({"event_uid": ev["event_uid"], "host": ev["host"], "event_id": ev["event_id"],
                    "event_utc": ev["event_utc"], "disposition": disp, "reason_detail": detail,
                    "anchor_logon_uid": anchor})
    return out


# ---------------------------------------------------------------- stats helpers

def nested_counts(rows: Iterable[Mapping], *keys: str) -> dict:
    """Nested dict of counts by the given row keys, e.g. rule -> host -> gate_tier -> n."""
    out: dict = {}
    for row in rows:
        node = out
        for k in keys[:-1]:
            node = node.setdefault(str(row[k]), {})
        last = str(row[keys[-1]])
        node[last] = node.get(last, 0) + 1
    return out


def disposition_counts(rows: Sequence[Mapping]) -> dict:
    """Totals per disposition (every name present, zeros included) and per host."""
    total = Counter(r["disposition"] for r in rows)
    return {"total": {d: total.get(d, 0) for d in DISPOSITIONS},
            "per_host": nested_counts(rows, "host", "disposition")}


def excluded_per_ip(suppressed: Mapping[str, Suppression]) -> dict[str, int]:
    """GT-02 count per excluded IP over every excluded in-window event (dispositions of trigger types
    and any other kept event)."""
    return dict(sorted(Counter(s.excluded_ip for s in suppressed.values() if s.excluded_ip).items()))


def excluded_ip_with_artefacts(events: Sequence[Mapping], excl_map: Mapping[tuple[str, int], str],
                               service_pairs: Mapping[str, str]) -> list[dict]:
    """Excluded sessions (host, logon ID, IP) with an in-window 4697, its paired 7045, or a share event.

    WHY listed: such a session may be a designed step run from a non-lab workstation (S04 x10
    Track A from .99); the owner must see it (GTA-05). Only in-window uids are listed.
    """
    paired_7045_of = {v: k for k, v in service_pairs.items()}
    acc: dict[tuple[str, int], list[str]] = {}
    for ev in events:
        if not (classify.is_4697(ev) or classify.is_share(ev)):
            continue
        lid = logon_id(ev.get("subject_logon_id"))
        if lid is None or (ev["host"], lid) not in excl_map:
            continue
        uids = acc.setdefault((ev["host"], lid), [])
        uids.append(ev["event_uid"])
        if ev["event_uid"] in paired_7045_of:
            uids.append(paired_7045_of[ev["event_uid"]])
    return [{"host": h, "logon_id_hex": f"0x{lid:x}", "source_ip": excl_map[(h, lid)], "event_uids": sorted(u)}
            for (h, lid), u in sorted(acc.items())]


def tier_d_lookup(drafts: Sequence[TriggerDraft], trigger_ids: Sequence[str],
                  ip_lookup: Mapping[tuple[str, int], list[str]]) -> list[dict]:
    """``trigger_ids`` are the ids in sorted-row order. For every tier-D row: its logon ID (4697 subject_logon_id / Sysmon 1 session_id; none for a lone
    7045) and the source IPs of 4624s with that ID on that host in the unclipped DB (spec 3, GTA-03)."""
    out = []
    for i, d in enumerate(sorted(drafts, key=draft_sort_key)):
        if d.tier != "D":
            continue
        if classify.is_4697(d.trigger):
            lid = logon_id(d.trigger.get("subject_logon_id"))
        elif classify.is_wsmprovhost_start(d.trigger):
            lid = logon_id(d.trigger.get("session_id"))
        else:
            lid = None
        found = ip_lookup.get((d.trigger["host"], lid)) if lid is not None else None
        out.append({"trigger_id": trigger_ids[i], "rule": d.rule, "host": d.trigger["host"],
                    "logon_id_hex": logon_hex(lid), "logon_found": found is not None,
                    "source_ips": list(found or [])})
    return out


# ---------------------------------------------------------------- serialisation

def csv_text(rows: Sequence[Mapping], columns: Sequence[str]) -> str:
    """CSV with ``\\n`` line endings; None -> empty cell; columns in the given order."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(columns), lineterminator="\n", extrasaction="raise")
    w.writeheader()
    for row in rows:
        w.writerow({c: ("" if row.get(c) is None else row[c]) for c in columns})
    return buf.getvalue()


def json_text(obj: Any) -> str:
    """Stable JSON: sorted keys, indent 2, UTF-8 characters kept, final newline."""
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def report_md(stats: Mapping) -> str:
    """Human-readable summary of stats.json (deterministic: built only from the stats dict)."""
    w = stats["window"]["row"]
    lines = [f"# Gate report: {stats['trial_id']}", "",
             f"- DB: `{stats['db']['path']}` sha256 before `{stats['db']['sha256_before']}`, "
             f"after `{stats['db']['sha256_after']}`",
             f"- Window file: `{stats['window']['file']}` sha256 `{stats['window']['file_sha256']}`",
             f"- Window: {w['start_utc']} .. {w['end_utc']} (`start <= t < end + 1 ms`), "
             f"source {w['window_source']}, time basis {stats['time_basis']}",
             f"- Events read: {stats['events']['loaded_total']}; in window: {stats['events']['in_window_total']}; "
             f"trigger-type in window: {stats['events']['trigger_type_in_window']}", "",
             "## Rows", "",
             f"- triggers.csv: {stats['triggers']['total']}",
             f"- unmatched_remote.csv: {stats['unmatched_remote']['total']}",
             f"- supporting.csv: {stats['supporting']['total']}",
             f"- local service installs (R6, no anchor): {stats['local_installs']['count']}", "",
             "## Dispositions", "", "| disposition | count |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in stats["dispositions"]["total"].items()]
    lines += ["", "## Triggers per rule, host, gate tier", "", "| rule | host | tier | count |", "|---|---|---|---|"]
    for rule, hosts in sorted(stats["triggers"]["per_rule_host_tier"].items()):
        for host, tiers in sorted(hosts.items()):
            for tier, n in sorted(tiers.items()):
                lines.append(f"| {rule} | {host} | {tier} | {n} |")
    lines += ["", "## Removed by the window (per host, channel/event id)", ""]
    for host, counts in sorted(stats["removed_by_window"].items()):
        lines.append(f"- {host}: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    lines += ["", "## Near window (trigger-type events up to "
              f"{stats['parameters']['near_window_s']:g} s outside an edge; counts only)", ""]
    for host, sides in sorted(stats["near_window"].items()):
        lines.append(f"- {host}: before {sides.get('before', 0)}, after {sides.get('after', 0)}")
    lines += ["", "## Excluded source IPs (GT-02)", "",
              f"- events per IP: {json.dumps(stats['excluded']['per_ip'], sort_keys=True)}",
              f"- sessions with artefacts: {len(stats['excluded']['excluded_ip_with_artefacts'])}"]
    for s in stats["excluded"]["excluded_ip_with_artefacts"]:
        lines.append(f"  - {s['host']} {s['logon_id_hex']} from {s['source_ip']}: {', '.join(s['event_uids'])}")
    lines += ["", "## Other", "",
              f"- machine-account triggers per host: {json.dumps(stats['machine_account_triggers_per_host'], sort_keys=True)}",
              f"- remote logons per ip_kind: {json.dumps(stats['remote_logons_per_ip_kind'], sort_keys=True)}",
              f"- near-duplicate uids: {len(stats['near_duplicate_uids'])}",
              f"- tier-D IP lookups: {len(stats['tier_d_ip_lookup'])}"]
    for t in stats["tier_d_ip_lookup"]:
        lines.append(f"  - {t['trigger_id']} {t['rule']} {t['host']} logon {t['logon_id_hex'] or '-'}: "
                     f"{', '.join(t['source_ips']) or 'no IP found'}")
    lines += ["", "## Sensitivity (pairs found per tolerance, s)", ""]
    for name, by_tol in sorted(stats["sensitivity"].items()):
        lines.append(f"- {name}: " + ", ".join(f"{k} s: {v}" for k, v in by_tol.items()))
    lines += ["", "## Parameters", "", "```json", json.dumps(stats["parameters"], sort_keys=True, indent=2), "```", ""]
    return "\n".join(lines)


def write_outputs(out_dir: Path, files: Mapping[str, str]) -> None:
    """Empty ``out_dir`` (rebuilt on every run) and write each file as UTF-8 without BOM, ``\\n`` endings."""
    out_dir = Path(out_dir)
    if out_dir.exists():
        for child in out_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        with open(out_dir / name, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
