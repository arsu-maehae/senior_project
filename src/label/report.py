"""``stats.json`` and ``report.md`` of the labeller (spec 04_label section 3.4).

WHY pure and without a timestamp: both files must be byte-identical between two runs on the same inputs (spec 3.4);
only ``run_info.json`` carries the time. They hold counts, rule ids, technique ids, levels, channels and hashes:
events outside the window are counted, never listed (LB-01), and no field text appears (LB-09).
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .events import EventScan
from .join import DUMP_OUTSIDE
from .labels import Match
from .rules import Rule

__all__ = ["label_counts", "node_counts", "hop_counts", "stats_dict", "report_md"]


def _count(table: dict[str, int], key: str) -> None:
    """Increment a counter."""
    table[key] = table.get(key, 0) + 1


def _sorted(d: Mapping[str, Any]) -> dict[str, Any]:
    """A dict with sorted keys (stable JSON)."""
    return {k: d[k] for k in sorted(d)}


def label_counts(matches: Sequence[Match], rules: Sequence[Rule], keys: Mapping[str, str]) -> dict[str, Any]:
    """Matches per rule (every rule, 0 included), per primary technique, per level; distinct count keys per rule
    (LB-11: one action counted once); matches on machine-account events per rule (report only, spec 2); labelled
    events by channel; rules with no match."""
    per_rule = {r.rule_id: 0 for r in rules}
    machine = {r.rule_id: 0 for r in rules}
    actions: dict[str, set[str]] = {r.rule_id: set() for r in rules}
    per_tech: dict[str, int] = {}
    per_level: dict[str, int] = {}
    by_channel: dict[str, set[str]] = {}
    for m in matches:
        rid = m.rule.rule_id
        per_rule[rid] = per_rule.get(rid, 0) + 1
        machine[rid] = machine.get(rid, 0) + int(m.event.machine_account == 1)
        actions.setdefault(rid, set()).add(keys.get(m.event.uid, m.event.uid))
        _count(per_tech, m.rule.technique)
        _count(per_level, m.rule.level)
        by_channel.setdefault(f"{m.event.channel}/{m.event.event_id}", set()).add(m.event.uid)
    return {
        "rows": len(matches),
        "labelled_events": len({m.event.uid for m in matches}),
        "matches_per_rule": per_rule,
        "matches_machine_account_per_rule": machine,
        "count_keys_per_rule": {k: len(v) for k, v in actions.items()},
        "matches_per_technique": _sorted(per_tech),
        "matches_per_level": _sorted(per_level),
        "labelled_events_by_channel": _sorted({k: len(v) for k, v in by_channel.items()}),
        "rules_with_no_match": [r.rule_id for r in rules if per_rule.get(r.rule_id, 0) == 0],
    }


def node_counts(node_rows: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    """Node rows, labelled rows by role / context, and node rows per rule by role / context (spec 10.2 shape)."""
    by_rc: dict[str, int] = {}
    per_rule: dict[str, dict[str, int]] = {}
    for n in node_rows:
        if n["labelled"] != "1":
            continue
        rc = f"{n['role']}/{n['context']}"
        _count(by_rc, rc)
        for rid in n["rule_ids"].split(";"):
            _count(per_rule.setdefault(rid, {}), rc)
    return {
        "rows": len(node_rows),
        "labelled_rows": sum(1 for n in node_rows if n["labelled"] == "1"),
        "labelled_rows_by_role_context": _sorted(by_rc),
        "rows_per_rule_by_role_context": {k: _sorted(v) for k, v in sorted(per_rule.items())},
    }


def hop_counts(hop_rows: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    """Hops, hops in a path, hops with / without a labelled node (L-LB3), and the LSASS reads of the dump columns."""
    states = [s for h in hop_rows for s in h["dump_labelled"].split(";") if s]
    in_path = [h for h in hop_rows if h["in_path"] == "1"]
    return {
        "rows": len(hop_rows),
        "in_path": len(in_path),
        "with_labelled_node": sum(1 for h in hop_rows if int(h["n_labelled_node_events"]) > 0),
        "in_path_without_labelled_node": sum(1 for h in in_path if int(h["n_labelled_node_events"]) == 0),
        "with_dump_reads": sum(1 for h in hop_rows if h["dump_event_uids"]),
        "dump_reads": len(states),
        "dump_reads_labelled": states.count("1"),
        "dump_reads_unlabelled": states.count("0"),
        "dump_reads_outside_window": states.count(DUMP_OUTSIDE),
    }


def stats_dict(trial_id: str, tool_version: str, db_display: str, sha_before: str, sha_after: str,
               manifest_sha256: str, window: Mapping[str, Any], scan: EventScan, labels: Mapping[str, Any],
               nodes: Mapping[str, Any], hops: Mapping[str, Any], row_counts: Mapping[str, int],
               parameters: Mapping[str, Any]) -> dict[str, Any]:
    """The ``stats.json`` dict (keys sorted by ``json_text``)."""
    return {
        "trial_id": trial_id,
        "tool_version": tool_version,
        "time_basis": "corrected",
        "db": {"path": db_display, "sha256_before": sha_before, "sha256_after": sha_after},
        "rules_manifest_sha256": manifest_sha256,
        "window": dict(window),
        "events": {
            "loaded_total": scan.loaded_total,
            "in_window_rows": scan.in_window_rows,
            "outside_window_rows": scan.outside_window_rows,
            "in_window_by_channel": scan.in_window_by_channel,
            "outside_window_by_channel": scan.outside_window_by_channel,
            "near_duplicate_groups": scan.near_duplicate_groups,
            "in_window_events": len(scan.events),
        },
        "labels": dict(labels),
        "nodes": dict(nodes),
        "hops": dict(hops),
        "files": _sorted(row_counts),
        "parameters": dict(parameters),
    }


def _table(head: Sequence[str], rows: Sequence[Sequence[Any]]) -> list[str]:
    """A Markdown table."""
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return out


def report_md(stats: Mapping[str, Any], rules: Sequence[Rule]) -> str:
    """The ``report.md`` text: counts per rule, events in / outside the window, node and hop label counts."""
    lab, ev, nod, hop = stats["labels"], stats["events"], stats["nodes"], stats["hops"]
    lines = [f"# Label report: {stats['trial_id']}", "",
             f"- tool version: {stats['tool_version']}",
             f"- DB SHA-256 before: {stats['db']['sha256_before']}",
             f"- DB SHA-256 after: {stats['db']['sha256_after']}",
             f"- rules manifest SHA-256 (LF): {stats['rules_manifest_sha256']}",
             "- labels are attributes of single events: they add no event, hop or path, order nothing and score "
             "nothing (spec 04 section 1).",
             "- SR-10 is an adapted SigmaHQ rule (field-format fix, decision 056 P1; derived from 098d7118).", "",
             "## Events", "",
             f"- rows read: {ev['loaded_total']}; in the window: {ev['in_window_rows']}; outside it (counted, never "
             f"listed): {ev['outside_window_rows']}; near-duplicate groups: {ev['near_duplicate_groups']}", "",
             "## Matches per rule", ""]
    rows = [(r.rule_id, r.source, r.technique, r.level, lab["matches_per_rule"].get(r.rule_id, 0),
             lab["count_keys_per_rule"].get(r.rule_id, 0), lab["matches_machine_account_per_rule"].get(r.rule_id, 0),
             ";".join(f"{k} {v}" for k, v in nod["rows_per_rule_by_role_context"].get(r.rule_id, {}).items()) or "-")
            for r in rules]
    lines += _table(("rule", "source", "technique", "level", "matches", "count keys", "machine-account matches",
                     "node rows by role/context"), rows)
    lines += ["", f"- label rows: {lab['rows']}; labelled events: {lab['labelled_events']}",
              f"- rules with no match in this trial: {', '.join(lab['rules_with_no_match']) or 'none'}",
              "- matches per technique: " + (", ".join(f"{k} {v}" for k, v in lab["matches_per_technique"].items())
                                             or "none"),
              "- matches per level: " + (", ".join(f"{k} {v}" for k, v in lab["matches_per_level"].items()) or "none"),
              "", "## Nodes and hops", "",
              f"- node rows: {nod['rows']}; labelled: {nod['labelled_rows']} ("
              + (", ".join(f"{k} {v}" for k, v in nod["labelled_rows_by_role_context"].items()) or "none") + ")",
              f"- hops: {hop['rows']}; in a path: {hop['in_path']}; with a labelled node: {hop['with_labelled_node']};"
              f" in a path without a labelled node (L-LB3): {hop['in_path_without_labelled_node']}",
              f"- LSASS reads of the hop identity rows (facts only; they never change identity): "
              f"{hop['dump_reads']} (labelled {hop['dump_reads_labelled']}, unlabelled "
              f"{hop['dump_reads_unlabelled']}, outside the window {hop['dump_reads_outside_window']})"]
    return "\n".join(lines) + "\n"
