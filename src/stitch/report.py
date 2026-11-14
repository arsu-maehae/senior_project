"""T7.5 ``stats.json`` dict and ``report.md`` text of one trial (spec 03_stitch section 3; ST-01, ST-04, ST-23,
ST-26, ST-44, ST-72, L-ST2; decisions 013, 050 item 8; STA-01, STA-08).

WHY pure: every value is already decided in the ``LinkIndex``, the ``PathSet`` (with notes applied) and the node
rows. This module only counts and spells them; ``stitch.__main__`` writes the files. Neither output has a
timestamp, so two runs on the same inputs give the same bytes (spec 3: only ``run_info.json`` is exempt).

WHY ``report.md`` is built from named fields only and holds event-level facts only (050 item 8): ids, host
names, source IPs, protocol / tier / method / reason vocabularies, counts and corrected times. It never prints an
account, an image, a command fragment or a target-side file or service name, so it can be shared without the
privacy review the CSVs need. No value is taken from a free-text field.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from gate.timeutil import fmt_us

from .index import jsonable, params_dict
from .links import LinkIndex
from .nodes import ROLES, PathNode
from .params import TARGET_ONLY_REASONS, TOOL_VERSION, StitchParams
from .paths import Path, PathSet, edge_types_text, hop_clock_unreliable
from .tiers import TIERS

__all__ = ["IDENTITY_SENTENCE", "L_ST2_SENTENCE", "hops_by_protocol_and_tier", "nodes_by_role_and_context",
           "clock_unreliable_hops", "note_paths", "stats_dict", "edge_types_text", "report_md"]
# ``edge_types_text`` is defined in ``paths`` (one spelling for paths.csv and report.md) and re-exported here.

# Decision 013 / STA-08: stated in every report, because an identity value of 1 next to a weak or absent link is
# by design and a reader must not take it for a link result.
IDENTITY_SENTENCE = ("Identity inputs (hop_identity.csv) use only the moving account of the target 4624 and the "
                     "source host found by IP; they never use the linked source session (decision 013), so they "
                     "are computed for every hop, target_only hops included.")
# Spec 9.1 L-ST2, shortened to the part a reader of one trial needs.
L_ST2_SENTENCE = ("Limitation L-ST2: chains that share a hop are merged (the locked merge rule), so a path can "
                  "hold hops of different movements; host_time chaining cannot tell which parent led to the "
                  "next hop, so the hop is flagged multi_chain_parent and its parents are listed.")


# ---------------------------------------------------------------- stats pieces (pure)

def hops_by_protocol_and_tier(li: LinkIndex) -> dict[str, dict[str, int]]:
    """Protocol -> best link tier (``HopVerdicts.best_tier``; D for a hop with no session, ST-49) -> hops.
    Every tier of ``TIERS`` is present, zero included, so two trials can be compared key by key."""
    out: dict[str, dict[str, int]] = {}
    for h in li.hopset.hops:
        row = out.setdefault(h.protocol, {t: 0 for t in TIERS})
        row[li.verdicts[h.hop_id].best_tier] += 1
    return dict(sorted(out.items()))


def nodes_by_role_and_context(nodes: Iterable[PathNode]) -> dict[str, dict[str, int]]:
    """Role -> context ("0" / "1") -> ``path_nodes.csv`` rows; every role and both contexts present."""
    out = {r: {"0": 0, "1": 0} for r in ROLES}
    for n in nodes:
        out[n.role][str(n.context)] += 1
    return out


def clock_unreliable_hops(li: LinkIndex) -> list[str]:
    """Hop ids whose ``hops.csv`` ``clock_unreliable`` is 1 (``paths.hop_clock_unreliable``, ST-02 both parts),
    sorted."""
    return sorted(h.hop_id for h in li.hopset.hops if hop_clock_unreliable(h, li.links[h.hop_id]))


def note_paths(paths: Iterable[Path]) -> dict[str, list[str]]:
    """Path ids with a ``shared_source_session_with`` note and with a ``shared_event_with`` note (ST-73)."""
    ps = list(paths)
    return {"paths_with_session_note": [p.path_id for p in ps if p.shared_source_session_with],
            "paths_with_event_note": [p.path_id for p in ps if p.shared_event_with]}


def _removed_by_window(li: LinkIndex, given: Mapping[str, Mapping[str, int]] | None) -> dict[str, dict[str, int]]:
    """ST-01 counts (host -> "Channel/eid" -> n): the argument when given, else the scan counts already kept on
    the index (``TrialIndex.scan_counts``). WHY the fallback: the index carries exactly the scan the links were
    built from, so no second source is needed."""
    if given is not None:
        return {h: dict(c) for h, c in given.items()}
    if li.index is None:
        raise ValueError("removed_by_window not given and LinkIndex.index is missing")
    return {h: dict(c) for h, c in li.index.scan_counts["removed_by_window"].items()}


def stats_dict(li: LinkIndex, pathset: PathSet, nodes: Sequence[PathNode], file_rows: Mapping[str, int],
               params: StitchParams, db_sha_before: str, db_sha_after: str,
               removed_by_window: Mapping[str, Mapping[str, int]] | None = None) -> dict[str, Any]:
    """The ``stats.json`` dict (JSON-ready, mapping keys sorted; spec 3 list). Pure, no timestamp.

    ``pathset`` must carry the notes (``nodes.apply_notes``). ``file_rows`` = data rows per written CSV. Hop and
    link-side counts are reused from ``li.counts`` (T7.3) and ``li.hopset.counts``, never recounted, so they
    equal the check file (STA-01). ``hops_in_no_path`` and ``non_seed_hops`` are listed (ST-04, ST-23).
    """
    c, pc = li.counts, pathset.counts
    near = sorted(h.hop_id for h in li.hopset.hops if h.gap_near_threshold)
    return jsonable({
        "trial_id": li.trial_id,
        "tool_version": TOOL_VERSION,
        "files": dict(file_rows),
        "remote_logons": c["remote_logons"],
        "hops": c["hops"],
        "seeds": c["seeds"],
        "hops_by_protocol": c["protocols"],
        "hops_by_protocol_and_tier": hops_by_protocol_and_tier(li),
        "hops_by_methods_linked": c["hops_by_methods_linked"],
        "candidate_rows_by_method": c["candidate_rows_by_method"],
        "unresolved_rows_by_reason": c["unresolved_rows_by_reason"],
        "target_only_reasons": {r: c["target_only_reasons"].get(r, 0) for r in TARGET_ONLY_REASONS},
        "hops_in_no_path": pc["hops_in_no_path"],
        "non_seed_hops": pc["non_seed_hops"],
        "followup_groups": c["followup_groups"],
        "followup_logons": c["followup_logons"],
        "artefacts": c["artefacts"],
        "kerberos_confirmed_hops": c["kerberos_confirmed_hops"],
        "service_admin_write_hops": c["service_admin_write_hops"],
        "chain_edges_by_type": pc["chain_edges_by_type"],
        "chainable_seeds": pc["chainable_seeds"],
        "multi_chain_parent_hops": pc["multi_chain_parent_hops"],
        "paths": pc["paths"],
        "multi_hop_paths": [p.path_id for p in pathset.paths if p.n_hops > 1],
        "isolated_paths": pc["isolated_paths"],
        "gap_near_threshold": c["gap_near_threshold"],
        "gap_near_threshold_hop_ids": near,
        "gap_near_threshold_user_e2e": c["gap_near_threshold_user_e2e"],
        "system_session_evidence": c["system_session_evidence"],
        "removed_by_window": _removed_by_window(li, removed_by_window),
        "path_nodes_by_role_and_context": nodes_by_role_and_context(nodes),
        "notes": note_paths(pathset.paths),
        "clock_unreliable_hops": clock_unreliable_hops(li),
        "data_limitation_hosts": c["data_limitation_hosts"],
        "parameters": params_dict(params),
        "db": {"sha256_before": db_sha_before, "sha256_after": db_sha_after},
    })


# ---------------------------------------------------------------- report.md (pure)

def _table(header: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    """Markdown table lines; ``|`` inside a value is escaped so a cell can never split. Empty rows -> "(none)"."""
    body = [list(map(str, r)) for r in rows]
    if not body:
        return ["(none)"]
    esc = lambda v: v.replace("|", "\\|")  # noqa: E731
    return (["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
            + ["| " + " | ".join(esc(v) for v in r) + " |" for r in body])


def _ids(ids: Sequence[str]) -> str:
    """Ids joined for prose; "(none)" when empty."""
    return ", ".join(ids) if ids else "(none)"


def _counts_section(stats: Mapping[str, Any]) -> list[str]:
    """Counts: files, hops, seeds, paths, edges, nodes, follow-ups, window removals."""
    removed = sum(n for c in stats["removed_by_window"].values() for n in c.values())
    lines = ["## Counts", ""]
    lines += _table(("file", "rows"), sorted(stats["files"].items()))
    lines += ["", f"- remote logons: {stats['remote_logons']}; hops: {stats['hops']}; seeds: {stats['seeds']} "
              f"(chainable: {stats['chainable_seeds']}); non-seed hops: {len(stats['non_seed_hops'])}",
              f"- paths: {stats['paths']} (multi-hop: {len(stats['multi_hop_paths'])}; isolated: "
              f"{stats['isolated_paths']}); chain edges: {edge_types_text(stats['chain_edges_by_type'])}",
              f"- follow-up groups: {stats['followup_groups']}; follow-up logons: {stats['followup_logons']}",
              f"- gap_near_threshold hops: {stats['gap_near_threshold']} (user endpoint to endpoint: "
              f"{stats['gap_near_threshold_user_e2e']})",
              f"- events removed by the window rule (ST-01): {removed}", "",
              "Hops per protocol and best link tier:", ""]
    lines += _table(("protocol",) + TIERS, [(p, *(v[t] for t in TIERS))
                                            for p, v in stats["hops_by_protocol_and_tier"].items()])
    lines += ["", "Hops per protocol by number of methods linked:", ""]
    lines += _table(("protocol", "0", "1", "2", "3"),
                    [(p, v["0"], v["1"], v["2"], v["3"]) for p, v in stats["hops_by_methods_linked"].items()])
    lines += ["", "Path node rows per role (context 0 / 1):", ""]
    lines += _table(("role", "context 0", "context 1"),
                    [(r, v["0"], v["1"]) for r, v in stats["path_nodes_by_role_and_context"].items()])
    return lines


def _paths_section(li: LinkIndex, pathset: PathSet) -> list[str]:
    """One row per path: id, first corrected time, hops, ``source>target`` per hop, size, edges, notes."""
    by_id = {h.hop_id: h for h in li.hopset.hops}
    rows = [(p.path_id, fmt_us(by_id[p.hop_ids[0]].first_us), "; ".join(p.hop_ids), "; ".join(p.hosts), p.n_hops,
             edge_types_text(p.edge_types), p.isolated, _ids(p.shared_source_session_with),
             _ids(p.shared_event_with)) for p in pathset.paths]
    return (["## Paths", "", "Ranked later (T9); listed here in path-id order (first hop, corrected time).", ""]
            + _table(("path", "first (corrected)", "hops", "hosts", "n_hops", "edge_types", "isolated",
                      "shared_source_session_with", "shared_event_with"), rows)
            + ["", "Notes never merge paths (ST-73)."])


def _edges_section(pathset: PathSet) -> list[str]:
    """Every chain edge with its path, type, delta and flags (ST-72)."""
    path_of = {h: f.path_id for h, f in pathset.hop_facts.items()}
    rows = [(path_of.get(e.from_hop_id) or "", e.from_hop_id, e.to_hop_id, e.link_type, e.time_delta_ms,
             e.order_within_tolerance, e.clock_unreliable) for e in pathset.edges]
    return ["## Chain edges", ""] + _table(("path", "from", "to", "link_type", "time_delta_ms",
                                            "order_within_tolerance", "clock_unreliable"), rows)


def _no_path_section(stats: Mapping[str, Any]) -> list[str]:
    """Hops in no path (ST-04): ids and count; they are the non-seed hops (ST-23)."""
    ids = stats["hops_in_no_path"]
    return ["## Hops in no path", "", f"{len(ids)} hops (no gate trigger, ST-23; still in hops.csv with "
            "in_path = 0): " + _ids(ids)]


def _multi_parent_section(stats: Mapping[str, Any]) -> list[str]:
    """Hops with more than one chain parent, their parents, and the L-ST2 sentence."""
    rows = [(h, "; ".join(ps)) for h, ps in stats["multi_chain_parent_hops"].items()]
    return ["## Hops with more than one chain parent", ""] + _table(("hop", "parents"), rows) + ["", L_ST2_SENTENCE]


def _target_only_section(stats: Mapping[str, Any]) -> list[str]:
    """``target_only`` reasons and their hop counts (ST-49)."""
    return ["## target_only reasons", ""] + _table(("reason", "hops"), stats["target_only_reasons"].items())


def _limits_section(li: LinkIndex) -> list[str]:
    """Hosts labelled ``data_limitation`` (048 item 13): reasons, last Security event (corrected), hops near end."""
    rows = [(h, "; ".join(lim.data_limitation_reasons), fmt_us(lim.last_security_us),
             _ids(lim.hops_near_end)) for h, lim in sorted(li.data_limits.items()) if lim.data_limitation]
    return ["## Data-limit hosts", ""] + _table(("host", "reasons", "last Security event (corrected)",
                                                 "hops near the end"), rows)


def _clock_section(stats: Mapping[str, Any], pathset: PathSet) -> list[str]:
    """Hops and edges with ``clock_unreliable`` = 1 (ST-02)."""
    edges = [f"{e.from_hop_id}>{e.to_hop_id}" for e in pathset.edges if e.clock_unreliable]
    return ["## Clock flags", "", f"- hops with clock_unreliable = 1: {_ids(stats['clock_unreliable_hops'])}",
            f"- chain edges with clock_unreliable = 1: {_ids(edges)}"]


def report_md(stats: Mapping[str, Any], li: LinkIndex, pathset: PathSet) -> str:
    """``report.md`` text: event-level facts only (050 item 8), sections in a fixed order, ``\\n`` line ends, one
    trailing newline. Deterministic: the same inputs give the same text. ``stats`` is the ``stats_dict`` result
    and ``pathset`` carries the notes."""
    head = [f"# Stitch report: {stats['trial_id']}", "",
            f"- tool version: {stats['tool_version']}",
            f"- DB SHA-256 before: {stats['db']['sha256_before']}",
            f"- DB SHA-256 after: {stats['db']['sha256_after']}",
            "- times are corrected (ST-02); paths are candidates for ranking, not verdicts."]
    sections = [head, _counts_section(stats), _paths_section(li, pathset), _edges_section(pathset),
                _no_path_section(stats), _multi_parent_section(stats), _target_only_section(stats),
                _limits_section(li), _clock_section(stats, pathset), ["## Identity inputs", "", IDENTITY_SENTENCE]]
    return "\n\n".join("\n".join(s) for s in sections) + "\n"
