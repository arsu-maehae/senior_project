"""``stats.json`` and ``report.md`` of the score stage (spec 05_score sections 3.5, 9.1; SC-53, SC-55).

Wording rules (CLAUDE.md, SC-55): scores **rank**; an account is **exposed**, never described as taken; no sentence
claims fewer false positives, finding the attacker, or a likelihood. ``FORBIDDEN_WORDS`` lists the words the report
must never contain, so a test can check the text. Both texts carry no timestamp, so they are byte-identical between
runs. Pure.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from .assemble import PathScore, TrialScores
from .identity import STATUS_EXPOSED
from .outputs import fmt_score, technique_sequence_text
from .params import PATH_VARIANTS, TIE_DECIMALS, TOOL_VERSION, VARIANT_B0

__all__ = ["FORBIDDEN_WORDS", "LIMITATIONS", "stats_dict", "report_md"]

FORBIDDEN_WORDS: tuple[str, ...] = ("stolen", "detects", "probability", "reduces false positives",
                                    "identifies the attacker")

# Spec 9.1, stated in every report.
LIMITATIONS: tuple[tuple[str, str], ...] = (
    ("L-SC1", "Within one protocol, attack and benign hops carry the same context-0 techniques and levels, so "
              "LengthScore and NodeScore cannot order them; only IdentityCoherence can, and it measures exposure, "
              "not theft. NodeScore is protocol-sensitive (WinRM paths score above SMB paths whatever their role; "
              "decision 063)."),
    ("L-SC2", "The order reference is hand-built (five templates from ATT&CK and CTI pages), not mined from CTI "
              "reports as in TPPR."),
    ("L-SC3", "On single-hop paths the order signal reduces to which techniques co-occur in the hop (sequence S1); "
              "true order exists only between hops."),
    ("L-SC4", "IdentityCoherence inherits the stitcher's limits L-ST5..L-ST9, and exposure is not proof that "
              "credentials were taken or used (Correction K)."),
    ("L-SC5", "The answer keys use Correction K's definition, so identity agreement with the keys checks the code, "
              "not the definition."),
    ("L-SC6", "Correction K sets no upper bound on the dump-to-move gap: a session that stays open makes any later "
              "move by that account count as exposed."),
    ("L-SC7", "Weakly supported templates: R5 (T1078 > T1003.001 > T1021.006) and R1's first step "
              "(T1078 > T1003.001) are supported only at campaign level. R4 and R5 were written after the "
              "development sequences were seen."),
)


def _ties(ranked: Sequence[Any]) -> dict[str, int]:
    """Tie facts of one ranking: groups of size > 1, items inside them, size of the top group."""
    groups = {(r.rank, r.tie_size) for r in ranked if r.tie_size > 1}
    return {"tie_groups": len(groups), "items_in_ties": sum(t for _r, t in groups),
            "top_tie_size": ranked[0].tie_size if ranked else 0}


def _in_path_hops(ts: TrialScores) -> set[str]:
    """Hops that belong to at least one path."""
    return {h for ps in ts.paths for h in ps.chain}


def _identity_counts(ts: TrialScores) -> dict[str, Any]:
    """(hop, account) status / value counts over all hops and over in-path hops, and in-path crossing counts."""
    inp = _in_path_hops(ts)
    def counts(accs: Sequence[Any]) -> dict[str, Any]:
        return {"status": dict(sorted(Counter(a.status for a in accs).items())),
                "value": dict(sorted(Counter("" if a.value is None else str(a.value) for a in accs).items())),
                "rows": len(accs)}
    crossings = [ts.hops[h] for h in sorted(inp) if ts.hops[h].crossing]
    return {"all_hops": counts(ts.accounts), "in_path_hops": counts([a for a in ts.accounts if a.hop_id in inp]),
            "in_path_crossings": len(crossings), "in_path_crossings_coherent": sum(c.value for c in crossings),
            "in_path_crossings_flagged": sum(1 for c in crossings if c.flagged)}


def stats_dict(ts: TrialScores, rows: Mapping[str, int], parameters: Mapping[str, Any],
               order_table_sha256: str) -> dict[str, Any]:
    """The ``stats.json`` dict (spec 3.5): paths per variant, ties, paths with no labelled unit, identity counts,
    host_time edge gaps (L-ST5 measurement), the chance line inputs, parameters. Pure."""
    n = len(ts.paths)
    gaps = list(ts.host_time_gaps_ms)
    return {
        "tool_version": TOOL_VERSION, "trial_id": ts.trial_id, "rows": dict(sorted(rows.items())),
        "candidates_per_variant": {**{v: n for v in PATH_VARIANTS}, VARIANT_B0: len(ts.b0)},
        "ties": {**{v: _ties(ts.ranked[v]) for v in PATH_VARIANTS}, VARIANT_B0: _ties(ts.b0_ranked)},
        "paths_without_labelled_unit": sum(1 for ps in ts.paths if not ps.units),
        "paths_without_crossing": sum(1 for ps in ts.paths if ps.identity.n_crossings == 0),
        "multi_hop_paths": sum(1 for ps in ts.paths if len(ps.chain) > 1),
        "identity": _identity_counts(ts),
        "host_time_edge_gaps_ms": {"count": len(gaps), "min": min(gaps) if gaps else None,
                                   "max": max(gaps) if gaps else None, "values": gaps},
        "chance_line": {"n_paths": n, "expected_top1_uniform": round(1.0 / n, TIE_DECIMALS) if n else None},
        "parameters": dict(parameters), "order_table_sha256": order_table_sha256,
    }


def _ranked_table(ts: TrialScores, variant: str) -> list[str]:
    """Markdown table of one variant's ranking."""
    by_id = {ps.path_id: ps for ps in ts.paths}
    lines = ["| rank | tie | path | score | L | N | N (ctx 1 incl.) | I | I low / high | crossings | sequence | hosts |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in ts.ranked[variant]:
        ps = by_id[r.item_id]
        idn = ps.identity
        lines.append(f"| {r.rank} | {r.tie_size} | {ps.path_id} | {fmt_score(r.score)} | "
                     f"{fmt_score(ps.length.length_score)} | {fmt_score(ps.node_score)} | "
                     f"{fmt_score(ps.node_score_ctx1)} | {fmt_score(idn.coherence)} | {fmt_score(idn.low)} / "
                     f"{fmt_score(idn.high)} | {idn.n_coherent}/{idn.n_crossings} | "
                     f"{technique_sequence_text(ps) or '-'} | {ps.path['hosts']} |")
    return lines


def _identity_lines(ts: TrialScores) -> list[str]:
    """Per in-path (hop, account): status in the exposed wording, value, counted reads, gap."""
    inp = _in_path_hops(ts)
    lines = ["| hop | account | status | value | counted reads | deciding reads | gap ms (earliest deciding) |",
             "|---|---|---|---|---|---|---|"]
    for a in ts.accounts:
        if a.hop_id not in inp:
            continue
        val = "-" if a.value is None else str(a.value)
        lines.append(f"| {a.hop_id} | {a.account} | {a.status} | {val} | {a.candidate_count} | "
                     f"{len(a.deciding_dump_event_uids)} | {a.time_delta_ms or '-'} |")
    return lines


def _path_notes(paths: Sequence[PathScore]) -> list[str]:
    """Notes on multi-hop paths: chain order and the hop crossings that make up I (ATK-SC-05)."""
    out = []
    for ps in paths:
        if len(ps.chain) > 1:
            out.append(f"- {ps.path_id}: chain order {' > '.join(ps.chain)}; IdentityCoherence "
                       f"{ps.identity.n_coherent}/{ps.identity.n_crossings} crossings (a merged path includes every "
                       f"hop the stitcher merged into it, background hops too).")
    return out or ["- none"]


def report_md(ts: TrialScores, stats: Mapping[str, Any]) -> str:
    """The human-readable report: ranked list per variant with components, identity per hop, b0 ranking, stated
    substitutions and limitations L-SC1..L-SC7. Pure."""
    exposed = sum(1 for a in ts.accounts if a.hop_id in _in_path_hops(ts) and a.status == STATUS_EXPOSED)
    lines = [f"# Score report: {ts.trial_id}", "",
             f"Tool `{TOOL_VERSION}`. Every candidate path of the stitcher is ranked, highest score first; nothing is "
             "dropped and no threshold is applied (Correction J). The path score w1*LengthScore + w2*NodeScore + "
             "w3*IdentityCoherence is a score for ordering paths for an analyst, not a likelihood. Ties share the "
             "best rank; the order inside a tie is the path id, for display only.", "",
             f"Paths: {len(ts.paths)}; paths with no labelled unit: {stats['paths_without_labelled_unit']}; "
             f"paths with no crossing: {stats['paths_without_crossing']}; b0 units: {len(ts.b0)}.", ""]
    for v in PATH_VARIANTS:
        lines += [f"## Ranking, variant `{v}`", ""] + _ranked_table(ts, v) + [""]
    lines += ["## Multi-hop paths", ""] + _path_notes(ts.paths) + [""]
    lines += ["## Identity per in-path hop and account (Correction K)", "",
              "`exposed` = the moving account had a logon session open on the source host when LSASS was read "
              "there by a counted read, and the move came at or after that read (5 s tolerance). Exposure does not "
              "show that credentials were taken or used. `unknown:<reason>` = no evidence either way (machine "
              "account, source host unknown or without logs, or a session whose end is unknown); it scores 0 like "
              f"`not_exposed` but is not the same statement. Exposed (hop, account) rows in paths: {exposed}.", ""]
    lines += _identity_lines(ts) + [""]
    lines += ["## Baseline `b0` (labelled units, no linking)", "",
              "| rank | tie | unit | host | techniques | level | score |", "|---|---|---|---|---|---|---|"]
    by_id = {u.unit_id: u for u in ts.b0}
    for r in ts.b0_ranked:
        u = by_id[r.item_id]
        lines.append(f"| {r.rank} | {r.tie_size} | {u.unit_id[:16]} | {';'.join(u.hosts)} | "
                     f"{';'.join(u.techniques)} | {u.level_value} | {fmt_score(r.score)} |")
    lines += ["", "## Stated substitutions", "",
              "- LengthScore runs TPPR Eq. 6/7 over the transitions of the path's technique sequence, not over "
              "provenance-graph edges (SC-23); the ScoreNI term of Eq. 5 is dropped, alpha + beta = 1 (decision 062).",
              "- The order reference is five hand-built templates (order_table.json, pinned by SHA-256); the tactic "
              "tree is the templates mapped to tactics with consecutive repeats removed (TPPR p. 5).",
              "- A step across a hop boundary scores as direct (`hop_chain`, SC-21b).",
              "- NodeScore counts labelled context-0 nodes, one unit per count_key; the LSASS dump counts only "
              "through identity. NodeScore with context-1 nodes included is shown beside it (decision 063).",
              "- Counted LSASS reads exclude wmiprvse, csrss, wininit and MsMpEng at their system folder under a "
              "system account (decision 064).", "",
              "## Limitations", ""]
    lines += [f"- {k}: {text}" for k, text in LIMITATIONS]
    return "\n".join(lines) + "\n"
