"""Writer side of the score CSVs (spec 05_score sections 3.1-3.4 and 3.6; SC-41, SC-61).

WHY column tuples here and nowhere else: they are the spec contract, a test can compare them with the spec, and
``csv_text`` (the stitcher's) refuses a row whose keys differ from the column list, so a column cannot be added or
dropped silently. Scores are written with 6 decimals after rounding to the 12-decimal tie value (SC-41), so the text
of two tied paths is always equal. Pure: no file is opened.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Sequence

from stitch.outputs import csv_text

from .assemble import PathScore, TrialScores
from .identity import AccountIdentity
from .params import METHOD_IDENTITY, METHOD_SEQUENCE, PATH_VARIANTS, SCORE_DECIMALS, VARIANT_B0
from .rank import Ranked, tie_value

__all__ = ["RANKED_FILE", "STEPS_FILE", "UNITS_FILE", "IDENTITY_VALUES_FILE", "B0_FILE", "STATS_FILE", "REPORT_FILE",
           "RUN_INFO_FILE", "OUTPUT_FILES", "RANKED_COLUMNS", "STEPS_COLUMNS", "UNITS_COLUMNS",
           "IDENTITY_VALUES_COLUMNS", "B0_COLUMNS", "fmt_score", "technique_sequence_text", "ranked_rows",
           "step_rows", "unit_rows", "identity_value_rows", "b0_rows", "table", "csv_text"]

RANKED_FILE, STEPS_FILE, UNITS_FILE = "ranked_paths.csv", "path_steps.csv", "path_node_units.csv"
IDENTITY_VALUES_FILE, B0_FILE = "hop_identity_values.csv", "b0_ranked.csv"
STATS_FILE, REPORT_FILE, RUN_INFO_FILE = "stats.json", "report.md", "run_info.json"
# The eight files of spec 3, sorted: the only names an existing ``--out`` folder may hold (decision 054).
OUTPUT_FILES: tuple[str, ...] = tuple(sorted((RANKED_FILE, STEPS_FILE, UNITS_FILE, IDENTITY_VALUES_FILE, B0_FILE,
                                              STATS_FILE, REPORT_FILE, RUN_INFO_FILE)))

# Spec 3.1, in spec order.
RANKED_COLUMNS: tuple[str, ...] = (
    "trial_id", "variant", "rank", "tie_size", "path_id", "score", "length_score", "edge_score", "seq_len",
    "node_score", "n_node_units", "node_score_ctx1", "identity_coherence", "identity_low", "identity_high",
    "n_crossings", "n_crossings_coherent", "n_crossings_flagged", "n_hops", "hop_ids", "hosts", "isolated",
    "merged_from", "multi_chain_parent", "technique_sequence", "best_tier_min", "clock_unreliable",
)
# Spec 3.2.
STEPS_COLUMNS: tuple[str, ...] = (
    "path_id", "step", "from_technique", "to_technique", "from_tactic", "to_tactic", "tactic_score",
    "technique_score", "score_e", "basis", "method", "candidate_count", "time_delta_ms", "from_event_uids",
    "to_event_uids",
)
# Spec 3.3.
UNITS_COLUMNS: tuple[str, ...] = ("path_id", "count_key", "event_uids", "hop_id", "techniques", "level_value")
# Spec 3.4.
IDENTITY_VALUES_COLUMNS: tuple[str, ...] = (
    "hop_id", "account", "value", "identity_status", "applicable", "not_applicable", "method", "candidate_count",
    "deciding_dump_event_uids", "open_session_uids", "time_delta_ms", "order_within_uncertainty",
    "session_open_before_window", "hop_best_tier", "clock_unreliable",
)
# Spec 3.6.
B0_COLUMNS: tuple[str, ...] = (
    "trial_id", "variant", "rank", "tie_size", "unit_id", "event_uids", "host", "techniques", "level_value", "score",
)


def fmt_score(x: float) -> str:
    """A score with 6 decimals, from the 12-decimal tie value (SC-41), so tied values print identically."""
    return f"{tie_value(x):.{SCORE_DECIMALS}f}"


def _joined(items: Iterable[str]) -> str:
    """``;``-joined list text (the list separator of every stage)."""
    return ";".join(items)


def technique_sequence_text(ps: PathScore) -> str:
    """``T1021.002>T1570>T1569.002`` (spec 3.1)."""
    return ">".join(i.technique for i in ps.sequence)


def _ranked_row(trial_id: str, variant: str, r: Ranked, ps: PathScore) -> dict[str, str]:
    """One ``ranked_paths.csv`` row; stitch columns copied as written."""
    p, idn = ps.path, ps.identity
    return {
        "trial_id": trial_id, "variant": variant, "rank": str(r.rank), "tie_size": str(r.tie_size),
        "path_id": ps.path_id, "score": fmt_score(r.score), "length_score": fmt_score(ps.length.length_score),
        "edge_score": fmt_score(ps.length.edge_score), "seq_len": str(ps.length.seq_len),
        "node_score": fmt_score(ps.node_score), "n_node_units": str(len(ps.units)),
        "node_score_ctx1": fmt_score(ps.node_score_ctx1), "identity_coherence": fmt_score(idn.coherence),
        "identity_low": fmt_score(idn.low), "identity_high": fmt_score(idn.high),
        "n_crossings": str(idn.n_crossings), "n_crossings_coherent": str(idn.n_coherent),
        "n_crossings_flagged": str(idn.n_flagged), "n_hops": p["n_hops"], "hop_ids": p["hop_ids"],
        "hosts": p["hosts"], "isolated": p["isolated"], "merged_from": p["merged_from"],
        "multi_chain_parent": str(ps.multi_chain_parent), "technique_sequence": technique_sequence_text(ps),
        "best_tier_min": ps.best_tier_min, "clock_unreliable": str(ps.clock_unreliable),
    }


def ranked_rows(ts: TrialScores) -> list[dict[str, str]]:
    """All path-variant rows: variants in ``PATH_VARIANTS`` order, each in rank order (ties by path_id, display only)."""
    by_id = {ps.path_id: ps for ps in ts.paths}
    return [_ranked_row(ts.trial_id, v, r, by_id[r.item_id]) for v in PATH_VARIANTS for r in ts.ranked[v]]


def step_rows(paths: Sequence[PathScore]) -> list[dict[str, str]]:
    """One ``path_steps.csv`` row per transition (SC-61: method, candidate_count = 1, time_delta_ms, event uids)."""
    out: list[dict[str, str]] = []
    for ps in paths:
        for s in ps.steps:
            sc = s.score
            out.append({
                "path_id": ps.path_id, "step": str(s.step), "from_technique": s.src.technique,
                "to_technique": s.dst.technique, "from_tactic": sc.from_tactic, "to_tactic": sc.to_tactic,
                "tactic_score": fmt_score(sc.tactic_score), "technique_score": fmt_score(sc.technique_score),
                "score_e": fmt_score(sc.score_e), "basis": sc.basis, "method": METHOD_SEQUENCE,
                "candidate_count": "1", "time_delta_ms": "" if s.time_delta_ms is None else str(s.time_delta_ms),
                "from_event_uids": _joined(s.src.event_uids), "to_event_uids": _joined(s.dst.event_uids),
            })
    return out


def unit_rows(paths: Sequence[PathScore]) -> list[dict[str, str]]:
    """One ``path_node_units.csv`` row per NodeScore unit (SC-31), path then count_key order."""
    return [{"path_id": ps.path_id, "count_key": u.count_key, "event_uids": _joined(u.event_uids),
             "hop_id": _joined(u.hop_ids), "techniques": _joined(u.techniques), "level_value": str(u.level_value)}
            for ps in paths for u in ps.units]


def _identity_row(a: AccountIdentity, hop_tier: Mapping[str, str]) -> dict[str, str]:
    """One ``hop_identity_values.csv`` row (SC-50..54, SC-61; ``hop_best_tier`` reported only, 045)."""
    return {
        "hop_id": a.hop_id, "account": a.account, "value": "" if a.value is None else str(a.value),
        "identity_status": a.status, "applicable": str(int(a.applicable)), "not_applicable": a.not_applicable,
        "method": METHOD_IDENTITY, "candidate_count": str(a.candidate_count),
        "deciding_dump_event_uids": _joined(a.deciding_dump_event_uids),
        "open_session_uids": _joined(a.open_session_uids), "time_delta_ms": a.time_delta_ms,
        "order_within_uncertainty": str(a.order_within_uncertainty),
        "session_open_before_window": str(a.session_open_before_window),
        "hop_best_tier": hop_tier.get(a.hop_id, ""), "clock_unreliable": str(a.clock_unreliable),
    }


def identity_value_rows(ts: TrialScores) -> list[dict[str, str]]:
    """Every (hop, account) of ``hop_identity.csv``, hop then account order."""
    return [_identity_row(a, ts.hop_tier) for a in ts.accounts]


def b0_rows(ts: TrialScores) -> list[dict[str, str]]:
    """``b0_ranked.csv`` rows in rank order (ties by unit id, display only)."""
    by_id = {u.unit_id: u for u in ts.b0}
    out: list[dict[str, str]] = []
    for r in ts.b0_ranked:
        u = by_id[r.item_id]
        out.append({"trial_id": ts.trial_id, "variant": VARIANT_B0, "rank": str(r.rank), "tie_size": str(r.tie_size),
                    "unit_id": u.unit_id, "event_uids": _joined(u.event_uids), "host": _joined(u.hosts),
                    "techniques": _joined(u.techniques), "level_value": str(u.level_value),
                    "score": fmt_score(r.score)})
    return out


def table(columns: Sequence[str], rows: Sequence[Mapping[str, str]]) -> tuple[str, int]:
    """(CSV text with LF line ends, data row count)."""
    return csv_text(columns, rows), len(rows)
