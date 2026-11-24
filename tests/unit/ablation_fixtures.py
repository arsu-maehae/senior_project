"""Synthetic inputs of the cmdline_target ablation report (spec 06 section 10, AB-03, AB-08..AB-11). Test helper only.

`side_blobs(trials, ablated=...)` returns the bytes of every file of `ablation_report.side_files(trials)` for one side
(default or ablated), built by hand from the column names the spec's tables name (rank_totals.csv, rank.csv,
link_accuracy_summary.csv, stitch hops.csv / links.csv / run_info.json, evaluate run_info.json). Values are chosen so the
default and the ablated side differ in known places: the key hop falls from tier B to D, the node recall falls, the
hop reading does not move, b0 and the denominators do not move.

The first trial of `trials` is a keyed attack trial (key rows); the others carry stitch files only (as S06 / unkeyed
trials do for the rows the report reads).
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from typing import Mapping, Sequence

CMD = "cmdline_target"
ATTACK_VALUES = {
    False: dict(top1="0.900000", mrr="0.933333", mrr_key="0.833333", recall="0.877451", prec="0.795192",
                f1="0.830077", fnr="0.122549", auc="0.972222", b0_recall="0.260609", tier="B", session_methods=CMD),
    True: dict(top1="0.900000", mrr="0.933333", mrr_key="0.833333", recall="0.400000", prec="0.300000",
               f1="0.342857", fnr="0.600000", auc="0.900000", b0_recall="0.260609", tier="D", session_methods=""),
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def csv_bytes(rows: Sequence[Mapping[str, str]]) -> bytes:
    cols: list[str] = []
    for r in rows:
        cols += [k for k in r if k not in cols]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode("utf-8")


def totals_rows(v: Mapping[str, str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for reading in ("hop", "node"):
        for variant in ("full", "b1", "b2"):
            rows.append(dict(row_kind="ranking", variant=variant, match_reading=reading, contested_set="", scenario="",
                             attack_trials="5", key_paths="6", key_paths_matched="6", top1_expected=v["top1"],
                             mrr_expected=v["mrr"], mrr_per_key_expected=v["mrr_key"], chance_top1="0.248333",
                             chance_mrr="0.376825", chance_per_key_mrr="0.337831", chance_pos_top1="0.900000",
                             chance_pos_mrr="0.933333", chance_pos_per_key_mrr="0.833333", score_gap_min="0.000000",
                             trials_gap_positive="4", s06_trials="1", s06_max_score="0.277778",
                             key_attack_score_min="0.583333", s06_margin="0.305556", s06_reason=""))
    for variant in ("full", "b1", "b2", "b0"):
        rows.append(dict(row_kind="node_prf", variant=variant, match_reading="", contested_set="", scenario="",
                         attack_trials="5", node_precision_mean=v["prec"], node_recall_mean=v["recall"],
                         node_f1_mean=v["f1"], node_fnr_mean=v["fnr"], node_precision_trials="5",
                         node_recall_trials="5", node_f1_trials="5"))
    for variant in ("full", "b1", "b2"):
        rows.append(dict(row_kind="auc_pooled", variant=variant, match_reading="node", contested_set="", scenario="",
                         attack_trials="5", auc=v["auc"], auc_n_pos="6", auc_n_neg="27", auc_chance="0.500000",
                         auc_trials="6"))
    rows.append(dict(row_kind="ranking_contested", variant="full", match_reading="hop", contested_set="paired",
                     scenario="", attack_trials="2", key_paths="3", key_paths_matched="3", top1_expected="0.500000",
                     mrr_expected="0.750000", mrr_per_key_expected="0.666667", scope_trial_ids="s98_t00"))
    rows.append(dict(row_kind="b0_recall", variant="full", match_reading="", contested_set="", scenario="",
                     attack_trials="5", labelled_recall_trials="5", full_recall_mean=v["recall"],
                     b0_recall_mean=v["b0_recall"], scope_trial_ids="s98_t00"))
    return rows


def link_summary_rows(trial: str, v: Mapping[str, str]) -> list[dict[str, str]]:
    return [dict(row_kind="hop", trial_id=trial, key_hop_id="k-h1", key_role="attack", hop_id=f"{trial}-h0001",
                 match="matched", best_tier=v["tier"], rank1="1", rank1_tier=v["tier"],
                 key_session_tier=v["tier"], key_session_methods=v["session_methods"], candidate_count="1",
                 candidate_count_cmd="1" if v["session_methods"] else "0")]


def rank_rows(trial: str, v: Mapping[str, str]) -> list[dict[str, str]]:
    return [dict(row_kind="trial", variant="full", match_reading="hop", key_path_id="", n_candidates="5",
                 n_candidates_positive="2", top1_expected=v["top1"], rr_expected="1.000000", chance_top1="0.2",
                 chance_pos_top1="0.5", chance_rr="0.45", chance_pos_rr="0.75", first_match_score="0.666667",
                 key_attack_score_min="0.666667", other_score_max="0.1", score_gap="0.566667", contested="0"),
            dict(row_kind="key_path", variant="full", match_reading="hop", key_path_id=f"{trial}-p1",
                 mapped_hop_ids=f"{trial}-h0001", candidate_count="5", rank_expected="1.000000",
                 rr_expected="1.000000", chance_rank_expected="3.0", chance_rr="0.45", chance_pos_rank_expected="1.5",
                 chance_pos_rr="0.75"),
            dict(row_kind="b0_recall", variant="full_vs_b0", match_reading="", key_node_count="21",
                 key_nodes_labelled="3", n_positive_units="4", budget_nodes="19.500000", budget_nodes_labelled="2.0",
                 full_recall=v["recall"], b0_recall=v["b0_recall"], full_recall_labelled="0.830000",
                 b0_recall_labelled="0.422857", contested="0")]


def stitch_files(trial: str, ablated: bool, v: Mapping[str, str]) -> dict[str, bytes]:
    hops = csv_bytes([dict(hop_id=f"{trial}-h0001", best_tier=v["tier"] if trial == "" else v["tier"]),
                      dict(hop_id=f"{trial}-h0002", best_tier="D")])
    links = [dict(hop_id=f"{trial}-h0001", method=CMD if not ablated else "target_only",
                  session_methods=CMD if not ablated else "", confidence_tier=v["tier"]),
             dict(hop_id=f"{trial}-h0002", method="target_only", session_methods="", confidence_tier="D")]
    if not ablated:
        links.insert(1, dict(hop_id=f"{trial}-h0001", method="sysmon3_port", session_methods="sysmon3_port",
                             confidence_tier="C"))
    info = {"tool_version": "stitch test", "parameters": {}}
    if ablated:
        info["disabled_methods"] = [CMD]
        info["parameters"]["disabled_methods"] = [CMD]
    return {"hops.csv": hops, "links.csv": csv_bytes(links), "run_info.json": (json.dumps(info) + "\n").encode()}


def side_blobs(trials: Sequence[str], ablated: bool, *, keyed: Sequence[str] | None = None,
               tweak: Mapping[str, str] | None = None) -> dict[str, bytes]:
    """rel path (as in ``side_files``) -> bytes of one side. `tweak` overrides value fields (e.g. tier)."""
    v = dict(ATTACK_VALUES[ablated])
    v.update(tweak or {})
    keyed = list(trials[:1]) if keyed is None else list(keyed)
    out: dict[str, bytes] = {
        "evaluate/development/rank_totals.csv": csv_bytes(totals_rows(v)),
        "evaluate/development/link_accuracy_summary.csv": csv_bytes(
            [r for t in keyed for r in link_summary_rows(t, v)]
            or [dict(row_kind="none", trial_id="", key_hop_id="", key_role="")])}
    for t in trials:
        st = stitch_files(t, ablated, v)
        for name, data in st.items():
            out[f"stitch/{t}/{name}"] = data
        out[f"evaluate/{t}/rank.csv"] = csv_bytes(rank_rows(t, v) if t in keyed else
                                                   [dict(row_kind="distribution", variant="full", match_reading="hop")])
        info = {"inputs": {"stitch_files": {"hops.csv": sha(st["hops.csv"]), "links.csv": sha(st["links.csv"])}}}
        out[f"evaluate/{t}/run_info.json"] = (json.dumps(info) + "\n").encode()
    return out


def shas(blobs: Mapping[str, bytes]) -> dict[str, str]:
    return {k: sha(b) for k, b in blobs.items()}
