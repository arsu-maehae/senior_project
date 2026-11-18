"""Order reference and edge score (spec 05_score SC-10, SC-22, SC-22a; decision 062; TPPR Eq. 2, 3, 5, Fig. 5, 6a).

TPPR scores each step of a candidate path against an attack-pattern tree mined from CTI reports and does not publish
the tree. We replace it with hand-built templates (``order_table.json``, SC-10) and keep TPPR's formulas:

- technique-PT = prefix tree of the templates (shared prefixes merge, TPPR §3.3.1, Fig. 5);
- tactic-PT = prefix tree of the templates mapped technique -> tactic, with **consecutive repeated tactics removed**
  before insertion (TPPR p. 5 §3.3.1: "mapping the attack technique of each node into its corresponding attack tactic
  and filtering out consecutively repeated nodes"; fact-checker correction of SC-22a, 2026-11-18);
- TacticScore (Eq. 2), TechniqueScore (Eq. 3), ScoreE = alpha * TacticScore + beta * TechniqueScore (Eq. 5 with the
  ScoreNI term removed, 062 item 5).

Everything here is pure except ``load_order_table`` (reads the one file and checks its pin).
"""
from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import ScoreError
from .params import (BASIS_ABSENT, BASIS_DIRECT, BASIS_HOP_CHAIN, BASIS_INDIRECT, BASIS_SAME_TACTIC,
                     ORDER_TABLE_FILE, ORDER_TABLE_SHA256, ScoreParams)

__all__ = ["Template", "OrderTable", "PrefixTree", "OrderReference", "StepScore", "lf_sha256", "parse_order_table",
           "load_order_table", "collapse_repeats", "build_prefix_tree", "technique_tree", "tactic_tree",
           "path_lengths", "out_degree", "has_direct", "tactic_score", "technique_score", "stage_positions",
           "build_reference", "score_step", "hop_chain_step"]


@dataclass(frozen=True)
class Template:
    """One hand-built template (SC-10): an ordered technique list and the sources it cites."""
    template_id: str
    techniques: tuple[str, ...]
    sources: tuple[str, ...]


@dataclass(frozen=True)
class OrderTable:
    """The parsed ``order_table.json``: templates, technique -> tactic, and the pinned LF SHA-256 of the file."""
    templates: tuple[Template, ...]
    tactic_of: Mapping[str, str]
    sha256: str


@dataclass(frozen=True)
class PrefixTree:
    """A prefix tree as flat tuples. Node 0 is the unlabelled root; ``labels[i]`` is node i's label, ``children[i]``
    its child node indices. WHY flat tuples: hashable, deterministic, and easy to print in a test."""
    labels: tuple[str, ...]
    children: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class OrderReference:
    """Everything the step scorer needs, built once per run from the order table."""
    table: OrderTable
    tech_tree: PrefixTree
    tac_tree: PrefixTree
    stage: Mapping[str, int]


@dataclass(frozen=True)
class StepScore:
    """The score of one transition u -> v (spec 3.2 columns)."""
    from_tactic: str
    to_tactic: str
    tactic_score: float
    technique_score: float
    score_e: float
    basis: str


def lf_sha256(data: bytes) -> str:
    """SHA-256 of ``data`` with CRLF / CR turned into LF. WHY: a Windows checkout with core.autocrlf may rewrite the
    file's line ends; the pin must describe the content, not the checkout (same rule as the label rules, LB-13)."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")).hexdigest()


def _str_list(value: Any, what: str) -> tuple[str, ...]:
    """A non-empty list of non-empty strings, else ScoreError naming ``what``."""
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and x for x in value):
        raise ScoreError(f"refused: order table {what} must be a non-empty list of strings")
    return tuple(value)


def parse_order_table(data: bytes) -> OrderTable:
    """Parse and validate the order table bytes (SC-10). Pure.

    Refused when: not JSON, no templates, a template without id / techniques / sources (each template must cite its
    source, SC-10), a technique repeated inside one template, or a template technique with no tactic (the tactic-PT
    needs one tactic per technique, 062 item 2)."""
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ScoreError(f"refused: order table is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict) or not isinstance(obj.get("tactic_of"), dict):
        raise ScoreError("refused: order table lacks a 'tactic_of' object")
    tactic_of = {str(k): str(v) for k, v in sorted(obj["tactic_of"].items())}
    raw = obj.get("templates")
    if not isinstance(raw, list) or not raw:
        raise ScoreError("refused: order table has no templates")
    templates = []
    for t in raw:
        tid = t.get("id") if isinstance(t, dict) else None
        if not isinstance(tid, str) or not tid:
            raise ScoreError("refused: order table template without an id")
        techs = _str_list(t.get("techniques"), f"{tid} techniques")
        srcs = _str_list(t.get("sources"), f"{tid} sources")
        if len(set(techs)) != len(techs):
            raise ScoreError(f"refused: order table template {tid} repeats a technique")
        missing = [x for x in techs if x not in tactic_of]
        if missing:
            raise ScoreError(f"refused: order table template {tid} technique(s) without a tactic: {missing}")
        templates.append(Template(tid, techs, srcs))
    return OrderTable(templates=tuple(templates), tactic_of=tactic_of, sha256=lf_sha256(data))


def load_order_table(path: Path = ORDER_TABLE_FILE, expected_sha256: str = ORDER_TABLE_SHA256) -> OrderTable:
    """Read the order table and refuse it unless its LF SHA-256 equals the pin in ``params`` (SC-10, SC-42).
    WHY refuse: one added template changes out() and so every TacticScore (ATK-SC-10); the frozen result must name
    exactly one table."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise ScoreError(f"refused: cannot read order table {path}: {exc}") from exc
    table = parse_order_table(data)
    if table.sha256 != expected_sha256:
        raise ScoreError(f"refused: order table SHA-256 {table.sha256} differs from the pin {expected_sha256} "
                         f"(SC-10; a table change needs a new decision record)")
    return table


def collapse_repeats(seq: Sequence[str]) -> tuple[str, ...]:
    """Drop consecutive repeats (``CA, LM, LM, EX`` -> ``CA, LM, EX``). WHY: TPPR builds the tactic-PT by mapping each
    technique to its tactic "and filtering out consecutively repeated nodes" (p. 5 §3.3.1)."""
    out: list[str] = []
    for x in seq:
        if not out or out[-1] != x:
            out.append(x)
    return tuple(out)


def build_prefix_tree(sequences: Sequence[Sequence[str]]) -> PrefixTree:
    """Prefix tree of ``sequences``: sequences sharing a prefix share those nodes (TPPR Fig. 5). Pure; children are
    kept in insertion order, so the same sequences give the same tree."""
    labels: list[str] = [""]
    children: list[list[int]] = [[]]
    for seq in sequences:
        node = 0
        for label in seq:
            nxt = next((c for c in children[node] if labels[c] == label), None)
            if nxt is None:
                labels.append(label)
                children.append([])
                nxt = len(labels) - 1
                children[node].append(nxt)
            node = nxt
    return PrefixTree(labels=tuple(labels), children=tuple(tuple(c) for c in children))


def technique_tree(table: OrderTable) -> PrefixTree:
    """Technique-PT: the templates as they are (SC-22a)."""
    return build_prefix_tree([t.techniques for t in table.templates])


def tactic_tree(table: OrderTable) -> PrefixTree:
    """Tactic-PT: each template mapped technique -> tactic, consecutive repeats collapsed, then a prefix tree
    (SC-22a as corrected by the fact-checker against TPPR p. 5)."""
    return build_prefix_tree([collapse_repeats([table.tactic_of[x] for x in t.techniques])
                              for t in table.templates])


def _descendant_depths(tree: PrefixTree, start: int) -> list[tuple[int, int]]:
    """(node, distance) for every proper descendant of ``start`` (depth-first, deterministic)."""
    out: list[tuple[int, int]] = []
    stack = [(c, 1) for c in reversed(tree.children[start])]
    while stack:
        node, d = stack.pop()
        out.append((node, d))
        stack.extend((c, d + 1) for c in reversed(tree.children[node]))
    return out


def path_lengths(tree: PrefixTree, u: str, v: str) -> list[int]:
    """len(p) for every p in P(u, v): downward paths from ANY node labelled ``u`` to a descendant labelled ``v``
    (SC-22a). Several nodes may carry one label (shared label in two branches), so all of them start paths."""
    return [d for i, lab in enumerate(tree.labels) if i and lab == u
            for node, d in _descendant_depths(tree, i) if tree.labels[node] == v]


def out_degree(tree: PrefixTree, label: str) -> int:
    """out(label) = number of children summed over all nodes carrying ``label`` (SC-22a)."""
    return sum(len(tree.children[i]) for i, lab in enumerate(tree.labels) if i and lab == label)


def has_direct(tree: PrefixTree, u: str, v: str) -> bool:
    """Pi_direct of Eq. 3: some node labelled ``u`` has a child labelled ``v``."""
    return any(tree.labels[c] == v for i, lab in enumerate(tree.labels) if i and lab == u for c in tree.children[i])


def tactic_score(tree: PrefixTree, ta_u: str, ta_v: str, b: float) -> float:
    """TacticScore (TPPR Eq. 2; SC-22a): b when both tactics are equal; else b * sum(1/len p) / out(TA_u) over
    P(TA_u, TA_v), capped at b; 0 when no path exists, out = 0, or a tactic is unknown.

    WHY the cap and the same-tactic value: both come from TPPR's Fig. 6a text (p. 7), not from Eq. 2 itself; they are
    applied as a stated reading so TacticScore stays in [0, b]."""
    if ta_u and ta_u == ta_v:
        return b
    if not ta_u or not ta_v:
        return 0.0
    out = out_degree(tree, ta_u)
    lengths = path_lengths(tree, ta_u, ta_v)
    if out == 0 or not lengths:
        return 0.0
    return min(b, b * sum(1.0 / n for n in lengths) / out)


def technique_score(tree: PrefixTree, u: str, v: str, a: float, eps: float) -> float:
    """TechniqueScore (TPPR Eq. 3; SC-22a) = a * max(Pi_direct, max over paths of len >= 2 of 1/len p, eps). WHY the
    eps floor: TPPR gives unobserved transitions "a negligible probability" (p. 6) instead of 0."""
    direct = 1.0 if has_direct(tree, u, v) else 0.0
    indirect = max((1.0 / n for n in path_lengths(tree, u, v) if n >= 2), default=0.0)
    return a * max(direct, indirect, eps)


def stage_positions(table: OrderTable) -> dict[str, int]:
    """Stage of a technique = its smallest 0-based position in any template (SC-21: "position in the reference").
    WHY the smallest position and never ATT&CK tactic IDs: the matrix puts Execution before Lateral Movement, but
    PsExec runs its service after the move (S0029), so only the templates may order T1569.002 after T1021.002 (062).
    Example: T1021.002 = 1 (R3), T1570 = 2 (R3), T1569.002 = 3 (R1, R4)."""
    stage: dict[str, int] = {}
    for t in table.templates:
        for i, x in enumerate(t.techniques):
            stage[x] = min(i, stage.get(x, i))
    return dict(sorted(stage.items()))


def build_reference(table: OrderTable) -> OrderReference:
    """Both trees and the stage map, built once (pure)."""
    return OrderReference(table=table, tech_tree=technique_tree(table), tac_tree=tactic_tree(table),
                          stage=stage_positions(table))


def _basis(ref: OrderReference, u: str, v: str, ta_u: str, ta_v: str) -> str:
    """SC-22a ``basis``: a technique in no template -> absent; else direct (Pi_direct = 1), same_tactic, indirect (a
    technique path exists), absent. WHY this precedence: it names the term that decided the step's score."""
    if u not in ref.stage or v not in ref.stage:
        return BASIS_ABSENT
    if has_direct(ref.tech_tree, u, v):
        return BASIS_DIRECT
    if ta_u and ta_u == ta_v:
        return BASIS_SAME_TACTIC
    if path_lengths(ref.tech_tree, u, v):
        return BASIS_INDIRECT
    return BASIS_ABSENT


def score_step(ref: OrderReference, u: str, v: str, params: ScoreParams) -> StepScore:
    """ScoreE of a within-hop transition u -> v, or of a boundary between two hops with no chain edge between them
    (siblings of a merged path, ATK-SC-17) (SC-22, SC-22a): alpha * TacticScore + beta * TechniqueScore. A
    technique missing from ``tactic_of`` has tactic "" and so TacticScore 0 (an empty tactic is never "the same
    tactic"); its TechniqueScore is eps and its basis ``absent``."""
    ta_u, ta_v = ref.table.tactic_of.get(u, ""), ref.table.tactic_of.get(v, "")
    tac = tactic_score(ref.tac_tree, ta_u, ta_v, params.b)
    tech = technique_score(ref.tech_tree, u, v, params.a, params.eps)
    return StepScore(from_tactic=ta_u, to_tactic=ta_v, tactic_score=tac, technique_score=tech,
                     score_e=params.alpha * tac + params.beta * tech, basis=_basis(ref, u, v, ta_u, ta_v))


def hop_chain_step(ref: OrderReference, u: str, v: str, params: ScoreParams) -> StepScore:
    """A transition across a real chain edge between two hops (SC-21b): scored as a direct step, ScoreE = alpha * b +
    beta * a, because the stitcher's chain edge (ST-72) already fixes that order (ATK-SC-05: scoring execution ->
    initial-access against the templates would give eps and penalise every multi-hop path). Only for a boundary with a
    ``path_edges`` edge from -> to (ATK-SC-17, decision 069 item 1, amends 067 item 4); the caller decides that."""
    return StepScore(from_tactic=ref.table.tactic_of.get(u, ""), to_tactic=ref.table.tactic_of.get(v, ""),
                     tactic_score=params.b, technique_score=params.a,
                     score_e=params.alpha * params.b + params.beta * params.a, basis=BASIS_HOP_CHAIN)
