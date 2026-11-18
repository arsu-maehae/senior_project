"""Stability sweep of the path score parameters on development trials (PLAN T9.5; spec 05_score section 5.2 step 2;
decision 066). Pure.

Each path's ``full`` score is recomputed from its ``ranked_paths.csv`` columns only: LengthScore
L = (1 - e^(-seq_len / lambda)) * edge_score (SC-23), then score = w1*L + w2*node_score + w3*identity_coherence
(SC-40), summed with ``math.fsum`` in the order L, N, I and ranked on the value rounded to 12 decimals (SC-41).
WHY from the written columns and not from the scorer: evaluate must not import score, and the sweep must show what
the written facts imply under other parameters, not re-derive the facts.

The sweep **never changes a parameter**: it reports, per grid point, the expected top-1 rate and MRR (hop reading,
decision 065 ties) over the keyed attack trials, the S06 check, and whether every key attack path keeps the expected
rank it has at the default. The default (lambda and w from the score ``run_info.json``) is checked first: the
recomputed scores must equal the written ``full`` scores within the rounding of the written columns, and must give
the written ranks; otherwise the run is refused, because a sweep built on other numbers would describe nothing.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Mapping, Sequence

from .inputs import EvalError
from .rank_metrics import Candidate, check_groups, placement

__all__ = ["LAMBDA_GRID", "W_STEPS", "SCORE_TOLERANCE", "PathComponents", "SweepTrial", "SweepPoint",
           "components_of", "length_score", "recompute", "rank_scores", "check_default", "grid_points",
           "evaluate_point", "run_sweep", "changed_keys", "stable_region", "informativeness"]

# Spec 05 section 5.2 step 2 / decision 066: lambda in {0.5, 1, 1/ln 2, 2, 3, 5}; w on the simplex in steps of 0.1.
LAMBDA_GRID: tuple[tuple[str, float], ...] = (("0.5", 0.5), ("1", 1.0), ("1/ln2", 1.0 / math.log(2.0)), ("2", 2.0),
                                              ("3", 3.0), ("5", 5.0))
W_STEPS = 10
# Since ATK-SC-24 (decision 069 item 4) the written columns carry 12 decimals, so the recomputed score lies within about
# 1e-12 of the written one; the tolerance stays at the old 6-decimal bound (still a refusal for any real difference,
# and unchanged so that a score run written before the fix is checked the same way).
SCORE_TOLERANCE = 1e-6 + 1e-9
_TIE_DECIMALS = 12               # SC-41, spelled here because evaluate must not import score


@dataclass(frozen=True)
class PathComponents:
    """The written facts of one ``full`` path: components, written score, rank and tie size."""
    path_id: str
    edge_score: float
    seq_len: int
    node_score: float
    identity: float
    score: float
    rank: int
    tie_size: int


@dataclass(frozen=True)
class SweepTrial:
    """One trial as the sweep needs it: its paths, and per key attack path the hop-reading matches (these do not
    depend on the score, so they are fixed once). An unkeyed trial (``keyed`` False) enters the default check only:
    it has no right / wrong and is not an S06 input."""
    trial_id: str
    paths: tuple[PathComponents, ...]
    key_matches: tuple[tuple[str, frozenset[str]], ...]     # (key path id, matching path ids), key order
    keyed: bool = True

    @property
    def attack(self) -> bool:
        """True when the key names at least one attack path (S06 keys name none)."""
        return bool(self.key_matches)


@dataclass(frozen=True)
class SweepPoint:
    """The metrics of one grid point."""
    lam_label: str
    lam: float
    w: tuple[float, float, float]
    kind: str                                   # grid / default_w
    top1: float | None
    mrr: float | None
    key_ranks: tuple[tuple[str, str, float | None], ...]   # (trial, key path, expected rank)
    s06_max: float | None
    attack_min: float | None


def components_of(ranked: Sequence[Mapping[str, str]]) -> tuple[PathComponents, ...]:
    """The ``full`` rows of ``ranked_paths.csv`` as PathComponents, sorted by path id."""
    out: list[PathComponents] = []
    for r in ranked:
        if r["variant"] != "full":
            continue
        try:
            out.append(PathComponents(path_id=r["path_id"], edge_score=float(r["edge_score"]),
                                      seq_len=int(r["seq_len"]), node_score=float(r["node_score"]),
                                      identity=float(r["identity_coherence"]), score=float(r["score"]),
                                      rank=int(r["rank"]), tie_size=int(r["tie_size"])))
        except (TypeError, ValueError):
            raise EvalError(f"refused: ranked_paths.csv full row {r.get('path_id', '?')} has a non-numeric "
                            "component") from None
    return tuple(sorted(out, key=lambda p: p.path_id))


def length_score(seq_len: int, edge_score: float, lam: float) -> float:
    """SC-23 / TPPR Eq. 7: (1 - e^(-seq_len / lambda)) * edge_score."""
    return (1.0 - math.exp(-seq_len / lam)) * edge_score


def recompute(paths: Sequence[PathComponents], lam: float, w: Sequence[float]) -> dict[str, float]:
    """path_id -> w1*L + w2*N + w3*I (``math.fsum`` in the order L, N, I, SC-41)."""
    return {p.path_id: math.fsum((w[0] * length_score(p.seq_len, p.edge_score, lam), w[1] * p.node_score,
                                  w[2] * p.identity)) for p in paths}


def rank_scores(scores: Mapping[str, float]) -> list[Candidate]:
    """Competition ranks on the score rounded to 12 decimals (SC-41); ``path_id`` orders inside a tie for display
    only. Returned as Candidates (no hop ids: the sweep matches by precomputed id sets)."""
    ordered = sorted(scores.items(), key=lambda it: (-round(it[1], _TIE_DECIMALS), it[0]))
    sizes: dict[float, int] = {}
    for _p, s in ordered:
        sizes[round(s, _TIE_DECIMALS)] = sizes.get(round(s, _TIE_DECIMALS), 0) + 1
    out: list[Candidate] = []
    rank, prev = 0, None
    for pos, (pid, s) in enumerate(ordered, start=1):
        v = round(s, _TIE_DECIMALS)
        if v != prev:
            rank, prev = pos, v
        out.append(Candidate(path_id=pid, rank=rank, tie_size=sizes[v], score=s, hop_ids=frozenset()))
    return out


def check_default(trials: Sequence[SweepTrial], lam: float, w: Sequence[float]) -> dict[str, float | int]:
    """Refuse unless the recomputed default scores equal the written ``full`` scores (within ``SCORE_TOLERANCE``)
    and give the written rank and tie size of every path. Returns {paths, max_abs_diff, rank_mismatch (= 0)}."""
    worst, n = 0.0, 0
    for t in trials:
        check_groups([(p.path_id, p.rank, p.tie_size) for p in t.paths], f"{t.trial_id} full ranks")
        scores = recompute(t.paths, lam, w)
        for p in t.paths:
            worst = max(worst, abs(scores[p.path_id] - p.score))
            n += 1
        if worst > SCORE_TOLERANCE:
            raise EvalError(f"refused: {t.trial_id}: a recomputed default score differs from the written full score "
                            f"by {worst:.3g} (> {SCORE_TOLERANCE:.3g})")
        got = {c.path_id: (c.rank, c.tie_size) for c in rank_scores(scores)}
        bad = sorted(p.path_id for p in t.paths if got[p.path_id] != (p.rank, p.tie_size))
        if bad:
            raise EvalError(f"refused: {t.trial_id}: recomputed default ranks differ from the written ranks for "
                            f"{len(bad)} path(s), e.g. {bad[0]}")
    return {"paths": n, "max_abs_diff": worst, "rank_mismatch": 0}


def grid_points(default_lam: float, default_w: Sequence[float]) -> list[tuple[str, float, tuple[float, float, float],
                                                                              str]]:
    """(lambda label, lambda, w, kind): every simplex point in steps of 0.1 at every grid lambda (``grid``), then the
    default w at every grid lambda (``default_w``). The grid lambda 1/ln 2 is replaced by the default lambda when the
    two agree to 1e-12, so the default point is computed with exactly the scorer's value."""
    out: list[tuple[str, float, tuple[float, float, float], str]] = []
    lams = [(lab, default_lam if math.isclose(v, default_lam, abs_tol=1e-12) else v) for lab, v in LAMBDA_GRID]
    for lab, lam in lams:
        for i in range(W_STEPS + 1):
            for j in range(W_STEPS + 1 - i):
                out.append((lab, lam, (i / W_STEPS, j / W_STEPS, (W_STEPS - i - j) / W_STEPS), "grid"))
    for lab, lam in lams:
        out.append((lab, lam, (float(default_w[0]), float(default_w[1]), float(default_w[2])), "default_w"))
    return out


def evaluate_point(trials: Sequence[SweepTrial], lam_label: str, lam: float, w: tuple[float, float, float],
                   kind: str) -> SweepPoint:
    """Metrics at one point: per key attack path its expected rank (065), per attack trial the top-1 credit and RR
    of its first match of any key attack path (handoff 14.2: per trial), their means, and the S06 inputs (highest
    score of a keyed trial without attack paths; lowest first-match score of the attack trials)."""
    key_ranks: list[tuple[str, str, float | None]] = []
    top1: list[float] = []
    rrs: list[float] = []
    s06: list[float] = []
    attack_low: list[float] = []
    for t in trials:
        if not t.keyed:
            continue
        cands = rank_scores(recompute(t.paths, lam, w))
        if not t.attack:
            s06.extend(c.score for c in cands)
            continue
        firsts: list[float | None] = []
        for kid, hit in t.key_matches:
            pl = placement(cands, hit)
            key_ranks.append((t.trial_id, kid, pl.rank_expected))
            firsts.append(pl.first_score)
        trial_pl = placement(cands, frozenset().union(*(h for _k, h in t.key_matches)))
        top1.append(trial_pl.top1_expected)
        rrs.append(trial_pl.rr("expected"))
        if all(f is not None for f in firsts):
            attack_low.append(min(f for f in firsts if f is not None))
    return SweepPoint(lam_label=lam_label, lam=lam, w=w, kind=kind,
                      top1=math.fsum(top1) / len(top1) if top1 else None,
                      mrr=math.fsum(rrs) / len(rrs) if rrs else None, key_ranks=tuple(key_ranks),
                      s06_max=max(s06) if s06 else None, attack_min=min(attack_low) if attack_low else None)


def run_sweep(trials: Sequence[SweepTrial], default_lam: float, default_w: Sequence[float]
              ) -> tuple[SweepPoint, list[SweepPoint], dict[str, float | int]]:
    """(default point, every grid point, default check facts). The default check runs first, over every trial
    (refusal on failure)."""
    check = check_default(trials, default_lam, default_w)
    w0 = (float(default_w[0]), float(default_w[1]), float(default_w[2]))
    default = evaluate_point(trials, "default", default_lam, w0, "default")
    points = [evaluate_point(trials, lab, lam, w, kind) for lab, lam, w, kind in grid_points(default_lam, default_w)]
    return default, points, check


def changed_keys(point: SweepPoint, default: SweepPoint) -> list[str]:
    """``trial:key path`` of every key attack path whose expected rank differs from the default (to 1e-9)."""
    ref = {(t, k): r for t, k, r in default.key_ranks}
    out: list[str] = []
    for t, k, r in point.key_ranks:
        d = ref.get((t, k))
        same = (r is None and d is None) or (r is not None and d is not None and abs(r - d) <= 1e-9)
        if not same:
            out.append(f"{t}:{k}")
    return out


def stable_region(points: Sequence[SweepPoint], default: SweepPoint) -> list[dict[str, object]]:
    """Per grid lambda: grid points, stable points (no key attack path's expected rank changes), and the stable
    radius = the smallest Chebyshev distance max_i |w_i - w_i(default)| from the default w to an unstable grid point
    at that lambda (every grid point strictly closer is stable; None when no point is unstable). Also whether the
    default w itself is stable at that lambda."""
    out: list[dict[str, object]] = []
    for lab, _v in LAMBDA_GRID:
        grid = [p for p in points if p.lam_label == lab and p.kind == "grid"]
        unstable = [p for p in grid if changed_keys(p, default)]
        dw = [p for p in points if p.lam_label == lab and p.kind == "default_w"]
        radius = min((max(abs(a - b) for a, b in zip(p.w, default.w)) for p in unstable), default=None)
        out.append({"lambda": lab, "grid_points": len(grid), "stable_points": len(grid) - len(unstable),
                    "stable_radius": radius, "default_w_stable": bool(dw) and not changed_keys(dw[0], default)})
    return out


def informativeness(trials: Sequence[SweepTrial]) -> dict[str, object]:
    """Why the sweep cannot move a development rank (ATK-SC-22, decision 069 item 9): per attack trial, whether every
    rival (a path matching no key attack path) has written score 0, and whether some rival has exactly the components
    (seq_len, edge_score, node_score, identity) of a matching path, so the two tie at every lambda and w. Pure."""
    attack = [t for t in trials if t.keyed and t.attack]
    zero: list[str] = []
    ties: list[str] = []
    for t in attack:
        hit = frozenset().union(*(h for _k, h in t.key_matches))
        rivals = [p for p in t.paths if p.path_id not in hit]
        facts = {(p.seq_len, p.edge_score, p.node_score, p.identity) for p in t.paths if p.path_id in hit}
        if all(p.score == 0.0 for p in rivals):
            zero.append(t.trial_id)
        if any((p.seq_len, p.edge_score, p.node_score, p.identity) in facts for p in rivals):
            ties.append(t.trial_id)
    return {"attack_trials": len(attack), "all_rivals_zero": tuple(zero), "tie_every_weight": tuple(ties)}
