"""Synthetic worlds for the T10.A tests (spec 06_evaluate, rules EV-01..08 and RS-01..11; decisions 070, 071, 072).

Written from the spec and decisions, not from the implementation. Every world is a `rank_fixtures.RankWorld` (plain data:
candidate paths with their written score components, stitch hops, key paths, b0 units) so the numbers below are computed
by hand. Candidate score at the frozen parameters (lambda = 1/ln 2, w = 1/3 each): LengthScore L = (1 - e^(-seq_len/lambda))
* edge = 0.75 for seq_len 2 and edge 1, 0.5 for seq_len 1; score_full = (L + N + I) / 3, score_b1 = (L + N) / 2,
score_b2 = N (N = node_score, I = identity coherence).

Only development trial ids are used (s02_t00 ... s07_t00, s06_t01); no test-split id appears anywhere.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Sequence

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import rank_fixtures as rf  # noqa: E402
from evaluate.rank_run import TrialRank, rank_from_inputs  # noqa: E402

KEY_NODES = ["T_H1", "a1", "a2"]
POS: dict[str, Any] = dict(seq_len=2, edge=1.0, node=0.25, ident=1.0)       # full 0.666667, b1 0.5, b2 0.25
ZERO: dict[str, Any] = dict(seq_len=0, edge=0.0, node=0.0, ident=0.0)       # every variant 0


def assemble(w: rf.RankWorld) -> TrialRank:
    """The TrialRank of a world (pure assembly of already-checked inputs, split development)."""
    return rank_from_inputs(w.trial, "development", w.stitch_data(), w.score_data(), w.key_data())


def key1(extra_target: Sequence[str] = ("a2",), agent: Sequence[str] = ("a1",)) -> rf.KH:
    """Key hop K1: target 4624 T_H1 (logon id 0x100, so stitch hop H1 when H1 is the first hop) plus evidence uids."""
    return rf.KH("K1", "T_H1", 0x100, {"target_event_uids": list(extra_target), "agent_event_uids": list(agent)})


def one_key(trial: str, paths: list[rf.P], b0: list | None = None) -> rf.RankWorld:
    w = rf.RankWorld(trial=trial)
    w.paths = paths
    w.key_hops = [key1()]
    w.key_paths = [rf.KP("K1-path", "attack", ["K1"])]
    w.b0 = b0 if b0 is not None else [("u1", 1, ["zz"])]
    return w


def solo_world(trial: str = "s02_t00") -> rf.RankWorld:
    """The key path P1 is the only candidate with a score above 0 in every variant: uncontested for full, b1 and b2
    ('key path the only scored path'); one labelled b0 unit: uncontested for b0."""
    return one_key(trial, [rf.P("P1", ["H1"], nodes=list(KEY_NODES), units=[("k1", ["a1"], 1)], **POS),
                           rf.P("P2", ["H2"], nodes=["q1"], **ZERO)],
                   b0=[("u1", 1, ["a1"])])


def rival_only_world(trial: str = "s03_t00") -> rf.RankWorld:
    """ATK-EV-05: the key path P1 scores 0 in every variant and its only positive rival is P2."""
    return one_key(trial, [rf.P("P1", ["H1"], nodes=list(KEY_NODES), **ZERO),
                           rf.P("P2", ["H2"], nodes=["r1", "r2"], units=[("k9", ["r1"], 1)], **POS)],
                   b0=[("u1", 1, ["r1"]), ("u2", 1, ["a1"])])


def half_contested_world(trial: str = "s02_t00") -> rf.RankWorld:
    """ATK-EV-06 trial A: full has two positive candidates (P1 0.583333 with the key, P2 0.333333 by identity alone),
    b1 only one (P1 0.375, P2 0), b2 none (N = 0 for both)."""
    return one_key(trial, [rf.P("P1", ["H1"], seq_len=2, edge=1.0, node=0.0, ident=1.0, nodes=list(KEY_NODES)),
                           rf.P("P2", ["H2"], seq_len=0, edge=0.0, node=0.0, ident=1.0, nodes=["b1"])])


def two_key_world(trial: str = "s07_t00") -> rf.RankWorld:
    """ATK-EV-03: n = 6 candidates and two key attack paths. Node reading: K1 is matched by P1 only (m_1 = 1), K2 by P2
    and P3 (m_2 = 2); the per-trial union has m = 3. Positive full scores: P1 0.75, P2 0.333333, P3 0.25 (n_pos = 3);
    P4..P6 score 0."""
    w = rf.RankWorld(trial=trial)
    k2 = ["T_H2", "c1", "c2"]
    w.paths = [rf.P("P1", ["H1"], seq_len=2, edge=1.0, node=0.5, ident=1.0, nodes=list(KEY_NODES)),
               rf.P("P2", ["H2"], seq_len=1, edge=1.0, node=0.5, ident=0.0, nodes=list(k2)),
               rf.P("P3", ["H3"], seq_len=1, edge=0.5, node=0.5, ident=0.0, nodes=list(k2)),
               rf.P("P4", ["H4"], nodes=["x4"], **ZERO), rf.P("P5", ["H5"], nodes=["x5"], **ZERO),
               rf.P("P6", ["H6"], nodes=["x6"], **ZERO)]
    w.key_hops = [key1(), rf.KH("K2", "T_H2", 0x101, {"target_event_uids": ["c1"], "agent_event_uids": ["c2"]})]
    w.key_paths = [rf.KP("K1-path", "attack", ["K1"]), rf.KP("K2-path", "attack", ["K2"])]
    w.b0 = [("u1", 1, ["zz"])]
    return w


def tie_group_world(trial: str, t: int, m: int) -> rf.RankWorld:
    """t candidates with identical components (one tie group at rank 1), the first m hold the key node set: expected
    top-1 = m / t under the node reading (decision 065 tie rule)."""
    paths = [rf.P(f"P{i}", [f"H{i}"], nodes=list(KEY_NODES) if i <= m else [f"x{i}"], **POS) for i in range(1, t + 1)]
    return one_key(trial, paths)


def labelled_world(trial: str, labelled: bool = True) -> rf.RankWorld:
    """ATK-EV-01. labelled=True: 4 key nodes {T_H1, a1, a2, a3}, 2 of them labelled (a1, a2 inside b0 units u1 and u3);
    full's single top path holds both labelled nodes (labelled recall 1.0 under decision 071, 0.5 under the old
    denominator); b0 at the equal budget of 2 takes u1 (a1) and u2 (x1, no key node): labelled recall 0.5.
    labelled=False: 2 key nodes {T_H1, a1}, no labelled key node: the labelled recall is undefined."""
    w = rf.RankWorld(trial=trial)
    if labelled:
        w.paths = [rf.P("P1", ["H1"], seq_len=2, edge=1.0, node=0.5, ident=1.0, nodes=["T_H1", "a1", "a2", "a3"],
                        units=[("k1", ["a1"], 2), ("k2", ["a2"], 2)])]
        w.key_hops = [key1(extra_target=("a2", "a3"))]
        w.b0 = [("u1", 4, ["a1"]), ("u2", 3, ["x1"]), ("u3", 2, ["a2"])]
    else:
        w.paths = [rf.P("P1", ["H1"], seq_len=2, edge=1.0, node=0.5, ident=1.0, nodes=["T_H1", "a1"])]
        w.key_hops = [key1(extra_target=(), agent=("a1",))]
        w.b0 = [("u1", 3, ["z9"])]
    w.key_paths = [rf.KP("K1-path", "attack", ["K1"])]
    return w


def copy_world(trial: str, distinct: bool) -> rf.RankWorld:
    """ATK-EV-14. The stitch hop H1 holds one 4624 as `T_H1|T_H1c` (representative | ST-05 copy). distinct=False: two b0
    units with score 1.0 that hold the representative and its copy (one unit after the merge). distinct=True: two units
    that hold different nodes (a1, T_H1)."""
    w = one_key(trial, [rf.P("P1", ["H1"], nodes=list(KEY_NODES), units=[("k1", ["a1"], 4)], **POS)])
    w.members = {"H1": [("T_H1|T_H1c", 0x100)]}
    w.b0 = [("u1", 4, ["a1"]), ("u2", 4, ["T_H1"])] if distinct else [("u1", 4, ["T_H1"]), ("u2", 4, ["T_H1c"])]
    return w


def hop_only_world(trial: str = "s02_t00") -> rf.RankWorld:
    """Q5: the hop reading and the node reading differ. P1 (hop H1, the hop the key's target 4624 maps to) holds none of
    the key's nodes: hop reading Jaccard 1.0 (top-1 1.0), node reading no match (top-1 0.0). P2 scores 0."""
    return one_key(trial, [rf.P("P1", ["H1"], nodes=["z1", "z2", "z3"], units=[("k1", ["z1"], 1)], **POS),
                           rf.P("P2", ["H2"], nodes=["b1"], **ZERO)])


def benign_trial(trial: str = "s06_t00", node: float = 0.5, seq_len: int = 1, edge: float = 0.5,
                 ident: float = 0.0) -> TrialRank:
    """A keyed S06 trial (no key attack path): one benign path with the given components, one zero path."""
    w = rf.RankWorld(trial=trial)
    w.paths = [rf.P("B1", ["G1"], seq_len=seq_len, edge=edge, node=node, ident=ident, nodes=["g1"],
                    units=[("m1", ["g1"], 2)]),
               rf.P("B2", ["G2"], nodes=["g2"], **ZERO)]
    w.key_hops = []
    w.key_paths = [rf.KP("benign-1", "benign", [])]
    w.b0 = [("v1", 2, ["g1"])]
    return assemble(w)


def unkeyed_s06(trial: str = "s06_t01", node: float = 0.25, seq_len: int = 1, edge: float = 0.5,
                ident: float = 0.0) -> TrialRank:
    """An unkeyed S06 trial (no answer key): one path with the given components (default full score (0.25 + 0.25) / 3 =
    0.166667), one zero path."""
    w = rf.RankWorld(trial=trial, keyed=False)
    w.paths = [rf.P("U1", ["V1"], seq_len=seq_len, edge=edge, node=node, ident=ident, nodes=["u1"],
                    units=[("n1", ["u1"], 1)]),
               rf.P("U2", ["V2"], nodes=["u2"], **ZERO)]
    w.b0 = [("w1", 1, ["u1"])]
    return assemble(w)


def identity_world(trial: str = "s02_t00") -> rf.RankWorld:
    """H3 held: the key path P1 (identity 1) has full 0.666667 and b1 0.5; the rival P2 (identity 0) has full 0.416667 and
    b1 0.625. full ranks the key path first (RR 1.0), b1 second (RR 0.5)."""
    return one_key(trial, [rf.P("P1", ["H1"], nodes=list(KEY_NODES), **POS),
                           rf.P("P2", ["H2"], seq_len=2, edge=1.0, node=0.5, ident=0.0, nodes=["b1"])])


def write_repo_with(root: Path, *worlds: rf.RankWorld) -> list[rf.RankWorld]:
    """A fake development repo (all nine trials, as `rank_fixtures.development_repo`) in which the given worlds replace
    the trial of the same id."""
    out = rf.development_repo(root)
    for w in worlds:
        w.write(root)
    return out
