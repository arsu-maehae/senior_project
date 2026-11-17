"""Synthetic worlds for the T9.5 ranking check tests (spec 05_score SCA-06, section 7.3; decisions 065, 066, 068).

Written from the spec and decisions, not from the implementation. A `RankWorld` is described by plain data (candidate
paths with their score components, stitch hops, key paths) and turned into the three things the check reads:

- in-memory objects (`stitch_data`, `score_data`, `key_data`) for the pure assembly, and
- a fake repo on disk (`write_repo`): `out/stitch/<t>/` (ten files, hashes in run_info), `out/score/<t>/` (ranked_paths,
  b0_ranked, path_node_units, run_info with hashes, inputs.stitch and parameters) and `ground_truth/approved/<t>.yaml`.

Ranks are computed here by an independent implementation of SC-41 (competition ranks on the score rounded to 12
decimals, scores summed with `math.fsum` in the order L, N, I from the 6-decimal written components). Nothing under the
real `out/`, `data/` or `ground_truth/` is touched.
"""
from __future__ import annotations

import json
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import evaluate_fixtures as ef  # noqa: E402
from evaluate.inputs import KeyData, StitchData  # noqa: E402
from evaluate.rank_inputs import ScoreData  # noqa: E402

LAM = 1.0 / math.log(2.0)
W = (1 / 3, 1 / 3, 1 / 3)
DB_SHA = "a" * 64
RANKED_COLS = ["trial_id", "variant", "rank", "tie_size", "path_id", "score", "length_score", "edge_score", "seq_len",
               "node_score", "n_node_units", "node_score_ctx1", "identity_coherence", "identity_low", "identity_high",
               "n_crossings", "n_crossings_coherent", "n_crossings_flagged", "n_hops", "hop_ids", "hosts", "isolated",
               "merged_from", "multi_chain_parent", "technique_sequence", "best_tier_min", "clock_unreliable"]
B0_COLS = ["trial_id", "variant", "rank", "tie_size", "unit_id", "event_uids", "host", "techniques", "level_value",
           "score"]
UNIT_COLS = ["path_id", "count_key", "event_uids", "hop_id", "techniques", "level_value"]


def f6(x: float) -> str:
    return f"{x:.6f}"


def competition(scores: Mapping[str, float]) -> dict[str, tuple[int, int]]:
    """pid -> (rank, tie_size): competition ranking on the score rounded to 12 decimals (SC-41)."""
    r12 = {k: round(v, 12) for k, v in scores.items()}
    return {k: (1 + sum(1 for o in r12.values() if o > v), sum(1 for o in r12.values() if o == v))
            for k, v in r12.items()}


@dataclass
class P:
    """One candidate path: hops, written components, `context` = 0 node uids, labelled units."""
    pid: str
    hops: list[str]
    seq_len: int = 1
    edge: float = 1.0
    node: float = 0.0
    ident: float = 0.0
    nodes: list[str] = field(default_factory=list)
    ctx1: list[str] = field(default_factory=list)
    units: list[tuple[str, list[str], int]] = field(default_factory=list)       # (count_key, uids, level)


@dataclass
class KH:
    """One key hop: its target 4624 (uid, logon id) and the uid lists it carries (field name -> uids)."""
    hop_id: str
    uid: str
    lid: int
    fields: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class KP:
    path_id: str
    role: str
    hops: list[str]


@dataclass
class RankWorld:
    trial: str = "s02_t00"
    paths: list[P] = field(default_factory=list)
    key_hops: list[KH] = field(default_factory=list)
    key_paths: list[KP] = field(default_factory=list)
    keyed: bool = True
    members: dict[str, list[tuple[str, int]]] = field(default_factory=dict)      # stitch hop -> [(uid, lid)]
    b0: list[tuple[str, int, list[str]]] = field(default_factory=list)           # (unit_id, level, uids)
    lam: float = LAM
    w: tuple[float, float, float] = W
    tamper: Any = None                                                           # fn(ranked rows) before writing

    # ---------------------------------------------------------------- derived rows
    def hop_ids(self) -> list[str]:
        seen: list[str] = []
        for p in self.paths:
            for h in p.hops:
                if h not in seen:
                    seen.append(h)
        for h in self.members:
            if h not in seen:
                seen.append(h)
        return seen

    def member_of(self, hop: str) -> list[tuple[str, int]]:
        if hop in self.members:
            return self.members[hop]
        return [(f"T_{hop}", 0x100 + self.hop_ids().index(hop))]

    def length(self, p: P) -> float:
        return (1.0 - math.exp(-p.seq_len / self.lam)) * p.edge

    def full_score(self, p: P) -> float:
        l6, n6, i6 = (float(f6(x)) for x in (self.length(p), p.node, p.ident))
        return math.fsum((self.w[0] * l6, self.w[1] * n6, self.w[2] * i6))

    def variant_scores(self) -> dict[str, dict[str, float]]:
        w1, w2, _w3 = self.w
        out: dict[str, dict[str, float]] = {"full": {}, "b1": {}, "b2": {}}
        for p in self.paths:
            l6, n6 = float(f6(self.length(p))), float(f6(p.node))
            out["full"][p.pid] = self.full_score(p)
            out["b1"][p.pid] = math.fsum((w1 * l6, w2 * n6)) / (w1 + w2)
            out["b2"][p.pid] = n6
        return out

    def ranked_rows(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for variant, scores in self.variant_scores().items():
            ranks = competition(scores)
            for p in sorted(self.paths, key=lambda q: (ranks[q.pid][0], q.pid)):
                rows.append({"trial_id": self.trial, "variant": variant, "rank": str(ranks[p.pid][0]),
                             "tie_size": str(ranks[p.pid][1]), "path_id": p.pid, "score": f6(scores[p.pid]),
                             "length_score": f6(self.length(p)), "edge_score": f6(p.edge), "seq_len": str(p.seq_len),
                             "node_score": f6(p.node), "n_node_units": str(len(p.units)),
                             "node_score_ctx1": f6(p.node), "identity_coherence": f6(p.ident),
                             "identity_low": f6(p.ident), "identity_high": f6(p.ident), "n_crossings": "1",
                             "n_crossings_coherent": "1", "n_crossings_flagged": "0", "n_hops": str(len(p.hops)),
                             "hop_ids": ";".join(p.hops), "hosts": "ep-01>ep-02", "isolated": "0",
                             "merged_from": ";".join(p.hops), "multi_chain_parent": "0", "technique_sequence": "",
                             "best_tier_min": "B", "clock_unreliable": "0"})
        if self.tamper:
            self.tamper(rows)
        return rows

    def b0_rows(self) -> list[dict[str, str]]:
        scores = {u: lvl / 4 for u, lvl, _ in self.b0}
        ranks = competition(scores)
        out = []
        for u, lvl, uids in sorted(self.b0, key=lambda t: (ranks[t[0]][0], t[0])):
            out.append({"trial_id": self.trial, "variant": "b0", "rank": str(ranks[u][0]),
                        "tie_size": str(ranks[u][1]), "unit_id": u, "event_uids": ";".join(uids), "host": "ep-02",
                        "techniques": "", "level_value": str(lvl), "score": f6(lvl / 4)})
        return out

    def unit_rows(self) -> list[dict[str, str]]:
        return [{"path_id": p.pid, "count_key": k, "event_uids": ";".join(u), "hop_id": p.hops[0], "techniques": "",
                 "level_value": str(lvl)} for p in self.paths for k, u, lvl in p.units]

    def stitch_rows(self) -> dict[str, list[dict[str, str]]]:
        hops = []
        for h in self.hop_ids():
            mem = self.member_of(h)
            hops.append(ef.hop_row(h, [u for u, _ in mem], [i for _, i in mem]))
        paths = [{"path_id": p.pid, "hop_ids": ";".join(p.hops), "hosts": "ep-01>ep-02", "n_hops": str(len(p.hops)),
                  "merged_from": ";".join(p.hops), "isolated": "0", "edge_types": ""} for p in self.paths]
        nodes = []
        for p in self.paths:
            for u in p.nodes:
                nodes.append({"path_id": p.pid, "hop_id": p.hops[0], "role": "member", "context": "0",
                              "host": "ep-02", "event_uid": u})
            for u in p.ctx1:
                nodes.append({"path_id": p.pid, "hop_id": p.hops[0], "role": "session_context", "context": "1",
                              "host": "ep-01", "event_uid": u})
        return {"hops.csv": hops, "paths.csv": paths, "path_nodes.csv": nodes}

    def key_json(self) -> dict[str, Any]:
        hops = [ef.key_hop(k.hop_id, target_uids=[k.uid], target_lid=k.lid, **{n: list(v) for n, v in k.fields.items()})
                for k in self.key_hops]
        for kh, k in zip(hops, self.key_hops):
            kh["target_event_uids"] = sorted(set([k.uid] + list(k.fields.get("target_event_uids", []))))
        return {"trial_id": self.trial, "db_sha256": DB_SHA, "status": "approved", "hops": hops, "event_keys": {},
                "paths": [{"path_id": kp.path_id, "role": kp.role, "hop_ids": list(kp.hops)} for kp in self.key_paths]}

    # ---------------------------------------------------------------- texts and objects
    def texts(self) -> dict[str, dict[str, str]]:
        """{'stitch': {name: text}, 'score': {name: text}} (run_info.json included, hashes consistent)."""
        sr = self.stitch_rows()
        stitch = {"hops.csv": ef.csv_text(ef.HOP_COLS, sr["hops.csv"]), "links.csv": ef.csv_text(ef.LINK_COLS, []),
                  "hop_artefacts.csv": ef.csv_text(ef.ART_COLS, []),
                  "hop_identity.csv": ef.csv_text(ef.IDENT_COLS, []),
                  "paths.csv": ef.csv_text(ef.PATH_COLS, sr["paths.csv"]),
                  "path_edges.csv": ef.csv_text(ef.EDGE_COLS, []),
                  "path_nodes.csv": ef.csv_text(ef.NODE_COLS, sr["path_nodes.csv"]),
                  "stats.json": json.dumps({"hops": len(sr["hops.csv"])}) + "\n", "report.md": "# stitch\n"}
        s_info = {"trial_id": self.trial, "parameters": {}, "db": {"path": "x", "sha256_before": DB_SHA,
                                                                    "sha256_after": DB_SHA},
                  "files": {n: {"sha256": ef.sha256_text(t), "rows": None} for n, t in stitch.items()}}
        stitch["run_info.json"] = json.dumps(s_info, sort_keys=True, indent=1) + "\n"
        score = {"ranked_paths.csv": ef.csv_text(RANKED_COLS, self.ranked_rows()),
                 "b0_ranked.csv": ef.csv_text(B0_COLS, self.b0_rows()),
                 "path_node_units.csv": ef.csv_text(UNIT_COLS, self.unit_rows())}
        read = {n: ef.sha256_text(stitch[n]) for n in ("hops.csv", "paths.csv", "path_nodes.csv", "hop_identity.csv",
                                                       "path_edges.csv", "run_info.json")}
        r_info = {"trial_id": self.trial, "files": {n: {"sha256": ef.sha256_text(t), "rows": None}
                                                    for n, t in score.items()},
                  "inputs": {"stitch": read, "label": {}}, "order_table_sha256": "0" * 64,
                  "parameters": {"lam": self.lam, "w1": self.w[0], "w2": self.w[1], "w3": self.w[2]}}
        score["run_info.json"] = json.dumps(r_info, sort_keys=True, indent=1) + "\n"
        return {"stitch": stitch, "score": score}

    def stitch_data(self) -> StitchData:
        t = self.texts()["stitch"]
        import csv
        import io

        def rows(name: str) -> tuple[dict[str, str], ...]:
            return tuple(csv.DictReader(io.StringIO(t[name], newline="")))
        return StitchData(Path("x"), {n: ef.sha256_text(x) for n, x in t.items()}, rows("hops.csv"), rows("links.csv"),
                          rows("hop_artefacts.csv"), rows("hop_identity.csv"), rows("paths.csv"),
                          rows("path_edges.csv"), rows("path_nodes.csv"), json.loads(t["stats.json"]),
                          json.loads(t["run_info.json"]))

    def score_data(self) -> ScoreData:
        t = self.texts()["score"]
        import csv
        import io

        def rows(name: str) -> tuple[dict[str, str], ...]:
            return tuple(csv.DictReader(io.StringIO(t[name], newline="")))
        return ScoreData(Path("y"), rows("ranked_paths.csv"), rows("b0_ranked.csv"), rows("path_node_units.csv"),
                         json.loads(t["run_info.json"]), ef.sha256_text(t["run_info.json"]),
                         {n: ef.sha256_text(x) for n, x in t.items()})

    def key_data(self) -> KeyData | None:
        if not self.keyed:
            return None
        return KeyData("ground_truth/approved/x.yaml", "k" * 64, "not_required", self.key_json())

    # ---------------------------------------------------------------- disk
    def write(self, repo: Path) -> None:
        tx = self.texts()
        for stage, files in tx.items():
            d = Path(repo) / "out" / stage / self.trial
            d.mkdir(parents=True, exist_ok=True)
            for n, t in files.items():
                (d / n).write_text(t, encoding="utf-8", newline="\n")
        if self.keyed:
            kp = Path(repo) / "ground_truth" / "approved" / f"{self.trial}.yaml"
            kp.parent.mkdir(parents=True, exist_ok=True)
            kp.write_text(json.dumps(self.key_json(), indent=1) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- the standard worlds
def tie_world(trial: str = "s04_t00") -> RankWorld:
    """Five candidates; key attack path K1 -> H1.

    full scores (hand): P1 = P2 = (0.75 + 0.25 + 1) / 3 = 0.666667 (rank 1, tie 2), P3 = (0.25 + 0.625 + 0) / 3 =
    0.291667 (rank 3), P5 = 0.5 / 3 = 0.166667 (rank 4), P4 = 0 (rank 5).
    b1 = (L + N) / 2: P1 = P2 = 0.5, P3 = 0.4375, P5 = 0.25, P4 = 0.   b2 = N: P3 0.625, P5 0.5, P1 = P2 0.25, P4 0.
    Key node set = {T_H1, a1, a2} (target_event_uids + agent_event_uids; related / identity_basis / candidates excluded).
    Node reading: P1 Jaccard 1.0, P5 {T_H1, a1, z} 0.5 (match), P3 {T_H1, y, z} 0.2 (no).
    """
    w = RankWorld(trial=trial)
    w.paths = [
        P("P1", ["H1"], seq_len=2, edge=1.0, node=0.25, ident=1.0, nodes=["T_H1", "a1", "a2"], ctx1=["d1"],
          units=[("k1", ["a1"], 1), ("k2", ["a2"], 1)]),
        P("P2", ["H2"], seq_len=2, edge=1.0, node=0.25, ident=1.0, nodes=["b1", "b2"],
          units=[("k3", ["b1"], 1)]),
        P("P3", ["H3"], seq_len=1, edge=0.5, node=0.625, ident=0.0, nodes=["T_H1x", "y", "z3"],
          units=[("k4", ["y"], 2)]),
        P("P4", ["H4"], seq_len=0, edge=0.0, node=0.0, ident=0.0, nodes=["q1"]),
        P("P5", ["H5"], seq_len=0, edge=0.0, node=0.5, ident=0.0, nodes=["T_H1", "a1", "z"],
          units=[("k5", ["z"], 2)]),
    ]
    # P3 above: nodes {T_H1x, y, z3} share nothing with the key (Jaccard 0); the 0.2 case is a separate unit test.
    w.key_hops = [KH("K1", "T_H1", 0x100, {"target_event_uids": ["a2"], "agent_event_uids": ["a1"],
                                             "related_logon_uids": ["r1"], "identity_basis": ["d1"],
                                             "candidates": ["c1"]})]
    w.key_paths = [KP("K1-path", "attack", ["K1"])]
    w.b0 = [("u1", 4, ["a1", "a2"]), ("u2", 3, ["b1"]), ("u3", 2, ["T_H1"]), ("u4", 1, ["q1"])]
    return w


def benign_world(trial: str = "s06_t00") -> RankWorld:
    """A keyed trial with no attack path (S06): benign paths only, highest full score 0.277778."""
    w = RankWorld(trial=trial)
    w.paths = [P("B1", ["G1"], seq_len=1, edge=0.5, node=0.5, ident=0.0, nodes=["g1"],
                 units=[("m1", ["g1"], 2)]),
               P("B2", ["G2"], seq_len=0, edge=0.0, node=0.0, ident=0.0, nodes=["g2"])]
    w.key_hops = []
    w.key_paths = [KP("benign-1", "benign", [])]
    w.b0 = [("v1", 2, ["g1"])]
    return w


def unkeyed_world(trial: str = "s02_t01") -> RankWorld:
    w = RankWorld(trial=trial, keyed=False)
    w.paths = [P("U1", ["V1"], seq_len=1, edge=1.0, node=0.5, ident=1.0, nodes=["u1"], units=[("n1", ["u1"], 2)]),
               P("U2", ["V2"], seq_len=0, edge=0.0, node=0.0, ident=0.0, nodes=["u2"])]
    w.b0 = [("w1", 2, ["u1"])]
    return w


def development_repo(root: Path) -> list[RankWorld]:
    """A fake repo holding all nine development trials (so `--development` runs): s02, s03, s04, s05, s07 t00 attack
    worlds (the tie world), s06_t00 benign, s02_t01, s03_t01, s06_t01 unkeyed."""
    from evaluate.params import DEVELOPMENT_TRIALS
    worlds: list[RankWorld] = []
    for t in DEVELOPMENT_TRIALS:
        if t == "s06_t00":
            w = benign_world(t)
        elif t.endswith("_t00"):
            w = tie_world(t)
        else:
            w = unkeyed_world(t)
        w.write(root)
        worlds.append(w)
    return worlds


def snapshot(root: Path) -> dict[str, bytes | None]:
    """relative path -> bytes (None for a folder), for 'nothing written' checks."""
    out: dict[str, bytes | None] = {}
    for p in sorted(Path(root).rglob("*")):
        out[p.relative_to(root).as_posix()] = None if p.is_dir() else p.read_bytes()
    return out
