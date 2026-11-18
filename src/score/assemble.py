"""Assemble the per-path components and the rankings of one trial (spec 05_score SC-04, SC-20..SC-54, SC-40, SC-41,
section 3.6). Pure: takes the parsed inputs (``inputs.ScoreInputs``) and the order reference, returns every number
the writers need. Nothing is dropped, merged or split here (SC-04; merging is the stitcher's, ST-73).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from gate.timeutil import to_us

from .baselines import B0Unit, b0_units, variant_score
from .errors import ScoreError
from .identity import AccountIdentity, HopIdentity, PathIdentity, account_identities, hop_identities, path_identity
from .inputs import ScoreInputs
from .length import LengthResult, Step, length_score, transitions
from .nodes import Unit, count_key_map, node_score, node_units
from .order import OrderReference
from .params import PATH_VARIANTS, TIER_ORDER, ScoreParams
from .rank import Ranked, competition_ranks
from .sequence import SeqItem, chain_order, hop_technique_uids, split_list, technique_sequence

__all__ = ["PathScore", "TrialScores", "event_times", "first_times", "best_tier_min", "identity_accounts",
           "missing_member_accounts", "score_path", "score_trial"]

Row = Mapping[str, str]


@dataclass(frozen=True)
class PathScore:
    """Every component of one stitch path (one ``ranked_paths.csv`` row per variant)."""
    path: Row                                   # the paths.csv row, copied fields come from here
    chain: tuple[str, ...]
    sequence: tuple[SeqItem, ...]
    steps: tuple[Step, ...]
    length: LengthResult
    units: tuple[Unit, ...]
    node_score: float
    node_score_ctx1: float
    identity: PathIdentity
    best_tier_min: str
    multi_chain_parent: int
    clock_unreliable: int
    scores: Mapping[str, float] = field(default_factory=dict)

    @property
    def path_id(self) -> str:
        """The stitch path id."""
        return self.path["path_id"]


@dataclass(frozen=True)
class TrialScores:
    """Everything one trial produced, before any text is written."""
    trial_id: str
    paths: tuple[PathScore, ...]
    ranked: Mapping[str, tuple[Ranked, ...]]
    accounts: tuple[AccountIdentity, ...]
    hops: Mapping[str, HopIdentity]
    hop_tier: Mapping[str, str]
    b0: tuple[B0Unit, ...]
    b0_ranked: tuple[Ranked, ...]
    host_time_gaps_ms: tuple[int, ...]


def event_times(event_rows: Sequence[Row]) -> dict[str, int]:
    """event_uid -> corrected time in microseconds (``event_labels.csv``; one time per uid, the earliest kept)."""
    out: dict[str, int] = {}
    for r in event_rows:
        t = to_us(r["event_utc_corrected"])
        out[r["event_uid"]] = min(t, out.get(r["event_uid"], t))
    return out


def first_times(hop_rows: Sequence[Row]) -> dict[str, int | None]:
    """hop_id -> ``first_utc_corrected`` in microseconds (None when empty): the SC-21 tie-break of the chain order."""
    return {r["hop_id"]: (to_us(r["first_utc_corrected"]) if r["first_utc_corrected"] else None) for r in hop_rows}


def best_tier_min(tiers: Sequence[str]) -> str:
    """The weakest T7 link tier among the hops (A strongest ... D weakest); reported only, never scored (045)."""
    known = [t for t in tiers if t]
    bad = [t for t in known if t not in TIER_ORDER]
    if bad:
        raise ScoreError(f"refused: hops.csv best_tier outside {TIER_ORDER}: {sorted(set(bad))}")
    return max(known, key=TIER_ORDER.index) if known else ""


def score_path(path: Row, hop_ids: Sequence[str], edges: Sequence[Row], nodes: Sequence[Row],
               hop_rows: Mapping[str, Row], first_us: Mapping[str, int | None], keys: Mapping[str, str],
               event_us: Mapping[str, int], hop_ident: Mapping[str, HopIdentity], ref: OrderReference,
               params: ScoreParams) -> PathScore:
    """All components of one path: chain order and sequence (SC-21), steps and LengthScore (SC-21b..23), NodeScore
    with and without ``context`` = 1 (SC-30..32), IdentityCoherence (SC-53, SC-54), and each variant's score."""
    pairs = [(e["from_hop_id"], e["to_hop_id"]) for e in edges]
    chain = tuple(chain_order(hop_ids, pairs, first_us))
    seq = technique_sequence(chain, hop_technique_uids(nodes), ref.stage)
    steps = tuple(transitions(seq, ref, params, event_us, frozenset(pairs)))     # ATK-SC-17: real edges only
    length = length_score(steps, params.lam)
    units = tuple(node_units(nodes, keys, ("0",)))
    n_score = node_score(units)
    ident = path_identity(hop_ids, hop_ident)
    scores = {v: variant_score(v, params, length.length_score, n_score, ident.coherence) for v in PATH_VARIANTS}
    clock = any(hop_rows[h]["clock_unreliable"] == "1" for h in hop_ids) or any(
        e["clock_unreliable"] == "1" for e in edges)
    return PathScore(path=path, chain=chain, sequence=seq, steps=steps, length=length, units=units,
                     node_score=n_score, node_score_ctx1=node_score(node_units(nodes, keys, ("0", "1"))),
                     identity=ident, best_tier_min=best_tier_min([hop_rows[h]["best_tier"] for h in hop_ids]),
                     multi_chain_parent=int(any(hop_rows[h]["multi_chain_parent"] == "1" for h in hop_ids)),
                     clock_unreliable=int(clock), scores=scores)


def _group(rows: Sequence[Row], key: str) -> dict[str, list[Row]]:
    """Rows grouped by one column, input order kept."""
    out: dict[str, list[Row]] = {}
    for r in rows:
        out.setdefault(r[key], []).append(r)
    return out


def identity_accounts(accounts: Sequence[AccountIdentity]) -> dict[str, frozenset[str]]:
    """hop_id -> the lower-cased accounts that have ``hop_identity.csv`` rows. WHY lower case: the stitcher groups a
    hop's identity rows by the lower-cased member account (``stitch.identity.accounts_of``, account_key) and writes
    the first member's spelling, so a member spelled in another case is the same account."""
    out: dict[str, set[str]] = {}
    for a in accounts:
        out.setdefault(a.hop_id, set()).add(a.account.lower())
    return {h: frozenset(v) for h, v in sorted(out.items())}


def missing_member_accounts(hop_row: Row, have: frozenset[str]) -> list[str]:
    """``hops.csv`` ``member_accounts`` of one hop (``;``-joined, one item per member; an empty item is a member with
    a NULL account, which gives no identity row, decision 005) that have no identity row, lower-cased and sorted."""
    return sorted({a.lower() for a in split_list(hop_row["member_accounts"])} - have)


def _check_path_hops(path_id: str, hop_ids: Sequence[str], hop_rows: Mapping[str, Row],
                     hop_ident: Mapping[str, HopIdentity], ident_accounts: Mapping[str, frozenset[str]]) -> None:
    """Refuse a path whose hop is missing from ``hops.csv`` or from ``hop_identity.csv``, or whose hop names a member
    account with no ``hop_identity.csv`` row: ST-60 writes identity rows for every (hop, member account), so a gap
    means the stitch files disagree, and a silent gap would drop a crossing or an account from the denominator
    (ATK-SC-20, decision 069 item 3; SC-02 refusal style)."""
    if not hop_ids:
        raise ScoreError(f"refused: paths.csv {path_id} lists no hop")
    for h in hop_ids:
        if h not in hop_rows:
            raise ScoreError(f"refused: paths.csv {path_id} hop {h} is not in hops.csv")
        if h not in hop_ident:
            raise ScoreError(f"refused: paths.csv {path_id} hop {h} has no row in hop_identity.csv")
        missing = missing_member_accounts(hop_rows[h], ident_accounts.get(h, frozenset()))
        if missing:
            raise ScoreError(f"refused: paths.csv {path_id} hop {h}: {len(missing)} hops.csv member account(s) "
                             f"without a row in hop_identity.csv (ATK-SC-20)")


def score_trial(inp: ScoreInputs, ref: OrderReference, params: ScoreParams) -> TrialScores:
    """Score every path of ``paths.csv`` (each exactly once, SC-04), rank each path variant (SC-41), and build and
    rank the ``b0`` units (section 3.6)."""
    ids = [p["path_id"] for p in inp.paths]
    if len(set(ids)) != len(ids):
        raise ScoreError("refused: paths.csv repeats a path_id")
    hop_rows = {r["hop_id"]: r for r in inp.hops}
    first_us = first_times(inp.hops)
    keys = count_key_map(inp.event_labels)
    event_us = event_times(inp.event_labels)
    accounts = tuple(account_identities(inp.hop_identity))
    hop_ident = hop_identities(accounts)
    ident_accounts = identity_accounts(accounts)
    edges, nodes = _group(inp.path_edges, "path_id"), _group(inp.node_labels, "path_id")
    paths: list[PathScore] = []
    for p in sorted(inp.paths, key=lambda r: r["path_id"]):
        hop_ids = split_list(p["hop_ids"])
        _check_path_hops(p["path_id"], hop_ids, hop_rows, hop_ident, ident_accounts)
        paths.append(score_path(p, hop_ids, edges.get(p["path_id"], []), nodes.get(p["path_id"], []), hop_rows,
                                first_us, keys, event_us, hop_ident, ref, params))
    ranked = {v: tuple(competition_ranks((ps.path_id, ps.scores[v]) for ps in paths)) for v in PATH_VARIANTS}
    b0 = tuple(b0_units(inp.event_labels))
    gaps = tuple(sorted(int(e["time_delta_ms"]) for e in inp.path_edges
                        if e["link_type"] == "host_time" and e["time_delta_ms"] not in ("", None)))
    return TrialScores(trial_id=inp.trial_id, paths=tuple(paths), ranked=ranked, accounts=accounts, hops=hop_ident,
                       hop_tier={h: r["best_tier"] for h, r in sorted(hop_rows.items())}, b0=b0,
                       b0_ranked=tuple(competition_ranks((u.unit_id, u.score) for u in b0)),
                       host_time_gaps_ms=gaps)
