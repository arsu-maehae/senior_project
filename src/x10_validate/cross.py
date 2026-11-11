"""Cross-trial parts of decision 029: window overlap (f FAIL), shape majority (i), scenario verdicts.

WHY separate: these need every validated trial at once; keeping them pure (results in, results out)
lets ``run`` and ``report`` apply the same rule and lets a tester check it on hand-made results.
"""
from __future__ import annotations

import copy
from collections import Counter
from typing import Mapping, Sequence

from .db import parse_ts

CRITERIA = ("a", "b", "c", "d", "e", "f", "g", "h", "i")
FULL_RERUN_MIN = 6           # 029 Decision 3: >= 6 of 10 trials fail


def is_t00(trial_id: str) -> bool:
    """t00 trials are the development dry runs: compared, but never part of an x10 verdict."""
    return trial_id.endswith("_t00")


def group_of(res: Mapping) -> str:
    """Scenario group: quarantined S05 is its own group (decision 030)."""
    return f"{res['scenario']}q" if res.get("quarantine") else res["scenario"]


def _window(res: Mapping, kind: str) -> tuple[float, float] | None:
    """``design`` = 029 literal window (design anchors); ``broad`` = cluster window (N1)."""
    w = res.get("window")
    if not w:
        return None
    if kind == "design":
        lo, hi = w.get("design_start_utc"), w.get("design_end_utc")
    elif kind == "design_unclipped":
        lo, hi = w.get("design_start_utc"), w.get("design_end_unclipped_utc")
    else:
        lo, hi = w["start_utc"], w["end_utc"]
    if not lo or not hi:
        return None
    return parse_ts(lo), parse_ts(hi)


def overlaps(results: Sequence[Mapping], kind: str = "design") -> dict[str, list[dict]]:
    """For each trial, the other trials whose window overlaps its own (any scenario, t00 included)."""
    wins = [(r["trial_id"], _window(r, kind)) for r in results]
    out: dict[str, list[dict]] = {t: [] for t, _ in wins}
    for i, (ta, wa) in enumerate(wins):
        for tb, wb in wins[i + 1:]:
            if wa and wb and wa[0] <= wb[1] and wb[0] <= wa[1]:
                out[ta].append({"trial": tb, "overlap_s": round(min(wa[1], wb[1]) - max(wa[0], wb[0]), 1)})
                out[tb].append({"trial": ta, "overlap_s": round(min(wa[1], wb[1]) - max(wa[0], wb[0]), 1)})
    return out


def apply_overlaps(res: dict, found: Sequence[dict], found_broad: Sequence[dict] = (),
                   found_unclipped: Sequence[dict] = ()) -> None:
    """f FAIL when the 029 design window (end clipped at the DB's last event) overlaps another trial's.

    Overlaps of the broad cluster window and of the unclipped design window are evidence only.
    """
    f = res["criteria"]["f"]
    if f["status"] == "n/a":
        return
    f["evidence"]["overlaps"] = list(found)
    f["evidence"]["overlaps_broad_window"] = list(found_broad)
    f["evidence"]["overlaps_design_unclipped"] = list(found_unclipped)
    f["evidence"]["status_basis"] = ("029 design window, end clipped at the DB's last event; broad and unclipped "
                                     "windows reported only")
    if found:
        f["status"] = "FAIL"
        f["evidence"]["reason"] = "design window overlaps " + ", ".join(o["trial"] for o in found)
    elif f["evidence"].get("older_clusters"):
        f["status"] = "WARN"
        f["evidence"]["reason"] = f"{len(f['evidence']['older_clusters'])} older anchor cluster(s) before the window"
    else:
        f["status"] = "PASS"
        f["evidence"].pop("reason", None)


def _sig(shape: Mapping) -> str:
    return repr(sorted((k, repr(v)) for k, v in shape.items()))


def apply_shapes(results: Sequence[dict]) -> None:
    """Criterion i: compare each trial's shape with the strict-majority shape of its group's x10 trials."""
    groups: dict[str, list[dict]] = {}
    for r in results:
        groups.setdefault(group_of(r), []).append(r)
    for members in groups.values():
        peers = [r for r in members if not is_t00(r["trial_id"]) and r.get("shape")]
        counts = Counter(_sig(r["shape"]) for r in peers)
        top = counts.most_common(1)
        majority = top[0][0] if top and len(peers) >= 2 and top[0][1] * 2 > len(peers) else None
        ref = next((r["shape"] for r in peers if _sig(r["shape"]) == majority), None)
        for r in members:
            if not r.get("shape"):
                r["criteria"]["i"] = {"status": "n/a", "evidence": {"reason": "no shape (no trial window)"}}
                continue
            if majority is None:
                r["criteria"]["i"] = {"status": "n/a", "evidence": {
                    "reason": f"no strict majority shape among {len(peers)} x10 trial(s) of the scenario",
                    "shape": r["shape"]}}
                continue
            diff = {k: {"trial": r["shape"][k], "majority": ref[k]} for k in r["shape"] if r["shape"][k] != ref[k]}
            r["criteria"]["i"] = {"status": "WARN" if diff else "PASS", "evidence": {
                "majority_of": f"{top[0][1]}/{len(peers)}", "differences": diff,
                "compared_as": "t00 vs x10 majority" if is_t00(r["trial_id"]) else "x10"}}


def apply_cross(results: Sequence[Mapping]) -> list[dict]:
    """Copy of the results with f overlap and i filled in."""
    out = [copy.deepcopy(dict(r)) for r in results]
    ov, ovb, ovu = overlaps(out, "design"), overlaps(out, "broad"), overlaps(out, "design_unclipped")
    for r in out:
        apply_overlaps(r, ov[r["trial_id"]], ovb[r["trial_id"]], ovu[r["trial_id"]])
    apply_shapes(out)
    return out


def failing(res: Mapping) -> list[str]:
    """Criteria with FAIL for one trial."""
    return [c for c in CRITERIA if res["criteria"].get(c, {}).get("status") == "FAIL"]


def verdict(results: Sequence[Mapping], expected: int = 10) -> dict:
    """029 Decision 3 for one scenario group: pass / replace N / full rerun (WARNs never count)."""
    trials = [r for r in results if not is_t00(r["trial_id"])]
    bad = {r["trial_id"]: failing(r) for r in trials if failing(r)}
    per_crit = Counter(c for cs in bad.values() for c in cs)
    if len(bad) >= FULL_RERUN_MIN or any(n >= FULL_RERUN_MIN for n in per_crit.values()):
        v = "full rerun"
    elif bad:
        v = f"replace {len(bad)}"
    else:
        v = "pass"
    return {"verdict": v, "validated": len(trials), "expected": expected,
            "provisional": len(trials) < expected, "failing_trials": bad, "fails_per_criterion": dict(per_crit),
            "all_failing_share_b": bool(bad) and len(bad) >= 2 and all("b" in cs for cs in bad.values())}
