"""Markdown report over all per-trial results (``out/x10_validate/report.md``).

WHY: decision 029 asks for a per-trial PASS/WARN/FAIL table, a per-scenario verdict and a redo
list the owner can act on; quarantined S05 (decision 030) and the t00 sanity runs are kept in
separate sections so they can never be mistaken for x10 results.
"""
from __future__ import annotations

from typing import Mapping, Sequence

from .cross import CRITERIA, failing, group_of, is_t00, rerun_status, verdict
from .params import IMPLEMENTATION_NOTES

OPEN_POINTS: tuple[str, ...] = (
    "Criterion f window: decision 029 names the window anchors 'agent-child commands of the design, "
    "rundll32 -> lsass dumps, target 4624 of design hops' (the f FAIL status uses this design window). "
    "The validator brief also counted every endpoint-to-endpoint user 4624 as an anchor (the broad "
    "cluster window, used to find the run and older clusters). In back-to-back x10 trials the broad "
    "window reaches into the next trial; those overlaps are shown as 'f(broad, info)' and do not set "
    "FAIL. Owner decides which window 029 means.",
    "Criterion f window end: the x10 trials ran about 5-6 min apart, shorter than the 300 s tail plus the "
    "60 s lead, so the literal design windows of consecutive trials overlap although no event is shared "
    "(each trial's DB ends at its export, before the next trial's first anchor). The validator clips "
    "every window end at the DB's last event (precedent: decision 026 amendment, export span as outer "
    "clip); unclipped overlaps are shown as 'f(unclipped, info)'. Owner confirms or rejects the clip.",
    "Decision 3 'full rerun ... or they fail on the same design criterion (b)': implemented as >= 6 of 10 "
    "trials failing (any criterion, or the same criterion); the flag 'all failing trials share b' is "
    "shown for the owner when 2-5 trials fail and all of them on b. Owner decides whether that alone "
    "means a full rerun.",
    "Criterion a counts files (ingest.json). An exported but empty channel (0 rows) is listed as "
    "'present_but_no_rows_in_db' and does not change the status.",
    "Criterion g with dc01 Security present but no LogonGuid pair near the window is reported n/a "
    "(not measurable), not PASS.",
    "Criterion i needs a strict majority of at least 2 x10 trials of the scenario; until then it is n/a.",
)


def _short(res: Mapping) -> str:
    """One-line evidence: the reasons behind every non-PASS status."""
    c = res["criteria"]
    bits: list[str] = []
    a = c["a"]["evidence"]
    if a.get("missing"):
        bits.append("a: missing " + ",".join(a["missing"]))
    if c["b"]["status"] == "FAIL":
        bits.append("b: missing " + ",".join(c["b"]["evidence"].get("missing", [])) if c["b"]["evidence"].get("missing")
                    else "b: " + str(c["b"]["evidence"].get("reason")))
    if c["c"]["status"] in ("FAIL", "WARN"):
        bits.append("c: intended not seen " + ",".join(c["c"]["evidence"].get("intended_missing", [])))
    if c["d"]["status"] == "FAIL":
        bits.append("d: " + str(c["d"]["evidence"].get("reason") or "dump in benign scenario"))
    if c["e"]["status"] == "FAIL":
        bits.append("e: " + str(c["e"]["evidence"].get("reason")))
    f = c["f"]["evidence"]
    if f.get("overlaps"):
        bits.append("f: design window overlaps " + ",".join(o["trial"] for o in f["overlaps"]))
    elif f.get("older_clusters"):
        bits.append(f"f: {len(f['older_clusters'])} older cluster(s)")
    if f.get("overlaps_design_unclipped") and not f.get("overlaps"):
        bits.append("f(unclipped, info): overlaps " + ",".join(o["trial"] for o in f["overlaps_design_unclipped"]))
    if f.get("overlaps_broad_window"):
        bits.append("f(broad, info): overlaps " + ",".join(o["trial"] for o in f["overlaps_broad_window"]))
    if c["g"]["status"] in ("WARN", "n/a"):
        g = c["g"]["evidence"]
        bits.append("g: " + (f"pairs>5s {g.get('pairs_over_5s')}" if g.get("pairs_over_5s") else str(g.get("reason", ""))[:40])
                    + (f" lb>5s {g['lower_bounds_over_5s']}" if g.get("lower_bounds_over_5s") else ""))
    h = c["h"]["evidence"]
    if h.get("duplicates_fail") or h.get("duplicates_identifiable"):
        bits.append(f"h: {len(h.get('duplicates_fail', []))} same-run dup, {len(h.get('duplicates_identifiable', []))} identifiable"
                    + "(" + ",".join(sorted({d['why'] for d in h.get('duplicates_identifiable', [])})) + ")")
    if c["i"]["status"] == "WARN":
        bits.append("i: differs in " + ",".join(c["i"]["evidence"].get("differences", {})))
    return "; ".join(bits) or "-"


def _table(results: Sequence[Mapping]) -> list[str]:
    head = "| trial | " + " | ".join(CRITERIA) + " | evidence |"
    sep = "|---|" + "---|" * len(CRITERIA) + "---|"
    rows = [f"| {r['trial_id']} | " + " | ".join(r["criteria"][c]["status"] for c in CRITERIA) + f" | {_short(r)} |"
            for r in sorted(results, key=lambda r: r["trial_id"])]
    return [head, sep, *rows] if rows else ["(none)"]


def _verdict_lines(by_group: Mapping[str, list[Mapping]]) -> tuple[list[str], list[str]]:
    vl = ["| scenario | validated / expected | verdict | failing trials | fails per criterion | all failing share b |",
          "|---|---|---|---|---|---|"]
    redo = ["| scenario | count | reason |", "|---|---|---|"]
    for g in sorted(by_group):
        v = verdict(by_group[g])
        tag = " (provisional)" if v["provisional"] else ""
        vl.append(f"| {g} | {v['validated']} / {v['expected']} | {v['verdict']}{tag} | "
                  f"{', '.join(v['failing_trials']) or '-'} | {v['fails_per_criterion'] or '-'} | {v['all_failing_share_b']} |")
        if v["failing_trials"]:
            reason = "; ".join(f"{t}: {','.join(cs)}" for t, cs in sorted(v["failing_trials"].items()))
            count = "10 (full rerun)" if v["verdict"] == "full rerun" else str(len(v["failing_trials"]))
            redo.append(f"| {g} | {count} | {reason} |")
    return vl, redo


def render(results: Sequence[Mapping], not_ingested: Sequence[Mapping], generated_utc: str) -> str:
    """The whole report as markdown text (pure)."""
    x10 = [r for r in results if not r.get("quarantine") and not is_t00(r["trial_id"])]
    quar = [r for r in results if r.get("quarantine")]
    t00 = [r for r in results if is_t00(r["trial_id"]) and not r.get("quarantine")]
    by_group: dict[str, list[Mapping]] = {}
    for r in x10:
        by_group.setdefault(group_of(r), []).append(r)
    vl, redo = _verdict_lines(by_group)
    qg: dict[str, list[Mapping]] = {}
    for r in quar:
        qg.setdefault(group_of(r), []).append(r)
    qvl, _ = _verdict_lines(qg)
    out = [
        "# x10 design validation (decision 029)", "",
        f"Generated {generated_utc} by `python -m x10_validate report` (read-only; independent of answer_key, "
        "log_check and any stitcher). Statuses: PASS | WARN | FAIL | n/a. WARNs never change a verdict.", "",
        "## x10 trials", "", *_table(x10), "",
        "## Not ingested", "",
        *([f"- {n['trial_id']}: {n['reason']}" for n in not_ingested] or ["(none)"]), "",
        "## Scenario verdicts (029 Decision 3)", "", *vl, "",
        "## Draft redo list (replacements start at trial_11; owner approves)", "",
        *(redo if len(redo) > 2 else ["(none)"]), "",
        "## Quarantine: S05 x10 (decision 030; design check only, never scored)", "",
        *_table(quar), "", *(qvl if quar else []), "",
        "## t00 sanity run (development trials; not part of any verdict)", "", *_table(t00), "",
        "## Implementation notes (029 'Consequences')", "", *[f"- {n}" for n in IMPLEMENTATION_NOTES], "",
        "## Open points / not measurable", "", *[f"- {p}" for p in OPEN_POINTS], "",
    ]
    return "\n".join(out)


def _status_lines_v2(by_group: Mapping[str, list[Mapping]], scenarios: Sequence[str],
                     minimum: int) -> tuple[list[str], list[str]]:
    """Per-scenario "validated so far" table (decision 052) and the list of failing trials to move and retire."""
    head = ["| scenario | validated so far | accepted | minimum | status | failing trials | fails per criterion |",
            "|---|---|---|---|---|---|---|"]
    failed = ["| trial | failing criteria |", "|---|---|"]
    for g in sorted(set(scenarios) | set(by_group)):
        st = rerun_status(by_group.get(g, []), minimum)
        status = "minimum reached" if st["minimum_reached"] else f"{st['still_needed']} more accepted needed"
        head.append(f"| {g} | {st['validated']} | {st['accepted']} | {minimum} | {status} | "
                    f"{', '.join(st['failing_trials']) or '-'} | {st['fails_per_criterion'] or '-'} |")
        failed += [f"| {t} | {','.join(cs)} |" for t, cs in sorted(st["failing_trials"].items())]
    return head, failed


def render_v2(results: Sequence[Mapping], not_ingested: Sequence[Mapping], generated_utc: str,
              scenarios: Sequence[str], minimum: int) -> str:
    """The x10_v2 report as markdown text (pure): criteria a-i unchanged, count against the decision 052 minimum.

    WHY separate from ``render``: the 029 wording ("replace N", "full rerun", replacements from trial_11,
    a fixed 10 expected trials) is superseded for the reruns, and the v1 report must stay byte-identical."""
    trials = [r for r in results if not r.get("quarantine") and not is_t00(r["trial_id"])]
    t00 = [r for r in results if is_t00(r["trial_id"]) and not r.get("quarantine")]
    by_group: dict[str, list[Mapping]] = {}
    for r in trials:
        by_group.setdefault(group_of(r), []).append(r)
    status, failed = _status_lines_v2(by_group, scenarios, minimum)
    notes = [n for n in IMPLEMENTATION_NOTES if not n.startswith(("N14 ", "N15 "))]
    notes.append("N14 (x10_v2) criterion a reads out/ingest/x10_v2/<trial>/ingest.json (files_missing); a report "
                 "whose `source` is not x10_v2 or whose `source_dir` is not under data/incoming/x10_v2/ is refused.")
    points = [p for p in OPEN_POINTS if "full rerun" not in p]
    out = [
        "# x10_v2 design validation (criteria of decision 029; stopping rule of decision 052)", "",
        f"Generated {generated_utc} by `python -m x10_validate report --source x10_v2` (read-only; independent of "
        "answer_key, log_check and any stitcher). Statuses: PASS | WARN | FAIL | n/a. WARNs never block.", "",
        "## x10_v2 trials", "", *_table(trials), "",
        "## Not ingested", "",
        *([f"- {n['trial_id']}: {n['reason']}" for n in not_ingested] or ["(none)"]), "",
        f"## Validated so far against the minimum (decision 052: minimum {minimum} accepted trials per scenario)", "",
        "A trial is accepted when no criterion a-i is FAIL. The count is what has been validated so far, not a "
        "fixed total; the cutoff and the test list are recorded in docs/lab/test_set.csv.", "", *status, "",
        "## Failed trials (decision 052 item 6; owner moves the folder, the tool retires the ingested copies)", "",
        *(failed if len(failed) > 2 else ["(none)"]), "",
        *(["## t00 sanity run (not part of any status)", "", *_table(t00), ""] if t00 else []),
        "## Implementation notes (029 'Consequences')", "", *[f"- {n}" for n in notes], "",
        "## Open points / not measurable", "", *[f"- {p}" for p in points], "",
    ]
    return "\n".join(out)


def failing_summary(results: Sequence[Mapping]) -> dict[str, list[str]]:
    """trial -> failing criteria (for the CLI printout)."""
    return {r["trial_id"]: failing(r) for r in results}
