# 031 — Criterion f: window rules adjusted after the data was seen

**Date:** 2026-11-11 · **Status:** accepted (owner, 2026-11-11) · **Task:** ×10 ingest and validation · **Amends:** 029 (measurement detail of criterion f only; criteria and severities are unchanged)

## Context
Decision 029 defines the f window as [first design anchor − 60 s, last design anchor + 300 s], with anchors = agent-child commands of the design, rundll32 → lsass dumps and target 4624 of design hops. The first validator version counted every endpoint-to-endpoint user 4624 as an anchor and did not clip the window. On the real data this gave two problems (validation report §6, `docs/research/x10_design_validation.md`):
1. Background `admin_it` logons between endpoints stretched the windows into the next trial, so f failed for most S02–S07 trials.
2. Trials ran 5–6 min apart, which is shorter than the 60 s lead plus the 300 s tail, so the design windows of consecutive trials overlap in time even though no event is shared: each trial's DB ends at its export, before the next trial's first anchor.

## Decision
1. The f FAIL (windows overlap) uses the design anchors named in 029 only. The broader window (all endpoint-to-endpoint user logons) is still used to find the trial's own run and the older clusters (f WARN); its overlaps are listed as `f(broad, info)` and do not set FAIL.
2. Every window end is clipped at the DB's last event (the export end). The export-span clip has a precedent in decision 026. Overlaps of the unclipped window are listed as `f(unclipped, info)` and do not set FAIL.

## What this changes, and what it does not
- Both rules were chosen **after** the validation results were seen. They are recorded here because 029 says nothing may change after the results are seen except through a new decision record.
- No scenario verdict in the validation report rests on f: every FAIL that sets a verdict is on a, b, c, d or e.
- Nothing was scored. No answer key was built or changed.
- Without the clip, f would FAIL by time alone in most S02–S07 trials (report §6). The owner accepted the clip.
- Replacement and rerun trials are checked with the same rules.

## Kill criteria
If a trial's window is found to contain design events of an adjacent trial (the same step in two DBs), this record is reopened and f is a FAIL for those trials regardless of the clip.

## Committee answer
**EN:** We changed how the trial window is measured after we saw that trials ran only minutes apart. The change does not affect any verdict, and nothing had been scored.
**TH:** เราปรับวิธีวัดหน้าต่างเวลาของแต่ละรอบหลังเห็นว่าแต่ละรอบห่างกันเพียงไม่กี่นาที การปรับนี้ไม่กระทบผลการตัดสินใดและยังไม่มีการให้คะแนน
