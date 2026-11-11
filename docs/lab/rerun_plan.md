# Rerun plan for the ×10 trials

**Date:** 2026-11-11 · **Status:** draft for the owner · **Source:** `docs/research/x10_design_validation.md` (commit 509e54c), decisions 029 and 030. This file is logistics only: what to run, how many, in which order, and when to proceed. Scenario designs are in the handoff and the decision records, not here.

## Rule for every item
1. Run **one** trial.
2. Ingest it (`batch` ingest, as for the first ×10).
3. Run the x10 validator on it.
4. **Proceed to the remaining trials only if that trial has no FAIL.** If it fails, stop, report to the owner, and do not run more.
5. After the last trial of an item, ingest and validate all of them; the item is done when none has a FAIL.

Broken trials stay where they are (archived, never deleted). New trials are numbered from `trial_11` (decision 029, rule 1).

## Before the first run and in every session
- All VMs are time-synced before the session starts.
- The offsets between hosts are checked at the start and at the end of each session and written down.
- The logs are exported per trial as before (4 hosts × 5 logs, 20 files). Check the file count before leaving the lab.

## Items

| # | Scenario | Trials | Why | Acceptance check |
|---|---|---|---|---|
| 1 | S03 | 1 (`trial_11`) | replaces `s03_t08` | run 1, ingest, validator: no FAIL |
| 2 | S06 | 2 (`trial_11`, `trial_12`) | replace `s06_t09`, `s06_t10` | run `trial_11`, ingest, validator: no FAIL; then `trial_12`, same check |
| 3 | S04 | 10 | full rerun (all 10 failed b, c, d) | run 1, ingest, validator: proceed only if it passes; then the other 9 |
| 4 | S07 | 10 | full rerun (all 10 failed c) | same; the design fix must be confirmed by the owner first |
| 5 | S05 | 10 | rebuild to the t00 design (the first 10 are quarantined, decision 030) | same |
| 6 | S01 | 10 | build (S01 has only t00, which is excluded from development and test) | same; the S01 design is confirmed by the owner first |

### Run order
1 → 2 → 3 → 4 → 5 → 6. Items 1 and 2 are single replacements of designs that already worked, so they come first and cost the least. Items 3 and 4 follow, because their designs and fixes are already described in the decision records. Items 5 and 6 come last because they are the largest and S01 needs its design confirmed.

Do not start an item before the previous one is validated, unless the owner says so.

### Per-item checklist
For each item, record in `docs/PROGRESS.md`: the trial ids, the date, the clock offsets at the start and end of the session, the validator result of the first trial, and the final validator result of the item.

## Open points for the owner
- **Numbering of full reruns.** The first 10 trials of S04, S07, S05 and S01 stay in `data/` as archived. Whether the new ten are `trial_11`–`trial_20` or reuse `t01`–`t10` in a new folder is not decided. The development and test mapping (decision 019: t01 and t00 for development, t02–t10 for test) must be restated for these scenarios, because the old S04 and S07 t01 are invalid.
- **S07 and S01** need a confirmed design before their first trial.
- **Validator limits for S01.** The validator has no design table for S01 yet; one must be added (and written down in a decision record) before item 6 can be validated.
- **Collector sessions and trial windows.** The end-of-trial sessions from 192.168.50.97, .98 and .99 are excluded by the trial window (PLAN T6.4); record these IPs in the lab notes so they are not mistaken for trial activity.
