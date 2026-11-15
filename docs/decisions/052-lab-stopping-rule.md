# 052 — Lab stopping rule for the x10_v2 full reruns (S01, S04, S05, S07)

**Date:** 2026-11-15 · **Status:** proposed (owner rulings of 2026-11-15 applied; accepted when the owner confirms) · **Task:** ×10 reruns, lab tooling · **Amends:** 034 (items 3, 4, consequences) · **Supersedes for the v2 scenarios:** 029 Decision 1 (`trial_11` numbering) · **Relates to:** 019 (split), 029 (criteria), 030, `docs/lab/rerun_plan.md`

## Context
Decision 034 plans 10 new trials for each of S01, S04, S05, S07 in `data/incoming/x10_v2/`, with `t01` development and `t02`–`t10` test (9 test trials), and replaces a failed trial by `trial_11` onwards. The lab time before the cutoff may not allow 10 trials per scenario, and nothing yet says when to stop, what decides that a trial counts, or where a failed trial goes. Without a rule fixed before any scoring, trials could be kept or dropped because of how the pipeline treats them. A failed trial is already ingested (ingest runs before the validator), so its id `sNN_tNN` must be freed for the re-run.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Always 10 per scenario, replacements as `trial_11+` (034 as written) | fixed test size | may not finish in the lab time; old failed copies stay beside the new ones; gaps in numbering |
| B. Minimum 5 accepted, continue towards 10, accepted by operational checks only, failed trials moved out and the number reused (**chosen**) | finishes with a defined test set; numbering has no gaps; no result can influence which trials count | test sizes can differ between scenarios (4 to 9); needs a retire step for the ingested copies |
| C. Stop when the pipeline results look stable | fewer trials | selection by results; breaks "never tune on test" |

## Decision
1. **Scope:** full reruns S01, S04, S05, S07 in `x10_v2`. The partial replacements S03 and S06 keep the 029/034 numbering (`trial_11+` in `x10`).
2. **Order:** trial numbers run in order within each scenario, `trial_01` first, no gaps. The order across scenarios is an operational choice in the lab handoff (round-robin to t05 first); it is **not fixed by this record**.
3. **Size:** minimum **5 accepted** trials per scenario (`t01` development; `t02`–`t05` test). Continue towards 10 if time allows.
4. **Test set:** every trial that passed validation by the **cutoff** (end of the lab session, or a later date the owner names). The cutoff and the accepted trials are recorded in the committed file `docs/lab/test_set.csv` (`trial_id, scenario, split, accepted_date`) and in one line of `docs/PROGRESS.md`; not under `data/` (git-ignored). A trial accepted after the cutoff is not in the test set. Never tune on test (019).
5. **What makes a trial count:** operational checks only: ingest `ok` with a reconciled row accounting, and the x10 validator criteria a–i with no FAIL (WARN is reported, not blocking). **Never** gate, stitch, score, rank or evaluate results, or whether the attack path is found. A missing `<HOST>_clock.txt` is noted in `ingest.json` and is not a failure (owner).
6. **Failed trials:** any trial with a FAIL (the 1-trial gate, or a later trial) stops further runs of that scenario and is reported to the owner. It is moved by the owner to `data/incoming/x10_v2_failed/<scenario>/attempt_N/`; its ingested copies (raw, DB, JSONL, manifest rows, per-trial outputs) are retired by the `retire-failed` tool to an archive path; its number is reused: a failed trial never keeps `trial_NN`, and a failed first trial never takes `trial_01`.

## Consequences
- Easier: a fixed stopping point and a test set that no result can influence; the ids `sNN_tNN` always mean an accepted trial.
- Harder: test sizes differ by scenario (4 to 9 test trials); any per-scenario figure must state its n. The report states that the test set is "all trials that passed the operational checks by the cutoff".
- Supersedes 034 item 4 "each scenario ends with 9 test trials" and 034 consequence "replaced by `trial_11` onwards"; rerun_plan rule 5 is reworded accordingly. The validator's "full rerun (≥ 6 of 10 fail)" wording is not used for v2.
- Needs tooling (plan of 2026-11-15): batch `--source x10_v2`, validator `--source x10_v2`, archive of the old S04/S07 `t01`–`t10` (not `t00`), `retire-failed`, clock-file ingest.

## Kill criteria
If fewer than 4 test trials of a scenario pass by the cutoff, that scenario is reported as "test set too small" and not scored as a test set; the owner decides whether to extend the cutoff. If the retire step cannot be verified by hash, the failed attempt is not moved and the next run uses a separate path (as in 034 and 030).

## Committee answer
**EN:** We fixed in advance when to stop and what counts: at least five trials per scenario that pass the file and design checks by a stated cutoff, judged only by those checks and never by how the pipeline scores them, so no trial was kept or dropped because of its result.
**TH:** เรากำหนดล่วงหน้าว่าจะหยุดเมื่อใดและอะไรนับเป็นรอบที่ใช้ได้ คือแต่ละสถานการณ์อย่างน้อยห้ารอบที่ผ่านการตรวจไฟล์และการออกแบบภายในวันตัดรอบที่ระบุ โดยตัดสินจากการตรวจเหล่านั้นเท่านั้น ไม่ดูผลคะแนนของระบบ จึงไม่มีรอบใดถูกเก็บหรือทิ้งเพราะผลลัพธ์
