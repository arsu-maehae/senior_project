# 046 — The stitcher runs on the nine development trials only, until T10

**Date:** 2026-11-13 · **Status:** accepted (owner instruction for T7.2, 2026-11-13) · **Task:** T7 (7.2) · **Relates to:** 019 (split), 034 (t01 = development), 043 (`DEVELOPMENT_TRIALS`), spec [03_stitch](../specs/03_stitch.md) §9

## Context
Decision 019 defines the split: development = t00 for S02–S07 plus t01; test = t02–t10. CLAUDE.md says "never tune on test". The stitcher's parameters (spec 03 §5) are frozen on the nine development trials (L-ST3). Spec 03 §2 refuses inputs that the gate or the clock step refuses. A t02–t10 trial that has gate outputs would still pass those checks, so nothing in the spec stops the stitcher from reading a test trial while T7 is being built. The owner asked (T7.2 plan) that the code itself refuse t02–t10 and that a test prove it.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. Rely on the gate and clock refusals | No extra rule | A test trial with gate outputs would be stitched during development | spec 03 §2 |
| B. Hard allowlist = `clock_offset.params.DEVELOPMENT_TRIALS`, checked first, before any file is opened | Test data cannot be read by mistake; one list shared with the clock step | Must be lifted on purpose at T10 | 019, 034, 043 |

## Decision
Option B. `src/stitch` refuses every trial id that is not in `clock_offset.params.DEVELOPMENT_TRIALS`, which holds s02–s07 t00, s02_t01, s03_t01 and s06_t01. The list is imported, never copied. The check runs before any file is opened, and nothing is written on a refusal. Lifting it for T10 needs the owner's approval and an amendment to this record.

## Consequences
- t02–t10 cannot reach any T7 result or tuning step.
- The test proves the refusal with paths that do not exist: the refusal reason must still be the allowlist.
- T10 has to change one line and this record.

## Kill criteria
None for development. At T10 the allowlist is replaced by the frozen-parameter run on the test set (spec 03 §5 "Freeze").

## Committee answer
**EN:** While we built the linking stage, the code itself refused every test trial. So no value could be tuned on test data, even by mistake.
**TH:** ระหว่างพัฒนาขั้นเชื่อมโยง โค้ดปฏิเสธรอบทดสอบทุกรอบตั้งแต่ต้น จึงไม่มีค่าพารามิเตอร์ใดถูกปรับจากข้อมูลทดสอบ แม้โดยไม่ตั้งใจ
