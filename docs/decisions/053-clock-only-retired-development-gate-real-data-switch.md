# 053 — No trial id is clock-only; x10_v2 t01 trials join development one by one; real-data inputs are required on the owner's machine

**Date:** 2026-11-17 · **Status:** accepted (owner instruction, 2026-11-17) · **Task:** T6c follow-up (archive readers) · **Amends:** 043 (item 3: clock-only evidence; the `params_sha256` pin) · **Relates to:** 034 item 4, 046, 051, 052

## Context
- `archive-v1 --execute` ran on 2026-11-17 (916 files verified): the old S04/S07 `t01`–`t10` left the normal paths. The ids `s04_t01` and `s07_t01` now mean the x10_v2 reruns, which are **development** trials (034 item 4).
- `CLOCK_ONLY_TRIALS = ("s04_t01", "s07_t01")` (clock_offset and trial_window params) would make the gate, window and stitch refuse those new trials by id, and made `python -m clock_offset` and `clock_offset.scan` raise `ClockOffsetError` on the missing DBs.
- The archive step silently turned 58 real-data tests into skips (full suite 4448 passed + 1 skipped at `39fd543`; 4390 passed + 59 skipped after). Nothing failed, so nothing flagged it.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. `CLOCK_ONLY_TRIALS = ()`, keep the mechanism (**chosen**) | one-line change per module; refusal and label path stay tested with injected ids | an unused empty list | 5 modules and ~30 tests use the parameter |
| B. Delete the constant and the clock-only machinery | no dead code | API change in gate, window, stitch, clock_offset and ~30 tests, no gain | `grep`: 121 occurrences in 21 files |
| C. Keep the ids clock-only, number the reruns differently | no src change | contradicts 034 and 052 (ids fixed, same mapping) | 034 item 2 |
| D. Add the x10_v2 t01s to `DEVELOPMENT_TRIALS` now | nothing to do later | no data yet; an allowlist entry before the validator passes breaks 019/046 | `data/incoming/x10_v2` does not exist yet |
| E. Real-data tests skip silently (status quo) | works on any machine | lost 58 tests unnoticed | 4448 → 4390 passed |
| F. `REQUIRE_REAL_DATA=1`: a missing real-data input fails, default still skips (**chosen**) | owner's machine cannot lose coverage silently; other machines still run | the owner must set the variable | see Consequences |

## Decision
1. **Clock-only retired.** `CLOCK_ONLY_TRIALS = ()` in `src/clock_offset/params.py` and `src/trial_window/params.py`; `DEFAULT_TRIALS = DEVELOPMENT_TRIALS`. The old clock-only trials of 043 are **historical evidence** in `archive_x10_v1/`. Their T6b.1 result is checked read-only on the frozen files (`test_hist_*` in `tests/unit/test_clock_offset.py`), never recomputed: the manifest rows moved, so it is a frozen-evidence check, not a code regression. An id is clock-only again only by a decision record.
2. **Development allowlist.** `s01_t01`, `s04_t01`, `s05_t01`, `s07_t01` are added to `DEVELOPMENT_TRIALS` (`clock_offset.params`; stitch and evaluate derive their allowlists from it) **one trial at a time, after that trial is ingested and passes the validator**, by a one-line change the owner approves and that is logged below. Not before.
3. **`REQUIRE_REAL_DATA=1`.** The real-data tests call `real_data.missing_input(reason)`. With the variable set it fails; unset it skips. A skip that is not a missing input (no symlink right, no `.97` session in the data) stays a skip and is counted in the report.
4. **Parameter freeze re-recorded.** `src/clock_offset/params.py` changed (trial lists only, no parameter value). New pin, recorded as in 043:

`params_sha256: 132658bd3007aee49b3714ddc2baffb3d3611f73b651856506d51c32382d77e3`

### Allowlist log (item 2)
| Trial | Ingested | Validator | Owner approval | Change |
|---|---|---|---|---|
| (none yet) | | | | |

## Consequences
- Gate and window refuse by id only (quarantine, split exclusion); they no longer refuse `s04_t01`/`s07_t01`. Stitch and evaluate still refuse them until item 2 adds them.
- 043's "skew-period evidence" now rests on `s06_t01` plus the frozen archive result until the reruns arrive; state this in the report.
- Limit: the historical tests cannot detect a regression in the clock-offset code on those two trials.

## Kill criteria
- A t01 rerun that passes the validator but is refused by an id rule: revert item 1 for that id and record why.
- `REQUIRE_REAL_DATA=1` fails on a trial that is legitimately absent: add the case to this record rather than relaxing the switch.

## Committee answer
**EN:** The two old clock-only trials were archived and their ids now belong to the development reruns, so keeping them clock-only would block the real data; their old measurement is kept as read-only history. Trials join the development set only after they are ingested and validated, and the owner's machine fails on missing data instead of silently skipping it.
**TH:** ทดลองเก่า 2 ชุดที่เคยใช้วัดนาฬิกาอย่างเดียวถูกเก็บเข้าคลังแล้ว และรหัสเดิมตอนนี้เป็นของการทดลองใหม่ที่ใช้พัฒนา การคงสถานะเดิมไว้จึงจะปิดกั้นข้อมูลจริง ผลวัดเก่าเก็บไว้เป็นหลักฐานแบบอ่านอย่างเดียว การทดลองจะเข้าชุดพัฒนาได้ต่อเมื่อนำเข้าและผ่านการตรวจแล้วเท่านั้น และเครื่องของเจ้าของโครงการจะล้มเหลวเมื่อข้อมูลหาย แทนที่จะข้ามการทดสอบอย่างเงียบ ๆ
