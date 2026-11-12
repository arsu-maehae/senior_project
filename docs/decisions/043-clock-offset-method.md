# 043 — Clock offset method: 1:1 LogonGuid pairs, median per host and trial; s04_t01/s07_t01 as clock-only evidence; two-step approval

**Date:** 2026-11-12 · **Status:** **accepted for step 1 (method), owner 2026-11-12.** Step 2 is open: `MIN_PAIRS`, `MAX_LOO_SHIFT_S`, `READING_AGREE_S` and the `late_gap_s` limit are confirmed on the rerun t01s · **Task:** T6b.1 · **Spec:** [08_clock_offset](../specs/08_clock_offset.md) · **Relates to:** 014 (amends its last sentence for kept trials), 019, 032, 034, 039

## Context
- **The skew:** from 2026-10-26, ep-01 ran 10–27 s behind dc01 (032). Before that date, endpoints sit within −2.3 … +4.5 s of dc01. Host pairs still reach 5–6 s, e.g. s03_t01 ep-01→ep-03, where the WinRM connection precedes the target logon by a raw 5.68 s.
- **The order check:** decision 014 compares the dump time and the move time across hosts with a 5 s tolerance. 032 asks for a per-host, per-trial correction, decided on development data only.
- **The evidence (spec §10):**
  - 9 development trials (t00 S02–S07; s02_t01, s03_t01, s06_t01 passed the validator) plus 2 clock-only trials.
  - Pairs are endpoint 4624 ↔ dc01 4769 with the same LogonGuid.
  - Single deltas scatter ±3–9 s on both sides of a stable centre, while dc01's own same-clock pairs show 4–8 ms latency.
  - An independent check exists: a source Sysmon 3 joined to the target 4624 by IpPort, 6 WinRM groups and 18 pairs.

## Options considered
| Option | Pros | Cons | Evidence (spec §10.3) |
|---|---|---|---|
| A. 1:1 mutual-nearest pairs, median | robust to two-sided scatter and to GUID reuse; same measure as validator N11 / 032 | ep-01 has only 2–6 pairs per trial | every independent check ≤ 1.58 s (raw up to 18.35 s) |
| B. nearest 4769 per 4624, median | more pairs | reused GUIDs pull the median (s06_t01 ep-03 +6.10 vs +0.04) | s06_t01 ep-01→ep-03 check −6.22 s (fails 5 s) |
| C. GUIDs seen exactly once only | cleanest pairs | 9 hosts drop to 0–1 pairs; ep-03 unmeasured in s06_t01 | check n/a where it matters |
| D. A without type 4 (batch/S4U) | removes the 60 s scheduled-task tickets | removes ep-01's best pairs | s06_t01 checks +6.52 / +5.18 s (fail) |
| A with minimum instead of median | assumes latency ≥ 0 | scatter is two-sided (s07_t00 ep-02 −4.06 … +8.52) | checks ≤ 1.49 s (passes, rejected on the model) |
| No correction (014 option B as is) | nothing new | raw ep-01 pairs up to 18.35 s apart | 3 of 6 checks > 5 s raw |

## Decision (accepted for step 1, owner 2026-11-12)
1. **Method:**
   - pair endpoint 4624 ↔ dc01 4769 by LogonGuid, 1:1 mutual nearest, in the raw agent window ± 30 min;
   - offset = median delta per host and trial; dc01 = 0;
   - corrected time = `event_utc − offset`;
   - applied to every host and every trial (no size threshold);
   - original times kept, the DB never written;
   - offsets stored as `data/processed/<trial>.clock_offsets.csv` with `db_sha256`.
2. **Hosts with too few pairs:** fewer than `MIN_PAIRS` (provisional 2) gives no correction, and the trial is flagged. Stability = the largest leave-one-out change of the median; above `MAX_LOO_SHIFT_S` (provisional 2.5 s, half the 014 tolerance, not fitted) the host is flagged `wide`. A host with no events in the window is reported, not flagged. Further rules after the attacker review ([review](../reviews/08_clock_offset-spec-2026-11-12.md)):
   - a pair with |delta| > 60 s is dropped (none of the measured pairs is);
   - a host that reboots after its last pair is `stale` and not applied (none measured);
   - a cross-host row with an unreliable side carries `clock_unreliable`;
   - offset uncertainty (`loo_shift`) is passed to T7.
3. **Clock-only evidence (owner A1):** s04_t01 and s07_t01 are measured for the offset method only.
   - They were excluded from development for their attack design (validator b/c/d), not their clocks.
   - They are not test data (test = t02–t10, decisions 019 and 034).
   - They appear in their own rows, labelled "clock-only", and are never gated or scored.
4. **Two-step approval (owner A2):** the method is approved now. `MIN_PAIRS` and `MAX_LOO_SHIFT_S` are confirmed on the rerun t01 trials of 2026-11-23..28, against a per-trial clock reading of each VM vs dc01. Computed vs read must agree within 2.5 s (CO-12). Test trials (t02–t10) are never used.
5. **Decision 014 amended:** its sentence "measured offsets are reported per trial, not applied" no longer holds for trials with this correction. The 5 s tolerance and the `order_within_tolerance` flag stay.

## Owner answers (step 1, 2026-11-12; spec 08 §8)
- **Q2:** a trial on or after 2026-10-26 with an uncorrected host (`none` or `stale`) that has events in the window is refused. `wide` hosts run, with the flag carried into every result (CO-17).
- **Q3:** a host with 1 pair is not corrected; `MIN_PAIRS = 2` is provisional.
- **Q4:** an unstable host is corrected with status `wide`, never left raw.
- **Q6:** Security 4616 and System 1 are kept for new ingests only (spec 01 amendment in T6b.2), with no re-ingest. A read-only scan of the existing trials' decoded exports flags any trial with a clock change in its window (CO-18, CO-19).
- **Q8 (c):** each rerun scenario's t01 (development) is not synced, with readings before the run and after collection. t02–t10 are synced after a reading, and both readings are recorded. Step 2 uses only the t01 start/end readings (CO-12).
- **Q5:** readings are `w32tm /stripchart` text, `<HOST>_clock.txt`, one per VM per trial in the trial folder.
- **Q10:** every host is corrected; no minimum offset.
- **Q12:** no change to the identity value now. `offset_unc` and `clock_unreliable` are carried to T7, and the T7 spec council decides.
- **Q1, Q7, Q9:** recommendations accepted.

## Consequences
- Amends decision 039 item 3: the 2026-10-26 raw-time refusal is replaced by the offsets-file checks and CO-17.
- Amends decision 014: its last sentence ("reported, not applied") no longer holds for corrected trials.
- The gate and `trial_window` switch to `TIME_BASIS = corrected` (spec 08 §4.1; amendments to 02_gate in T6b.2). The 2026-10-26 refusal is replaced by "offsets file present and matching".
- Results carry the offsets and `clock_flag`.
- **Limits to state in the report:**
  - dc01 is the reference, not true time;
  - one offset per trial, so a clock step inside a trial is invisible (4616 is not kept by the normaliser);
  - the independent check covers WinRM hops only;
  - ep-01's pairs are start-of-trial logons, not attack hops;
  - the skew-period development evidence is s06_t01 plus the two clock-only trials until the reruns.

## Kill criteria
Decision 032 applies, measured independently of the estimating pairs. Do not use the correction, and the owner decides exclusions or reruns, if either holds:
- a development port-join check has corrected |Δ| > 5 s;
- a rerun t01 offset differs from the lab reading by > 2.5 s.

Today 18/18 check pairs are ≤ 1.58 s.

## Committee answer
**EN:** Each endpoint's clock is compared with the domain controller's using Kerberos records that both sides log with the same ID. We take the median gap per host and trial, and subtract it. We checked the result on connections the method never used: after correction they agree within 1.6 s, against up to 18 s before.
**TH:** เราเทียบนาฬิกาของแต่ละเครื่องกับ DC โดยใช้บันทึก Kerberos ที่ทั้งสองฝั่งบันทึกด้วย ID เดียวกัน ใช้ค่ามัธยฐานของส่วนต่างต่อเครื่องต่อรอบแล้วนำไปหักออก และตรวจกับการเชื่อมต่อที่วิธีนี้ไม่ได้ใช้ หลังแก้แล้วต่างกันไม่เกิน 1.6 วินาที จากเดิมสูงสุด 18 วินาที
