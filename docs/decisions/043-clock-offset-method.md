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

## Parameter freeze (spec 08 §5, ATK-10, COT-17; T6b.2, 2026-11-12)
`src/clock_offset/params.py` SHA-256, computed over its bytes with CRLF normalised to LF (so git's line-ending conversion on Windows cannot change it):

`params_sha256: 9dcd662b18863d062741e904482d45df005c73c2ba679f7718dfd68a70df82e3`

(First recorded as `0bfa7c8d…` before the owner added `MIN_CLOCK_STEP_MS` on 2026-11-12; see the T6b.2 amendment below.)

Step 2 may change only `MIN_PAIRS`, `MAX_LOO_SHIFT_S`, `READING_AGREE_S` and `MIN_CLOCK_STEP_MS` (marked PROVISIONAL in the file), and only from the rerun t01 trials. Any change records a new hash here.

## Kill criteria
Decision 032 applies, measured independently of the estimating pairs. Do not use the correction, and the owner decides exclusions or reruns, if either holds:
- a development port-join check has corrected |Δ| > 5 s;
- a rerun t01 offset differs from the lab reading by > 2.5 s.

Today 18/18 check pairs are ≤ 1.58 s.

## Committee answer
**EN:** Each endpoint's clock is compared with the domain controller's using Kerberos records that both sides log with the same ID. We take the median gap per host and trial, and subtract it. We checked the result on connections the method never used: after correction they agree within 1.6 s, against up to 18 s before.
**TH:** เราเทียบนาฬิกาของแต่ละเครื่องกับ DC โดยใช้บันทึก Kerberos ที่ทั้งสองฝั่งบันทึกด้วย ID เดียวกัน ใช้ค่ามัธยฐานของส่วนต่างต่อเครื่องต่อรอบแล้วนำไปหักออก และตรวจกับการเชื่อมต่อที่วิธีนี้ไม่ได้ใช้ หลังแก้แล้วต่างกันไม่เกิน 1.6 วินาที จากเดิมสูงสุด 18 วินาที

## T6b.2 implementation amendment (owner answers 2026-11-12)
Evidence: CO-19 scan of the decoded exports of the 11 allowlisted trials (`out/clock_offset/<trial>/clock_events.csv`), the T6b.1 measurement script re-run for COA-01, and `tests/unit/test_clock_offset.py`.

1. **COA-01 path:** the T6b.1 script (`clock_measure.py`, read-only, hard allowlist) still existed. A wrapper called its own functions unchanged to get ms medians. The new code agrees within 1 ms on all 33 endpoint rows, with equal pair counts (largest difference 0.49 ms, from rounding to whole ms). The fallback (±5 ms vs §10.1) was not needed.
2. **Rounding:** each median is computed exactly in µs and rounded half away from zero to whole ms. Quartiles use position (n−1)·p. The `wide` test is strict (`loo_shift > 2.5 s`).
3. **Clock-change rule (CO-15/CO-18 amended):**
   - **Owner choice:** a clock change counts only with \|shift\| ≥ `MIN_CLOCK_STEP_MS` = 1000 ms (new, provisional, step 2) or an unknown shift. Boots always count.
   - **Evidence:**
     - Windows logs routine 0–2 ms time-service adjustments as 4616 + Kernel-General System 1, e.g. s06_t00 ep-02 +2 ms between pairs at 09:05:52.
     - Real steps are 8.48 s (s02_t00 ep-02) to 15 days (snapshot-revert catch-up on the t01s).
     - Without the threshold, a routine adjustment after the last pair in a new DB would make the host `stale` and refuse a post-10-26 trial.
   - **Cut:** a counted change between pairs drops the pairs before it. One after the last kept pair → `stale`. One before the first pair → `expected`. This replaces the self-contradictory CO-18 sentence.
   - **Shift of a DB row:** read from its JSONL line through `source_relative_path` + `source_line`, read-only.
4. **`clock_change_in_window` (CO-19 amended):**
   - It is set only by a counted change after the host's first pair, or on a host with no pairs (dc01 included). `expected` and `routine` changes are listed, not flagged.
   - **Result:** false on all 11 trials. The scan found 4616/System 1 in the exports of 9 trials, every one `expected` or `routine`.
   - The counted in-window steps are on ep-02: s02_t00 +8.48 s; s06_t00 +1 h 50 min; s07_t00 +2 h 2 min; every t01.
   - 0 of the 225 key-hop events in the six t00 keys were logged before a counted step on their host (owner check, COA-08). The t01 trials have no approved keys yet.
5. **Events before a counted change → `clock_unreliable = 1` in every output** (owner addition).
   - "Logged before" = recorded time in [the host's last boot before the change, max(previous time, change time)). For a backward step, the whole interval counts. Boots do not trigger this rule.
   - **Carrier:** the new `data/processed/<trial>.clock_changes.csv`, with DB and export changes together. It adds `channel`, `event_id` and `last_boot_before_utc` to the owner's column list, so consumers can apply the interval without the DB.
   - Its SHA-256 goes into the window row next to `offsets_sha256`.
6. **Readings (CO-12):**
   - **Time zone:** read from the `tzutil /g` line appended to each file and mapped Windows → IANA by an explicit table. The venv has no `tzdata`, so zones without DST use fixed offsets and DST zones are refused. With no line, the time zone is a required argument; with neither, the file is invalid.
   - **Sign:** assumed host − dc01 = −o (`SIGN_CONVENTION = -1`). The sign and the time zone are confirmed at the first rerun session.
   - **Assignment:** start = last session before min(run start, sync). A file is invalid if any session does not track dc01.
   - **Ingest copy:** planned only (spec 08 §4.2); no code touches `data/raw`.
7. **`late_gap_s`:**
   - **Reading taken:** the CSV uses spec §3's stated meaning, "to the last agent event", i.e. the uncut window end − 300 s.
   - **Why it matters:** the bracketed "(window end − 300 s)" equals that only when the export span does not cut the window. On 7 of 11 trials the span does cut it. The clipped-end value, which reproduces §10.7, is kept in `stats.json` (`late_gap_clipped_end_s`).
   - **Open:** §10.7 and CO-16's "35–97 s on t01" understate the gap (e.g. s06_t01 ep-01 280 s, not 35 s). The owner confirms the definition before Q11 (step 2).
8. **Gate and window (to be applied in T6b.2 tasks 4–5):**
   - **Columns:** CO-09 naming. `event_utc` = original, plus `event_utc_corrected`; `event_utc_raw` is dropped.
   - **GTA-05:** redefined to run on any development trial with a .97/.98/.99 session, and skipped until one exists.
   - **Clock-only trials:** s04_t01 and s07_t01 are refused by `trial_window` (`CLOCK_ONLY_TRIALS`).
   - **Pairings:** every gate pairing is same-host, so only the GT-01 clip depends on the time basis.
