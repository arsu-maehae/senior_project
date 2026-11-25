# 078 — Collection-tail criterion for the old ×10 trials (S02, S03, S06 t01–t10)

**Date:** 2026-11-25 · **Status:** proposed (owner review; kill-criterion run on development trials pending) ·
**Relates to:** [029](029-x10-replacement-rule-and-pass-criteria.md) (pass criteria), [019](019-dev-test-split.md) (split),
[014](014-cross-host-time-tolerance.md) (cross-host tolerance), spec 03_stitch ST-23/ST-26/ST-42/ST-43, `tools/lab` 5-minute tail (commit cf3362b)

## Context
The S02 migration check (2026-11-25) found the logs exported before the run had finished. The same issue shows in the
old ×10 trials. From recorded `out/x10_validate` fields, 26 of 28 measurable trials have less than 300 s between the
last design step (`design_end_unclipped_utc` − 300 s) and the DB's last event. Per host, using the per-file
`last_event_utc` in `data/manifest.csv`, the tails are shorter still.

Decision 029 has no tail criterion. This record proposes one, **set after the tails were seen**. To keep it
independent of results, the threshold comes only from frozen pipeline parameters and validator fields. No pipeline
output of a test trial was opened, and no event content was read.

**After-step windows in the pipeline:**

| Window | Value | Affects linking or scoring? |
|---|---|---|
| gate RDP/service/WinRM pairing | 5 s | yes |
| stitch `copy_install_s` (ST-32) | 10 s | confirmation only |
| stitch `link_after_s` (ST-42/43) | **15 s** | **yes: the largest that does** |
| stitch `followup_max_s` (ST-26) | 30 s | no: follow-ups add no links, identity rows or protocol, and non-seed hops never enter a path (ST-23) |
| Kerberos confirmation (ST-47) | no time window | no (LogonGuid match only) |
| `trial_window` end margin | 300 s, already clipped at the export end | bounds the data, not a link rule |
| gate `near_window_s` | 300 s | counts only |

## Options considered
Each option is a rule for the minimum tail. The test-trial counts (t02–t10, existing validator FAILs excluded) are the
trials that are usable or limited under that rule.

| Option | Rule (minimum tail) | Measured on | S02 / S03 / S06 | Note |
|---|---|---|---|---|
| A | 30 s (`followup_max_s`) + 27 s fixed | DB last event | 3 / 3 / 2 | Uses a window that changes no link |
| B | 15 s + 27 s fixed | DB last event | 5 / 3 / 5 | One worst-case skew (S06) applied to all trials |
| C | 15 s + the trial's own worst skew (criterion g; 27 s if g is missing) | DB last event | 9 / 8 / 7 | Overstates the tail: the DB end is the latest-exported host |
| **D** | **same rule as C** | **source host of the last hop: min(Security, Sysmon) `last_event_utc`** | **6 / 4 / 0** | **Proposed** |
| E | 15 s + 5 s (decision 014 tolerance) | as D, both ends corrected with criterion g median offsets | 7 / 6 / 0 | Avoids counting the skew twice; S06 still 0 |

## Decision (proposed)
A trial meets the tail criterion when its tail on the source host of the last hop is at least 15 s plus its own worst
criterion-g pair offset (27 s if criterion g is missing).
- **Tail** = earliest `last_event_utc` of that host's Security and Sysmon files minus the last design step.
- **Source host** = the validator's design `source` of the hop with the latest time.
- **Classes:**
  - **usable:** tail ≥ 300 s;
  - **limited:** usable, but the window ends at the export, stated as a limitation;
  - **fails:** below the minimum, or an existing validator FAIL.
- The new campaign keeps the 5-minute tail rule (`tools/lab` `-TailSec 300`).

**Classification under D:**

| Class | Trials (`t01` = development) |
|---|---|
| usable | s02_t01 |
| limited | s02_t02, t03, t04, t07, t09, t10 · s03_t02, t05, t06, t09 |
| fails (tail) | s02_t05, t06, t08 · s03_t01, t03, t04, t07, t10 · s06_t01–t08 |
| fails (existing validator FAIL) | s03_t08 (b, c, e), s06_t09 (a, b), s06_t10 (b) |

**Trials that change class against C** (DB-level → per-host), 18 in all:
- usable → limited: s03_t02;
- limited → fails: s02_t05, t06, t08; s03_t01, t03, t04, t07, t10; s06_t01–t08.

## Consequences
- **Test sets below 5:**
  - S03 has 4 test trials and S06 has 0; S02 keeps 6.
  - The replacement slots (s03_t11, s06_t11, s06_t12) are already taken by the existing fails, and S02 has none.
  - So D, if accepted, needs new S03 and S06 trials from the new campaign (5-minute tail).
- **Development trials:**
  - s03_t01 (19 s on ep-01, needs 21 s) and s06_t01 (−1 s raw, 16 s corrected, needs 34 s) fail D.
  - Yet the pipeline produced 28 hops / 4 paths and 32 hops / 6 paths on them.
  - In S06 the last hop's source command (validator `execution.last_utc`) is logged about 14 s before the target logon.
    What is cut is only the 15 s after-window. So D may be stricter than linking needs, and the kill-criterion run
    tests this.
- **Report limitation wording:** "*n* test trials have less than 300 s of logs after the last designed step; their
  analysis window ends at the export."
- **Measurement limits:**
  - Security/Sysmon `last_event_utc` stands in for the export time. An idle channel understates it, which makes the
    rule conservative.
  - Criteria b and c already ensure that every designed step is present.

## Kill criteria
1. **Too low:** clip each development trial's window at last design step + 15 s + its own skew and rerun stitch/score
   on development trials only, in scratch outputs. If any link, tier or path score changes, the threshold is too low:
   raise it.
2. **Too strict:** if the same run, clipped at the last design step itself, changes nothing, the after-window is not
   needed for these designs. The rule can then be relaxed to: the last hop's source-side step lies inside the source
   host's export. This needs owner approval before that arm is run.

## Committee answer
**EN:** We set the minimum log tail from the time windows the pipeline actually uses to link events: 15 s after the
last step, plus each trial's own clock offset. We measured it on the machine that holds the evidence, using only
recorded timestamps, and we did not look at any pipeline result on the test trials, so no trial was kept or dropped
because of its score.

**TH:** เราตั้งเกณฑ์ช่วงล็อกหลังขั้นตอนสุดท้ายจากหน้าต่างเวลาที่ไปป์ไลน์ใช้เชื่อมเหตุการณ์จริง คือ 15 วินาทีหลังขั้นตอนสุดท้าย บวกค่าความคลาดเคลื่อนของนาฬิกาของแต่ละรอบ และวัดบนเครื่องที่เก็บหลักฐาน โดยใช้เฉพาะเวลาที่บันทึกไว้แล้ว เราไม่ได้ดูผลของไปป์ไลน์บนชุดทดสอบเลย จึงไม่มีรอบใดถูกเก็บหรือตัดออกเพราะคะแนน
