# 078 — Collection-tail criterion for the old ×10 trials (S02, S03, S06 t01–t10)

**Date:** 2026-11-25 · **Status:** accepted (owner, 2026-11-25, after the kill test); amended 2026-11-26 (S06 hybrid,
see the last section) ·
**Relates to:** [029](029-x10-replacement-rule-and-pass-criteria.md) (pass criteria), [019](019-dev-test-split.md) (split),
[014](014-cross-host-time-tolerance.md) (cross-host tolerance), [034](034-x10-v2-reruns-folder-and-split.md) / [052](052-lab-stopping-rule.md) (full reruns),
spec 03_stitch ST-23/ST-26/ST-42/ST-43, `tools/lab` 5-minute tail (commit cf3362b) · **Evidence:**
[docs/results/078-kill-test/](../results/078-kill-test/summary.md)

## Context
The S02 migration check (2026-11-25) found the logs exported before the run had finished. The same issue shows in the
old ×10 trials: in 26 of 28 measurable trials the recorded `out/x10_validate` fields put the export end less than
300 s after the last design step (`design_end_unclipped_utc` − 300 s).

Decision 029 has no tail criterion, and this one is **set after the tails were seen**. To keep it independent of
results, it comes only from:
- frozen pipeline parameters;
- validator fields;
- per-file `last_event_utc` metadata in `data/manifest.csv`;
- one kill test on development trials.

No pipeline output of a test trial was opened, no pipeline stage ran on a test trial, and no event content was read.

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
Each option is a rule for the minimum tail. The test-trial counts (t02–t10) are the trials that are usable or limited
under that rule.

| Option | Rule (minimum tail) | Measured on | S02 / S03 / S06 | Why not / why |
|---|---|---|---|---|
| A | 30 s (`followup_max_s`) + 27 s fixed | DB last event | 3 / 3 / 2 | Uses a window that changes no link |
| B | 15 s + 27 s fixed | DB last event | 5 / 3 / 5 | One worst-case skew (S06) applied to all trials |
| C | 15 s + the trial's own worst skew | DB last event | 9 / 8 / 7 | Overstates the tail: the DB end is the latest-exported host |
| D | 15 s + own skew | source host of the last hop, uncorrected | 6 / 4 / 0 | Mixes two host clocks without correcting them |
| **E** | **15 s + own skew** | **source host of the last hop, both ends clock-corrected** | **7 / 5 / 0** | **Accepted: the same rule and time basis as the kill test** |

## Decision
A trial meets the tail criterion when its corrected tail on the source host of the last hop is at least 15 s
(`link_after_s`) plus its own worst criterion-g host-pair offset.

**Terms:**
- **Source host** = the validator's design `source` of the hop with the latest time.
- **Tail** = earliest `last_event_utc` of that host's Security and Sysmon files (manifest) minus the last design step.
- **Correction:** both times are corrected as event time − host offset (CO-09), each with its own host's offset.

**Offsets:** the criterion-g medians (`host_offsets_vs_dc01`). On all 9 development trials they equal the pipeline's
`clock_offsets.csv` to the millisecond, with the same pair counts (same LogonGuid mutual-nearest median method), so
the test trials are corrected with the pipeline's method without running `clock_offset` on them. Where a needed host
offset is missing, the uncorrected tail is compared with 15 s + 27 s.

**Classes:**
- **usable:** tail ≥ 300 s;
- **limited:** usable, with the analysis window ending at the export, stated as a limitation;
- **fails:** below the minimum, or an existing validator FAIL.

**Why option E:** the kill test clipped on the corrected basis at exactly step + 15 s + own skew, so the tested rule
and the applied rule match.

**Why no intermediate threshold is tested:** a value between +0 s and +15 s + skew would be chosen after seeing which
trials it saves (mainly S06, tails −18 to 19 s), which is fitting the criterion to the outcome.

The new campaign keeps the 5-minute tail (`tools/lab` `-TailSec 300`).

## Kill test (development trials only; scratch repos; [results](../results/078-kill-test/summary.md))
**Setup:**
- The runner `python -m run_trial --development --repo <scratch>`, unchanged.
- Only the scratch copy of the window file had `end_utc` changed.
- **Control arm:** reproduced the committed `out/` exactly (363 files, 0 mismatches).
- The real repository was unchanged (1,266 files hashed before and after).

**Arm +15 s** (end = last design step + 15 s + own skew; cuts of 5–283 s):
- **No linking change:** nothing changed on any hop, link or path present in both arms. Key-hop link accuracy is
  unchanged, and the key path keeps rank 1 with the same score.
- **No Sigma-label change:** no path node-score changed.
- **Only effect:** hops lying wholly after the clip vanished with their one-hop paths, for example s02_t01's later
  ep-01 → ep-02 `admin_it` hop (not a design step), and rank ties shrank.
- **Kill criterion 1 (threshold too low): not triggered.**

**Arm +0 s** (end = last design step): the last design hop broke in **7 of 9** trials.
- Trigger lost and the key path leaves the ranking: s03_t00, s07_t00, s03_t01.
- Sysmon 3 port join lost (tier A → B): s03_t00, s05_t00 (where the 3-hop path also splits).
- Source evidence lost (tier B → D, target only): s06_t00.
- Members lost: s02_t01, s06_t01.
- Sigma labels: `node_score_ctx1` / `n_node_units` changed on one path each in s06_t00 and s07_t00.
- **Kill criterion 2 (relax to +0 s): not supported**, because the after-window is needed.

## Final classification (option E; corrected tail / minimum, in s)

| Class | Trials (`t01` = development) |
|---|---|
| usable | s02_t01 (318 / 18.8) |
| limited | s02_t02 (265), t03 (163\*), t04 (158\*), t07 (22 / 18.2), t08 (27 / 25.0), t09 (32 / 19.2), t10 (29 / 19.0) · s03_t01 (25 / 21.2), t02 (27 / 20.0), t05 (70), t06 (26 / 18.5), t07 (33 / 24.2), t09 (105) |
| fails (tail) | s02_t05 (7 / 19.7), t06 (20 / 20.8) · s03_t03 (11 / 17.2), t04 (20 / 23.3), t10 (15 / 19.8) · s06_t01 (16 / 33.8), t02 (11 / 32.1), t03 (−18 / 28.6), t04 (14 / 42.0), t05 (19 / 31.7), t06 (4\* / 42.0), t07 (13 / 30.2), t08 (15 / 27.8) |
| fails (existing validator FAIL) | s03_t08 (b, c, e), s06_t09 (a, b), s06_t10 (b) |

\* No offset for a needed host, so the tail is uncorrected and the minimum is 15 s + 27 s.

**Test trials left:** S02 7, S03 5, **S06 0**.

## Consequences
- **S06 needs a full rerun.** It has 0 test trials, and its development trial s06_t01 fails too. The planned
  replacement slots (s06_t11, s06_t12) can't reach 5. The rerun gets new ids s06_t01 (development) and t02+ (test),
  as for S01, S04, S05 and S07. This needs amendments to 034 and 052, planned separately.
- **The development set changes.** s06_t01 is one of the 9 development trials on which the stage parameters were
  frozen. Those parameters stay frozen, and the replacement s06_t01 joins only after ingest and the validator, as in
  decision [053](053-clock-only-retired-development-gate-real-data-switch.md). Development results that include the old s06_t01 are reported as such.
- **S02 and S03 stay at 5 or more test trials.** Open for the owner: whether the tail-failed trials (S02: t05, t06;
  S03: t03, t04, t10) get 029 replacements (`trial_11` onwards). Either way they are excluded from the test set.
- **Report limitation wording:** "*n* test trials have less than 300 s of logs after the last designed step; their
  analysis window ends at the export." Later agent activity outside the design (for example s02_t01's second
  `admin_it` hop) can be missing from such trials.
- **Measurement limits:**
  - Security/Sysmon `last_event_utc` stands in for the export time (conservative if a channel was idle).
  - The kill test cut all hosts at one corrected time, whereas a real export cuts each host at its own time.

## Kill criteria (for this accepted rule)
- If a later development trial (for example the rerun t01 trials) changes a link, tier or path score when clipped
  at step + 15 s + own skew, raise the threshold in a new record.
- If the new campaign's coordinator manifests show tails at or above 300 s but validator criterion b still finds
  missing steps, the tail is not the cause, and this criterion is revisited.

## Amended (owner, 2026-11-26): scope, s06_t01 and the S06 test trials
- **Scope:** the criterion decides test-set membership. A development trial that fails it is kept with a stated
  limitation; development trials are never replaced because of this rule.
- **s06_t01 is kept as development.** Its corrected tail is 16 s, which exceeds `link_after_s` (15 s), the after-step
  window that affects linking. It fails only the skew margin (+18.8 s, minimum 33.8 s). The +0 s kill-test arm showed
  that the first seconds after the last step matter, and s06_t01 has them.
  - Limitation: the 16–34 s after the step are missing, and the kill test cannot vouch for them, because s06_t01's
    own clip (+33.8 s) lay beyond its data.
- **S06 test trials** come from x10_v2 as `s06_t11` onwards (034 and 052 amendments), not from a full rerun.
  "Consequences: S06 needs a full rerun" and the development-set bullet above are superseded. The development set
  and `DEVELOPMENT_TRIALS` are unchanged.
- **Limitation (machine A / machine B):** S06's development trials (`t00`, `t01`) were collected on machine A with the
  old procedure, while its test trials (`t11`+) come from machine B with the `tools/lab` scripts of cf3362b
  (readiness gate, OP_DONE, 5-minute tail). S02 and S03 are machine A only, and the full-rerun scenarios are machine B
  only, so this split is specific to S06 and is stated with every S06 test figure.
- **Closed: no 029 replacements for S02 or S03.** Both meet the minimum under 078 (S02 7 test trials, S03 5); their
  tail-failed trials (S02 t05, t06; S03 t03, t04, t10) are excluded from the test set and not replaced. This closes the
  open point in "Consequences" above.

## Committee answer
**EN:** We set the minimum log tail from the time window the pipeline actually uses to link events: 15 s after the
last step, plus each trial's own clock offset. We tested it on the development trials: cutting there changed no
link and no score, while cutting at the last step broke the last hop in 7 of 9. It is measured on the machine that
holds the evidence, using only recorded timestamps, so no test trial was kept or dropped because of its score.

**TH:** เราตั้งเกณฑ์ช่วงล็อกหลังขั้นตอนสุดท้ายจากหน้าต่างเวลาที่ไปป์ไลน์ใช้เชื่อมเหตุการณ์จริง คือ 15 วินาทีหลังขั้นตอนสุดท้าย บวกค่าความคลาดเคลื่อนของนาฬิกาของแต่ละรอบ และทดสอบบนชุดพัฒนาแล้ว ตัดที่จุดนี้ไม่มีการเชื่อมโยงหรือคะแนนใดเปลี่ยน แต่ถ้าตัดตรงขั้นตอนสุดท้ายพอดี การเคลื่อนที่ครั้งสุดท้ายเสียไป 7 ใน 9 รอบ เราวัดบนเครื่องที่เก็บหลักฐานโดยใช้เฉพาะเวลาที่บันทึกไว้ จึงไม่มีรอบทดสอบใดถูกเก็บหรือตัดออกเพราะคะแนน
