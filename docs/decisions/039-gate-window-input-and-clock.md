# 039 — Gate window from neutral trial metadata; corrected times; t00 only until clocks are corrected

**Date:** 2026-11-11 · **Status:** accepted (owner answers Q2, Q3, Q4 on spec 02_gate, 2026-11-11) · **Task:** T6 (6.4), T7 (7.7) · **Amends:** PLAN 6.4 (window source) and 7.7 (identity look-back) · **Relates to:** 026, 032, 036

## Context
PLAN 6.4 said the gate clips each trial to its answer key's `agent.run_interval`. The attacker review (ATK-12) noted that this feeds ground-truth files into the system under test, and test keys (t02–t10) are not approved yet. The clip also drops source-host logons opened before the window that identity (Correction K) needs (ATK-09). And from 2026-10-26 ep-01 ran 10–27 s behind dc01 (decision 032), so a raw-time clip and the 5 s pairings can be wrong on those trials.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| Window from the key (draft or approved) | Already exists | Pipeline reads ground truth; test keys unapproved | ATK-12 |
| Window computed from the data by the decision 026 function, written to `data/trial_windows.csv`; S01 from operator-recorded start/end | Gate never reads `ground_truth/`; same rule as the keys | One more step; S01 depends on operator notes | decision 026; S01 has no agent (035) |
| Gate on raw times everywhere | Runs now | ep-01 skew up to 27 s on S04/S06/S07 ×10 | decision 032 |
| Corrected times; t00 only until the correction exists | No result built on skewed clocks | ×10 trials wait for decision 032's correction | decision 032 |

## Decision
1. **Window input (Q2):** a separate step (`src/trial_window/`) computes each trial's window from the trial DB and `data/manifest.csv` with the decision 026 rule (first agent root − 60 s; last agent step or command + 300 s, clipped to the manifest export end) and writes `data/trial_windows.csv`. S01 uses the operator-recorded trial start and end with the same margins (`window_source = operator`). Neither the gate nor this step opens any path under `ground_truth/` (test GTT-14). On the six t00 trials the computed window must equal the approved key's `agent.run_interval` (test GTA-06, which alone reads the keys). S01 margins (operator start − 60 s, end + 300 s, clipped to the manifest export end) accepted by the owner 2026-11-11.
2. **Identity look-back (Q3):** the gate output carries the window. T7 may look up session opens on the source host before the window **for the identity check only**, never as an anchor or trigger. PLAN 7.7 is amended to say so.
3. **Clock (Q4):** the clip and the pairings use clock-corrected times once decision 032's correction exists; original times stay and are written next to them. Until then the gate runs on t00 development trials only, on raw times, and refuses any trial collected on or after 2026-10-26.

## Consequences
The pipeline's only trial-specific input besides the DB is a file computed from the data, so test results do not rest on the key's window. Gating of t01 and the test set waits for decision 032's correction (a spec and a PLAN entry are still needed for it). S01 windows depend on the T2 checklist recording start and end times. If the decision 026 function needs anything from the keys or owner reviews, GTA-06 or GTT-14 fails and the step is changed.

## Kill criteria
If a computed t00 window differs from the key's `run_interval`, find the cause before gating. If the correction is ruled out (032 kill criteria), the owner decides which ×10 trials are gated on raw times or rerun.

## Committee answer
**EN:** The time window of each trial is computed from the logs themselves, by the same rule the answer key uses, so the system never reads the answer key. Trials with clock drift are gated only after their clocks are corrected.
**TH:** ช่วงเวลาของแต่ละรอบคำนวณจากล็อกเองด้วยกฎเดียวกับที่เฉลยใช้ ระบบจึงไม่อ่านเฉลยเลย ส่วนรอบที่นาฬิกาคลาดเคลื่อนจะผ่าน gate ก็ต่อเมื่อแก้เวลาแล้ว
