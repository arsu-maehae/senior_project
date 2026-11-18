# 070 — Freeze amendment: primary readings of H2 and H4, contested-trial reading, chance line in every table

**Date:** 2026-11-18 · **Status:** accepted (owner, 2026-11-18) — **supersedes** 065 (the H2 and H4 readings, the
"Variants" chance line wording) and 066 (rows "H readings (primary)" and "Readings reported beside") · **Task:** T9
follow-up, before T5.7 (no test trial scored, no test key opened) · **Relates to:** spec [05_score](../specs/05_score.md)
§7.3; [065](065-score-baselines-and-success-criteria.md), [066](066-score-parameter-freeze.md),
[068](068-rank-check-readings.md), [069](069-score-stage-review-fixes.md) item 9; review ATK-SC-14, -15, -21

## Context
066 froze the parameters and the H1–H5 readings at `6338884`, with the stricter readings of 069 item 9 reported beside
and a rule that a reading may change only by a new freeze record before T5.7. The owner changes two primary readings
and adds two reporting rules. The development numbers that motivated each change (out/evaluate at `c21db11`, hop
reading, ties by expected rank; DEVELOPMENT numbers, not results):

| Change | Motivating development numbers |
|---|---|
| 1. H4 primary = labelled-node recall (**numbers corrected by [071](071-h4-labelled-recall-denominator.md)**: denominator = labelled key nodes, dev 0.830 vs 0.423) | all `context` = 0 nodes: `full` 0.877 vs `b0` 0.261 — won by construction, since b0 can hold only labelled events (ATK-SC-14); labelled nodes only: 0.214 vs 0.121 (per trial: s02 0.188 / 0.000, s03 0.250 / 0.238, s04 0.119 / 0.071, s05 0.265 / 0.147, s07 0.250 / 0.150) |
| 2. MRR primary = per-key MRR | per-trial MRR 0.933 credits s07's first match only; per-key MRR 0.833 (key paths s02 1, s03 1, s04-B 0.667, s05 1, s07-x 0.667, s07-y 0.667) (ATK-SC-15) |
| 3. Thresholds unchanged | per-key MRR 0.833 is below the MRR ≥ 0.85 threshold on development data; it is **not** moved |
| 4. Contested-trial reading | only 2 of 5 attack trials (s04, s07) have more than one path with score > 0 under `full`/`b1`/`b2`; in the other 3 the key path is the only scored path, so the chance line over scored paths equals the observed values (0.900 / 0.933, 069) |
| 5. Chance line in every table | chance top-1 0.248 / MRR 0.377 over all paths vs observed 0.900 / 0.933; over scored paths 0.900 / 0.933 |

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Keep 065/066 readings | no change after the freeze | H4 won by construction; s07's second key path uncredited |
| Change readings, keep thresholds (**chosen**) | stricter readings; no threshold fitted to development numbers | H2 (MRR ≥ 0.85) already fails on development data under the new reading |
| Change readings and lower the MRR threshold to fit 0.833 | H2 would hold on development | tuning a test criterion on development results |

## Decision
1. **H4 primary:** node recall over **labelled** `context` = 0 key nodes (the b0-reachable set) at an equal node budget;
   all-node recall is reported beside it.
2. **H2 primary:** **per-key MRR** — each key attack path's own expected reciprocal rank (ties by expected rank, 065),
   averaged over key attack paths; per-trial MRR (first match, handoff §14.2) is reported beside it. H3 (strict
   MRR(`full`) > MRR(`b1`)) uses the per-key MRR.
3. **Thresholds unchanged:** H1 top-1 ≥ 0.80; H2 per-key MRR ≥ 0.85; H3 strict; H4 `full` > `b0`; H5 as in 065. No
   threshold is moved after seeing development results.
4. **Secondary contested reading:** for `full`, `b0`, `b1`, `b2`, every metric is also reported over **contested**
   attack trials only — trials where the variant's candidate set has more than one candidate with score > 0 (for `b0`
   the candidates are labelled units). It never replaces the primary reading. Development: contested = s04, s07 for
   `full`/`b1`/`b2` (top-1 0.750, per-trial MRR 0.833, per-key MRR 0.667, identical in all three); all 5 attack trials
   for `b0`.
5. **Chance line:** every T10 results table shows the chance line (uniformly random order; over all candidates and over
   candidates with score > 0) next to the observed values.

Everything else in 065 and 066 stands (parameters and order-table hash frozen at `6338884`; tie rule; H1, H3, H5
numbers).

## Consequences
- `evaluate --rank` (development) still labels the 065 readings as primary; T10 implements 070's primary readings, the
  contested reading and the chance-line columns before the test run (PLAN T10).
- On development data H2 would not hold (0.833 < 0.85) and H3 would not hold (equal MRR); both are reported as such.

## Kill criteria
- Any further change to a reading or threshold after this record follows 065's rule: before T5.7 only by a new freeze
  record; after T5.7 it is post-hoc and reported beside the frozen result.

## Committee answer
**EN:** Before opening the test answer keys we made two success checks stricter: recall is measured only on events an
alerts-only baseline could see, and each attack path's own rank counts. We did not lower any threshold, even though one
check already fails on development data, and every table shows what random ordering would score.
**TH:** ก่อนเปิดเฉลยชุดทดสอบ เราทำให้เกณฑ์ความสำเร็จสองข้อเข้มขึ้น คือวัด recall เฉพาะเหตุการณ์ที่เส้นฐานแบบแจ้งเตือนอย่างเดียวมองเห็นได้
และนับอันดับของเส้นทางโจมตีแต่ละเส้นเอง เราไม่ลดเกณฑ์ใดเลย แม้เกณฑ์หนึ่งจะไม่ผ่านบนข้อมูลพัฒนาแล้ว และทุกตารางแสดงค่าที่การเรียงแบบสุ่มจะได้
