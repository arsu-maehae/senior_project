# 076 — T10 addendum D readings: node P/R/F1/FNR, pooled ROC-AUC, weight-sensitivity table

**Date:** 2026-11-18 · **Status:** accepted (stage lead; within spec 06 §10, owner instruction 2026-11-18 "build every
part that needs no test data"; for owner review) · **Task:** T10 (PLAN 10.2, 10.5 development part) · **Relates
to:** spec [06_evaluate](../specs/06_evaluate.md) NP-01..05, AUC-01..03, SW-01..03; handoff §14.2, §14.3;
[065](065-score-baselines-and-success-criteria.md), [068](068-rank-check-readings.md), [071](071-h4-labelled-recall-denominator.md)

## Context
Handoff §14.2 lists node P/R/F1/FNR on the top-k paths, an optional pooled ROC-AUC, and processing time. §14.3 part 4
asks for a w1–w3 sweep with a statement on whether the ranking stays stable. None of these is a frozen hypothesis
(065, 070), so each is **reported without a verdict**.

DEVELOPMENT numbers, not results:
- **Node P/R/F1/FNR**, macro over 5 attack trials:
  - `full`: 0.795 / 0.877 / 0.830 / 0.123
  - `b0` at the same all-node budget: 0.453 / 0.261 / 0.321 / 0.739
  - `b1` and `b2` equal `full` in every trial
- **Pooled AUC** (node reading, n_pos 6, n_neg 27): `full` 0.972, `b1` 0.960, `b2` 0.907. Per trial: 1.0, except s04
  at 0.875.
- **Sweep:** 396 grid points, same ranks as at the default weights in all 396.

## Options considered → decision
| # | Point | Chosen | Why |
|---|---|---|---|
| 1 | Ties at the top-k cut | expectation via `inclusion_probabilities` (068); P = E[covered]/E[held] (ratio of expectations, stated) | same tie rule as every other metric (065) |
| 2 | Basis for P/R | all `context` = 0 key nodes (the handoff's node metric); b0 at full's all-node budget | H4's labelled primary (071) is a different question; NP-05 |
| 3 | Undefined values | P and F1 empty when E[held] = 0; R and FNR empty when there are no key nodes; F1 = 0 when P = R = 0 | no division by zero; F1 at its continuous limit |
| 4 | Means | `math.fsum` macro mean over the trials where the value is defined; counts written | small n, so each trial is visible |
| 5 | b0 holding fewer nodes than the budget | P divides by the nodes b0 actually holds (s02: 11 of a budget of 16) | b0 runs out of labelled units; padding would invent nodes |
| 6 | AUC | Mann–Whitney on 12-decimal scores, ties 0.5; positives are the union of node-reading matches in keyed attack trials; negatives are every other candidate of keyed trials, including keyed S06; pooled and per trial, each undefined when n_pos or n_neg = 0 | handoff "pooled path-level"; the per-trial AUC was added because pooling compares score levels across scenarios (Correction J; ATK-EV-34) |
| 7 | Sweep | N = the 396 grid points (6 λ × 66 w); the `default_w` points are not counted; hop reading (068); the default point is cross-checked against the full/hop ranking row; never the word "stable" (ATK-SC-22) | "same ranks as at the default weights" is what the data shows; the informativeness sentence explains why |
| 8 | `--results` and `rank_sweep.csv` | the sweep is recomputed in memory; `rank_sweep.csv`, if present, must equal it, else "stale: rerun --rank-sweep" | RS-02 staleness rule |
| 9 | P wording | "nodes not in the key", never a false-positive rate | the key omits true follow-up events (ATK-EV-35) |

## Consequences
- The reconstruction-quality table (handoff §14.3 part 1) now exists on development data.
- On development data `full` = `b1` = `b2` in P/R. Identity changes no within-trial order here, as already shown by H3.
- AUC is high because most attack trials have one scored path. That is a stated limit, not a claim.

## Kill criteria
Any of these turned into a test-time hypothesis would need a new freeze record before T5.7 (065 rule).

## Committee answer
**EN:** Besides the frozen checks we report the standard reconstruction numbers: precision, recall, F1, and the share
of answer-key nodes the top-ranked paths miss, plus a pooled AUC. They carry no pass or fail, and each one states its
limits.
**TH:** นอกจากเกณฑ์ที่ตรึงไว้ เรารายงานตัวเลขมาตรฐานของการสร้างเส้นทางใหม่ คือ precision, recall, F1 และสัดส่วนโหนดในเฉลยที่เส้นทางอันดับต้นไม่ครอบคลุม
รวมถึง AUC แบบรวม ตัวเลขเหล่านี้ไม่ตัดสินผ่านหรือไม่ผ่าน และแต่ละตัวระบุข้อจำกัดของตัวเอง
