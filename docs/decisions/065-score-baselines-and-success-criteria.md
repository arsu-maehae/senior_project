# 065 — Baselines (b0, b1, b2, chance line) and success criteria H1–H5, written before any test trial is scored

**Date:** 2026-11-18 · **Status:** accepted (owner, 2026-11-18); numbers frozen with the commit hash in
[066](066-score-parameter-freeze.md) · **Task:** T9.0 / T9.5 · **Relates to:** spec [05_score](../specs/05_score.md)
§3.6, §7.3, Q12, Q13; handoff §14.2, §14.3; Correction J, K; [018](018-s04-both-tracks-exposed.md),
[021](021-s04-track-a-source-session.md); [019](019-dev-test-split.md); review ATK-SC-01, ATK-SC-02

## Context
The owner asked (2026-11-18) for baselines scored by the same ranking code and for success criteria fixed before any
test trial is scored. The attacker showed that without a tie rule s04 track A (benign) and B (attack), which tie at
rank 1, decide H1 by `path_id`, and that "top k + 2" is vacuous in trials with three paths.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| Ties optimistic (rank r) | simple | S04 passes for free | ATK-SC-01 |
| Ties pessimistic (r + t − 1) | strict | S04 always fails | ATK-SC-01 |
| Ties by expected rank under random order (**chosen**, others as sensitivity) | neutral; no `path_id` | fractional ranks | owner 2026-11-18 |
| H3 full ≥ b1 | cannot fail on key paths | uninformative | ATK-SC-02 |
| H3 full > b1, strict (**chosen**, owner) | tests "identity adds ranking value" | equal MRR = not held | owner 2026-11-18 |

## Decision
**Variants** (one scorer, one ranker): `full`; `b1` = (w1·L + w2·N)/(w1 + w2) (handoff's "B3, w₃ = 0"); `b2` = NodeScore
only (handoff B2); `b0` = one candidate per labelled event unit, no linking (handoff B0); a chance line = expected value
of a uniformly random order. The handoff's B1 (linked paths in time order, no ranking) is not built; the chance line
is the "linked, not ranked" reference that takes its place in the comparison promised in handoff §24 (B1 vs Full).
**Ties:** a match in a tie group of size t at rank r has expected rank r + (t − 1)/2 (a
2-way tie at the top = rank 1.5), top-1 credit 1/t; optimistic and pessimistic reported as sensitivity.
**Hypotheses** (attack test trials S01–S05, S07 t02–t10; match = node Jaccard ≥ 0.5; expected, to be measured):
- H1 top-1 rate (`full`) ≥ 0.80.
- H2 MRR (`full`) ≥ 0.85.
- H3 IdentityCoherence adds ranking value: MRR(`full`) > MRR(`b1`), strict.
- H4 node recall of `full`'s top-k > that of `b0` at an equal node budget.
- H5 in each S06 test trial, the highest benign path score (`full`) < the lowest key attack path score of the attack
  test trials.

## Consequences
- With identical L and N inside one protocol, H1 rests on IdentityCoherence, whose definition the keys share (L-SC5);
  on S04 track A and B tie, so S04 contributes top-1 credit 0.5 at best.
- T10 reports each hypothesis as held / not held with the chance line; no "reduces false positives" wording.

## Kill criteria
- Any change to a number or reading after the freeze commit of 066 needs a new freeze record. Before T5.7 (no test
  trial scored, no test key opened) it is a dated change; after T5.7 it is invalid as a test criterion and is reported
  as a post-hoc change beside the frozen result.

## Committee answer
**EN:** We wrote what success means before scoring any test trial: how often the attack path comes first, its average
reciprocal rank, whether the identity term improves that rank, and how we compare with alerts-only and order-blind
baselines. Ties count by their expected position, so an attack path tied with one benign path at the top counts as rank 1.5.
**TH:** เรากำหนดเกณฑ์ความสำเร็จไว้ก่อนให้คะแนนข้อมูลทดสอบใด ๆ ได้แก่ เส้นทางโจมตีขึ้นอันดับหนึ่งบ่อยเพียงใด ค่าเฉลี่ยส่วนกลับของอันดับ
ค่าความสอดคล้องของตัวตนช่วยให้อันดับดีขึ้นหรือไม่ และเปรียบเทียบกับเส้นฐานที่ใช้เพียงการแจ้งเตือนและที่ไม่สนใจลำดับ
กรณีคะแนนเท่ากันนับตามตำแหน่งที่คาดหมาย เส้นทางโจมตีที่เสมอกับเส้นทางปกติหนึ่งเส้นที่อันดับหนึ่งจึงนับเป็นอันดับ 1.5
