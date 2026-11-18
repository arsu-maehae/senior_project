# 071 — Freeze correction: H4 labelled-node recall divides by the labelled (b0-reachable) key nodes

**Date:** 2026-11-18 · **Status:** accepted (owner, 2026-11-18, spec 06 Q6 option a). **Corrects** the H4 numbers
written in [070](070-score-freeze-amendment-readings.md); 070's reading text and every threshold are unchanged. There is one **addition**: a trial with no labelled key node
is undefined and left out of the mean. 070 had no such case.
**Task:** T10.A, before T5.7 (no test trial scored, no test key opened). **Relates to:** spec
[06_evaluate](../specs/06_evaluate.md) EV-02, Q6; review ATK-EV-01
([docs/reviews/06_evaluate-spec-2026-11-18.md](../reviews/06_evaluate-spec-2026-11-18.md)).

## Context
070 item 1 makes the primary H4 reading "node recall over **labelled** `context` = 0 key nodes (the b0-reachable set)
at an equal node budget". The code computes something else. `src/evaluate/rank_run.py` `_b0.side` divides the
labelled-budget coverage by **all** key nodes, for both `full` and `b0` (ATK-EV-01, confirmed in code), and 070's
development numbers came from that code (`full` 0.214 vs `b0` 0.121).

A read-only re-measurement on 2026-11-18 used the 070 denominator: key nodes that lie inside a b0 unit, with ST-05
copies merged. Per trial s02/s03/s04/s05/s07:
- labelled key nodes: 3/4/5/10/10, against 16/12/21/34/40 key nodes in all
- `full`: 1.0/0.75/0.5/0.9/1.0, mean **0.830**
- `b0`: 0.0/0.714/0.3/0.5/0.6, mean **0.423**

`full` > `b0` in 5/5 trials under both denominators. DEVELOPMENT numbers, not results.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| (a) Fix the code to 070's text (**chosen**) | matches the reading the owner froze; recall is measured on the set b0 can reach, so neither side loses for nodes no labelled unit holds | a number written in a frozen record changes | 070 item 1 text; ATK-EV-01 |
| (b) Keep the code, reword 070 | no number changes | the primary reading becomes "share of all key nodes", which mostly measures label coverage (3 of 16 key nodes in s02) | the same measurement |

## Decision
The primary H4 recall, for both `full` and `b0`, has the same numerator as before. The denominator is the
**labelled key nodes**: the `context` = 0 key attack nodes (ST-05 copies replaced by their representative) that lie
inside at least one row of `b0_ranked.csv` (`event_uids`). A trial with no labelled key node has an undefined H4
labelled recall. It is reported as such and left out of the mean, with the count stated. The budget, the tie handling
and the threshold (H4: `full` > `b0`, strict, on the mean over attack trials) are unchanged. The all-node recall stays
beside, unchanged (0.877 vs 0.261).

## Consequences
- Implemented in `evaluate --rank` with PLAN 10.7. rank.csv, rank_totals.csv and rank.md get the new values. The
  development numbers in 070's "Context" table remain as history and are marked "corrected by 071".
- The H4 primary value now depends on which nodes the Sigma rules label (spec 04). Better label coverage changes the
  denominator, so this is stated as a limit beside H4.

## Kill criteria
Any further change follows 065's rule. Before T5.7 a change needs a new freeze record. After T5.7 it is post hoc and
is reported beside the frozen result.

## Committee answer
**EN:** Our recall check for the alerts-only baseline was meant to count only the attack events an alert could see. A
review found the code divided by all attack events, so we corrected the code to the rule we had frozen, before
opening any test key. No threshold changed.
**TH:** การวัด recall เทียบกับเส้นฐานแบบแจ้งเตือนอย่างเดียวตั้งใจนับเฉพาะเหตุการณ์โจมตีที่การแจ้งเตือนมองเห็นได้ การทบทวนพบว่าโค้ดหารด้วยเหตุการณ์โจมตีทั้งหมด
เราจึงแก้โค้ดให้ตรงกับกฎที่ตรึงไว้ ก่อนเปิดเฉลยชุดทดสอบใด ๆ และไม่มีการเปลี่ยนเกณฑ์ใดเลย
