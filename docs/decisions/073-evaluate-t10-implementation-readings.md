# 073 — Implementation readings of spec 06 (070/071 readings in `evaluate --rank`, results tables)

**Date:** 2026-11-18 · **Status:** accepted (stage lead; within approved spec 06 and records 070–072; for owner
review at the stage review) · **Task:** T10.B, T10.E · **Relates to:** spec [06_evaluate](../specs/06_evaluate.md)
EV-01..08, RS-01..11; [071](071-h4-labelled-recall-denominator.md), [072](072-evaluate-t10-readings-and-runner.md)

## Context
The implementer and the tester raised small points that spec 06 leaves open. None of them changes a frozen parameter,
a threshold or a primary reading. The development values are unchanged by these readings: H1 held 0.900; H2 not held
0.833333; H3 not held, difference 0.000000; H4 held 0.830000 > 0.422857; H5 held, margin 0.305556.

## Options considered → decision (one row per reading)
| # | Point | Chosen | Why |
|---|---|---|---|
| 1 | results.csv carries a `note` column not named in §3.3 | keep it | holds the H5 reason, the contested-set name and the "reported beside" labels; the row key is (table, variant, reading_scope, metric, **source**) because EV-04 paired and own-set rows share the first four |
| 2 | spec 05 §7.3 "stated limits" end with a sentence that quotes the forbidden phrases, and RS-10 forbids them in results.md | leave that one sentence out of results.md; the wording block states the same rule without quoting the phrases | RS-08 and RS-10 both hold |
| 3 | H3/H4 verdict form | a difference row, compared value r12(r12(a) − r12(b)) against `> 0` | RS-09 on one written value; both sides shown in their own rows |
| 4 | a keyed S06 trial with no candidates | H5 **not held**, reason "no candidate paths (undefined)" | the conservative reading; a check that cannot be computed never counts as held |
| 5 | the forbidden-word list in evaluate | a copy, pinned by a test to equal `score.report`'s list | evaluate must not import score (068) |
| 6 | "distinct b0 units" (EV-03) | distinct canonical `event_uids` sets after the ST-05 copy merge | ATK-EV-14 |
| 7 | sweep tables: the chance line over score > 0 | labelled "(default w)" | a weight change can move a score to 0 |
| 8 | `primary_metric` of the b0 row | `full_recall_labelled_mean;b0_recall_labelled_mean` | both sides of the H4 comparison |
| 9 | new columns not named in §3.1 | `key_nodes_labelled`, `labelled_recall_trials`, `contested_set`, `scope_trial_ids`, `chance_per_key_mrr`, `chance_pos_per_key_mrr` | appended after the existing columns, so old column positions stay the same (EV-07) |

## Consequences
Spec 06 §3 is updated to name these columns and the row key. The tests pin each reading (`test_results_tables.py`,
`test_evaluate_readings.py`).

## Kill criteria
If the owner rejects reading 4 (S06 trial without candidates), H5 becomes "undefined" there. That case is not in the
development data.

## Committee answer
**EN:** These are small bookkeeping choices made while coding. Each one picks the stricter or the more transparent
option, and none changes a threshold or a frozen reading.
**TH:** นี่คือการเลือกเล็ก ๆ ระหว่างเขียนโค้ด แต่ละข้อเลือกทางที่เข้มกว่าหรือโปร่งใสกว่า และไม่มีข้อใดเปลี่ยนเกณฑ์หรือการอ่านผลที่ตรึงไว้
