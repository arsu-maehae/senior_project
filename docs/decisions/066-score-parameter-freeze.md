# 066 — Score parameters: a-priori values, stability check on development data, freeze before the test keys unlock

**Date:** 2026-11-18 · **Status:** accepted (owner, 2026-11-18) — **values proposed; freeze section completed at
T9.5** · **Task:** T9.5 · **Relates to:** spec [05_score](../specs/05_score.md) §5, §5.2, SC-42, Q11;
[065](065-score-baselines-and-success-criteria.md); handoff §12.4 (l. 977), Correction G.7; [019](019-dev-test-split.md);
review ATK-SC-12

## Context
TPPR reports none of α, β, a, b, λ, w1, w2 (Correction G.7). The handoff asks for weights chosen by a sensitivity
sweep with rank stability reported, "not a tuned optimum". Six keyed development trials are too few to tune on, and
no weight can separate s04 track A from B (equal L and N, both exposed).

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| Grid optimum on development | best development numbers | leaks development knowledge into test results | ATK-SC-12 |
| Nearest grid point fixing a development miss | small move | still tuned | spec Q11 |
| A-priori values, sweep for stability only (**chosen**) | no tuning; explainable | may be far from best | handoff l. 977 |

## Decision
Values: **λ = 1/ln 2** (one technique transition, i.e. two techniques, gives length factor 0.5), **w1 = w2 = w3 = 1/3**, **α = β = 0.5** (ScoreNI weight
0, 062), **a = b = 1**, **ε = 0.01** (TPPR: "a negligible probability for unobserved transitions"). The development
sweep (w on the simplex, step 0.1; λ ∈ {0.5, 1, 1/ln 2, 2, 3, 5}) is reported for stability only and never moves a
value; only the owner may change one, by its own record, before the freeze. If S01 t01 is ingested before the freeze,
it is run and reported first.

## Freeze (completed at T9.5)
| Item | Value |
|---|---|
| Parameters in `src/score/params.py` | *to fill* |
| `order_table.json` SHA-256 | *to fill* |
| H1–H5 numbers and readings | as in 065 |
| Freeze commit | *to fill* |
After this commit no value changes on test data; T10 reports sensitivity around these values only. A test pins
`src/score/params.py` to this table.

## Consequences
- The development ranking is a check, not a target; misses are reported, not fixed by weights.

## Kill criteria
- A value in `src/score/params.py` differs from the freeze table (pin test fails) → the run is invalid.

## Committee answer
**EN:** The base paper does not publish its weights, so we fix simple values in advance: equal weights for the three
terms and a length constant that gives a path with one technique transition half credit. We check on development
data only that rankings stay stable around them, and freeze them before the test answer keys are opened.
**TH:** งานต้นแบบไม่ได้เผยแพร่ค่าน้ำหนัก เราจึงกำหนดค่าง่าย ๆ ไว้ล่วงหน้า คือให้น้ำหนักสามองค์ประกอบเท่ากัน และค่าคงที่ความยาวที่ให้เส้นทาง
ที่มีการเปลี่ยนเทคนิคหนึ่งครั้งได้คะแนนครึ่งหนึ่ง เราตรวจบนข้อมูลพัฒนาเท่านั้นว่าอันดับคงที่รอบค่าเหล่านี้ และล็อกค่าไว้ก่อนเปิดเฉลยชุดทดสอบ
