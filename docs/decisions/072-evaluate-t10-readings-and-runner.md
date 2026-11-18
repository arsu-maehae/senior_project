# 072 — T10 development-part readings (spec 06 Q1–Q5) and the per-trial runner's scope

**Date:** 2026-11-18 · **Status:** accepted (owner, 2026-11-18: spec 06 approved as proposed). This is a **freeze record**. Item 1 narrows
070 item 4 ("every metric") in two places: b0's contested reading covers H4 only, and H5 has no contested reading. 070's
kill criteria allow such a change before T5.7 only through a freeze record. Each narrowing leaves out a more lenient
reading, never a stricter one. · **Task:** T10.A ·
**Relates to:** spec [06_evaluate](../specs/06_evaluate.md) §8 Q1–Q5, EV-03/04/06, RT-01..11, RS-02;
[070](070-score-freeze-amendment-readings.md) item 4; [071](071-h4-labelled-recall-denominator.md); review ATK-EV-01..14

## Context
070 adds a "contested" secondary reading for `full`, `b0`, `b1` and `b2`, and a chance line in every table. It says
"every metric" for all four variants. For b0, which has no paths, 065 does not define top-1 or MRR. For H5, which is
one check per S06 trial, taking a subset of attack trials can only raise the lowest key score. The data-checker counted the
contested trials on development data:
- s04_t00 and s07_t00 for `full`/`b1`/`b2`
- all 5 attack trials for `b0`, where every unit scores above 0

Spec 06 also needs a runner per trial. Gate has **no allowlist**, and the t02–t10 DBs already sit in
`data/processed/`. `trial_window` rewrites the whole `data/trial_windows.csv`. The rank outputs carry no `run_info`
hash.

## Options considered
| Q | Option | Pros | Cons |
|---|---|---|---|
| Q1 b0 contested | H4 only, paired on full's contested set (**chosen**) | b0 ranks labelled event units, not paths. 065 defines top-1/MRR over candidate paths matched by node Jaccard, and a unit is not such a path. On development data no unit reaches Jaccard ≥ 0.5 with a key path of 12–40 nodes. | "every metric" in 070 read as "every metric that is defined" |
| | define a b0 top-1 by "unit inside the key path" | a b0 MRR to show | a new metric invented after the freeze |
| Q2 H5 contested | none (**chosen**) | restricting the attack side to a subset can only raise the lowest key score, which is more lenient (ATK-EV Q2) | one fewer table |
| Q3 results input | recompute in memory with all rank checks, refuse if committed rank files differ (**chosen**) | every freshness check of 068/069 applies; no new file format | the ranking is computed twice |
| | new `rank_run_info.json` | read files only | a new artefact and new checks |
| Q4 runner | `src/run_trial` package (**chosen**) | one `python -m` entry like every stage | needs `pip install -e .` once |
| Q5 match reading | node reading for verdicts, hop reading beside (**chosen**) | spec 05 §7.3 names node Jaccard (handoff §14.2) | the two readings give identical values on development data, so a synthetic test must show they can differ |

## Decision
1. **Contested reading**, per 070 item 4 (EV-03/04):
   - Each variant's own contested set is reported.
   - Paired comparisons (H3 full vs b1, H4 full vs b0) use **full's** contested set for both sides.
   - Contested rows never carry a verdict.
   - b0 takes the H4 recall only.
   - H5 has no contested reading.
   - A trial left out because its only positive candidate is a rival is named "uncontested — key path not scored".
2. **Results tables** recompute the ranking in memory and refuse when the committed `rank.csv` / `rank_totals.csv`
   differ ("stale").
3. **Runner scope** (RT-01..11):
   - Steps: gate → stitch → label → score → evaluate (link accuracy, label recall for keyed trials, rank).
   - The allowlist check (`clock_offset.params.DEVELOPMENT_TRIALS`, imported) comes **first**, then a presence check of
     the DB, clock files and window row, which prints the commands that create anything missing.
   - Every stage keeps its own refusals.
   - Exit 0 still needs the step's output files to have been rewritten.
   - The runner never runs `clock_offset` or `trial_window`.
4. **Verdicts** use the node reading and are compared at 12 decimals (RS-09). While `split = development` the column
   is named `dev_check`.

## Consequences
- The contested reading on development data shows the ranking where it can be wrong (2 of 5 trials). It never
  replaces the primary reading.
- The runner is the only guard against a test trial reaching gate. RT-01 is tested with a zero-byte test DB present.
- Processing time per stage comes from the runner's `run_log` (handoff §14.2). It is machine-dependent and kept out of
  results.md, so that file stays deterministic.

## Kill criteria
- If a test-time need appears for a b0 top-1, or for a contested H5, it is post hoc and is reported beside the result.
- If the hop and node readings disagree on any test trial, both are shown, and the verdict keeps the node reading.

## Committee answer
**EN:** We report a second, harder reading over the trials where more than one path scores above zero, because in those trials
more than one path competes for the top. We kept it secondary, gave it no pass or fail, and left out cases where it would
only make a check easier to pass. One command rebuilds a trial, but it refuses any test trial before touching it.
**TH:** เรารายงานการอ่านผลชุดที่สองที่ยากกว่า เฉพาะการทดลองที่มีเส้นทางคะแนนมากกว่าศูนย์เกินหนึ่งเส้น เพราะในกรณีนั้นมีเส้นทางมากกว่าหนึ่งเส้นแข่งกันขึ้นอันดับแรก
เราให้เป็นผลรอง ไม่ตัดสินผ่านหรือไม่ผ่าน และไม่ใช้ในกรณีที่จะทำให้ผ่านง่ายขึ้น คำสั่งเดียวสร้างผลของการทดลองใหม่ได้ แต่ปฏิเสธการทดลองชุดทดสอบก่อนแตะข้อมูลใด ๆ
