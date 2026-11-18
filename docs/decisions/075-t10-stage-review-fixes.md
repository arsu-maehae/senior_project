# 075 — T10 (development part) stage-review fixes: S06 by scenario id, one H5 function, chance flag, dry-run isolation

**Date:** 2026-11-18 · **Status:** accepted (stage lead; fixes within approved spec 06 and records 070–074; for owner
review) · **Task:** T10.F · **Relates to:** review ATK-EV-15..25; spec [06_evaluate](../specs/06_evaluate.md);
[072](072-evaluate-t10-readings-and-runner.md), [073](073-evaluate-t10-implementation-readings.md),
[074](074-run-trial-implementation-readings.md)

## Context
The stage review of the built code (2026-11-18) found the following:
- **data-checker:** an independent recomputation from the raw score, stitch and key files matches results.csv and
  rank_totals.csv on every item.
- **fact-checker:** no blocking item. The doc fixes are applied: 072 is marked as a freeze record that narrows 070 item
  4, and 071 names its addition.
- **attacker:** ATK-EV-15..25. One item is blocking before the test run. ATK-EV-15: a keyed trial whose key yields no
  attack path (for example a typo in a role) was treated as an S06 benign trial. It would leave H1–H4 silently and fail
  H5. None of these items changes a development number.

## Options considered → decision
| ID | Finding | Decision |
|---|---|---|
| ATK-EV-15 (blocking) | S06 decided by "no key attack paths" | S06 = scenario id (`s06_` prefix). Evaluate refuses a keyed non-S06 trial with no key attack path, and a keyed S06 trial with any. |
| ATK-EV-16 | rank.md / rank_totals computed H5 over the matched trials only | one shared `rank_report.h5_facts` for rank_totals, rank.md and results. An unmatched key path leaves margin and held empty and gives a reason (new column `s06_reason`). |
| ATK-EV-19 | "held" next to a chance line equal to the observed value | `equals_chance_pos` column = 1 when observed ≤ chance over scored paths at 12 decimals. The results.md verdict cell reads "… — not above chance over scored paths" (development: H1 and H2). |
| ATK-EV-20 | H4/H5 verdicts hide coverage | H4 is `undefined` when no trial has labelled key nodes. The coverage "(k of n attack trials)" and "(n keyed S06 trials)" is shown in the results.md cell. No new threshold. |
| ATK-EV-21 | one H5 reason for different causes | four distinct reasons |
| ATK-EV-22 | 6-decimal display next to a 12-decimal verdict | `observed_12` shown in the results.md tables. Trial counts (`trials_full_above_b0[_labelled]`, `trials_gap_positive`) and the sweep's `s06_held` are compared at 12 decimals. `paired_difference` keeps r12(r12(a) − r12(b)) (073). |
| ATK-EV-23 | forbidden-word scan only on results.md | results.csv is scanned too |
| ATK-EV-17 | the dry run passed files and folders missing from the committed `out/` | `new` is a failure (no allowed list). Every compared folder needs at least one matching file, and the set of compared folders must equal the expected set. |
| ATK-EV-18 | the dry run proved reproducibility, not isolation | perturbation cases: a changed scratch clock file must be refused by gate, and a changed scratch key must change or stop evaluate. The tree check also lists every file under `data/processed/` and `docs/` (name, size, mtime; contents not read). |
| ATK-EV-24 | loose JSON equality | `json.dumps(sort_keys=True)` comparison; timestamp keys accepted only for ISO-8601 UTC values |
| ATK-EV-25 | guards only by convention | `run_trial()` checks the allowlist itself; `--repo` whose `out/` or `data/` resolves into the real repo is refused (unless it is the real repo); the dry run finishes deletion on a second Ctrl-C; a hard kill is stated as a limit |

## Consequences
- Development verdicts are unchanged:
  - H1 held — not above chance over scored paths
  - H2 not held — not above chance
  - H3 not held
  - H4 held (5 of 5 attack trials)
  - H5 held (1 keyed S06 trial)
- The six `ranking` rows of rank_totals.csv are unchanged.
- The "not above chance" flag states openly that on development data the ranking adds nothing over a random order of the
  scored paths, because in 3 of 5 attack trials only the key path is scored.

## Kill criteria
If a test-run key fails the ATK-EV-15 check, the run stops. The key is fixed and re-approved before T5.7, never
patched in code.

## Committee answer
**EN:** The review found that a broken answer key could have been silently counted as a benign trial. We now decide
the benign scenario by its name and refuse any key that has no attack path where one is expected. Every results table
also says when a result is no better than chance.
**TH:** การทบทวนพบว่าเฉลยที่ผิดพลาดอาจถูกนับเป็นการทดลองปกติโดยไม่มีใครเห็น ตอนนี้เราระบุสถานการณ์ปกติจากชื่อ
และปฏิเสธเฉลยที่ไม่มีเส้นทางโจมตีในที่ที่ควรมี และทุกตารางผลบอกด้วยว่าผลใดไม่ดีกว่าการสุ่ม
