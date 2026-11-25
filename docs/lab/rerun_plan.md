# Rerun plan for the ×10 trials

**Date:** 2026-11-11 · **Status:** draft for the owner · **Source:** `docs/research/x10_design_validation.md` (commit 509e54c), decisions 029–034. This file is logistics only: what to run, how many, in which folder, in which order, and when to proceed. Scenario designs are in the handoff and the decision records, not here.

## Rule for every item
1. Run **one** trial.
2. Ingest it (`batch` ingest, as for the first ×10, from the source folder named below).
3. Run the x10 validator on it.
4. **Proceed to the remaining trials only if that trial has no FAIL.** If it fails, stop, report to the owner, and do not run more. *(Full reruns, decision 052 item 6: this is the 1-trial gate. A failed `trial_01` stops the scenario until the design is fixed, then `trial_01` is run again as a new gate. A failed later trial does not stop the scenario: see rule 5.)*
5. After the last trial of an item, ingest and validate all of them; the item is done when none has a FAIL. **Partial replacement (S03):** a failing trial is replaced by a new trial numbered `trial_11` onwards in `data/incoming/x10` (decision 029). **S06 (decisions 034 and 052 as amended by 078, 2026-11-26):** new trials in `data/incoming/x10_v2/S06/trial_11` … `trial_20`, all test, minimum 5 accepted; the failed-trial handling below applies, with `trial_11` as the 1-trial gate. **Full reruns (S01, S04, S05, S07):** *(decision 052)* any trial with a FAIL is moved by the owner to `data/incoming/x10_v2_failed/<scenario>/attempt_N/`, its ingested copies are retired with the `retire-failed` tool, and its number is reused (a failed first trial never takes `trial_01`). A later failed trial (not `trial_01`) is retired and its number is run again; stop and ask the owner only if two trials of the same scenario fail in a row (a pass in between resets the count). Trial numbers run in order within each scenario, with no gaps.

Broken trials are archived, never deleted (decision 034).

## Where the new trials go (decision 034)
- **Partial replacement** (S03): `data/incoming/x10/<scenario folder>/trial_11`. Id `s03_t11`.
- **S06** (034/052 as amended by 078, 2026-11-26): `data/incoming/x10_v2/S06/trial_11` … `trial_20` (minimum 5 accepted, all test). Ids `s06_t11` onwards. The planned `x10/S06/trial_11`, `trial_12` are cancelled; no archive of the old S06 trials (the ids do not collide).
- **Full reruns** (S04, S07, S05, S01): a new folder `data/incoming/x10_v2/<scenario folder>/trial_01` … `trial_10` (minimum 5 accepted per scenario, up to 10 if time allows; decision 052). Ids `s04_t01` … `s04_t10`, same for the others. `data/incoming/x10/` is not touched.
- **Failed full-rerun trials** (decision 052): moved by the owner to `data/incoming/x10_v2_failed/<scenario folder>/attempt_N/` (never ingested from there). Their ingested copies are retired by the `retire-failed` tool; the number is reused. Two failed trials in a row in one scenario: stop and ask the owner (decision 052 item 6).
- **Archive of the old trials:** the old broken copies stay in `data/incoming/x10/`. Before the first `x10_v2` ingest, the old S04 and S07 **`t01`–`t10`** copies (not `t00`) in `data/raw/`, `data/processed/`, `data/manifest.csv` and the per-trial outputs that share the id are moved by a script, with hash checks, to `archive_x10_v1/` paths, so the new trials sit on the normal paths (decision 034, amended by 052). The old S05 trials are already in quarantine and do not collide. S01 has no old ×10 trials.

## Before the first run and in every session
- *(Owner 2026-11-12, decision 043 item 11; replaces the session sync of decision 032 item 2.)* **No clock sync:** do not run `w32tm /resync` on any VM before or between trials. A sync would land after ep-01's only offset pairs (its boot logons) and the trial would be refused.
- **Clock readings, every trial, on EP-01, EP-02 and EP-03:**
  1. after the VMs are up and **before the Caldera operation starts**: `w32tm /stripchart /computer:<dc01> /samples:5`, then `tzutil /g`, both appended to `<HOST>_clock.txt` in the trial folder;
  2. **after log collection**: the same two commands, appended to the same file.
  One file per VM per trial (`EP-01_clock.txt`, …), never edited afterwards (spec 08 CO-12). t01 readings are used in step 2; t02–t10 readings are reported only.
- The logs are exported per trial as before (4 hosts × 5 logs, 20 files). Check the file count before leaving the lab.

## Items

| # | Scenario | Trials | Folder | Why | Acceptance check |
|---|---|---|---|---|---|
| 1 | S03 | 1 | `x10` · `trial_11` | replaces `s03_t08` (test) | run 1, ingest, validator: no FAIL |
| 2 | S06 | min 5, up to 10 | `x10_v2` · `trial_11`–`trial_20` | 078: old t02–t08 fail the tail rule, t09/t10 failed the validator (amended 2026-11-26; replaces "2 × `x10` replacements") | run `trial_11` (1-trial gate), ingest `--source x10_v2`, validator `--source x10_v2`, 078 tail check from the coordinator manifest: proceed only if it passes; then `trial_12` onwards |
| 3 | S04 | min 5, up to 10 | `x10_v2` · `trial_01`–`trial_10` | full rerun (all 10 failed b, c, d) | run `trial_01`, ingest, validator: proceed only if it passes; then the other 9 |
| 4 | S07 | min 5, up to 10 | `x10_v2` · `trial_01`–`trial_10` | full rerun (all 10 failed c) | same; the design fix is confirmed by the owner first (decision 033) |
| 5 | S05 | min 5, up to 10 | `x10_v2` · `trial_01`–`trial_10` | rebuild to the t00 design (the first 10 are quarantined, decision 030) | same |
| 6 | S01 | min 5, up to 10 | `x10_v2` · `trial_01`–`trial_10` | build (S01 has only t00, which is excluded) | same; the S01 design is confirmed by the owner first |

### Run order
Trial numbers run in order within each scenario (decision 052). The order **across** scenarios is an operational choice in the lab handoff (round-robin to t05 first); it is not fixed by decision 052 or this file. Suggested default if the handoff says nothing: 1 → 2 → 3 → 4 → 5 → 6 (items 1 and 2 are single replacements of designs that already worked; items 3 and 4 have their designs described; items 5 and 6 are the largest and S01 needs its design confirmed).

Per trial, the rule at the top applies (run one, ingest, validate, proceed only without a FAIL), whatever the cross-scenario order.

### Per-item checklist
For each item, record in `docs/PROGRESS.md`: the trial ids, the date, that each trial folder has the three `<HOST>_clock.txt` files with a start and an end reading (a missing file is noted, not a failure), the validator result of the first trial, the failed attempts moved to `x10_v2_failed`, and the final validator result of the item. Accepted trials are added to `docs/lab/test_set.csv`.

## Development and test mapping (decision 034, amended by 052)
For the full reruns, new `t01` = development and every later accepted trial = test. The test set is every trial that passed the operational checks (ingest ok, validator a–i with no FAIL; never pipeline results) by the **cutoff** (end of the lab session, or a later date the owner names), with a minimum of `t02`–`t05`. The cutoff and the accepted trials are recorded in `docs/lab/test_set.csv` (`trial_id, scenario, split, accepted_date`) and in a `docs/PROGRESS.md` line. The replacement trial `s03_t11` is test. Development stays `t00` for S02–S07 plus `t01` for all seven scenarios; the old S04 and S07 `t01` are invalid and replaced by the new `t01`. *(Amended 2026-11-26, decision 078:)* the test set also follows the 078 tail rule: S02 keeps 7 test trials (t05, t06 excluded), S03 keeps 5 (t03, t04, t10 excluded; t08 failed the validator), and S06's test trials are the accepted x10_v2 `s06_t11` onwards (old t02–t10 excluded; `s06_t01` stays development with a stated limitation). The full-rerun scenarios have 4 to 9 test trials; state n with every figure.

## Work needed before the first `x10_v2` trial is ingested
Planned 2026-11-15 (plan approved by the owner; decision 052). Implementation tasks, tracked in `docs/PLAN.md`:
- The batch ingest takes `x10_v2` as a source, with its own report folder (`out/ingest/x10_v2/`), and refuses a trial id still held by an old copy.
- The validator takes `x10_v2` as a source, with its own output folder (`out/x10_validate_v2/`), and lists `s01` among the expected scenarios. The S01 design table is done (decisions 035 and 036: manual RDP hop with a dump step on ep-01).
- The one-time archive of the old S04 and S07 `t01`–`t10` copies, with hash checks (built and tested on synthetic folders; run once by the owner), and the `retire-failed` tool for failed v2 attempts.
- The ingest keeps each host's `<HOST>_clock.txt` (one file, two readings) as `data/raw/<s>/<t>/<host>/clock.txt` plus a manifest row; a missing file is noted in `ingest.json`, not a failure.

## Open points for the owner
- **S07 and S01** need a confirmed design before their first trial. For S01 the validator design is decision 035 (draft); confirm it and its open points (LSASS dump on ep-01? type 3 + port 3389 accepted as RDP?).
- **Collector sessions and trial windows.** The end-of-trial sessions from 192.168.50.97, .98 and .99 are excluded by the trial window (PLAN T6.4); the IPs are recorded in decision 032. Whether T6.4 also excludes them by source IP is open.
