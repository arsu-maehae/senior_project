# Rerun plan for the ×10 trials

**Date:** 2026-11-11 · **Status:** draft for the owner · **Source:** `docs/research/x10_design_validation.md` (commit 509e54c), decisions 029–034. This file is logistics only: what to run, how many, in which folder, in which order, and when to proceed. Scenario designs are in the handoff and the decision records, not here.

## Rule for every item
1. Run **one** trial.
2. Ingest it (`batch` ingest, as for the first ×10, from the source folder named below).
3. Run the x10 validator on it.
4. **Proceed to the remaining trials only if that trial has no FAIL.** If it fails, stop, report to the owner, and do not run more.
5. After the last trial of an item, ingest and validate all of them; the item is done when none has a FAIL. A failing trial is replaced by a new trial numbered `trial_11` onwards in the same folder (decision 029).

Broken trials are archived, never deleted (decision 034).

## Where the new trials go (decision 034)
- **Partial replacements** (S03, S06): `data/incoming/x10/<scenario folder>/trial_11` (and `trial_12`). Ids `s03_t11`, `s06_t11`, `s06_t12`.
- **Full reruns** (S04, S07, S05, S01): a new folder `data/incoming/x10_v2/<scenario folder>/trial_01` … `trial_10`. Ids `s04_t01` … `s04_t10`, same for the others. `data/incoming/x10/` is not touched.
- **Archive of the old trials:** the old broken copies stay in `data/incoming/x10/`. Before the first `x10_v2` ingest, the old S04 and S07 copies in `data/raw/`, `data/processed/` and `data/manifest.csv` are moved by a script, with hash checks, to `archive_x10_v1/` paths, so the new trials sit on the normal paths (details in decision 034). The old S05 trials are already in quarantine and do not collide. S01 has no old ×10 trials.

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
| 2 | S06 | 2 | `x10` · `trial_11`, `trial_12` | replace `s06_t09`, `s06_t10` (test) | run `trial_11`, ingest, validator: no FAIL; then `trial_12`, same check |
| 3 | S04 | 10 | `x10_v2` · `trial_01`–`trial_10` | full rerun (all 10 failed b, c, d) | run `trial_01`, ingest, validator: proceed only if it passes; then the other 9 |
| 4 | S07 | 10 | `x10_v2` · `trial_01`–`trial_10` | full rerun (all 10 failed c) | same; the design fix is confirmed by the owner first (decision 033) |
| 5 | S05 | 10 | `x10_v2` · `trial_01`–`trial_10` | rebuild to the t00 design (the first 10 are quarantined, decision 030) | same |
| 6 | S01 | 10 | `x10_v2` · `trial_01`–`trial_10` | build (S01 has only t00, which is excluded) | same; the S01 design is confirmed by the owner first |

### Run order
1 → 2 → 3 → 4 → 5 → 6. Items 1 and 2 are single replacements of designs that already worked, so they come first and cost the least. Items 3 and 4 follow, because their designs and fixes are already described in the decision records. Items 5 and 6 come last because they are the largest and S01 needs its design confirmed.

Do not start an item before the previous one is validated, unless the owner says so.

### Per-item checklist
For each item, record in `docs/PROGRESS.md`: the trial ids, the date, that each trial folder has the three `<HOST>_clock.txt` files with a start and an end reading, the validator result of the first trial, and the final validator result of the item.

## Development and test mapping (decision 034)
For the full reruns, new `t01` = development and `t02`–`t10` = test. Replacement trials (`s03_t11`, `s06_t11`, `s06_t12`) are test. Development stays `t00` for S02–S07 plus `t01` for all seven scenarios; the old S04 and S07 `t01` are invalid and replaced by the new `t01`. Each scenario ends with 9 test trials.

## Work needed before the first `x10_v2` trial is ingested
- The batch ingest takes `x10_v2` as a source, with its own report folder (`out/ingest/x10_v2/`).
- The validator takes `x10_v2` as a source, with its own output folder (`out/x10_validate_v2/`), and lists `s01` among the expected scenarios (`X10_SCENARIOS` in `src/x10_validate/cli.py`). The S01 design table is done (decision 035, manual RDP hop; open point: whether S01 includes an LSASS dump).
- The archive step above, with hash checks, run once.
These are implementation tasks and are not part of this plan.

## Open points for the owner
- **S07 and S01** need a confirmed design before their first trial. For S01 the validator design is decision 035 (draft); confirm it and its open points (LSASS dump on ep-01? type 3 + port 3389 accepted as RDP?).
- **Collector sessions and trial windows.** The end-of-trial sessions from 192.168.50.97, .98 and .99 are excluded by the trial window (PLAN T6.4); the IPs are recorded in decision 032. Whether T6.4 also excludes them by source IP is open.
