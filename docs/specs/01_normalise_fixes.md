# Stage spec: 01_normalise_fixes

**Owner:** <data owner> · **Status:** draft · Builds on `src/parsing_normalization` (reviewed 2026-11-09).

## 1. Purpose
Make the existing parser/normaliser work for all 70 trials and for cross-host linking. Not a rewrite.

## 2. Input contract
Phase 1 JSONL per trial (existing converter output) + its manifest.

## 3. Output contract
One SQLite file per trial: `data/processed/<scenario>_t<NN>.sqlite3`, same `events` schema plus the new columns below,
and two views: `events_dedup`, `events_display`.

## 4. Rules
| ID | Rule | Source |
|---|---|---|
| NF-01 | Add `trial_id` (e.g. `t03`) parsed from the folder name; every row carries scenario_id + trial_id | Review fix 1 |
| NF-02 | Remove hard-coded totals (85 files, 2,981,147 events) and fixed workspace paths; read expected counts from the trial's own manifest; paths from CLI arguments | Review fix 1 (`full_import.py:25–26`, `cli.py`) |
| NF-03 | `source_port` aliases include `IpPort` (4624/4625/4648) | Review fix 2 (`normalize.py:316`) |
| NF-04 | New column `account_name` = bare username, lowercase: strip `DOMAIN\`, `@REALM`; keep `domain` separate; keep the original in `account` | Review fix 3 |
| NF-05 | Read Sysmon 10 `SourceUser` (and `TargetUser`) into subject/target account | Review fix 3 |
| NF-06 | Do not fall back to the XML `Execution ProcessID` for Security, System and WinRM channels | Review fix 6 (`normalize.py:322`) |
| NF-07 | View `events_display` adds `printf('0x%x', …)` hex for subject_logon_id, target_logon_id, session_id | D1 |
| NF-08 | View `events_dedup` keeps one row per `duplicate_content_sha256` (lowest event_uid) | Review fix 5 |
| NF-09 | Analysis DB keeps only `RELEVANT_EVENT_IDS` (+ 4634/4647 logoffs for session end, 4688 if present); raw stays in JSONL; store `source_relative_path` + line number as the pointer | SQLite size (17.4 GB/trial) |
| NF-10 | Host names in one style (all lowercase: `dc01`, `ep-01`) | Review fix 8 |

## 5. Parameters
None.

## 6. Edge cases
| Case | Where | Expected | Test |
|---|---|---|---|
| 4769 TargetUserName `svc_backup@LAB.LOCAL` vs 4624 `svc_backup` + `LAB` | all Kerberos hops | same `account_name` | NF-T04 |
| Machine accounts `EP-02$` | 4769 ServiceName, 4624 | `machine_account = 1`, `account_name = ep-02$` | NF-T05 |
| Duplicate export files | trial 1 (§21.8) | appear once in `events_dedup` | NF-T08 |

## 7. Acceptance tests
- Unit: one real example per event type (4624, 4769, 4768, Sysmon 1/3/10/11, 7045, 5145, WinRM 91, PS 4104) → expected column values.
- Sample: S02 t01 imports with counts equal to its manifest; `log-check s02_t01` items 2 and 4 show IpPort populated and SMB port matches.
- Logoff events 4634/4647 must be kept: they are needed to know when a session ended (identity, Correction K).

## 8. OPEN questions
| Question | Options | Council? |
|---|---|---|
| Keep 4688 (Security process creation)? | keep / drop if Sysmon 1 covers it | no |
| One DB per trial or per scenario | trial (default) / scenario | no |
