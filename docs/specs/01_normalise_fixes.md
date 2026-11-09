# Stage spec: 01_normalise_fixes

**Owner:** stage owner (the user) · **Status:** revised 2026-11-09, approved in advance by the owner; attacker review pending · Builds on `src/parsing_normalization` (reviewed 2026-11-09). Old `full_import.py` and its 7 tests stay untouched; the new code is `evtx_pipeline/trial_import.py` beside them.

## 1. Purpose
Make the existing parser/normaliser work for all 70 trials and for cross-host linking. Not a rewrite.

## 2. Input contract
- EVTX: `data/raw/<scenario>/<trial>/<host>/<channel>.evtx` (T1 layout, `docs/data_inventory.md`).
- Phase 1 JSONL per trial from the existing `convert` command, written to `data/processed/jsonl/<scenario>_<trial>/` with its `manifest.json` (input root passed to `convert` = `data/raw/<scenario>/<trial>`, so a JSONL `relative_path` is `<host>/<channel>.evtx`).
- **Scenario, trial and host come from CLI arguments** (`--scenario s02 --trial t00`) and from the folder `<host>` of `relative_path`. No regex over the path for scenario or trial.

## 3. Output contract
One SQLite file per trial: `data/processed/<scenario>_<trial>.sqlite3` (e.g. `s02_t00.sqlite3`), same `events` schema plus the new columns below, and two views: `events_dedup`, `events_display`. A copy of the S02, S04 and S05 t00 files goes to `data/sample/`.

## 4. Rules
| ID | Rule | Source |
|---|---|---|
| NF-01 | Add `trial_id` (e.g. `t03`) from the `--trial` argument; every row carries `scenario_id` + `trial_id`, and the argument must match the folder name | Review fix 1 |
| NF-02 | Remove hard-coded totals (85 files, 2,981,147 events) and fixed workspace paths from the NEW code; expected counts come from the trial's own `manifest.json`; paths come from CLI arguments. `full_import.py` is left as is | Review fix 1 (`full_import.py:25–26`, `cli.py`) |
| NF-03 | `source_port` aliases include `IpPort` (4624/4625/4648). A port of 0 is stored as 0 but is **never a link key**: any join on ports requires port > 0 | Review fix 2 (`normalize.py:316`); S01 EP-02: 3 of 7 remote 4624 rows have IpPort 0 |
| NF-04 | New column `account_name` = bare username, lowercase: strip `DOMAIN\` and `@REALM`; **keep a trailing `$`** on machine accounts; keep `domain` separate; keep the original in `account` | Review fix 3 |
| NF-05 | Read Sysmon 10 `SourceUser` (and `TargetUser`) into subject/target account | Review fix 3 |
| NF-06 | Do not fall back to the XML `Execution ProcessID` for Security, System and WinRM channels | Review fix 6 (`normalize.py:322`) |
| NF-07 | View `events_display` adds `printf('0x%x', …)` hex for subject_logon_id, target_logon_id, session_id | D1 |
| NF-08 | View `events_dedup` keeps one row per `duplicate_content_sha256` (lowest event_uid) | Review fix 5 |
| NF-09 | Analysis DB keeps only `RELEVANT_EVENT_IDS` plus 4634/4647 logoffs (session end); 4688 is kept if present in Security. `raw_event` is stored as **NULL**; raw stays in the JSONL; new column `source_line` (1-based line in the JSONL file) plus `source_relative_path` is the pointer; `raw_event_sha256` stays | SQLite size (17.4 GB for 85 files) |
| NF-10 | Host names in one style, all lowercase: `dc01`, `ep-01`, `ep-02`, `ep-03`. The host set lives in one constant | Review fix 8; T1 layout |

## 5. Parameters
None. CLI: `python -m evtx_pipeline.cli import-trial --jsonl <dir> --scenario s02 --trial t00 --database <path>`.

## 6. Edge cases
| Case | Where | Expected | Test |
|---|---|---|---|
| 4769 TargetUserName `svc_backup@LAB.LOCAL` vs 4624 `svc_backup` + `LAB` | all Kerberos hops | same `account_name` = `svc_backup` | NF-T04 |
| Machine accounts `EP-02$` | 4769 ServiceName, 4624 | `machine_account = 1`, `account_name = ep-02$` | NF-T05 |
| Duplicate export files | trial 1 (§21.8) | appear once in `events_dedup` | NF-T08 |
| 4624 with IpPort `0` | Kerberos logons | `source_port = 0`; never used as a join key | NF-T03 |
| Host from `<host>` folder vs `Computer` field (`WIN-…` default names) | s01 ep-03 System/WinRM | host = folder name; the raw computer name stays in `export_host` | NF-T10 |
| Same bytes in two scenarios (s01 and s02 dry runs) | t00 | two separate DBs; no cross-DB merge | NF-T11 |

## 7. Acceptance tests
- Unit: one real example per event type (4624, 4769, 4768, Sysmon 1/3/10/11, 7045, 5145, WinRM 91, PS 4104) → expected column values.
- Sample: S02, S04 and S05 **t00** import with row counts equal to their manifests (kept + excluded = emitted); `log-check s02_t00` items 2 and 4 show IpPort populated and SMB port matches.
- Logoff events 4634/4647 must be kept: they are needed to know when a session ended (identity, Correction K).
- `events_dedup` row count ≤ `events` row count; `raw_event` is NULL in every row and every row has a `source_line`.

## 8. Settled questions
| Question | Answer |
|---|---|
| Keep 4688 (Security process creation)? | Keep if the data-checker finds it in Security (owner, 2026-11-09). Decision record. |
| One DB per trial or per scenario | Per trial. |
| Port 0 | Stored as 0; link key only if port > 0 (owner). |
