# Stage spec: 01_normalise_fixes

**Owner:** stage owner (the user) · **Status:** revised 2026-11-10; owner approved the attacker findings (NF-11 to NF-20) · Builds on `src/parsing_normalization` (reviewed 2026-11-09). Old `full_import.py` and its 7 tests stay untouched; the new code is `evtx_pipeline/trial_import.py` beside them.

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
| NF-03 | `source_port` aliases include `IpPort` (4624/4625/4648). A port of 0 is stored as 0 but is **never a link key**: any join on ports requires port > 0 | Review fix 2 (`normalize.py:316`); S01 EP-02: 4 of 7 remote 4624 rows (NTLM) have IpPort 0 (erratum 2026-11-10) |
| NF-04 | New column `account_name` = bare username, lowercase: strip `DOMAIN\` and `@REALM`; **keep a trailing `$`** on machine accounts; keep `domain` separate; keep the original in `account` | Review fix 3 |
| NF-05 | Read Sysmon 10 `SourceUser` (and `TargetUser`) into subject/target account | Review fix 3 |
| NF-06 | Do not fall back to the XML `Execution ProcessID` for Security, System and WinRM channels | Review fix 6 (`normalize.py:322`) |
| NF-07 | View `events_display` adds `printf('0x%x', …)` hex for subject_logon_id, target_logon_id, session_id | D1 |
| NF-08 | View `events_dedup` keeps one row per `duplicate_content_sha256`; the survivor is chosen by NF-19 (lowest `source_relative_path`, `source_line`), not by event_uid. The digest covers `system` + `event_data` + `user_data` (so it includes `Computer`) and not the host folder: identical payload with the same Computer in two folders counts as one event (accepted; strict xfail in `test_trial_import.py`) | Review fix 5 |
| NF-09 | Analysis DB keeps only `RELEVANT_EVENT_IDS` plus Security 4634/4647 logoffs (session end) and 4688 if present; plus the **log-state events** Security 1102 and System 104 (log cleared) and System 6005, 6006, 6008, 41, 1074 (start, stop, unexpected shutdown, restart), decision 004. `raw_event` is stored as **NULL**; raw stays in the JSONL; new column `source_line` (1-based line in the JSONL file) plus `source_relative_path` is the pointer; `raw_event_sha256` stays | SQLite size (17.4 GB for 85 files) |
| NF-10 | Host names in one style, all lowercase: `dc01`, `ep-01`, `ep-02`, `ep-03`. The host set lives in one constant | Review fix 8; T1 layout |


## 4b. Rules added after the attacker review (owner approved 2026-11-10)
| ID | Rule | Source |
|---|---|---|
| NF-11 | **Logon-ID column chosen by event ID**: `session_id` = TargetLogonId for 4624/4634 and for 4647 (real 4647 events carry only TargetLogonId; SubjectLogonId is the fallback); SubjectLogonId for 4648/4672/4688/5140/5145; LogonId for Sysmon 1; NULL for events with no session. A logon id of `0x0` is stored as **NULL** in `session_id`, `subject_logon_id`, `target_logon_id`, `target_linked_logon_id`. (Ports differ: decision 005) | Attacker 1; JSONL s01_t00 dc01 line 2 (4688: Subject 0x5f3f3, Target 0x0); tester: s01_t00 ep-01 security line 121 (4647 has TargetLogonId 0x62f43 only) |
| NF-12 | New column `target_linked_logon_id` (integer) from 4624 `TargetLinkedLogonId` (elevated twin session) | Attacker 3 |
| NF-13 | `predefined_session` is set only for 4624/4634/4647/4648/4672, from the logon id (996 to 999) or a predefined account name (incl. `nt authority\anonymous logon`); never from the process owner of Sysmon 1/3/10/11 | Attacker 2 |
| NF-14 | New typed columns: Sysmon 3 `initiated` (1/0); Sysmon 10 `source_image`, `granted_access`, `target_process_guid`. Sysmon `LogonGuid` goes to new column `sysmon_logon_guid`, NOT to `logon_guid` (`logon_guid` = Security 4624/4769 only). Sysmon 1/3/11 `User` fills `subject_account` and `account_name` | Attacker 4; Correction I |
| NF-15 | Host rules: host = `<host>` folder (must be in the host set, else the import fails); `Computer` goes to `export_host`; `source_host` and `destination_host` are lowercased by the same function; a CLI scenario or trial that disagrees with the folder fails the import | Attacker 5 |
| NF-16 | `raw_event` is NULL: the new trial schema relaxes the `NOT NULL`/`json_valid` constraint (old schema untouched). `raw_event_sha256` = sha256 of the canonical (sort_keys, compact) JSON of the Phase 1 line. `source_files` stores the JSONL path and its sha256. `source_line` counts physical lines split on `\n` only. `field_values_json` stays | Attacker 6, 11 |
| NF-17 | Accounting is **counted independently, never subtracted**: per source file store emitted (from the manifest), lines read, kept, excluded_not_relevant, excluded_bad_event_id, blank_lines; abort if sums differ from the manifest or if `parse_errors.jsonl` is non-empty; a kept row with NULL `timestamp_utc` fails the import | Attacker 7, 11 |
| NF-18 | `domain` as given; new `domain_short` = first label before `.`, lowercase (`LAB.LOCAL` gives `lab`); for Sysmon `User`/`SourceUser` the `DOMAIN\` prefix fills `domain`/`domain_short` before it is stripped; `machine_account` is derived from `account_name` ending in `$` | Attacker 8 |
| NF-19 | `events_dedup` survivor = lowest (`source_relative_path`, `source_line`); near-duplicates (same host/channel/event_id/record_id, different payload) are listed in `duplicate_events` but kept in the view; the dedup count is not part of the accounting | Attacker 10 |
| NF-20 | `events_display` shows NULL for NULL ids (no `0x0`); readers of `source_line` iterate lines by `\n` only | Attacker 11 |

Not done in this stage: clock-skew offsets, port-reuse handling (stitching tests). Known gaps (fact-check): `session_id` is NULL for 4625, 4697, 4776, 4778/4779 (their ids stay in `subject_logon_id`/`target_logon_id` or `field_values_json`); for 4648 `account_name` is the account whose credentials were used, the process owner is in `subject_account`; for 4688 `process_id` is the creator's PID (`NewProcessId` is not in `process_id`).

## 4c. Rules added after the stage review (attacker re-check, 2026-11-10; additions only, no owner rule changed)
| ID | Rule | Source |
|---|---|---|
| NF-21 | WinRM 91: parse `resourceUri` of the form `... (DOMAIN\user clientIP: a.b.c.d)` into `account_name`, `domain`, `domain_short` and `source_ip` (the original string stays in `field_values_json`). `clientIP` may be IPv4 or IPv6; an IPv6 zone id (`%4`) is stripped before normalising (s05_t00 ep-03 winrm line 1856: `fe80::6577:2c72:f5c8:1b99%7` gives `fe80::6577:2c72:f5c8:1b99`); the account is parsed even if the address cannot be | Review N2; s05_t00 ep-02 winrm line 1525 |
| NF-22 | Security 5145: new column `relative_target_name` (RelativeTargetName); `share_path` stays ShareLocalPath | Review N3; s04_t00 ep-02 security line 5839 |
| NF-23 | New column `event_utc` = Sysmon `UtcTime` (normalised like `timestamp_utc`) for Sysmon rows, equal to `timestamp_utc` for every other row. `timestamp_utc` stays the EVTX record time (ordering, dedup). Measured gap `timestamp_utc - event_utc` over Sysmon rows (2026-11-10): dc01 and ep-01 always 0 to 60 s (max 28.2 s); ep-02 is 0 to 60 s in s01, s02, s04 and s05 (max 13.8 s) but has 12 and 14 rows over 60 s in s06 and s07 (max 7,341 s); only ep-03 has negative gaps (s01: 184 rows, min -26.3 s; s03, s05, s06: 46 rows, min -11.5 s) and 114 rows over 60 s in s03, s05, s06 (max 59,944.6 s). Expected cause, to be measured in T4: clock steps on the VMs hosted on VMware. The stitcher must not assume a small fixed gap | Review N4; s02_t00 ep-02 sysmon line 214 (1.96 s), s05_t00 ep-02 sysmon line 107 (6.8 s) |
| NF-24 | Security 4688: `process_id` = NewProcessId (the new process), `parent_process_id` = ProcessId (the creator). Other events keep today's meaning | Review N5; s02_t00 ep-02 security line 8 (new 0x700, creator 0x27d8) |
| NF-25 | Security 4778/4779: `session_id` from `LogonID` | Review N9 |
| NF-26 | Publish: after the rename, `PRAGMA journal_mode` of the published file must be `delete` (else fail and remove it); `trial_run.status = 'complete'` is the readiness flag; the JSON report is written before the rename | Review N10 |

Recorded, not done in this stage: (N1) each DB holds the whole campaign history of its hosts, so the trial window must be applied in the stitch stage from answer-key start/end times (T5/T6); (N7) the importer cannot tell that an expected host/channel file is missing, `docs/data_inventory.md` is the expectation list; (N8) `normalization_issues` are not written to `normalization_errors`; (N6) see known gaps above.

## 5. Parameters
None. CLI: `python -m evtx_pipeline.cli import-trial --jsonl <dir> --scenario s02 --trial t00 --database <path>`.

## 6. Edge cases
| Case | Where | Expected | Test |
|---|---|---|---|
| 4769 TargetUserName `svc_backup@LAB.LOCAL` vs 4624 `svc_backup` + `LAB` | all Kerberos hops | same `account_name` = `svc_backup` | NF-T04 |
| Machine accounts `EP-02$` | 4624 TargetUserName; 4769 TargetUserName `ep-02$@LAB.LOCAL` | `machine_account = 1`, `account_name = ep-02$`. For 4769 the flag follows the requesting account; the service is in `service_name` | NF-T05 |
| Duplicate export files | trial 1 (§21.8) | appear once in `events_dedup` | NF-T08 |
| 4624 with IpPort `0` | Kerberos logons | `source_port = 0`; never used as a join key | NF-T03 |
| Host from `<host>` folder vs `Computer` field (`WIN-…` default names) | s01 ep-03 System/WinRM | host = folder name; the raw computer name stays in `export_host` | NF-T10 |
| Same bytes in two scenarios (s01 and s02 dry runs) | t00 | two separate DBs; no cross-DB merge | NF-T11 |

## 7. Acceptance tests
- Unit: one real example per event type (4624, 4769, 4768, Sysmon 1/3/10/11, 7045, 5145, WinRM 91, PS 4104) → expected column values.
- Sample: S02, S04 and S05 **t00** import with row counts equal to their manifests (kept + excluded = emitted); `log-check s02_t00` items 2 and 4 show IpPort populated and SMB port matches.
- Logoff events 4634/4647 must be kept: they are needed to know when a session ended (identity, Correction K).
- `events_dedup` row count ≤ `events` row count; `raw_event` is NULL in every row and every row has a `source_line`.
- NF-11: the 4688 on s01_t00 dc01 JSONL line 2 gives `session_id = 0x5f3f3`; a Kerberos 4624 gives `subject_logon_id` NULL; no row has 0 in any logon-id column. NF-13: a Sysmon 3 SMB row with `User = NT AUTHORITY\SYSTEM` gives `predefined_session = 0`; a 4624 with TargetLogonId 0x3e7 gives 1. NF-15: a record with Computer EP-01 in folder ep-02 gives host ep-02. NF-17: a JSONL with one bad event id, one blank line and one irrelevant id reconciles, and the import exits non-zero if totals differ.

## 8. Settled questions
| Question | Answer |
|---|---|
| Keep 4688 (Security process creation)? | Keep if the data-checker finds it in Security (owner, 2026-11-09). Decision record. |
| One DB per trial or per scenario | Per trial. |
| Port 0 | Stored as 0; link key only if port > 0 (owner). |
