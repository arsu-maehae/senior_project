# Stage spec: 00_log_check

**Owner:** stage owner (the user) · **Status:** revised after attacker review (2026-11-10); T4 plan pre-approved by the owner · Task T4

## 1. Purpose
Measure, read-only, which linking and identity evidence exists in one trial database, so the gate (T6) and stitching (T7) are designed on measured evidence. It also proposes a PROVISIONAL, anchor-derived trial window until the T5 answer keys exist.

## 2. Input contract
- One trial DB from T3: `data/processed/<scenario>_<trial>.sqlite3`, opened read-only (`file:…?mode=ro`). Analysis uses the view `events_dedup` (CLAUDE.md data rules). Columns used: `host, channel, event_id, timestamp_utc, event_utc, account_name, domain_short, source_ip, source_port, destination_ip, destination_port, logon_type, authentication_package, logon_guid, target_logon_id, target_linked_logon_id, subject_logon_id, session_id, process_id, process_guid, parent_process_guid, image, command_line, source_image, target_image, granted_access, initiated, service_name, service_image_path, share_name, relative_target_name, event_uid`.
- Optional window file `docs/research/provisional_windows.csv` (`trial_id, start_utc, end_utc, status, anchors, note`); a row there overrides the computed window.
- Optional answer key `ground_truth/approved/<trial_id>.yaml` (none exist yet).

## 3. Output contract
Location `out/log_check/<trial_id>/`:
- `report.json`: `{trial_id, db_path, db_sha256, window:{start_utc,end_utc,status,flags[],clusters[],anchors[]}, checks:{<LC-id>:{result:{…}, status:"OK|PROBLEM|INFO|NOT_MEASURABLE", effect:str, sql:[str]}}}`.
- `report.md`: the check table (check · result · status · effect on stitching or identity), the window warning (WN-03b), then per-check detail.
- `hop_candidates.csv`: one row per (hop instance, candidate source session) from LC-04 and LC-06 (one row with empty candidate when there is none), columns `trial_id, protocol, hop_id, target_host, target_event_uids, target_time_utc, account_name, source_ip, source_port, source_host, method, candidate_count_sessions_before_account, candidate_count_sessions_after_account, candidate_count_rows, time_delta_ms, confidence_tier, candidate_session_id, candidate_account, candidate_logon_type, zero_reason, supporting_event_uids` (CLAUDE.md code rules: method, candidate_count, time_delta_ms, confidence_tier, event_uids).
Example row: `s04_t00,SMB,s04-h2,ep-02,<uids>,2026-09-24T10:57:36.855Z,svc_backup,192.168.50.21,49734,ep-01,cmdline_target,2,1,4,906,B,0x17c46,svc_backup,4,,<uids>`.

## 4. Rules
| ID | Rule | Source |
|---|---|---|
| WN-01 | Run day per scenario (`RUN_DAY`): s01–s04 2026-09-24, s05–s07 2026-10-12 | handoff §19 table, l.1501 |
| WN-02 | Anchors on the run day only: (a) Sysmon 10 with `source_image` ending `rundll32.exe` and `target_image` ending `lsass.exe`; (b) System 7045 / Security 4697 whose `service_image_path` is an `.exe` directly under `C:\Windows\` (not system32, not drivers, not Program Files); (c) WinRM 91 with an `account_name` in `SCENARIO_ACCOUNTS` | T4 anchor survey |
| WN-03 | Anchors are clustered (a gap > `CLUSTER_GAP_S` starts a new cluster); all clusters are reported; the window uses the cluster containing an (a)-type anchor (latest such cluster if several), else the largest cluster. Window = [first anchor − `MARGIN_BEFORE`, last anchor + `MARGIN_AFTER`] on `event_utc`; status `PROVISIONAL`; anchors listed (event_uid, host, time, type). No (a)-type anchor → flag `no_dump` (expected for S06) | owner 2026-11-10; attacker 7 |
| WN-03b | The report states: "anchor-derived window — built from attack signatures; must NOT be used for evaluation (T7.6/T10 use T5 answer-key windows)" | attacker 8 |
| WN-04 | No anchor → window = whole run day, status `RUN_DAY_ONLY`; a row in `provisional_windows.csv` overrides (s01 t00: EP-01/DC01 are S02 exports, decision 001) | decision 001 |
| WN-05 | Answer-key windows (T5) replace provisional ones; the report states which was used | plan T4 |
| LC-01 | Counts by channel and event_id, whole DB and in window; `events` vs `events_dedup` rows | log-check skill 1 |
| LC-02 | Remote 4624 in window: logon_type 3 or 10, `source_ip` not NULL; loopback (`::1`, `127.0.0.1`), link-local (`fe80::`) and lab IPv4 reported separately; per package: count, port > 0, port = 0, valid `logon_guid` | skill 2; NF-03 |
| LC-03 | Kerberos confirmation: remote 4624 (lab IPv4) whose `logon_guid` equals a dc01 4769 `logon_guid` | skill 3; Correction I |
| LC-04 | **SMB per decision 011.** Remote 4624s (lab IPv4, endpoint host, in window) are grouped into one *hop instance* per (host, account_name, source_ip) within `HOP_GROUP_S`. Source host = `HOST_IP` lookup of `source_ip` (unknown → reported). Source candidates = Sysmon 1 and 4688 on the source host with `event_utc` in [t − `CMD_BEFORE_S`, t + `CMD_AFTER_S`] (t = first 4624 of the hop instance; the look-back may go outside the window) whose `command_line` names the target. Name matching is case-insensitive and boundary-aware (`192.168.50.2` must not match `192.168.50.22`; FQDN `ep-02.lab.local` matches `ep-02`); name forms: `ep-0N`, `endpoint-0N`, the target IP. `-enc`/`-EncodedCommand` base64 is decoded (UTF-16LE) for matching only. Sysmon 1 and 4688 for one process collapse on (host, session_id or command_line, \|Δt\| ≤ 2 s); a 4688 with NULL command_line is no evidence. Per hop instance report: `candidate_count_rows`, `candidate_count_sessions` **before** and **after** the account filter (candidate session account = 4624 account), a mismatch table, `time_delta_ms` (command − 4624), and for 0 candidates the reason: (a) no command on the source host in range, (b) commands exist but none names the target, (c) an encoded command could not be decoded. Per candidate session: account, logon type and start of its 4624 on the source host (if any), first command time, predefined (SYSTEM) flag | decision 011; attacker 1–4 |
| LC-04b | Legacy: source Sysmon 3 `image = System`, dest port 445, joined to target 4624 by (ip, port > 0, \|Δt\| ≤ `PORT_JOIN_S`). Expected 0 rows (decision 011) | skill 4 |
| LC-04c | Target side: same-host 5140/5145 with `session_id` = a hop 4624's `target_logon_id`; each 7045/4697 tied to the session whose 5145 `relative_target_name` (ADMIN$ write) ends with the service binary file name; report services matching exactly one session, several, or none; 4697 and 7045 for one service count once (host, service_name, \|Δt\| ≤ 2 s); share of SMB hop instances whose first 4624 has port 0 | attacker 10 |
| LC-04d | Sensitivity: LC-04 session counts (after account filter) at `CMD_AFTER_S` ∈ {10, 30, 300} and `CMD_BEFORE_S` ∈ {30, 120, 300} | attacker 5 |
| LC-05 | RDP: source Sysmon 3 `mstsc.exe` → 3389 joined by (ip, port > 0, \|Δt\| ≤ `PORT_JOIN_S`); target inbound Sysmon 3 dest port 3389 (`initiated = 0`) and remote 4624 type 10 or 3 from the same IP within 5 s of it. No RDP source data in the development set → status `NOT_MEASURABLE`, "until S01 t01" | skill 5; owner 2026-11-10 |
| LC-06 | WinRM: source Sysmon 3 `powershell.exe` → 5985/5986 joined to target 4624 by (ip, port > 0, \|Δt\| ≤ `PORT_JOIN_S`); target WinRM 91 (`account_name`, `source_ip`) within `PORT_JOIN_S` of the 4624; target `wsmprovhost.exe` Sysmon 1 whose `session_id` = 4624 `target_logon_id`; source session = `session_id` of the Sysmon 1 that created the `powershell.exe` (via `process_guid`) | skill 6; NF-21 |
| LC-07 | Sessions: share of remote 4624 (lab IPv4, in window) whose `target_logon_id` appears as a Sysmon 1 or 4688 `session_id` on the same host | skill 7 |
| LC-08 | Dumps: every WN-02(a) Sysmon 10 in window (a 0x1410/0x1fffff pair within 1 s is one dump): time, host, source image, account_name, granted_access. Open sessions on that host at dump time = 4624 (any type) before the dump whose `target_logon_id` has no matching 4634/4647 before the dump; a logoff matches the logon id or its linked id, must be later than that 4624, with no boot event (6005/6006/6008/41/1074) between; sessions starting before the first record of the host or with a 1102/104/boot event between start and dump are `end_unknown`; only sessions started within `SESSION_LOOKBACK_S` before the dump (or `end_unknown`) are listed. Split interactive (2, 7, 10, 11), batch/service (4, 5), network (3). Sessions are listed by host, not by the dumper's process owner | skill 8; Correction K; decision 004; attacker 9 |
| LC-08b | Per dump: every scenario account with an open session on the dump host, its session start and type, and whether that session ran a command in the 10 min after the dump; explicitly answer the S04-A question (admin_it on ep-01 at the S04 dump) | handoff Correction H.2; attacker 9 |
| LC-09 | Clock offset per host vs dc01: for each 4624 on the host whose `logon_guid` equals a dc01 4769 `logon_guid`, delta = 4624 time − 4769 time (ms); report n, p5, p50, p95, min, max; if all endpoint medians agree within 1 s but differ from 0 by > 1 s, flag `dc01_skew_possible`. Cross-channel offset per host: Security 4688 time − Sysmon 1 `event_utc` for the same process (host, 4688 `process_id` = Sysmon 1 `process_id`, same image file name, \|Δt\| ≤ 5 s). Sysmon gap `timestamp_utc − event_utc` per host (min, p50, p99, max, rows > 60 s) | decision 010; t3 findings §5; attacker 5–6 |
| LC-10 | Answer-key anchors: if a key exists, every listed event is present; else `NOT_MEASURABLE`, "no key yet" | skill 9 |
| LC-11 | Every check stores the SQL it ran; the script never writes to the DB (hash before = after); outputs only under `out/log_check/<trial_id>/` | CLAUDE.md |
| LC-12 | Status: `PROBLEM` if a check needed for linking or identity finds no evidence where the expectation table expects some, `OK` if found, `INFO` for descriptive checks, `NOT_MEASURABLE` if the data cannot answer | this spec |
| LC-13 | Command lines in reports and CSVs are masked: the value after `/user:<account> `, after `-Password`, after `/p:` and any `$env:*PW*` expansion shown literally is replaced by `***` | S04 ep-01 command lines contain a lab password |

## 5. Parameters
| Name | Value | Why | Sensitivity test? |
|---|---|---|---|
| RUN_DAY | s01–s04 2026-09-24; s05–s07 2026-10-12 | handoff | no |
| SCENARIO_ACCOUNTS | svc_backup, admin_it, svc_sql | handoff §19 Option D table; S04 ep-01 agents (foothold, foothold_admin, foothold_sql) | no |
| HOST_IP | dc01 192.168.50.10, ep-01 .21, ep-02 .22, ep-03 .23 | observed; LC check verifies each host's own Sysmon 3 `source_ip` | no |
| MARGIN_BEFORE / MARGIN_AFTER | 600 s / 600 s | recon before the dump, cleanup after | counts at 300 s too |
| CLUSTER_GAP_S | 1200 s | separates trials on one run day | no |
| HOP_GROUP_S | 10 s | an SMB client opens several 4624 within seconds (S04: 3 per track) | no |
| CMD_BEFORE_S / CMD_AFTER_S | 120 s / 10 s | command precedes the logon; measured: source commands appear 0.9–1.7 s *after* the target 4624 in S02/S04 (ep-01 clock leads ep-02) | yes, LC-04d |
| PORT_JOIN_S | 5 s | Correction I | no |
| SESSION_LOOKBACK_S | 21600 s | DBs hold days of history | no |
| Expectation table | SMB hops: S02, S04 (×2), S05 hop 1, S07 (×2); WinRM: S03, S05 hop 2; RDP: S01; dumps: all except S06 | handoff §19, §21.5 | no |

## 6. Edge cases (attacker review 2026-11-10 + T4 data survey)
| Case | Where it occurs | Expected behaviour | Test ID |
|---|---|---|---|
| Sysmon 1 + 4688 for one command; cmd/powershell + tool rows from one command | every trial (s02, s04 ep-01) | one candidate session; rows > sessions | LCT-01 |
| Two tracks seconds apart, both naming `\\192.168.50.22` | S04 ep-01 → ep-02 (admin_it 0xd6398 at 10:57:35, svc_backup 0x17c46 at 10:57:37) | 2 sessions before the account filter, 1 after, per hop; mismatch table empty | LCT-02 |
| Command after the target 4624 (clock offset) | S02 (+1.7 s), S04 (+0.9 to +1.1 s) | still a candidate within +10 s | LCT-03 |
| IP prefix false match (`192.168.50.2` vs `.22`) | synthetic | no match | LCT-04 |
| Encoded command naming the target | synthetic | matched after decoding; reason (c) if undecodable | LCT-05 |
| No command names the target | synthetic | reason (b) | LCT-06 |
| Two services 3 s apart on one host | S04 ep-02 HealthAgentSvc / UpdaterService | each tied to one session by 5145 file name | LCT-07 |
| Reused logon id; logoff on the linked id; session from a previous day | synthetic; multi-day DBs | open / closed / end_unknown correct | LCT-08 |
| Dump pair 0x1410 + 0x1fffff | every dump | one dump | LCT-09 |
| Window from benign anchors only | S06 t00 | flag `no_dump` | LCT-10 |
| Earlier trial's anchors on the same run day | s05–s07 (10-12), s03–s04 (09-24) | clusters reported; window from the right cluster | LCT-11 |
| Passwords in command lines | S04 ep-01 | masked in all outputs | LCT-12 |
| Dump as SYSTEM | s02 ep-02 05:41:32 | open sessions listed by host | LCT-13 |
| Caldera agent session owns every command | all Caldera trials (agents as foothold accounts, Option D) | candidate session's own 4624 (type 4 batch for agents) reported, so a shared agent session is visible | LCT-14 |

## 7. Acceptance tests
- Synthetic DB with known rows: each check returns the expected numbers; DB unchanged (hash before/after); edge cases LCT-01 … LCT-14.
- Real t00 runs (S02, S04, S05 in `data/sample/`): reports exist; LC-01 totals equal DB row counts; LC-04b = 0 rows; LC-08 lists the rundll32 dumps (s02 ep-01 05:42:00, s04 ep-01 10:56:56, s05 ep-01 07:09:43 and ep-02 07:11:49); S04 LC-04 gives 2 sessions before / 1 after the account filter for both tracks; data-checker re-derives 5 numbers per trial independently.

## 8. OPEN questions
| Question | Options | Needs council? |
|---|---|---|
| Is the command-line join (LC-04) good enough to link SMB hops? | measure here; decide in council | yes (Correction I council, T4) |

## 9. Out of scope
No linking decisions, no gate triggers, no scoring. Windows are provisional, anchor-derived, and only scope the counts.
