# Stage spec: 07_answer_key

**Owner:** stage owner (the user) · **Status:** draft for attacker/fact-check review (2026-11-10) · Task T5 (5.1, 5.2, 5.5)

## 1. Purpose
Build, from the saved logs only, a draft answer key per development trial: what the Caldera agent executed, which target-side events each cross-host move produced, and the expected identity value per hop. The key is evidence for evaluation (T7.6, T9, T10); it must not be derived from the stitcher or from `log_check` link results (decision 020, provenance).

## 2. Input contract
- Trial DB `data/processed/<scenario>_<trial>.sqlite3`, opened read-only, view `events_dedup` only. Columns: `event_uid, host, channel, event_id, event_utc, timestamp_utc, account_name, subject_account, subject_logon_id, target_logon_id, logon_type, authentication_package, source_ip, source_port, image, parent_image, process_guid, parent_process_guid, process_id, command_line, destination_ip, destination_port, initiated, source_image, target_image, granted_access, service_name, service_image_path, share_name, relative_target_name, powershell_host_application`.
- Intended steps `src/answer_key/intended_steps.yaml`: per scenario, hand-written from handoff_18.md §19.2, §19.4, §21.5 (steps, agent account, protocol, source/target host, expected service name). Each entry cites its handoff line. Anything the handoff states only as "design" is marked `design_only`.
- Agent evidence `docs/research/agent_evidence.md` (T5 step 1): the agent image `C:\Users\Public\splunkd.exe`, its Caldera server and port.
- Provisional window `docs/research/provisional_windows.csv` (decision 012) — only to bound the search; never to decide that an event is part of the attack.
- NOT read: `out/log_check/**`, any stitch output, `src/log_check` link functions.

## 3. Output contract
`ground_truth/drafts/<trial_id>.yaml` (never `approved/`). Top level: `trial_id, scenario, status: draft, provenance: "log-based, agent process tree (decision 020)", db_sha256, window:{start_utc,end_utc,source}, agent:{image, server_ip, server_port, accounts[]}, steps[], hops[], paths[], benign_paths[], unconfirmed[], open_points[]`.
- `steps[]`: `step_id, kind (agent_start|lsass_dump|move|service_exec|benign), host, time_utc, account, status (confirmed|unconfirmed), source (agent_tree|target_side), event_uids[], note`.
- `hops[]`: `hop_id, protocol (SMB|WinRM|RDP), source_host, target_host, account, move_time_utc, basis (command_names_target|time_account_only), status (confirmed|unconfirmed), agent_event_uids[] (the agent-tree command line), target_event_uids[] (4624, 5140/5145, 7045/4697, WinRM 91 as present), identity_expected (0|1), identity_basis{dump_event_uid, open_session_ids[], dump_time_utc, move_after_dump (bool, with the 5 s tolerance applied)}, handoff_step (id of the intended step matched)`.
- `paths[]`: ordered `hop_id`s per attack path with `role` (attack|attack_pair|distractor). `benign_paths[]`: hops that are not part of the attack (S04 Track A, S06).
- `unconfirmed[]`: every step or hop with `status: unconfirmed` and the reason.
Example hop: `{hop_id: s02-h1, protocol: SMB, source_host: ep-01, target_host: ep-02, account: svc_backup, basis: command_names_target, status: confirmed, identity_expected: 1}`.

## 4. Rules
| ID | Rule | Source |
|---|---|---|
| AK-01 | The record of what Caldera executed is the agent process tree: Sysmon 1 (and Security 4688) whose parent is `splunkd.exe`, plus descendants one level down by `parent_process_guid`, plus PowerShell 4104 in the same session. Agent identity is confirmed first from the data: `splunkd.exe` Sysmon 3 to the Caldera server port 8888 (agent_evidence.md) | decision 020; handoff §19.2 |
| AK-02 | A hop is `basis = command_names_target` only if an agent-tree command line names the target host or IP (name forms `ep-0N`, `endpoint-0N`, FQDN, the lab IP; case-insensitive, boundary-aware; `-enc` payloads decoded for matching only) AND the hop matches an intended step (same protocol, source host, target host, account family). Only then may the status be `confirmed` | owner instruction 2026-11-10 |
| AK-03 | Target-side events (4624 remote Type 3/10 from the source IP, 5140/5145 by `SubjectLogonId` = 4624 `TargetLogonId`, 4697 by `SubjectLogonId`, 7045 by service binary name = the name in the agent command line, WinRM 91) are collected for a confirmed command by name or by the command's own content (service name, binary file name, share path). Time and account are used only to choose among candidates of that name | owner instruction |
| AK-04 | A hop found only by time and account (no agent command line names the target, or the command is not under the agent tree) gets `basis = time_account_only` and `status = unconfirmed`. Never `confirmed`. It is listed in `unconfirmed[]` for review | owner instruction (independence rule) |
| AK-05 | An intended step with no match in the agent tree: `status: unconfirmed`, reason recorded; it is never dropped and never guessed | owner instruction |
| AK-06 | The key never imports `src/log_check` link outputs or any stitcher code, and never reads `out/log_check/**`. A test greps imports | owner instruction; decision 020 |
| AK-07 | `identity_expected` follows Correction K: 1 if the moving account had a logon session open on the SOURCE host when LSASS was read there (Sysmon 10, `rundll32` → `lsass.exe`, T1003.001) and the move (target 4624 time) is after the dump by ≥ 5 s cross-host (decision 014); else 0. Open sessions come from 4624 / 4634 on the source host as in decision 004; sessions with no logoff and no boot event are open (`end_unknown` is listed, never dropped). The linked source session is not used (decision 013) | CLAUDE.md Identity; decisions 013, 014, 018 |
| AK-08 | S04 Track A: `identity_expected = 1` per decision 018 (admin_it had an open session on ep-01 at the dump). The source session behind this is chosen from the evidence and flagged `needs_owner_approval` (open point) | decision 018; owner instruction |
| AK-09 | S06: no dump on any host (decision 017) → every hop `identity_expected = 0`; all hops are `benign_paths` | decision 017 |
| AK-10 | LSASS-dump edges are part of the key (`kind: lsass_dump`, one dump = a 0x1410/0x1fffff pair within 1 s, E3), with the dump host, time and Sysmon 10 uids | handoff §21.5 |
| AK-11 | S07: key follows the data for accounts (both paths use the account the data shows; handoff item 0d); the handoff's `svc_sql` is recorded as `handoff_account` with a mismatch note | handoff l.1244, l.1933 |
| AK-12 | The key window is `[first confirmed step − 60 s, last confirmed step + 300 s]` for evaluation, `source = key`; it replaces the provisional window (WN-05). Steps outside it are listed | decision 012, WN-05 |
| AK-13 | Command lines in drafts are masked as in LC-13 (`/user:` value, `-Password`, `/p:`, `$env:*PW*`) | LC-13 |
| AK-14 | The helper writes only under `ground_truth/drafts/`; it refuses a path under `ground_truth/approved/` and never writes to a DB (hash before = after) | CLAUDE.md data rules |
| AK-15 | Existence check (5.5, separate script `src/answer_key/verify.py`): every `event_uid` in a draft exists in `events_dedup` of the trial DB; event id, host and time agree with the key record; each lies in the key window; counts per kind are reported. It reads only the DB and the draft, and shares no code with the builder except the DB opener | PLAN 5.5; independence |

## 5. Parameters
| Name | Value | Why | Sensitivity test? |
|---|---|---|---|
| `KEY_MARGIN_BEFORE_S` / `KEY_MARGIN_AFTER_S` | 60 / 300 | cover agent poll lag (S07 gap ~110 s) and late 7045 | report steps found outside |
| `CROSS_HOST_TOL_S` | 5 | decision 014 | compare identity at 0 and 5 s |
| `DUMP_PAIR_S` | 1 | E3 pairing | no |
| `CMD_TARGET_WINDOW_S` | 120 before / 300 after a target 4624 when choosing among same-name candidates | handoff §19.4 S07 gap | list counts |

## 6. Edge cases (from attacker review)
| Case | Where it occurs | Expected behaviour | Test ID |
|---|---|---|---|
| A hop with a 4624 and matching account but no agent command naming the target | S02–S07: hops the agent did not name (e.g. IP `-`) | `time_account_only`, `unconfirmed` | AKT-04 |
| `192.168.50.2` vs `192.168.50.22` | any | boundary-aware name match | AKT-02 |
| Encoded command names the target | S05/S06 WinRM | decoded for matching only | AKT-02b |
| Two services with one binary name on one host | S07 | disambiguated by name and session, else `unconfirmed` | AKT-03 |
| Agent account differs from the handoff table | S06 (svc_backup agent, admin_it credentials), S07 | record the data; `handoff_account` note | AKT-11 |
| Dump pair counted twice | all dumps | one dump per 1-s pair | AKT-10 |
| VBoxService / svchost lsass access | all hosts | never an anchor (E1, E2) | AKT-10b |
| A key hop outside the window | any | listed in `unconfirmed[]`, not silently kept | AKT-12 |
| Draft path is under `approved/` | misuse | refuse | AKT-14 |

## 7. Acceptance tests
Tests are written from this spec, not from the code (tester). On `data/sample/` (S02, S04, S05 t00) plus s06/s07 t00 DBs: every hop has a `basis`; a `time_account_only` hop is never `confirmed`; the builder module imports nothing from `log_check`; S04 Track A `identity_expected = 1`; S06 all hops 0; every event_uid in each draft exists (AK-15); output only under `ground_truth/drafts/`; DB hash unchanged.

## 8. OPEN questions
| Question | Options | Needs council? |
|---|---|---|
| S04 Track A source session (desktop 0xd6398 vs agent 0x17b18) | by evidence at 5.4; identity value is 1 either way (decision 018) | no; owner approval |
| S03 and S05 hop 2 source host per handoff (EP-02 → EP-03) vs the agent tree | decided from data at 5.4 | no |
| S07 second account | follows data (handoff 0d) | no |
| Caldera ability/adversary definitions and result files | added later as a cross-check only (TODO in PROGRESS.md) | no |

## 9. Out of scope
Linking (T7), gate rules (T6), scoring, test keys (5.6), the lock tag (5.7). Keys for t01 follow when those trials are ingested.
