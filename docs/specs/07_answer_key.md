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
- `hops[]`: `hop_id, protocol (SMB|WinRM|RDP), source_host, target_host, account, move_time_utc, basis (command_names_target|time_account_only), status (confirmed|unconfirmed), agent_event_uids[] (the agent-tree command line), target_event_uids[] (4624, 5140/5145, 7045/4697, WinRM 91 as present), identity_expected (0|1), identity_basis{dump_event_uid, open_session_ids[], dump_time_utc, move_after_dump (bool, with the 5 s tolerance applied)}, handoff_step (stable id from the intended step, not any tool's hop number), handoff_account, agent_account, cmd_credential_account, logon_account, account_mismatch, target_binding, candidate_count, needs_owner_approval, flags[] (source_host_conflict, decision_conflict, weak_exposure_only, handoff_mismatch, attempt_no_target_evidence)`.
- `paths[]`: ordered `hop_id`s per attack path with `role` (attack|attack_pair|distractor). `benign_paths[]`: hops that are not part of the attack (S04 Track A, S06).
- `unconfirmed[]`: every step or hop with `status: unconfirmed` and the reason.
Example hop: `{hop_id: s02-h1, protocol: SMB, source_host: ep-01, target_host: ep-02, account: svc_backup, basis: command_names_target, status: confirmed, identity_expected: 1}`.

## 4. Rules
| ID | Rule | Source |
|---|---|---|
| AK-01 | The record of what Caldera executed is the agent process tree: Sysmon 1 (and Security 4688) whose parent is `splunkd.exe`, plus ALL descendants (any depth, `parent_process_guid`, Sysmon 1 only; the walk stops at the trial run day). 4688 is corroboration only (no ProcessGuid); PowerShell 4104 has no parent chain and NEVER confirms. Agent identity is confirmed first from the data: `splunkd.exe` Sysmon 3 to the Caldera server port 8888 (agent_evidence.md) | decision 020; handoff §19.2 |
| AK-02 | A hop is `basis = command_names_target` only if an agent-tree command line names the target host or IP (name forms `ep-0N`, `endpoint-0N`, FQDN, the lab IP; case-insensitive, boundary-aware; `-enc` payloads decoded for matching only) AND the hop matches an intended step on protocol, source host, target host and time order. Accounts are recorded, not matched: `agent_account` (Sysmon 1 account of the splunkd child), `cmd_credential_account` (parsed from `/user:` or `PSCredential`, before masking), `logon_account` (target 4624); any difference sets `account_mismatch` (S06, S07). The source host must differ from the target host (a self-target such as ep-02 -> 192.168.50.22 is never a hop) and the agent account must be a user, not `system` or a machine account. A command that names a target but has no matching target-side logon is `attempt_no_target_evidence`, not a hop. Only then may the status be `confirmed` | owner instruction 2026-11-10 |
| AK-03 | Target-side events (4624 remote Type 3/10 from the source IP, 5140/5145 by `SubjectLogonId` = 4624 `TargetLogonId`, 4697 by `SubjectLogonId`, 7045 by service binary name = the name in the agent command line, WinRM 91) are collected for a confirmed command by name or by the command's own content (service name, binary file name, share path). Time and account are used only to choose among candidates of that name; `candidate_count` is recorded and the first candidate is never taken silently. Each hop records `target_binding` = `logon_id_artifact` (5145/4697 by SubjectLogonId, WinRM 91 / wsmprovhost by session) | `name_only` | `time_account`; T7 strict truth uses `logon_id_artifact` only. Stray runs (S02 ep-02 `system` agent, own-IP target) are `stray_agent_ep02` and never contribute events to a hop | owner instruction |
| AK-04 | A hop found only by time and account (no agent command line names the target, or the command is not under the agent tree) gets `basis = time_account_only` and `status = unconfirmed`. Never `confirmed`. It is listed in `unconfirmed[]` for review | owner instruction (independence rule) |
| AK-05 | An intended step with no match in the agent tree: `status: unconfirmed`, reason recorded; it is never dropped and never guessed | owner instruction |
| AK-06 | The key never imports `src/log_check` link outputs or any stitcher code, and never reads `out/log_check/**`. A test greps imports, and the key code imports no join helper from the parser or stitcher either; code independence is reviewed by the tester (the check is on imports, not on copied logic) | owner instruction; decision 020 |
| AK-07 | `identity_expected` follows Correction K: 1 if the moving account had a logon session open on the SOURCE host when LSASS was read there (Sysmon 10, `rundll32` → `lsass.exe`, T1003.001) and the move (target 4624 time) is after the dump by ≥ 5 s cross-host (decision 014); else 0, **computed per trial from the DB** (never a constant). The source host is the host holding the agent-tree command; it must equal the host of the target 4624 `source_ip`, else `source_host_conflict`. Dump-before-move is also recorded on the source clock alone (dump versus the agent command on that host) next to the 4624 comparison with the 5 s tolerance; a disagreement is flagged. Open sessions come from 4624 / 4634 on the source host as in decision 004; sessions with no logoff and no boot event are open (`end_unknown` is listed, never dropped). The linked source session is not used (decision 013). `identity_basis` also lists each open session's `logon_type` and `exposure_strength` (strong = types 2, 7, 10, 11, 4, 5; weak = type 3), `end_unknown_ids[]`, and the dump used; `weak_exposure_only` is flagged when only type 3 sessions were open (the value stays Correction K). The dump is on the hop's SOURCE host, nearest before the move (S05 hop 2 uses the ep-02 dump; S07 records which of the two ep-01 dumps). Account names are normalised (`LAB\x` = `x`, case-insensitive); machine accounts are not user accounts | CLAUDE.md Identity; decisions 013, 014, 018 |
| AK-08 | S04 Track A: `identity_expected = 1` per decision 018 (admin_it had an open session on ep-01 at the dump). The value is computed (AK-07) and compared with 018: expected 1; any deviation raises `decision_conflict` (018's kill criterion). The source session behind it (desktop 0xd6398 vs agent 0x17b18) is chosen from the evidence (which session ran a command naming ep-02, and which 7045/5145 tie to it) and flagged `needs_owner_approval`. Track A is not under splunkd, so by owner rule it stays `unconfirmed`; the key records `proposed_role: benign`, `session_id`, `session_logon_type`, `splunkd_ancestor: false` for review | decision 018; owner instruction |
| AK-09 | S06: no dump on any host (decision 017) → expected: every hop 0, all hops `benign_paths`; computed per trial as in AK-07, and a dump found in an S06 trial raises `decision_conflict` (017's kill criterion) | decision 017 |
| AK-10 | LSASS-dump edges are part of the key (`kind: lsass_dump`, at least one rundll32 -> lsass record with a domain SourceUser is a dump, records within 1 s are one dump and a single surviving record still counts), with the dump host, time and Sysmon 10 uids | handoff §21.5 |
| AK-11 | S07: key follows the data for accounts (both paths use the account the data shows; handoff item 0d); the handoff's `svc_sql` is recorded as `handoff_account` with a mismatch note | handoff l.1244, l.1933 |
| AK-12 | The key window is built from ALL steps, confirmed and unconfirmed, `[first − 60 s, last + 300 s]`, `source = key`, and is used only to report where events fall; evaluation covers the whole run-day trial (T7.6/T10 decide). Steps and benign hops outside the window are listed with counts, and the window is compared with the provisional one so a shrink is visible (WN-05) | decision 012, WN-05 |
| AK-13 | Command lines in drafts are masked as in LC-13 (`/user:` value, `-Password`, `/p:`, `$env:*PW*`) | LC-13 |
| AK-14 | The helper writes only under `ground_truth/drafts/`; it refuses a path under `ground_truth/approved/` and never writes to a DB (hash before = after) | CLAUDE.md data rules |
| AK-15 | Existence check (5.5, separate script `src/answer_key/verify.py`): every `event_uid` in a draft exists in `events_dedup` of the trial DB; event id, host and time agree with the key record; each lies in the key window; counts per kind are reported. It reads only the DB and the draft, and shares no code with the builder except the DB opener. The draft stores `db_sha256` and a content key (host, channel, event_id, record id, time) next to each uid; verify.py rejects a key whose hash differs. A negative-control test (an existing but wrong uid) must be detected, so the check is not tautological | PLAN 5.5; independence |

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
| S02 stray ep-02 `system` run (own-IP target, stray 7045 and 4624) | s02 t00, maybe s04 t00 | `stray_agent_ep02`; exactly one confirmed S02 hop; stray 7045/4624 not in `target_event_uids`; stray dump not used for identity | AKT-15 |
| Depth-3 agent chain (`cmd /c` wrapper); 4104 alone | synthetic DB copy | found at depth 3; 4104 alone gives `time_account_only` | AKT-16 |
| Command naming a target with no 4624 (failed attempt); decode failure; two targets; the source's own name | synthetic | `attempt_no_target_evidence`; `decode_failed` -> unconfirmed; no silent first pick | AKT-17 |
| Tampered DB: delete Track A's ep-01 4624 / insert a dump into S06 | temp copy | identity flips with `decision_conflict` | AKT-18 |
| Dump shifted so the move is at dump-4 s / dump-6 s | synthetic (t00 gaps >= 38 s never test it) | 1 with `order_within_tolerance` / 0 | AKT-19 |
| S07 two hops, one source session | s07 t00 | two hops, distinct 4624 logon ids and service names (XferService, SyncService); not merged | AKT-20 |
| Re-ingest in a different file order | synthetic | verify.py rejects the old key by hash | AKT-21 |

## 7. Acceptance tests
Tests are written from this spec, not from the code (tester). On `data/sample/` (S02, S04, S05 t00) plus s06/s07 t00 DBs: every hop has a `basis`; a `time_account_only` hop is never `confirmed`; the builder module imports nothing from `log_check`; S04 Track A `identity_expected = 1`; S06 all hops 0; every event_uid in each draft exists (AK-15); output only under `ground_truth/drafts/`; DB hash unchanged.

## 8. OPEN questions
| Question | Options | Needs council? |
|---|---|---|
| S04 Track A source session (desktop 0xd6398 vs agent 0x17b18) | by evidence at 5.4; identity value is 1 either way (decision 018) | no; owner approval |
| S03 and S05 hop 2 source host per handoff (EP-02 -> EP-03) vs the agent tree | decided from data at 5.4; the handoff value is kept as `handoff_mismatch`, never overwritten | no |
| S04 Track A and the background admin_it SMB logons (S04/S05/S06/S07 h1) are not under splunkd, so `unconfirmed` is neither attack nor benign. Allow a separate status `confirmed_benign` (basis `manual_session_command`: interactive session, command names the target, no splunkd ancestor) and `benign_background`? Evaluation policy: attack-confirmed = positive, benign = negative, `time_account_only` excluded and counted | keep the owner rule (`unconfirmed`, with `proposed_role`) or add the status | owner decides at the stop |
| T7.6 reports WinRM tier A (port join, independent of the key's command evidence) apart from tier B (SMB command line); tier B is agreement with the command-line rule, never accuracy | state in the T7.6 spec and the report | no |
| S07 second account | follows data (handoff 0d) | no |
| Caldera ability/adversary definitions and result files | added later as a cross-check only (TODO in PROGRESS.md) | no |

## 9. Out of scope
Linking (T7), gate rules (T6), scoring, test keys (5.6), the lock tag (5.7). Keys for t01 follow when those trials are ingested.
