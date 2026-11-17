# Stage spec: 04_label

**Owner:** <stage owner> · **Status:** **draft (T8.1), not approved.** Candidate rule list written 2026-11-17 before
any rule-hit measurement (§3.1, committed first); measurements §10; reviews pending. · **Last updated:** 2026-11-17

Decisions this spec rests on: Correction G (NodeScore = Sigma rule level), Correction J (no threshold), Correction G.4
(nothing dropped), [019](../decisions/019-dev-test-split.md) (split), [039](../decisions/039-gate-window-input-and-clock.md)
(window), [043](../decisions/043-clock-offset-method.md) (corrected times), [045](../decisions/045-tier-rule-scope.md)
(tier rule scope), [046](../decisions/046-stitch-development-allowlist.md) / [053](../decisions/053-clock-only-retired-development-gate-real-data-switch.md)
(development allowlist). Handoff: §5.5 (technique set), §7.2 (gate rules R1–R8), §10 (labelling), §3.6.5 (SigmaHQ
WinRM rules), §24 item 6 (lock the list before testing; recall check). Open spec 03 question: Q9.

## 1. Purpose
The labeller tags single events with ATT&CK techniques, tactics and a rule level from a **locked list of Sigma
rules**, and joins those tags to the stitcher's path nodes. It adds attributes only: it never adds, removes or
merges an event, hop or path, it orders nothing and it scores nothing (T9 computes NodeScore from the levels).

## 2. Input contract
| Input | What is read | Notes |
|---|---|---|
| Trial DB | `data/processed/<trial_id>.sqlite3`, view `events_dedup`, opened read-only | All events inside the trial window. Hash before = hash after. |
| Stitch outputs | `out/stitch/<trial_id>/path_nodes.csv`, `hops.csv`, `hop_artefacts.csv`, `hop_identity.csv`, `run_info.json` (spec 03 §3) | Node join only. The labels themselves do not depend on them. |
| Gate outputs | `out/gate/<trial_id>/stats.json` (window row, time basis, DB and clock hashes) | Window and corrected time, as the stitcher reads them (spec 03 §2). |
| Clock files | `data/processed/<trial_id>.clock_offsets.csv`, `.clock_changes.csv` | `event_utc_corrected`, `clock_unreliable` through `clock_offset.correct` (CO-09). |
| Rule files | `src/label/rules/*.yml` (Sigma YAML, from 8.2) and `src/label/rules/manifest.csv` | The locked list (§3.1 after owner approval). |

Columns used from `events_dedup`: `event_uid, host, channel, event_id, record_id, event_utc, field_values_json`
(the raw fields every rule reads, lower-case keys, §4 LB-04), plus `account_name` and `machine_account` for the
report only. Rules may read `commandline`, `scriptblocktext`, `contextinfo` and `payload`; **no output contains any
part of them** (LB-09).

- **Ground truth.** `src/label` never opens a path under `ground_truth/`. The recall check (§7, LBA-04) lives in
  `src/evaluate`, which already reads keys.

Refused inputs (stop with an error, write nothing):
- a trial id not in `clock_offset.params.DEVELOPMENT_TRIALS` (046, 053), checked before any file is opened;
- any gate or stitch input file missing; gate `stats.json` `time_basis` not `corrected`;
- the DB SHA-256 differs from gate `stats.json` `db.sha256_after` or from stitch `run_info.json`;
- the window row in gate `stats.json` differs from the trial's row in `data/trial_windows.csv`; the clock files'
  SHA-256 differ from those in gate `stats.json`;
- every input the gate or stitcher refuses (quarantine, CO-17, S01 without offsets), checked with the same shared
  functions;
- a rule file whose SHA-256 differs from `manifest.csv`, a rule in the manifest with no file or the reverse, a rule
  that uses a field, modifier or logsource outside §4 LB-04 / LB-05, or a level outside the Sigma level set.

## 3. Rules list and output contract

### 3.1 Candidate rule list — selected before measurement (2026-11-17)
Selected from SigmaHQ (`github.com/SigmaHQ/sigma`, commit **`54967d64e6dda2b4daa81f47f7a8bf1f591b68a0`**,
2026-11-13, folder `rules/windows/`) and the handoff technique set (§5.5) and gate rules (§7.2). **Selection used
only the rule texts, the handoff and the list of event ids and field names present in the DBs; no rule was run on
any trial before this list was written.** Changes after measurement are listed in §3.2 with their numbers.

Rule ids: `SR-nn` (labelling rules). Level values: informational 0, low 1, medium 2, high 3, critical 4 (locked,
Correction G).

| Rule | Technique (primary) | Other ATT&CK tags of the rule | Source | Title (SigmaHQ id / file) | Event(s) | Level |
|---|---|---|---|---|---|---|
| SR-01 | T1003.001 | – | SigmaHQ | Lsass Memory Dump via Comsvcs DLL (`a49fa4d5-11db-418c-8473-1e014a8dd462`, `process_access/proc_access_win_lsass_dump_comsvcs_dll.yml`) | Sysmon 10 | high |
| SR-02 | T1003.001 | – | SigmaHQ | Potential Credential Dumping Activity Via LSASS (`5ef9853e-4d0e-4a70-846f-a9ca37d876da`, `process_access/proc_access_win_lsass_memdump.yml`) | Sysmon 10 | medium |
| SR-03 | T1003.001 | T1059.001, T1021.006 | SigmaHQ | Remote LSASS Process Access Through Windows Remote Management (`aa35a627-33fb-4d04-a165-d33b4afca3e8`, `process_access/proc_access_win_lsass_remote_access_trough_winrm.yml`) | Sysmon 10 | high |
| SR-10 | T1021.002 | – | SigmaHQ | Access To ADMIN$ Network Share (`098d7118-55bc-4912-a836-dc6483a8d150`, `builtin/security/win_security_admin_share_access.yml`) | Security 5140 | low |
| SR-11 | T1021.002 | – | SigmaHQ | SMB Create Remote File Admin Share (`b210394c-ba12-4f89-9117-44a2464b9511`, `builtin/security/win_security_smb_file_creation_admin_shares.yml`) | Security 5145 | high |
| SR-12 | T1021.002 | – | SigmaHQ | Remote Service Activity via SVCCTL Named Pipe (`586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3`, `builtin/security/win_security_svcctl_remote_service.yml`) | Security 5145 | medium |
| SR-20 | T1570 | – | own | Executable written to an admin share: 5145, `ShareName` ends `ADMIN$` or `C$`, `RelativeTargetName` ends `.exe` / `.dll` / `.ps1` / `.bat` / `.cmd` / `.vbs`, `AccessList` contains WriteData (`%%4417`) | Security 5145 | low (LB-07) |
| SR-30 | T1569.002 | – | own | Service installed (System): 7045, `Provider_Name` = Service Control Manager. Handoff R6 | System 7045 | low (LB-07) |
| SR-31 | T1569.002 | – | own | Service installed (Security): 4697. Handoff R6 | Security 4697 | low (LB-07) |
| SR-40 | T1021.006 | T1059.001 | SigmaHQ | Remote PowerShell Session Host Process (WinRM) (`734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8`, `process_creation/proc_creation_win_winrm_remote_powershell_session_process.yml`) | Sysmon 1, Security 4688 | medium |
| SR-41 | T1021.006 | T1059.001 | SigmaHQ | Potential Remote PowerShell Session Initiated (`c539afac-c12a-46ed-b1bd-5a5567c9f045`, `network_connection/net_connection_win_susp_remote_powershell_session.yml`) | Sysmon 3 | high |
| SR-42 | T1021.006 | T1059.001 | SigmaHQ | Remote PowerShell Session (PS Module) (`96b9f619-aa91-478f-bacb-c3e50f8df575`, `powershell/powershell_module/posh_pm_remote_powershell_session.yml`) | PowerShell 4103 | high |
| SR-50 | T1021.001 | – | own | RDP logon: 4624 `LogonType` = 10. Handoff R5 (the type 3 + port 3389 case is a correlation and stays in the gate / stitcher) | Security 4624 | low (LB-07) |
| SR-60 | T1078 | (tactic tags only) | SigmaHQ | Suspicious Remote Logon with Explicit Credentials (`941e5c45-cda7-4864-8cea-bbb7458d194a`, `builtin/security/win_security_susp_logon_explicit_credentials.yml`) | Security 4648 | medium |
| SR-61 | T1550.002 | – | SigmaHQ | Pass the Hash Activity 2 (`8eef149c-bd26-49f2-9e5a-9b00e3af499b`, `builtin/security/account_management/win_security_pass_the_hash_2.yml`) | Security 4624 | medium |

15 rules, within the handoff ceiling (~15, §10); 1–3 per technique. T1059.001 has no rule of its own: it is a second
tag of SR-03 and SR-40..42 (handoff §3.6.2 "tag both together"); OPEN Q3. SR-60 and SR-61 are the handoff's
supporting signals R3 and R2; their techniques (T1078, T1550.002) are outside the lateral-movement core and T9
decides how its order table treats them (OPEN Q10).

**Considered and not selected (reason, all from the rule text):**
| SigmaHQ rule | Reason |
|---|---|
| `a18dd26b` Potentially Suspicious GrantedAccess Flags On LSASS (medium) | Filters every source image under `\Windows\System32\`, so it cannot fire on a System32 tool reading LSASS; SR-02 covers the generic access-mask case |
| `678dfc63`, `fa34b441` (rules-threat-hunting) | Threat-hunting folder (`detection.threat-hunting`), not detection rules |
| `646ea171` Process Memory Dump Via Comsvcs.DLL (process_creation, high) | Labels the command, not the LSASS access; the Sysmon 10 event is the one identity uses (Correction K); would be a 4th T1003.001 rule |
| `1d61f71d`, `26481afe`, `5e993621` (suspicious service image paths) | Tagged T1543.003 (persistence), path-specific; the handoff maps a remote service install to T1569.002 (R6) |
| `42c575ea` PsExec Service Installation | One tool; SR-30 covers every 7045 |
| `c462f537`, `32d56ea1` (PsExec / Impacket pipes) | Tool-specific named pipes |
| `13acf386` Remote PowerShell Sessions Network Connections (WinRM) | Needs Security 5156, not collected |
| `posh_pc_remote_powershell_session` | Needs PowerShell classic event 400, not collected |
| `0f63e1ef` Admin User Remote Logon | Needs a site-specific admin name pattern |
| `910ab938` Transferring Files with Credential Data via Network Shares | Credential files (T1003.002/.003), not tool transfer |

### 3.2 Changes after measurement
| Rule | Change | Reason | Numbers (§10) |
|---|---|---|---|
| (filled after measurement 4) | | | |

### 3.3 Licence
SigmaHQ rules are released under the **Detection Rule License (DRL) 1.1** (SigmaHQ `LICENSE`, commit above:
"The rules contained in the SigmaHQ repository … are released under the Detection Rule License (DRL) 1.1").
Any SigmaHQ rule file copied into the repo (from 8.2) keeps its `title`, `id`, `author`, `references` and `date`
fields unchanged, and the file and `manifest.csv` carry the DRL 1.1 attribution and the source commit. A copied rule
that is changed (for example a field rename) keeps its `id` in a `related:` entry of type `derived` and gets a new
`id`; the change is stated in the file and in §3.2. Own rules carry `license: own` in the manifest.

### 3.4 Output contract
Location `out/label/<trial_id>/`. Rebuilt on every run. Rows sorted by time, then id. Every file except
`run_info.json` is byte-identical between two runs on the same inputs.

**`event_labels.csv`** — one row per (event, rule) match.
| Column | Type | Meaning |
|---|---|---|
| trial_id, event_uid | text | the representative uid (LB-03) |
| dup_uids | text | the ST-05 near-duplicate copies, `|`-joined; empty if none |
| host, channel, event_id, record_id | text / int | |
| event_utc, event_utc_corrected | text | corrected as spec 08 CO-09 |
| rule_id, rule_title, rule_source, sigma_id | text | `SR-nn`; `sigmahq` / `own`; SigmaHQ id or empty |
| technique, techniques, tactics | text | primary technique (§3.1); all ATT&CK technique tags of the rule; all tactic tags, `;`-joined |
| level, level_value | text / int | Sigma level; 0–4 |
| method | text | `sigma_rule` |
| clock_unreliable | int | as spec 03 ST-02, for the event's host |

**`node_labels.csv`** — one row per row of the stitcher's `path_nodes.csv`, labelled or not.
`path_id, hop_id, role, context, host, event_uid, labelled` (0/1)`, rule_ids, techniques, max_level_value` (empty if
unlabelled).

**`hop_labels.csv`** — one row per hop of `hops.csv`: `hop_id, in_path, n_node_events, n_labelled_node_events,
techniques` (of its node events)`, dump_event_uids` (from `hop_identity.csv`)`, dump_labelled, dump_rule_ids,
dump_max_level_value`. The dump columns show the LSASS reads that identity uses even when they are not path nodes
(OPEN Q1).

**`rules_manifest.csv`** (copy of the input manifest as used): `rule_id, file, sha256, source, sigma_id,
sigma_commit, title, author, license` (`DRL-1.1` / `own`)`, references, technique, techniques, tactics, level`.

**`stats.json`, `report.md`, `run_info.json`** — matches per rule, per technique, per level; labelled events by
channel; events in the window and outside it (counted, never listed); node and hop label counts; rules with no match
in this trial; DB hash before and after; rules manifest hash; parameters.

**No tier columns.** A label row matches one event against one rule and links no events, so the tier columns of the
CLAUDE.md code rule do not apply (decision 045 scope: rows that only measure carry no tier). `method` is written.
OPEN Q8 asks the owner to confirm.

## 4. Rules
| ID | Rule | Source |
|---|---|---|
| LB-00 | **Allowed trial.** Refuse per §2 before reading any event. | 046, 053; spec 03 ST-00 |
| LB-01 | **Window.** Only events whose corrected time is inside the trial window are labelled. Others are counted in `stats.json`, never listed. | spec 03 ST-01; decision 039 |
| LB-02 | **Single-event rules only.** Every rule matches one event. Sigma correlation rules are not used; joining events is the stitcher's job. | handoff §10 ("adds attributes, does not change the graph") |
| LB-03 | **Near duplicates.** Rows the gate flags `near_duplicate` (spec 02 GT-18) are one event: one label row per rule, on the representative uid, with the copies in `dup_uids`. | spec 03 ST-05 |
| LB-04 | **Field mapping.** A Sigma field name maps to the lower-case key of `field_values_json` (`TargetImage` → `targetimage`, `Provider_Name` → `provider`). For logsource `process_creation` on Security 4688: `Image` → `newprocessname`, `ParentImage` → `parentprocessname`, `CommandLine` → `commandline`; `OriginalFileName` has no 4688 field and never matches. A field absent from the event never matches a selection item and makes a `filter` item false. Logsources: `process_access` → Sysmon 10; `process_creation` → Sysmon 1 and Security 4688; `network_connection` → Sysmon 3; `ps_module` → PowerShell 4103; `service: security` → Security; `service: system` → System. | Sigma taxonomy; DB fields §10.3 |
| LB-05 | **Sigma subset.** Values: strings (case-insensitive, `*` / `?` wildcards), integers, lists (any of). Modifiers: `contains`, `startswith`, `endswith`, `all`. Conditions: `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`, `1 of them`, `all of them`. A rule that uses anything else is refused at load time (§2). | Sigma specification |
| LB-06 | **Everything is written.** Every match of every rule is a row; an event may match several rules; nothing is dropped and there is no threshold. Which match counts for NodeScore is T9's choice. | Correction J, G.4 |
| LB-07 | **Levels.** SigmaHQ rules keep their level. Own rules get **low** (Sigma: a notable event, rarely an incident on its own) because each matches the base event of a technique with no suspicious condition; OPEN Q5. The level value map is locked (0–4). | Correction G; OPEN Q5 |
| LB-08 | **Node join.** A `path_nodes.csv` row is labelled when its `event_uid`, or any ST-05 copy of it, has at least one label row. `context` = 1 nodes are labelled the same way; the `context` column is carried so T9 can choose (OPEN Q6). | spec 03 ST-71 |
| LB-09 | **No command or script text in any output.** Outputs carry uids, rule ids, technique ids, levels and target-side names already written by the stitcher. | spec 03 §2; spec 00 LC-13 |
| LB-10 | **Rule list lock.** The rules run are exactly the rows of `manifest.csv`, each pinned by SHA-256; the manifest is pinned in `run_info.json`. Changing a rule after the lock needs a decision record. | handoff §24 item 6; PLAN 8.1 |

## 5. Parameters
| Name | Value | Why | Sensitivity test? |
|---|---|---|---|
| `SIGMA_COMMIT` | `54967d64e6dda2b4daa81f47f7a8bf1f591b68a0` | the SigmaHQ state the list was taken from | no |
| `LEVEL_VALUE` | informational 0, low 1, medium 2, high 3, critical 4 | Correction G | no |
| `OWN_RULE_LEVEL` | low | LB-07; OPEN Q5 | T9 reports NodeScore with own rules at low and medium |

## 6. Edge cases
| Case | Where it occurs | Expected behaviour | Test ID |
|---|---|---|---|
| (filled from measurement and the attacker review) | | | |

## 7. Acceptance tests
Unit (synthetic rows, LBT):
| ID | What must be true |
|---|---|
| LBT-01 | Each refusal of §2 stops the run and writes nothing; a t02 id is refused with paths that do not exist. |
| LBT-02 | Each rule SR-nn: one minimal matching event and one non-matching event per selection and per filter. |
| LBT-03 | Field mapping: lower-case keys; the 4688 renames; a missing field never matches a selection and makes a filter false; case-insensitive matching; wildcards. |
| LBT-04 | Subset parser: every supported modifier and condition form; an unsupported modifier, field or logsource refuses the rule file. |
| LBT-05 | Window: an event outside the window has no row in any file. Near-duplicate: one row, copies in `dup_uids`. |
| LBT-06 | Node join: a node whose uid is an ST-05 copy is labelled; an unlabelled node has `labelled` = 0 and is still written. |
| LBT-07 | No output file contains any substring of length ≥ 12 of any `command_line`, `commandline`, `scriptblocktext`, `contextinfo` or `payload` value of the DB; DB hash unchanged; two runs byte-identical; `src/label` opens nothing under `ground_truth/`. |
| LBT-08 | Manifest: a changed rule file, a missing file or an extra file refuses the run; the licence columns are present for every SigmaHQ rule. |

Real data (development trials only; the tests and `src/evaluate` read the keys, `src/label` never does):
| ID | What must be true |
|---|---|
| LBA-01 | Counts: label rows per rule equal `stats.json`; every node row of `path_nodes.csv` is in `node_labels.csv`. |
| LBA-02 | Every key `lsass_dump` event (Sysmon 10) of the six keys is labelled T1003.001. |
| LBA-03 | Every attack hop of the six keys has at least one node labelled with a lateral-movement technique (T1021.002, T1021.006, T1021.001) or T1569.002 / T1570. |
| LBA-04 | **Labelling recall (PLAN 8.3)** in `src/evaluate`: `out/evaluate/<trial>/label_recall.csv` and `out/evaluate/development/label_recall.md`. One row per key event of the kinds in the table below: `trial_id, hop_id or step_id, kind, event_uid, expected_technique, labelled, labelled_expected, rule_ids`. Recall per technique and overall on the six keyed t00 trials. Labels on background and benign key hops are reported, never scored as right or wrong. t01 trials: counts only. **Development numbers, not results; never run on t02–t10 before T10.** |

Expected technique per key event (the recall table):
| Key event | Channel / event | Expected technique |
|---|---|---|
| step `lsass_dump` | Sysmon 10 | T1003.001 |
| SMB hop: target 5140 / 5145 on an admin share | Security 5140 / 5145 | T1021.002 |
| SMB hop: copied executable | Security 5145 (write) | T1570 |
| step `service_exec` / hop install | System 7045, Security 4697 | T1569.002 |
| WinRM hop: `wsmprovhost` process | Sysmon 1 / 4688 | T1021.006 |
| WinRM hop: source connection to 5985 | Sysmon 3 (source) | T1021.006 |
| target 4624 of a hop | Security 4624 | none expected (reported only: no rule labels a plain type 3 logon) |

## 8. OPEN questions
| # | Question | Options / proposal | Status |
|---|---|---|---|
| Q1 | The LSASS read on the source host may not be a node of the hop's path (spec 03 ST-71 adds source-session events only for tier A/B links). Should T9 count the `hop_identity` dump events as nodes of the path? | (a) yes, T9 adds them as nodes for NodeScore; (b) no, they enter only through IdentityCoherence. Measurement §10.2 | open |
| Q2 | Spec 03 Q9: which `R1_lsass` rows count as the credential-access event, and do `end_unknown` sessions count? | Proposal: the LSASS reads labelled T1003.001 by the locked rules; `end_unknown` not counted (as now). §10.5 | open |
| Q3 | T1059.001 and T1078 as labels | (a) only as second tags of SR-03, SR-40..42 and SR-60 (as listed); (b) own rules | open |
| Q4 | Sigma evaluator | (a) own subset matcher, LB-05 (recommended: no new dependency, every function explainable); (b) pySigma (new dependency, its own field pipelines) | open |
| Q5 | Level of own rules | (a) low (LB-07); (b) medium; (c) the level of the nearest SigmaHQ rule | open |
| Q6 | `context` = 1 nodes | labelled the same way (LB-08); T9 decides whether they count | open |
| Q7 | SR-42 (PowerShell 4103) reads a high-volume channel | keep; volume in §10.4 | open |
| Q8 | No tier columns on label rows (§3.4) | confirm | open |
| Q9 | Discovery techniques (T1087, T1018) | out of scope unless the key steps contain such events (§10.1) | open |
| Q10 | T1550.002 (SR-61) and T1078 (SR-60) in T9's order table | T9 spec | open |

## 9. Out of scope
NodeScore value, tactic order table, ranking (T9). Any change to the gate or the stitcher. Correlation rules.
Test trials t02–t10. Running over all trials before the stage passes review.

## 10. Measurements (development trials only, read-only)
(filled by T8.1 measurement)
