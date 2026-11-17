# Stage spec: 04_label

**Owner:** <stage owner> · **Status:** **draft (T8.1), not approved.** Candidate rule list written 2026-11-17 before
any rule-hit measurement (§3.1, commit `2628082`); measurements §10; data-checker and attacker review merged
([review](../reviews/04_label-spec-2026-11-17.md)); owner answers Q1–Q14 pending, then the lock decision record (Q12).
· **Last updated:** 2026-11-17

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
2026-11-13, folder `rules/windows/`) and the handoff technique set (§5.5) and gate rules (§7.2). **No rule was run
on any trial before this list was written.** Changes after measurement are listed in §3.2 with their numbers.
What the author had seen before writing the list (review ATK-L09):
- the s05_t00 answer key, read while planning (its step kinds and hop event uids, and its hop command fields);
- the channel / event-id counts of s05_t00;
- the field-name keys (not values) of 12 event types in s05_t00.

The own rules SR-20, SR-30, SR-31 and SR-50 come from handoff R4–R6 and the field names. The extension list of SR-20
and its `%%4417` code are generic (Windows WriteData code); they were not checked against any value before the
list. Every measurement of §10 ran after commit `2628082`.

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

Conditions of the SigmaHQ rules as written at the pinned commit (summary; the files are the authority; filters
listed by what they exclude):
| Rule | Selection | Filters (excluded) |
|---|---|---|
| SR-01 | TargetImage ends `\lsass.exe`; SourceImage ends `\rundll32.exe`; CallTrace contains `comsvcs.dll` | – |
| SR-02 | TargetImage ends `\lsass.exe`; GrantedAccess contains `0x1038` / `0x1438` / `0x143a` / `0x1fffff`; CallTrace contains `dbgcore.dll` / `dbghelp.dll` / `kernel32.dll` / `kernelbase.dll` / `ntdll.dll` | SourceUser contains `AUTHORI` / `AUTORI`; a THOR CallTrace with `0x103800`; SourceImage Sysmon64 |
| SR-03 | TargetImage ends `\lsass.exe`; SourceImage ends `:\Windows\system32\wsmprovhost.exe` | GrantedAccess `0x80000000` |
| SR-10 | 5140; ShareName `Admin$` | SubjectUserName ends `$` |
| SR-11 | 5145; ShareName ends `C$`; AccessMask `0x2` | SubjectUserName ends `$`; IpAddress `::1` |
| SR-12 | 5145; ShareName `\\*\IPC$`; RelativeTargetName `svcctl`; AccessList contains `WriteData` | – |
| SR-40 | Image ends `\wsmprovhost.exe` **or** ParentImage ends `\wsmprovhost.exe` | – |
| SR-41 | DestinationPort 5985 / 5986; Initiated `true`; SourceIsIpv6 `false` | User = Network Service (localised forms); loopback source and destination; Avast image |
| SR-42 | ContextInfo contains ` = ServerRemoteHost ` and `wsmprovhost.exe` | ContextInfo with the Microsoft.PowerShell.Archive module path |
| SR-60 | 4648; ProcessName ends `\cmd.exe`, `\powershell.exe`, `\pwsh.exe`, `\winrs.exe`, `\wmic.exe`, `\net.exe`, `\net1.exe`, `\reg.exe` (a `-` ProcessName never matches) | TargetServerName `localhost`; SubjectUserName and TargetUserName both end `$` |
| SR-61 | 4624 with (SubjectUserSid `S-1-0-0`, LogonType 3, LogonProcessName `NtLmSsp`, KeyLength 0) or (LogonType 9, LogonProcessName `seclogo`) | TargetUserName `ANONYMOUS LOGON` |

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
**Nothing below is applied.** Each row is a proposal made **after** measurement 4 (§10.4) and is therefore a
development-set choice. The owner accepts or rejects each one (OPEN Q11). §3.1 stays the record of what was chosen
before measurement.

| # | Rule | Proposed change | Reason | Numbers (§10) |
|---|---|---|---|---|
| P1 | SR-10 | `ShareName: 'Admin$'` (equals) → `ShareName|endswith: '\ADMIN$'`. A derived rule: new id, `related: 098d7118… derived` (§3.3) | Windows logs 5140 `ShareName` as `\\*\ADMIN$`, so the rule as written matches nothing. **T1021.002 then has no label in any trial** | SR-10 = 0 in 9 of 9 trials (§10.4). 5140 `ADMIN$` by a user account in the window: 9 rows over the 9 trials (0–2 per trial). Key 5140 `ADMIN$`: attack 5 of 5 and benign 1 would be labelled. Key 5140 `IPC$` (3 attack) stays unlabelled (§10.1) |
| P2 | SR-42 | (a) `' = ServerRemoteHost '` → `' = ServerRemoteHost'` (derived); or (b) drop SR-42 | The stored ContextInfo has a newline after the value, not a space: 170 of 170 rows that contain it in the nine DBs (whole DBs; 108 in the windows; data-checker count, which corrects a first count of 139 over three DBs). As written: 0 matches. Every WinRM hop already gets T1021.006 from SR-40 / SR-41 (§10.6). Proposal: **(b) drop** | 4103 rows with `ServerRemoteHost` + `wsmprovhost.exe`: 2 / 1 / 48 / 57 (s03_t00, s05_t00, s03_t01, s06_t01), else 0 |
| P3 | SR-31 | ~~add `filter: SubjectUserName|endswith: '$'`~~ → **P3′: add `filter: ServiceType` in (`0xd0`, `0xe0`)** (per-user service template instances) | Any 4697 also matches the per-user service instances Windows creates at each logon (`OneSyncSvc_<id>`, `UnistoreSvc_<id>` …), all under a machine account. None is a path node, but a labels-only baseline (B0) would count them. **Review ATK-L05:** an account filter would also drop a real install made by an attacker-controlled SYSTEM / machine-account context, so P3 is replaced by P3′, which filters the service kind and not the account | SR-31: 459 window matches, 451 by a machine account; the 8 by a user account are exactly the 8 hop installs (node rows: 8). Whole DBs of the six keyed trials: `ServiceType` 0xe0 883 and 0xd0 41 (all `<name>_<id>` instances under a machine account); 0x10 7 (the installs) |
| – | SR-03, SR-11, SR-12, SR-50, SR-61 | none | 0 matches; kept as written. SR-03 / SR-50: no WinRM dump or RDP in the data. SR-11: the lab copies to `ADMIN$`, not `C$`. SR-12: no `svcctl` 5145 is logged. SR-61: `LogonProcessName` is padded (`NtLmSsp `), but trimming it gives 0 as well | §10.4, §10.5 |

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
| count_key | text | LB-11 |
| method | text | `sigma_rule` |
| clock_unreliable | int | as spec 03 ST-02, for the event's host |

**`node_labels.csv`** — one row per row of the stitcher's `path_nodes.csv`, labelled or not.
`path_id, hop_id, role, context, host, event_uid, labelled` (0/1)`, rule_ids, techniques, max_level_value` (empty if
unlabelled).

**`hop_labels.csv`** — one row per hop of `hops.csv`: `hop_id, in_path, n_node_events, n_labelled_node_events,
techniques` (of its node events)`, dump_event_uids` (the distinct non-empty `dump_event_uid` values of the hop's
`hop_identity.csv` rows, which has several rows per hop, `;`-joined)`, dump_labelled` (`1` / `0` /
`outside_window` for a look-back read, ST-63)`, dump_rule_ids, dump_max_level_value`. The dump columns are facts
about the LSASS reads that identity uses. They are not nodes and never change identity (OPEN Q1, Q2; review ATK-L02).
A hop with no labelled node event has `n_labelled_node_events` = 0 and empty `techniques` (review ATK-L08).

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
| LB-03 | **Near duplicates.** Rows with the same host, channel and record ID but different uids (the spec 02 GT-18 definition, applied by the labeller to every channel, because the gate flags only 4624 trigger rows) are one event: one label row per rule, on the representative uid (the smallest uid), with the copies in `dup_uids`. Development data has none (`near_duplicate_uids` empty in all nine trials, data-checker), so this is tested on synthetic rows only. | spec 03 ST-05; 02_gate GT-18 |
| LB-04 | **Field mapping.** A Sigma field name maps to the lower-case key of `field_values_json` (`TargetImage` → `targetimage`, `Provider_Name` → `provider`). For logsource `process_creation` on Security 4688: `Image` → `newprocessname`, `ParentImage` → `parentprocessname`, `CommandLine` → `commandline`; `OriginalFileName` has no 4688 field and never matches. A field absent from the event never matches a selection item and makes a `filter` item false. Logsources: `process_access` → Sysmon 10; `process_creation` → Sysmon 1 and Security 4688; `network_connection` → Sysmon 3; `ps_module` → PowerShell 4103; `service: security` → Security; `service: system` → System. | Sigma taxonomy; DB fields §10.3 |
| LB-05 | **Sigma subset.** Values: strings (case-insensitive, `*` / `?` wildcards), integers, lists (any of). Modifiers: `contains`, `startswith`, `endswith`, `all`. Conditions: `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`, `1 of them`, `all of them`. A rule that uses anything else is refused at load time (§2). | Sigma specification |
| LB-06 | **Everything is written.** Every match of every rule is a row; an event may match several rules; nothing is dropped and there is no threshold. Which match counts for NodeScore is T9's choice. | Correction J, G.4 |
| LB-07 | **Levels.** SigmaHQ rules keep their level. Own rules get **low** (Sigma: a notable event, rarely an incident on its own) because each matches the base event of a technique with no suspicious condition; OPEN Q5. The level value map is locked (0–4). | Correction G; OPEN Q5 |
| LB-08 | **Node join.** A `path_nodes.csv` row is labelled when its `event_uid`, or any ST-05 copy of it, has at least one label row. `context` = 1 nodes are labelled the same way; the `context` column is carried so T9 can choose (OPEN Q6). | spec 03 ST-71 |
| LB-09 | **No command or script text in any output.** Outputs carry uids, rule ids, technique ids, levels and target-side names already written by the stitcher. | spec 03 §2; spec 00 LC-13 |
| LB-11 | **One action, one count key.** Each label row gets `count_key`: for a Sysmon 1 and a 4688 of one process (same host, `process_id`, \|Δt\| ≤ `PROCESS_COLLAPSE_S`, spec 03 ST-11) the Sysmon 1 uid; for a 4697 and 7045 of one install (paired as 02_gate GT-12) the 4697 uid; else the event's own uid. Both events stay labelled; the key lets T9 count one action once (review ATK-L04). | spec 03 ST-11; 02_gate GT-12 |
| LB-12 | **Sigma escapes and literals.** In a rule value `\*` and `\?` are a literal `*` / `?`, `\\` is one backslash, and any other backslash is literal (Sigma specification). The stored `ShareName` `\\*\ADMIN$` holds a literal `*` (review ATK-L10). | Sigma specification |
| LB-13 | **Total order and stable bytes.** Rows sort by corrected time, then `event_uid`, then `rule_id`. Times are written as in spec 03 (microseconds, `Z`). Rule files are hashed after normalising line endings to LF, so a CRLF checkout cannot change the hash (review ATK-L10). | spec 03 §3 |
| LB-10 | **Rule list lock.** The rules run are exactly the rows of `manifest.csv`, each pinned by SHA-256; the manifest is pinned in `run_info.json`. Changing a rule after the lock needs a decision record. | handoff §24 item 6; PLAN 8.1 |

## 5. Parameters
| Name | Value | Why | Sensitivity test? |
|---|---|---|---|
| `SIGMA_COMMIT` | `54967d64e6dda2b4daa81f47f7a8bf1f591b68a0` | the SigmaHQ state the list was taken from | no |
| `LEVEL_VALUE` | informational 0, low 1, medium 2, high 3, critical 4 | Correction G | no |
| `OWN_RULE_LEVEL` | low | LB-07; OPEN Q5 | T9 reports NodeScore with own rules at low and medium |
| `PROCESS_COLLAPSE_S` | 2 s | as `src/stitch/params.py` (spec 03 ST-11), one definition | no |

## 6. Edge cases
| Case | Where it occurs | Expected behaviour | Test ID |
|---|---|---|---|
| Field values stored as one-element lists in `field_values_json` | every DB (§10.3) | the matcher unwraps one-element lists; a list of more than one value matches when any element matches (none measured) | LBT-03 |
| Value format differs from the SigmaHQ rule's assumption (`\\*\ADMIN$`; newline after `ServerRemoteHost`; `NtLmSsp ` padded) | every trial | the rule is applied as written (no trimming, exact Sigma semantics); a format fix is a derived rule listed in §3.2 | LBT-02 |
| LSASS dump is a path node only as a `context` = 1 source-session event | 5 keyed trials (§10.2) | labelled like any node; `context` carried (LB-08, Q1, Q6) | LBA-02 |
| R1_lsass rows of system / AV processes (`wmiprvse`, `csrss`, `wininit`, `MsMpEng`) | all 9 trials | not labelled T1003.001 (§10.5) | LBA-02 |
| Benign hops carry the same movement labels as attack hops | s04 track A, s06 (§10.6) | written as labels; telling them apart is T9's job (identity), never T8's | LBA-03 |
| Executable written to `ADMIN$` under a machine account | s02_t00, 2 rows (§10.4) | labelled by SR-20 (own rule, no account filter); reported | LBT-02 |
| Per-user service instances (4697 by a machine account at logon) | all trials but s03_t01, s06_t01 | labelled by SR-31 as written; P3 proposes a filter | LBT-02 |
| **ATK-L03 level asymmetry:** SMB attack hops carry only own-rule `low` labels; benign WinRM hops carry SigmaHQ `medium` / `high` | s06_t00 vs s02/s04/s05/s07 (§10.7) | written as labels; reported in §10.7; the ranking consequence is OPEN Q13 (T9) | LBA-06 |
| ATK-L04 one action logged twice (Sysmon 1 + 4688; 4697 + 7045) | every WinRM / service hop | both labelled, one `count_key` (LB-11) | LBT-09 |
| ATK-L01 dump tool not covered by SR-01 / SR-02 (procdump, Task Manager, direct MiniDumpWriteDump, other masks) | not in current data (one dump technique in the lab, so 14 of 14 is not evidence of coverage) | unlabelled; identity unaffected because Q2 no longer filters on labels | LBT-02 negative case |
| ATK-L02 dump before the window or moved out by clock skew | not in current data | not labelled (LB-01); `dump_labelled` = `outside_window`; identity unaffected | LBT-05 |
| ATK-L05 attacker install under a machine / SYSTEM account | not in current data | SR-31 still labels it under P3′ (service-kind filter, not account) | LBT-02 |
| ATK-L06 RDP by IP logged as type 3 | S01 (not ingested) | SR-50 does not fire; the hop has no T1021.001 label; limitation L-LB2 | LBT-02 |
| ATK-L08 hop with no service and no executable copy (read-only SMB, other remote method) | not in current data (7 of 7 attack hops labelled) | `n_labelled_node_events` = 0, stated in the report (L-LB3) | LBA-03 negative control |
| ATK-L10 literal `*` in `ShareName`; trailing backslash; CRLF rule file | every trial / Windows checkout | LB-12, LB-13 | LBT-04, LBT-08 |

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
| LBT-08 | Manifest: a changed rule file, a missing file or an extra file refuses the run; the same file with CRLF line endings has the same hash (LB-13); the licence columns are present for every SigmaHQ rule. |
| LBT-09 | `count_key`: a Sysmon 1 + 4688 pair and a 4697 + 7045 pair each share one key; a third event outside `PROCESS_COLLAPSE_S` gets its own. |
| LBT-10 | **Format contract (review ATK-L06).** Fixtures for LBT-02 include one real DB row per rule selection where one exists (extracted by uid from a development DB, sensitive fields blanked). For every literal in every rule, the test lists the distinct stored values of that field in the development DBs and reports a literal that no stored value could match. It reports; it does not fail, because a literal may target events the lab never produced. |

LBT-07 also scans `servicefilename`, `imagepath` and `parentcommandline` (review ATK-L11). Service names are
target-side names and may appear in outputs, as in spec 03.

Real data (development trials only; the tests and `src/evaluate` read the keys, `src/label` never does):
| ID | What must be true |
|---|---|
| LBA-01 | Counts: label rows per rule equal `stats.json`; every node row of `path_nodes.csv` is in `node_labels.csv`. |
| LBA-02 | Every key `lsass_dump` event (Sysmon 10) of the six keys is labelled T1003.001. |
| LBA-03 | Every attack hop of the six keys has at least one node labelled with a lateral-movement technique (T1021.002, T1021.006, T1021.001) or T1569.002 / T1570. |
| LBA-05 | No T1003.001 label is added to any node or hop of a benign key hop (s04 A); `hop_labels` dump columns are facts only (review ATK-L07). |
| LBA-06 | Level profile report (review ATK-L03): for every key hop, the mean `max_level_value` of its labelled `context` = 0 nodes and of all its labelled nodes, with a flag when a benign hop is at or above an attack hop of the trial set. Reported, not a pass / fail. |
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
| Q1 | **Measured (§10.2):** every key LSASS dump is a path node, but **only as a `context` = 1 source-session event** (spec 03 ST-71: tier A/B source session, at or before the hop). T1003.001 is never on a `context` = 0 node. If T9 counts only `context` = 0 nodes, no path gets a credential-access label; with a tier C/D link the dump is not a node at all | (a) T9 counts `context` = 1 nodes that carry a label; (b) T9 adds the labelled `hop_identity` dumps of each hop as nodes (`hop_labels.csv` lists them); (c) the dump enters only through IdentityCoherence. **Changed after review ATK-L07: proposal (c).** Option (b) would give a benign hop from a dumped host a high T1003.001 label, which repeats the "exposed ≠ stolen" error inside NodeScore and counts the dump twice with w3. Cost of (c): no path carries a credential-access technique for T9's order table unless T9 reads `hop_labels` | open |
| Q2 | Spec 03 Q9: which `R1_lsass` rows count as the credential-access event, and do `end_unknown` sessions count? | **Measured (§10.5):** 70 R1_lsass rows, 20 labelled T1003.001; every labelled read is an R1 row; all 14 key dump events are labelled; the 50 others come from `wmiprvse`, `csrss`, `wininit`, `MsMpEng`. **First proposal ("only labelled R1 rows count") withdrawn after review ATK-L01 / ATK-L02:** it couples the locked identity value to label coverage. The lab uses one dump technique, so 14 of 14 shows no coverage of other tools, and a look-back dump before the window is never labelled. Options for T9: (a) R1 rows as now (spec 03 ST-61), with `dump_labelled` shown as a fact; (b) R1 rows minus a stated source-image exclusion list (`wmiprvse`, `MsMpEng`, `csrss`, `wininit`), decided in the T9 spec with its own record. T8 itself never filters identity. `end_unknown`: not counted (as now) | open |
| Q3 | T1059.001 and T1078 as labels | (a) only as second tags of SR-03, SR-40..42 and SR-60 (as listed); (b) own rules | open |
| Q4 | Sigma evaluator | (a) own subset matcher, LB-05 (recommended: no new dependency, every function explainable); (b) pySigma (new dependency, its own field pipelines) | open |
| Q5 | Level of own rules | (a) low (LB-07); (b) medium; (c) the level of the nearest SigmaHQ rule | open |
| Q6 | `context` = 1 nodes | labelled the same way (LB-08); T9 decides whether they count. Review ATK-L07: exclude them from NodeScore (they hold the SR-41 duplicates and the dumps). Measured: on `context` = 0 nodes s04 A (benign) and s04 B (attack) are identical (§10.7) | open (T9) |
| Q7 | SR-42 (PowerShell 4103) matches nothing as written | see P2: drop (proposed) or derive | open |
| Q8 | No tier columns on label rows (§3.4) | confirm | open |
| Q9 | Discovery techniques (T1087, T1018) | out of scope unless the key steps contain such events (§10.1) | open |
| Q10 | T1550.002 (SR-61) and T1078 (SR-60) in T9's order table | T9 spec | open |
| Q11 | Changes after measurement P1–P3 (§3.2) | accept / reject each; an accepted change is recorded in the rule-list decision | open |
| Q13 | **Level asymmetry (review ATK-L03).** With SR-10 dead and own rules at `low`, every SMB attack hop averages 1.00 on its `context` = 0 nodes, against 2.00–2.33 for the benign WinRM hops (§10.7). A NodeScore over these labels orders protocols, not attack against benign | options: (a) accept and state it: separating attack from benign is the identity term's job (Correction K), and NodeScore is reported as protocol-sensitive; (b) own rules at `medium` (Q5 b); (c) T9 counts one label per technique per hop. Any choice is a development-set choice, made in the T9 spec with the B2 baseline in view. **Not decided here** | open (T9) |
| Q14 | Measurement scripts are in `out/label_measure/` (gitignored, as `out/stitch_measure/` was), so the audit is not in git (review ATK-L09) | (a) keep as is (precedent spec 03 §10); (b) commit them under a tracked folder (counts only) in 8.2 | open |
| Q12 | Lock record | after Q3, Q4, Q5, Q11: one decision record locks the list (rules, levels, own-rule level, evaluator, SigmaHQ commit), then 8.2 copies the files with the §3.3 attribution | open |

## 9. Out of scope
NodeScore value (including the value for a path with no labelled node), tactic order table, ranking (T9). Any change
to the gate or the stitcher. Correlation rules. Test trials t02–t10. Running over all trials before the stage passes
review. **After the lock no rule is added, dropped or changed by looking at test-trial counts; a rule that never
matches on development data stays in the list as locked (review ATK-L09).**

### 9.1 Limitations stated by this spec
- **L-LB1 One dump technique.** The lab dumps LSASS one way (SR-01 matches all 14 key dumps; SR-02 matches 7). Labels
  of other dump tools are untested, so T1003.001 coverage is not measured.
- **L-LB2 RDP untested.** SR-50 (type 10) has never seen real data. RDP by IP with NLA can log type 3, which SR-50
  does not label (handoff §7.2 caveat). S01 is not ingested.
- **L-LB3 Hops without artefacts.** A hop with no service install, executable copy or WinRM process has no labelled
  node: SR-10 (after P1) is the only rule on a plain share access, and nothing labels a target 4624.
- **L-LB4 Rules dead on this data.** 7 of 15 rules match nothing in the development trials (§10.4), 3 of them because
  of value formats (P1, P2; SR-61's selection fails even with trimming).

## 10. Measurements (development trials only, read-only, 2026-11-17)
Scripts in `out/label_measure/` (gitignored): `measure_t81.py`, `diag_t81.py`, `perhop_t81.py`. They import the
stitcher's allowlist (`stitch.inputs.check_allowlist`, = `DEVELOPMENT_TRIALS`). `s02_t02` was refused when tried,
before any file was opened. DBs were opened `mode=ro`, and all nine SHA-256 values were unchanged and equal to gate
`stats.json`. Events were clipped to the gate window on corrected times. Rule predicates mirror §3.1 as written.
**No command line, script block, ContextInfo or Payload text was printed or saved.** Only counts, uids, share names,
access codes, service names and image file names appear. Keys were read only by the scripts, for counting. t01 trials
carry no right/wrong label. The candidate list (§3.1) was committed before measurement 4 ran (commit `2628082`).

### 10.1 Key events by kind (six keyed t00 trials)
| Key event | Channel / event | Events | Path node | Labelled (rule) |
|---|---|---|---|---|
| step `lsass_dump` | Sysmon 10 | 14 | 14 (`source_session_event`, context 1) | 14 T1003.001 (SR-01 14; SR-02 7 of them) |
| step `service_exec` | System 7045 / Security 4697 | 6 / 6 | all | 6 T1569.002 (SR-30) / 6 T1569.002 (SR-31) |
| step `move`, `agent_start`, `benign` (source commands) | Sysmon 1 / 4688 | 21 / 49 / 14 | `move` 21; `agent_start` 24 of 68; `benign` 9 of 14 | none (no rule targets a command) |
| attack hop target 4624 | Security 4624 | 24 | all | none (expected: no rule labels a plain network logon) |
| attack hop 5140 | Security 5140 | 8 (`ADMIN$` 5, `IPC$` 3) | all | **none** (SR-10 as written, P1) |
| attack hop 5145 | Security 5145 | 30 (all `ADMIN$`) | all | 10 T1570 (SR-20, the executable writes); 20 none |
| attack hop install | 4697 / 7045 | 4 / 4 | all | T1569.002 |
| attack WinRM `wsmprovhost` | Sysmon 1 / 4688 | 2 / 2 | all | T1021.006 (SR-40) |
| attack WinRM source connection | Sysmon 3 | 5 | all (`source_evidence`) | T1021.006 (SR-41) |
| attack WinRM 91 | WinRM 91 | 2 | all | none (no rule) |
| background hop events (4 hops) | 4624 / 5140 / 5145 | 4 / 8 / 12 (`IPC$`, `LabShare`) | all | none |
| benign hop events (s04 A, s06) | 4624, 5140/5145, 4697/7045, Sysmon 1/4688, 91 | 13, 1/6, 2/2, 2/2, 1 | all | same rules as the attack hops of the same protocol |

No key step is of a Discovery kind (kinds: `agent_start`, `benign`, `lsass_dump`, `move`, `service_exec`) → Q9.

### 10.2 Path nodes and labels
| Rule | Matches in window (9 trials) | Path-node rows by role / context |
|---|---|---|
| SR-01 | 20 | `source_session_event` / 1: 20 |
| SR-02 | 9 | `source_session_event` / 1: 10 |
| SR-20 | 16 | `artefact` / 0: 14 |
| SR-30 | 9 | `artefact` / 0: 8 |
| SR-31 | 459 | `artefact` / 0: 8 |
| SR-40 | 39 | `artefact` / 0: 7; `target_session_event` / 1: 18 |
| SR-41 | 19 | `source_evidence` / 0: 18; `source_session_event` / 1: 29 |
| SR-60 | 35 | `source_evidence` / 0: 33 |

(Node rows count a node once per path that holds it.) T1003.001 is on `context` = 1 nodes only (Q1). In s02_t00, 2
labelled LSASS reads lie in the window that the key does not list (the key's dump step lists 2). In the other keyed
trials the labelled reads equal the key dumps.

### 10.3 Fields
Every field a §3.1 rule reads is present in 100 % of the rows of its event in all nine trials (Sysmon 10
`targetimage, sourceimage, calltrace, grantedaccess, sourceuser`; 5140 / 5145 `sharename, accessmask, accesslist,
subjectusername, ipaddress`, and 5145 `relativetargetname` (absent from all 174 window 5140 rows, which no rule
needs; data-checker); 7045 `provider, imagepath, servicename`; 4697 `servicename,
servicefilename`; Sysmon 1 `image, parentimage`; 4688 `newprocessname, parentprocessname`; Sysmon 3
`destinationport, initiated, sourceisipv6, user, sourceip, destinationip, image`; 4103 `contextinfo`; 4624
`logontype, subjectusersid, logonprocessname, keylength, targetusername`; 4648 `processname, targetservername,
subjectusername, targetusername`). Formats:
- Values are one-element JSON lists; no multi-element list was found in any rule field.
- `ShareName` = `\\*\ADMIN$`.
- `AccessList` holds `%%` codes (`%%4417` = WriteData): space-separated in 5145 (sometimes with a trailing space);
  in 5140, `%%4416` followed by a newline and tabs. `contains` matching is unaffected.
- `Provider` = `Service Control Manager`.
- `Initiated` / `SourceIsIpv6` = `true` / `false`.
- `LogonProcessName` is padded to 8 characters (`NtLmSsp `, `Advapi  `).
- ContextInfo has `= ServerRemoteHost` followed by a newline.

### 10.4 Rule hits in the window (machine-account matches in brackets)
| Rule | s02_t00 | s03_t00 | s04_t00 | s05_t00 | s06_t00 | s07_t00 | s02_t01 | s03_t01 | s06_t01 |
|---|---|---|---|---|---|---|---|---|---|
| SR-01 | 4 | 2 | 2 | 4 | 0 | 4 | 2 | 2 | 0 |
| SR-02 | 1 | 1 | 1 | 2 | 0 | 2 | 1 | 1 | 0 |
| SR-20 | 4 (2) | 0 | 4 | 2 | 0 | 4 | 2 | 0 | 0 |
| SR-30 | 1 | 0 | 2 | 1 | 1 | 2 | 1 | 0 | 1 |
| SR-31 | 49 (49) | 67 (67) | 69 (67) | 92 (91) | 68 (67) | 45 (43) | 68 (67) | 0 | 1 (0) |
| SR-40 | 0 | 2 | 0 | 2 | 6 | 0 | 0 | 13 | 16 |
| SR-41 | 0 | 3 | 0 | 3 | 3 | 0 | 0 | 3 | 7 |
| SR-60 | 0 | 5 | 0 | 5 | 10 | 0 | 0 | 5 | 10 |
| SR-03, SR-10, SR-11, SR-12, SR-42, SR-50, SR-61 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

- **No-match causes (count-only diagnostics):**
  - SR-10: format, P1.
  - SR-42: format, P2.
  - SR-11: no 5145 on `C$` with `0x2`. There are 7–17 5140 on `C$` per trial, none matching.
  - SR-12: no `svcctl` 5145.
  - SR-61: the NTLM type 3 logons do not have the `S-1-0-0` + key length 0 combination. Trimmed `NtLmSsp`: 3–13 per
    trial, 0 matching.
  - SR-03, SR-50: no such events.
- **SR-31 machine-account matches** are per-user service instances created at logon (for example `OneSyncSvc_<id>`,
  `UnistoreSvc_<id>`, `CaptureService_<id>`), one each. The user-account 4697s are the two `PktDropService` and two
  `BenignMon` installs plus the other hop installs: 8 in total, which equals the 8 node rows.

### 10.5 R1_lsass rows and T1003.001 (spec 03 Q9 input)
| | s02_t00 | s03_t00 | s04_t00 | s05_t00 | s06_t00 | s07_t00 | s02_t01 | s03_t01 | s06_t01 | total |
|---|---|---|---|---|---|---|---|---|---|---|
| R1_lsass rows (gate) | 17 | 4 | 4 | 15 | 4 | 10 | 6 | 6 | 4 | 70 |
| labelled T1003.001 | 4 | 2 | 2 | 4 | 0 | 4 | 2 | 2 | 0 | 20 |
| labelled, not R1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

The 50 R1 rows that are not labelled have these source images: `wmiprvse.exe` (`0x1410`, 12), `MsMpEng.exe` (20),
`csrss.exe` and `wininit.exe` (`0x1fffff`, one each per trial). S06 has no dump (decision 017), and no read is
labelled there.

### 10.6 Labels per key hop (stitch hop holding the key's target 4624; techniques on its nodes)
| Key hop | Role | Protocol | Context 0 | Context 1 only |
|---|---|---|---|---|
| s02-h1 | attack | SMB | T1570 | T1003.001 |
| s03-h1 | attack | WinRM | T1021.006, T1078 | T1003.001 |
| s04-B-h1 | attack | SMB | T1569.002, T1570 | T1003.001 |
| s05-h1 | attack | SMB | T1569.002, T1570 | T1003.001 |
| s05-h2 | attack | WinRM | T1021.006, T1078 | T1003.001 |
| s07-h-x, s07-h-y | attack | SMB | T1569.002, T1570 | T1003.001 |
| s04-A-h1 | benign | SMB | T1569.002, T1570 | – |
| s06-winrm-1, s06-winrm-2 | benign | WinRM | T1021.006, T1078 | – |
| s06-smb-1 | benign | SMB | T1569.002 | T1021.006 |
| s04-t1, s05-t1, s06-t1, s07-t1 | background | SMB | – | – |

- Every attack hop (7 of 7 key attack hops) has a `context` = 0 node with a movement-family label (LBA-03 holds as
  written).
- No SMB hop has T1021.002 (P1).
- Benign hops of the same protocol get the same `context` = 0 labels as attack hops. Only the `context` = 1
  T1003.001 differs.
- Background hops get no label.

### 10.7 Level profile per key hop (§3.1 levels as written, own rules low; mean of each labelled node's highest level)
| Key hop | Role | Protocol | `context` 0 mean (n) | all labelled nodes mean (n) |
|---|---|---|---|---|
| s02-h1 | attack | SMB | 1.00 (2) | 2.00 (4) |
| s03-h1 | attack | WinRM | 2.25 (8) | 2.43 (14) |
| s04-A-h1 | benign | SMB | 1.00 (4) | 1.00 (4) |
| s04-B-h1 | attack | SMB | 1.00 (4) | 1.67 (6) |
| s05-h1 | attack | SMB | 1.00 (4) | 1.67 (6) |
| s05-h2 | attack | WinRM | 2.33 (9) | 2.50 (16) |
| s06-winrm-1 | benign | WinRM | 2.33 (9) | 2.23 (13) |
| s06-winrm-2 | benign | WinRM | 2.00 (6) | 2.27 (11) |
| s06-smb-1 | benign | SMB | 1.00 (2) | 2.20 (5) |
| s07-h-x / s07-h-y | attack | SMB | 1.00 (4) / 1.00 (4) | 1.67 (6) / 2.00 (8) |
| background (4) | background | SMB | – | – |

These are hop level, not path level. A row counts each node row, so one action logged twice counts twice (LB-11
fixes this for T9). Input for Q6 and Q13.
