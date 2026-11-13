# Stage spec: 03_stitch

**Owner:** <stage owner> · **Status:** **approved (owner, 2026-11-13).** Measured on development data 2026-11-13; data-checker and attacker review merged ([review](../reviews/03_stitch-spec-2026-11-13.md)); council [044](../decisions/044-stitch-linking-and-windows-council.md) accepted ("after" side 15 s); [045](../decisions/045-tier-rule-scope.md) accepted; owner answers Q1–Q16 merged; Q9 stays open for the T8 / T9 specs. **Amended by [047](../decisions/047-stitch-session-model.md) (owner, 2026-11-13): ST-10 boot groups and 4688 session, §5 `BOOT_GROUP_S`, STT-11.** · **Last updated:** 2026-11-13

Decisions this spec rests on: [011](../decisions/011-smb-linking-without-sysmon3.md), [013](../decisions/013-council-correction-i-amended.md) (Correction I amended), [014](../decisions/014-cross-host-time-tolerance.md) (5 s), [015](../decisions/015-port-zero-kerberos-hops.md), [038](../decisions/038-gate-rule-choices.md) (`confidence_tier` belongs to T7), [039](../decisions/039-gate-window-input-and-clock.md) (identity look-back), [043](../decisions/043-clock-offset-method.md) (corrected times). Accepted with this spec: [044](../decisions/044-stitch-linking-and-windows-council.md) (council), [045](../decisions/045-tier-rule-scope.md) (tier rule scope, review 08 SF-9). With T7.2: [046](../decisions/046-stitch-development-allowlist.md) (development allowlist until T10), [047](../decisions/047-stitch-session-model.md) (session model). Input notes: [03_stitch_input_notes](03_stitch_input_notes.md) (IN-01, IN-02). Measurements: §10.

## 1. Purpose
The stitcher takes the remote logons the gate marked and turns them into **hops** (one movement from a source
host to a target host), finds the **candidate source sessions** of each hop, and assembles **candidate paths**.
It decides nothing about attack or benign: it records every candidate with how it was found, so that the
scoring stage (T9) can rank the paths and the evaluation (T7.6) can check each link against the answer key.

## 2. Input contract
| Input | What is read | Notes |
|---|---|---|
| Gate outputs | `out/gate/<trial_id>/triggers.csv`, `unmatched_remote.csv`, `supporting.csv`, `dispositions.csv`, `stats.json` (spec 02_gate §3) | On the corrected time basis. Every remote type 3/10 logon is in exactly one of the first two files (GT-15). |
| Trial DB | `data/processed/<trial_id>.sqlite3`, view `events_dedup`, opened read-only | Source-side events and artefact details. Hash before = hash after. |
| Clock files | `data/processed/<trial_id>.clock_offsets.csv`, `.clock_changes.csv` (spec 08 §3) | Corrected time, `offset_unc_ms`, `clock_unreliable` through the shared functions of `clock_offset.correct` (CO-09). |
| Trial window | the row recorded in the gate `stats.json` (`window.row`); it must equal the trial's row in `data/trial_windows.csv` | The stitcher never computes a window. |
| Parameters | `src/stitch/params.py` | §5. |

Columns used from `events_dedup`: `event_uid, host, channel, event_id, record_id, event_utc, logon_type, source_ip,
source_port, destination_ip, destination_port, destination_host, initiated, account_name, subject_account,
target_logon_id, target_linked_logon_id, subject_logon_id, session_id, logon_guid, authentication_package, image,
parent_image, command_line, process_guid, parent_process_guid, process_id, share_name, relative_target_name,
service_name, service_image_path, source_image, target_image, granted_access, machine_account, field_values_json`
(the last only for the 4648 target fields). The data-checker confirmed these on `data/sample/` (review §1), with
five limits the rules respect: `target_linked_logon_id` is never set on type 3 logons; 4688 command lines are
missing in 28–44 % of rows (Sysmon 1 has them all); Sysmon 10 carries no session; a 4647 has its logon ID in
`target_logon_id` only; a boot is not always logged as System 41.

- **Times.** Every comparison between events of two hosts uses `event_utc_corrected = event_utc − offset_ms(host)`
  (spec 08 CO-09). Comparisons on one host are unaffected by the correction. Instants are compared, never text.
- **IDs.** Logon IDs are integers in every join and hex only in display columns (D1). A NULL logon ID, port or IP
  never matches anything (decision 005). IP addresses are normalised as in spec 02_gate §2 before every comparison.
- **Command lines.** Unlike the gate, the stitcher reads `command_line`. **No output file contains any part of a
  command line**; outputs carry event uids, and names taken from target-side events only (command lines hold lab
  passwords, spec 00 LC-13).
- **Ground truth.** `src/stitch` never opens a path under `ground_truth/`.

Refused inputs (stop with an error, write nothing):
- any gate output file missing, or `stats.json` `time_basis` not `corrected`;
- the DB's SHA-256 differs from `stats.json` `db.sha256_after`;
- the window row in `stats.json` differs from the trial's row in `data/trial_windows.csv`, or the clock files'
  SHA-256 differ from `stats.json` `clock.offsets_sha256` / `clock_changes_sha256`;
- every input the gate refuses (quarantined trial, clock-only trial, CO-17), checked again with the same shared
  functions, so a stale gate folder cannot be stitched;
- **S01 (review 08 SF-8):** the clock step refuses a trial with no agent roots, so no S01 trial has an offsets
  file, the window step and the gate refuse it, and the stitcher has no input. This spec adds no special case:
  **Owner 2026-11-13 (Q8): the refusal stays.** S01 is fixed by operator times and an offsets file after the lab (review 08 SF-8), not by loosening this rule.

## 3. Output contract
Location `out/stitch/<trial_id>/`. Rebuilt on every run. Rows sorted by time, then id. Every file except
`run_info.json` is byte-identical between two runs on the same inputs.

**`hops.csv`** — one row per hop group (ST-20).
| Column | Type | Meaning |
|---|---|---|
| hop_id | text | `<trial_id>-h<NNNN>` in time order |
| target_host, source_ip, ip_kind, source_host | text | source host = lab host that owns the normalised source IP, else empty |
| first_utc, first_utc_corrected, last_utc_corrected | text | first / last member 4624 |
| member_count | int | number of member logons |
| member_logon_uids, member_logon_ids, member_logon_ids_hex, member_accounts, member_ports | text | `;`-joined, in member order |
| mixed_account | int | 1 if the members' accounts differ (ST-21) |
| protocol, rules | text | `winrm`, `rdp`, `smb_service`, `smb`, `none` (ST-22); `rules` = the distinct gate rules of the members, `;`-joined |
| chain_parent_count, chain_parent_hop_ids, multi_chain_parent | int / text / int | number of hops chained into this hop; their ids; 1 if more than one (ST-72, limitation L-ST2) |
| trigger_ids, is_seed, in_path | text / int | gate trigger rows of the members; 1 if at least one (ST-23); 1 if the hop is in a row of `paths.csv` |
| authentication_packages | text | of the members |
| confirm, confirm_event_uids | text | `kerberos_logonguid`, `service_admin_write`, both, or `none` (ST-47) |
| inside_gap_max_ms, prev_gap_ms, next_gap_ms | int | largest gap between members; gap to the neighbouring hops of the same target and source IP |
| gap_near_threshold, splits_at_1s, merges_at_3s | int | 1 if a gap lies in the review band; 1 if a 1 s gap would cut this hop; 1 if a 3 s gap would join it to a neighbour (ST-20) |
| service_install_count | int | installs attached to the hop; more than 1 is a sign of two hops in one group |
| shares_port_with_hops | text | other hops with a member on the same (source IP, source port) (ST-24) |
| followup_logon_uids, followup_logon_count | text / int | logons attached to this hop as follow-ups (ST-26); they are not members |
| candidate_count, best_tier | int, text | distinct candidate source sessions over all methods; best `confidence_tier` of its link rows |
| evidence_before_range, evidence_after_range | int | source evidence naming the target between 120 s and `LINK_LOOKBACK_S` before, and between `LINK_AFTER_S` and 30 s after: counted, never a candidate (ST-42) |
| supporting_span_ms | int | first to last attached artefact event (ST-34) |
| clock_unreliable, gate_clock_unreliable | int | the hop's own hosts and events (ST-02); the value inherited from the members' gate rows |

**`hop_artefacts.csv`** — one row per artefact attached to a hop (ST-30..ST-34): `hop_id, kind` (`share_burst`,
`service_install`, `winrm_host`, `winrm_91`, `rdp_connection`, `followup_logon`)`, member_logon_uid` (the member whose logon ID the
events carry; empty for an install with no 4697)`, logged_under_hop_id` (the hop of that logon ID; differs from
`hop_id` only for a burst moved by ST-32)`, method` (`logon_id`, `file_name_time`, `ip_time`, `port_reuse`)`, candidate_count,
time_delta_ms` (artefact start − hop first 4624, same host)`, supporting_span_ms, confidence_tier, event_uids,
names` (service name and binary file name, or the `.exe` file names of a share burst)`, untied_same_name_bursts`.

**`links.csv`** — one row per (hop, candidate source session, method), plus one `target_only` row for a hop with no
candidate (ST-40..ST-50).
| Column | Type | Meaning |
|---|---|---|
| link_id, hop_id | text | `<hop_id>-l<NN>` |
| method | text | `sysmon3_port`, `source_4648`, `cmdline_target`, `target_only` |
| session_methods | text | every method that found this session for this hop (the same on all rows of the session) |
| source_host | text | |
| source_session_id, source_session_id_hex | int / text | empty for `target_only` or an unresolved process |
| session_unresolved_reason | text | `no_sysmon1_in_window`, `system_process`; else empty |
| source_session_account, source_session_logon_type, source_session_logon_uid | | the session's own 4624 on the source host, if it is inside the window |
| account_match, account_match_members, account_match_member_count | text / int | `direct` / `4648` / `none`: best over the members; the value per member; how many members are `direct` or `4648` (ST-45) |
| name_check, name_check_names, name_check_event_uids | text | `match` / `no_match` / `no_names` (ST-46); the target-side names that matched; the command events they matched in |
| candidate_count | int | distinct candidate sessions of this hop **by this method** |
| candidate_count_all, candidate_count_account | int | distinct sessions over all methods; of those, sessions with `account_match` ≠ `none` |
| matched_member_count | int | members this method matched (port join: members whose port matched) |
| time_delta_ms, time_delta_raw_ms | int | this method's evidence event for this session that is nearest in corrected time to the hop's first member, minus that member's 4624; empty for `target_only` |
| supporting_event_uids | text | the source evidence events and the matched member uids |
| confidence_tier | text | A / B / C / D (ST-48), one value per (hop, session), repeated on its rows |
| link_rank, tie, rank_basis | int / text | order of the hop's candidate **sessions** (ST-50), repeated on a session's rows; `tie` = 1 if the first rank is shared; what decided the rank |
| target_only_reason | text | `source_host_unknown`, `source_host_no_logs`, `no_evidence_in_range` |
| clock_unreliable | int | 1 if the source or target host is `none` / `wide` / `stale`, or an event of the row was logged before a counted clock change |

**`hop_identity.csv`** — the identity inputs (ST-60..ST-64), one row per (hop, moving account, LSASS read on the
source host): `hop_id, account, source_host, move_utc_corrected, dump_event_uid, dump_utc_corrected,
dump_source_image, dump_account, gap_ms, order_margin_ms, order_ok, order_within_tolerance,
order_within_uncertainty, offset_unc_source_ms, offset_unc_target_ms, open_session_uids, open_session_types,
session_open_before_window, end_unknown_session_uids, not_applicable, clock_unreliable`. A hop with no LSASS read
on its source host has one row per account with empty dump columns. A hop with no known source host, or a
machine-account member, has one row with `not_applicable` = `source_host_unknown` / `machine_account`.

**`paths.csv`**, **`path_edges.csv`** and **`path_nodes.csv`** — candidate paths (ST-70..ST-74).
`paths.csv`: `path_id, hop_ids` (time order)`, hosts` (in hop order)`, n_hops, seed_trigger_ids` (of all its
seeds)`, merged_from` (the maximal chains it was built from, ST-73)`, isolated` (1 if it has one hop and no edge)`,
edge_types` (`session` / `host_time` counts)`, shared_source_session_with, shared_event_with` (notes: other paths
that share a source session or an event; never a merge, ST-73).
`path_edges.csv`: `path_id, from_hop_id, to_hop_id, link_type` (`session` | `host_time`)`, time_delta_ms`
(to-hop first member − from-hop first member, corrected)`, order_within_tolerance, clock_unreliable`.
`path_nodes.csv`: `path_id, hop_id, role` (`target_logon`, `artefact`, `source_evidence`, `source_session_event`,
`target_session_event`)`, context` (1 for session events and follow-up logons, ST-71)`, host, session_id,
event_uid, link_id`.

**`stats.json`**, **`report.md`**, **`run_info.json`** — counts per file; hops per protocol and tier; per protocol
the number of hops linked by 0, 1, 2 and 3 methods; `target_only` reasons; hops in no path (ids); follow-up logons attached (ST-26); chain edges per link type; hops with
`gap_near_threshold`, counted apart for user endpoint → endpoint hops; system-session candidates excluded; events
refused by the window rule; parameters; DB hash before and after.

## 4. Rules
| ID | Rule | Source |
|---|---|---|
| ST-00 | **Allowed trial.** Refuse per §2 before reading any event. | 02_gate GT-00; 08 CO-17; review 08 SF-8 |
| ST-01 | **Window.** An event whose corrected time is outside the trial window is never a hop member, an artefact, source evidence or a path node. The only exception is the identity look-back of ST-63. Such events are counted in `stats.json`, never listed. | PLAN 7.7; decision 039 |
| ST-02 | **Corrected times** for every cross-host comparison; both times written. `clock_unreliable` = 1 on a row when a host of the row is `none`, `wide` or `stale`, or an event of the row was logged before a counted clock change on its host. `gate_clock_unreliable` carries the gate's value, which is also 1 for every row of a trial whose window-edge host is unreliable. The two are kept apart so the first stays a signal. | 08 CO-09, CO-15; decision 043; review ATK-12 |
| ST-03 | **Remote logons** = the anchors of `triggers.csv` plus the rows of `unmatched_remote.csv`. Nothing else starts a hop. Each remote logon is a member of exactly one hop or a follow-up logon of exactly one hop (ST-26). | 02_gate GT-14, GT-15 |
| ST-04 | **No threshold, nothing dropped.** Every hop and every candidate link is written. Every path is written. A hop that ends in no path is still in `hops.csv` with `in_path` = 0 and is listed in `stats.json`. | Correction J, G.4; review ATK-04 |
| ST-05 | **Near duplicates.** Rows the gate flags `near_duplicate` (same host, channel and record ID, different uid) count as one event: one hop member, one piece of evidence. All uids are kept in the uid columns. | 02_gate GT-18; review ATK-14 |
| ST-10 | **Sessions per host.** A session is (host, logon ID, boot epoch): opened by a 4624 of any type, closed by a 4634 or 4647 with that logon ID in `target_logon_id`, or by the next boot. **A boot (047):** boot events of the same kind (startup: System 41, 6005, 6008; shutdown: 1074, 6006) at most `BOOT_GROUP_S` apart are one restart; a clean restart (shutdown group, then startup group) has one boundary, at the shutdown group's last event; a startup group with no shutdown group before it starts its epoch at its first event (047, amended 2026-11-14); no single event is required. A process belongs to the session of its Sysmon 1 `session_id` (the Sysmon LogonId); a 4688 process to its `target_logon_id` when present and non-zero, otherwise its `subject_logon_id` (047). | PLAN 7.2; handoff §9.1; review §1; 047 |
| ST-11 | **Process trees.** Sysmon 1 rows are linked by `process_guid` / `parent_process_guid`. A Sysmon 3, 10 or 11 belongs to the process with its `process_guid` when a Sysmon 1 for it exists; no rule requires that it does. A Sysmon 1 and a 4688 of one process (same host, `process_id`, \|Δt\| ≤ `PROCESS_COLLAPSE_S`) count once. | PLAN 7.2; spec 00 LC-04f |
| ST-20 | **Hop groups (IN-01).** Remote logons with the same target host and the same normalised source IP, taken in time order, form one hop while each gap to the previous logon is ≤ `GROUP_GAP_S`. A larger gap starts a new hop, unless ST-26 attaches the new group to the hop before it. A logon with a blank IP is a hop of its own. The row records every member uid and logon ID, the largest inside gap, the gaps to the neighbouring hops, `gap_near_threshold` (a gap inside `GROUP_REVIEW_BAND_S`), `splits_at_1s`, `merges_at_3s` and `service_install_count`. **The value is frozen (044 (b)):** a trial whose gaps fall in the band gets the same rule and the flags, never its own value. | IN-01 items 1, 2; §10.2; 044 (b) |
| ST-21 | **Account is never a grouping key.** A group may hold several accounts (`mixed_account`); every account check is made per member. | Correction I; decision 013; IN-01 item 3; §10.2 (s06-smb-1) |
| ST-22 | **Protocol** of a hop, from the gate rules of its members, first that applies: R8 → `winrm`; R5 → `rdp`; R6 → `smb_service`; R4 → `smb`; else `none`. | 02_gate GT-10..13; spec 00 LC-04f |
| ST-23 | **Seeds (owner 2026-11-13, Q13).** A hop with at least one gate trigger row is a path seed. A hop with only unmatched logons is kept in `hops.csv`, linked like any other, flagged (`is_seed` = 0, `in_path` = 0) and listed in `stats.json`. It does not seed a path and is not added to one by chaining either (ST-72 chains seeds only; owner confirmed 2026-11-13). | PLAN 7.5 ("candidate paths from triggers"); owner Q13 |
| ST-24 | **Shared source port.** A (source IP, source port) pair may carry several hops (one SMB connection reused for minutes). The port is never a grouping key; hops that share a port are listed in `shares_port_with_hops`. The only use of a shared port is ST-26. | IN-01 "related"; §10.2 |
| ST-26 | **Follow-up logons (owner 2026-11-13, Q10).** A group with no gate trigger row is **not a hop** when (i) the hop before it with the same target host and source IP is a seed, (ii) every member's source port is a member port of that hop, and (iii) its first logon is at most `FOLLOWUP_MAX_S` after that hop's last member (same host clock). Its logons are attached to that hop as `followup_logon` artefacts (`method = port_reuse`, `context`). They are not members: they add no links, no identity rows and no protocol, and their own source evidence is not linked. Development: 3 groups (§10.7). Without condition (i) the port rule would also take 11 machine-account dc01 groups that follow other untriggered groups. | owner Q10; §10.7 |
| ST-25 | **Evaluation match (T7.6).** A key hop matches a hop group when the key's target 4624 is any member. | IN-01 item 4 |
| ST-30 | **Share bursts (IN-02).** The 5145 and 5140 events of one member logon ID (same host, `subject_logon_id` = the member's logon ID, at or after its 4624) are cut into bursts: a gap > `BURST_GAP_S` starts a new burst. Only 5145 carries a file name. | IN-02 item 1; §10.3; review §1 |
| ST-31 | **Burst attachment.** A burst belongs to the hop of its own logon ID (`method = logon_id`, tier A) unless ST-32 ties it to an install of another hop. Every row records `time_delta_ms` and `supporting_span_ms`, so a burst far from its hop's logon is visible. | IN-02 items 1, 3 |
| ST-32 | **Copy ↔ install tie.** A service install (4697 and/or 7045, paired as 02_gate GT-12) with binary file name F is tied to a share burst on the same host that holds a 5145 whose `relative_target_name` file name equals F (case-insensitive), where the burst's last such write is at or before the install and at most `COPY_INSTALL_S` before it. `method = file_name_time`, tier B, `candidate_count` = number of bursts that match; **every matching burst is attached**, none is chosen. The install belongs to the hop of the 4697's logon ID (tier A). A tied burst is attached to **the install's hop**, also when it was logged under another hop's logon ID; `logged_under_hop_id` keeps that hop. A same-name burst outside `COPY_INSTALL_S` is not tied and is listed in `untied_same_name_bursts`. A 7045 with no 4697 is attached through this tie only; with no tie it is listed as unattached. | Correction I ("7045 by time + binary file name"); IN-02 items 2, 4; §10.3; review ATK-10 |
| ST-33 | **Other artefacts.** `wsmprovhost` Sysmon 1 whose `session_id` is a member logon ID (or its linked ID, which is never set in the development data); WinRM 91 and inbound 3389 Sysmon 3 as the gate paired them. | 02_gate GT-11, GT-13; review §1 |
| ST-34 | **Span.** `supporting_span_ms` = first to last event of an artefact row, and of all artefacts of a hop. **Computed by the stitcher; the gate is not changed (owner 2026-11-13, Q12).** The artefact events come from the trigger rows' `supporting_event_uids` in `triggers.csv` and from the DB rows the stitcher attaches (ST-30..33); `supporting.csv` lists only `R1_lsass`, `R3_explicit` and `R8_parent` rows and holds no share or service event. | IN-02 item 3; owner Q12 |
| ST-40 | **Source host** = the lab host that owns the hop's source IP. An unknown, blank or unrecognised link-local source gives a `target_only` row (`source_host_unknown`); a source host with no logs in the DB gives `source_host_no_logs`. | decision 013; §10.4 |
| ST-41 | **Method `sysmon3_port` (tier A where logged).** A Sysmon 3 on the source host with `initiated` = 1, destination IP = the target's IP, `source_port` = a member's port (> 0; port 0 never joins) and \|Sysmon 3 − that member's 4624\| ≤ `PORT_JOIN_S` on corrected times. Its `process_guid` gives the Sysmon 1 and that gives the session. The join is made per member; one Sysmon 3 may match several members and members of several hops. `candidate_count` counts distinct **sessions**; `matched_member_count` counts members. A Sysmon 3 whose process has no Sysmon 1 inside the window gives a row with an empty session and `session_unresolved_reason`; it is never dropped. | Correction I; decisions 005, 014, 015; IN-01 item 5; review ATK-13 |
| ST-42 | **Method `source_4648`.** A 4648 on the source host whose target fields name the target (host name forms or IP, boundary-aware), with corrected time in **[first member − `LINK_LOOKBACK_S`, last member + `LINK_AFTER_S`]**. Session = its SubjectLogonId. Evidence of ST-42 or ST-43 that names the target outside this range but within 120 s before or 30 s after is counted in `evidence_before_range` / `evidence_after_range` and is never a candidate. | decision 013; spec 00 LC-04h; 044 (b) |
| ST-43 | **Method `cmdline_target`.** A Sysmon 1 or 4688 on the source host whose command line names the target (same matching, encoded PowerShell decoded for matching only), in the same time range. Session = its session. Any command that names the target counts, whatever it does. | decisions 011, 013; spec 00 LC-04 |
| ST-44 | **Candidates are sessions.** Each (hop, session, method) is one row. System sessions (0x3e4, 0x3e5, 0x3e7) are not candidates; they are counted in `stats.json`. | decision 013; handoff §9.1 |
| ST-45 | **`account_match`, per member:** `direct` if the candidate session's own account equals the member's account; `4648` if not, but a 4648 of that session naming the target used the member's account as credentials; else `none`. Never a filter. The row keeps the value per member and the number of members matched, because in a mixed-account hop the best value alone cannot tell two sessions apart. | Correction I; decision 013; review ATK-02 |
| ST-46 | **`name_check` (owner 2026-11-13; 044 (a)).** `match` when a file or service name of the hop's own target-side artefacts (5145 `.exe` file name, service name, service binary file name) appears, boundary-aware and case-insensitive, **in a command line that is this session's own ST-43 evidence for this hop**; `no_match`; `no_names` when the hop has no such artefact. It reads the same command lines as ST-43, so **it is not independent evidence**: it is never a method, never a confirmation, never raises `candidate_count`, and **never changes the tier**. It may order candidates that are otherwise equal (ST-50). It cannot help when two hops come from one session, or for WinRM hops (no names). | owner 2026-11-13; 044 (a); §10.4; review ATK-08 |
| ST-47 | **Confirmation.** `kerberos_logonguid` when a member's `logon_guid` equals the `logon_guid` of a dc01 4769 (uids recorded). It confirms account and target service; it never finds the source session. NTLM hops have none. `service_admin_write` when the hop has an ST-32 tie. | Correction I; decision 015 |
| ST-48 | **Link tier (`confidence_tier`), per (hop, session).** **A:** `sysmon3_port` found this session and no other. **B:** found by `source_4648` or `cmdline_target`, `account_match` is `direct` or `4648`, and it is the hop's only such session over all methods. **C:** as B but the hop has more than one such session; or `sysmon3_port` found several sessions. **D:** `target_only`, or `account_match` = `none`. A hop whose members all have port 0 is at most B. The tier uses the account, as decision 013 states; the account is still never a filter, and every candidate row is written. | CLAUDE.md cross-host link; decisions 013, 015; spec 00 LC-04g |
| ST-49 | **`target_only`.** A hop with no candidate keeps one row, tier D, `candidate_count` 0, with the reason. It is never dropped and still gets its identity inputs. | decision 013 |
| ST-50 | **Order of a hop's candidate sessions** (for path assembly, never for dropping): tier; then account-consistent (`direct` and `4648` rank **equal**) before `none`; then `name_check` = `match` (tie-break only). Sessions still equal stay equal: `tie` = 1 and all of them are used. Time distance is not a tie-break (clock residuals of 1.5 s and more, §10.8; OPEN Q14). `rank_basis` says what decided. | owner 2026-11-13; 044 (a); review ATK-02, ATK-03 |
| ST-60 | **Identity input.** For every hop, `target_only` included, and for each member account: the moving account is the member's 4624 account, the source host comes from the IP, the move time is that account's first member 4624. The linked session is not used. A machine account, or a hop with no known source host, gets a row with `not_applicable` set, so the missing value is explicit. | CLAUDE.md identity input; decision 013; review ATK-04, ATK-09 |
| ST-61 | **LSASS reads** = the `R1_lsass` rows of `supporting.csv` on the source host. The stitcher lists each one with its source image and account. Which of them count as the credential-access event is not decided here (OPEN Q9). | Correction K; 02_gate GT-16 |
| ST-62 | **Order.** `order_margin_ms` = move − (dump − `ORDER_TOL_S`), on corrected times. `order_ok` = margin ≥ 0 (decision 014). `order_within_tolerance` = \|move − dump\| < `ORDER_TOL_S` (decision 014). `order_within_uncertainty` = \|`order_margin`\| < max(`offset_unc`(source) + `offset_unc`(target), `ORDER_UNC_FLOOR_S`); a `none` or `stale` host sets it. **Flag only: it never changes `order_ok` (044 (c)).** | decision 014; spec 08 §4.1 item 7, Q12; 044 (c) |
| ST-63 | **Open sessions and the look-back.** A session of the moving account on the source host is open at the dump when its 4624 is at or before the dump and it is not closed before it (ST-10), on the source host's own clock. System logon IDs and machine accounts are excluded. For this check **only**, the session's opening 4624, its 4634 / 4647 and the host's boot events may lie before the trial window (`session_open_before_window` = 1). None of them becomes a member, artefact, source evidence or path node. A session with a Security log clear (1102) between its opening and the dump is listed in `end_unknown_session_uids` and is **not** counted as open by the stitcher. | Correction K; decision 039; spec 00 LC-08; review ATK-05 |
| ST-64 | **The stitcher writes facts, T9 computes the value.** One row per (hop, account, LSASS read). | PLAN 9.3 |
| ST-70 | **Seeds start paths.** Every seed hop starts a candidate path. A hop with no trigger is in no path (ST-23). | PLAN 7.5; owner Q13 |
| ST-71 | **Nodes of a hop:** its member logons; its attached artefacts; the source evidence events of its first-ranked sessions; and, marked `context` = 1, events of processes in the members' sessions on the target, and events of processes of a first-ranked source session **only when its tier is A or B and only at or before the hop's last member**. A tier C or D link gives no source-session events. Node events are path content for T8 / T9; **they never merge paths** (ST-73). | PLAN 7.2, 7.5; review ATK-01; owner Q7 |
| ST-72 | **Chaining (owner 2026-11-13, Q6).** Two seed hops H1 → H2 are chained when H2's source host is H1's target host and H2 starts after H1: H2's first member 4624 ≥ H1's first member 4624 − `ORDER_TOL_S` on corrected times (a cross-host comparison, decision 014; within ±`ORDER_TOL_S` the edge has `order_within_tolerance` = 1). Link type **`session`** when one of H2's first-ranked tier A or B source sessions is a member logon ID of H1; otherwise **`host_time`**, the weaker type. **A hop whose logons are all machine accounts takes no part in chaining** (owner 2026-11-13, Q15 (b), as Correction K excludes machine accounts from identity); it is still a seed and its own path. Every edge is written to `path_edges.csv` with its type. **A hop with more than one chain parent** gets `multi_chain_parent` = 1 and lists its parents (owner Q16; limitation L-ST2). Development: 2 edges, both `host_time`, both into s05-h2 (from s05-h1, 118.8 s, and from background s05-t1, 450.8 s); 0 `session` edges; `s05-p1` is the only key path built by chaining (§10.7). | owner Q6, Q15, Q16; §10.7 |
| ST-73 | **Paths and merging (owner 2026-11-13, Q7).** A candidate path is a maximal chain of seed hops. Maximal chains that contain the same hop are merged (the locked "merge paths that share nodes", with the hop as the node; owner Q16 (a)); `merged_from` lists the chains. **Nothing else merges paths:** a shared source session, a shared evidence event or shared context events never merge two paths; they are recorded as notes (`shared_source_session_with`, `shared_event_with`). | Correction J; PLAN 7.5; owner Q7 |
| ST-74 | **Isolated paths are kept.** A path that shares nothing with any other, including a single `target_only` seed, is written like every other path. | Correction G.4 |

## 5. Parameters
| Name | Value | Why | Sensitivity test? |
|---|---|---|---|
| `GROUP_GAP_S` | **2 s (044 (b))** | user endpoint → endpoint hops: largest gap inside one hop 1.33 s (s03_t01, no key), smallest gap between two key hops 2.47 s (s04 A → B); margin 0.67 s below, 0.47 s above, **one observation on each side**. For endpoint → dc01 logons there is no margin: gaps run through 2 s (1.93 … 2.12 s) (§10.2) | hops at 1 / 2 / 3 / 5 s; trials whose hop count changes between 1.5 and 3 s |
| `GROUP_REVIEW_BAND_S` | 1.0–3.0 s | flags a hop whose inside or neighbour gap is near the threshold; counted apart for user endpoint → endpoint hops | no |
| `BURST_GAP_S` | 5 s | the only multi-burst user session (s07) is the same at 1, 5 and 30 s; one case (§10.3) | 1 / 30 s |
| `COPY_INSTALL_S` | 10 s | nearest copy 50–182 ms before the install in 6 of 6 (§10.3) | 2 / 30 s |
| `PORT_JOIN_S` | 5 s, corrected times | decision 014; measured \|Δ\| ≤ 2.09 s corrected (§10.5) | 2 / 5 / 10 s |
| `LINK_LOOKBACK_S` | **30 s (044 (b); amends 014's 120 s)** | widest evidence of a hop −10.51 s, of a follow-up group −15.50 s: 14.5 s to spare. At 120 s one hop is held only by an earlier hop's evidence 86 s back, and one candidate with `account_match` none appears at −92 s (§10.4, §10.5) | 30 / 120 s |
| `LINK_AFTER_S` | **15 s (044 (b), owner's choice; amends 014's 10 s)** | latest evidence a hop depends on +6.75 … +7.15 s (s06-smb-1): 7.85 s to spare; results at 10 s and 30 s are identical. It absorbs clock residual; it is not causal evidence (§10.8) | 5 / 10 / 30 s |
| `ORDER_TOL_S` | 5 s | decision 014 | – |
| `ORDER_UNC_FLOOR_S` | **2.5 s (044 (c))** | reported `offset_unc` (0.001–0.64 s in s06_t00) is below the residual seen there (≥ 1.55 s, §10.8); 2.5 s is half the tolerance, the same reasoning as spec 08 `MAX_LOO_SHIFT_S` | report flagged hops at 0 / 2.5 / 5 s |
| `FOLLOWUP_MAX_S` | **30 s (owner 2026-11-13, Q10)** | the 3 follow-up groups start 9.6–11.9 s after their hop's last member; the same 3 at 15, 30, 60 s and unbounded (§10.7). 30 s leaves 18 s and matches the look-back | 15 / 60 s |
| `PROCESS_COLLAPSE_S` | 2 s | spec 00 LC-04f | no |
| `BOOT_GROUP_S` | **120 s (047, owner 2026-11-13)** | widest spread inside one restart 40.9 s (ep-01 41 → 6005); closest separate same-kind boot events 383.6 s (shutdowns); no t00 key result changes against the literal rule (13 of 13 key open sessions) | no |
| `LAB_HOST_IPS`, `SYSTEM_LOGON_IDS` | as `src/gate/params.py` | one definition | no |

**Freeze.** The values are chosen on the nine development trials and are not changed per trial. A test trial that
falls outside a margin is reported with its flags and counts; T10 reports results with and without flagged hops.

## 6. Edge cases
| Case | Where it occurs | Expected behaviour | Test ID |
|---|---|---|---|
| Two hops 2.47 s apart, same source and target | s04_t00 A / B | two hops; `gap_near_threshold` = 1 and `merges_at_3s` = 1 on both | STA-02 |
| Five logons of one hop, largest gap 1.33 s | s03_t01 (WinRM) | one hop; `splits_at_1s` = 1 | STA-02 |
| Two installs in one hop | not in current data (would follow from two hops under 2 s apart) | one hop, `service_install_count` = 2, counted in `stats.json` | STT-02 |
| Mixed accounts in one hop | s06_t00 s06-smb-1, s06_t01 | one hop, `mixed_account` = 1, `account_match` per member | STA-03 |
| Copy logged under an earlier hop's logon, 95.3 s later | s07_t00 path Y | burst attached to Y by `file_name_time`; not to X | STA-04 |
| Install with no file copy | s06 `BenignMon` (both trials) | install attached by logon ID; no tie | STA-04 |
| Two same-name bursts before one install | not in current data | both attached, `candidate_count` 2 | STT-03 |
| Copy 12 s before its install | not in current data | not tied; listed in `untied_same_name_bursts` | STT-03 |
| Two candidate sessions for each of two hops, each the other's | s04_t00 (A lists B's session at +3.05 s, B lists A's at −1.87 s) | both rows written; the account-consistent one is tier B and first, the other tier D | STA-05 |
| Two account-consistent sessions for one hop (two sessions of one account; or a desktop session `direct` and an agent session `4648`) | not in current data | both tier C, equal rank, `tie` = 1, both used; no session events as nodes | STT-08 |
| Evidence only far back (another hop's command to the same target) | s06_t00 s06-smb-1 at −86 s; s02_t01 05:34:09 at −92 s | not a candidate; `evidence_before_range` > 0 | STA-06 |
| Hop linked only by evidence after its logon | s06_t00 s06-smb-1 (+6.75 … +7.15 s) | linked (inside +15 s); `time_delta_ms` positive, visible | STA-07 |
| No Sysmon 3 for a WinRM hop | s06_t00 ep-01 → ep-03 | no tier A; linked by 4648 and command line (tier B) | STA-05 |
| Sysmon 3 whose process started before the window | not in current data | row with empty session and `session_unresolved_reason` | STT-04 |
| Logons 11–13 s after a WinRM hop on its ports | s06_t00, s06_t01 | follow-up logons of that hop (ST-26), not a hop | STA-02 |
| Two hops chaining into one hop | s05_t00 (s05-h1 and background s05-t1 → s05-h2) | two `host_time` edges; one merged path {s05-t1, s05-h1, s05-h2}; s05-h2 has `multi_chain_parent` = 1 with both parents listed (ST-73, L-ST2) | STA-09 |
| Hop into a host, later machine-account logons from that host to dc01 | s02_t01, s05_t00, s06_t01 (7 edges before Q15) | no edge: machine-account-only hops take no part in chaining (ST-72, Q15 (b)); each stays its own path | STA-09 |
| Two hops of one agent session | s07 X and Y; the S06 hops | separate paths; `shared_source_session_with` set (ST-73) | STA-09 |
| Discovery command naming dc01 before a machine-account logon to dc01 | not in current data (0 candidates for dc01 in every trial) | candidate row with `account_match` none, tier D, no session nodes | STT-06 |
| Source host has no logs | s07_t00 ep-03 → dc01 (5 groups) | `target_only`, `source_host_no_logs` | STT-09 |
| User hop with a blank or unrecognised link-local source | not in current data (blank IPs are machine accounts to dc01) | each logon its own hop, `target_only`, identity row `not_applicable` | STT-09 |
| Raw-time port join fails | s03_t01 (−5.3 … −7.0 s), s06_t01 (−16.7 … −18.9 s) | joined on corrected times (\|Δ\| ≤ 0.9 s) | STA-07 |
| Corrected source evidence later than the target logon | s06_t00, s05_t00, s03_t01, s06_t01 (§10.8) | linked inside the range; both deltas written | STA-07 |
| `wide` host | s06_t01 ep-03 | `clock_unreliable` = 1 on rows that touch ep-03; an ep-01 → ep-02 hop has 0 and `gate_clock_unreliable` = 1 | STT-12 |
| Session opened and closed before the window | not in current data | not open; none of its events in any other file | STT-11 |
| Logon ID reused after a boot before the window | not in current data | the boot epoch separates the two sessions | STT-11 |
| Identity facts give 1 for a hop whose only candidate is another account's session | s02_t01 05:34:09 at a 120 s look-back | by design: identity does not use the link (decision 013); stated in the report | STA-08 |
| Near-duplicate 4624 | not measured | one member, both uids kept | STT-02 |
| Track A of S04 run from an excluded workstation | S04 ×10 (02_gate §6) | the gate excludes it; the stitcher never sees it | – |
| S01 trial | not ingested | refused (no offsets file) | STT-01 |

## 7. Acceptance tests
Unit (synthetic rows, STT):
| ID | What must be true |
|---|---|
| STT-01 | Each refusal of §2 stops the run and writes nothing; an S01 trial without an offsets file is refused. |
| STT-02 | Grouping: gaps of `GROUP_GAP_S` and `GROUP_GAP_S` + 1 ms; two accounts in one group; the same port in two groups; a blank-IP logon alone; **groups at a larger gap are unions of groups at a smaller gap**; a group whose ports are all the preceding seed hop's ports, 11 s later, is attached as follow-up logons, and the same group after an untriggered group, with one new port, or 31 s later, is a hop; the flags `splits_at_1s`, `merges_at_3s`, `service_install_count`; a near-duplicate logon is one member. |
| STT-03 | Bursts and the copy ↔ install tie: a copy under another hop's logon ID moves to the install's hop; two bursts with the same file name are both attached with `candidate_count` 2; a copy after the install never ties; a copy outside `COPY_INSTALL_S` is listed, not tied. |
| STT-04 | Port join: per member; port 0 and NULL never join; \|Δ\| = `PORT_JOIN_S` joins, + 1 ms does not; computed on corrected times (a raw gap of 18 s with an offset of −18 s joins); a process with no Sysmon 1 gives a row with an empty session. |
| STT-05 | 4648 and command-line methods: name boundary cases (`.2` vs `.22`); the edges of [−`LINK_LOOKBACK_S`, +`LINK_AFTER_S`]; evidence at −60 s is counted, not a candidate; one process logged as Sysmon 1 and 4688 counts once. |
| STT-06 | `account_match` is never a filter: a candidate with `none` is written; values per member in a mixed-account hop. |
| STT-07 | **Blanking `name_check` changes only `link_rank`, `tie` and `rank_basis`**: tier, method, `candidate_count` and `confirm` are identical. A name inside a longer file name does not match; a command that is not the row's own evidence does not match. |
| STT-08 | Tiers A / B / C / D on their minimal cases; port-0 hop at most B; `direct` and `4648` rank equal; two account-consistent sessions give tier C and `tie` = 1. |
| STT-09 | `target_only` rows with each reason; the hop still has identity rows, with `not_applicable` where it applies. |
| STT-10 | Kerberos confirmation by LogonGuid only; a zero GUID never confirms; it never sets the source session. |
| STT-11 | Identity: session closed before the dump → not open; boot between → not open; a session opened between two startup events of one restart (≤ `BOOT_GROUP_S` apart) stays open (047); a 4624 logged after a shutdown group and before the next startup event belongs to the new boot (047); a 4688 process belongs to its target logon ID when present and non-zero (047); opened and closed before the window → not open; opened before the window and still open → used, flagged, and absent from every other file; a log clear between → `end_unknown`, not open; changing the linked session changes no identity row. |
| STT-12 | An event outside the window is in no row of any file (ST-01), the ST-63 look-back apart; `clock_unreliable` and `gate_clock_unreliable` as ST-02. |
| STT-13 | No output file contains any substring of length ≥ 12 of any `command_line` value of the DB other than a target-side name; `src/stitch` opens nothing under `ground_truth/`; DB hash unchanged; two runs byte-identical. |
| STT-14 | Paths: an isolated `target_only` seed is in `paths.csv`; a hop in no path has `in_path` = 0 and is in `stats.json`; a tier D link adds no source-session nodes. Chaining: a `host_time` edge when the second hop's source is the first hop's target and it starts after the first; no edge when it starts more than 5 s before; a `session` edge when its first-ranked tier A / B session is a member logon of the first hop; two chains that share a hop are one path and that hop has `multi_chain_parent` = 1 with both parents listed; a hop whose logons are all machine accounts gets no edge; a hop with no trigger gets no edge; two hops that share only a source session or an event are two paths with the note set. |
| STT-15 | Order flags: a move 4 s inside the boundary with uncertainties 1.76 s and 2.97 s → `order_within_uncertainty` = 1 and `order_ok` unchanged; uncertainties of 1 ms → the floor applies. |

Real data (development trials only; the tests read the keys, `src/stitch` never does):
| ID | What must be true |
|---|---|
| STA-01 | Counts: every remote logon of the gate files is a member of exactly one hop or a follow-up logon of exactly one hop; hop and link counts equal `stats.json`. |
| STA-02 | On the six t00 trials no two key hops share a hop group, and each key hop's group has the member count of the input-notes table (3 / 5 / 3 / 3 / 1 / 3 / 5 / 1 / 3 / 5 / 3 / 1 / 3 / 2 / 1). |
| STA-03 | s06-smb-1: one hop with both accounts; the key's 4624 is a member. |
| STA-04 | s07_t00: path Y's hop has the `Ypay.exe` copy and its own install; path X's hop has only its own copy. Each of the 6 installs with a copy has exactly one tied burst. |
| STA-05 | **T7.6 link check:** for each of the 11 keyed hops that have a key source session, that session is among the hop's first-ranked sessions; reported per hop: methods, tier, `candidate_count`. S04: track A's first-ranked session is not track B's, and the reverse. WinRM tier A is reported apart from tier B. **Tier B on SMB is agreement with the command-line rule the key also uses, not accuracy** (spec 07 §8). The only check that does not use the key: where the port join and the command line both find a session (6 WinRM hops), they find the same one. |
| STA-06 | The 4 background key hops are `target_only`; s06-smb-1 and the s02_t01 05:34:09 group report `evidence_before_range` > 0. On t01 trials counts are reported without a right/wrong label. |
| STA-07 | Sensitivity report at the §5 alternative values, and the kill criteria of 044: no keyed hop needs evidence outside [−30 s, +15 s]; link results at 15 s and 30 s are equal. Decision 014: port-join results at 5 s vs 10 s. |
| STA-08 | Identity inputs: for the 15 keyed hops the facts give the key's `identity_expected`; no hop is within `ORDER_TOL_S` of a dump or inside the uncertainty band. |
| STA-09 | The attack hops of every development key are in `paths.csv` (PLAN T7 done-when). `s05-p1`: s05-h1 and s05-h2 are in one path joined by a `host_time` edge; that path also holds background s05-t1 and nothing else; s05-h2 has `multi_chain_parent` = 1 with parents s05-h1 and s05-t1. No other development trial has a chain edge. s07 X and Y are in two paths with `shared_source_session_with` set. |

## 8. OPEN questions and owner answers
| # | Question | Answer / options | Status |
|---|---|---|---|
| Q1–Q5 | Council 044: name check and the tier; look-back; "after" side; grouping gap; offset uncertainty and identity | **Owner 2026-11-13:** accepted, with the "after" side 15 s (10 s leaves 2.85 s, about the 2.5 s floor). Decision 014's window sentence amended to 30 s / 15 s, citing 044 | answered; 044 accepted |
| Q6 | Chaining hops into a multi-hop path | **Owner:** chain when the second hop's source host is the first hop's target host and it starts after the first hop; type `host_time`, weaker than a `session` link (ST-72). `s05-p1` is the only development key case | answered |
| Q7 | Which nodes merge two paths | **Owner:** never on a shared source session; paths join only through chaining; a shared session is a note (ST-73) | answered |
| Q8 | S01 has no offsets file (review 08 SF-8) | **Owner:** keep the refusal; fixed by operator times and an offsets file after the lab | answered |
| Q9 | Which `R1_lsass` rows count as the LSASS read for identity, and do `end_unknown` sessions count? On development data the values are the same either way (§10.6) | deferred to the T8 / T9 specs | **open** |
| Q10 | Logons 11–13 s after a WinRM hop on the hop's ports | **Owner:** context on the preceding hop, not separate hops (ST-26). `FOLLOWUP_MAX_S` = 30 s approved | answered |
| Q11 | Tier line for clock pairs (review 08 SF-9), record [045](../decisions/045-tier-rule-scope.md) | **Owner:** accepted; CLAUDE.md code rule worded accordingly | answered |
| Q12 | `supporting_span_ms` in the gate output | **Owner:** no gate change; the stitcher computes the span (ST-34) | answered |
| Q13 | Hops with no trigger | **Owner:** flagged and listed only; they do not seed paths. They are not added to a path by chaining either (owner confirmed) (ST-23) | answered |
| Q13b | May the look-back read a process start before the window, to resolve a port join's session (PLAN 7.7 allows identity only)? | **Owner:** no — decision 039 allows pre-window lookups for identity only; the row gets `session_unresolved_reason` | answered |
| Q14 | May time order break a tie between candidate sessions? | **Owner:** no | answered |
| Q15 | Chaining machine-account hops (9 edges as first written, 7 of them into or from machine-account dc01 groups) | **Owner:** (b) hops whose logons are all machine accounts take no part in chaining, as Correction K does for identity (ST-72). Recount: 2 edges | answered |
| Q16 | Merging chains that share a hop (s05: background s05-t1 and s05-h1 both chain into s05-h2) | **Owner:** (a) keep the locked merge rule; flag a hop with more than one chain parent and list the parents (ST-72, `multi_chain_parent`); stated as limitation L-ST2 (§9.1). No council | answered |

## 9. Out of scope
Sigma labels (T8). Scores, the IdentityCoherence value and ranking (T9). Evaluation metrics (T10). The clock offset
method (spec 08): the observations of §10.8 are evidence for review 08 SF-6 / SF-7 and **change nothing in the
clock step now**. RDP source linking on real data (no RDP trial ingested; no type 10 logon and no 3389 connection in
any development trial; ST-41 covers it on synthetic data only). Changing the gate. Test trials t02–t10.

### 9.1 Limitations stated by this spec
- **L-ST1 SMB source links.** For NTLM SMB hops the source session is found from a command on the source host that
  names the target (9 of 14 development groups; 2 of them also by a 4648; 5 have no candidate). The port join links
  none, because Sysmon did not log SMB and an SMB connection belongs to the kernel, and NTLM has no LogonGuid
  confirmation. A tier B link on SMB is agreement with the command-line rule the answer key also uses, not measured
  accuracy; it depends on tooling that names its target (L10, L11; decision 044).
- **L-ST2 Merged chains.** Chains that share a hop are merged (the locked merge rule), so a path can hold hops that
  belong to different movements. In s05_t00 the key path [s05-h1, s05-h2] lies in one path with background s05-t1,
  because both s05-h1 and s05-t1 reach ep-02 before s05-h2 leaves it. `host_time` chaining cannot tell which
  parent led to the next hop; the hop is flagged `multi_chain_parent` and its parents are listed so the reader and
  T9 can see it (owner 2026-11-13, Q16).
- **L-ST3 Values from nine trials.** `GROUP_GAP_S`, `LINK_LOOKBACK_S`, `LINK_AFTER_S`, `FOLLOWUP_MAX_S` and the
  uncertainty floor are chosen on the nine development trials, three of them without a key, and are frozen.

## 10. Measurements (development trials only, read-only, 2026-11-13)
Scripts with a hard allowlist of the nine development trials (s02–s07 t00; s02_t01, s03_t01, s06_t01); `s02_t02`
was refused when tried. DBs opened `mode=ro`; all nine SHA-256 unchanged. Outputs and the scripts:
`out/stitch_measure/`. Gate outputs for the three t01 trials were produced by the existing gate (no code change);
the six t00 rows of `data/trial_windows.csv` are byte-identical to before. t01 trials have no approved key, so
their numbers carry no right/wrong label. Times are corrected unless marked raw. Six numbers were re-derived by
the data-checker with independent SQL and match (review §1.2). Values are truncated, not rounded.

**What was measured and what the rules say.** Candidates were measured with 4648 and command line at
[−120 s, +10 s]; the chosen range is [−30 s, +15 s]. From the saved evidence times, the only difference is the
s02_t01 05:34:09 group, which has no candidate at 30 s (§10.4). The name check was measured as a case-insensitive
substring in the commands that name the target; ST-46 adds the boundary rule. An unreliable host with no offset
counted as uncertainty 0 in §10.6.

### 10.1 Gate rows
| trial | trigger rows (R4 / R6 / R8) | unmatched | supporting (R1 / R3 / R8 parent) | remote logons | blank IP | endpoint → dc01 (user / machine) | endpoint → endpoint | hop groups at 2 s | seeds |
|---|---|---|---|---|---|---|---|---|---|
| s02_t00 | 7 (7/0/0) | 83 | 17 / 18 / 0 | 90 | 2 | 30 / 55 | 3 | 25 | 4 |
| s02_t01 | 13 (12/1/0) | 57 | 6 / 36 / 0 | 70 | 4 | 25 / 37 | 4 | 26 | 10 |
| s03_t00 | 5 (4/0/1) | 72 | 4 / 23 / 0 | 77 | 4 | 24 / 44 | 5 | 19 | 3 |
| s03_t01 | 6 (5/0/1) | 77 | 6 / 29 / 0 | 83 | 7 | 13 / 58 | 5 | 21 | 4 |
| s04_t00 | 9 (7/2/0) | 72 | 4 / 18 / 0 | 81 | 4 | 22 / 48 | 7 | 21 | 5 |
| s05_t00 | 16 (14/1/1) | 113 | 15 / 51 / 0 | 129 | 4 | 53 / 63 | 9 | 41 | 10 |
| s06_t00 | 10 (7/1/2) | 105 | 4 / 49 / 1 | 115 | 7 | 43 / 51 | 14 | 36 | 7 |
| s06_t01 | 10 (7/1/2) | 64 | 4 / 37 / 2 | 74 | 7 | 7 / 47 | 13 | 26 | 6 |
| s07_t00 | 9 (7/2/0) | 83 | 10 / 37 / 0 | 92 | 7 | 27 / 52 | 6 | 26 | 6 |

- No R5 (RDP) row in any trial. Every trigger row is `gate_tier` A.
- The gate's `clock_unreliable` is 1 on all 74 rows of s06_t01, because a window-edge host (ep-03) is `wide`; it
  is 0 elsewhere.
- Hop groups cover logons from a lab source IP; blank-IP logons are single hops. 23 groups are user-account
  endpoint → endpoint groups (1, 2, 1, 1, 3, 3, 5, 4, 3 in table order), 21 of them seeds.

### 10.2 Grouping (IN-01)
Key hops merged into one group / key hops whose sibling logons are split, six t00 trials:
| grouping key | 1 s | 2 s | 5 s | 10 s |
|---|---|---|---|---|
| target + source IP | none / none | none / none | **s04 A + B** / none | **s04 A + B** / none |
| target + source IP + port | – | none / **9 hops split** | s04 A + B / 9 split | – |
| target + source IP + account | – | none / **s06-smb-1 split** | none / s06-smb-1 split | – |

- Inside the 23 user endpoint → endpoint groups the largest gap between two members is **1.328 s** (s03_t01
  WinRM, a trial without a key); on t00 it is 0.837 s (s05-h2). The smallest gap between two different key hops is
  **2.47 s** (s04 A's last logon → B's first). **One observation on each side.** At 1 s the s03_t01 group would
  be cut in two.
- **The margin holds for these 23 groups only.** Among endpoint → dc01 logons, gaps between consecutive logons
  run through 2 s without a break (1.926, 1.95, 1.987, 2.089, 2.105, 2.117, 2.123 s across the trials), so for
  those groups the cut is arbitrary and the review flag will fire often.
- Member counts and spreads of the input-notes table are reproduced.
- Mixed-account groups among user endpoint → endpoint hops: s06_t00 (s06-smb-1) and s06_t01 (06:23:59).
- (IP, port) pairs carrying more than one group: 2–6 per trial of 56–110. Examples: port 49734 for s04-t1, A and
  B; in s06_t00 and s06_t01 a two-logon Kerberos group 11.4 s / 13.0 s after a WinRM hop on that hop's ports.
- Grouping compares times on one host, so the clock correction does not move it.

### 10.3 Artefacts (IN-02)
- Service installs by a remote logon: 8 (s02_t01 1, s04_t00 2, s05_t00 1, s06_t00 1, s06_t01 1, s07_t00 2).
  Every one has both a 4697 and a 7045 (no 7045-only install).
- **Copy and install are under different logon IDs in 6 of 6 installs that have a copy.** Each has exactly one
  copy session; the copy's nearest write is 50–182 ms before the install.
- The two S06 installs (`BenignMon`) have no copy of the binary at all.
- User share sessions: 13 in total; **one** has more than one burst (s07_t00 `0x49cdfa`: 15 events, bursts at
  0 s and 95.3 s, two different `.exe` names), the same at burst gaps of 1, 5 and 30 s. The first share event is
  4–27 ms after the session's 4624.
- Machine-account share sessions on dc01 with more than one burst: 2–3 per trial.

### 10.4 Candidate links (groups at 2 s; port ±5 s)
User endpoint → endpoint groups, at the measured range [−120 s, +10 s] and at the chosen range [−30 s, +15 s]:
| protocol | groups | `sysmon3_port` | `source_4648` | `cmdline_target` (120 s / 30 s) | > 1 candidate session | `target_only` (120 s / 30 s) | Kerberos confirmed |
|---|---|---|---|---|---|---|---|
| SMB (NTLM), with or without a service | 14 | 0 | 2 | 10 / **9** | 2 | 4 / **5** | 0 |
| WinRM (Kerberos) | 7 | 6 | 7 | 7 / 7 | 0 | 0 | 7 |
| no artefact (Kerberos) | 2 | 0 | 2 | 2 / 2 | 0 | 0 | 2 |

- **SMB linking rests on the command line.** At the chosen range: 9 of 14 groups by the command line, 2 of them
  also by a 4648 (S06, both trials), **0 by the port join**, 5 `target_only` (the four t00 background logons and
  the s02_t01 05:34:09 logon). So 7 SMB hops have one signal, 2 have two, 5 have none.
- **Where two methods can be compared without the key** (the 6 WinRM hops with a port join), the port join and
  the command line find the same session in 6 of 6.
- Ambiguous (more than one candidate session): s04 A and s04 B, the same two sessions each (`0xd6398`, `0x17c46`).
  Each hop sees the other hop's command (A lists B's at +3.05 s, B lists A's at −1.87 s). `account_match` leaves
  one each (the key's). The name check also leaves one each (the same). No hop has two account-consistent
  sessions, so no tie has occurred and the tie-break is untested on real data.
- Name check = match for the key's session in 7 of 7 keyed SMB hops with a named artefact (s02-h1, s04 A and
  B, s05-h1, s06-smb-1, s07 X and Y); WinRM hops have no names.
- **s06-smb-1 at a 120 s look-back** has, besides its own evidence at +6.75 … +7.15 s, evidence of the earlier
  WinRM hop to the same target: a command at −85.81 s and 4648s at −84.9 … −76.3 s, all in the same agent
  session. With 120 s the hop is held by that evidence whatever the "after" side is; with 30 s it depends on the
  "after" side alone (5 s loses it, 10 s and more keep it).
- **s02_t01 05:34:09** (`admin_it`): at 120 s its only candidate is the `svc_backup` session from a command
  92.5 s earlier (`account_match` none, no name match). At 30 s it has none.
- The WinRM hop without a port join is s06_t00 ep-01 → ep-03: no Sysmon 3 with its ports exists.
- Against the t00 keys (11 keyed hops with a key source session): key session among the candidates **11 of 11**;
  the only candidate **9 of 11**; the only account-consistent candidate 11 of 11. The two that need the account
  are the S04 pair, where accounts coincide with sessions by lab construction (decision 013).
- Endpoint → dc01 groups (18–38 per trial): no candidate by any method in any trial; all Kerberos-confirmed.
  5 groups in s07_t00 have a source host with no logs (ep-03).
- Source evidence outside the trial window: 0 groups.

Sensitivity (user endpoint → endpoint groups):
| setting | effect |
|---|---|
| port join, corrected, ±2 / ±5 / ±10 s | 6 of 7 WinRM hops at all three; at ±10 s one follow-up group also joins (−9.4 s) |
| port join, raw, ±5 s | 3 of 7 (fails in s03_t01 and s06_t01; s03_t00 fails at ±2 s) |
| 4648 at ±2 / ±5 / ±10 s | loses 3 / 1 / 0 of the 11 groups that have one at [−120, +10] |
| look-back 30 s instead of 120 s | loses only the s02_t01 05:34:09 candidate |
| look-back 300 s | s03_t00 gets a second session (command at −173 s) |
| after 5 s, look-back 30 s | s06-smb-1 becomes `target_only` |
| after 10, 15 or 30 s, look-back 30 s | identical results |

### 10.5 Time gaps (source evidence − first member 4624, seconds)
| evidence | corrected | raw |
|---|---|---|
| port join, WinRM hops (25 matches) | −2.09 … +1.57 | −18.87 … −1.21 |
| nearest command, keyed hops | −6.40 (s07 X) … +6.75 (s06-smb-1) | −3.11 … +3.97 |
| nearest command, unkeyed t01 hops with their own artefact | −8.88, −2.54, −0.68, +0.10, +1.14 | −19.09 … −5.86 |
| nearest command, the two follow-up groups (the preceding hop's command) | −8.25 (s06_t00), −15.50 (s06_t01) | |
| whole command burst of a hop, widest | −10.51 (s02_t01 05:32:45) … +7.15 (s06-smb-1) | |

[−30 s, +15 s] holds every value above with 14.5 s and 7.85 s to spare. Outside it lie only another hop's
evidence (−76 … −86 s, s06-smb-1) and the −92 s candidate.

### 10.6 Identity inputs
- 23 user endpoint → endpoint groups: the facts give value 1 for 11 and 0 for 12. On the 15 keyed hops they equal
  the key's `identity_expected` (15 of 15).
- Dump-to-move gaps of the value-1 hops: 38.4 … 141.4 s. **No hop is within 5 s of a dump, and none within
  5 s + offset_unc(source) + offset_unc(target)** (largest sum of uncertainties 4.73 s, s06_t01 ep-01 + ep-03).
  The flag of ST-62 is therefore untested on real data.
- **No result needs a session opened before the window** (0 of 11).
- The s02_t01 05:34:09 `admin_it` logon has value 1 (an `admin_it` session open at the dump, 141 s before).
- Counting every `R1_lsass` row or only rows run by a non-system account gives the same values on these trials.
  R1 rows per host: 2–15, of which 0–4 by a user account (`rundll32`).

### 10.7 Paths
- Hops whose candidate source session is a member logon of an earlier hop: **0 of 23**.
- Hops whose source host is an earlier hop's target, later in time: 1 (s05 ep-02 → ep-03).
- Groups joined when every candidate source session counts as a shared node (measured): s04 A + B; s07 X + Y;
  s06_t00 four groups; s06_t01 four groups; s02_t01 two groups. By the first-ranked session only (read from
  `candidates.csv`): s04 A and B stay apart; s07 X + Y and the S06 groups still join (one agent session each).
- Seeds per trial: 3–10, of which 2–8 are endpoint → dc01 share logons with no source candidate. Each would be a
  single-hop `target_only` path.
- Non-seed user endpoint → endpoint hops: 2, both the follow-up groups that ST-26 now attaches to their hop, so
  none remains.
- **Follow-up rule (ST-26)**, measured on `hop_groups.csv`: 3 groups are attached: s06_t00 and s06_t01, two-logon
  `admin_it` groups 11.0 s and 11.9 s after the WinRM hop on that hop's ports; s05_t00, one machine-account group to
  dc01, 9.6 s after a seed group. The same 3 at 15, 30, 60 s and unbounded. Without condition (i) (the preceding
  hop is a seed) the port rule takes 14 groups: 12 machine-account dc01 groups (11 of them after untriggered
  groups) and the 2 user groups.
- **Chain edges (ST-72)** among seeds, by the owner's rule (source = earlier target, starts after it):
  9 edges, all `host_time` (0 `session`):
  - s05_t00 (4): s05-h1 → s05-h2 (118.8 s); background s05-t1 → s05-h2 (450.8 s); s05-t1 → an ep-02 → dc01
    machine-account group (7.6 s); s05-h2 → an ep-03 → dc01 machine-account group (197.0 s);
  - s02_t01 (4): each of the two ep-01 → ep-02 hops → two later ep-02 → dc01 machine-account groups (113–285 s);
  - s06_t01 (1): the ep-01 → ep-02 WinRM hop → an ep-02 → dc01 machine-account group 2.7 s later
    (`order_within_tolerance` = 1).
  Among user-account seeds only: 2 edges, both into s05-h2.
- **Recount after the owner's Q15 (b)** (hops whose logons are all machine accounts take no part; seeds only,
  Q13), read-only on `hop_groups.csv`: **2 edges in total**, both in s05_t00, both `host_time`: s05-h1 → s05-h2
  (118.8 s) and background s05-t1 → s05-h2 (450.8 s). The other eight trials have none. One hop has more than one
  chain parent: s05-h2 (parents s05-h1, s05-t1).
- **Paths under ST-73:** s05_t00 has one multi-hop path, {s05-t1, s05-h1, s05-h2}; it holds both hops of `s05-p1`.
  Every other seed in every trial is its own path. s07 X and Y and the S06 hops stay separate paths (shared source
  session recorded as a note).

### 10.8 Clock observations (evidence for review 08 SF-6 / SF-7; **the clock step is not changed**)
Source evidence later than the target logon it belongs to, on corrected times:
| trial | hop | evidence | corrected | raw | reported `offset_unc` (source / target) |
|---|---|---|---|---|---|
| s06_t00 | ep-01 → ep-02 WinRM | port-matched connection | +1.55 … +1.57 s | −1.21 s | 0.64 / 0.001 s |
| s06_t00 | s06-smb-1 | nearest command | +6.75 s | +3.97 s | 0.64 / 0.001 s |
| s05_t00 | s05-h1 | nearest command | +1.55 s | −0.34 s | 0.007 / 0.001 s |
| s03_t01 | ep-01 → ep-03 WinRM | port-matched connection | −0.88 … +0.82 s | −7.04 … −5.34 s | 1.14 / 0.04 s |
| s06_t01 | ep-01 → ep-03 WinRM | port-matched connection | −0.04 … +0.48 s | −18.87 … −18.35 s | 1.76 / 2.97 s |

- s07_t00 ep-02's offset estimate is +0.07 s (uncertainty 1.12 s); the same host on the same day is +2.68 s
  (s05_t00) and +2.10 s (s06_t00) (spec 08 §10.1).
- A connection cannot follow the logon it produced. The s06_t00 port value therefore bounds the error of that
  host pair's offset from below at 1.55 s, more than its reported uncertainty. For the command values this
  reading holds only if that command caused the logon, which the logs do not show.
- If the s06-smb-1 command did cause its logon, a keyed hop lies outside 5 s on corrected times; decision 014's
  kill criterion names that case. Recorded here for the owner; nothing is changed.
