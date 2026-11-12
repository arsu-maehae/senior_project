# Stage spec: 02_gate

**Owner:** <stage owner> · **Status:** approved (owner, 2026-11-11); attacker-reviewed; owner answers Q1–Q4 applied; §2.1 window rule and GTA-06 amended by the owner 2026-11-11 (decision 040); §2 refusals and IP normalisation, §3, §3.1 stats keys, §5, GT-02(c), GT-05, GT-11, GT-12, GT-13, GT-15, GTT-07, GTT-14..18 amended by the owner 2026-11-12 (decision 041); §2 columns, §3.1, §5 `WINRM_PAIR_S`, §6, GT-02(c), GT-05, GT-13, GTT-19, GTT-20 amended by the owner 2026-11-12 (decision 042); §2, §2.1, §2.2, §3, §3.1, §5, §6, GT-01, GTT-07, GTT-21, GTA-03, GTA-05, GTA-06, GTA-07 amended by the owner 2026-11-12 (T6b.2, decision 043: clock-corrected times) · **Last updated:** 2026-11-12

Decisions: [042](../decisions/042-gate-own-link-local-and-winrm-91-order.md) own IPv6 link-local addresses and WinRM 91 order (review F1, F4), [041](../decisions/041-gate-implementation-readings.md) implementation readings (owner answers 2026-11-12), [037](../decisions/037-gate-excluded-source-ips.md) excluded source IPs, [038](../decisions/038-gate-rule-choices.md) rule choices, [039](../decisions/039-gate-window-input-and-clock.md) window input and clock rule, [040](../decisions/040-trial-window-agent-tree-and-gta06-containment.md) window from the agent tree, GTA-06 containment. Review: [02_gate-spec-2026-11-11](../reviews/02_gate-spec-2026-11-11.md).

## 1. Purpose
The gate reads one trial database and marks the events that show one host being reached from another host over
the network: SMB share access, RDP, service install, WinRM. It is a cheap, deliberately noisy first pass (handoff
§7.1, Correction D): it only points the stitcher (T7) at the remote logons worth linking. It does not decide
whether a movement is an attack; a legitimate admin doing the same thing also triggers it.

## 2. Input contract
| Input | What is read | Notes |
|---|---|---|
| Trial DB | `data/processed/<scenario>_<trial>.sqlite3`, view `events_dedup`, opened read-only | One DB per trial (NF-09). The gate never writes to it (hash before = after). |
| Trial window | the trial's row in `data/trial_windows.csv` (section 2.1) | PLAN T6.4, decisions 026 and 039. **The gate never opens any path under `ground_truth/`.** |
| Parameters | `src/gate/params.py` | Section 5. |

Columns used: `event_uid, host, channel, event_id, record_id, event_utc, logon_type, source_ip, source_port,
destination_ip` (*added by the owner 2026-11-12, decision 041: the remote address of an outbound Sysmon 3*)`, destination_port, initiated, account_name, domain_short, target_logon_id, target_linked_logon_id,
subject_logon_id, session_id, machine_account, authentication_package, image, parent_image, share_name,
relative_target_name, service_name, service_image_path, target_image, granted_access, subject_account` (*amended by the owner 2026-11-12, decision 042*: the host's own machine account for evidence E2 of GT-05).
- Time: `event_utc` everywhere (Sysmon UtcTime, else record time; decision 010), compared as parsed UTC instants, never as text. Section 2.2 says which times (raw or corrected) may be used.
- IP addresses (*amended by the owner 2026-11-12, decision 041*): before **every** IP comparison (excluded IPs,
  lab host IPs and own IP, loopback, R5 pairing, WinRM 91 ↔ anchor, the GT-02(b) map, GT-02(c)) an address is
  stripped and an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is normalised to its IPv4 form `a.b.c.d`. Blank, `-`
  and NULL never compare equal to anything. `ip_kind` describes the normalised address (`::ffff:192.168.50.21` →
  `ipv4`); stats counts are keyed by the normalised address. Every output CSV keeps the **original** logged text in
  `source_ip`.
- Logon IDs: integers for every comparison, hex only in display columns (D1). **A NULL logon ID never matches anything** (logon ID 0 is stored as NULL, decision 005).
- The gate does not read `command_line` and never rebuilds what was typed on a host.

Refused inputs (the gate stops with an error and writes nothing):
- a quarantined DB (path under `quarantine/` or trial id `s05q_*`, decision 030);
- a trial with no row in `data/trial_windows.csv`, or a row with an empty start or end;
- a trial not allowed by the clock rule (section 2.2);
- *(amended by the owner 2026-11-12, decision 041)* a window row whose `db_sha256` differs from the SHA-256 of the
  trial DB being gated (the window was computed from another version of the DB);
- *(amended by the owner 2026-11-12, decision 041)* a window row whose `time_basis` differs from the gate's
  `TIME_BASIS` (`raw` until decision 032's correction exists; section 2.2).
- *(amended by the owner 2026-11-12, T6b.2, decision 043)* a trial whose `data/processed/<trial>.clock_offsets.csv` or `<trial>.clock_changes.csv` (spec 08 §3) is missing; whose offsets `db_sha256` differs from the DB's SHA-256; or whose window row `offsets_sha256` / `clock_changes_sha256` differs from the SHA-256 of those files;
- *(amended by the owner 2026-11-12, review SF-3/SF-4, decision 043)* a trial whose offsets file is not bound to its clock-changes file or to the trial: an offsets or clock-changes row whose `trial_id` is not the trial, an offsets `clock_changes_sha256` that is not the SHA-256 of the changes file, `clock_scan` not `complete` (incomplete CO-19 export scan), or a row with status `ok`/`wide` and no `offset_ms` (spec 08 §3);
- *(amended by the owner 2026-11-12, T6b.2, decision 043)* a clock-only trial (`s04_t01`, `s07_t01`; decision 034, spec 08 COA-04);
- *(amended by the owner 2026-11-12, T6b.2, decision 043)* CO-17: a trial whose window starts on or after 2026-10-26 when a host with events in the window has offset status `none` or `stale`.

### 2.1 Trial window file (`data/trial_windows.csv`)
A separate step (`src/trial_window/`, PLAN T6.4) writes this file. The gate only reads it.

| Column | Meaning |
|---|---|
| trial_id | `<scenario>_<trial>`, e.g. `s04_t00` |
| start_utc, end_utc | window edges, ISO UTC with milliseconds |
| window_source | `computed_agent_run` (from the data) or `operator` (recorded by the person who ran the trial) |
| margin_start_s, margin_end_s | margins already included in the edges (60 and 300) |
| rule | short text of the rule used |
| db_sha256 | hash of the trial DB the window was computed from |
| time_basis | `raw` or `corrected` (section 2.2) |
| offsets_sha256, clock_changes_sha256 | *(amended by the owner 2026-11-12, T6b.2, decision 043)* SHA-256 of the trial's `clock_offsets.csv` and `clock_changes.csv` used for the window |
| clock_flag | *(amended by the owner 2026-11-12, T6b.2, decision 043)* hosts with offset status `none`, `wide` or `stale` that have events in the window, `;`-joined (spec 08 CO-08) |
| clock_change_in_window | *(amended by the owner 2026-11-12, T6b.2, decision 043)* `true`/`false`: a counted clock change after a host's first pair, or on a host with no pairs (spec 08 CO-19 as amended) |
| start_host, end_host | *(amended by the owner 2026-11-12, T6b.2, decision 043)* hosts of the events that set the window edges: the agent-tree event's host, or, when the manifest clip sets the edge, the host of the export file whose (corrected) first/last time set it (empty for an operator window), so a consumer knows which host clocks the clip compares against |

How the window is computed:
- *(amended by the owner 2026-11-12, T6b.2, decision 043)* **Time basis `corrected`:** every Sysmon 1's time is corrected by its host's offset (`event_utc − offset_ms`, spec 08 CO-09; a host with status `none`/`stale` keeps its raw time) **before** the agent tree is walked and the edges are taken. The edges are corrected times. A raw-basis window (no offsets) is computed **only** by the GTA-06 test (spec 08 §4.1 item 6, owner Q7).
- **Trials with agent activity (S02–S07):** computed from the **agent process tree only**, using the trial DB and
  `data/manifest.csv` (decision 040). The key builder (`build_draft`), intended steps and identified hops are not used.
  - Start = the earliest agent (`C:\Users\Public\splunkd.exe`) root of the run, found by walking back while roots
    are 30 minutes or less apart (≤ 1800 s, `TRIAL_GAP_S`; decision 026), **minus 60 s**.
  - End = the last Sysmon 1 descended from the run's agent roots (by ProcessGuid, any depth) **plus 300 s**.
  - Both edges are clipped to the export span of the trial's files in `data/manifest.csv` (decision 026 amendment).
  - *(amended by the owner 2026-11-12, T6b.2, decision 043)* On the corrected basis, each manifest file's first and last event times are corrected by **its host's** offset (`none`/`stale` host: raw) before the min/max span is taken, so the clip compares corrected edges with corrected span ends. The raw-basis window (GTA-06 only) keeps the raw span.
  - The step does not read `ground_truth/` or the owner-review file.
  - The agent identity (image, server `192.168.50.50:8888`) is lab metadata in `src/trial_window/params.py`.
- **Trials with no agent activity (S01, manual RDP):** the trial start and end written down by the operator
  (T2 checklist), with the same margins: start − 60 s, end + 300 s, clipped to the manifest export end.
  `window_source = operator`.
- **No row is written, with the reason printed** (owner, 2026-11-12; decision 040), when:
  - the trial is quarantined (`s05q_*` or a DB under `quarantine/`, decision 030);
  - the trial is `s01_t00`, excluded from the split (decision 019);
  - the clock rule (section 2.2) refuses it (*(amended by the owner 2026-11-12, T6b.2, decision 043)*: offsets or clock-changes file missing or not matching the DB, a clock-only trial, or CO-17);
  - S01 has no operator-recorded start/end;
  - the trial has no export span in `data/manifest.csv`, or that span does not overlap the unclipped window at all. A partial overlap is clipped as above.
- A trial DB that is missing is an **error**: the step exits non-zero with the path, and writes no file.
- **Window end margin, stated plainly:** an event logged up to 300 s after the last agent step or command (or after
  the operator's recorded end) is inside the window. The start margin is 60 s before the first agent root (or the
  operator's recorded start).

### 2.2 Clock rule (decision 039, owner 2026-11-11)
*(amended by the owner 2026-11-12, T6b.2, decision 043)* **The correction exists (src/clock_offset, spec 08). `CLOCK_CORRECTION_AVAILABLE = true`, `TIME_BASIS = corrected`.** The "until that correction exists" rule below is replaced by the refusals of section 2 (offsets and clock-changes files present and matching, clock-only trials, CO-17); the t00-only and 2026-10-26 refusals are removed. A host with status `none` or `stale` keeps raw times (only possible before 2026-10-26; CO-17). Every gate pairing compares two events on the **same host** (R5, WinRM 91 ↔ anchor, wsmprovhost ↔ 91, 7045 ↔ 4697), so one offset per host cancels and the pairings are unchanged; only the GT-01 clip and the `near_window` counts depend on the time basis. Text kept below for the record.

- The gate clips and pairs events on **clock-corrected times** once the per-host, per-trial correction of
  decision 032 exists. Original times stay in the DB and are written next to the corrected ones in the outputs.
- **Until that correction exists**, the gate runs on t00 development trials only, on raw times
  (`time_basis = raw`). It refuses every other trial, and in any case every trial collected on or after
  2026-10-26 (the date from which ep-01 was 10–27 s behind, decision 032). The trial date is taken from the
  window start.
- The window step uses the same time basis as the gate.

## 3. Output contract
Location `out/gate/<trial_id>/`. Rebuilt on every run. Rows sorted by (`event_utc`, `event_uid`, `rule`); *(amended by the owner 2026-11-12, T6b.2, decision 043)* the sort uses `event_utc_corrected`.
Every file except `run_info.json` is byte-identical between two runs on the same inputs.

**`triggers.csv`** — one row per rule firing.
| Column | Type | Meaning |
|---|---|---|
| trigger_id | text | `<trial_id>-g<NNNN>` in sort order |
| rule | text | `R4_smb`, `R5_rdp`, `R6_service`, `R8_winrm` |
| host | text | host the event was logged on (the reached host) |
| event_utc | text | *(amended by the owner 2026-11-12, T6b.2, decision 043)* **original** logged time of the trigger event (spec 08 CO-09) |
| event_utc_corrected | text | *(amended by the owner 2026-11-12, T6b.2, decision 043)* `event_utc − offset_ms(host)`, the time used by the clip and the rules; equals `event_utc` for a host with status `none`/`stale`. ~~`event_utc_raw`~~ is removed (it duplicated the original time). |
| trigger_event_uid | text | the event that fires the rule (4624; the 4697 of an install, else its 7045; the Sysmon 1) |
| anchor_logon_uid | text/null | remote 4624 on the same host this trigger belongs to; null if none |
| target_logon_id, target_logon_id_hex | int / text | logon ID of the anchor |
| logon_type | int/null | of the anchor |
| source_ip | text/null | IpAddress of the anchor, else WinRM 91 clientIP; null if blank |
| ip_kind | text | `ipv4`, `ipv6`, `link_local`, `blank`; of the normalised address, so an IPv4-mapped IPv6 address is `ipv4` (*amended by the owner 2026-11-12, decision 041*) |
| account_name, domain_short | text | account of the anchor 4624 (the moving account, decision 027) |
| authentication_package | text | NTLM / Kerberos (R2 is shown here, never a trigger) |
| machine_account | int | 1 if the account ends in `$` |
| supporting_event_uids | text | `;`-joined uids that complete the rule |
| method | text | `logon_id`, `ip_port_time`, `ip_time`, `none` (*amended by the owner 2026-11-12, decision 041:* `method` and `gate_tier` describe how the row is tied to its anchor logon; `service_name_time` removed, no rule uses it) |
| candidate_count | int | number of anchors that matched the same supporting event the same way (1 = unique). *Amended by the owner 2026-11-12 (decision 041):* for each supporting event, the number of distinct anchors it matched by the same method; the row takes the maximum. R6/R8: the number of anchors matching the trigger event (one row per anchor). A row with no supporting event: 1 if the event is its own anchor or has one anchor, 0 if it has no anchor. |
| time_delta_ms | int/null | *Amended by the owner 2026-11-12 (decision 041):* earliest of (the trigger event, if it is not the anchor, and the supporting events) − anchor, in ms (same host clock). Null if there is no anchor, or if the anchor is the only event (R5 type 10 with no supporting event). |
| gate_tier | text | same host only: **A** tied by logon ID, or the event is its own anchor; **B** tied by IP + port + time or IP + time (*service name + time removed, amended by the owner 2026-11-12, decision 041*); **D** no anchor. This is the CLAUDE.md "confidence tier" of a gate row, named `gate_tier` so it is never confused with the T7 link tiers (decision 038). |
| near_duplicate | int | 1 if another row of the same host, channel and `record_id` exists with a different uid |
| window_source | text | copied from `data/trial_windows.csv` |
| time_basis | text | `raw` or `corrected` |
| clock_flag | text | *(amended by the owner 2026-11-12, T6b.2, decision 043)* copied from the window row (trial level) |
| clock_change_in_window | text | *(amended by the owner 2026-11-12, T6b.2, decision 043)* copied from the window row (trial level), `true`/`false` |
| clock_unreliable | int | *(amended by the owner 2026-11-12, T6b.2, decision 043)* 1 if any event of the row (trigger, anchor, supporting) is on a host with status `none`/`wide`/`stale`, or was logged before a counted clock change on its host (spec 08 CO-15, `clock_offset.correct.event_unreliable`), or a window edge host (`start_host`, `end_host`) has status `none`/`wide`/`stale` (the clip compares against that host's clock) |

Example (illustrative values): `s04_t00-g0007, R4_smb, ep-02, 2026-09-24T10:57:36.9Z, 2026-09-24T10:57:36.9Z, <4624 uid>, <4624 uid>, 873286, 0xd5346, 3, 192.168.50.21, ipv4, svc_backup, LAB, NTLM, 0, <5140 uid>;<5145 uid>, logon_id, 1, 412, A, 0, computed_agent_run, raw`.

**`dispositions.csv`** — exactly one row per in-window event of a trigger type (4624 type 3/10, and type 2/11 —
*amended by the owner 2026-11-12, decision 041, so that `interactive_logon` can appear*; 5140/5145; 7045; 4697;
Sysmon 1 with `image` or `parent_image` ending `\wsmprovhost.exe`; WinRM 91; Sysmon 3 with `destination_port` 3389):
`event_uid, host, event_id, event_utc, disposition, reason_detail, anchor_logon_uid`; *(amended by the owner 2026-11-12, T6b.2, decision 043)* plus `event_utc_corrected, clock_flag, clock_change_in_window, clock_unreliable` (the event's own clock and the edge hosts, as in `triggers.csv`).
Disposition, in this precedence order (first match wins): `excluded_source_ip`, `excluded_source_ip_session`,
`interactive_logon`, `system_logon_id`, `loopback_or_self`, `paired_excluded`, `trigger`, `supporting`,
`unmatched_remote`, `no_rule`.
*Amended by the owner 2026-11-12 (decision 041):* `trigger` = the event is the `trigger_event_uid` **or the
`anchor_logon_uid`** of any `triggers.csv` row; `supporting` = the event is in any row's `supporting_event_uids`, or
is listed in `supporting.csv` (an `R8_parent` Sysmon 1 → `supporting`). An outbound 3389 Sysmon 3 that is not
excluded, loopback or self is `no_rule` with `reason_detail` `outbound 3389, source side of an RDP connection` (GT-05).

**`unmatched_remote.csv`** — remote 4624 type 3/10 that fired no rule and is the anchor of no trigger row (GT-15). T7 reads it next to `triggers.csv`.
Same columns as `triggers.csv` minus `rule`.

**`supporting.csv`** — supporting signals, listed, never triggers: `R1_lsass`, `R3_explicit`, `R8_parent`.
Columns `rule, event_uid, host, event_utc, account_name, session_id`; *(amended by the owner 2026-11-12, T6b.2, decision 043)* plus `event_utc_corrected, clock_flag, clock_change_in_window, clock_unreliable`.

**`stats.json`** + **`report.md`** — trial id; DB path and SHA-256 before/after; the window row used (all columns of
`data/trial_windows.csv`) and that file's hash; counts per host × event id removed by the window; `near_window`
**counts only** per host (trigger-type events up to 300 s outside each edge — no uids); counts per disposition;
triggers per rule × host × gate tier; machine-account triggers per host (Q1); local service installs (R6 with no
anchor); excluded-IP sessions that also have a service install or share write (`excluded_ip_with_artefacts`, uids);
`near_duplicate` uids; for every tier-D row, the IP of its logon ID looked up in the unclipped DB; parameters.
**`run_info.json`** — run time and tool version (not byte-compared).

### 3.1 `stats.json` keys (*named by the owner 2026-11-12, decision 041; tests check these exact names*)
JSON object, keys sorted, indent fixed. Exactly these top-level keys:

| Key | Content |
|---|---|
| `trial_id` | text |
| `db` | `{path, sha256_before, sha256_after}`; path relative to the repo when inside it |
| `window` | `{row, file, file_sha256}`: `row` = all columns of the trial's `data/trial_windows.csv` row; `file` = that file's path |
| `time_basis` | `raw` or `corrected` |
| `clock` | *(amended by the owner 2026-11-12, T6b.2, decision 043)* `{offsets_file, offsets_sha256, clock_changes_file, clock_changes_sha256, clock_flag, clock_change_in_window, offsets: host → {offset_ms, offset_status, offset_unc_ms}, unreliable_rows: {triggers, unmatched_remote, dispositions, supporting}}` |
| `events` | `{loaded_total, in_window_total, trigger_type_in_window, trigger_type_in_window_per_host}` |
| `removed_by_window` | host → `<channel>/<event_id>` → count of events dropped by GT-01 |
| `near_window` | host → `{before, after}` counts of trigger-type events up to `NEAR_WINDOW_S` outside each edge (no uids) |
| `dispositions` | `{total: disposition → count (every name, zeros included), per_host: host → disposition → count}` |
| `triggers` | `{total, per_rule: rule → count, per_rule_host_tier: rule → host → gate_tier → count}` |
| `unmatched_remote` | `{total, per_host: host → count}` |
| `supporting` | `{total, per_rule: R1_lsass / R3_explicit / R8_parent → count}` |
| `remote_logons_per_ip_kind` | `ip_kind` → count of remote 4624 type 3/10 (GT-06) |
| `machine_account_triggers_per_host` | host → count of trigger rows with `machine_account` = 1 (GT-07) |
| `local_installs` | `{count, trigger_ids}`: R6 rows with no anchor |
| `excluded` | `{per_ip: normalised excluded IP → count of excluded in-window events, excluded_ip_with_artefacts: [{host, logon_id_hex, source_ip, event_uids}]}` |
| `near_duplicate_uids` | sorted list of in-window uids flagged near-duplicate (GT-18) |
| `tier_d_ip_lookup` | `[{trigger_id, rule, host, logon_id_hex, logon_found, source_ips}]`, one per tier-D row; `source_ips` are the original texts from the unclipped DB |
| `own_link_local` | (*amended by the owner 2026-11-12, decision 042*) `{per_host: host → [{address, evidence (E1 / E2 / E1/E2), e1_sysmon3, e2_4624}], conflicts: [{address, hosts, evidence: host → E1/E2}], machine_accounts: host → [machine accounts], e2_rejected: [{host, address, machine_account, other_accounts}]}`; see GT-05 |
| `sensitivity` | `{rdp_pairs, service_pairs, winrm_91_anchor_pairs, winrm_91_to_wsmprovhost_pairs}`, each tolerance in seconds as text (`"2"`, `"5"`, `"10"`) → number of pairs found at that tolerance (counts only; rules always use §5 values). `rdp_pairs`: (remote 4624, inbound 3389 Sysmon 3) pairs; `service_pairs`: 7045↔4697 pairs; `winrm_91_anchor_pairs`: (R8 anchor, WinRM 91) pairs with the same IP; `winrm_91_to_wsmprovhost_pairs`: (wsmprovhost Sysmon 1, WinRM 91) on one host with the **91 0..t s after** the Sysmon 1 (*amended by the owner 2026-11-12, decision 042*; before: the Sysmon 1 after the 91) |
| `parameters` | every §5 parameter, JSON-ready |

## 4. Rules
Applied in this order; each step sees only what the previous step kept.

| ID | Rule (plain terms) | How it is measured | Source |
|---|---|---|---|
| GT-00 | **Allowed trial.** Refuse the trial if section 2 or 2.2 says so, before reading any event. | – | decisions 030, 039 |
| GT-01 | *(amended by the owner 2026-11-12, T6b.2, decision 043)* the clip uses `event_utc_corrected`. **Window clip.** Keep an event only if `start ≤ event_utc < end + 1 ms` (instants; the window file has ms, the DB has µs). Everything else is dropped before any other rule and appears in no row of any output file; it is only counted in `stats.json`. Times as section 2.2. | counts per host × event id; `near_window` counts | PLAN T6.4, decisions 026, 039 |
| GT-02 | **Non-lab workstation sessions** (192.168.50.97, .98, .99; purpose inferred as log collection, decision 032). (a) A 4624 whose `source_ip` is one of them → `excluded_source_ip`. (b) Every in-window event tied to such a logon ID on the same host → `excluded_source_ip_session`: 5140/5145 and 4697 by `subject_logon_id`, Sysmon 1 by `session_id`, 4634/4647. The logon-ID → IP map for (b) is built from the **unclipped** DB, so a session whose 4624 is before the window is still recognised; this lookup can only remove events, never add any. (c) WinRM 91 or Sysmon 3 with a remote address in the list → excluded (*amended by the owner 2026-11-12, decision 041:* the remote address of an inbound Sysmon 3, `initiated` = 0, is `source_ip`; of an outbound one, `initiated` = 1, it is `destination_ip`); ~~a wsmprovhost Sysmon 1 on the same host within 5 s after such a WinRM 91 → excluded~~ (*amended by the owner 2026-11-12, decision 042*:) a wsmprovhost Sysmon 1 is excluded when its **paired** WinRM 91 (GT-13 pairing: the earliest 91 on the same host 0–5 s after the Sysmon 1, one-to-one) has an excluded clientIP **and** the Sysmon 1 has no tier-A anchor (a remote type 3 4624 that survived GT-02..05, matched by logon ID, logged at or before it). A lab-IP anchor decides, never the time pairing alone. (d) A 7045 paired (GT-12) with an excluded 4697 → `paired_excluded`. By IP only, never by account (these sessions use `admin_it`, also a scenario account); applied inside the window too (`s04_t01`, decision 032). An excluded session that has a service install or share write is listed in `excluded_ip_with_artefacts` (it may be a designed step run from that workstation: S04 ×10 Track A ran from .99, `docs/research/x10_design_validation.md` line 13). | dispositions; count per IP | decisions 032, 037 |
| GT-03 | **Interactive logons.** 4624 with `logon_type` 2 or 11 → `interactive_logon`. | count | handoff §7.2 |
| GT-04 | **System logon IDs** 0x3e4, 0x3e5, 0x3e7 (996, 997, 999) on the event's own logon ID → `system_logon_id`: 4624 `target_logon_id`, 4697 `subject_logon_id`, Sysmon 1 `session_id`. A 7045 paired with such a 4697 → `paired_excluded`. | count | handoff §7.2 |
| GT-05 | **Loopback or self.** `source_ip` 127.0.0.1, ::1, ::ffff:127.0.0.1, or the host's own lab IP → `loopback_or_self`. *Amended by the owner 2026-11-12 (decision 041):* compared after IP normalisation (§2). For an **outbound** Sysmon 3 to port 3389 (`initiated` = 1, the source-host side) the address judged is `destination_ip`, not `source_ip`: destination in the excluded list → `excluded_source_ip` (GT-02c); destination loopback or the host's own IP → `loopback_or_self`; otherwise → `no_rule` with `reason_detail` `outbound 3389, source side of an RDP connection`, so T7 can use it. `loopback_or_self` stays for real loopback and own-IP events. *Amended by the owner 2026-11-12 (decision 042):* a host's **own IPv6 link-local addresses** count as its own IP. They are found per trial DB (unclipped, never a fixed list, never all link-local) from that host's own events: **E1** an outbound Sysmon 3 (`initiated` = 1) on host H with link-local `source_ip` L; **E2** a remote 4624 (type 3/10) on H from L whose account is H's own machine account (the subject account, domain stripped, of 4624s on H opened by a system logon ID; E2 only when H has exactly one), and every 4624 on H from L uses that account. **Conflict rule:** an address with evidence on more than one host is recognised for none. Addresses compare as compressed text without `%zone`. A recognised (host, address) → `loopback_or_self`, `reason_detail` ending `own link-local (E1)`, `(E2)` or `(E1/E2)`; listed in stats `own_link_local`. The account is used only to recognise an address, never to link events. A link-local logon from another host's address, or from an address with no evidence, stays remote (GT-06). | count | handoff §7.2; decisions 025, 041, 042 |
| GT-06 | **Remote** = not removed by GT-02..05 and one of: a parseable IP (`ipv4`/`ipv6`), a blank or `-` IP (`blank`), or an IPv6 link-local address (`link_local`). Blank and link-local logons can fire rules (recall first, §7.1) with `ip_kind` set, so they are visible. | count per `ip_kind` | handoff §7.1; decision 038 |
| GT-07 | **Machine accounts are kept** (owner, Q1). A remote logon by an account ending in `$` goes through the rules like any other; it is flagged `machine_account = 1` and counted per host in stats. | count per host | owner 2026-11-11 |
| GT-10 | **R4 SMB.** A remote 4624 type 3 fires R4 when at least one 5140 or 5145 on the same host has `subject_logon_id` = its `target_logon_id` and `event_utc` ≥ the logon. Supporting = all such share events. Method `logon_id`, tier A. | triggers per host | handoff §7.2 table; decision 038 |
| GT-11 | **R5 RDP.** A remote 4624 type 10 fires R5 (its own anchor, method `none`, tier A). A remote 4624 type 3 also fires R5 when an inbound Sysmon 3 (`initiated` = 0) to `destination_port` 3389 on the same host has the same `source_ip` **and the same `source_port`**, within `RDP_PAIR_S` = 5 s (method `ip_port_time`, tier B). If the 4624 port is 0 or NULL (decision 015), IP + time is used (method `ip_time`, tier B). `candidate_count` = number of 4624s matching the Sysmon 3; the reverse count is in `reason_detail`. *Amended by the owner 2026-11-12 (decision 041):* "within 5 s" = \|Δt\| ≤ 5.000 s, either order, inclusive. An inbound 3389 Sysmon 3 that matches a type 10 R5 row the same way (same IP and port, or IP + time when the 4624 port is 0/NULL; \|Δt\| ≤ 5 s) is added to that row's `supporting_event_uids` (disposition `supporting`). | triggers per host | handoff §7.2 caveat; decisions 035 N17, 036 |
| GT-12 | **R6 service.** Every remaining 7045 and 4697 fires R6. A 7045 and a 4697 on the same host with the same `service_name` within `SERVICE_PAIR_S` = 5 s are one install: one row, the 4697 is `trigger_event_uid`, the 7045 is supporting (*amended by the owner 2026-11-12, decision 041:* the pairing is shown by the 7045 uid in `supporting_event_uids` and by `service_name_time` in the 7045's `reason_detail` in `dispositions.csv`; the row's `method`/`gate_tier` describe the anchor tie only: anchored → `logon_id`, A; no anchor → `none`, D). Anchor = the remote 4624 whose `target_logon_id` = the 4697 `subject_logon_id` (tier A). A 7045 with no 4697 has no anchor (tier D); tying it to a logon by time and file name is T7's job. Installs with no anchor are counted as local installs in stats. *Amended by the owner 2026-11-12 (decision 041):* "within 5 s" = \|Δt\| ≤ 5.000 s, either order, inclusive; a 7045 pairs with the **nearest** 4697 of the same name on the same host, one-to-one, ties broken by uid. The anchor is a remote 4624 of **type 3 or 10** with that logon ID whose `event_utc` is **≤ the 4697's**; with no such logon the row is tier D. Several matching anchors give **one row per anchor**, each with `candidate_count` = their number. | triggers per host | handoff §7.2; CLAUDE.md cross-host link |
| GT-13 | **R8 WinRM.** A Sysmon 1 whose `image` ends `\wsmprovhost.exe` (case-insensitive) fires R8. Anchor = remote 4624 type 3 on the same host whose `target_logon_id` or `target_linked_logon_id` = the Sysmon 1 `session_id` (method `logon_id`, tier A); none → tier D. WinRM 91 on the same host with the anchor's IP within 5 s is supporting. A Sysmon 1 whose `parent_image` (not `image`) is wsmprovhost goes to `supporting.csv` as `R8_parent`. *Amended by the owner 2026-11-12 (decision 041):* the anchor's `event_utc` must be **≤ the Sysmon 1's**; several matching anchors give **one row per anchor**, each with `candidate_count` = their number. Supporting WinRM 91 = same host, clientIP = the anchor's `source_ip`, \|91 − anchor 4624\| ≤ 5.000 s (either order, inclusive). ~~A tier-D row takes the **latest** WinRM 91 on the same host 0–5 s before the Sysmon 1~~ (*amended by the owner 2026-11-12, decision 042*:) a wsmprovhost Sysmon 1 is paired with the **earliest WinRM 91 on the same host 0–5 s after it** (inclusive), one-to-one: starts in time order (uid breaks ties), each 91 used once, over all in-window starts and 91s before suppression. A tier-D row takes its paired 91: its clientIP is the row's `source_ip` and its uid is supporting; a paired 91 removed by GT-02..05 is not used (blank `source_ip`). An `R8_parent` Sysmon 1 has disposition `supporting`. | triggers per host | handoff §7.2, §3.6.3; decision 038 |
| GT-14 | **Several rules on one anchor** give several rows (for example R4 and R6 on one SMB logon). T7 groups rows by `anchor_logon_uid`. Nothing is merged or dropped. | – | Correction G.4 |
| GT-15 | **Unmatched remote logons.** A remote 4624 type 3/10 that fires no rule is not a trigger; it goes to `unmatched_remote.csv` so T7 can still use it and a missed movement stays visible. *Amended by the owner 2026-11-12 (decision 041):* a 4624 that is the `anchor_logon_uid` of any trigger row (e.g. of R6 or R8 only) **counts as fired**: disposition `trigger`, not in `unmatched_remote.csv`. Every remote type 3/10 logon is in exactly one of the two files. | count | decisions 038, 041 |
| GT-16 | **Supporting signals.** R1 (Sysmon 10, `target_image` ends `\lsass.exe`, `granted_access` in the R1 set), R3 (4648) and R8_parent are listed after GT-01 and GT-02 and never start the stitcher. | count | handoff §7.2, Correction D |
| GT-17 | **No threshold.** Every trigger is kept; no score, no cut-off. | – | Correction J |
| GT-18 | **NULL never joins; near duplicates are flagged.** No rule matches on a NULL logon ID, port or IP. Rows with the same host, channel and `record_id` but different uids (left by `events_dedup`) are all kept and flagged `near_duplicate`, and their uids are listed in stats. | count | decision 005; NF-08 |

## 5. Parameters
| Name | Value | Why | Sensitivity test? |
|---|---|---|---|
| Window | row of `data/trial_windows.csv` (start = first agent root − 60 s, end = last Sysmon 1 in the agent tree + 300 s, clipped to the manifest export span; S01: operator times with the same margins) | PLAN T6.4, decisions 026, 039, 040 | no (owner rule) |
| `EXCLUDED_SOURCE_IPS` | 192.168.50.97, .98, .99 | decisions 032, 037 | no |
| `LAB_HOST_IPS` | dc01 .10, ep-01 .21, ep-02 .22, ep-03 .23 (as `src/log_check/params.py`); Caldera .50 listed for display only | self check; source host by IP | no |
| `SYSTEM_LOGON_IDS` | 996, 997, 999 | handoff §7.2 | no |
| `LOOPBACK` | 127.0.0.1, ::1, ::ffff:127.0.0.1 | handoff §7.2 | no |
| `RDP_PAIR_S` | 5 s (\|Δt\| ≤ 5 s, either order, inclusive; amended by the owner 2026-11-12, decision 041) | decisions 035 N17, 036 (same host) | report counts at 2 s and 10 s |
| `SERVICE_PAIR_S` | 5 s (\|Δt\| ≤ 5 s, either order, inclusive; decision 041) | same-host 7045/4697 pairing | report counts at 2 s and 10 s |
| `WINRM_PAIR_S` | 5 s (91 ↔ anchor: \|Δt\| ≤ 5 s, either order, inclusive, decision 041; wsmprovhost → 91: the 91 0–5 s **after** the Sysmon 1, one-to-one, GT-02(c) and tier-D R8, *amended by the owner 2026-11-12, decision 042*; t00 gaps 57–666 ms, 21 pairs) | WinRM 91 ↔ anchor / wsmprovhost | report counts at 2 s and 10 s |
| `R1_ACCESS_MASKS` | 0x1010, 0x1410, 0x143a, 0x1fffff | handoff §7.2 R1 | no |
| `NEAR_WINDOW_S` | 300 s | edge counts make clock skew and clipped events visible | no |
| `CLOCK_CORRECTION_AVAILABLE` | ~~false~~ **true** *(amended by the owner 2026-11-12, T6b.2, decision 043)* | the correction exists (spec 08) | no |
| `TIME_BASIS` | **corrected** *(amended by the owner 2026-11-12, T6b.2, decision 043)* | spec 08 §4.1 item 2 | no |
| `RAW_TIME_CUTOFF_DATE` | 2026-10-26 | first collection date with ep-01 10–27 s behind (decision 032); *(amended by the owner 2026-11-12, T6b.2, decision 043)* now used only as the CO-17 date | no |
| `CLOCK_ONLY_TRIALS` | `s04_t01`, `s07_t01` *(amended by the owner 2026-11-12, T6b.2, decision 043)* | measured for the offset method only, never gated (decision 034, spec 08 COA-04) | no |

## 6. Edge cases (attacker review 2026-11-11)
| Case | Where it occurs | Expected behaviour | Test ID |
|---|---|---|---|
| Excluded-IP logon inside the window | `s04_t01` .99 at 04:12:22 (decision 032) | `excluded_source_ip`; no trigger | GTT-02, GTA-05 |
| Excluded-IP session whose 4624 is before the window, wsmprovhost inside it | expected at trial ends | Sysmon 1 `excluded_source_ip_session` via the unclipped lookup; no R8 tier-D row | GTT-09 |
| Excluded-IP session that installs a service | S04 ×10 Track A from .99 (`x10_design_validation.md` l.13) | excluded, listed in `excluded_ip_with_artefacts`; GTA-05 stops and reports to the owner | GTA-05 |
| 7045 paired with an excluded 4697 | any | `paired_excluded` | GTT-09 |
| Blank / `-` / link-local source IP | Kerberos logons (decision 015) | can fire R4/R5, `ip_kind` set | GTT-10 |
| Window end in ms, DB event at +7 µs | `s04_t00` end 11:00:07.787Z vs manifest .787007 | kept | GTT-01b |
| Answer key has a top-level `window` different from `run_interval` | `s04_t00` (10:55:56 vs 10:53:55) | the gate reads neither; the computed start must equal the `run_interval` start, and every key-hop event must lie inside the computed window (decision 040) | GTA-06 |
| Trial collected on or after 2026-10-26 before the clock correction exists | S04, S06, S07 ×10 (2026-10-26/27) | refused | GTT-07 |
| *(amended by the owner 2026-11-12, T6b.2, decision 043)* Trial on or after 2026-10-26 with a host `none`/`stale` that has events | s07_t01 ep-03 (1 pair; clock-only anyway) | refused (CO-17) | GTT-07, COT-20 |
| *(amended by the owner 2026-11-12, T6b.2, decision 043)* Events logged before a counted clock change (snapshot catch-up) | ep-02 in s02_t00 (+8.48 s), s06_t00, s07_t00 (hours) | corrected time is wrong by the step; most fall outside the window; any that stays has `clock_unreliable = 1` | GTT-21 |
| SMB logon and RDP connect from one IP within 5 s | possible in S01 | no R5 unless ports match (or port 0 → `ip_time`) | GTT-05 |
| Hop with no share event | 4624-led background hops | `unmatched_remote.csv`, never lost | GTT-05, GTA-01 |
| wsmprovhost start missing, child present | any WinRM | `R8_parent` in `supporting.csv` | GTT-05 |
| NULL logon IDs on two rows | logon ID 0 stored as NULL | no match | GTT-12 |
| Near-duplicate 4624 | `events_dedup` keeps different payloads | rows flagged, `candidate_count` shows it | GTT-12 |
| Machine-account logons on dc01 | Group Policy / SYSVOL access | kept, flagged, counted (Q1) | GTT-13 |
| dc01 logs on to itself over its own link-local address (`dc-01$`) | all six t00 trials (review F1) | `loopback_or_self` by E2 (*amended by the owner 2026-11-12, decision 042*) | GTT-19 |
| Link-local logon from another host's own address | none in t00 | stays remote, fires (GT-06) | GTT-19 |
| WinRM 91 logged 57–666 ms after the wsmprovhost start | s03/s05/s06 t00 (review F4) | paired 91 after the Sysmon 1; a 91 before it never pairs (*amended by the owner 2026-11-12, decision 042*) | GTT-20 |
| No inbound 3389 Sysmon 3 logged | RDP by IP under NLA | type 3 RDP logon cannot fire R5 → `unmatched_remote` (S01 should run by hostname, decision 036) | – |

## 7. Acceptance tests
Unit tests (synthetic rows, `tests/unit/test_gate.py`):
| ID | What must be true |
|---|---|
| GTT-01 | An event 1 ms before the start or after `end + 1 ms` is in no row of any output file (only counts); an event exactly on an edge is kept. |
| GTT-01b | Window end `…07.787Z`, DB event `…07.787007Z` → kept; `Z` and `+00:00` forms compare equal. |
| GTT-02 | An excluded-IP 4624 inside the window is excluded with its 5145, 4697 and wsmprovhost Sysmon 1; no row in `triggers.csv`, `unmatched_remote.csv` or `supporting.csv` has an excluded `source_ip`. |
| GTT-03 | An `admin_it` 4624 from 192.168.50.21 next to an excluded-IP `admin_it` logon still fires (by IP, not account). |
| GTT-04 | Type 2/11, logon IDs 996/997/999, loopback and own-IP logons never fire. |
| GTT-05 | Each rule fires on its minimal positive case and not with one condition removed: R4 without a share event (→ `unmatched_remote`); R5 type 3 with the 3389 Sysmon 3 at 6 s, or with a different port; R6 4697 by 0x3e7 (its 7045 → `paired_excluded`); R8 with wsmprovhost as parent only (→ `R8_parent`). |
| GTT-06 | A 7045 + 4697 pair gives one R6 row with the 4697 as trigger; two installs of one name 20 s apart give two rows. |
| GTT-07 | *(amended by the owner 2026-11-12, T6b.2, decision 043)* **Replaced:** refused, nothing written: a quarantined DB; no row (or an empty edge) in `data/trial_windows.csv`; a row whose `db_sha256` is not the DB's hash or whose `time_basis` is not `corrected`; a missing `clock_offsets.csv` or `clock_changes.csv`; an offsets `db_sha256` that is not the DB's; a row `offsets_sha256`/`clock_changes_sha256` that differs from the files; a clock-only trial; CO-17 (window start on or after 2026-10-26 with a `none`/`stale` host that has events; a `wide` host runs; before that date it runs with the flag). A non-t00 trial is no longer refused. *(Review SF-3/SF-4, 2026-11-12)* Also refused: offsets or clock-changes `trial_id` not the trial; `clock_changes_sha256` not the changes file's hash (e.g. a changes file copied from another trial); `clock_scan = incomplete`; an `ok`/`wide` row without `offset_ms`. *Old text:* Refused, nothing written: a quarantined DB; a trial with no row (or an empty edge) in `data/trial_windows.csv`; while `CLOCK_CORRECTION_AVAILABLE` is false, a non-t00 trial and a trial whose window starts on or after 2026-10-26; *(decision 041)* a row whose `db_sha256` is not the DB's hash, or whose `time_basis` is not the gate's. |
| GTT-08 | DB hash unchanged; two runs give byte-identical files (all but `run_info.json`). |
| GTT-09 | Excluded-IP 4624 outside the window + wsmprovhost inside → excluded, no tier-D R8; 7045 paired with an excluded 4697 → `paired_excluded`. |
| GTT-10 | Blank-IP type 3 with a 5145 fires R4; blank-IP type 10 fires R5; `ip_kind` = `blank`. |
| GTT-11 | Every in-window trigger-type event has exactly one row in `dispositions.csv`; disposition counts sum to the in-window trigger-type count per host. |
| GTT-12 | Two rows with NULL logon IDs never match; a near-duplicate 4624 pair is flagged on both rows. |
| GTT-13 | A machine-account type 3 with a 5140 fires R4 with `machine_account = 1` and is counted in stats. |
| GTT-14 | **`src/gate` never opens a path under `ground_truth/`**: a run with file opens recorded (patched `open` / `sqlite3.connect` / `pathlib` reads, plus a check of the source text for the string `ground_truth`) shows no such path. The same test covers `src/trial_window`. *Extended by the owner 2026-11-12 (decision 041):* a fresh interpreter that imports every module of `gate` and `trial_window` (their `__main__` included) has none of `answer_key.build`, `answer_key.finish`, `answer_key.verify`, `answer_key.overlap` in `sys.modules`; the 60 s / 300 s margins come from the neutral module `src/lab_common/margins.py`. |
| GTT-15 | *(decision 041)* An outbound 3389 Sysmon 3 (`initiated` = 1) is `no_rule` with `reason_detail` `outbound 3389, source side of an RDP connection`; to an excluded IP → `excluded_source_ip`; to loopback or the host's own IP → `loopback_or_self`. Loopback and own-IP 4624 stay `loopback_or_self`. |
| GTT-16 | *(decision 041)* IPv4-mapped addresses compare as IPv4: `::ffff:192.168.50.99` is excluded with its session; `::ffff:127.0.0.1` and `::ffff:<own IP>` are `loopback_or_self`; a 4624 from `::ffff:192.168.50.21` pairs with a 3389 Sysmon 3 from `192.168.50.21` and with a WinRM 91 in the other form; `source_ip` keeps the original text, `ip_kind` = `ipv4`, stats keyed by the IPv4. |
| GTT-17 | *(decision 041)* `near_duplicate` on an R6/R8 row follows its `trigger_event_uid`, not its anchor. |
| GTT-18 | *(decision 041)* `stats.json` has exactly the §3.1 keys; the `sensitivity` counts at 2, 5 and 10 s are right for all four pairings. |
| GTT-19 | *(decision 042)* Own link-local: E2 dc01 self-logon → `loopback_or_self` `own link-local (E2)`, no trigger or unmatched row; E1 from an outbound Sysmon 3 before the window, any text form (`fe80:0:…%12`); `E1/E2`; a link-local logon from another host's own address, or with no evidence, stays remote and fires; conflict (E1/E1 and E1/E2 on two hosts) → recognised for none, listed; E2 guard (another account from the address) → rejected, listed; E2 needs the receiving host's own and only machine account; inbound Sysmon 3 is no evidence; an own-address WinRM 91 → `loopback_or_self`. |
| GTT-21 | *(amended by the owner 2026-11-12, T6b.2, decision 043)* Corrected times: an event clipped by its corrected time (inside the raw window but outside after correction, and the reverse); `event_utc` = original and `event_utc_corrected` = `event_utc − offset` in every output file; a `none`/`stale` host keeps raw time; `clock_unreliable` = 1 for an event logged before a counted clock change, for a `wide`/`none` host, and for every row when an edge host is `wide`; same-host pairings give identical rows on the raw and corrected basis; `stats.json` `clock` key. |
| GTT-20 | *(decision 042)* WinRM pairing: a 91 before the wsmprovhost never pairs (an excluded one does not exclude it; a lab one gives no tier-D IP); an excluded paired 91 does not exclude a start with a lab tier-A anchor; an anchor removed by GT-05 is not tier A; 1:1 earliest-first (two starts / two 91s; one 91 for two starts); one excluded 91 excludes only its paired start; per host only; a paired loopback 91 gives no tier-D IP. |

Real-data tests (development data only, decision 019; `data/sample/` first, then all six t00 trials s02–s07):
| ID | What must be true |
|---|---|
| GTA-01 | For every hop in `ground_truth/approved/s0{2..7}_t00.yaml` (read by the test, never by `src/gate`): an **attack or benign** hop must have a row in `triggers.csv` whose `anchor_logon_uid` equals the hop's target 4624 uid (a hop whose only target event is a 7045 may match by `trigger_event_uid`). A **background** hop must be in `triggers.csv` or in `unmatched_remote.csv`. A **miss** = a hop in neither file; only a miss stops the task (CLAUDE.md stop rule). An attack or benign hop that is only in `unmatched_remote.csv` is reported as a failure of this test for the owner to review, not a stop. |
| GTA-02 | The `admin_it` type 3 logon on ep-02 from 192.168.50.21 at 2026-10-12 07:05:15.541 (key hop s05-t1) is in the s05, s06 and s07 t00 DBs. In s06 and s07 it is outside the window and its uid is in no row of any output file. In s05 it is inside and has a trigger or an `unmatched_remote` row (the rule it fires is reported). |
| GTA-03 | On every trial gated: no row of `triggers.csv`, `unmatched_remote.csv` or `supporting.csv` has `event_utc` (*(amended by the owner 2026-11-12, T6b.2, decision 043)*: `event_utc_corrected`) outside the window or an excluded `source_ip`; for every tier-D row, the unclipped lookup of its logon ID's IP is not an excluded IP. |
| GTA-04 | `dispositions.csv` partitions the in-window trigger-type events (GTT-11 on real data); `stats.json` counts equal the file counts. |
| GTA-05 | *(amended by the owner 2026-11-12, T6b.2, decision 043)* On **every development trial gated that has a 4624 from 192.168.50.97/.98/.99**, each such logon is `excluded_source_ip`; if that session has a 4697, 7045 or share write, the run stops and reports to the owner. Skipped with that reason until such a trial exists (none of the t00 trials has one; `s04_t01` is clock-only and never gated). *Old text:* (only after the clock correction exists and a window row exists for `s04_t01`) the .99 logon at 04:12:22 UTC is `excluded_source_ip`; if that session has a 4697, 7045 or share write, the run stops and reports to the owner. Skipped with a reason until then. |
| GTA-06 | **Window start and containment** (amended by the owner 2026-11-11, decision 040), on the six t00 trials s02–s07, for the window computed by `src/trial_window`. *(amended by the owner 2026-11-12, T6b.2, decision 043)* computed on the **raw** basis for this test only (the keys are in raw time; spec 08 §4.1 item 6, owner Q7); the corrected-basis window is checked by GTA-07. (1) Its start equals the approved key's `agent.run_interval` start, to the millisecond. (2) **Pass/fail:** every event referenced by the key's hops (attack, benign and background, with their supporting events) lies inside it (`start ≤ t < end + 1 ms`). (3) Reported per trial: the end difference from `run_interval` in seconds, and the smallest gap between any key-hop event and the window end. The test reads the key; `src/trial_window` does not. If any key event is outside, stop and report it with both windows side by side. Do not change the window rule or margins to make it pass. Millisecond equality of the end was dropped: the key's end includes target-side 4624 times that the agent tree cannot see (measured s02 +0.976 s, s03 −2.762 s, s05 −2.420 s). |

| GTA-07 | *(amended by the owner 2026-11-12, T6b.2, decision 043)* (spec 08 §4.1 item 8, ATK-11) On the six t00 trials, gated on the corrected basis: every key-hop event (attack, benign, background, with supporting events) has its `event_utc_corrected` inside the corrected window, so the clip removes none; the 15 key hops keep their trigger rows at tier A (GTA-01); `near_window` counts on the raw and on the corrected basis are reported per trial. |

Note: the t00 development data has no session from .97/.98/.99 in any key (they appear in ×10 S04 trials), so on
development data the excluded-IP rule is proven by GTT-02/03/09 only, until GTA-05 can run.

## 8. Questions (owner answers 2026-11-11)
| Question | Answer |
|---|---|
| Q1 Machine-account (`…$`) remote logons on dc01 will fire R4 often. | **Keep and count** (GT-07). No new suppression rule; the locked gate list is unchanged. |
| Q2 Where does the window come from for trials without an approved key? | **Computed from the data**, never from `ground_truth/` (section 2.1, GTT-14, GTA-06; decision 039). S01 uses the operator-recorded start and end. |
| Q3 The clip drops a source-host logon opened before the window that is still open at the hop; identity (Correction K) needs it. | **Accepted:** the gate output carries the window; T7 may look up pre-window session opens **for the identity check only, never as an anchor or trigger**. PLAN 7.7 amended (decision 039). |
| Q4 Raw or corrected times for the clip? | **Corrected** (section 2.2). Until decision 032's correction exists the gate runs on t00 development trials only and never on a trial collected on or after 2026-10-26. |

## 9. Out of scope
Cross-host linking and source sessions (T7); 7045 → logon by time and file name (T7); Sigma labels (T8); scores (T9);
the clock offset correction itself (decision 032; the gate only consumes it); R7 TGS-without-TGT (supporting only,
needs ticket-lifetime logic); command lines.
