# 048 — Readings for T7.3: hop groups, artefacts, source methods, Kerberos confirmation

**Date:** 2026-11-14 · **Status:** **accepted (owner, T7.3 plan approval 2026-11-14)**. Item 9 was accepted explicitly. Item 1 (matcher source) and item 13 (truncated-log rule) were settled by the task 0 checks below; item 13 is narrowed from the plan text and is reported to the owner · **Task:** T7 (7.3) · **Relates to:** spec [03_stitch](../specs/03_stitch.md) ST-03..ST-47; 013, 014, 038, 044, 046, 047

## Context
Spec 03_stitch fixes the T7.3 rules but leaves some implementation readings open: where command text may be read, which 4648 column is the session, port-join scope, the tiers of three artefact kinds, and how a truncated target log is reported. Task 0 ran read-only checks on the nine development trials (DBs `mode=ro`, all nine SHA-256 equal to gate `db.sha256_after` before and after; script and output in the session scratchpad, counts below):
- **4648.** `subject_logon_id` is present in every row and equals `session_id` in every row (28 / 167 / 31 / 198 / 193 / 59 / 184 / 176 / 181). `destination_host` and `field_values_json` are never NULL.
- **Share and service events.** 5140 / 5145 `subject_logon_id`, 5145 `relative_target_name`, 5140 `share_name`, 4697 and 7045 `service_name` / `service_image_path` are never NULL. 7045: 1 / 0 / 2 / 1 / 1 / 2 / 1 / 0 / 1.
- **Kerberos.** 4769 rows only on dc01. GUIDs are lower-case, without braces, and none is all-zero. 4769 NULL GUIDs: 0–8 per trial. 4624 NULL GUIDs: 203–958 per trial (NTLM and local logons).
- **Sysmon 3.** `initiated` takes 0 or 1. `destination_ip` and `source_port` are never NULL. WinRM 91 sits in channel `WinRM`.
- **Gate `near_duplicate` rows:** 0 in every trial.
- **Hosts with no rows at all:** ep-03 in s02_t00, s04_t00 and s07_t00; ep-02 in s03_t00.
- **Last Security event against the window end (corrected).** It is 0.7–120.8 s before the end on 19 host-trials and after it on 13. A quiet host is normal: the window ends 300 s after the last agent command. Only s06_t01 ep-03 is known to have an export that ends early: Security at 06:23:26 raw, while its Sysmon log runs to 06:24:18.
- **Independence check (owner addition 1).** `src/answer_key` imports nothing from `log_check`. Key commands and `agent_event_uids` come from `answer_key.targets.find_targets` (`build._names`), a separate matcher, so the key was **not** built with `log_check.matching` or `log_check.bridge`.
  - However, `import log_check.matching` runs `log_check/__init__.py`. That loads the whole package, including `checks_key` (which reads `ground_truth/approved/`) and `window` (which can take a window from the answer key).

## Options considered (item 1, the only real choice)
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. Reuse `log_check.matching` / `bridge` | Tested code (LCT-04/05/12); allowed by the owner when no dependence exists | Importing it loads key-reading modules into the stitcher process | package `__init__` above |
| **B. Own matcher in `stitch/cmdtext.py`, written from the spec; dev-only comparison with `log_check`** | The stitcher loads no key-reading code, and the import guard can forbid `log_check` entirely | One more matcher to test | same |

## Decision
1. **Command text and 4648 fields stay in one module (option B).**
   - `src/stitch/cmdtext.py` is the only stitcher code that selects `command_line` or `field_values_json`. It selects them only by `event_uid`, for in-window Sysmon 1 / 4688 / 4648 rows.
   - For a command it returns: the targets named, the field type matched (`host_name` / `windows_name` / `ip`), `via` (`plain` / `decoded`), `undecodable`, and the target-side names found. The text never leaves the function.
   - For a 4648 it returns only the target texts.
   - Its matcher is written from the spec: boundary-aware, case-insensitive, with `-EncodedCommand` decoding used for matching only. It is tested on the `log_check` boundary cases. A development-only script reports, as counts and uids, where it and `log_check` disagree on the nine trials.
   - `src/stitch` never imports `log_check` or `answer_key.build` / `finish` / `verify` / `overlap` / `targets`, and a fresh-interpreter test checks this.
   - **Name boundary (ST-46 data side; STT-07 "a name inside a longer file name does not match"; added in task 1).** Host names keep the FQDN rule: a following `.label` is allowed, `.digit` is not. File and service names use a stricter right boundary: no word character, no `-`, and no `.` followed by a word character. So `Xpay` is not found in `Xpay.exe`, and `Xpay.exe` is not found in `Xpay.exe.config`, but `Xpay.exe` is found at the end of a sentence.
   - **What `CmdResult` returns.** Every requested Sysmon 1 / 4688 uid of the requested host gets a result. `has_command` = 0 marks a 4688 with no command line logged (28–44 % of 4688 rows, spec §2). `undecodable` is set per event. `names_found` covers every probed target of the host; T7.4 keeps only the names found in the session's own evidence for this hop (ST-46).
2. **The scan is extended, not rebuilt.**
   - Non-command columns are added to `SCAN_COLUMNS`.
   - In-window 5140, 5145, 4697, 4648, dc01 4769, 7045 and WinRM 91 rows go to a separate `link_rows` list, collapsed per ST-05 with their own counters.
   - `t72_index.json` stays byte-identical.
3. **4648 session = `subject_logon_id`** (equal to `session_id` in every row).
4. **Command evidence is a process of the T7.2 index.**
   - Its time is the process start (the Sysmon 1 time when collapsed).
   - Its session is the process's session (decision 047 for a 4688-only process).
   - A collapsed pair counts once and keeps both uids. Only in-window processes count.
5. **Port join (ST-41).**
   - The Sysmon 3 must be **logged on the hop's source host** (owner addition), with `initiated` = 1, destination IP = the target's IP, and port = a member's port (> 0). Times are compared corrected, with |Δ| ≤ 5 s inclusive.
   - There is no source-IP condition. A system process gives a row with `session_unresolved_reason` = `system_process`. It is not a candidate and it is counted.
6. **`source_host_no_logs`** = the DB holds no row of that host. *(Task 5: taken from the hosts of every row the scan reads, of any kind, not only the rows it keeps or counts.)*
7. **Grouping** compares logged same-host times. A gap equal to `GROUP_GAP_S` joins. Hop ids follow the first member's corrected time, then uid. Flags: `gap_near_threshold` = a gap in [1, 3] s; `splits_at_1s` = an inside gap > 1 s; `merges_at_3s` = a neighbour gap ≤ 3 s.
   *Added in task 2:* port 0 counts as NULL for the follow-up port test and for `shares_port_with_hops`, as in ST-41 ("> 0"); no development member has port 0. Previous and next gaps and `merges_at_3s` look only at neighbouring hops, never at follow-up groups. `inside_gap_max_ms` is empty for a one-member hop. A NULL account counts as its own value for `mixed_account`. **§10.1 "hop groups at 2 s" counts only groups with a source IP**: the stitcher's group count before follow-ups is that number plus the blank-IP single hops (2/4/4/7/4/4/7/7/7), both are reported, and nothing was tuned.
8. **ST-26 "the hop before it"** is the nearest preceding hop (never a follow-up group) with the same target and IP.
9. **Artefact tiers (owner accepted).**
   - `wsmprovhost` (`logon_id`): A.
   - WinRM 91 and inbound 3389 (`ip_time`): the `gate_tier` of the pairing gate row.
   - Follow-up logons (`port_reuse`): **C**.
10. **Installs** are paired with `gate.classify.pair_services` (GT-12). A share or service event belongs to a member only when it is in the window and in the member's own session (the same session key).
    *Added in task 3:*
    - **Install facts.** The install pairing tolerance is the gate's own `service_pair_s` (5 s, imported, not copied). The install time is the earlier of its 4697 and 7045; the 7045 is logged 0.7–3.1 ms first in every development install. Measured to it, the copy-to-install gap is 50–181 ms; §10.3's "50–182 ms" was measured to the 4697. Service name and path come from the 4697, and from the 7045 only when the 4697 path is blank.
    - **Ties.** A burst ties on its last same-name write. A tied burst is attached to every hop whose install it ties, and stays on its own hop only if one of those installs belongs to its own hop. `candidate_count` is 1 for a `logon_id` row, and the install's number of tied bursts for a moved one.
    - **Other rows.** One `winrm_91` / `rdp_connection` row per gate trigger row and kind. `wsmprovhost` needs the member's own session, like shares and installs. A follow-up row's `time_delta_ms` is measured from the hop's first member, and follow-up rows count in the hop span.
11. **Kerberos** (ST-47): equal GUIDs, compared lower-case without braces, with an in-window dc01 4769. An all-zero GUID never confirms. It never sets a session. *Amended in task 4:* a match whose 4769 is outside the window is **not used and not counted**. The scan never keeps an out-of-window 4769, so the plan's "counted" part cannot be done from the scan. One development hop is affected: `s03_t01-h0001`, a machine-account ep-02→dc01 hop whose 4769s are logged 11.2 s before the window start. It is not confirmed, so endpoint→dc01 confirmation is 216 of 217 hops, against §10.4's "all", which was measured without the window. No keyed hop is affected.
12. **Out-of-range evidence** (ST-42) is counted from in-window events only.
13. **Truncated target logs (owner answer on s06_t01; narrowed after the pre-check).**
    - The check file lists, for every host, its last Security event (raw and corrected).
    - A host is labelled `data_limitation` only when source evidence of any method names it **after** that event, inside the window. The count per method and the hops into it whose last member is within `LINK_AFTER_S` of that event are listed.
    - It is never a stitcher error and never fails a test.
    - The plan's wording ("every host whose last Security event is before the window end") would have labelled 19 host-trials whose hosts were only quiet.
    - **Narrowed rule accepted by the owner (2026-11-14), with a second condition.** A host is also labelled when a process on that host (T7.2 process index, in the window) starts strictly after its last Security event (same-host logged time) and belongs to a session with no logon (`open_known` = 0). A process with no session does not count. The check file records the count (split into system and user sessions), the process uids and `data_limitation_reasons` (`evidence_after`, `unknown_session_process`). The hops near the end are listed for either reason.
    - **Result on the nine development trials:** exactly one host is labelled, s06_t01 ep-03, by the second condition only. Two user-session Sysmon 1 processes start at 06:24:17.9 and 06:24:18.3, 51.6 s after its last Security event at 06:23:26.3 raw. Their session 0x11341f is not a system ID and has no 4624. No source evidence on another host names ep-03 after the cutoff. The hop near the end is `s06_t01-h0021`. No other host in any trial is labelled by either condition.

**Matcher comparison (dev-only, task 5, 2026-11-14).** `stitch.cmdtext` and `log_check.matching` were run on every Sysmon 1 / 4688 command line of the nine development DBs (read-only, hashes unchanged), with every other lab host as the target: 161,019 command-target pairs, 122 matches by both, **0 disagreements**. The script prints counts and uids only and lives in the session scratchpad.

## Consequences
- The stitcher process loads no answer-key or log-check code.
- The matcher exists twice in the repo (`answer_key.targets` for the keys, `stitch.cmdtext` for the pipeline). Tier B on SMB is still agreement with the key's rule, not accuracy (spec L-ST1, 044).

## Kill criteria
- The dev-only comparison finds an event where `stitch.cmdtext` and `log_check` disagree and the spec does not explain it → fix the matcher before task 5.
- Any development trial with a 4648 whose `subject_logon_id` is NULL or differs from `session_id` → revisit item 3.

## Committee answer
**EN:** The answer keys were built with their own matcher, and the linking stage has a third one written from the spec. The linking stage cannot load any code that reads the keys, and a test proves it. Command text is read in one place only, and only "match or no match" leaves that place.
**TH:** เฉลยสร้างด้วยตัวจับคู่ชื่อของมันเอง ส่วนขั้นเชื่อมโยงมีตัวจับคู่ชุดที่สามที่เขียนจากสเปก ขั้นเชื่อมโยงจึงโหลดโค้ดที่อ่านเฉลยไม่ได้ และมีการทดสอบยืนยันเรื่องนี้ ข้อความคำสั่งถูกอ่านเพียงจุดเดียว และสิ่งที่ออกจากจุดนั้นมีเพียงผลว่า "ตรงหรือไม่ตรง" เท่านั้น
