# 047 — Session model of the stitcher: session columns, boot epochs, repeated opens

**Date:** 2026-11-13 · **Status:** **proposed.** Items 1–2 follow the owner's T7.2 instruction (pre-checks P1, P2). **Item 3 (boot groups, new parameter `BOOT_GROUP_S`) needs the owner's approval**, because it reads ST-10 differently from its literal text. Items 4–7 are implementation details the spec leaves open. · **Task:** T7 (7.2) · **Relates to:** spec [03_stitch](../specs/03_stitch.md) ST-10, ST-11, ST-63; 005 (NULL never joins); 039 (identity look-back)

## Context
T7.2 builds sessions per host (ST-10) and process trees (ST-11). Read-only pre-checks were run on the nine development trials, with DBs opened `mode=ro` and every SHA-256 unchanged. The scripts and full counts are in `out/stitch_check/precheck/`. The counts below are listed in this order: s02_t00, s03_t00, s04_t00, s05_t00, s06_t00, s07_t00, s02_t01, s03_t01, s06_t01.

- **P1 (Sysmon 1 session column).** `session_id` equals the raw Sysmon `LogonId` in **every** Sysmon 1 row (553 / 4370 / 342 / 5220 / 4641 / 488 / 4983 / 4747 / 4713). It equals `TerminalSessionId` in 0 rows, and no value lies in 0–15. 85–99 % of values match a 4624 `target_logon_id` on the same host. The rest are system IDs or sessions opened before the export.
- **P2 (4688 target logon ID).** The DB has `target_logon_id` for 4688. A zero is stored as NULL (NF-11, decision 005). Rows where it is present, non-zero and different from `subject_logon_id` (per host in the appendix): 306 / 1398 / 356 / 1621 / 1490 / 445 / 1474 / 1312 / 1309. In all of them the subject is a system ID (0x3e7 etc.). Where such a 4688 pairs with a Sysmon 1 (same host and pid, ≤ 2 s), the Sysmon `LogonId` equals the **target** ID in 122 / 118 / 113 / 287 / 157 / 103 / 187 / 81 / 95 pairs, and the subject in 0. No pair matches neither ID.
- **Boot events.** One restart logs several boot events. A startup group is 41, 6005 and 6008, e.g. ep-01 logs a 41 and then a 6005 up to 40.9 s later. A shutdown group is 1074 and 6006, up to 33.4 s apart. The next event of the same kind belonging to another boot comes ≥ 2304.8 s later (startup) or ≥ 383.6 s later (shutdown). User 4624s are logged inside startup groups. Read literally, ST-10 ("closed by the next boot event, any of 41/1074/6005/6006/6008") ends those sessions at the second event of the same restart. User sessions that end at a boundary within 120 s of opening: literal rule 15 / 58 / 30 / 56 / 4 / 4 / 56 / 56 / 56; grouped rule 5 / 35 / 13 / 39 / 4 / 4 / 39 / 39 / 39. The approved t00 keys' identity open sessions are open at the dump under **both** rules (13 of 13), so no key result depends on the choice.
- **Repeated opens.** Logon IDs with two or more 4624s in one epoch: 8 / 24 / 10 / 25 / 10 / 7 / 25 / 25 / 25. All are system IDs (types 0 and 5), plus 1 machine-account ID in s07_t00 that is reused after its logoff. Near-duplicate 4624s (same record ID): 0.
- **Other counts.**
  - Closes with no 4624 in their epoch: 2–13 per trial, none of them system IDs.
  - 4647 together with a 4634 for one session: 0. 4647 alone: 2–9 per trial.
  - Security 1102: one per host on dc01, ep-01 and ep-02, all before the window. None inside any window.
  - Sysmon 10 `process_guid` with a Sysmon 1: that Sysmon 1's image equals the Sysmon 10 `source_image` in 100 % of rows (0 mismatches), so the GUID is the source process.
  - 4688 with a NULL `process_id`: 0.
  - Sysmon 1 with two or more 4688 candidates at 2 s: 0 / 3 / 2 / 7 / 3 / 0 / 0 / 0 / 1.

## Options considered (item 3, the only open choice)
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. Literal: every boot event is an epoch boundary | Spec text as written | Ends 10–23 user sessions per trial seconds after they open, at the second event of the same restart. Wrong `closed` / `not_open` answers for anything that later reads those sessions | counts above |
| **B. Grouped:** consecutive boot events of the same kind (startup 41 / 6005 / 6008; shutdown 1074 / 6006) at most `BOOT_GROUP_S` = 120 s apart are one group; each group's first event is a boundary | Matches "the next boot" and "no single event is required"; 120 s lies between 40.9 s (largest inside a group) and 383.6 s (smallest between groups) | One new parameter, chosen on development data | counts above |
| C. Only 6005 marks a boot | Simple, one per boot | 41 precedes 6005 by up to 40.9 s on ep-01; sessions in between would close at 6005; spec says no single event is required | counts above |

## Decision
1. **Sysmon 1 session** = `session_id`, which holds the Sysmon `LogonId` (P1). A missing value never forms a session (decision 005).
2. **4688 session** = `target_logon_id` when it is present and non-zero, otherwise `subject_logon_id` (owner, P2). This replaces the "4688: `subject_logon_id`" reading in ST-10. That reading would put 306–1621 user processes per trial in a SYSTEM session.
3. **Boot epochs (proposed, needs owner approval).** Option B with `BOOT_GROUP_S` = 120 s. The epoch of an instant is the number of boundaries at or before it on that host. A session closes at the first boundary after its open (`close_kind` = `boot`) unless a 4634 or 4647 comes first.
4. **Repeated opens.**
   - A 4624 for a session that is open (system IDs only on development data) is added to that session's `open_uids`.
   - A 4624 after the session has closed starts a new session.
   - The session key is (host, logon ID, epoch, sequence); the sequence is 0 for the first session and is needed only for the s07 case.
5. **Closes.** The first 4634 or 4647 in the epoch at or after the open closes the session; every closing uid is kept. A close with no open is counted, not made a session.
6. **Same-host order** uses the logged time (`us_raw`). The per-host offset is one constant per trial, so the order is the same on corrected times.
7. **Other details.** A process whose session has no 4624 gives a session with `open_known` = 0. A log clear is Security 1102 only, as ST-63 states.

## Consequences
- ST-10's text needs a one-line amendment when item 3 is accepted ("boot = a group of boot events …; 4688 session per decision 047").
- Item 3 adds `BOOT_GROUP_S` to spec §5, frozen like the other values.
- STT-11 gains a case: a session opened between a 41 and a 6005 of one restart stays open.
- No key result changes under either rule.

## Kill criteria
- Item 3: on any trial, two boot events of the same kind more than 40.9 s and less than 383.6 s apart. The gap would then be ambiguous; report it and revisit.
- Item 2: a 4688 / Sysmon 1 pair whose `LogonId` equals neither ID.

## Committee answer
**EN:** A Windows restart writes several boot events up to 40 s apart. We count them as one restart, so a logon made during start-up is not closed by the next event of the same restart. A new process belongs to the logon named in its own event, which Sysmon confirms in every pair.
**TH:** การรีสตาร์ต Windows หนึ่งครั้งเขียนเหตุการณ์บูตหลายรายการห่างกันได้ถึง 40 วินาที เราจึงนับเป็นการรีสตาร์ตครั้งเดียว เพื่อไม่ให้ logon ที่เกิดระหว่างเริ่มเครื่องถูกปิดโดยเหตุการณ์ถัดไปของการรีสตาร์ตเดียวกัน และโปรเซสใหม่เป็นของ logon ที่ระบุในเหตุการณ์ของมันเอง ซึ่ง Sysmon ยืนยันได้ทุกคู่

## Appendix — P2 per host (rows with 4688 target logon ID present, non-zero and ≠ subject / all 4688 rows)
| trial | dc01 | ep-01 | ep-02 | ep-03 |
|---|---|---|---|---|
| s02_t00 | 84 / 223 | 118 / 342 | 104 / 318 | – |
| s03_t00 | 233 / 651 | 99 / 278 | – | 1066 / 4139 |
| s04_t00 | 148 / 400 | 97 / 257 | 111 / 305 | – |
| s05_t00 | 195 / 563 | 163 / 597 | 148 / 484 | 1115 / 4320 |
| s06_t00 | 161 / 440 | 104 / 288 | 147 / 478 | 1078 / 4157 |
| s07_t00 | 171 / 472 | 120 / 319 | 154 / 502 | – |
| s02_t01 | 156 / 452 | 110 / 311 | 147 / 488 | 1061 / 4158 |
| s03_t01 | 127 / 387 | 49 / 190 | 136 / 442 | 1000 / 4008 |
| s06_t01 | 126 / 362 | 47 / 171 | 138 / 450 | 998 / 4006 |
