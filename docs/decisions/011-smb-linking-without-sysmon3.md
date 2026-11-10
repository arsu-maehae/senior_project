# 011 — Link SMB hops without Sysmon 3

**Date:** 2026-11-10 · **Status:** accepted (owner); **partly superseded by decision 013** (2026-11-10): account is a supporting check, never a join condition; identity is computed for every hop including `target_only`; the source session may also come from a 4648 or a port join; 013's kill criteria replace this record's · **Task:** T4 prep

## Context
Correction I (CLAUDE.md) links a cross-host hop from the target 4624 (IpAddress, IpPort, account, time) to a source Sysmon 3 (SourceIp/Port, DestinationIp/Port), then ProcessGuid → Sysmon 1 → LogonId session. Evidence (`docs/research/sysmon_config_check.md`, `docs/research/t3_data_findings.md` §1):
- The Sysmon configuration (`docs/lab/sysmon_DC-01.txt.xml`, SwiftOnSecurity v74, SHA-256 `055FEBC6…87162`, the file ep-03 loaded on 2026-09-11) has no include rule for `System` or port 445, so SMB connections were never logged. Its Event 3 rules explain every recorded endpoint Sysmon 3 row.
- s02, s04, s07 t00: 0 Sysmon 3 rows to 445 on any endpoint (also absent in the raw JSONL). `Image = System` occurs only in s01 ep-03, before the config load.
- Of the remote 4624 rows with port > 0, only 12 (s03, s05, s06) have any Sysmon 3 candidate.
- The SMB trials S02–S07 ×10 are already collected with this configuration.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Re-run the SMB trials with a 445 rule | Correction I as written | Weeks of collection; owner decided against it |
| B. Link SMB hops from target-side Security events plus the source command process | Uses data that exists in every SMB trial; matches how SMB attribution works anyway | No port-level join on the source side; more candidates when several sessions run commands naming the target |
| C. Target side only, no source session | Simplest | No source session; *(013: identity is still computed from the moving account and the source host, so this con no longer holds)* |

## Decision
Option B (owner, 2026-11-10). The SMB trials are not re-run. An SMB hop is linked through:
1. **Target side:** 4624 (source IP, IpPort, account, time) and the SMB activity of that logon session: 5140/5145 (share access) and 7045 (service install; 4697 where present).
2. **Source side:** the logon session whose command process (Sysmon 1, or Security 4688 where Sysmon 1 is missing) has a command line naming the target (host name or IP), with the account and time consistent with the target 4624. *(Superseded by 013: the account is recorded as `account_match`, not required.)*
3. Kerberos hops are still confirmed by DC 4769 ↔ 4624 LogonGuid.

Even with Sysmon 3 the SMB connection is owned by `System` (kernel SMB client), so session attribution always comes from the command process in the session. Sysmon 3 would only have added the source port for the join; it would never have named the session. Every link records `method`, `candidate_count`, `time_delta_ms`, `confidence_tier` and supporting `event_uid`s (CLAUDE.md code rules).

## Consequences
- Correction I is marked "under review — council in T4" in CLAUDE.md; its text is unchanged until the council verdict.
- The source-side join is by command-line target and time, not by port, so `candidate_count` can exceed 1 when several sessions name the same target in the window. This must be measured on the development trials (T7.6).
- No Sysmon config change before S01 ×10: RDP to 3389 is already logged (rule `DestinationPort is 3389`; inbound RDP rows exist on s01 ep-02).
- Report: limitation L10 and future work F9 (`docs/report/limitations_future_work.md`).

## Kill criteria
If on the development trials the source-side command-line join leaves more than one candidate session for most SMB hops, or misses the answer-key session, reopen (e.g. add 5145 relative path + 7045 image path matching to the source command line).

## Committee answer
**EN:** Our Sysmon configuration did not record SMB connections, and even when it does they belong to the kernel's System process, so we attribute an SMB hop through the target's logon and share/service events and the source session whose command names the target.
**TH:** การตั้งค่า Sysmon ของเราไม่ได้บันทึกการเชื่อมต่อ SMB และแม้จะบันทึก การเชื่อมต่อนั้นก็เป็นของโปรเซส System ของเคอร์เนล เราจึงระบุ hop แบบ SMB จากเหตุการณ์ logon และการเข้าถึง share/การติดตั้ง service ฝั่งปลายทาง ร่วมกับเซสชันฝั่งต้นทางที่คำสั่งระบุชื่อเครื่องปลายทาง
