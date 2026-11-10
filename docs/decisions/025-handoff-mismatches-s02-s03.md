# 025 — S02 stray run and S03 source host: the key follows the data

**Date:** 2026-11-10 · **Status:** proposed, needs owner approval · **Task:** T5 (5.4)

## Context
- **S02.** Two executions of the S02 ability exist in `s02_t00` (`docs/research/agent_evidence.md`, finding 1): the legacy ep-02 `system` agent (dump 05:41:32, `sc \\192.168.50.22` to its own IP, 5140/5145 with SubjectLogonId 999 and `PktDropService` 7045/4697 at 05:42:05) and the real ep-01 `svc_backup` run (dump 05:42:00, 4624 on ep-02 at 05:42:45.9 from 192.168.50.21, 5145 writing `PktDrop.exe` under logon 1741361, `sc` at 05:42:47). SQL on `events_dedup` of `s02_t00` (ep-02, 05:41:00–05:44:00): the stray run has no 4624 at all (its 5140/5145 carry SubjectLogonId 999, account `endpoint-02$`, source IP 192.168.50.22); the only `PktDropService` 7045 and 4697 anywhere in the DB are the stray's at 05:42:05; the three ep-02 4624s after it (05:42:45.9, 46.05, 46.12, logons 1741361, 1741492, 1741529) are `svc_backup` from 192.168.50.21. There is no 7045/4697 for the real run: the stray run had already created `PktDropService`, so the real `sc create` found it existing (inference; the error text is not in the logs).
- **S03.** Handoff §21.5 says "target EP-02 → EP-03"; the data (`s03-h1`) shows the admin_it command on ep-01 naming ep-03 (09:41:33) and a WinRM move ep-01 → ep-03 with a wsmprovhost session, moving account `admin_it`, identity 1.

## Decision
S02 key: one confirmed hop `s02-h1` (ep-01 → ep-02, `svc_backup`, identity 1, `logon_id_artifact` binding on the 5145 session); the ep-02 run is `stray_agent_ep02`, outside the attack path; its 7045/4697 and 5140/5145 are not in the hop's events, its dump is not used for identity (SYSTEM token, not a domain SourceUser). S03 key: the data's source ep-01; the draft carries the flag `handoff_mismatch`, and the handoff's source host (ep-02, §21.5 l.1720) is recorded here because the draft does not store it.

## Consequences
The S02 hop has an SMB trigger (4624 + 5140/5145) but no service-install artefact; T6/T7 must not require a 7045 for it. The stray run adds a 4624-free self-targeted SMB sequence on ep-02 that the gate and stitcher must not turn into a hop (source host = target host).

## Kill criteria
If the Caldera definitions show S03 was meant to start on ep-02, correct the intended step and revisit.

## Committee answer
**EN:** The answer key follows what the logs show: in S02 a stray ep-02 run is set aside, and in S03 the move starts from ep-01, not ep-02.
**TH:** เฉลยทำตามสิ่งที่ log แสดง ใน S02 เราแยกการรันที่หลงมาจาก ep-02 ออก และใน S03 การเคลื่อนที่เริ่มจาก ep-01 ไม่ใช่ ep-02
