# 015 — Kerberos hops with IpPort 0

**Date:** 2026-11-10 · **Status:** accepted (owner, T4 close) · **Task:** T4 (4.3)

## Context
Remote 4624 with `IpPort = 0` (decision 005: stored as 0, never a link key) are almost all Kerberos logons (exception: 4 NTLM rows in s01): s01 32, s02 26, s03 64, s04 36, s05 53, s06 52, s07 40 in the whole DBs (t3 findings §4). Log-check LC-04c: 0% of the SMB hop instances in S02–S07 t00 have port 0 (all SMB hops are NTLM by IP, with a port). LC-03: most lab-IPv4 remote 4624 carry a LogonGuid that matches a DC 4769 (58/61, 117/119, 73/80, 146/152, 109/113, 88/94).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Exclude port-0 hops | Simple | Drops Kerberos hops whose source can still be found |
| B. Link port-0 hops by the non-port methods (4648, command line) and confirm by LogonGuid | Keeps them; uses existing evidence | No tier A for them |

## Decision
Option B. A port-0 4624 never enters a port join (decision 005); its source session comes from the 4648 or command-line method (decision 013), and a LogonGuid match to a DC 4769 is recorded as `confirm = kerberos_logonguid`. Its tier is at most B.

## Consequences
Kerberos hops with port 0 are kept and linked; the tier shows the missing port. No change in the development data (no SMB attack hop has port 0).

## Kill criteria
If a T5 key shows a port-0 attack hop whose source session the non-port methods miss, add a dedicated rule.

## Committee answer
**EN:** When Windows logs port 0 for a Kerberos logon we cannot join on the port, so we use the other source methods and confirm the logon through the domain controller.
**TH:** เมื่อ Windows บันทึกพอร์ต 0 สำหรับ logon แบบ Kerberos เราไม่สามารถเชื่อมด้วยพอร์ตได้ จึงใช้วิธีอื่นหาเซสชันต้นทาง และยืนยัน logon ผ่าน domain controller
