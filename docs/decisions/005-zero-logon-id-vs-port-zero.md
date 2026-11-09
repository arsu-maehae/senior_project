# 005 — Logon ID 0 becomes NULL, port 0 stays 0

**Date:** 2026-11-10 · **Status:** accepted · **Task:** T3

## Context
Evidence: `s01_t00/dc01/security.jsonl` line 2 is a 4688 with SubjectLogonId 0x5f3f3 and TargetLogonId 0x0. The current fallback chain (`normalize.py:289`) picks TargetLogonId first, so `session_id` becomes 0 instead of 0x5f3f3. Kerberos 4624 rows carry SubjectLogonId 0x0 and 4625 carries TargetLogonId 0x0. For ports: S01 EP-02 Security has 3 of 7 remote 4624 rows with IpPort 0 (Kerberos).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Logon-ID 0 to NULL, column chosen by event ID; port 0 stays 0 | Joins on 0 cannot glue unrelated events; a logon ID of 0 carries no meaning | Two zero rules |
| B. Keep 0 everywhere, filter at join time | One rule | One forgotten filter silently joins unrelated rows |
| C. NULL both | One rule | Loses the fact that Windows logged a port of 0 |

## Decision
Option A (owner, 2026-11-10). The logon-ID column is chosen by event ID (NF-11) and `0x0` is stored as NULL in the logon-ID join columns. Port 0 is stored as 0 and links use port > 0 only (NF-03). They differ because a logon ID of 0 is never a real session (it is a placeholder, so NULL is its true value), whereas port 0 is a value Windows really logged for a Kerberos logon: we keep that fact and refuse to use it as a key.

## Consequences
The stitcher cannot join sessions on 0. The raw value stays readable in the JSONL through `source_line`. The report must state the two rules together.

## Kill criteria
If a real session with logon ID 0 appears in the data, or a link needs port 0, reopen.

## Committee answer
**EN:** A logon ID of 0 means "no session", so we store nothing; a port of 0 is a real logged value, so we keep it but never join on it.
**TH:** Logon ID เป็น 0 หมายถึง "ไม่มีเซสชัน" จึงเก็บเป็นค่าว่าง ส่วนพอร์ต 0 เป็นค่าที่ Windows บันทึกจริง จึงเก็บไว้แต่ไม่ใช้เป็นคีย์เชื่อม
