# 017 — S06 has no LSASS dump (benign baseline)

**Date:** 2026-11-10 · **Status:** accepted (owner, T4 close) · **Task:** T4 (4.3)

## Context
Log-check LC-08 on s06_t00: no rundll32 → lsass Sysmon 10 in the window (and none on any host in the DB); the provisional window is flagged `no_dump` (decision 012). S06 is the benign baseline (handoff §19.4 l.1474: expected identity 0.0; "benign control" §21 l.1655). Its hops (admin_it WinRM/SMB run by the svc_backup agent with admin_it credentials; h6 svc_backup with the BenignMon service) are expected to pass the gate (T6 not built); h2–h6 have source candidates, h1 will be `target_only`. Note for T5.4: handoff §19.2 (l.1434) says S06 uses SandcatAgent_admin (admin_it), while the t00 data shows the svc_backup agent session 0x1682b.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Treat S06 identity as missing | Avoids a misleading 0 | Correction K defines 0 when no dump precedes the move |
| B. IdentityCoherence = 0 for every S06 hop, as Correction K defines | Follows the locked rule; is the benign control | Identity alone cannot rank among S06 paths |

## Decision
Option B. With no LSASS read on any source host, every S06 hop scores 0 (Correction K, unchanged). S06 serves as the check that benign paths rank below attack paths (handoff §14.2, Correction J).

## Consequences
S06 ranking depends on LengthScore and NodeScore only. Its answer key (T5.4) must list the benign paths.

## Kill criteria
If the S06 answer key or a later trial shows an LSASS read in S06, recompute and update this record.

## Committee answer
**EN:** The benign scenario has no credential dump, so by our identity rule every move in it scores zero; it is the control that benign paths should rank below attack paths.
**TH:** สถานการณ์ปกติไม่มีการ dump credential ตามกฎ identity ของเรา ทุกการเคลื่อนที่ในนั้นจึงได้ศูนย์ และใช้เป็นตัวควบคุมว่าเส้นทางปกติควรถูกจัดอันดับต่ำกว่าเส้นทางโจมตี
