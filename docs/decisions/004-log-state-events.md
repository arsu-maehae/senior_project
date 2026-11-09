# 004 — Keep log-cleared and shutdown events

**Date:** 2026-11-10 · **Status:** accepted · **Task:** T3

## Context
The attacker review found that NF-09 kept only logons and logoffs. The first record of `s01_t00/dc01/security.jsonl` is a 1102 (log cleared at 2026-09-24 04:54). Sessions open before a clear have no 4624, and sessions ended by a reboot have no 4634. Correction K (CLAUDE.md) needs "session still open" to be told apart from "log truncated or host restarted".

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Whitelist only 4634/4647 | Smallest DB | Cannot tell a never-closed session from a truncated log |
| B. Add 1102, 104, 6005, 6006, 6008, 41, 1074 | Gives the stitcher a log-state signal; the events are rare | Seven more IDs to test |

## Decision
Option B (owner, 2026-11-10). Security 1102 and System 104, 6005, 6006, 6008, 41, 1074 join the kept IDs, together with Security 4634, 4647 and 4688 if present.

## Consequences
A session with no logoff can be marked "unknown end" when a clear, shutdown or restart follows it. Limitation for the report: dry-run logs start at a log clear, so a first-record 1102 is expected.

## Kill criteria
If T4 shows none of these events occurs in the development trials, drop them from the whitelist.

## Committee answer
**EN:** A missing logoff does not mean a session is still open; we keep log-clear and restart events so we can say "unknown" instead of guessing.
**TH:** ถ้าไม่มีเหตุการณ์ logoff ไม่ได้แปลว่าเซสชันยังเปิดอยู่ เราจึงเก็บเหตุการณ์ล้างล็อกและรีสตาร์ทไว้ เพื่อบอกว่า "ไม่ทราบ" แทนการเดา
