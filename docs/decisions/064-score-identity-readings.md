# 064 — IdentityCoherence readings (closes spec 03 Q9)

**Date:** 2026-11-18 · **Status:** accepted (owner, 2026-11-18) · **Task:** T9.3 · **Relates to:** spec
[05_score](../specs/05_score.md) SC-50..55, Q7–Q10; spec 03 ST-60..64, Q9; [013](013-council-correction-i-amended.md),
[014](014-cross-host-time-tolerance.md), [044](044-stitch-linking-and-windows-council.md) (c), [049](049-stitch-t74-readings.md),
[056](056-sigma-rule-list-lock.md) item 8; Correction K; review ATK-SC-04, -06, -07, -08

## Context
The stitcher writes identity facts per (hop, account, `R1_lsass` read) and computes no value (ST-64). Open: which
reads count, `end_unknown` sessions, hops with several user accounts, paths with no applicable crossing, clock-flagged
order. Measured (§10.3): every variant gives the same value on all 61 in-path (hop, account) pairs, and the hop value
equals the key on 15 of 15 keyed hops. In-path read events: rundll32 18; wmiprvse 12, MsMpEng 12, wininit 9, csrss 9.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| Q7 (a) every R1 read | no list | AV / OS reads with a session open make a benign move "exposed" | ATK-SC-04 |
| Q7 (b) image-name exclusion | simple | a renamed dumper is missed | ATK-SC-04 |
| Q7 (b′) exclusion only for the four images in their system folder **and** under a system account (**chosen**) | narrows Correction K's "credential-access event" to reads that are not routine OS / AV activity (a stated substitution; 056 item 8 left any exclusion to this spec) | a dump injected into a real system process is missed | §10.3 |
| Q8 max over a hop's accounts (**chosen**) vs per-account crossings | hop is the unit (CLAUDE.md) | an exposed co-member lifts the hop | s06 (both 0) |
| Q9 no crossing → 0 (**chosen**) | handoff §12.4 code | "no evidence" scores like "not exposed" → `identity_status` | ATK-SC-06 |
| Q10 value from `order_ok`, low/high beside it (**chosen**) | 044 (c): flag only | — | 0 flagged on dev |

## Decision
A (hop, account) is **1** iff a counted read on the source host has `order_ok` = 1 (move ≥ dump − 5 s, 014) and a
non-empty `open_session_uids`; else 0. Counted reads = `R1_lsass` rows minus (b′): image path (case-insensitive)
`C:\Windows\System32\wbem\wmiprvse.exe`, `…\System32\csrss.exe`, `…\System32\wininit.exe`,
`C:\ProgramData\Microsoft\Windows Defender\Platform\<version>\MsMpEng.exe` or `C:\Program Files\Windows
Defender\MsMpEng.exe`, **and** `dump_account` in {system, network service, local service}. On development data these
cover 331 of 457 read rows; all 126 rundll32 rows (svc_backup 94, admin_it 26, system 6) stay counted. `end_unknown` sessions (Security log cleared between opening and dump) are not
open (ST-63); a session with no logoff event is open (handoff §12.4). Sessions with system logon IDs
0x3e4/0x3e5/0x3e7 and machine accounts are never open sessions (Correction K item 4, ST-63). Machine accounts (K item
4), unknown source host and source host without logs (ST-60, 049) are not crossings; since they leave the
denominator, a path with one exposed hop and one unknown hop gets 1, not 0.5. Hop value = max
over its applicable accounts; IdentityCoherence = coherent crossings / crossings, 0 when there are none. Every row
carries `identity_status` (`exposed`, `not_exposed`, `unknown:<reason>`); `identity_low` / `identity_high` give the
path value with clock-flagged crossings at 0 and 1. Only the moving account and the source host are used (013), so
`target_only` hops get a value. Wording: exposed, never stolen.

## Consequences
- Spec 03 Q9 is closed. On development data the choice changes no value; it is a principled choice, stated as such.
- Correction K sets no upper bound on the dump-to-move gap (L-SC6); s04 track A (benign) is exposed like track B.

## Kill criteria
- Any keyed development hop's value differs from `identity_expected` (SCA-02) → stop and report.
- A test-trial key dump is run by an excluded system image → reported in T10 as a miss of (b′), no retuning.

## Committee answer
**EN:** A move counts as exposed when the moving account had a session open on the source machine when LSASS was read
there, and the move came after that read. We ignore routine reads by Windows and antivirus processes only when they
run from their system folder as a system account, so a renamed tool still counts. Exposure is not theft, and we say so.
**TH:** การเคลื่อนย้ายนับว่า "ถูกเปิดเผย" เมื่อบัญชีที่เคลื่อนย้ายมีเซสชันเปิดอยู่บนเครื่องต้นทางขณะมีการอ่าน LSASS และการเคลื่อนย้าย
เกิดหลังการอ่านนั้น เราไม่นับการอ่านตามปกติของ Windows และโปรแกรมป้องกันไวรัส เฉพาะเมื่อรันจากโฟลเดอร์ระบบด้วยบัญชีระบบ
เครื่องมือที่เปลี่ยนชื่อจึงยังถูกนับ การถูกเปิดเผยไม่ใช่การถูกขโมย และเราระบุไว้ชัดเจน
