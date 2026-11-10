# 018 — S04: both tracks score identity 1 (exposed ≠ stolen)

**Date:** 2026-11-10 · **Status:** accepted (owner, T4 close) · **Task:** T4 (4.3)

## Context
Log-check LC-08b on s04_t00: at the LSASS dump on ep-01 (10:56:56), admin_it had an agent session (0x17b18, type 4, since 10:54:47) and a desktop session (0xd6398/0xd663a, type 11, since 10:55:16) open; svc_backup had 0x17c46 (type 4). Track A (admin_it, HealthAgentSvc) and Track B (svc_backup, UpdaterService) both move to ep-02 after the dump, so both score 1 under Correction K. The same pattern holds at every dump: admin_it desktop sessions are open on the dump host in S02–S05 and S07. Handoff Correction H.2 (handoff_18.md:148, :204) predicted this under the "every account signed in at dump time" definition.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Change Correction K to the account that ran the dump | Track A would score 0 | Locked decision; the dumper's account is not the stolen credential (Option D, handoff H.4) |
| B. Keep Correction K; report S04 Track A = Track B on identity as a known limitation | Honest; matches "exposed ≠ stolen" | The S04 ablation cannot show identity separating the tracks |

## Decision
Option B (owner, 2026-11-10). Correction K is not changed. S04's identity values are reported as 1 and 1; the S04 ablation result is stated with this limitation (L12). Ties between the two tracks must not be broken arbitrarily in ranking: T9 reports them as ties.

## Consequences
S04 can no longer be presented as the case where the identity term separates attacker from admin. Ranking of the tracks rests on LengthScore and NodeScore (the dump node is on the attack path only if stitching attaches it). Report text must say "exposed", never "stolen".

## Kill criteria
If a T5 answer key shows admin_it had no session open at the S04 dump in a test trial, report per-trial values instead of this general statement.

## Committee answer
**EN:** Our identity rule asks whether the moving account was exposed on the source host at the dump; in S04 the admin was logged on there too, so both moves score one — exposure is not proof of theft.
**TH:** กฎ identity ของเราถามว่าบัญชีที่เคลื่อนที่ถูกเปิดเผยบนเครื่องต้นทางขณะ dump หรือไม่ ใน S04 ผู้ดูแลระบบก็ล็อกอินอยู่บนเครื่องนั้น ทั้งสองการเคลื่อนที่จึงได้หนึ่ง การถูกเปิดเผยไม่ใช่หลักฐานว่าถูกขโมย
