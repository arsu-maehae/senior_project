# 023 — S07: both paths move as `svc_backup`; the key follows the data

**Date:** 2026-11-10 · **Status:** proposed, needs owner approval · **Task:** T5 (5.4)

## Context
The handoff (§19.2, §21.5) names path X `svc_backup` and path Y `svc_sql`; handoff item 0d and l.1933 say to fix the key to the data. Evidence in `ground_truth/drafts/s07_t00.yaml` and `events_dedup` of `s07_t00`:
- Hop X (`XferService`, 4624 09:17:57.75Z) and hop Y (`SyncService`, 4624 09:19:33.18Z) both come from ep-01 and both have a `svc_backup` target 4624 on ep-02. Both agent commands run in the `svc_backup` agent session `0x161a2`. Hop Y's command uses credentials `LAB\svc_sql` (`cmd_credential_account`).
- No `svc_sql` event of any kind exists on ep-02 in this trial (SQL on `events_dedup` of `s07_t00`). The only `svc_sql` endpoint logon is a type-4 session on ep-01 (4648 + 4624 at 2026-10-12 09:10:39.96Z, logon id 91427; the DB holds no 4634 for it, so it counts as open at both dumps). The two target logons on ep-02 differ: X `0x49cdfa`, Y `0x4b5d51` (the handoff, item 0d, says one SMB session `0x49cdfa`; the data shows two).
- Dumps on ep-01: 09:17:06.233Z (X) and 09:18:36.227Z (Y). `svc_backup` session `0x161a2` is open at both; moves are 51.5 s and 57.0 s later. Identity = 1 for both. With the moving account read as `svc_sql` instead, the type-4 session is open at the second dump and the value is also 1, so the identity value does not depend on this choice.

## Decision
Key: two hops `s07-h-x`, `s07-h-y`, separate `attack_pair` paths, moving account `svc_backup` for both; hop Y carries `account_mismatch` and `handoff_mismatch` (handoff account `svc_sql`). The two hops share source session, target and account, so identity cannot separate them; only the service name and logon ids do.

## Consequences
The under-fire test no longer has two different moving accounts. The report states that S07 tests two paths of one account (limitation); it does not claim two identities.

## Deviation from the design (owner, 2026-11-10)
The S07 design has two identities (`svc_backup`, `svc_sql`); the collected t00 data has one. This is recorded as a deviation. TODO: check S07 t01–t10 for any `svc_sql` 4624 on ep-02 once ingested. If no trial has one, it becomes a limitation for the report (S07 tests two paths of one account, not two identities).

## Kill criteria
If a t01 trial shows a `svc_sql` 4624 on ep-02, split the hops by account.

## Committee answer
**EN:** In S07 both moves reached ep-02 under the same account, so identity cannot tell the two paths apart; they are told apart by their services and logons.
**TH:** ใน S07 การเคลื่อนที่ทั้งสองเข้า ep-02 ด้วยบัญชีเดียวกัน identity จึงแยกสองเส้นทางไม่ได้ แยกได้ด้วยบริการและ logon
