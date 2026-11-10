# 027 — Answer key: the moving account is the one the target logged

**Date:** 2026-11-10 · **Status:** accepted (owner, 2026-11-10, after reviewing the six-hop rows) · **Task:** T5

## Context
In two development scenarios the command asked for one account and the target logged another (`docs/research/agent_evidence.md`, decisions 023 and 024; rows reviewed by the owner):
- **S07 hop Y** (`s07-h-y`): the agent session `0x161a2` (`svc_backup`) ran `net use \\192.168.50.22\IPC$ /user:LAB\svc_sql …`; the target 4624 on ep-02 (09:19:33.18Z, logon `0x4b5d51`) and the 4697 `SyncService` carry `svc_backup`. No `svc_sql` event exists on ep-02 in `s07_t00`.
- **S06 `s06-smb-1`**: the `svc_backup` agent ran `net use \\192.168.50.22\ADMIN$ /user:LAB\admin_it …; sc.exe \\192.168.50.22 create BenignMon`; the 4697 `BenignMon` is tied by SubjectLogonId to a `svc_backup` logon (`0x2f219d`); the `admin_it` NTLM logon (`0x2f2125`, 09:04:30.593Z) sits 49 ms earlier and is recorded as a `credential_logon_uids` entry.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Key account = the account requested in the command | Matches the design (S07: two accounts) | The pipeline sees only the target 4624/4697; scoring against an account it cannot see would count a correct link as wrong |
| B. Key account = the target-side account (target 4624 / artefact logon), requested account kept as a note | Matches what the pipeline can observe; identity (Correction K) already uses the target 4624 account (CLAUDE.md "Identity input") | The key no longer shows the designed account for these hops |

## Decision
Option B. `hops[].account` is `logon_account` (the target-side account). The requested account stays in `cmd_credential_account`, the agent's own account in `agent_account`; a difference sets `account_mismatch` and, where the handoff names another account, `handoff_mismatch`. This is the existing implementation, now stated as a rule.

## Consequences
S07's two-account design did not happen as intended in t00: both hops move as `svc_backup`. TODO: check S07 t01–t10 for any `svc_sql` 4624 on the target; if no S07 trial shows `svc_sql` on the target, add a limitation to `docs/report/limitations_future_work.md` that S07's two-account design did not happen as intended (see decision 023). The S06 `admin_it` credential logon is a supporting logon of the hop, not a second hop.

## Kill criteria
If an S07 trial shows a `svc_sql` 4624 on ep-02 for the Y command, split the hops by target-side account.

## Committee answer
**EN:** The answer key records the account the target machine actually logged, because that is what our pipeline can see; the account the command asked for is kept as a note.
**TH:** เฉลยบันทึกบัญชีที่เครื่องเป้าหมายบันทึกจริง เพราะเป็นสิ่งที่ pipeline มองเห็น ส่วนบัญชีที่คำสั่งขอไว้เก็บเป็นหมายเหตุ
