# 033 — S07: path Y runs under path X's logon, so `svc_sql` never authenticates on ep-02

**Date:** 2026-11-11 · **Status:** owner-directed 2026-11-11; cause supported at event level; the fix is proposed and untested · **Task:** ×10 ingest and validation · **Relates to:** decision 027 (key account is target-side), 029 (criterion c), 024 (S06 shows a similar target-side account)

## Context
Criterion c of the validation (`docs/research/x10_design_validation.md`) fails in all 10 S07 trials: the design account of path Y is `svc_sql`, but ep-02 never logs it. t00 shows the same (decision 027). The owner's hypothesis: the SMB logon session that path X opened to ep-02 as `svc_backup` is reused by path Y, so path Y's `svc_sql` credentials are never used on ep-02.

## Evidence (event level only; read-only SQL on `events_dedup`; s07_t00 to s07_t10)
For each trial, path X's first `svc_backup` 4624 on ep-02 (network logon from 192.168.50.21) has a logon id. Looking at the events that belong to path Y on ep-02:

| trial | path X logon id on ep-02 | seconds from that logon to path Y's `ADMIN$` write | subject logon id of path Y's `ADMIN$` write |
|---|---|---|---|
| s07_t00 | 4836858 | 95.3 | same as X |
| s07_t01 | 3070786 | 102.1 | same as X |
| s07_t02 | 2934647 | 91.3 | same as X |
| s07_t03 | 2969694 | 117.6 | same as X |
| s07_t04 | 2892631 | 104.5 | same as X |
| s07_t05 | 3005470 | 104.4 | same as X |
| s07_t06 | 2889858 | 98.5 | same as X |
| s07_t07 | 2908078 | 113.3 | same as X |
| s07_t08 | 3079921 | 88.5 | same as X |
| s07_t09 | 2950809 | 109.5 | same as X |
| s07_t10 | 2911313 | 103.5 | same as X |

Further facts, the same in all 11 trials:
- No 4624 for `svc_sql` exists on ep-02 between the start of path Y and its `ADMIN$` write; no row of any event type on ep-02 carries `svc_sql` as account (0 rows).
- Path X's logon id has no 4634 (logoff) in the DB before path Y's write: the logon stays open from path X until path Y.
- The service created for path Y (4697, `SyncService`) has subject `svc_backup`. Its subject logon id is a new, short-lived `svc_backup` network logon from 192.168.50.21 (4624 and 4634 within about 20–70 ms), not the `svc_sql` one. Each service call also produces one further short `svc_backup` logon.
- `svc_sql` authenticates only on ep-01 (4624 with logon type 4 and 4648 with target localhost, in every trial) and on dc01 (4769 for the ep-01 machine account in 5 of 11 trials).

## Finding
At the event level, path Y reuses path X's `svc_backup` logon on ep-02. `svc_sql` is used on ep-01 but never authenticates on ep-02. The hypothesis is supported in 11 of 11 trials. Limits: the data show that the logon is reused and that no `svc_sql` logon exists; they do not show why. S06's target-side account pattern (decision 024) looks similar but was not re-examined here.

## Proposed fix (not yet tested)
Path Y must come from a session that really authenticates as `svc_sql` on ep-02, as its own logon, with path X's logon to ep-02 no longer open (a 4634 for it before path Y's first event on ep-02). The mechanism is left to the lab owner; this record fixes only what the events must show.

## Acceptance test (1 trial, before the other 9)
Run one S07 trial, ingest it, run the x10 validator. It passes only if:
1. ep-02 logs a 4624 (network logon from 192.168.50.21) for `svc_sql` in path Y's time range;
2. the subject logon id of path Y's `ADMIN$` write and service creation equals that logon's id;
3. the validator reports criterion c = PASS for path Y with the observed account `svc_sql`, and no criterion has a FAIL.
If it fails, no further trials are run (rule in `docs/lab/rerun_plan.md`).

## Consequences
- The S07 full rerun (decision 029, rule 3; owner answer 2026-11-11) waits for a confirmed fix.
- If the fix cannot make `svc_sql` authenticate on ep-02, the owner records a limitation in `docs/report/limitations_future_work.md` (the decision 027 TODO), and S07's design account for path Y is revisited.
- The key account remains the target-side account (decision 027).

## Kill criteria
If the 1-trial acceptance test shows `svc_sql` on ep-02 but with path Y's actions still under another logon id, the finding is wrong or incomplete and this record is reopened.

## Committee answer
**EN:** In S07 the second path used the logon that the first path had already opened on ep-02, so the second account never logged on there. We propose a separate logon for the second path and test it with one trial first.
**TH:** ใน S07 เส้นทางที่สองใช้เซสชันที่เส้นทางแรกเปิดไว้แล้วบน ep-02 จึงไม่มีการล็อกอินของบัญชีที่สองที่นั่น เสนอให้เส้นทางที่สองใช้เซสชันแยกต่างหาก และทดสอบด้วยหนึ่งรอบก่อน
