# 036 — S01 includes a credential-access (dump) step on ep-01; RDP rules confirmed

**Date:** 2026-11-11 · **Status:** accepted (owner, 2026-11-11) · **Task:** ×10 ingest and validation · **Amends:** 035 (the S01 design table; open points 1 and 2 are closed here)

## Context
Decision 035 transcribed the S01 design from the handoff and decision 016 and left two points open: whether S01 has an LSASS dump on ep-01, and whether a remote type 3 with inbound port 3389 counts as RDP.

## Decision
1. **S01 has a dump step.** The design table gets `dump_ep-01`: one LSASS read on ep-01 before the RDP hop, measured like the dump step of the other scenarios (decision 029): a rundll32 → lsass Sysmon 10 on ep-01 by a user token, one in the trial window. The dumping account must be the intended account `svc_backup` (as S05 ep-02 names its dumping account); the observed account is reported. The step is needed so the identity rule (Correction K: the moving account had a session open on the source host when LSASS was read) can be evaluated for S01.
   - **How S02–S07 handle it:** `DumpDesign` entries in `src/x10_validate/design.py` (S02, S03, S04 and S07 one or two dumps on ep-01, S05 one on ep-01 and one on ep-02 by `admin_it`); criterion b needs the step present in the trial window; criterion h counts executions of the dump (N12); criterion d fires on a dump only in S06. The validator checks that the dump is present, not its order relative to the hop.
   - **Reconciling the sources:** the owner states that the S01 design in the x10 trial validity note included the dump, while the handoff (§21.5, §21.8) names only the RDP hop and lists LSASS edges for the other scenarios. That validity note is not in the repository (checked in `docs/research/`, `docs/PROGRESS.md` and the decisions). Under this record the dump step is part of S01, following the owner's statement; the handoff text should be read as incomplete for S01, not as excluding the dump.
2. **Type 3 + inbound 3389 within 5 s stays accepted as RDP (035, N17).** Both events are logged on ep-02, so clock drift between hosts does not affect the 5 s pairing.
3. **Note for the lab:** S01 RDP should be run by **hostname**, so that it produces a clean type 10 logon (connecting by IP can produce type 3 under NLA, handoff Correction E4).
4. **The `x10_v2` source option of the validator is left to the separate `x10_v2` work** (decision 034, rerun plan).

## Consequences
- The validator's S01 design table gets the dump step; tests are updated; the regression on the 66 existing trials must stay at 0 status differences (S01 has no ×10 data yet).
- 035 note N20 ("a dump in an S01 run changes no status") no longer holds: the dump is a design step.
- The S01 design needs no further confirmation for the dump; the rest of 035 stands.

## Kill criteria
If the first S01 trial shows the RDP hop but no dump, criterion b FAILs; the owner decides whether the design or the run is wrong before more trials are run.

## Committee answer
**EN:** S01 now includes a credential-dump step on EP-01 before the RDP move, so the identity rule can be tested on S01 like on the other scenarios.
**TH:** S01 มีขั้นตอนดึงข้อมูลยืนยันตัวตน (dump) บน EP-01 ก่อนการเชื่อมต่อ RDP เพื่อให้ทดสอบกฎตัวตนกับ S01 ได้เหมือนสถานการณ์อื่น
