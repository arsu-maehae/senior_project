# 032 — Clocks: sync before reruns, per-trial offset correction for kept trials, collector IPs

**Date:** 2026-11-11 · **Status:** owner-directed 2026-11-11; the correction method is a proposal, to be decided on development data before any scoring · **Task:** ×10 ingest and validation · **Relates to:** decision 014 (5 s cross-host tolerance), 026 (trial window), 029 (criterion g)

## Context
Criterion g measures each endpoint's offset against dc01 from endpoint 4624 ↔ dc01 4769 pairs with the same LogonGuid (validation report §5, `docs/research/x10_design_validation.md`). Findings:
- S02 and S03 (2026-10-15): host-pair offsets are within 5 s, except ep-03 at 5–10 s in some trials.
- S04, S05 (quarantine), S06, S07 (2026-10-26/27): ep-01 is about 10–27 s behind dc01 and behind ep-02 and ep-03 in almost every trial; ep-02 stays within a few seconds of dc01. Example `s06_t04`: ep-01 − dc01 median −25.0 s (data-checker, 2 pairs), validator −24.7 s.
- Decision 014's tolerance is 5 s. The identity rule ("the move happened after the dump") compares a source-host time (dump on ep-01) with a target-host time (4624 on ep-02), so an ep-01 clock that is behind by more than 5 s can reverse the order.
- g is a WARN in decision 029 and changed no verdict.
Also seen in the data: at the end of most trials, `admin_it` WinRM sessions from 192.168.50.97, .98 and .99 reach the endpoints. They are not part of any design.

## Decision
1. **The tolerance is not widened.** It stays 5 s (decision 014).
2. **Before any rerun** all VMs are time-synced. Offsets between hosts are checked at the start and at the end of each session and written down (`docs/lab/rerun_plan.md`, `docs/PROGRESS.md`). A session whose end offset exceeds 5 s is reported to the owner before its trials are accepted.
3. **For kept trials** (trials that stay in the set with known offsets), the proposal is a per-host, per-trial offset correction applied before linking: the offset of each endpoint against dc01 is estimated from the trial's own LogonGuid pairs (the criterion g measure) and subtracted from that host's event times. Conditions:
   - The method, the minimum number of pairs and the handling of hosts with too few pairs are decided on **development** data only (t00, and t01 once valid), before any scoring. Test trials are never used to tune it.
   - The estimated offsets are stored per trial next to the DB and are reported with every result.
   - The original times are kept; the correction is a separate step, not an edit of the events.
   - A host with no usable pairs gets no correction, and the trial is flagged.
4. **Collector IPs.** The following addresses are recorded for exclusion from trial activity:

| IP | Workstation name seen | Observed as |
|---|---|---|
| 192.168.50.97 | ARSU-MAEHAE | `admin_it` WinRM/network logons at the end of trials (for example `s04_t05`, `s04_t10`) |
| 192.168.50.98 | not recorded | `admin_it` network logons on ep-01 (for example `s04_t01`) |
| 192.168.50.99 | DESKTOP-VSUAVJ5 | `admin_it` network logons on ep-02 followed by `wsmprovhost.exe` (S04 `t01`–`t10`) |

   Their purpose (log collection) is inferred, not confirmed. They are excluded by the trial window (PLAN T6.4). Note for T6.4: in `s04_t01` the .99 logon (04:12:22 UTC) lies inside the design window, which ends at 04:13:01, so the window clip alone may not remove such sessions. The owner decides whether T6.4 also excludes these source IPs explicitly.

## Consequences
- Reruns start from synced clocks, so no correction is expected for them.
- The correction in point 3 applies only to trials kept with offsets (S02, S03, S06 except the replaced trials). It is not implemented; it needs a spec and an entry in PLAN before the gate and stitcher are built.

## Kill criteria
If on development data the corrected times still leave more than 5 s between the host pairs, or the pairs are too few to estimate an offset, the correction is not used and the affected trials are excluded or rerun.

## Committee answer
**EN:** We keep the 5-second tolerance. We sync the clocks before new runs and measure them at the start and end of each session. For the trials we keep, we propose a per-trial correction decided on development data only.
**TH:** เรายังคงเกณฑ์ความคลาดเคลื่อน 5 วินาทีไว้ ซิงค์นาฬิกาก่อนรันใหม่และวัดต้นและท้ายแต่ละรอบ สำหรับรอบที่เก็บไว้เสนอให้แก้เวลารายรอบ โดยตัดสินใจจากข้อมูลชุดพัฒนาเท่านั้น
