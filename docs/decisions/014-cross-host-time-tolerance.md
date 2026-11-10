# 014 — Cross-host time tolerance of at least 5 s

**Date:** 2026-11-10 · **Status:** accepted (owner, T4 close) · **Task:** T4 (4.3)

## Context
Log-check LC-09 (mutual-nearest 4624 ↔ DC 4769 pairs, p50 per host): ep-01 −1.1 to +3.4 s, ep-02 +0.07 to +2.7 s, ep-03 +4.0 to +4.5 s versus dc01; dc01 against itself 5–6 ms; S04 flagged `dc01_skew_possible`. Offsets change per trial (snapshot revert). In the SMB hops the source command appears −3.1 to +1.1 s from the target 4624 (`docs/research/data_reality.md` §2.7). Security 4688 and Sysmon 1 agree on every host (median 0 ms). Sysmon record-time outliers on ep-02/ep-03 (decision 010).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. 1–2 s tolerance | Few false candidates | Misses ep-03 hops (offset 4.5 s) and S07 h2 (−3.1 s) |
| B. ≥ 5 s tolerance for cross-host joins; same-host ordering on the host's own clock | Covers every measured offset | More candidates in busy windows (recorded in `candidate_count`) |
| C. Correct each host by its measured offset | Tighter | Offsets measured from few pairs (3–23 per host) and change per trial |

## Decision
Option B. Every cross-host time join (port join, 4648, command line vs target 4624, WinRM 91) uses a tolerance of at least 5 s (parameter, default 5 s for port joins; the command-line window stays [t − 120 s, t + 10 s], spec 00_log_check). Ordering on one host (dump before the move's command, Correction K) uses that host's own clock and needs no tolerance. Measured offsets are reported per trial, not applied.

## Consequences
`time_delta_ms` is recorded on every link row, so the tolerance can be audited. T7 adds a sensitivity check at 2, 5 and 10 s. Limitation: no absolute time reference; dc01 is the reference.

## Kill criteria
If T7.6 link accuracy changes when the tolerance goes from 5 s to 10 s, or a keyed hop falls outside 5 s, revisit (option C).

## Committee answer
**EN:** Host clocks in the lab differ from the domain controller by up to about 4.5 s, so cross-host joins allow at least 5 s; ordering on one host uses that host's own clock.
**TH:** นาฬิกาของเครื่องในแล็บต่างจาก domain controller ได้ถึงราว 4.5 วินาที การเชื่อมข้ามเครื่องจึงยอมให้คลาดเคลื่อนอย่างน้อย 5 วินาที ส่วนการเรียงลำดับบนเครื่องเดียวใช้นาฬิกาของเครื่องนั้นเอง
