# 014 — Cross-host time tolerance of at least 5 s

**Date:** 2026-11-10 · **Status:** accepted (owner, T4 close) · **Task:** T4 (4.3)

## Context
Log-check LC-09 (mutual-nearest 4624 ↔ DC 4769 pairs, p50 per host): ep-01 −1.1 to +3.4 s, ep-02 −1.7 to +2.7 s, ep-03 +4.0 to +4.5 s versus dc01 (medians; single pairs spread further, e.g. S07 ep-02 −4.1 to +8.5 s); dc01 against itself 5–6 ms; S04 flagged `dc01_skew_possible`. Offsets change per trial (snapshot revert). In the SMB hops the source command appears −3.1 to +1.1 s from the target 4624 (`docs/research/data_reality.md` §2.7). Security 4688 and Sysmon 1 agree on every host (median 0 ms). Sysmon record-time outliers on ep-02/ep-03 (decision 010).

## Evidence added from the T5 keys (2026-11-10)
The key's `time_delta_ms` is the target 4624 time minus the first agent command naming the target, in ms (`ground_truth/drafts/*.yaml`, hops with status `confirmed`). A target event cannot precede the command that causes it, so a negative value means the target host's clock is behind the source host's by at least that much (a lower bound; the true offset also includes the delay between command start and network use). Positive values mix clock offset with script start-up time and say nothing about offsets.

| Source → target | Hop | `time_delta_ms` |
|---|---|---|
| ep-01 → ep-02 | s02-h1 | −793 |
| ep-01 → ep-02 | s04-A-h1 | −1085 |
| ep-01 → ep-02 | s04-B-h1 | −907 |
| ep-01 → ep-02 | s06-winrm-1 | −370 |
| ep-01 → ep-02 | s06-smb-1 | −3921 |
| ep-01 → ep-02 | s05-h1 | +336 |
| ep-01 → ep-02 | s07-h-x / s07-h-y | +3729 / +2339 |
| ep-01 → ep-03, ep-02 → ep-03 | s03-h1, s05-h2, s06-winrm-2 | +2763, +2421, +6094 |

On ep-01 → ep-02, target events are logged about 1 s before the source command on 2026-09-24 (S02, S04: −0.8 to −1.1 s) and up to 3.9 s before it on 2026-10-12 (S06 `s06-smb-1`), so ep-02's clock is behind ep-01's by at least those amounts. The largest observed lower bound (3.9 s) is inside the 5 s tolerance but close to it. These are lower bounds from single hops, not a measured offset per host pair.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. 1–2 s tolerance | Few false candidates | Misses ep-03 hops (offset 4.5 s) and S07 h2 (−3.1 s) |
| B. ≥ 5 s tolerance for cross-host comparisons | Covers every measured median offset (not every single pair) | More candidates in busy windows (recorded in `candidate_count`) |
| C. Correct each host by its measured offset | Tighter | Offsets measured from few pairs (3–23 per host) and change per trial |

## Decision
Option B. Every cross-host time join (port join, 4648, command line vs target 4624, WinRM 91) uses a tolerance of at least 5 s (parameter, default 5 s for port joins; the command-line window stays [t − 120 s, t + 10 s], spec 00_log_check). The Correction K order check (dump before the move) is also cross-host: per CLAUDE.md "Identity input" the move time is the target 4624 time (target clock) and the dump time is on the source host. A hop counts as "after the dump" when 4624 time ≥ dump time − 5 s; hops within ±5 s of the dump are flagged `order_within_tolerance`. On t00 every dump-to-move gap is ≥ 38 s (S04 10:56:56→10:57:34, S03 09:40:29→09:41:36, S05 07:11:49→07:12:48, S07 09:17:06→09:17:58), so no hop is affected. *(Corrected after the fact-check; the earlier text said this check was same-host.)* Measured offsets are reported per trial, not applied.

## Consequences
`time_delta_ms` is recorded on every link row, so the tolerance can be audited. T7 adds a sensitivity check at 2, 5 and 10 s. Limitation: no absolute time reference; dc01 is the reference.

## Kill criteria
If T7.6 link accuracy changes when the tolerance goes from 5 s to 10 s, or a keyed hop falls outside 5 s, revisit (option C).

## Committee answer
**EN:** Host clocks in the lab differ from the domain controller by up to about 4.5 s, so every cross-host comparison — including the dump-before-move check — allows at least 5 s.
**TH:** นาฬิกาของเครื่องในแล็บต่างจาก domain controller ได้ถึงราว 4.5 วินาที การเปรียบเทียบข้ามเครื่องทุกแบบ รวมถึงการตรวจว่า dump เกิดก่อนการเคลื่อนที่ จึงยอมให้คลาดเคลื่อนอย่างน้อย 5 วินาที
