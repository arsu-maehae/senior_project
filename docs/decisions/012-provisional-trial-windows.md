# 012 — Provisional trial windows from attack signatures

**Date:** 2026-11-10 · **Status:** accepted (owner), superseded per trial by the T5 answer keys · **Task:** T4 (4.0b)

## Context
Each t00 database holds days of host history (t3 findings §3; s05 ep-03 spans 2026-09-17 to 10-12), so counts and candidate searches need a trial window. No Caldera reports, run manifests or operator notes for the dry runs are available on this PC (owner, 2026-11-10); answer keys come in T5. The run day per scenario is known from the handoff (S01–S04 2026-09-24, S05–S07 2026-10-12, handoff l.1501). A survey of the run days found tight anchor groups:

| Trial | Anchors on the run day (UTC) |
|---|---|
| s02 | dumps ep-01 05:42:00, ep-02 05:41:32; PktDropService (C:\Windows\PktDrop.exe) on ep-02 05:42:05 |
| s03 | dump ep-01 09:40:29; WinRM 91 admin_it on ep-03 09:41:36 |
| s04 | dump ep-01 10:56:56; HealthAgentSvc 10:57:34 and UpdaterService 10:57:37 on ep-02 |
| s05 | dumps ep-01 07:09:43, ep-02 07:11:49; PktDropService 07:10:47; WinRM 91 on ep-03 07:12:48 |
| s06 | no dump; BenignMon (C:\Windows\HealthAgent.exe) 09:04:30; WinRM 91 09:03:56 |
| s07 | dumps ep-01 09:17:06, 09:18:36; XferService 09:17:58, SyncService 09:19:33 on ep-02 |
| s01 | none of its own (EP-01/DC01 files are S02 exports, decision 001) |

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Whole run day | No assumptions | Several trials share a run day (s05–s07; s02–s04), so counts mix trials |
| B. Anchor clusters ± 10 min (spec 00_log_check WN-01…WN-05) | Tight, reproducible, anchors listed for hand checking | Built from attack events, so circular for evaluation |
| C. Wait for T5 keys | Independent | Blocks T4 |

## Decision
Option B for measurement only. Anchors: rundll32 → lsass Sysmon 10; 7045/4697 with an `.exe` directly under `C:\Windows\`; WinRM 91 by a scenario account; clustered by 20-minute gaps; window = cluster ± 600 s; status PROVISIONAL; `no_dump` flag when no dump anchor (S06). s01 t00 uses a manual override (`docs/research/provisional_windows.csv`: the S01 ep-02 export span, reference only). Every report carries the warning that these windows must not be used for evaluation.

## Consequences
T4 counts are scoped to plausible trial windows. T7.6 and T10 must use T5 answer-key windows; the log-check report states which window was used (WN-05). Margins are checked at 300 s as a sensitivity.

## Kill criteria
If a T5 answer key places any attack step outside the provisional window of its trial, recompute that trial's T4 measurements with the key window and note the change in `docs/research/data_reality.md`.

## Committee answer
**EN:** Without run logs for the dry runs we scoped each trial around its own attack signatures, labelled the window provisional, and never use it for evaluation; the answer keys replace it.
**TH:** เนื่องจากไม่มีบันทึกการรันของ dry run เราจึงกำหนดช่วงเวลาของแต่ละ trial รอบร่องรอยการโจมตีของ trial นั้น ระบุว่าเป็นช่วงชั่วคราว และไม่ใช้ในการประเมินผล โดยจะแทนที่ด้วย answer key
