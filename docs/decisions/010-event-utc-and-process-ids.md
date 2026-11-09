# 010 — Sysmon event time column and 4688 process IDs

**Date:** 2026-11-10 · **Status:** accepted · **Task:** T3

## Context
The attacker's re-check found two columns whose meaning would mislead the stitcher. (1) `timestamp_utc` is the EVTX record time; for Sysmon the record time is later than the event's own `UtcTime`: s02_t00 ep-02 sysmon line 214 differs by 1.96 s, s05_t00 ep-02 sysmon line 107 by 6.8 s. A 4624 to Sysmon 3 time delta (Correction I) would be off by that much. (2) For Security 4688, `process_id` holds the creator's PID (0x27d8 in s02_t00 ep-02 security line 8) next to `image` = wevtutil.exe, whose new PID 0x700 is dropped.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Add `event_utc` (Sysmon UtcTime, else record time); keep `timestamp_utc` | Nothing existing changes; stitcher picks the right time | One more column; two times to explain |
| B. Replace `timestamp_utc` by UtcTime for Sysmon | One time column | Mixed meaning across channels; ordering and dedup change |
| C. Leave as is | No work | Time deltas wrong by seconds |
| 4688 D. `process_id` = NewProcessId, `parent_process_id` = creator | Matches `image`; joins to Sysmon 1 (`process_id`) | Different from `normalize_event` for 4688 only |

## Decision
A for time (NF-23) and D for 4688 (NF-24). Owner rules are untouched; both are additions or a corrected meaning of a column the owner had not specified.

## Consequences
Stitching uses `event_utc` for time windows and deltas, and records which column it used. The report states that Sysmon `timestamp_utc` is record time.

## Kill criteria
If the maximum gap between `event_utc` and `timestamp_utc` is under 100 ms on all trials, drop `event_utc`.

## Committee answer
**EN:** Sysmon logs when it wrote the record and when the event happened; we keep both and use the event time for linking.
**TH:** Sysmon บันทึกทั้งเวลาที่เขียนระเบียนและเวลาที่เหตุการณ์เกิดขึ้น เราเก็บทั้งสองและใช้เวลาเกิดเหตุการณ์ในการเชื่อม
