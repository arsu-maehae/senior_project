# 001 — Which S01 EP-02 export goes into data/raw

**Date:** 2026-11-09 · **Status:** accepted · **Task:** T1 / 1.3

## Context
EP-02 for the S01 dry run exists twice in `data/incoming/dryrun`. They are not byte copies. Handoff_18 §19 and the doc note at line 1501 say S01–S04 ran on 2026-09-24. Counts and times below come from parsing every file with the `evtx` package (read-only).

| Export | Channels | Security records | First → last event (UTC) |
|---|---|---|---|
| `ep-01/Dryrun_S01/EP-02/` | Security, Sysmon, System | 20,346 (id 1–20346) | 2026-09-24 06:06 → 08:17 |
| `ep-02/dryrun_s01/` | Security, Sysmon, System, WinRM, PowerShell | 24,244 (id 1–24244) | 2026-09-11 → 2026-09-15 16:47 (WinRM/System start 09-07) |

Also: the WinRM and System files in `ep-02/dryrun_s01` carry the computer name `WIN-B395B3RKK73`, a default Windows name, not `Endpoint-02`. The same pattern appears in `ep-03/dryrun_s01` (`WIN-V4KV8HLJS0B`).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Keep `ep-01/Dryrun_S01/EP-02` only | Covers 2026-09-24; matches the S01 run | Loses WinRM/PowerShell, which an RDP scenario does not need |
| B. Keep `ep-02/dryrun_s01` only | Larger, five channels | Ends 2026-09-15, nine days before S01; contains no event from the run |
| C. Keep both under different names | Nothing lost | Mixes unrelated events into S01 and breaks the one-file-per-channel layout |

Rule from the user: keep the export that covers the S01 run; if one contains the other, keep the larger. Neither contains the other, so the first part decides.

## Decision
Option A. `ep-01/Dryrun_S01/EP-02/*` becomes `s01/t00/ep-02/{security,sysmon,system}.evtx`. `ep-02/dryrun_s01/*` stays in `data/incoming` only (override file `docs/data_overrides_t00.csv`).

## Consequences
- S01 on ep-02 has no WinRM or PowerShell log. The rule says RDP moves need only Security + Sysmon, so this is not a gap.
- `ep-03/dryrun_s01` (kept as "extra host" by user instruction) also ends 2026-09-15, so it holds no S01-run events. It is kept but marked in the inventory.
- Limitation for the report: some dry-run logs are cumulative from the VM snapshot, not trimmed to the run window.

## Kill criteria
If the S01 answer key or Caldera/operator notes place the S01 run before 2026-09-15, switch to option B.

## Committee answer
**EN:** We kept the EP-02 export whose timestamps cover the S01 run (2026-09-24); the other one ends nine days earlier, so it cannot contain the attack.
**TH:** เราเลือกไฟล์ EP-02 ที่ช่วงเวลาครอบคลุมการรัน S01 (24 ก.ย. 2026) ส่วนอีกชุดสิ้นสุดก่อนหน้านั้นเก้าวัน จึงไม่สามารถมีเหตุการณ์โจมตีอยู่ได้
