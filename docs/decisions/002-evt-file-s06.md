# 002 — `EP01_PowerShell.evt` in S06 is EVTX

**Date:** 2026-11-09 · **Status:** accepted · **Task:** T1 / 1.3

## Context
`ep-01/Dryrun_S06/EP01_PowerShell.evt` has an `.evt` extension. Legacy EVT files start with `LfLe`; EVTX files start with `ElfFile\0`.
- Header bytes: `45 6c 66 46 69 6c 65 00` = `ElfFile\0` (EVTX).
- Size 1,118,208 bytes. The `evtx` parser reads 151 records (id 1–151), 2026-09-24 09:26 → 2026-10-12 09:07 UTC, with no error.
- First record: Channel `Microsoft-Windows-PowerShell/Operational`, Computer `Endpoint-01.lab.local`.
- The S07 sibling `EP01_PowerShell.evtx` has the same channel.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Copy as `.evtx` | Parses; the S06 PowerShell log is not lost | Renames a file (recorded in the mapping) |
| B. Exclude | Follows the extension | Throws away a valid log; the converter would then never see it |

## Decision
Option A. Destination `s06/t00/ep-01/powershell.evtx`; mapping reason "EVTX header, renamed from .evt". The original stays untouched in `data/incoming`. The rule is by header, not extension, so it applies to real trials too. A file with legacy `LfLe` magic would be excluded.

## Consequences
The converter's "legacy EVT not supported" note does not apply to this file. Limitation: none expected.

## Kill criteria
If the converter fails on this file in T3, exclude it and record the error.

## Committee answer
**EN:** We decide by the file header, not the extension; this file is a valid EVTX log with a wrong name.
**TH:** เราตัดสินจากส่วนหัวของไฟล์ ไม่ใช่นามสกุล ไฟล์นี้เป็น EVTX ที่ถูกต้องแต่ตั้งชื่อนามสกุลผิด
