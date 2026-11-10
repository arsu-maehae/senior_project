# 016 — RDP source-side evidence pending S01 t01

**Date:** 2026-11-10 · **Status:** accepted (owner, T4 close) · **Task:** T4 (4.3)

## Context
S01 t00 is target-side only (decision 001): its EP-01 and DC01 files are S02 exports. Target side present: 7 remote 4624 to ep-02 (Type 3, 3 with port 0) and 4 inbound `svchost.exe` Sysmon 3 rows to 3389 (`Initiated = false`). The Sysmon config logs any connection with destination port 3389 (`docs/research/sysmon_config_check.md` §1), so `mstsc.exe` → 3389 on the source will be logged. S01 t01 is not scheduled (owner).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Design RDP linking now from the config alone | Ready early | Untested on real source data |
| B. Keep the generic rule (decision 013: port join tier A) and mark RDP NOT_MEASURABLE until S01 t01 | Honest; no guessing | RDP results come late |

## Decision
Option B. RDP hops use the amended Correction I (port join `mstsc.exe` → 3389 ↔ target 4624 Type 10 or remote Type 3 + inbound 3389, tier A; else 4648/command line). Log-check LC-05 reports NOT_MEASURABLE until S01 t01 is ingested (`/ingest-trial`); then LC-05 is run and this record is updated.

## Consequences
S01 is excluded from the development set until t01 exists (decision 001). The gate's R5 (RDP: Type 10, or remote Type 3 + port 3389) is unchanged.

## Kill criteria
If S01 t01 shows no `mstsc.exe` → 3389 Sysmon 3 row on EP-01, re-examine the endpoint Sysmon config (run `Sysmon64 -c` before collecting).

## Committee answer
**EN:** Our RDP source evidence cannot be measured until the RDP trial is re-collected; the config already logs port 3389, so we keep the standard port join and test it then.
**TH:** หลักฐานฝั่งต้นทางของ RDP ยังวัดไม่ได้จนกว่าจะเก็บ trial RDP ใหม่ การตั้งค่า Sysmon บันทึกพอร์ต 3389 อยู่แล้ว เราจึงใช้การเชื่อมด้วยพอร์ตตามมาตรฐานและจะทดสอบเมื่อได้ข้อมูล
