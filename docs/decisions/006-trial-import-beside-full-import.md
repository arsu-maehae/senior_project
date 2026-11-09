# 006 — New trial_import.py beside full_import.py

**Date:** 2026-11-10 · **Status:** accepted · **Task:** T3

## Context
`full_import.py:25-26` hard-codes 85 files and 2,981,147 events; `preflight` (l.86-135) needs a profile file and a fixed workspace layout; `smoke_import.py:248` and `profile.py:335` hard-code 85 too. Seven tests in `src/parsing_normalization/tests/test_full_import.py` depend on that.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Parametrise `run_full_import` | One code path | Changes reviewed code; seven tests must change |
| B. Add `trial_import.py`, reuse helpers | Old code and tests untouched; per-trial rules in one new module | Some duplicated glue |

## Decision
Option B (owner, 2026-11-09). `full_import.py` and its tests stay untouched; `trial_import.py` reuses `normalize_event`, `_row_values`, `_insert_batch` and the duplicate-ledger code where they fit.

## Consequences
The old command keeps working on the original run. Trial imports get their own checks (NF-17).

## Kill criteria
If more than a third of `trial_import.py` is copied from `full_import.py`, refactor into a shared module.

## Committee answer
**EN:** We left the reviewed importer untouched and added a per-trial importer that reuses its functions.
**TH:** เราไม่แก้ตัวนำเข้าเดิมที่ผ่านการรีวิวแล้ว แต่เพิ่มตัวนำเข้าแบบต่อ trial ที่เรียกใช้ฟังก์ชันเดิม
