# 003 — Non-event files, identical exports, trial id t00

**Date:** 2026-11-09 · **Status:** accepted · **Task:** T1 / 1.3

## Context
- `ep-02/dryrun_s05/vmware-vmtoolsd-svc_backup.log` is a text file (6,804 bytes, VMware Tools lines dated 2026-09-17), not an event log. The folders `DiagOutputDir` and `vmware-SYSTEM` that the user named are not present under `incoming`.
- Six file pairs are byte-identical across scenarios (same sha256): all three DC01 files of S01 and S02, and all three EP-01 files of S01 and S02 (for example DC01 Security, 14,823 records in both).
- The dry runs were handed over with no trial number.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Identical files: copy both | Layout stays one folder per scenario; mapping stays 1:1 | Same events counted twice if S01 and S02 are ever merged |
| Identical files: keep one | Saves 6 files | Breaks the per-scenario layout; hides the fact |
| Non-event files: exclude from `data/raw` | Raw stays only logs | Nothing lost; the file stays in `incoming` |

## Decision
1. Ignore non-event files by name (`vmware-*`, `DiagOutputDir`, `vmware-SYSTEM`) and by missing EVTX header. They stay in `incoming`.
2. Copy identical S01/S02 files to both scenarios, and flag them in `docs/data_inventory.md` ("identical to s02"). Do not deduplicate by content.
3. Dry runs get trial id `t00`; real trials are `t01`–`t10`. The word "dryrun" is not used under `data/raw`.

## Consequences
Cross-scenario analysis must not merge s01 and s02 dry-run logs. Dry-run scenarios share cumulative logs, so event-time windows must come from the answer key, not from the file bounds.

## Kill criteria
If T4 finds the S01 and S02 windows cannot be separated at all, mark one of them unusable as a development trial.

## Committee answer
**EN:** Only real event logs enter `data/raw`; files that happen to be identical are kept per scenario and flagged, never silently merged.
**TH:** มีเฉพาะไฟล์บันทึกเหตุการณ์จริงที่เข้า `data/raw` ไฟล์ที่ซ้ำกันทุกไบต์เก็บแยกตามสถานการณ์และทำเครื่องหมายไว้ ไม่รวมโดยไม่แจ้ง
