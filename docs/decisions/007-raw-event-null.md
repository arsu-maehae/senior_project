# 007 — raw_event stored as NULL in analysis DBs

**Date:** 2026-11-10 · **Status:** accepted · **Task:** T3

## Context
The old database was 17.4 GB for 85 files. `events.raw_event` is `NOT NULL CHECK(json_valid)` (`schema.py:30`). NF-09 keeps raw data in the JSONL and stores a pointer (`source_relative_path` + `source_line`).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. NULL + pointer | Small DB; JSONL stays the raw source | Constraint relaxed in the new schema; readers must split lines on `\n` only |
| B. Keep raw_event | Self-contained | Size; duplicate storage |

## Decision
Option A (owner, 2026-11-09). The new trial schema allows NULL `raw_event`; `raw_event_sha256` is the sha256 of the canonical JSON of the Phase 1 line, and `source_files` stores the JSONL path and sha256 (NF-16). The old schema is not changed.

## Consequences
A row's raw event is found by (JSONL file, line). The JSONL files must stay under `data/processed/jsonl/`.

## Kill criteria
If a later stage often needs raw fields that are not in typed columns, add the column instead of restoring raw_event.

## Committee answer
**EN:** The database holds typed columns and a pointer; the raw log stays in one place.
**TH:** ฐานข้อมูลเก็บคอลัมน์ที่แยกแล้วกับตัวชี้ ส่วนล็อกดิบเก็บไว้ที่เดียว
