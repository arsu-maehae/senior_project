# 019 — Development / test split: t00 (S02–S07) + t01 (all 7) vs t02–t10

**Date:** 2026-11-10 · **Status:** accepted (owner, T5 start) · **Task:** T5

## Context
The old split was development = t00 for S02–S07 + t01 for S01, test = trials 2–10. That leaves trial 1 of S02–S07 in neither set and gives S01 one development trial from a different trial number than the other scenarios. S01 t00 is excluded (target side only; its source EP-01 and DC01 files are S02 exports filed under S01 — decision 001).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Keep the old split | No edits | t01 of S02–S07 unused; the two sets are not symmetric across scenarios |
| B. Development = t00 (S02–S07) + t01 (all 7 scenarios); test = t02–t10 | Every scenario has two development trials; test set is the same trials for every scenario | Only t00 is ingested today, so t01 development keys wait for ingest |

## Decision
Option B (owner, 2026-11-10). Development = t00 for S02–S07 plus t01 for all seven scenarios. Test = t02–t10 for all seven scenarios. S01 t00 stays excluded. Weights, λ and code are tuned on development trials only; test keys are locked (`answer-keys-locked`) before T10.

## Consequences
Development keys for this run cover S02–S07 t00 only. t01 keys are built when those trials are ingested. PLAN.md header and the CLAUDE.md split and `data/sample` lines are updated to match. Trial count: test = t02–t10 is 9 trials per scenario, 63 in total; t00 is the dry run, so the CLAUDE.md phrase "all 70 trials" (7 × 10) is a different count; the owner reconciles the numbering when the ×10 trials are ingested.

## Kill criteria
If t01 of a scenario turns out unusable (under-fired, missing hosts), record it as excluded here and keep t00 as that scenario's only development trial.

## Committee answer
**EN:** We tune only on trial 0 (dry run) and trial 1 of each scenario (S01: trial 1 only) and score once on trials 2 to 10, so the test result is not tuned.
**TH:** เราปรับค่าเฉพาะบนรอบที่ 0 (dry run) และ 1 ของแต่ละสถานการณ์ (S01 ใช้เฉพาะรอบที่ 1) และวัดผลครั้งเดียวบนรอบที่ 2 ถึง 10 ผลทดสอบจึงไม่ถูกปรับแต่ง
