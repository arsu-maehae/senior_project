# 030 — S05 ×10: quarantine, never scored

**Date:** 2026-11-10 · **Status:** accepted (owner, 2026-11-10) · **Task:** ×10 ingest and validation

## Context
The S05 ×10 trials arrived in `data/incoming/x10/S05_WRONG_DESIGN_DO_NOT_USE`. Another session reported that they were run with the wrong design. The owner wants them ingested only to check that claim.

## Decision
- Raw copies go to `data/raw/quarantine/s05/tNN/<host>/<channel>.evtx`; DBs to `data/processed/quarantine/s05q_tNN.sqlite3` (trial id `s05q_tNN`); manifest rows go to a separate `data/manifest_quarantine.csv`, so `data/manifest.csv` keeps its format and contains no quarantined trial.
- Quarantined trials are excluded from the development and test sets (decision 019) and are never scored, gated, linked or keyed. No answer key is built for them.
- They are validated with the decision 029 criteria in a separate quarantine section of `docs/research/x10_design_validation.md`, only to confirm or refute the wrong-design claim.
- S05 then needs a full rerun with the correct design (decision 029, rule 3) unless the validation refutes the claim; the owner decides.

## Consequences
Until a correct S05 ×10 exists, S05 has development data only from t00 (and t01 of the rerun, when collected).

## Kill criteria
If the validation shows the S05 trials match the design, the owner may lift the quarantine in a new decision record.

## Committee answer
**EN:** The S05 repeats were run with the wrong design, so we keep them apart, use them only to confirm that, and never score them.
**TH:** การรันซ้ำของ S05 ใช้การออกแบบผิด เราจึงแยกเก็บไว้ ใช้เพียงยืนยันข้อนั้น และไม่นำไปให้คะแนน
