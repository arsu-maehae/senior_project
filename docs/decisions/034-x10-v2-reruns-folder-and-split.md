# 034 — Full reruns go to `x10_v2`; partial replacements stay `trial_11+`; dev/test split for the reruns

**Date:** 2026-11-11 · **Status:** accepted (owner, 2026-11-11) · **Task:** ×10 ingest and validation · **Relates to:** 019 (split), 029 (replacement rule), 030 (S05 quarantine), 033 (S07)

## Context
Validation (`docs/research/x10_design_validation.md`, decisions 029–033) leaves two kinds of redo:
- **Partial replacements:** S03 (one trial, replacing `s03_t08`) and S06 (two trials, replacing `s06_t09` and `s06_t10`).
- **Full reruns of ten trials:** S04, S07, S05 (rebuilt to the t00 design) and S01 (built for the first time).
Decision 029 numbers replacements from `trial_11`. That is fine for a few replacements, but a full rerun would make `trial_11`–`trial_20` and leave old broken `t01`–`t10` next to them. The old S04 and S07 `t01` are also invalid, so the development trial of those scenarios must be replaced too.

## Decision
1. **Partial replacements** (S03, S06) are numbered `trial_11`, `trial_12` and stay in the scenario folders of `data/incoming/x10/`, ids `s03_t11`, `s06_t11`, `s06_t12`.
2. **Full reruns** (S04, S07, S05, S01) arrive in a new folder `data/incoming/x10_v2/` as fresh `trial_01`–`trial_10` (ids `s04_t01` … `s04_t10`, same mapping as 029). `data/incoming/x10/` is not touched.
3. **The old broken trials are archived, never deleted.** Before the `x10_v2` ingest, the old S04 and S07 trials (and the old S05 trials already in quarantine, decision 030) stay out of the development and test sets, are marked in the validation report, and are kept in `data/incoming/x10/` as they are. Because the new trials reuse the ids `tNN`, the old S04 and S07 copies in `data/raw/`, `data/processed/` and `data/manifest.csv` are moved by a script, with hash checks, to an archive path (`data/raw/archive_x10_v1/`, `data/processed/archive_x10_v1/`, `data/manifest_archive_x10_v1.csv`) before the new trials are ingested, so that the current trials sit on the normal paths. Nothing is moved by this record. The old S05 copies are already under `quarantine/` and do not collide.
4. **Development and test split (decision 019 restated for the reruns).** For S04, S07, S05 and S01 the new `t01` is **development** and the new `t02`–`t10` are **test**. The old `t01` of S04 and S07 is no longer development (invalid). The replacement trials `s03_t11`, `s06_t11` and `s06_t12` are **test**, because the trials they replace (`t08`, `t09`, `t10`) were test; each scenario keeps 9 test trials. Development stays: `t00` for S02–S07 plus `t01` for all seven scenarios (S02, S03 and S06 keep their current `t01`; S01 `t00` stays excluded). Never tune on test.

| Scenario | Development | Test |
|---|---|---|
| S01 | v2 `t01` | v2 `t02`–`t10` |
| S02 | `t00`, `t01` | `t02`–`t10` |
| S03 | `t00`, `t01` | `t02`–`t07`, `t09`, `t10`, `t11` |
| S04 | `t00`, v2 `t01` | v2 `t02`–`t10` |
| S05 | `t00`, v2 `t01` | v2 `t02`–`t10` |
| S06 | `t00`, `t01` | `t02`–`t08`, `t11`, `t12` |
| S07 | `t00`, v2 `t01` | v2 `t02`–`t10` |

## Consequences
- The batch ingest and the validator read `data/incoming/x10`; they need an `x10_v2` source, a separate output folder (`out/ingest/x10_v2/`, `out/x10_validate_v2/`) and an archive step. This is implementation work for the implementer and is listed in `docs/lab/rerun_plan.md`. The validator needs an S01 design table (a decision record first).
- Replacement trials and v2 trials are validated with the same criteria (029, 031).
- The rule "run 1 trial, ingest, validate, proceed only if it passes" applies to every v2 scenario; the first accepted trial is `t01`.
- If a v2 trial fails, it is replaced by a new trial in `x10_v2` numbered `trial_11` onwards, as in 029.

## Kill criteria
If the archive move cannot be verified by hash, it is not done and the v2 trials get a separate path (as in decision 030) instead.

## Committee answer
**EN:** The full reruns go into their own folder as fresh trials 1–10, the old broken trials are kept but not used, and the first new trial of each scenario is development while trials 2–10 are test.
**TH:** การรันซ้ำทั้งชุดแยกเก็บในโฟลเดอร์ใหม่เป็นรอบที่ 1–10 รอบเดิมที่เสียยังเก็บไว้แต่ไม่ใช้ รอบที่ 1 ของแต่ละสถานการณ์เป็นชุดพัฒนา และรอบที่ 2–10 เป็นชุดทดสอบ
