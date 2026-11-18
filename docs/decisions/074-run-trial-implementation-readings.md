# 074 — Runner and dry run: implementation readings (normalised provenance hashes, exit codes, log fields)

**Date:** 2026-11-18 · **Status:** accepted (stage lead, within approved spec 06 and record 072; for owner review at
the stage review) · **Task:** T10.C, T10.D · **Relates to:** spec [06_evaluate](../specs/06_evaluate.md) RT-01..11,
DR-01..07; [072](072-evaluate-t10-readings-and-runner.md)

## Context
The first dry run (`python -m run_trial.dryrun`, 2026-11-18) rebuilt all 9 development trials in a scratch repo and
then ran the 4 summary steps. Both negative cases held, the real tree check passed (845 files unchanged) and the
scratch repo was deleted. The run still **failed** on one point. `label_recall.csv` (6 keyed trials) holds a column
`label_run_sha256`, the SHA-256 of label's `run_info.json`. That file carries `generated_utc`, so this CSV can never
be byte-identical after a rerun.

The list of keys in DR-03 was also incomplete. Gate writes a `run_info.json` with `run_utc`. Five more cross-stage
hashes point at a timestamped `run_info.json`:
- label `stitch_files_sha256.run_info.json`
- score `inputs.label` / `inputs.stitch` `run_info.json`
- evaluate `inputs.stitch_files.run_info.json`
- the `label_recall.md` column `label_run_info_sha256`

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Normalise a named list of provenance hashes, each accepted only with a chained proof (**chosen**) | stage outputs stay as they are; every substitution is named, counted and proven | the comparison is more complex |
| Drop or alter `label_run_sha256` in evaluate | CSV stays strictly byte-identical | removes provenance that the label-recall tests use; changes a reviewed stage |
| Normalise any ISO time or hash pattern | simple | could mask a real difference (ATK-EV-10) |

## Decision
1. **DR-03 amended.** One explicit constant lists every normalised (file, key or column):
   - `generated_utc`, gate `run_utc`
   - the five run_info hashes above, evaluate `inputs.stitch_run_info_sha256`, and rank.md `score_run_info_sha256`
   - `label_recall.csv` column `label_run_sha256`. Only that column is normalised; every other column, the row count
     and the row order must be byte-identical.

   A normalised hash is accepted only when **(1)** the scratch value equals the SHA-256 of the scratch `run_info.json`
   it names, **(2)** the committed value equals the SHA-256 of the committed `run_info.json` it names, and **(3)** that
   pair of `run_info.json` files is itself equal after normalising. Otherwise the file is reported as `differs`.
   Substitutions are counted per file and key. rank.md writes only the first 16 hex digits of `score_run_info_sha256`, so there the proof compares the 16-digit prefix; every other hash is compared in full. **Result** (second dry run, 2026-11-18): 363 files, 309 identical, 54 equal after normalising, 0 differ / missing / new; exit 0.
2. **Exit codes.** Runner exit 2 always means a refusal (RT-01, RT-02 or a stage's own refusal). A usage error or a
   failed post-check gives exit 1. Any other non-zero stage exit is passed through.
3. **Post-check.** "Rewritten during the step" allows 2 s of slack for file-time precision.
4. **Log fields beyond §3.2.**
   - Per step: `result` (ok / refused / failed / not run), `post_check`, `note`.
   - Per trial: `failed_step`.
   - Development log: `not_run_trials`, `status`.
   - The interpreter is written as `python` and the repo as `<repo>`.
5. **Logs on refusal.** An RT-02 refusal writes a log with the pseudo-step `presence`, and every real step is marked
   `not run`. An RT-01 refusal writes nothing (RT-08).
6. **Copied inputs.** `data/manifest.csv` is not copied, because no stage in the chain reads it.
   `data/trial_windows.csv` is copied whole; it holds only the 9 development rows (data-checker 2026-11-18).
7. **Location.** The dry run is `python -m run_trial.dryrun` (`src/run_trial/dryrun.py`), not `tools/`. The
   implementer edits `src/` only, and one package holds the runner and its check.

## Consequences
The dry run checks that the chain reproduces the committed `out/`, apart from provenance hashes of files that differ
only in their timestamps. Each such hash is proven to point at an equal file. Wall times are measured per stage
(handoff §14.2). They are machine-dependent and kept out of `results.md`.

## Kill criteria
If any further non-deterministic field appears, it is added to the list only with a chained proof, or the stage is
made deterministic. The comparison is never widened to a pattern.

## Committee answer
**EN:** Our one-command rebuild reproduces every output of the nine development trials. The only bytes that change
are timestamps and the fingerprints of files that differ only in a timestamp, and we prove each such fingerprint
points at an otherwise identical file.
**TH:** คำสั่งเดียวที่สร้างผลใหม่ได้ผลลัพธ์ตรงกับของเดิมทุกไฟล์ของการทดลองชุดพัฒนาเก้าชุด ส่วนที่ต่างมีเพียงเวลาที่บันทึกและลายนิ้วมือของไฟล์ที่ต่างกันแค่เวลา
และเราพิสูจน์ว่าลายนิ้วมือแต่ละค่าชี้ไปยังไฟล์ที่เหมือนกันทุกอย่างนอกจากเวลา
