# 054 — Tests write nothing under `out/`; `--out` for the stitch CLIs

**Date:** 2026-11-17 · **Status:** accepted (owner, T7.7 plan with the owner changes, 2026-11-17) · **Task:** T7.7 · **Relates to:** 046, 049, 051, 053

## Context
- The real-data stitch tests ran `python -m stitch --trial <t> --repo REPO`, which rebuilds `out/stitch/<t>/` on every full suite. `run_info.json` gets a new timestamp, so the SHA-256 that `out/evaluate/<t>/run_info.json` records for it (`inputs.stitch_run_info_sha256`, 051) went stale after **every** full run (noted in the 053 PROGRESS entry).
- I measured it on HEAD `9152db1`: a snapshot of all of `out/` (636 files) before and after one full suite with `REQUIRE_REAL_DATA=1` (4469 passed, 1 skipped, 1 xfailed). The suite wrote 9 × 10 files in `out/stitch/` (9 `run_info.json` changed, 81 rewritten with the same bytes), 9 × `out/stitch_check/<t>/t73_links.json` (same bytes), `out/gate_tests/gta_report.md` (same bytes, `test_gate_real::test_gta_report`) and `out/trial_window/gta06.md` (same bytes, the `gta06` fixture of `test_trial_window`). Nothing else.
- None of the three stitch CLIs had a way to write anywhere but `out/`. `python -m evaluate` already had `--out`.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. `--out DIR` on `python -m stitch`, `stitch.check_index`, `stitch.check_links`; tests pass a tmp folder (**chosen, owner**) | the tests still run the real CLI path; mirrors evaluate's `--out`; usable by hand (e.g. a sensitivity run) | a small `src/` change during the review step | evaluate `--out` since T7.6 |
| B. Tests patch `out_dir` / `CHECK_OUT_REL` | no `src/` change | patching module internals; the CLI path is no longer what runs | first plan draft, rejected by the owner |
| C. Guard only the stitch and evaluate folders | smaller | other stages' tests write too (2 report files) | measurement above |
| D. Guard all of `out/`, compare content hash **and** modification time (**chosen, owner**) | catches every write, also a same-bytes rewrite; covers all stages | a test that must write a report writes to tmp and prints it | 636 files / 11 MB: a snapshot takes well under a second |

## Decision
1. **`--out`.**
   - `python -m stitch --out DIR` writes the ten spec §3 files into DIR. The default stays `out/stitch/<trial>` and keeps its spec 3 rebuild exactly as before (a stale file there is still removed).
   - An explicit DIR is checked after ST-00 and before anything is written (`src/stitch/outdir.py`). Inside the repository it must lie strictly below `out/`; outside the repository it is free.
   - Because the folder is swapped in and the old one deleted, an existing DIR may hold only the ten spec file names. Anything else is refused, and the refusal names at most three entries.
   - `check_index` / `check_links --out DIR` put their one check file into DIR, under the same repository rule. They delete nothing, so a shared folder is fine.
   - ST-00 still comes first: a test trial is refused before DIR is looked at (046).
   - The bytes of every output except `run_info.json` do not depend on DIR: `run_info` records the DB path relative to the repository, not the output path.
2. **Guard.** The root `conftest.py` has a session-scoped autouse fixture (logic in `tests/unit/out_guard.py`). It snapshots all of `out/` (folders, and files by SHA-256 plus `mtime_ns`) at session start and end, and fails the session (exit ≠ 0) on any added, removed, changed or rewritten path. It lives in the root conftest so the normaliser tests under `src/` are covered too.
3. **Tests moved to tmp:**
   - `test_stitch_outputs_real` and `test_stitch_paths_real` (`--out` into a per-module `tempfile.mkdtemp`, removed at exit);
   - `test_stitch_links_real` c1 (`--out tmp_path`);
   - `test_gate_real::test_gta_report` (report into `tmp_path`, printed);
   - the `gta06` fixture of `test_trial_window` (report into its tmp folder).
   - The committed `out/gate_tests/gta_report.md` and `out/trial_window/gta06.md` are frozen copies of 2026-11-17. No CLI rewrites them.
4. **Committed `out/` must stay current, checked read-only:**
   - `test_the_committed_out_stitch_folder_equals_a_fresh_run`: every file but `run_info.json` byte-identical; `run_info.json` equal apart from `generated_utc`.
   - `test_committed_out_evaluate_folder_equals_a_fresh_evaluation`.
   - `test_committed_evaluate_run_info_records_the_current_stitch_files`.
   - With the guard, these hold across suite runs. After any real `python -m stitch` run, `python -m evaluate --development` must be rerun, or the last test fails and says so.

## Consequences
- A full suite no longer changes the repository's pipeline outputs. Evaluate's recorded stitch hashes stay valid.
- A new test that needs to write a file must use a tmp folder. The guard names the offending path.
- Two report files are no longer refreshed by the suite. The live reports print with `pytest -s`.

## Kill criteria
- A required output can only be produced under `out/` by a test → make it a CLI step instead (never relax the guard).
- The snapshot of `out/` becomes slow (> 5 s per session) → hash only files whose size or `mtime_ns` changed.

## Committee answer
**EN:** Test runs used to rewrite the pipeline outputs, so the hashes that later stages record went stale silently. Now every test writes to a temporary folder, and one guard fails the whole run if anything under `out/` changes. The committed outputs are checked against a fresh run instead.
**TH:** เดิมการรันชุดทดสอบเขียนทับไฟล์ผลลัพธ์ของ pipeline ทำให้ค่า hash ที่ขั้นถัดไปบันทึกไว้ไม่ตรงโดยไม่มีใครรู้ ตอนนี้ทุกเทสต์เขียนลงโฟลเดอร์ชั่วคราว และมีตัวเฝ้าระวังที่ทำให้การรันทั้งชุดล้มเหลวทันทีถ้าไฟล์ใดใน `out/` เปลี่ยน ส่วนผลลัพธ์ที่ commit ไว้จะถูกตรวจเทียบกับการรันใหม่แทน
