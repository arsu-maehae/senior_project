# EVTX Parsing and Normalization

A component of a cross-host security event analysis project. It inventories Windows EVTX files, converts events to JSONL with provenance, and provides normalization and SQLite import code.

The implementation and full setup instructions are in [src/parsing_normalization](src/parsing_normalization/README.md). Source logs and generated output are not included in this repository.

## Setup

From the repository root, with Python 3.11+:

```
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[test]"
```

`pip install -e .` installs every package under `src/` (`gate`, `clock_offset`, `trial_window`, `stitch`, `answer_key`, `log_check`, `lab_common`, `data_layout`, `x10_validate`) and `evtx_pipeline` in editable mode, as defined in the root `pyproject.toml`. It replaces the separate install of `src/parsing_normalization`, so do not install that one as well. The pipeline commands then run from the repository root, for example `python -m gate --help`, `python -m clock_offset --help`, `python -m trial_window --help` and `python -m stitch.check_links --help`. Run the tests with `python -m pytest`.

## Running the pipeline for one trial

One command rebuilds a development trial from its database to its evaluation (spec 06, decisions 072, 074):

```
python -m run_trial --trial s04_t00        # gate -> stitch -> label -> score -> evaluate (link accuracy, label recall, rank)
python -m run_trial --development          # all 9 development trials in order, then the development summaries and results tables
python -m run_trial.dryrun                 # rebuild in a scratch copy outside the repo, compare with out/, delete the copy
```

Each stage keeps its own checks and refusals; the runner stops at the first step that refuses or fails, names it, and writes `out/run_trial/<trial>/run_log.json` (exit code and wall time per step; with `--development` also `out/run_trial/development/run_log.md`). It refuses any trial outside `DEVELOPMENT_TRIALS` (`src/clock_offset/params.py`) before anything is opened: gate itself has no allowlist and the test DBs are in `data/processed/`.

**Full order for a new trial.** A trial must first be admitted to `DEVELOPMENT_TRIALS` by an owner decision (decision 053); test trials (t02–t10) stay locked until the answer keys are tagged `answer-keys-locked` (PLAN T5.7).

1. Ingest: `python -m data_layout.batch --only <trial>` (writes `data/processed/<trial>.sqlite3`).
2. Clock offsets: `python -m clock_offset --trials <trial>` (writes `<trial>.clock_offsets.csv` and `<trial>.clock_changes.csv`).
3. Trial window: `python -m trial_window --trials <every trial already in data/trial_windows.csv> <trial>`. **It rewrites the whole file**, so list every existing trial too.
4. `python -m run_trial --trial <trial>`.

If step 1, 2 or 3 is missing, `run_trial` refuses before any stage and prints the exact commands for the missing pieces.

## Tests and real data

Many tests read real trial data that is not in git (`data/processed`, `data/sample`, `out/`, `ground_truth/approved`, `data/trial_windows.csv`, `data/processed/archive_x10_v1`). By default a missing input **skips** the test, so the suite runs on any machine. On the owner's machine a skip can hide lost coverage (58 tests skipped silently when the old S04/S07 trials were archived), so set `REQUIRE_REAL_DATA=1` and a missing real-data input **fails** the test instead:

```
set REQUIRE_REAL_DATA=1          (cmd)
$env:REQUIRE_REAL_DATA = "1"     (PowerShell)
export REQUIRE_REAL_DATA=1       (Git Bash)
python -m pytest
```

Accepted values: `1`, `true`, `yes`, `on` (any case). Unset, empty or anything else means the default (skip). The switch lives in `tests/unit/real_data.py` (`missing_input`); a real-data test calls it, not `pytest.skip`, for an input that should exist on the owner's machine. A skip that is a property of the data or the machine (no symlink right, no `192.168.50.97` session in any development trial) stays a skip and is still counted: read the skip count and the reasons in the report. Decision 053 item 3.

**Tests never write under `out/`** (decision 054). The root `conftest.py` snapshots all of `out/` when a session starts and ends, and fails the session if any file there was added, removed, changed or rewritten. A test that runs a CLI writes into a tmp folder: `python -m stitch --trial <id> --out DIR` (also `stitch.check_index` / `stitch.check_links --out DIR`, and `python -m evaluate --trial <id> --out DIR`). Inside the repository `--out` must lie below `out/`. After a real `python -m stitch` run, rerun `python -m evaluate --development`, because evaluate records the hashes of the stitch files it read and a test checks them.

The full-import workflow was built for a specific dataset and is not a general-purpose importer. See the component README for its constraints, data links, commands and tests.
