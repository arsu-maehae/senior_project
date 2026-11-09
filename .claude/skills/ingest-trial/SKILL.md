---
description: Bring a newly collected trial into the project - check files, copy into the standard layout, update the manifest, import into its SQLite database and run the data checks.
disable-model-invocation: true
---
# Ingest trial: $ARGUMENTS   (e.g. "s03 t04 D:\exports\s03_t04")

1. List the source folder. For each file decide: host, channel, keep / ignore (non-log files, duplicates).
   Show the mapping and anything unclear; wait for the user's OK if any file is ambiguous.
2. Copy (never move) into `data/raw/<scenario>/<trial>/<host>/<channel>.evtx`.
3. Append to `data/manifest.csv`: path, sha256, size, scenario, trial, host, channel, source path, date.
4. Check against the scenario's expected hosts/channels in `docs/data_inventory.md`; report missing ones.
5. Run the converter + normaliser for this trial → `data/processed/<scenario>_<trial>.sqlite3`.
   Check row counts against the converter's own counts.
6. Run the log-check procedure on the new database.
7. If Caldera operation logs exist for the trial, draft its answer key into `ground_truth/drafts/` and list what the user must confirm.
8. One line in docs/PROGRESS.md and a commit (code and docs only; data is git-ignored).
Report: files kept/ignored, gaps, log-check result, answer-key draft status.
