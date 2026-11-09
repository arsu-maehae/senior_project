# Progress log

One line per small task: `date · task id · what was done · commit · decision records`.
A summary block at the end of each big task. Newest at the bottom.

## Starting state (2026-11-09)
- Proposal defense passed (2 Nov 2026). Advisor: follow the plan; path severity only if time allows.
- Data: dry-run smoke test of all 7 scenarios (85 files). S02–S07 ×10 trials collected (location to be confirmed). S01 ×10 pending (manual).
- Code: `src/parsing_normalization/` converts EVTX → JSONL → SQLite (built for the dry-run set only). Review findings → docs/specs/01_normalise_fixes.md.
- Next: T0 setup, then T1.

## Log
2026-11-09 · T0 data rules · deny rules limited to data/incoming; CLAUDE.md Data rules rewritten; .pytest_cache ignored · 3cb5b70 · none
2026-11-09 · T0 0.1/0.3 hook + layout · data/sample and out created (git-ignored, not tracked); hook uses venv Python, resolves paths from script, treats pytest exit 5 as pass; 7 parser tests pass · see next commit · none
2026-11-09 · T0 0.2/0.4 kit and papers · 6 agents confirmed by user; HADES.pdf and TPPR.pdf present, valid PDFs, match README · (same commit) · none

### T0 summary (2026-11-09)
- **Built:** layout complete (data/sample, out/ exist locally, git-ignored); data rules split by folder (incoming protected, raw script-only); hook fixed.
- **Decisions:** none needing a record. Hook now uses the venv Python, resolves paths from its own location, and treats pytest exit 5 as success.
- **Tests:** `.venv\Scripts\python.exe -m pytest` → 7 passed (src/parsing_normalization/tests). tests/unit is still empty.
- **Open questions:** S02–S07 x10 trials are "not copied yet", so T1 starts with the dry runs in data/incoming/dryrun. The hook command in settings.json uses a relative `.venv/` path, so Claude Code must start from the repo root.
- **Check by hand:** `/agents` is gone in this Claude Code version; the 6 agents were confirmed by listing them.
2026-11-09 · T1 1.3 decisions · 001 S01 EP-02 export, 002 .evt is EVTX, 003 non-event and identical files · a41edad · 001–003
2026-11-09 · T1 1.1/1.2/1.4/1.6 data_layout · map/copy/manifest CLI; 22 tests; 80 files copied to data/raw (t00), 6 ignored, incoming hashes unchanged, manifest 80 rows · bdd4755 · none
2026-11-09 · T1 1.7 inventory · docs/data_inventory.md; fact-check found S01 dc01/ep-01 are S02 exports (end 05:50, EP-02 window 06:06–08:17) → real gap, T1 NOT done · f0c0eae + next commit · 001, 003 amended
2026-11-09 · T1 close · S01 t00 labelled "target side only", excluded from development set (user verdict, decision 001); S06 expectations "unconfirmed — settle in T5"; hook uses $CLAUDE_PROJECT_DIR (tested from /tmp in Git Bash, exit 0) · see commit · 001

### T1 summary (2026-11-09)
- **Built:** `src/data_layout/` (map, copy, manifest; reusable for `/ingest-trial`), 22 unit tests; 80 dry-run files in `data/raw/*/t00/`, 6 ignored; `data/manifest.csv` (80 rows); `docs/data_inventory.md`.
- **Decisions:** [001](decisions/001-s01-ep02-export.md), [002](decisions/002-evt-file-s06.md), [003](decisions/003-non-event-and-duplicate-files.md).
- **Tests:** 29 passed (7 parser + 22 data_layout). Incoming hashes unchanged before/after copy.
- **Open:** 1.5 waits for the real trials. Time overlap for S02–S07 is not checked yet (T4 `/log-check`). Manifest `date` is file mtime and unreliable.
- **Check by hand:** ten rows of `data/manifest.csv` (especially s01 and s06), and the "Time coverage" section of the inventory.

2026-11-10 · T3 spec + records · spec 01 revised (NF-11..NF-20, then NF-21..NF-26); decisions 004–010; attacker/fact-checker/data-checker reviews · 41520fb, 7dae15f · 004–010
2026-11-10 · T3 code · trial_normalize.py (57dec16), trial_import.py + import-trial CLI (f8340fe), NF-21..26 (0e8ccc8); 261 tests pass, 1 strict xfail; 7 t00 DBs imported, counts reconcile with manifests; S02/S04/S05 in data/sample · see commits · 004–010

### T3 summary (2026-11-10)
- **Built:** `trial_normalize.py` (per-event rules), `trial_import.py` + `import-trial` CLI (per-trial DB, views `events_dedup`/`events_display`, independent accounting), unchanged `normalize.py`/`full_import.py` and their 7 tests. JSONL for 7 t00 trials in `data/processed/jsonl/`, DBs in `data/processed/s0N_t00.sqlite3`, samples in `data/sample/`. Review: `docs/reviews/01_normalise_fixes-2026-11-10.md`.
- **Decisions:** [004](decisions/004-log-state-events.md) log-state events, [005](decisions/005-zero-logon-id-vs-port-zero.md) logon-ID 0 vs port 0, [006](decisions/006-trial-import-beside-full-import.md) new importer beside the old one, [007](decisions/007-raw-event-null.md) raw_event NULL, [008](decisions/008-account-name-and-domain.md) account_name/domain, [009](decisions/009-keep-4688.md) keep 4688, [010](decisions/010-event-utc-and-process-ids.md) event_utc and 4688 PIDs.
- **Tests:** 261 passed, 1 xfailed (dedup ignores the host folder when Computer and payload are identical, accepted). Row accounting per file equals each manifest.
- **Open:** (1) S02, S04, S07 have no SMB/RDP/WinRM Sysmon 3, so Correction I cannot link their hops from Sysmon 3: decide in T4 before T6/T7. (2) Sysmon clock outliers on ep-02/ep-03. (3) Trial windows must come from answer keys (T5/T6). (4) Importer cannot detect a missing expected file. Details in `docs/research/t3_data_findings.md`.
- **Check by hand:** 10 rows of 4624 and 4769 (shown in the report) and 10 rows of `events_display` for 4688/Sysmon 3 in `data/sample/s02_t00.sqlite3`.
