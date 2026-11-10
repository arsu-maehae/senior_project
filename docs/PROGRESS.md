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
2026-11-10 · T4 prep · Sysmon config check (09c2291); decision 011: SMB hops linked without Sysmon 3, no re-run; Correction I marked under review (council in T4); L10/F9 in docs/report/limitations_future_work.md; config XML committed as evidence · see commit · 011
2026-11-10 · T4 4.0 (in progress) · spec 00_log_check (attacker-reviewed, LC-04e/f/g added); src/log_check built and run on 7 t00 DBs (out/log_check/); decision 012 provisional windows; tester + data-checker cross-check NOT yet finished; data_reality.md and council not started · see commit · 012
2026-11-10 · T4 4.2 · docs/research/data_reality.md: per-hop evidence for S01–S07 t00 (SMB = command-line join tier B, WinRM = port join tier A, RDP not measurable until S01 t01; 4648 bridge needed in S06; Correction K gives 1 for both S04 tracks) · see commit · 012
2026-11-10 · T4 4.0 tests · tests/unit/test_log_check.py: 87 tests (LCT-01..14, LC-04e/f/g, real-data acceptance on data/sample); suite 348 passed, 1 xfailed; data-checker cross-check of 5 numbers × 6 trials: all match · see commit · 012
2026-11-10 · T4 council + records · decision 013 (Correction I amended; identity from moving account + source host), records 014–018, L11/L12; LC-04h 4648 coverage; stage review fixes (LC-14 wording, account_match per 013, LC-04d bridge, LC-08 end_unknown) · 8e19e30, b6c1bec, 336ffa7 + close commit · 013–018

### T4 summary (2026-11-10)
- **Built:** `src/log_check/` (spec `docs/specs/00_log_check.md`): read-only evidence measurement per trial DB → `out/log_check/<trial>/report.json|report.md|hop_candidates.csv`; provisional anchor-derived windows (decision 012). Reports for s01–s07 t00. `docs/research/data_reality.md` (per-hop evidence). Review: `docs/reviews/00_log_check-2026-11-10.md`.
- **Decisions:** [011](decisions/011-smb-linking-without-sysmon3.md) (partly superseded), [012](decisions/012-provisional-trial-windows.md) windows, [013](decisions/013-council-correction-i-amended.md) council: Correction I amended + identity input, [014](decisions/014-cross-host-time-tolerance.md) ≥ 5 s cross-host tolerance, [015](decisions/015-port-zero-kerberos-hops.md) port-0 Kerberos hops, [016](decisions/016-rdp-evidence-pending.md) RDP pending S01 t01, [017](decisions/017-s06-no-dump.md) S06 no dump, [018](decisions/018-s04-both-tracks-exposed.md) S04 both tracks score 1 (exposed ≠ stolen). CLAUDE.md "Cross-host link" amended, "Identity input" added. Limitations L10–L12, future work F9.
- **Measured:** every scenario-account attack hop in S02–S07 t00 has exactly one account-consistent source session; SMB hops by command line only (no naming 4648, no Sysmon 3), WinRM hops by port join (tier A) agreeing with the command line; S04 tracks 2 → 1 candidates with the account check; S06 needs the 4648 method; endpoint clocks −1.7 to +4.5 s vs DC01 (medians).
- **Tests:** 380 passed, 1 xfailed. Data-checker re-derived 5 numbers × 6 trials independently: all match. DB hashes unchanged.
- **Open:** RDP source side until S01 t01; "right session" unverifiable until T5 keys (S04 Track A → desktop 0xd6398 vs agent 0x17b18); S07 svc_sql path not visible (T5.4); S06 agent account differs from the handoff (T5.4); T7 requirements listed in the review (hop grouping, S07 session reuse, IpPort not unique, IpAddress `-` hops).
- **Check by hand:** 10 rows of `out/log_check/s04_t00/hop_candidates.csv` (shown in the T4 report) and the per-hop table in `docs/research/data_reality.md`.
2026-11-10 · T5 0 · dev/test split fixed in PLAN.md and CLAUDE.md · see commit · 019
2026-11-10 · T5 1-2 · docs/research/agent_evidence.md: splunkd.exe is the Caldera agent (Sysmon 3 to 192.168.50.50:8888; attack commands are its grandchildren); s02 has a stray ep-02 SYSTEM run (self-target, not a hop); decision 020 key provenance; draft spec 07 · see commit · 020
- TODO (cross-check, not a source of truth): when the Caldera files are copied (S05 definitions in s05-backup-20261031_052818, other ability/adversary YAMLs in data/, the 140 result files in data/results), compare them with the log-based keys and record mismatches in decision 020.
2026-11-10 · T5 5.1 · spec 07 attacker + fact-check fixes (tolerance direction, moving account = 4624 account, source host by IP, window, schema, flags/roles); PLAN 5.2 wording; 019/agent_evidence corrections · see commit · 019, 020
2026-11-10 · T5 5.2-5.5 · src/answer_key builds drafts from the splunkd agent tree + handoff steps + target-side artefacts (basis command_names_target / time_account_only); verify.py existence check; 135 tests pass (suite 373 + 135, 1 xfailed); drafts s02-s07 t00 in ground_truth/drafts (NOT approved); records 021-025 · see commit · 019-025
2026-11-10 · T5 review fixes · source host from 4624 IP, logoff-after-logon, AK-16/17/18, leftover search bounded to the trial run interval (026), tests 135 → 159 (tightened, 021–025 pinned); fact-checker + attacker findings merged in docs/reviews/07_answer_key-2026-11-10.md; drafts rebuilt, verify ok on s02–s07 t00 · see commit · 026

### T5 summary (2026-11-10, development set t00; STOPPED for owner approval)
- **Built:** spec `docs/specs/07_answer_key.md` (AK-01..AK-18); `src/answer_key/` (agent-tree builder, target-side collection by artefact, Correction K identity computed per hop, `verify` existence check); drafts `ground_truth/drafts/s0{2..7}_t00.yaml` (JSON content, NOT approved); existence reports `out/answer_key/s0N_t00/verify.md` (ok, 0 failures). Evidence: `docs/research/agent_evidence.md`. Review: `docs/reviews/07_answer_key-2026-11-10.md`.
- **Decisions:** [019](decisions/019-dev-test-split.md) split, [020](decisions/020-answer-key-provenance.md) provenance, [021](decisions/021-s04-track-a-source-session.md) S04-A session, [022](decisions/022-s05-hop2-pivot-dump.md) S05 hop 2, [023](decisions/023-s07-accounts-follow-data.md) S07 accounts, [024](decisions/024-s06-benign-paths.md) S06, [025](decisions/025-handoff-mismatches-s02-s03.md) S02 stray / S03 source, [026](decisions/026-key-run-interval-and-leftovers.md) run interval.
- **Tests:** 159 answer-key tests + 373 others pass, 1 xfailed; DB hashes unchanged.
- **Not done:** 5.3–5.5 are NOT ticked (waiting for approval); 5.6 (test keys) and 5.7 (lock) wait for the ×10 trials; t01 keys wait for t01 ingest.
- **Check by hand:** 10 hops across `ground_truth/drafts/*.yaml` (hop id, basis, status, identity, target uids), especially s04-A-h1, s06-smb-1, s07-h-y, s03-h1.
- TODO (decision 023): when S07 t01–t10 are ingested, check for any svc_sql 4624 on ep-02; if none, state the S07 one-account deviation as a limitation in the report.
- TODO (decision 026): recheck run intervals with `python -m answer_key check-overlap` on the ×10 trials; prefer manifest spans when they become tighter.
- TODO (lock gate, AK-21): before the lock tag every hop is confirmed or explicitly excluded by the owner; no unconfirmed hop remains in an approved key.
2026-11-10 · T5 owner answers · role field (attack|benign|background); basis manual_command_names_target (s04-A-h1 confirmed, session 0xd6398); manifest span clip + check-overlap (no overlaps; s05-t1 shared with s06/s07); verify lock_ready (s02, s03 true; s04-s07 blocked by one background hop each); decisions 021/023/026 amended; PLAN 10.6 independent ablation; 219 tests pass · see commit · 021, 023, 026
- TODO (decision 027): when S07 t01–t10 are ingested, if no trial shows svc_sql on the target (4624 on ep-02 for the Y command), add a limitation to docs/report/limitations_future_work.md that S07's two-account design did not happen as intended.
- TODO (T6.4 / T7.7): clip each trial DB to its key window before gating and linking; write the test that an event outside the window never reaches the gate or the stitcher.
2026-11-10 · T5 owner review round 2 · lock rule changed (decision 028): background hops need reviewed:true, owner-only excluded/excluded_reason via src/answer_key/owner_reviews.json; lock_ready true on s02-s07 t00; decision 027 (key account = target-side account); decision 014 clock-offset evidence added; PLAN 6.4 trial-window clip + 7.7 test; password check: 4 tracked files contain the lab password (docs/handoff_18.md, src/log_check/matching.py, tests/unit/test_answer_key.py, tests/unit/test_log_check.py), none outside them in history; 233 answer-key tests pass · see commit · 014, 027, 028
2026-11-10 · T5 password scrub · lab password removed from the 4 tracked files (handoff -> ***, matching.py comment, tests use a fake value; real-data checks are structural and use env LAB_PASSWORD only if set); it remains in git history, including pushed commits d3891e6, 88efc2e, eb182d4 on origin/build (owner decides on rotation / history rewrite) · see commit
