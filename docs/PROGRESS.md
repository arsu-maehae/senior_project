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
