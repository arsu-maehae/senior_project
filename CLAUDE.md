# Identity-Aware Attack Path Reconstruction — project rules

Every Claude agent in this repo reads this file. Keep it short; details live in `docs/handoff_18.md` and `docs/specs/`.

## What we are building
A proof of concept that rebuilds lateral-movement attack paths across Windows machines from saved logs
(Sysmon, Security, System, WinRM, PowerShell; DC Kerberos events) and **ranks** candidate paths by a path score.
Lab: 5 VMs (DC01, Caldera, ep-01, ep-02, ep-03), 7 scenarios × 10 trials, answer keys in `ground_truth/`.

## Pipeline (one stage = one folder under src/)
EVTX → JSONL → normalise → SQLite (one DB per trial) → gate → stitch → Sigma label → score → rank → evaluate → (UI)

## Locked decisions — do not change without a council verdict in docs/decisions/
- **No threshold θ.** Output every candidate path ranked by score, highest first (Correction J).
- **Path score** = w1·LengthScore + w2·NodeScore + w3·IdentityCoherence. It is a score for ordering, **not a probability**.
- **LengthScore** = (1 − e^(−len/λ)) · mean edge order score (TPPR Eq. 5, 7). Order uses OUR tactic-order table (TPPR's pattern tree is unpublished).
- **NodeScore** = mean Sigma rule level of labelled nodes (informational 0 … critical 4, /4) — substitution for TPPR's GNN score (Correction G).
- **Merge** paths that share nodes; **never drop an isolated path** (Correction G.4).
- **Identity** (Correction K): a cross-host hop = 1 if the moving account had a logon session **open on the SOURCE host** when LSASS was read there (Sysmon 10, T1003.001), and the move happened after that. Path value = fraction of hops = 1. Exposed ≠ stolen.
- **Cross-host link** (Correction I): target 4624 (IpAddress, IpPort, account, time) ↔ source Sysmon 3 (SourceIp/Port, DestinationIp/Port) → ProcessGuid → Sysmon 1 → LogonId session. LogonGuid only **confirms** Kerberos hops (DC 4769 ↔ 4624). SMB connections show `Image = System`: anchor on the command process in the session.
- **Gate**: primary triggers R4 SMB, R5 RDP (also remote Type 3 + port 3389), R6 service, R8 WinRM; suppression first (Type 2/11, system logon IDs 0x3e4/0x3e5/0x3e7, loopback). R1/R2/R3/R7 are supporting signals only (handoff §7.2).
- **Logon IDs**: integer for joins, original hex for display (D1).
- **Wording**: never claim "reduces false positives", "detects stolen accounts" or "identifies the attacker". Say "ranks", "exposed", "expected, to be measured".

## Data rules
- `data/incoming/` = untouched original copies, never modify. `data/raw/` = written only by the copy/ingest scripts, never edited afterwards. `data/processed/`, `data/sample/` and `out/` = pipeline outputs. `data/manifest.csv` is maintained by the scripts.
- Never modify `ground_truth/approved/` or `docs/papers/`. Claude writes answer-key drafts only to `ground_truth/drafts/`; the user approves and moves them. Write outputs to `out/<stage>/<trial_id>/`.
- Work on `data/sample/` (S02, S04, S05 t00; S01 t01 later) first; run all 70 trials only after a stage passes review.
- Use the deduplicated view `events_dedup`, not `events`, for analysis.

## Code rules
- Python 3.11+, type hints, small pure functions, no hidden global state.
- Every stage reads a documented input and writes a documented output (see its spec).
- Every output row that links events records: `method`, `candidate_count`, `time_delta_ms`, `confidence_tier`, supporting `event_uid`s.

## Environment (Windows PC)
- Repo: `D:\senior_project` (no spaces in the path). Python venv in `.venv`; start `claude` from a terminal where the venv is active.
- Shell: Git Bash (Bash tool) or PowerShell. Use Python scripts rather than shell-specific one-liners.
- Existing parser/normaliser: `src/parsing_normalization/` (reviewed 2026-11-09; fixes in docs/specs/01_normalise_fixes.md). Extend it, do not rewrite it.
- Papers: `docs/papers/` (HADES, TPPR PDFs). Fact-check paper claims against these files, not memory.

## How work runs (autonomy)
- Work one BIG task from docs/PLAN.md at a time (`/next`). Plan it first; after the user says go, do all its small tasks without stopping.
- For every non-trivial choice, write a decision record (`/decision-record`) with the evidence: log counts, spec rule, paper section. No undocumented decisions.
- Stop early only if: data is missing or wrong, a locked decision looks wrong, an answer key needs human approval, or a test on answer-key events fails and the fix is unclear.
- After each small task: tests pass → `git commit` (never push) → one line in docs/PROGRESS.md.
- At the end of a big task: run `/stage-review` where a stage was built, then report: what was built, decisions made, test results, open questions.

## Who may edit what
- **implementer**: `src/` only. **tester**: `tests/` only. **researcher**: `docs/research/` only.
- **fact-checker, attacker, data-checker**: read-only; they report, they never fix.
- Only ONE agent edits `src/` at a time.

## Definition of done for a stage
1. Spec in `docs/specs/` is approved by the stage owner.
2. Tests pass on `data/sample/`, including the attacker's edge cases.
3. Fact-checker report has no blocking issue.
4. The stage owner can explain every function (`/explain-module`).
5. Decision record written for any design choice made.
