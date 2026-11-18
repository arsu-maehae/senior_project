# Stage spec: 06_evaluate (T10, development-only part)

**Owner:** <stage owner> · **Status:** **approved (owner, 2026-11-18)**: Q1–Q5 as proposed (record [072](../decisions/072-evaluate-t10-readings-and-runner.md)); Q6 option (a), denominator = labelled key nodes (freeze record [071](../decisions/071-h4-labelled-recall-denominator.md)); data-checker and attacker review
merged in §6 and §8 ([review](../reviews/06_evaluate-spec-2026-11-18.md)) · **Last updated:** 2026-11-18

**Scope of this draft.** Only the T10 parts that need no test data (owner, 2026-11-18): (A) PLAN 10.7, the
[070](../decisions/070-score-freeze-amendment-readings.md) readings in `evaluate --rank`; (B) a one-command runner per
trial; (C) the T10 results-table generator, run on development data and labelled DEVELOPMENT. The test run (10.4),
weight sensitivity on test data (10.5), the ablation (10.6) and anything that opens t02–t10, lifts the development
allowlist or needs the tag `answer-keys-locked` (T5.7) are **out of scope** (§9) and get their own spec section later.

Decisions this spec rests on: Correction J (rank, no θ; threshold-free metrics), Correction K, handoff §14.2–§14.3
(metrics, baseline ladder), [019](../decisions/019-dev-test-split.md) (split, never tune on test),
[046](../decisions/046-stitch-development-allowlist.md) / [053] (allowlist; new t01 trials only by owner decision),
[054](../decisions/054-t77-out-guard-and-out-option.md) (`--out`, tests write nothing under out/),
[065](../decisions/065-score-baselines-and-success-criteria.md) (variants, tie rule, H1–H5 numbers),
[066](../decisions/066-score-parameter-freeze.md) (freeze at `6338884`), [068](../decisions/068-rank-check-readings.md),
[069](../decisions/069-score-stage-review-fixes.md) item 9, **[070](../decisions/070-score-freeze-amendment-readings.md)**
(primary readings, contested reading, chance line in every table), spec [05_score](05_score.md) §3.6, §7.3.

## 1. Purpose
(A) Make the development ranking check report exactly the readings frozen for T10 (070), so that the test run later
changes only the trial list, not the code path. (B) Rebuild one trial from its database to its evaluation with one
command, each stage keeping its own refusals, and record the processing time per stage (handoff §14.2). (C) Turn the
ranking check into the T10 results tables (H1–H5 held / not held, baselines, chance line, contested reading), shown
now on development data only, every table labelled **DEVELOPMENT — not a result**.

## 2. Input contract
| Input | Used by | Meaning |
|---|---|---|
| `data/processed/<t>.sqlite3`, `<t>.clock_offsets.csv`, `<t>.clock_changes.csv`, `data/trial_windows.csv` row | B | what gate needs; created by ingest, `clock_offset`, `trial_window` (not run by the runner) |
| `out/gate|stitch|label|score/<t>/` | B (chained), A | stage outputs, each with its own freshness checks (unchanged) |
| `out/score/<t>/ranked_paths.csv`, `b0_ranked.csv`, `run_info.json`; `out/stitch/<t>/path_nodes.csv`; `ground_truth/approved/<t>.yaml` (keyed development trials only) | A, C | as read today by `rank_run.rank_trial` with all its checks (068, 069: score freshness, frozen parameters, key presence, key ↔ stitch DB hash) |
| `out/evaluate/development/rank_totals.csv`, `out/evaluate/<t>/rank.csv` | C | written by A; checked for staleness (RS-02) |
| `out/run_trial/development/run_log.json` (optional) | C | processing time; only referenced, never copied into results files (RS-07) |

The allowlist is `clock_offset.params.DEVELOPMENT_TRIALS` = s02–s07 t00, s02_t01, s03_t01, s06_t01; keyed =
`KEYED_DEVELOPMENT_TRIALS` = the six t00 trials. Nothing in this spec changes either list.

## 3. Output contract
### 3.1 A — `evaluate --rank` (changed columns/rows only; every other column of rank.csv / rank_totals.csv unchanged)
- `rank.csv`: new column `contested` (`1`/`0`, on `trial` and `b0_recall` rows of keyed attack trials; empty
  elsewhere) and `n_positive_units` for b0 (labelled units with score > 0).
- `rank_totals.csv`: new column `reading_scope` = `all` | `contested`. Rows `ranking` and `b0_recall` keep
  `reading_scope = all`; new rows with `reading_scope = contested` and `attack_trials` = the number of contested
  trials (EV-03). New column `primary_metric` naming the 070 primary column of the row (`mrr_per_key_expected` for
  `ranking` rows; `full_recall_labelled_mean` / `b0_recall_labelled_mean` for `b0_recall` rows).
- Further appended columns (073): rank.csv `key_nodes_labelled`; rank_totals.csv `contested_set`, `scope_trial_ids`, `chance_per_key_mrr`, `chance_pos_per_key_mrr`, `labelled_recall_trials`; `primary_metric` of the b0 row names both sides (`full_recall_labelled_mean;b0_recall_labelled_mean`).
- `rank.md`: section "Primary readings (decision 070)" first: per variant top-1 (expected), **per-key MRR**, chance
  line over all candidates **and** over score > 0 in the same table; "Reported beside" holds per-trial MRR, E[1/rank],
  optimistic/pessimistic, all-node recall. H4 table columns reordered: labelled basis first (primary), all-node basis
  beside. Every table (S06, H4, contested, per-trial) carries the two chance-line columns where a ranking metric is
  shown (EV-05). Label `RECALL_BASIS_ALL` becomes "all context-0 nodes (reported beside, 070)".

### 3.2 B — runner `python -m run_trial --trial <t> | --development [--repo R]`
New package `src/run_trial` (added to `pyproject.toml` packages). Writes `<R>/out/run_trial/<t>/run_log.json`
(per trial) and, with `--development`, `<R>/out/run_trial/development/run_log.json` + `run_log.md`.

`run_log.json` (per trial): `trial_id`, `repo` (relative spelling `.` or the given path), `tool_version`,
`generated_utc`, `steps`: list of `{step, argv, exit_code, wall_ms, stderr_tail}` in run order, `status` =
`ok` | `refused` | `failed`, `refused_step`. Development log: `trials` (list of per-trial objects as above, in
`DEVELOPMENT_TRIALS` order), `stopped_at` (`trial`, `step`) or empty, `summary_steps` (RT-06).

### 3.3 C — `python -m evaluate --results --development`
Writes `out/evaluate/development/results.md` and `results.csv` (added to every development keep list, so link
accuracy / label recall / rank runs keep them, and vice versa).

`results.csv` — one row per (table, variant, reading_scope, metric, source) (EV-04 paired and own-set rows share the first four; record [073](../decisions/073-evaluate-t10-implementation-readings.md)), plus a `note` column (H5 reason, contested-set name, "reported beside" labels): `status_note` (`DEVELOPMENT — not a result`),
`split`, `table` (`H1`…`H5`, `baselines`, `contested`, `recall`), `hypothesis`, `variant`, `reading_scope`
(`all`|`contested`), `metric`, `is_primary` (1/0), `observed`, `threshold` (frozen, empty where none), `comparator`
(`>=`, `>`, `<`), `verdict` (`held` / `not held` / empty for rows reported beside), `chance_all`, `chance_pos`,
`n_trials`, `n_key_paths`, `source` (rank_totals.csv row key). Values with 6 decimals as in rank_totals.csv.

`results.md` — header line `# DEVELOPMENT — not a result (decision 019)`; one table per hypothesis, each table headed
again **DEVELOPMENT — not a result**, each showing observed, frozen threshold, verdict, chance line over all and over
score > 0; then baselines (full, b1, b2, b0 side by side), contested reading, recall (labelled primary, all-node
beside), per-key and per-trial MRR; a pointer to `out/run_trial/development/run_log.md` for processing time; the
wording block of RS-08.

## 4. Rules
### A — 070 readings in `evaluate --rank` (PLAN 10.7)
| ID | Rule | Source |
|---|---|---|
| EV-01 | Primary MRR for H2 and H3 = **per-key MRR** (`mrr_per_key_expected`): each key attack path's own expected RR (065 tie rule), averaged over key attack paths. Per-trial MRR (first match, handoff §14.2) is reported beside. | 070 item 2 |
| EV-02 | Primary H4 recall = **labelled** `context` = 0 key nodes at an equal labelled-node budget (`*_labelled`); all-node recall reported beside. The H4 comparison uses the mean over attack trials; `trials_full_above_b0_labelled` reported beside. **Denominator (Q6 → 071):** the labelled key nodes = `context` = 0 key nodes (ST-05 copies merged) inside at least one `b0_ranked.csv` unit; a trial with none is undefined, reported and left out of the mean (the code divided by all key nodes, ATK-EV-01). | 070 item 1 |
| EV-03 | **Contested trial** for variant v ∈ {full, b1, b2}: a keyed attack trial whose v-candidate set has > 1 candidate with written score > 0 (12 decimals; `rank_metrics.positive_ids`). For b0: > 1 distinct labelled unit with score > 0 in `b0_ranked.csv`, ST-05 copies merged first (ATK-EV-14). Every metric of that variant is recomputed over contested trials only and written beside the primary reading, never in its place. Zero contested trials → row written with `attack_trials = 0` and empty metrics. Trials left out are listed with the reason; a trial whose only positive candidate is a rival (key path at 0) is named "uncontested — key path not scored" so the failure stays visible (ATK-EV-05). | 070 item 4 |
| EV-04 | b0 has no paths, so its contested reading covers the H4 recall only (labelled primary, all-node beside). **Paired comparisons** (H3 full vs b1, H4 full vs b0) under the contested reading use **full's** contested set for both sides; each variant's own contested set is reported beside (ATK-EV-06). Contested rows never carry a verdict. | OPEN Q1; ATK-EV-06 |
| EV-05 | Every rank.md table that shows a ranking metric shows the chance line over all candidates (`chance_*`) and over candidates with score > 0 (`chance_pos_*`) next to it; for the contested rows the chance line is computed over the contested trials. The chance line beside **per-key MRR** is per key path: each key path uses `chance_line(n, m_k)` with m_k = candidates matching that key path, averaged over key paths (not the per-trial union m; ATK-EV-03, s07_t00). | 070 item 5; ATK-EV-03 |
| EV-08 | New totals rows use their own `row_kind` (`ranking_contested`, `b0_recall_contested`), so existing tables and row counts of `ranking` / `b0_recall` rows are unchanged (ATK-EV-12). | ATK-EV-12 |
| EV-06 | Match reading for the H verdicts = **node** reading (Jaccard ≥ 0.5 over `context` = 0 nodes, handoff §14.2, spec 05 §7.3); the hop reading stays in rank.md / rank_totals.csv beside it. | spec 05 §7.3 |
| EV-07 | Nothing else changes: tie rule, chance-line formulas, S06 check, b0 budget, frozen parameters, refusals, the allowlist. Existing primary-reading numbers remain recoverable from the same files (columns kept, only labels and order change). | 066, 070 |

### B — Runner
| ID | Rule | Source |
|---|---|---|
| RT-01 | **Allowlist first:** a trial not in `DEVELOPMENT_TRIALS` is refused (exit 2) before any file of it is opened and before any stage starts. This is needed because **gate has no allowlist** and the t02–t10 DBs exist in `data/processed/`. | 019, 046; survey 2026-11-18 |
| RT-02 | **Upstream presence pre-check** (owner): `data/processed/<t>.sqlite3`, `<t>.clock_offsets.csv`, `<t>.clock_changes.csv` exist and `data/trial_windows.csv` has exactly one row for `<t>`; otherwise refuse before any stage and print the exact commands that create them: `python -m data_layout.batch --only <t>` (DB missing), `python -m clock_offset --trials <t>`, `python -m trial_window --trials <every trial id already in trial_windows.csv, plus t, sorted>` (trial_window rewrites the whole file, so the list keeps existing rows). Presence only; hashes and consistency stay in gate. | owner 2026-11-18 |
| RT-03 | Steps per trial, each a subprocess `sys.executable -m <stage> … --repo R`, in order: `gate --trial t --out R/out/gate`, `stitch --trial t`, `label --trial t`, `score --trial t`, `evaluate --trial t`, `evaluate --trial t --label-recall` (keyed trials only, `KEYED_DEVELOPMENT_TRIALS`: the committed t01 folders hold no `label_recall.csv`, data-checker 2026-11-18), `evaluate --trial t --rank`. | handoff pipeline; CLAUDE.md |
| RT-04 | Each stage keeps its own refusals; the runner adds none beyond RT-01/RT-02. The first non-zero exit stops the trial; the runner prints the step name, the exit code and the stage's stderr tail, writes `run_log.json` with `status` = `refused` (exit 2) or `failed` (other), and exits with that code. | CLAUDE.md "each step refusing on its own checks" |
| RT-05 | The runner never runs `clock_offset`, `trial_window`, ingest or any `--development` flag of a stage in per-trial mode. It does not delete or edit stage outputs itself. | trial_window rewrites all rows |
| RT-06 | `--development`: runs RT-01..RT-04 for every trial in `DEVELOPMENT_TRIALS` order; stops at the first failing trial and names it (and the step); after all 9 succeed runs the summary steps `evaluate --development`, `evaluate --development --label-recall`, `evaluate --development --rank-sweep`, `evaluate --development --results`; writes the combined development log. | owner 2026-11-18 |
| RT-07 | `wall_ms` per step = wall-clock time of the subprocess (processing time per stage, handoff §14.2). It is a measurement only, machine-dependent, written only to `out/run_trial/`. | handoff §14.2 |
| RT-08 | `--repo` must be an existing directory holding `data/` and `out/`; the runner never writes outside `<R>/out/run_trial/` itself. Every step gets an explicit absolute `--repo` (and gate `--out`), never a default (ATK-EV-07). A refused trial id creates no `out/run_trial/<t>/` folder. `stderr_tail` is written with the repo path replaced by `<repo>`. | 054; ATK-EV-07, -12 |
| RT-09 | **Post-check per step** (ATK-EV-11): exit 0 is not enough — the step's documented output files (gate 7, stitch 10, label 7, score 8, evaluate the files it names) must exist and have been rewritten during the step (mtime ≥ step start); otherwise `status = failed`. Exit 2 whose stderr starts with `usage:` is `failed` (a runner bug), not `refused`. | ATK-EV-11 |
| RT-10 | On a stop, the log lists every later step as `not run` and says that outputs from an earlier run remain in those folders; with `--development` the summary steps (incl. `--results`) are not run, so results.md is not regenerated from a partial chain (ATK-EV-11). | ATK-EV-11 |
| RT-11 | The development list is imported from `clock_offset.params.DEVELOPMENT_TRIALS`, never copied. | ATK-EV Q4 |

### B2 — Dry run (`tools/run_trial_dryrun.py`)
| ID | Rule | Source |
|---|---|---|
| DR-01 | Scratch repo created with `tempfile.mkdtemp()` **outside the repository** (system temp folder); refuse if the resolved path lies under the repository. | owner 2026-11-18 |
| DR-02 | Copies into it: the 9 development DBs and their clock files, `data/trial_windows.csv`, `ground_truth/approved/` (t00 keys), `data/manifest.csv` if a stage reads it. No t02–t10 file is copied. | RT-01 |
| DR-03 | Runs `run_trial --development --repo <scratch>` (subprocess), then compares every file under `<scratch>/out/{gate,stitch,label,score,evaluate}/<t>/` and `out/evaluate/development/` with the committed `out/` copy: CSV byte-identical; MD and JSON equal after normalising (`generated_utc` values — present in stitch, label, score, evaluate per-trial and development `run_info.json`; the one cross-stage hash of a `run_info.json`, evaluate's `inputs.stitch_run_info_sha256`, and `score_run_info_sha256` in rank.md; no repo path is written, data-checker 2026-11-18). Gate writes no `run_info.json` and no timestamp, so gate files must be byte-identical. Reports per file: identical / equal after normalising / differs (first differing line). | plan; data-checker item 6 |
| DR-04 | Negative cases in the same scratch repo: (a) a **zero-byte** `data/processed/s02_t02.sqlite3` plus a fake window row are placed in scratch, then `run_trial --trial s02_t02` must be refused with the RT-01 allowlist message (not RT-02's), the file unchanged, no `out/gate/s02_t02` and no `out/run_trial/s02_t02` created (ATK-EV-08); (b) one copied clock file removed → refused by RT-02 with the create commands printed, no stage started. | RT-01, RT-02; ATK-EV-08 |
| DR-05 | The scratch repo is deleted in a `finally` block (also on failure or Ctrl-C): a running child stage is terminated and waited for first, read-only flags are cleared, deletion is retried; the tool then checks the folder no longer exists and prints `scratch repo <path> deleted` or the deletion error (exit non-zero). At start it warns about leftover folders with its prefix (`run_trial_dryrun_`) from a hard kill (ATK-EV-09). | owner 2026-11-18; ATK-EV-09 |
| DR-06 | **The committed tree is checked, not assumed** (ATK-EV-07): SHA-256 trees of the real `out/`, `data/` and `ground_truth/` are taken before and after the run and must be equal. The file set is compared in **both** directions against the committed folders: missing in scratch = differs; present only in scratch = `new` (reported, e.g. results.md before it is committed). | ATK-EV-07 |
| DR-07 | Normalising touches only the named keys / lines of DR-03 and reports the number of substitutions per file; CSVs are compared byte for byte, and if they differ only by line endings that is reported separately (ATK-EV-10). | ATK-EV-10 |

### C — Results tables
| ID | Rule | Source |
|---|---|---|
| RS-01 | `--results` runs with `--development` only; `--results --trial <t>` and any non-development split are refused: "results tables on test trials need the T5.7 key lock and an owner-approved test allowlist (PLAN 10.4)". | 019; out of scope |
| RS-02 | Inputs: the ranking check is recomputed in memory with `rank_run.rank_trial` for every development trial (all its refusals apply), then the rendered `rank_totals.csv` and each `rank.csv` must equal the committed files byte for byte; otherwise refuse "stale: rerun `python -m evaluate --development --rank`". (Rank outputs have no `run_info` hash today, so freshness is checked by re-rendering.) | CLAUDE.md "documented input"; OPEN Q3 |
| RS-03 | H1 = top-1 (expected tie reading), `full`, node reading, all attack trials: held iff ≥ 0.80. | 065, spec 05 §7.3 |
| RS-04 | H2 = per-key MRR, `full`: held iff ≥ 0.85. H3 = per-key MRR(`full`) **>** per-key MRR(`b1`), strict; equal = not held. Top-1 rates and the difference reported beside. | 070 items 2–3, 065 |
| RS-05 | H4 = mean labelled-node recall `full` > `b0` at the equal labelled budget (denominator: Q6); all-node recall beside. H5 = S06 margin (lowest key attack score − highest S06 score, `full`) > 0 in every **keyed** S06 trial; unkeyed S06 trials (development: s06_t01, max 0.2857 > s06_t00's 0.2778) are reported beside, with the margin they would give (ATK-EV-04). If any key attack path has no matching candidate, the lowest key attack score is undefined and H5 is **not held** (reason written), never computed over the rest (ATK-EV-04). Share of attack trials above it beside. H5 wording: "orders the S06 benign paths below the attack paths by score". | 070 item 1, 065; ATK-EV-04 |
| RS-06 | Every table: observed value, frozen threshold, verdict, chance line over all candidates and over score > 0 (for H4/H5, where no ranking chance applies, the column says `n/a` with the reason); contested reading for full, b1, b2, b0 beside H1–H4 (no verdict, EV-04); H5 has no contested reading (Q2: a subset can only widen the margin). | 070 items 4–5 |
| RS-09 | **Verdicts on exact values** (ATK-EV-02): each compared quantity is computed with `math.fsum` and compared after rounding to 12 decimals (as SC-41); H3 "equal" = equal at 12 decimals = not held. results.csv carries `observed_12` (the compared value) beside the 6-decimal `observed`. | ATK-EV-02; SC-41 |
| RS-10 | The verdict column is named `dev_check` while `split = development` (renamed `verdict` only for the test run, out of scope); `score.report.forbidden_hits` (or its evaluate equivalent) runs over results.md and must return nothing (ATK-EV-13). | ATK-EV-13 |
| RS-11 | CLI: `--results` with `--rank`, `--rank-sweep`, `--label-recall`, `--stitch-dir` or `--out` is refused (ATK-EV-12). | ATK-EV-12 |
| RS-07 | `results.md` / `results.csv` are deterministic (no timestamp, no timing): processing time is only referenced (`out/run_trial/development/run_log.md`), so a fresh `--results` equals the committed files. | 054 committed-folder test |
| RS-08 | Wording: "ranks", "expected, to be measured", "development check"; never "reduces false positives", "detects stolen accounts", "identifies the attacker"; the stated limits of H1–H3 (spec 05 §7.3, L-SC5) are copied into results.md. | CLAUDE.md |

## 5. Parameters
None new. Thresholds H1 0.80, H2 0.85, H3 strict, H4 strict, H5 margin > 0 and the score parameters are frozen
(066 at `6338884`, readings 070); this spec reads them from `evaluate.params` (pinned by `test_rank_pins`) and adds a
pin for the H thresholds.

## 6. Edge cases (attacker review merged, ATK-EV-01..14, 2026-11-18)
| Case | Where | Expected | Test |
|---|---|---|---|
| ATK-EV-01 labelled recall divides by all key nodes | every keyed attack trial (code: `rank_run._b0.side`) | owner Q6; synthetic: 4 key nodes, 2 labelled, full holds both → 1.0 under (a) | EVT-08 |
| ATK-EV-02 threshold hit exactly (0.80, 0.85) or equal MRR from different sums | synthetic | verdict on 12-decimal fsum value (RS-09) | RST-03 |
| ATK-EV-03 per-key chance line with two key paths | s07_t00; synthetic n = 6 | per-key chance uses m_k per key path (EV-05) | EVT-05 |
| ATK-EV-04 unmatched key path / unkeyed S06 trial | synthetic; s06_t01 | H5 not held with reason / reported beside (RS-05) | RST-05 |
| ATK-EV-05 only positive candidate is a rival | synthetic | listed as "uncontested — key path not scored" (EV-03) | EVT-04 |
| ATK-EV-06 full and b1 contested sets differ | synthetic | paired reading on full's set; own sets beside; no verdict (EV-04) | EVT-06 |
| ATK-EV-07 a step writes the committed out/ | seeded run without `--repo` | before/after tree hashes differ → dry run fails (DR-06) | RTT-07 |
| ATK-EV-08 test-trial refusal proven only by a missing DB | scratch with zero-byte s02_t02 DB | RT-01 message, nothing created (DR-04a) | RTT-01 |
| ATK-EV-09 Ctrl-C / locked or read-only files | Windows | child killed, retry, deletion verified (DR-05) | RTT-08 |
| ATK-EV-10 CRLF checkout / broad normalising | any | named keys only, EOL-only difference reported (DR-07) | RTT-06 |
| ATK-EV-11 exit 0 without output; usage error exit 2 | synthetic | RT-09 post-check, RT-10 not-run list | RTT-03, RTT-04 |
| ATK-EV-12 contested rows in old tables; CLI combinations | — | own row_kind (EV-08), refusals (RS-11) | EVT-07, RST-01 |
| ATK-EV-13 "held" quoted out of context | results.csv | `dev_check` column, forbidden-word scan (RS-10) | RST-08 |
| ATK-EV-14 b0 contested by ST-05 copies | every trial | distinct units after merging copies (EV-03) | EVT-03 |
| Test trial passed to the runner | any t02–t10 | refused by RT-01 before gate opens the DB | RTT-01 |
| Clock or window row missing | new trial | refused by RT-02 with create commands; no stage run | RTT-02 |
| Stage refuses mid-chain (e.g. label stale) | synthetic | runner stops, names step, exit 2, log `refused` | RTT-03 |
| Committed rank files stale | after a score rerun | `--results` refused (RS-02) | RST-02 |
| Variant with 0 contested trials | b1 on a synthetic repo | contested row with `attack_trials = 0`, empty metrics | EVT-03 |
| Key path ties a rival at rank 1 | s04_t00 | expected rank 1.5 counts in contested and primary | EVT-01 |

## 7. Acceptance tests
### 7.1 Development (DEVELOPMENT numbers, not results; values from 070 / 069 at `c21db11`)
- **EVA-01** per-key MRR `full` = 0.833333 (s02 1, s03 1, s04-B 0.666667, s05 1, s07-x 0.666667, s07-y 0.666667);
  per-trial MRR 0.933333 beside.
- **EVA-02** contested trials `full`/`b1`/`b2` = {s04_t00, s07_t00}: top-1 0.750, per-trial MRR 0.833, per-key MRR
  0.667, identical in all three; `b0` contested = all 5 attack trials.
- **EVA-03** H4 labelled, depending on Q6: (b) denominator all key nodes (as 070's numbers): `full` 0.214251 vs
  `b0` 0.121317; (a) denominator labelled key nodes, b0-reachable = key nodes inside a b0 unit (read-only
  measurement 2026-11-18, 3/4/5/10/10 labelled key nodes in s02/s03/s04/s05/s07): `full` 0.830 (1.0, 0.75, 0.5,
  0.9, 1.0) vs `b0` 0.423 (0.0, 0.714, 0.3, 0.5, 0.6). Direction (full > b0 in 5/5 trials) is the same under both.
  All-node 0.877451 vs 0.260609 beside.
- **EVA-04** chance line all candidates top-1 0.248 / MRR 0.377; over score > 0 0.900 / 0.933.
- **RSA-01** results.md `dev_check` on development: H1 held (0.900 ≥ 0.80), H2 not held (0.833 < 0.85), H3 not
  held (0.833 = 0.833), H4 held (Q6: 0.830 > 0.423 or 0.214 > 0.121), H5 held (margin 0.306, one keyed S06 trial;
  s06_t01 unkeyed beside, margin 0.298).
- **RTA-01** dry run: 9/9 trials, every output file identical or equal after normalising (DR-03); s02_t02 refused;
  missing-clock case refused; scratch repo reported deleted and absent.
- **RTA-02** processing time per stage written for every step of the 9 trials (`wall_ms` > 0).

### 7.2 Unit tests (synthetic)
EVT-01..07 (rank readings, contested sets, chance columns in every table, label text), RTT-01..08 (allowlist first,
pre-check messages and the trial_window list, stop-at-first-failure, log contents, `--development` naming the failing
trial, no write outside out/run_trial), RST-01..08 (refusals, verdict logic at the threshold boundary: 0.80 held,
0.849999 not held, equal MRR not held; determinism; DEVELOPMENT label on every table).

## 8. OPEN questions
| # | Question | Options / proposal | Needs council? |
|---|---|---|---|
| Q1 | b0 under the contested reading (070 item 4 says "every metric") | **(a) proposal:** H4 recall only — b0 ranks single labelled units, not paths, so top-1/MRR against a key path are undefined (a unit cannot reach node Jaccard ≥ 0.5 with a multi-node key path); paired H4 on full's contested set, b0's own set beside (attacker agrees, ATK-EV-06). (b) define a b0 top-1 by "unit inside the key path". | no (record 071) |
| Q2 | H5 contested reading | **(b) proposal (changed after attacker):** none — H5 is per S06 trial, and restricting the attack side to a subset can only raise the lowest key score, i.e. a more lenient reading. (a) margin over contested attack trials only. | no (record 071) |
| Q3 | Results input: files or recomputation | **(a) proposal (RS-02):** recompute in memory with all rank checks, then refuse if the committed rank files differ (staleness check without a new run_info). (b) add a `rank_run_info.json` with hashes and read files only. | no (record 071) |
| Q4 | Runner location and name | **(a) proposal:** `src/run_trial` package (one `python -m` entry like every stage; list imported, RT-11; needs `pip install -e .` once). (b) `tools/run_trial.py`. | no |
| Q5 | H verdict match reading | **(a) proposal (EV-06):** node reading (spec 05 §7.3 names node Jaccard); hop reading beside; a synthetic test where the two differ (development values are identical under both). | no |
| **Q6** | **H4 labelled-recall denominator (ATK-EV-01, blocking).** 070 item 1 says "node recall over **labelled** context = 0 key nodes (the b0-reachable set)"; the code (`rank_run._b0`) divides the labelled-budget coverage by **all** key nodes, and 070's numbers (0.214 vs 0.121) were computed that way. | **(a) proposal:** fix the code to 070's text — denominator = key nodes inside a b0 unit (the b0-reachable set; ST-05 copies merged); development becomes 0.830 vs 0.423 (EVA-03). This changes a value written in a frozen record, so it needs a short freeze record **071 (correction of 070's numbers, reading text unchanged, thresholds unchanged)**, before T5.7. (b) keep the code; amend 070's text to "share of all key nodes reached with labelled nodes only" (also a freeze record). Either way H4's direction on development is unchanged. | owner (freeze record; no council needed unless you want one) |

## 9. Out of scope
The test run (PLAN 10.4), the `answer-keys-locked` tag and key approvals (T5.7), test allowlists, weight sensitivity
on test data and the summary (10.5), the ablation without the command-line method (10.6), node P/R/F1/FNR tables and
pooled ROC-AUC (10.2 rest), any change to a frozen parameter, threshold or reading, and any change to
`DEVELOPMENT_TRIALS`.
