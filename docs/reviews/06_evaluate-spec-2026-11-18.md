# Review of spec 06_evaluate (T10, development-only part) — 2026-11-18

Spec: [docs/specs/06_evaluate.md](../specs/06_evaluate.md). Scope: 070 readings in `evaluate --rank` (PLAN 10.7),
runner `run_trial` with a scratch-repo dry run, results tables on development data. No t02–t10 file opened.

## Data-checker (read-only, development trials only)
All MATCH:
- 9/9 trials have a DB, `clock_offsets.csv`, `clock_changes.csv` and exactly one `trial_windows.csv` row. The CSV
  holds these 9 rows only.
- Stage folders exist for all 9 trials.
- The t01 evaluate folders have no `label_recall.csv` and no `link_accuracy_hops.csv`. So RT-03 runs `--label-recall`
  for keyed trials only.
- Contested trials: s04_t00 and s07_t00 for full/b1/b2; all 5 attack trials for b0, where every unit scores above 0.
- Per-key expected RR: 1, 1, 0.667, 1, 0.667, 0.667, giving per-key MRR 0.833333.
- Contested-only, derived: top-1 0.750, per-trial MRR 0.833, per-key MRR 0.667. These equal 070.
- H4 labelled 0.214251 vs 0.121317; all nodes 0.877451 vs 0.260609.
- `generated_utc` appears only in the stitch, label, score and evaluate `run_info.json`. Gate writes no `run_info` and
  no timestamp.
- One cross-stage hash of a `run_info.json`: evaluate `inputs.stitch_run_info_sha256`.
- No repo path is written anywhere.

## Attacker (ATK-EV-01..14)
**Blocking**
- **ATK-EV-01** (owner Q6): the labelled recall is divided by all key nodes, not by the labelled key nodes.
  - Confirmed in `src/evaluate/rank_run.py` `_b0.side`.
  - Read-only re-measurement with the b0-reachable denominator: full 0.830 vs b0 0.423 (it was 0.214 vs 0.121).
  - The direction is unchanged in 5/5 trials.
- **ATK-EV-02**: a verdict that lands exactly on a threshold. Fixed by RS-09 (fsum, compared at 12 decimals).
- **ATK-EV-03**: the chance line beside per-key MRR must be per key path. Fixed in EV-05.
- **ATK-EV-07**: the dry run must prove the committed tree is untouched and compare the file set in both directions.
  Fixed by DR-06.

**Should-fix**, merged as rules:
- ATK-EV-04 → RS-05: an unmatched key path means H5 is not held; unkeyed S06 trials are reported beside.
- ATK-EV-05 → EV-03: a trial that is uncontested because the key path was not scored is named.
- ATK-EV-06 → EV-04: the paired contested reading uses full's contested set, and contested rows carry no verdict.
- ATK-EV-08 → DR-04a: the test-trial refusal is proven with a zero-byte DB present.
- ATK-EV-09 → DR-05: cleanup covers a child process, read-only files and retries.
- ATK-EV-10 → DR-07: only the named keys are normalised, and line-ending differences are reported.
- ATK-EV-11 → RT-09, RT-10: post-check per step, and a "not run" list on a stop.

**Minor**, merged:
- ATK-EV-12 → EV-08, RS-11, RT-08
- ATK-EV-13 → RS-10: `dev_check` column, forbidden-word scan
- ATK-EV-14 → EV-03: b0 units counted after ST-05 copies are merged

**OPEN-question opinions**: Q1 (a) with the paired reading; Q2 changed to (b), no contested H5; Q3 (a); Q4 (a);
Q5 (a) plus a synthetic hop/node divergence test.

## Status
Draft complete; awaiting owner approval of the spec and an answer to Q6. A Q6 answer changes a number written in
frozen record 070, so it needs freeze record 071 before T5.7.

## Addendum D (rest of 10.2, 10.5, 10.6), 2026-11-18
**Data-checker** (read-only, development trials):
- Every tier-B hop in s02, s04, s05, s07 t00 and s02_t01 is linked by `cmdline_target` only.
- Key attack hops that depend on `cmdline_target` alone, which drop to target_only / tier D in the ablation:
  - s02-h1 → h0025
  - s04-B-h1 → h0024
  - s05-h1 → h0030
  - s07-h-x → h0027
  - s07-h-y → h0031
- Key attack hops that keep a port and 4648 link (tier A): s03-h1 → h0020 and s05-h2 → h0032.
- S06 key hops (benign) keep 4648 or port.
- Identity does not depend on cmdline linking (013).

**Attacker** ATK-EV-26..36, merged as D-G (AB-05..11, SW-03, AUC-03, NP-05, PT-02, SUM-02). The main points:
- The default run must stay byte-identical (ATK-EV-26).
- The ablation flag is refused in the real repo (ATK-EV-27).
- Every use of cmdline evidence in the stitcher is switched off and listed (ATK-EV-28).
- The hop reading is the ablation's headline reading, because the key is built from the same command-line evidence
  (ATK-EV-29).
- No verdict appears anywhere in the ablation (ATK-EV-30).

No item needs a new hypothesis or a change to a frozen record.
