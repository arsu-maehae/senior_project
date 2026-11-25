# Decision 078 kill-criterion run (development trials only, scratch repos, 2026-11-25)

Arms: control (unchanged windows), clip15 (end = last design step + 15 s + own criterion-g skew), clip0 (end = last
design step). Runner: `python -m run_trial --development --repo <scratch>`, unchanged. Real repo: 1266 files hashed
before/after, 0 changed. Control: 363 files compared with out/, 0 mismatches. All scratch repos deleted.

## clip15
- Linking on matched hops/links/paths: 0 changes in all 9 trials. Key hop link accuracy unchanged; key path rank 1
  and score unchanged (keyed t00).
- Only effect: hops lying wholly after the clip vanish with their one-hop paths (s05_t00: 1 seed ep-03>dc01;
  s02_t01: 4 seeds incl. the extra ep-01>ep-02 admin_it hop at 05:34:09, 3 machine-account dc01 hops) and
  rank ties among unchanged scores shrink.
- Sigma: 0 path node-score changes; hop-level label counts shrink only (dc01 hop node events, dump lists).
- Kill criterion 1 (threshold too low): NOT triggered.

## clip0
- Linking changes in 7 of 9 trials: the last design hop loses its trigger (s03_t00, s07_t00, s03_t01: key path
  leaves the ranking), loses Sysmon 3 port join (s03_t00, s05_t00: tier A->B), loses its source evidence
  (s06_t00: tier B->D target_only), or loses members (s02_t01, s06_t01, s05_t00 path split).
- Sigma: node_score_ctx1 / n_node_units change on s06_t00 p0007, s07_t00 p0005.
- s02_t00, s04_t00: hop-level label counts only.
- Kill criterion 2 (relax to +0 s): NOT supported; the after-window is needed.
