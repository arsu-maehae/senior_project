---
description: Run the evaluation (Full system and baselines B0–B3) over chosen trials and produce the results tables. Use in the evaluation phase only.
disable-model-invocation: true
---
# Evaluation run: $ARGUMENTS   (e.g. "s02,s04 t01-t03" or "all")

1. Confirm the answer keys for the chosen trials are locked (git tag `answer-keys-locked`). If not, stop.
2. For each trial run: B0 alerts only · B1 linked paths, no ranking (time order) · B2 order-blind (NodeScore only)
   · B3 full with w3 = 0 · Full. Same data, same answer keys.
3. Compute per trial (docs/specs/06_evaluate.md): node P/R/F1/FNR on top-k (k = answer-key attack paths),
   top-1 rate, reciprocal rank, score gap, S06 check, labelling recall, processing time per stage.
4. Write out/eval/<run-id>/results.csv and summary.md: mean, min–max over trials, per scenario and per variant.
5. Ask the `fact-checker` to check summary.md claims against results.csv before anyone uses them.
Report numbers exactly as computed. A variant that does not help is a valid result; do not tune on the test trials.
