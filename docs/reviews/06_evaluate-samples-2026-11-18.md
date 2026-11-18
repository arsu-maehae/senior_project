# Hand-check samples — T10 development part (2026-11-18)

DEVELOPMENT numbers, not results. Up to 10 rows per output; check each row against the file it cites (spec 06 §3). Generated from the committed out/ after `python -m run_trial --development`.

## out/evaluate/development/results.csv (5 primary + 5 contested rows)

| table | variant | reading_scope | metric | observed | observed_12 | threshold | comparator | dev_check | equals_chance_pos | chance_all | chance_pos | n_trials |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| H1 | full | all | top1_expected | 0.900000 | 0.900000000000 | 0.80 | >= | held | 1 | 0.248333 | 0.900000 | 5 |
| H2 | full | all | mrr_per_key_expected | 0.833333 | 0.833333333333 | 0.85 | >= | not held | 1 | 0.337831 | 0.833333 | 5 |
| H3 | full_vs_b1 | all | mrr_per_key_expected_difference | 0.000000 | 0.000000000000 | 0.00 | > | not held |  | n/a: difference of two variants; the chance line of each side is in its own row | n/a: difference of two variants; the chance line of each side is in its own row | 5 |
| H4 | full_vs_b0 | all | recall_labelled_mean_difference | 0.407143 | 0.407142857143 | 0.00 | > | held |  | n/a: node recall at an equal node budget, no ranking order to draw at random | n/a: node recall at an equal node budget, no ranking order to draw at random | 5 |
| H5 | full | all | s06_margin_min | 0.305556 | 0.305555555555 | 0.00 | > | held |  | n/a: score margin across trials, no ranking order to draw at random | n/a: score margin across trials, no ranking order to draw at random | 1 |
| H1 | full | contested | top1_expected | 0.750000 | 0.750000000000 |  |  |  | 1 | 0.266667 | 0.750000 | 2 |
| H1 | b1 | contested | top1_expected | 0.750000 | 0.750000000000 |  |  |  | 1 | 0.266667 | 0.750000 | 2 |
| H1 | b2 | contested | top1_expected | 0.750000 | 0.750000000000 |  |  |  | 1 | 0.266667 | 0.750000 | 2 |
| H2 | full | contested | mrr_per_key_expected | 0.666667 | 0.666666666667 |  |  |  | 1 | 0.301587 | 0.666667 | 2 |
| H2 | b1 | contested | mrr_per_key_expected | 0.666667 | 0.666666666667 |  |  |  | 1 | 0.301587 | 0.666667 | 2 |

## out/evaluate/development/rank_totals.csv (ranking / contested / b0 rows)

| row_kind | variant | match_reading | reading_scope | attack_trials | top1_expected | mrr_expected | mrr_per_key_expected | chance_per_key_mrr | full_recall_labelled_mean | b0_recall_labelled_mean | labelled_recall_trials | s06_margin | s06_reason | primary_metric |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ranking | full | node | all | 5 | 0.900000 | 0.933333 | 0.833333 | 0.337831 |  |  |  | 0.305556 |  | mrr_per_key_expected |
| ranking | b1 | node | all | 5 | 0.900000 | 0.933333 | 0.833333 | 0.337831 |  |  |  | -0.041667 |  | mrr_per_key_expected |
| ranking | b2 | node | all | 5 | 0.900000 | 0.933333 | 0.833333 | 0.337831 |  |  |  | -0.333333 |  | mrr_per_key_expected |
| ranking_contested | full | node | contested | 2 | 0.750000 | 0.833333 | 0.666667 | 0.301587 |  |  |  |  |  | mrr_per_key_expected |
| ranking_contested | b1 | node | contested | 2 | 0.750000 | 0.833333 | 0.666667 | 0.301587 |  |  |  |  |  | mrr_per_key_expected |
| ranking_contested | b2 | node | contested | 2 | 0.750000 | 0.833333 | 0.666667 | 0.301587 |  |  |  |  |  | mrr_per_key_expected |
| b0_recall | full_vs_b0 |  | all | 5 |  |  |  |  | 0.830000 | 0.422857 | 5 |  |  | full_recall_labelled_mean;b0_recall_labelled_mean |
| b0_recall_contested | full_vs_b0 |  | contested | 2 |  |  |  |  | 0.750000 | 0.450000 | 2 |  |  | full_recall_labelled_mean;b0_recall_labelled_mean |
| b0_recall_contested | full_vs_b0 |  | contested | 5 |  |  |  |  | 0.830000 | 0.422857 | 5 |  |  | full_recall_labelled_mean;b0_recall_labelled_mean |

## out/evaluate/<t>/rank.csv — b0_recall rows (071 denominator) and s07 full node rows

| trial_id | row_kind | key_path_id | contested | key_node_count | key_nodes_labelled | budget_nodes_labelled | full_recall_labelled | b0_recall_labelled | n_positive_units | rank_expected | rr_expected |
|---|---|---|---|---|---|---|---|---|---|---|---|
| s02_t00 | b0_recall |  | 1 | 16 | 3 | 3.000000 | 1.000000 | 0.000000 | 10 |  |  |
| s03_t00 | b0_recall |  | 1 | 12 | 4 | 8.000000 | 0.750000 | 0.714286 | 11 |  |  |
| s04_t00 | b0_recall |  | 1 | 21 | 5 | 5.000000 | 0.500000 | 0.300000 | 10 |  |  |
| s05_t00 | b0_recall |  | 1 | 34 | 10 | 14.000000 | 0.900000 | 0.500000 | 17 |  |  |
| s07_t00 | b0_recall |  | 1 | 40 | 10 | 10.000000 | 1.000000 | 0.600000 | 12 |  |  |
| s07_t00 | key_path | s07-h-x-path |  | 28 |  |  |  |  |  | 1.500000 | 0.666667 |
| s07_t00 | key_path | s07-h-y-path |  | 12 |  |  |  |  |  | 1.500000 | 0.666667 |
| s07_t00 | trial | s07-h-x-path;s07-h-y-path | 1 |  |  |  |  |  |  | 1.000000 | 1.000000 |

## out/run_trial/development/run_log.json (first 10 steps)

| trial | step | exit_code | wall_ms | result | post_check |
|---|---|---|---|---|---|
| s02_t00 | gate | 0 | 304 | ok | [] |
| s02_t00 | stitch | 0 | 637 | ok | [] |
| s02_t00 | label | 0 | 554 | ok | [] |
| s02_t00 | score | 0 | 247 | ok | [] |
| s02_t00 | evaluate | 0 | 313 | ok | [] |
| s03_t00 | gate | 0 | 811 | ok | [] |
| s03_t00 | stitch | 0 | 1796 | ok | [] |
| s03_t00 | label | 0 | 1118 | ok | [] |
| s03_t00 | score | 0 | 260 | ok | [] |
| s03_t00 | evaluate | 0 | 896 | ok | [] |
