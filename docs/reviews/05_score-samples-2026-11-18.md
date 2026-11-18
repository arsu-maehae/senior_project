# Hand check: score stage samples — 2026-11-18

Up to 10 rows per T9 output, development trials only, picked by a read-only script (not committed; it only filters the CSVs). 64-hex uids shortened to 8 characters. **What to check by hand:**

- `ranked_paths.csv`: score = (L + N + I)/3 for `full`, (L + N)/2 for `b1`, N for `b2`; equal scores share a rank (s04 p0004/p0005 tie at 1, decisions 018/021); zero-score paths are ranked, never dropped.
- s05 p0004: L = (1 − e^(−4 ln 2)) · 0.875 = 0.9375 · 0.875 = 0.8203125; I = 2/3 (background hop h0010 not exposed).
- `path_steps.csv`: T1021.002→T1570 and T1570→T1569.002 direct (R3/R4); T1569.002→T1078 `hop_chain` (real chain edge h0030→h0032); T1078→T1021.006 indirect 0.5 via R5 (weak template, L-SC7).
- `path_node_units.csv`: one row per `count_key`; SMB hops are all level 1 (own rules low, Q1 asymmetry accepted, 063).
- `hop_identity_values.csv`: s04 admin_it (h0023, benign track A) and svc_backup (h0024, attack track B) are both `exposed` — exposed ≠ stolen; machine-account and unknown-source hops are `unknown:<reason>` with empty value.
- `b0_ranked.csv`: alerts only, no linking; T1003.001 dumps rank at the top of b0 (level 3), which `full` never counts in NodeScore (056 item 7).
- `rank.csv` (DEVELOPMENT numbers, not results): s04 and s07 key paths at expected rank 1.5 per key; s07 at trial level rank 1 (both key paths in the top tie group); `chance_pos_top1` equals `top1_expected` in s04 (see 069 consequences).

### `out/score/s04_t00/ranked_paths.csv` (5 rows)

| variant | rank | tie_size | path_id | score | length_score | node_score | identity_coherence | n_crossings | n_hops_unknown | technique_sequence |
|---|---|---|---|---|---|---|---|---|---|---|
| full | 1 | 2 | s04_t00-p0004 | 0.666666666667 | 0.750000000000 | 0.250000000000 | 1.000000000000 | 1 | 0 | T1021.002>T1570>T1569.002 |
| full | 1 | 2 | s04_t00-p0005 | 0.666666666667 | 0.750000000000 | 0.250000000000 | 1.000000000000 | 1 | 0 | T1021.002>T1570>T1569.002 |
| full | 3 | 3 | s04_t00-p0001 | 0.000000000000 | 0.000000000000 | 0.000000000000 | 0.000000000000 | 0 | 1 |  |
| full | 3 | 3 | s04_t00-p0002 | 0.000000000000 | 0.000000000000 | 0.000000000000 | 0.000000000000 | 0 | 1 |  |
| full | 3 | 3 | s04_t00-p0003 | 0.000000000000 | 0.000000000000 | 0.000000000000 | 0.000000000000 | 1 | 0 |  |

### `out/score/s05_t00/ranked_paths.csv` (3 rows)

| variant | rank | tie_size | path_id | score | length_score | edge_score | seq_len | node_score | identity_coherence | technique_sequence |
|---|---|---|---|---|---|---|---|---|---|---|
| full | 1 | 1 | s05_t00-p0004 | 0.655916132479 | 0.820312500000 | 0.875000000000 | 4 | 0.480769230769 | 0.666666666667 | T1021.002>T1570>T1569.002>T1078>T1021.006 |
| b1 | 1 | 1 | s05_t00-p0004 | 0.650540865385 | 0.820312500000 | 0.875000000000 | 4 | 0.480769230769 | 0.666666666667 | T1021.002>T1570>T1569.002>T1078>T1021.006 |
| b2 | 1 | 1 | s05_t00-p0004 | 0.480769230769 | 0.820312500000 | 0.875000000000 | 4 | 0.480769230769 | 0.666666666667 | T1021.002>T1570>T1569.002>T1078>T1021.006 |

### `out/score/s06_t00/ranked_paths.csv` (7 rows)

| variant | rank | tie_size | path_id | score | length_score | node_score | identity_coherence | technique_sequence |
|---|---|---|---|---|---|---|---|---|
| full | 1 | 1 | s06_t00-p0005 | 0.277777777778 | 0.250000000000 | 0.583333333333 | 0.000000000000 | T1078>T1021.006 |
| full | 2 | 2 | s06_t00-p0006 | 0.250000000000 | 0.250000000000 | 0.500000000000 | 0.000000000000 | T1078>T1021.006 |
| full | 2 | 2 | s06_t00-p0007 | 0.250000000000 | 0.500000000000 | 0.250000000000 | 0.000000000000 | T1021.002>T1569.002 |
| full | 4 | 4 | s06_t00-p0001 | 0.000000000000 | 0.000000000000 | 0.000000000000 | 0.000000000000 |  |
| full | 4 | 4 | s06_t00-p0002 | 0.000000000000 | 0.000000000000 | 0.000000000000 | 0.000000000000 |  |
| full | 4 | 4 | s06_t00-p0003 | 0.000000000000 | 0.000000000000 | 0.000000000000 | 0.000000000000 |  |
| full | 4 | 4 | s06_t00-p0004 | 0.000000000000 | 0.000000000000 | 0.000000000000 | 0.000000000000 |  |

### `out/score/s05_t00/path_steps.csv` (4 rows)

| path_id | step | from_technique | to_technique | tactic_score | technique_score | score_e | basis |
|---|---|---|---|---|---|---|---|
| s05_t00-p0004 | 1 | T1021.002 | T1570 | 1.000000000000 | 1.000000000000 | 1.000000000000 | direct |
| s05_t00-p0004 | 2 | T1570 | T1569.002 | 1.000000000000 | 1.000000000000 | 1.000000000000 | direct |
| s05_t00-p0004 | 3 | T1569.002 | T1078 | 1.000000000000 | 1.000000000000 | 1.000000000000 | hop_chain |
| s05_t00-p0004 | 4 | T1078 | T1021.006 | 0.500000000000 | 0.500000000000 | 0.500000000000 | indirect |

### `out/score/s07_t00/path_node_units.csv` (8 rows)

| path_id | count_key | hop_id | techniques | level_value |
|---|---|---|---|---|
| s07_t00-p0005 | 2e795a85... | s07_t00-h0027 | T1569.002 | 1 |
| s07_t00-p0005 | 52f0246c... | s07_t00-h0027 | T1570 | 1 |
| s07_t00-p0005 | 8177dd10... | s07_t00-h0027 | T1570 | 1 |
| s07_t00-p0005 | fcdd4d6a... | s07_t00-h0027 | T1021.002 | 1 |
| s07_t00-p0006 | 792a3682... | s07_t00-h0031 | T1570 | 1 |
| s07_t00-p0006 | 9be76372... | s07_t00-h0031 | T1570 | 1 |
| s07_t00-p0006 | cee44f90... | s07_t00-h0031 | T1569.002 | 1 |
| s07_t00-p0006 | f395acd0... | s07_t00-h0031 | T1021.002 | 1 |

### `out/score/s04_t00/hop_identity_values.csv` (10 rows)

| hop_id | account | value | identity_status | candidate_count | time_delta_ms | open_session_uids |
|---|---|---|---|---|---|---|
| s04_t00-h0004 | svc_backup | 0 | not_exposed | 0 |  |  |
| s04_t00-h0012 | admin_it | 0 | not_exposed | 2 |  |  |
| s04_t00-h0014 | admin_it | 0 | not_exposed | 2 |  |  |
| s04_t00-h0016 | admin_it | 0 | not_exposed | 2 |  |  |
| s04_t00-h0018 | svc_backup | 0 | not_exposed | 0 |  |  |
| s04_t00-h0019 | admin_it | 0 | not_exposed | 2 |  |  |
| s04_t00-h0021 | admin_it | 1 | exposed | 2 | 20604 | 9e811527...;a49cf8bb...;d0e1f7ec... |
| s04_t00-h0023 | admin_it | 1 | exposed | 2 | 38396 | 9e811527...;a49cf8bb...;d0e1f7ec... |
| s04_t00-h0024 | svc_backup | 1 | exposed | 2 | 41061 | ecaab42b... |
| s04_t00-h0025 | svc_backup | 0 | not_exposed | 0 |  |  |

### `out/score/s06_t00/hop_identity_values.csv` (10 rows)

| hop_id | account | value | identity_status | not_applicable | candidate_count |
|---|---|---|---|---|---|
| s06_t00-h0001 | endpoint-02$ |  | unknown:machine_account | machine_account | 0 |
| s06_t00-h0002 | endpoint-02$ |  | unknown:machine_account | machine_account | 0 |
| s06_t00-h0003 | endpoint-03$ |  | unknown:source_host_unknown | source_host_unknown | 0 |
| s06_t00-h0004 | endpoint-03$ |  | unknown:machine_account | machine_account | 0 |
| s06_t00-h0005 | endpoint-01$ |  | unknown:machine_account | machine_account | 0 |
| s06_t00-h0006 | endpoint-02$ |  | unknown:machine_account | machine_account | 0 |
| s06_t00-h0006 | svc_backup | 0 | not_exposed |  | 0 |
| s06_t00-h0007 | dc-01$ |  | unknown:source_host_unknown | source_host_unknown | 0 |
| s06_t00-h0008 | dc-01$ |  | unknown:source_host_unknown | source_host_unknown | 0 |
| s06_t00-h0009 | endpoint-03$ |  | unknown:machine_account | machine_account | 0 |

### `out/score/s03_t00/b0_ranked.csv` (10 rows)

| rank | tie_size | unit_id | host | techniques | level_value | score |
|---|---|---|---|---|---|---|
| 1 | 5 | 0482a4f7... | ep-01 | T1021.006 | 3 | 0.750000000000 |
| 1 | 5 | 05f81d10... | ep-01 | T1003.001 | 3 | 0.750000000000 |
| 1 | 5 | 0cae4c26... | ep-01 | T1021.006 | 3 | 0.750000000000 |
| 1 | 5 | ba92293b... | ep-01 | T1021.006 | 3 | 0.750000000000 |
| 1 | 5 | c95122d5... | ep-01 | T1003.001 | 3 | 0.750000000000 |
| 6 | 6 | 56f39627... | ep-01 | T1078 | 2 | 0.500000000000 |
| 6 | 6 | 64255c88... | ep-01 | T1078 | 2 | 0.500000000000 |
| 6 | 6 | 78c95d9b... | ep-03 | T1021.006 | 2 | 0.500000000000 |
| 6 | 6 | 8d6c51a5... | ep-01 | T1078 | 2 | 0.500000000000 |
| 6 | 6 | 9bdd1e08... | ep-01 | T1078 | 2 | 0.500000000000 |

### `out/evaluate/s07_t00/rank.csv` (10 rows)

| row_kind | variant | match_reading | key_path_id | matched_jaccards | first_rank | tie_size | rank_expected | rr_expected | chance_rr | score_gap |
|---|---|---|---|---|---|---|---|---|---|---|
| key_path | full | hop | s07-h-x-path | s07_t00-p0005=1.000000 | 1 | 2 | 1.500000 | 0.666667 | 0.285714 |  |
| key_path | full | hop | s07-h-y-path | s07_t00-p0006=1.000000 | 1 | 2 | 1.500000 | 0.666667 | 0.285714 |  |
| trial | full | hop | s07-h-x-path;s07-h-y-path |  | 1 | 2 | 1.000000 | 1.000000 | 0.428571 | 0.666667 |
| key_path | full | node | s07-h-x-path | s07_t00-p0005=0.750000 | 1 | 2 | 1.500000 | 0.666667 | 0.285714 |  |
| key_path | full | node | s07-h-y-path | s07_t00-p0006=0.631579 | 1 | 2 | 1.500000 | 0.666667 | 0.285714 |  |
| trial | full | node | s07-h-x-path;s07-h-y-path |  | 1 | 2 | 1.000000 | 1.000000 | 0.428571 | 0.666667 |
| key_path | b1 | hop | s07-h-x-path | s07_t00-p0005=1.000000 | 1 | 2 | 1.500000 | 0.666667 | 0.285714 |  |
| key_path | b1 | hop | s07-h-y-path | s07_t00-p0006=1.000000 | 1 | 2 | 1.500000 | 0.666667 | 0.285714 |  |
| trial | b1 | hop | s07-h-x-path;s07-h-y-path |  | 1 | 2 | 1.000000 | 1.000000 | 0.428571 | 0.500000 |
| key_path | b1 | node | s07-h-x-path | s07_t00-p0005=0.750000 | 1 | 2 | 1.500000 | 0.666667 | 0.285714 |  |

### `out/evaluate/s04_t00/rank.csv` (6 rows)

| variant | match_reading | first_rank | tie_size | rank_expected | top1_expected | chance_top1 | chance_pos_top1 | score_gap | full_recall | b0_recall |
|---|---|---|---|---|---|---|---|---|---|---|
| full | hop | 1 | 2 | 1.500000 | 0.500000 | 0.200000 | 0.500000 | 0.000000 |  |  |
| full | node | 1 | 2 | 1.500000 | 0.500000 | 0.200000 | 0.500000 | 0.000000 |  |  |
| b1 | hop | 1 | 2 | 1.500000 | 0.500000 | 0.200000 | 0.500000 | 0.000000 |  |  |
| b1 | node | 1 | 2 | 1.500000 | 0.500000 | 0.200000 | 0.500000 | 0.000000 |  |  |
| b2 | hop | 1 | 2 | 1.500000 | 0.500000 | 0.200000 | 0.500000 | 0.000000 |  |  |
| b2 | node | 1 | 2 | 1.500000 | 0.500000 | 0.200000 | 0.500000 | 0.000000 |  |  |
