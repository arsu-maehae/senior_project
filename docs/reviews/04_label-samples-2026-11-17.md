# T8 hand-check samples (s05_t00, development), 2026-11-17

Ten rows per output, so the owner can check them by hand against the DB and the key. Uids are shortened to 8 characters, and only selected columns are shown. No output file holds command text.

What to check: each event_labels row is the named event kind on that host and matches the rule (open the event by its uid); node rows give the same rule and level as event_labels; `dump_labelled` has one flag per dump uid, in order (decision 058); in recall rows, target 4624 and background rows are never scored (decision 060).

### `out/label/s05_t00/event_labels.csv` (21 rows; every 2th shown)

| event_uid | host | channel | event_id | event_utc_corrected | rule_id | technique | level | count_key |
|---|---|---|---|---|---|---|---|---|
| ad1d872f… | ep-01 | Sysmon | 10 | 2026-10-12T07:09:42.433000Z | SR-01 | T1003.001 | high | ad1d872f… |
| e4d78c4c… | ep-01 | Sysmon | 10 | 2026-10-12T07:09:42.450000Z | SR-02 | T1003.001 | medium | e4d78c4c… |
| d54b5b7e… | ep-02 | Security | 5145 | 2026-10-12T07:10:45.102370Z | SR-20 | T1570 | low | d54b5b7e… |
| fb21a51a… | ep-02 | System | 7045 | 2026-10-12T07:10:45.231891Z | SR-30 | T1569.002 | low | 1ca63b4f… |
| d6b495b6… | ep-02 | Sysmon | 10 | 2026-10-12T07:11:47.032000Z | SR-01 | T1003.001 | high | d6b495b6… |
| 1f9214b8… | ep-02 | Sysmon | 10 | 2026-10-12T07:11:47.054000Z | SR-02 | T1003.001 | medium | 1f9214b8… |
| f4dbd3ab… | ep-02 | Sysmon | 3 | 2026-10-12T07:12:43.634000Z | SR-41 | T1021.006 | high | f4dbd3ab… |
| 8505d54f… | ep-03 | Security | 4688 | 2026-10-12T07:12:43.681396Z | SR-40 | T1021.006 | medium | 7828fece… |
| 1780d970… | ep-02 | Sysmon | 3 | 2026-10-12T07:12:44.497000Z | SR-41 | T1021.006 | high | 1780d970… |
| 65a30831… | ep-02 | Sysmon | 3 | 2026-10-12T07:12:44.907000Z | SR-41 | T1021.006 | high | 65a30831… |

### `out/label/s05_t00/node_labels.csv` (23 rows after filter; every 2th shown)

| path_id | hop_id | role | context | host | event_uid | labelled | rule_ids | techniques | max_level_value |
|---|---|---|---|---|---|---|---|---|---|
| s05_t00-p0004 | s05_t00-h0030 | source_session_event | 1 | ep-01 | ad1d872f… | 1 | SR-01 | T1003.001 | 3 |
| s05_t00-p0004 | s05_t00-h0030 | artefact | 0 | ep-02 | 5abbaf5a… | 1 | SR-10 | T1021.002 | 1 |
| s05_t00-p0004 | s05_t00-h0030 | artefact | 0 | ep-02 | 865e6313… | 1 | SR-20 | T1570 | 1 |
| s05_t00-p0004 | s05_t00-h0030 | artefact | 0 | ep-02 | 1ca63b4f… | 1 | SR-31 | T1569.002 | 1 |
| s05_t00-p0004 | s05_t00-h0032 | source_session_event | 1 | ep-02 | 1f9214b8… | 1 | SR-01;SR-02 | T1003.001 | 3 |
| s05_t00-p0004 | s05_t00-h0032 | source_evidence | 0 | ep-02 | f4dbd3ab… | 1 | SR-41 | T1021.006 | 3 |
| s05_t00-p0004 | s05_t00-h0032 | artefact | 0 | ep-03 | 7828fece… | 1 | SR-40 | T1021.006 | 2 |
| s05_t00-p0004 | s05_t00-h0032 | target_session_event | 1 | ep-03 | 8505d54f… | 1 | SR-40 | T1021.006 | 2 |
| s05_t00-p0004 | s05_t00-h0032 | source_evidence | 0 | ep-02 | 1780d970… | 1 | SR-41 | T1021.006 | 3 |
| s05_t00-p0004 | s05_t00-h0032 | source_evidence | 0 | ep-02 | 0ceafe7c… | 1 | SR-60 | T1078 | 2 |

### `out/label/s05_t00/hop_labels.csv` (23 rows after filter; every 2th shown)

| hop_id | in_path | n_node_events | n_labelled_node_events | n_labelled_context0_node_events | techniques | dump_labelled | dump_rule_ids |
|---|---|---|---|---|---|---|---|
| s05_t00-h0007 | 0 | 0 | 0 | 0 |  | 0;0;0;0 |  |
| s05_t00-h0009 | 0 | 0 | 0 | 0 |  | 0;0;1;1;0;0;0 | SR-01;SR-02 |
| s05_t00-h0018 | 0 | 0 | 0 | 0 |  | 0;0;1;1;0;0;0 | SR-01;SR-02 |
| s05_t00-h0020 | 0 | 0 | 0 | 0 |  | 0;0;0;0 |  |
| s05_t00-h0022 | 0 | 0 | 0 | 0 |  | 0;0;0;0 |  |
| s05_t00-h0024 | 0 | 0 | 0 | 0 |  | 0;0;1;1;0;0;0 | SR-01;SR-02 |
| s05_t00-h0028 | 0 | 0 | 0 | 0 |  | 1;1;0;0 | SR-01;SR-02 |
| s05_t00-h0030 | 1 | 39 | 7 | 5 | T1021.002;T1569.002;T1570 | 0;0;1;1;0;0;0 | SR-01;SR-02 |
| s05_t00-h0033 | 0 | 0 | 0 | 0 |  | 0;0;1;1;0;0;0 | SR-01;SR-02 |
| s05_t00-h0037 | 0 | 0 | 0 | 0 |  | 0;0;0;0 |  |

### `out/evaluate/s05_t00/label_recall.csv` (30 rows; every 3th shown)

| trial_id | hop_or_step_id | kind | event_uid | expected_technique | labelled | labelled_expected | rule_ids | role | scored | match_method | label_techniques |
|---|---|---|---|---|---|---|---|---|---|---|---|
| s05_t00 | s05-dump1 | lsass_dump | ad1d872f… | T1003.001 | 1 | 1 | SR-01 | step | 1 | uid | T1003.001 |
| s05_t00 | s05-dump2 | lsass_dump | d6b495b6… | T1003.001 | 1 | 1 | SR-01 | step | 1 | uid | T1003.001 |
| s05_t00 | s05-h1 | smb_share | 5abbaf5a… | T1021.002 | 1 | 1 | SR-10 | attack | 1 | uid | T1021.002 |
| s05_t00 | s05-h1 | smb_copy | 2418cb3a… | T1570 | 0 | 0 |  | attack | 1 | none |  |
| s05_t00 | s05-h1 | service_install | 1ca63b4f… | T1569.002 | 1 | 1 | SR-31 | attack | 1 | uid | T1569.002 |
| s05_t00 | s05-h1 | target_4624 | 617e1298… | none | 0 |  |  | attack | 0 | none |  |
| s05_t00 | s05-h2 | winrm_process | 8505d54f… | T1021.006 | 1 | 1 | SR-40 | attack | 1 | uid | T1021.006;T1059.001 |
| s05_t00 | s05-h2 | winrm_source_conn | f4dbd3ab… | T1021.006 | 1 | 1 | SR-41 | attack | 1 | uid | T1021.006;T1059.001 |
| s05_t00 | s05-h2 | target_4624 | b6d66d2e… | none | 0 |  |  | attack | 0 | none |  |
| s05_t00 | s05-t1 | smb_share | 29c8d081… | T1021.002 | 0 | 0 |  | background | 0 | none |  |

