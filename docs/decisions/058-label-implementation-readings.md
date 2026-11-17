# 058 — Label stage: implementation readings where spec 04 is silent

**Date:** 2026-11-17 · **Status:** accepted (T8.2c, within the approved spec) · **Task:** T8.2 · **Relates to:** [056](056-sigma-rule-list-lock.md), [057](057-pyyaml-for-sigma-rules.md), spec [04_label](../specs/04_label.md) LB-03, LB-08, LB-10, LB-11, §3.4

## Context
Building `src/label` left eleven points that spec 04 does not settle. None of them changes a rule, a level or which
events are labelled. Evidence comes from the 9 development trials: two `--development` runs give byte-identical outputs
apart from `run_info.json`, the DB hashes are unchanged, and the per-rule counts match §10.4 and the node counts
match §10.2.

## Options considered
| Point | Chosen reading | Alternative | Why |
|---|---|---|---|
| 1 `dump_labelled` with several dump reads | one value per uid in `dump_event_uids`, same order (corrected time, then uid) | a single hop-level value | every development hop with dump reads has several, and one value would hide which read is labelled |
| 2 `techniques` in node / hop rows | primary technique per rule only (as §10.6); all tags stay in `event_labels.csv` | every tag | keeps node rows comparable with the §10.6 table |
| 3 LB-03 near-duplicate groups | built among in-window rows only | whole DB | an out-of-window uid must never appear in an output (LB-01); 0 groups in development |
| 4 extra DB columns | `process_id`, `service_name` are read | – | LB-11 pairing needs them; they are not command text |
| 5 LB-11 pairing set | all in-window events, labelled or not; 2 s (`StitchParams.process_collapse_s`), 5 s (`GateParams.service_pair_s`, GT-12) | labelled events only | the pair is a property of the events, not of the labels; reuses the stitch and gate tolerances |
| 6 a field stored as `[null]` | absent | the empty string | Sigma treats a missing field as no match |
| 7 SR-10 adapted | the rule file has its own id `2495f327-…` and `related: 098d7118… derived`. `manifest.csv` and the `sigma_id` of label rows keep the upstream `098d7118…` for attribution, and `report.md` says the rule is adapted | a manifest notes column | the §3.4 manifest columns stay as approved |
| 8 folder swap / JSON writers | imported from `stitch.__main__` | from `evaluate.writers` | `evaluate` reads answer keys; `src/label` must not import it |
| 9 rules folder | any file other than `*.yml` and `manifest.csv` is refused | ignored | LB-10 lock: nothing unlisted near the rules |
| 10 stitch file hashes | recorded in `run_info.json`, no refusal | refuse when they differ | the stitch outputs are re-run often; T9 checks the chain |
| 11 allowlist refusal text | the shared stitch text ("the stitcher runs on …") | a label-specific text | reuses `stitch.inputs.check_allowlist`; cosmetic |

**SR-31 count.** SR-31 matches 9 events (1,0,2,1,1,2,1,0,1), and 8 of them are path nodes. The ninth is a
`PktDropService` 4697 with ServiceType `0x10` under the machine account `ENDPOINT-02$` in s02_t00. P3′ filters on
the service kind and not on the account, so it keeps this event on purpose (ATK-L05). The spec's "8 in total" counts the
user-account 4697s, which equal the 8 node rows, so there is no conflict.

## Decision
Adopt the readings in the table. They are coded in `src/label` and covered by the T8.2d tests.

## Consequences
- `hop_labels.csv` `dump_labelled` is a `;`-joined list, so T9 must read it per uid.
- T9 does not see secondary techniques at node level; it reads them from `event_labels.csv` if needed.
- A changed stitch output after labelling is not refused. Only `run_info.json` records it.

## Kill criteria
- T9 needs a single hop-level dump flag or secondary techniques at node level. In that case the output columns change,
  with a new record.
- A near-duplicate group crosses the window edge on test data. Then point 3 is revisited.

## Committee answer
**EN:** The spec fixed the rules and the outputs. These are small reading choices made while coding. Each keeps the
labels the same and is written down, so the owner can check it.
**TH:** สเปกกำหนดกฎและผลลัพธ์ไว้แล้ว ส่วนนี้เป็นการตีความเล็ก ๆ ตอนเขียนโค้ด ทุกข้อไม่เปลี่ยนผลการติดป้าย และบันทึกไว้ให้เจ้าของงานตรวจได้
