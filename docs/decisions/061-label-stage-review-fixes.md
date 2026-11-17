# 061 — Label stage review fixes: rule lock pinned in code, stale-input refusals, context-0 hop counts

**Date:** 2026-11-17 · **Status:** accepted (stage review T8.4) · **Task:** T8.4 · **Relates to:** [056](056-sigma-rule-list-lock.md), [058](058-label-implementation-readings.md) (replaces point 10), [059](059-sr20-share-literal-fix.md), [060](060-label-recall-readings.md), review [04_label-stage-2026-11-17](../reviews/04_label-stage-2026-11-17.md), spec [04_label](../specs/04_label.md) LB-10

## Context
The stage review found one blocking item. ATK-S01: the LB-10 lock only referred to itself. `manifest.csv` was checked
against hashes recomputed from the same files, and `--write-manifest` turned any rule edit into a passing run, so
"no change after the lock" could not be checked. The review also found four cheap non-blocking items. S03: hop
counts included `context` = 1 dump nodes. S04: the recall wording. S05: stale stitch, gate and clock inputs were
accepted silently. S06: evaluate kept files across trials without a check.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Pin each rule's SHA-256 and the manifest SHA-256 as literals in `src/label/params.py`, check them before loading, plus a test holding the same literals (**chosen**) | a rule change needs a code change, a new record and a test change; it shows in the git diff | three places to update on a legitimate change |
| B. Pin in a decision record only | one place | nothing enforces it |
| C. Git tag on the rules | standard | the tool cannot check a tag at run time |

## Decision
Option A, plus the S03–S06 fixes:
- **S01.** `RULE_SHA256` (14 files) and `MANIFEST_SHA256` are in `params.py`. `rules.check_pins` runs first and refuses a
  difference with "a rule change needs a new decision record and updated pins". Pins (LF SHA-256), after 059:

| Rule | SHA-256 | Rule | SHA-256 |
|---|---|---|---|
| SR-01 | e21fdafd9ae62edb6a1e56626098962446db0116b7d74c65390e2004f9b6eea1 | SR-30 | bb8fdfdf290358e91a0268f5a1df2b4d81c5189395df5c7a65a612edd5b87c04 |
| SR-02 | 685d4e6de0d8644006aea0a333d155f8053e8fd545a211003c608cc2a633a952 | SR-31 | 1358bda73b3fa08a6738afa1d44abb1d2dcbd52c1142b9c3ae693f4948dd348f |
| SR-03 | aa5a9efa0c5fe4e3b65d26433eb163293706c08bd14579161ca4eaf41dcd8729 | SR-40 | fc874778dd8be01110ead523c56b7892206daf981152fa40371f3a2b9741f1a1 |
| SR-10 | ea4c7616dc2668960a7f90be68bd14bac6f8918146bf3caa3c1f03989f027cb4 | SR-41 | d6e78042bab06777df640416fa2d62e6906f28fa155e09b115de1674cbcadc59 |
| SR-11 | 48965a503ddb84bd0f98b9215467e1ac5b83caaf40cda976b154e108efdec368 | SR-50 | 5a05e9aacee626c8a139c30bccb1ebba710c7514590e0874dc601ac8f2d9eb32 |
| SR-12 | 8b0320e5467b94d464f5212a363a72cebfdfb6ce3bfa36d2c43c8bc9b6ed3171 | SR-60 | abc7123f2e21d4bf6fc90711885f68478d253993b360897fa00d6a27c3a903bb |
| SR-20 | 570444935014e6040f59809e0ccd5932e149240dade4cca2fcabe3d36dca1532 | SR-61 | a60b80c34a90e086dc1a394b8bc2c252684d17fec99c37939f8a9f43a958f1b7 |

  `manifest.csv`: 3508a065dad556d0aad214470270dc4868759c4b023b3454febfb1d45288ee5e.
- **S03.** `hop_labels.csv` gains `n_labelled_context0_node_events` right after `n_labelled_node_events`. Hop `techniques`,
  `in_path_without_labelled_node`, and the new stats `with_labelled_context0_node` and
  `labelled_context0_node_events` use `context` = 0 nodes only, as in 056 item 7. As a result, T1003.001 leaves the
  hop techniques of 11 of 284 hops, and T1021.006 leaves those of 2 s06 hops.
- **S05.** This replaces 058 point 10. src/label refuses with exit 2 and writes nothing when:
  - the stitch run_info's `gate_stats_sha256`, offsets hash or clock-changes hash differs from the current files;
  - a stitch CSV (path_nodes, hops, hop_identity, hop_artefacts) differs from its run_info hash;
  - a required column is missing, or a row is ragged;
  - a `dump_utc_corrected` value is empty or cannot be parsed.
- **S04.** The recall is called rule coverage of key events in the code, the .md and decision 060.
- **S06.** A kept evaluate file must name only the trial being written (`trial_id`, checked before any write).
  `label_recall.csv` gains `label_run_sha256` as its last column. `--out` is checked before the no-key return.

Development effect: `event_labels` and `node_labels` are byte-identical. Recall is unchanged (46/69). Two runs are
byte-identical.

## Consequences
- A legitimate rule change, such as the next 059, must update the rule file, the manifest, `params.py`, the pin test and a
  new record. The git diff shows all five.
- Re-running the gate or clock stage forces a stitch and label re-run before evaluation.

## Kill criteria
- If a pin check refuses a run with no rule change (for example a line-ending change), the LF normalisation (LB-13) is
  wrong and must be fixed. The pins are not removed.

## Committee answer
**EN:** The reviewer showed that we could have quietly changed a rule after locking the list. Now each rule's
fingerprint is written into the code and a test, so any change is refused unless we write a new record. The tool
also refuses inputs that are out of date.
**TH:** ผู้ตรวจชี้ว่าเราอาจแก้กฎอย่างเงียบ ๆ หลังล็อกรายการได้ ตอนนี้ลายนิ้วมือ (SHA-256) ของกฎทุกไฟล์ถูกเขียนไว้ในโค้ดและในเทสต์ การแก้ใด ๆ จะถูกปฏิเสธจนกว่าจะมีบันทึกการตัดสินใจใหม่ และเครื่องมือยังปฏิเสธข้อมูลนำเข้าที่ล้าสมัยด้วย
