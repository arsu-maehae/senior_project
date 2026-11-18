# 069 — Score stage review fixes (T9.6)

**Date:** 2026-11-18 · **Status:** accepted (coordinator under spec 05 and decisions 064, 065, 067, 068; items marked
"owner" await the T9 report) · **Task:** T9.6 · **Relates to:** review [05_score-2026-11-18](../reviews/05_score-2026-11-18.md);
amends [067](067-score-implementation-readings.md) item 4; [065](065-score-baselines-and-success-criteria.md),
[068](068-rank-check-readings.md)

## Context
The stage review found no blocking item (data-checker 7/7 MATCH, fact-checker none). The attacker found implementation
cases where a score or a development metric could move for a reason the spec does not intend.

## Options considered
| ID | Options | Evidence |
|---|---|---|
| ATK-SC-17 | sibling hops `hop_chain` (067 item 4) / scored against templates | a merged path gains a 1.0 step and length for no chain evidence; no development value depends on it (s05 h0010 has no technique) |
| ATK-SC-24 | write 6 decimals / 12 decimals | evaluate and the sweep read the written values; ties at 12 |
| ATK-SC-14, -15, -21 | change 065 readings / report beside | 065 is owner-set |

## Decision
1. **ATK-SC-17:** `hop_chain` only across a real `path_edges` chain edge; a boundary between sibling hops (no chain
   edge) is scored against the templates. 067 item 4 is amended accordingly.
2. **ATK-SC-19:** `identity_low` / `identity_high` per account (robust = value 1 and not flagged; possible = value 1 or
   flagged); hop low = any robust, hop high = any possible.
3. **ATK-SC-20:** refuse a path hop whose `member_accounts` lacks a `hop_identity.csv` row.
4. **ATK-SC-24:** score and component columns written with 12 decimals.
5. **ATK-SC-06:** `n_hops_unknown` in `ranked_paths.csv`.
6. **ATK-SC-18:** `evaluate --rank` refuses a score run whose label hashes, order-table hash or parameters differ from
   the current files / the frozen values (copy pinned in `src/evaluate/params.py`, test-pinned to 066).
7. **ATK-SC-16:** the node-level match also requires one of the key path's target-logon uids (ST-05 copies
   normalised).
8. **ATK-SC-25:** refuse when one of the six keyed development trials has no approved key.
9. **Reported beside, primary unchanged (owner):** H4 recall on labelled nodes only (ATK-SC-14); per-key MRR
   (ATK-SC-15); chance line over candidates with score > 0 and E[1/rank] (ATK-SC-21). The sweep is described as "not
   informative on development data" (ATK-SC-22).
10. Wording fixes FC-2..8 (spec §5.1, 062, SC-61, 068 item 6, report wording, docstrings).

## Consequences
- Rerun on the 9 development trials: every score, rank, step and identity value equals the old run to 6 decimals
  (identity 15/15); s05_t00-p0004 0.655916132479 (its sibling h0010 has no technique, so no step crosses the sibling
  boundary); ATK-SC-20 refused nothing; `n_hops_unknown` > 0 on 30 of 53 paths (machine-account hops).
- Reported beside (hop reading, `full`, development): per-key MRR 0.833; E[1/rank] 0.950; **the chance line over
  candidates with score > 0 is 0.900 / 0.933, equal to the observed top-1 / MRR**: in 4 of 5 attack trials the key
  attack paths are the only paths with a nonzero score (s07: x and y), so on development data the ranking among scored paths adds
  nothing over chance; the separation comes from which paths get any score at all (labels and exposure).
- Readings: the node-match anchor = the key's `target_event_uids` that are 4624 members of a stitch hop; an account
  with only `end_unknown` sessions is applicable (its hop is not "unknown"); `order_tol_s` is a stitch fact, not a
  score parameter, so it is not in the frozen set; ST-05 copies also resolved in the H4 node sets and b0 rows (no
  copies on development data); `report.md` prints 12 decimals.

## Kill criteria
- After the fixes, any development score, rank or identity value changes without a stated reason → stop and report.

## Committee answer
**EN:** Reviewers tried to break the scoring. We fixed every case where a score or a check could move for a reason the
method does not intend, such as merged paths earning an order bonus without evidence, and we report the stricter
readings of two success checks beside the ones fixed in advance.
**TH:** ผู้ตรวจพยายามหาจุดที่ทำให้การให้คะแนนผิด เราแก้ทุกกรณีที่คะแนนหรือการตรวจอาจเปลี่ยนด้วยเหตุผลที่วิธีการไม่ได้ตั้งใจ เช่น เส้นทางที่ถูกรวม
ได้คะแนนลำดับเพิ่มโดยไม่มีหลักฐาน และเรารายงานการอ่านที่เข้มกว่าของเกณฑ์ความสำเร็จสองข้อคู่กับเกณฑ์ที่กำหนดไว้ล่วงหน้า
