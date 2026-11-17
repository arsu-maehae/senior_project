# 055 — T7.7 review: owner rulings on near-duplicate copies, `target_only_ok`, and the rule questions

**Date:** 2026-11-17 · **Status:** accepted (owner, 2026-11-17) · **Task:** T7.7 stage review ([review](../reviews/03_stitch-2026-11-17.md)) · **Amends:** spec 03 §3 (`hops.csv` `member_logon_uids`) and §9.1; 051 item 6 · **Relates to:** 050, 054

## Context
The attacker review of the built stitch stage found items that are not code bugs: the code follows the spec or a decision literally, and a change needs the owner. None of them occurs in the nine development trials.
- `near_duplicate_groups` = 0 in all nine `stats.json`.
- No background hop has an unresolved row.
- The rule questions describe shapes absent from the data (spec §6 and the review).

## Options considered
| Item | Options | Chosen (owner) |
|---|---|---|
| OQ-1 (ATK-24 b): ST-05 says "all uids are kept in the uid columns"; `hops.csv` wrote one representative uid per member, so a key naming the other copy of a target 4624 would not match (ST-25) | (a) copies in the member's item joined by `\|`; (b) a new column `member_copy_uids`; (c) leave and state it | **(a)**: keeps `member_logon_uids` parallel to `member_logon_ids`; no new column; outputs without copies are byte-identical |
| OQ-2: 051 item 6 gave `target_only_ok` = 1 only for a hop with exactly one row, the `target_only` row; a background hop with an unresolved port-join row (no session, not a candidate) scored 0 | (a) a `target_only` row and no candidate session; (b) keep 051 as written | **(a)**: unresolved rows name no session, so they are not candidates (ST-41, ST-49) |
| OQ-3: ATK-18 (no upper bound on `host_time` chaining), ATK-19 (untriggered hops seed nothing), ATK-20 (pre-window or erased 4624), ATK-22 (system-session-only evidence), ATK-25 (ST-26 can absorb a second movement) | (a) limitations, no rule change in T7; (b) change some rules now | **(a)**: spec §9.1 L-ST5..L-ST9; ATK-18 measured on the t01 reruns before any cap |

## Decision
1. `hops.csv` `member_logon_uids`: each member's item is its representative uid, then its ST-05 copies in uid order, joined by `|` (`stitch.outputs.member_uids_cell`). Evaluate's ST-25 match and `key_logons_in_hop` accept any uid of the item (`evaluate.keys.member_uid_set`), and report the key's own uid.
2. Evaluate: `target_only_ok` = 1 when the hop has a `target_only` row and no candidate session (`link_accuracy.has_only_target_only`).
3. No rule change for ATK-18, 19, 20, 22, 25. They are stated as limitations L-ST5..L-ST9 in spec 03 §9.1 and carried to T9 / T10.

## Consequences
- Development outputs are unchanged: no copies, no unresolved rows. The committed-equals-fresh tests guard this.
- A reader that splits `member_logon_uids` on `;` still gets one item per member and must split an item on `|` to see the copies.
- The five limitations are what a test trial or a new scenario may show. The T10 report states them.

## Kill criteria
- A t01 rerun or test trial shows a key path merged with unrelated seeds through `host_time` chaining (L-ST5) → council on a time cap or an account condition for chain edges.
- A key hop is unmatched because of L-ST9 or L-ST7 → revisit ST-26 or the window look-back for links.

## Committee answer
**EN:** The review found five rule gaps that our development data never triggers. We stated them as limitations instead of changing rules we cannot test. Two small output readings were fixed so that duplicate copies of a logon and processes we could not resolve cannot distort the evaluation.
**TH:** การรีวิวพบช่องว่างของกฎห้าข้อที่ข้อมูลชุดพัฒนาไม่เคยกระตุ้น เราจึงระบุไว้เป็นข้อจำกัดแทนการแก้กฎที่ทดสอบไม่ได้ และแก้การตีความผลลัพธ์เล็กน้อยสองจุด เพื่อไม่ให้สำเนาซ้ำของ logon และ process ที่หาเจ้าของไม่ได้ทำให้การประเมินผิดเพี้ยน
