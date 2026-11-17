# 059 — SR-20 share literals anchored on the backslash (field-format fix)

**Date:** 2026-11-17 · **Status:** accepted (a field-format fix of the same kind as 056 P1; 056's freeze requires this new record) · **Task:** T8.3 / T8.4 · **Relates to:** [056](056-sigma-rule-list-lock.md) (P1), spec [04_label](../specs/04_label.md) §3.1 SR-20, LBT-02, LBT-10

## Context
SR-20 (own rule, T1570) selects `ShareName|endswith: 'ADMIN$'` or `'C$'`. The ShareName is stored as `\\*\<share>`
(spec 04 §10.3, P1), and `IPC$` also ends in `C$`. A new test written for T8.2d (`test_label_rules.py`) caught this.
Measured on the 9 development trials: all 16 SR-20 matches are on `ADMIN$`, no 5145 is on `C$`, and 218 5145 rows are
on `IPC$`. Today none of the `IPC$` rows also meets the extension and WriteData conditions, so no label is wrong yet,
but the rule does not say what spec 04 §3.1 means ("ADMIN$ or C$").

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. `endswith: '\ADMIN$'` / `'\C$'` (**chosen**) | states §3.1 exactly; the same format as the P1 fix of SR-10; 0 development labels change | a changed locked file, so it needs this record | 16/16 on ADMIN$; 0 C$ |
| B. Leave it; the other conditions block IPC$ | no change | the rule text means something other than the spec; an exe-named IPC$ write would be labelled T1570 | 218 IPC$ 5145 |
| C. Drop the C$ item | simpler | §3.1 lists C$; the lab never used it | – |

## Decision
Option A. Only the two `ShareName` literals change. The rule id is kept, because it is our own rule and the meaning is
the §3.1 meaning. The manifest SHA-256 is rebuilt. This is not a development-set choice: the count stays 16 and the
change follows the written spec.

## Consequences
- SR-20 counts and node rows are unchanged (16 events, 14 nodes).
- LBT-02 / the new rule test check that `\\*\IPC$` does not match SR-20.
- SR-11 (SigmaHQ b210394c, unchanged copy) has the same upstream `ShareName|endswith: 'C$'`, which also covers
  `IPC$`. It stays as written: it matches 0 events in development (spec 04 §10.4), and changing a SigmaHQ rule
  with no measured need would be a development-set choice. The test suite records this as a characterisation. If
  SR-11 ever matches an `IPC$` row on development data, it is reported, and any fix needs a new record (056 freeze).
  056 kill criterion 2 covers literals that match nothing. It does not cover over-matching like this.

## Kill criteria
- Any SR-20 count changes after the fix on development data. That would show the literal mattered, and the change is
  then reviewed again.

## Committee answer
**EN:** The rule meant "the ADMIN$ or C$ share", but "IPC$" also ends in "C$". We anchored the names on the
backslash, as we had already done for SR-10. No label changed.
**TH:** กฎนี้ตั้งใจจับเฉพาะแชร์ ADMIN$ หรือ C$ แต่ชื่อ "IPC$" ก็ลงท้ายด้วย "C$" เช่นกัน เราจึงให้ชื่อแชร์เริ่มต้นด้วยเครื่องหมายแบ็กสแลช แบบเดียวกับที่แก้ SR-10 ไปแล้ว ไม่มีป้ายใดเปลี่ยน
