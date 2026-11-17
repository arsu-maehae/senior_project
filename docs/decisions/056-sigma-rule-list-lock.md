# 056 — Sigma rule list locked for T8 (14 rules), own Sigma-subset matcher, owner answers to spec 04 Q1–Q14

**Date:** 2026-11-17 · **Status:** accepted (owner, 2026-11-17) · **Task:** T8.1 · **Relates to:** spec [04_label](../specs/04_label.md), review [04_label-spec-2026-11-17](../reviews/04_label-spec-2026-11-17.md), Correction G, Correction K, [013](013-council-correction-i-amended.md), [019](019-dev-test-split.md), [045](045-tier-rule-scope.md), spec 03 Q9

## Context
PLAN 8.1 asks for a locked rule list (technique, rule, source, level) before testing, and handoff §24 item 6 says the
same. Spec 04 §3.1 chose 15 candidates from SigmaHQ commit `54967d64e6dda2b4daa81f47f7a8bf1f591b68a0` and the handoff,
and the list was committed before any rule ran on a trial (`2628082`). Measurement on the nine development trials
(spec 04 §10) found three rules that could never match because of how the fields are stored:
- SR-10: 0 matches in 9 of 9 trials, because `ShareName` is logged as `\\*\ADMIN$`, so no T1021.002 label exists at
  all;
- SR-42: 0 matches, because ContextInfo has a newline after the value where the rule expects a space (170 of 170 rows);
- SR-31: 459 matches, 451 of them per-user service instances (`ServiceType` 0xd0 / 0xe0, 924 rows in the six keyed
  DBs); the real installs are 0x10.

All 14 key LSASS dumps are labelled, but only on `context` = 1 nodes. Measured on `context` = 0 nodes, SMB attack hops
average level 1.00 and benign WinRM hops 2.00–2.33 (§10.7).

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. Lock §3.1 exactly as written | no development-set choice | T1021.002 never labelled; SR-42 dead; B0 counts 451 per-user services | §10.4 |
| B. §3.1 + P1 (adapted SR-10), P2 (drop SR-42), P3′ (SR-31 service-kind filter) (**chosen**) | fixes format errors, not detection logic; every change has its numbers in §3.2 | three development-set choices, stated as such | §3.2; review DC-3, ATK-L05 |
| C. pySigma as the matcher | maintained library | new dependency, its own field pipelines, harder to explain function by function | spec 04 Q4 |
| D. Own Sigma-subset matcher over standard Sigma YAML (**chosen**) | no dependency; every function explainable; rule files stay portable Sigma | the subset must be tested (LBT-04) | spec 04 LB-04, LB-05 |
| E. Count the dump in NodeScore (Q1 a/b) | credential access visible in the path's levels | "exposed ≠ stolen" moves into NodeScore and counts twice with w3 | review ATK-L07 |
| F. Identity uses only labelled R1 rows (first Q2 proposal) | drops AV / system LSASS reads | couples the locked identity value to label coverage; one dump technique in the lab | review ATK-L01, ATK-L02 |

## Decision
Option B with matcher D:
1. **List.** SR-01, SR-02, SR-03, SR-10, SR-11, SR-12, SR-20, SR-30, SR-31, SR-40, SR-41, SR-50, SR-60, SR-61, with the
   §3.1 levels.
2. **SR-10 adapted.** SR-10 is an **adapted SigmaHQ rule** (field-format fix only): `ShareName|endswith: '\ADMIN$'`,
   with a new id and `related: 098d7118-55bc-4912-a836-dc6483a8d150, type: derived`.
3. **SR-42 dropped.**
4. **SR-31 filter.** SR-31 excludes `ServiceType` 0xd0 / 0xe0.
5. **Own rules** stay `low`.
6. **Matcher.** The matcher is our own Sigma subset (LB-04, LB-05, LB-12); rule files are standard Sigma YAML with the
   DRL 1.1 attribution of spec 04 §3.3.
7. **The dump** counts only through IdentityCoherence. `context` = 1 nodes stay out of NodeScore. `hop_labels.csv`
   reports dump labels as facts only.
8. **Identity input** stays the gate's `R1_lsass` rows. Any exclusion is decided in the T9 spec.
9. **Q13** (level asymmetry) is deferred to the T9 spec as its first question.
10. **Q14.** The measurement scripts are committed in 8.2.
11. **The other questions** take the spec's proposed answers:
    - Q3: T1059.001 and T1078 only as second tags;
    - Q8: no tier columns on label rows (045 scope);
    - Q9: Discovery out of scope;
    - Q10: the order table is decided in the T9 spec.

**Freeze.** Rule files are pinned by SHA-256 in `manifest.csv` (LB-10). Any later change needs a new record. No rule
is added, dropped or changed by looking at test-trial counts, and a rule that never matches stays in the list.

## Consequences
- T8.2 can be built: 14 rule files, a manifest, the matcher, and the outputs of spec 04 §3.4.
- T1021.002 is labelled on ADMIN$ share access, but `IPC$` and plain logons stay unlabelled (L-LB3).
- SR-03, SR-11, SR-12, SR-50 and SR-61 match nothing in the development data. They are kept as locked (L-LB4); RDP is
  untested (L-LB2).
- T1003.001 coverage rests on one dump technique (L-LB1). It does not affect identity, because labels never filter
  identity.
- Leaving `context` = 1 out of NodeScore means no path's NodeScore reflects the dump, and s04 track A and track B
  look alike on `context` = 0 nodes. Telling them apart is the identity term's job, as Correction K intends.

## Kill criteria
- On the development data after 8.2, a key LSASS dump is not labelled T1003.001, or a key attack hop has no
  labelled `context` = 0 node (LBA-02, LBA-03). Then the list is reopened by a new record, on development data only.
- LBT-10 shows another rule literal that no stored value can match. That rule is reported. It is fixed by a new
  record only if the fix is a field format, like P1.

## Committee answer
**EN:** We took detection rules from the public SigmaHQ set and fixed the list before running it on any trial. We
then changed only what failed because of how Windows stores a field, and wrote down each change with its numbers.
Rule severity feeds the node score, but a credential dump only counts through the identity term, so an exposed
account is never scored as a stolen one twice.
**TH:** เราเลือกกฎตรวจจับจากชุด SigmaHQ ที่เปิดเผยต่อสาธารณะ และล็อกรายการไว้ก่อนนำไปรันกับข้อมูลทดลองใด ๆ หลังจากนั้นแก้เฉพาะกฎที่ไม่ทำงานเพราะรูปแบบการบันทึกฟิลด์ของ Windows และบันทึกทุกการแก้พร้อมตัวเลข ระดับความรุนแรงของกฎใช้คำนวณคะแนนโหนด แต่การดัมพ์รหัสผ่านนับผ่านค่าความสอดคล้องของตัวตนเท่านั้น บัญชีที่ถูกเปิดเผยจึงไม่ถูกนับซ้ำเหมือนถูกขโมย
