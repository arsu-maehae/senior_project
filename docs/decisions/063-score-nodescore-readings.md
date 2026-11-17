# 063 — NodeScore readings: context-0 nodes, one unit per action, empty path 0, protocol asymmetry accepted

**Date:** 2026-11-18 · **Status:** accepted (owner, 2026-11-18) · **Task:** T9.2 · **Relates to:** spec
[05_score](../specs/05_score.md) SC-30..33, Q1, Q2, Q14; [056](056-sigma-rule-list-lock.md) items 5, 7, Q13;
[058](058-label-implementation-readings.md) (`count_key`); Correction G.1; review ATK-SC-03, ATK-S10

## Context
CLAUDE.md locks NodeScore = mean Sigma level of labelled nodes, /4 (Correction G.1). 056 item 7 keeps `context` = 1
nodes (session context, where the dump lands) out of NodeScore. One action logged twice (Sysmon 1 + 4688, 4697 +
7045) would count twice without `count_key`. Measured (§10.2, data-checker): SMB hops 1.00, WinRM hops 2.00–2.43,
attack or benign; 38 of 53 paths have no labelled unit.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| Q1 (a) accept the protocol asymmetry, state it (**chosen**) | no development-set tuning of levels | NodeScore orders protocols | §10.2 |
| Q1 (b) own rules medium | SMB 1.50–1.75 | still below WinRM; a development choice | §10.2 table |
| Q1 (c) one unit per technique per hop | fewer repeat units | SMB 1.00, WinRM 2.00–2.50: no change in order | §10.2 table |
| Q2 empty path → 0 (**chosen**) vs term dropped | all scores on one scale | — / incomparable scores | 38 of 53 |
| Q14 (a) keep 056 item 7, report `node_score_ctx1` (**chosen**) vs (b) council to count `context` = 1 | no double count with identity | the dump never raises NodeScore | ATK-SC-03 |

## Decision
NodeScore = mean over the path's **`count_key` units** of labelled `context` = 0 nodes, each unit at its highest
`level_value`, divided by 4; a path with no unit scores 0 with `n_node_units` = 0. Leaving `context` = 1 nodes out is
a **reading of which nodes belong to the path** (ST-71 marks them as session context), not a change to the locked
formula; because its effect is to keep the dump out, NodeScore with `context` = 1 included is written beside it
(`node_score_ctx1`, never in the score). The protocol asymmetry is accepted and stated: separating attack from benign
inside one protocol is the identity term's job (Correction K).

## Consequences
- NodeScore ranks WinRM paths above SMB paths regardless of role; `b2` (NodeScore only) shows the size of this.
- The report states NodeScore as protocol-sensitive (L-SC1).

## Kill criteria
- On development data, a path's NodeScore differs from the recomputation over `event_labels.csv` units (SCA-04).
- The stage review finds a labelled `context` = 0 action counted twice under one `count_key` rule gap → fix in the
  label stage by its own record.

## Committee answer
**EN:** NodeScore is the average severity of the Sigma rules that matched the path's own events, counting each action
once. A credential dump is counted only in the identity term, so it is never counted twice. NodeScore is higher for
WinRM than for SMB whatever the role; we state that and show it with an order-blind baseline.
**TH:** NodeScore คือค่าเฉลี่ยระดับความรุนแรงของกฎ Sigma ที่ตรงกับเหตุการณ์ของเส้นทางเอง โดยนับแต่ละการกระทำครั้งเดียว
การดัมพ์รหัสผ่านนับเฉพาะในค่าความสอดคล้องของตัวตน จึงไม่ถูกนับซ้ำ NodeScore ของ WinRM สูงกว่า SMB ไม่ว่าจะเป็นการโจมตีหรือไม่
เราระบุข้อนี้ไว้และแสดงด้วยเส้นฐานที่ไม่สนใจลำดับ
