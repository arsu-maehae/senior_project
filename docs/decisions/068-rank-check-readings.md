# 068 — Development ranking check (`evaluate --rank`, `--rank-sweep`): readings

**Date:** 2026-11-18 · **Status:** accepted (coordinator; T10's spec 06 may restate them for the test run) ·
**Task:** T9.5 · **Relates to:** spec [05_score](../specs/05_score.md) SCA-06, §5.2, §7.3;
[065](065-score-baselines-and-success-criteria.md), [066](066-score-parameter-freeze.md), [051](051-link-accuracy-readings.md)
(evaluate never imports stitch); handoff §14.2

## Context
065 fixes the tie rule for one matching path in a tie group and the hypotheses H1–H5. Building the development check
needed readings for several matches in one group, the node set of a key path, the chance line and the b0 budget.

## Decision
1. **Node set of a key attack path** = union over its hops of `target_event_uids`, `agent_event_uids`,
   `agent_corroboration_4688_uids`, `port_join_event_uids`, `credential_logon_uids`; not `related_logon_uids`,
   `identity_basis` (the dump is `context` = 1) or `candidates`. `steps` add no uid on any development key. A
   candidate's node set = its `context` = 0 `path_nodes` uids. Both a hop-level and this node-level Jaccard (≥ 0.5)
   are reported; the node-level one is the handoff §14.2 reading.
2. **Several matches in one tie group** (m of t tied paths match): expected first-match rank r − 1 + (t + 1)/(m + 1),
   top-1 credit m/t (r = 1), pessimistic r + t − m; equals 065 when m = 1. s07 x and y share the top group → rank 1.
3. **Top-1 and MRR per trial** with the first candidate matching any key attack path (handoff §14.2), averaged over
   attack trials (5 on development; s06_t00 enters only the S06 check, s06_t01 is unkeyed).
4. **Chance line:** `chance_mrr` = 1/E[rank] (consistent with 065's 1/1.5); E[1/rank] reported as `chance_rr_mean`.
5. **b0 budget:** full's top-k nodes with ties at the cut by inclusion probability; b0 units in rank order, its tie
   group at the cut read at node level (each new node held with probability remaining budget / new nodes).
6. **Sweep** (hop-level reading only; review FC-7): the 0.1 weight grid lacks w = 1/3, so the default point is added; "stable" = no key attack path's
   expected rank changes; reported as counts and distance to the nearest unstable point. It never changes a value.

## Consequences (development numbers, not results)
- Expected reading: top-1 0.900, MRR 0.933 for `full`, `b1` and `b2` alike (chance 0.248 / 0.377); s04 B at 1.5.
  On development data the identity term changes no within-trial rank, so H3 (strict) would not hold here.
- S06 check: `full` +0.306 (held); `b1` −0.042, `b2` −0.333 (not held): the identity term separates across trials.
- b0 vs `full` at equal budget: 0.261 vs 0.877. Sweep: no key attack path's expected rank changes at any of the 402 points, which is **not informative** on development data (069, ATK-SC-22: in 4 of 5 attack trials every rival scores 0, s04 ties at every weight); S06 holds at 44–48 of 66 weight points
  per λ.

## Kill criteria
- The recomputed default score differs from the written `full` score beyond 1e-6, or two runs differ → invalid run.

## Committee answer
**EN:** On development data we count a tie by its expected place and report the chance level beside every number.
There the identity term does not change the order inside a trial, but it is what keeps the benign paths of the
no-attack scenario below every attack path. We report both, and fix nothing to the development numbers.
**TH:** บนข้อมูลพัฒนา เรานับกรณีเสมอด้วยตำแหน่งที่คาดหมาย และรายงานระดับโอกาสสุ่มคู่กับทุกตัวเลข ค่าความสอดคล้องของตัวตนไม่เปลี่ยน
ลำดับภายในการทดลองเดียวกัน แต่เป็นสิ่งที่ทำให้เส้นทางปกติในสถานการณ์ที่ไม่มีการโจมตีอยู่ต่ำกว่าเส้นทางโจมตีทุกเส้น เรารายงานทั้งสองอย่าง
และไม่ปรับค่าใดตามตัวเลขของข้อมูลพัฒนา
