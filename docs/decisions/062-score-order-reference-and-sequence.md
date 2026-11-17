# 062 — Order reference (hand-built templates) and the technique sequence of a path

**Date:** 2026-11-18 · **Status:** accepted (owner, 2026-11-18) · **Task:** T9.1 · **Relates to:** spec
[05_score](../specs/05_score.md) SC-10, SC-20..23, Q3–Q6; research [score_order_templates](../research/score_order_templates.md);
handoff §11.2–11.4, Correction G.3, G.5; TPPR Eq. 2–7 (pp. 6–7); [056](056-sigma-rule-list-lock.md) items 7, Q3, Q10

## Context
TPPR scores each edge of a candidate path against a pattern tree mined from CTI reports (ATT-SPT, §3.3.1) and does
not publish it. Our stitch paths carry no technique on their edges, and 52 of 53 development paths have one hop
(spec 05 §10.1). Labels exist only on path nodes; within one WinRM hop the 4648 (T1078) and `wsmprovhost` (T1021.006)
events alternate in time (s03_t01: 6 alternations). The dump may count only through identity (056 item 7).

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. CTI-mined tree (TPPR) | closest to TPPR | no time; mining pipeline is a project of its own | handoff §11.4 |
| B. Hand-built templates from ATT&CK / CTI pages (**chosen**) | small, cited per transition | hand-made; two links weakly supported | research doc |
| S1. Sequence per hop by template position, hops in chain order, first appearance (**chosen**) | no sub-second event order; mirrors ATT-SPT's "order of first appearance" | inside one hop it scores which techniques co-occur, not their order | §10.1 |
| S2. Strict event-time order of every unit | literal order | scores ms-level noise and repeats | s03_t01 |
| ScoreNI kept from the hop graph | full Eq. 5 | defined only on 1 of 53 paths | §10.1 |

## Decision
1. **Templates** (`src/score/order_table.json`, pinned by SHA-256): R1 T1078 → T1003.001 → T1021.002 → T1569.002;
   R2 T1078 → T1003.001 → T1021.001 (shortened: no source for T1021.001 → T1569.002); R3 T1003.001 → T1021.002 →
   T1570; R4 T1003.001 → T1021.002 → T1570 → T1569.002; R5 T1078 → T1003.001 → T1021.006. T1550.002 is in no template
   (no source joins it to the SMB move), so its transitions score ε. R5 and R1's first step are **weakly supported**
   (owner Q4, spec L-SC7).
2. **Tactics:** T1078 initial-access; T1003.001 credential-access; T1021.001/.002/.006, T1570, T1550.002
   lateral-movement; T1569.002 execution. The tactic tree is the templates mapped to tactics. Stage order for sorting
   comes from template positions, never from ATT&CK tactic IDs (Execution precedes Lateral Movement in the matrix, but
   PsExec runs its service after the move, S0029).
3. **Sequence (S1):** a hop's technique set = distinct primary techniques of its labelled `context` = 0 nodes, sorted
   by first template position then ID; hops in chain order; first appearance kept. A step from one chained hop to the
   next scores as direct (`hop_chain`), since the stitcher's chain edge already fixes that order.
4. **Edge score:** ScoreE = α·TacticScore (Eq. 2, capped at b) + β·TechniqueScore (Eq. 3), α + β = 1. ScoreNI (Eq. 4)
   is dropped: on a technique chain it encodes only position and length (0 for one edge, 1 at the ends, 2 inside),
   which LengthScore already carries. **Stated substitution:** Eq. 6/7 run over technique transitions, not provenance
   edges; len = number of transitions; fewer than two techniques → LengthScore 0.

## Consequences
- The order signal is explainable step by step (`path_steps.csv` gives `basis` per transition).
- Inside one protocol, attack and benign hops have the same technique set, so LengthScore cannot order them (L-SC1).
- The templates were proposed after the development sequences were seen (R4, R5); test trials stay unseen (L-SC7).

## Kill criteria
- The fact-checker finds a template transition whose cited source does not say it → that transition is removed by a
  new record before the freeze (066).
- On development data, `full` scores change when only the hop-list order of a path changes (SCT-21b fails).

## Committee answer
**EN:** TPPR's attack-pattern tree is not published, so we wrote five short attack templates from MITRE ATT&CK and
public incident reports, citing each step, and scored paths with TPPR's own tactic and technique formulas. We read a
path's techniques per hop and in hop order, so millisecond event order cannot change a score. Two templates are only
weakly supported, and we say so.
**TH:** ต้นไม้รูปแบบการโจมตีของ TPPR ไม่ได้เผยแพร่ เราจึงเขียนแม่แบบการโจมตีสั้น ๆ ห้าแบบจาก MITRE ATT&CK และรายงานเหตุการณ์สาธารณะ
โดยอ้างอิงทุกขั้น แล้วให้คะแนนเส้นทางด้วยสูตรระดับ tactic และ technique ของ TPPR เอง เราอ่านเทคนิคของเส้นทางทีละฮอปตามลำดับฮอป
ลำดับเหตุการณ์ระดับมิลลิวินาทีจึงไม่เปลี่ยนคะแนน มีแม่แบบสองแบบที่หลักฐานรองรับไม่หนักแน่น และเราระบุไว้ชัดเจน
