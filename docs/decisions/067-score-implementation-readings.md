# 067 — Score stage implementation readings (T9.1–9.4)

**Date:** 2026-11-18 · **Status:** accepted (coordinator); **item 4 amended by 069 item 1** (hop_chain only across a real chain edge) · **Task:**
T9.1–9.4 · **Relates to:** spec [05_score](../specs/05_score.md) SC-02, SC-10, SC-21, SC-21b, SC-22a, SC-53, SC-54;
[062](062-score-order-reference-and-sequence.md), [064](064-score-identity-readings.md), [058](058-label-implementation-readings.md)

## Context
Building `src/score` needed readings where the approved spec leaves a detail open. None changes a development value
except as stated; all are local to `src/score`.

## Options considered
| Point | Options | Evidence |
|---|---|---|
| Order-table pin | hash raw bytes / hash with CRLF→LF (as the label rules) | spec 04 LB-13 |
| Stage of a technique | first position in a given template / smallest position in any template | spec example T1021.002>T1570>T1569.002 |
| Sibling hops in a merged path (no chain edge between them) | `hop_chain` / score against templates | s05_t00-p0004: h0010 has no label, no effect |

## Decision
1. **Order-table pin:** SHA-256 over the file with CRLF turned into LF (`6bfae08b869178c618cef9b42b341eb9c78441ef2aeeb4cf9aeaaf2cfa07d61e`);
   `.gitattributes` keeps it LF.
2. **Stage of a technique** = its smallest 0-based position in any template; techniques in no template sort after,
   by ID.
3. **Tactic-PT** (062 item 3): IA>CA>LM>EX plus CA>LM>EX after filtering consecutive repeats; so LM→EX = b and
   IA→LM = 0.5b. `basis`: a technique in no template is `absent` first; `indirect` = a technique-PT path exists.
4. **Hop order and boundaries (SC-21b):** hops are put in a topological order of `path_edges`, ties by
   (`first_utc_corrected`, `hop_id`); **every** step between two different hops is `hop_chain`, including sibling hops
   of a merged path that have no chain edge between them. The given order of the hop list cannot change a score.
5. **Clock flag (SC-54):** a rejecting read = a counted read with an open session but `order_ok` = 0. A crossing is
   flagged if any applicable account has `order_within_uncertainty` = 1 on a deciding or rejecting read.
6. **Status (SC-53):** `unknown:end_unknown_session` when a counted read has `order_ok` = 1 but only `end_unknown`
   sessions.
7. **Freshness (SC-02):** three checks — the label run's `stitch_files_sha256` equals the current stitch files; the
   stitch CSVs read equal the stitch `run_info` hashes; the label CSVs read equal the label `run_info` hashes. Also
   refused: a labelled node with no `event_labels.csv` row, one uid with two `count_key`s, a path hop missing from
   `hops.csv` or `hop_identity.csv`.
8. **b0 window:** `event_labels.csv` is already clipped to the trial window (spec 04 LB-01), so b0 clips nothing more.
9. **`hop_identity_values.csv`** covers every hop in `hop_identity.csv`, not only hops on a path.

## Consequences
- On development data: 53 paths ranked per variant; identity 15/15; two runs byte-identical; s04 track A and B tie
  at rank 1 (0.666667); the s06 benign WinRM path scores 0.277778 (`full`).

## Kill criteria
- The stage review finds a development value that depends on a reading above in a way the spec forbids (e.g. hop-list
  order changes a score) → fix by a new record.

## Committee answer
**EN:** Where the specification left a detail open, we wrote down how the code reads it, for example how hops are
ordered in a merged path and how the order table's hash is taken. None of these readings changes a development result
except as stated.
**TH:** ในจุดที่ข้อกำหนดยังไม่ระบุรายละเอียด เราบันทึกไว้ว่าโค้ดตีความอย่างไร เช่น การเรียงฮอปในเส้นทางที่ถูกรวม และวิธีคำนวณแฮชของ
ตารางลำดับ การตีความเหล่านี้ไม่เปลี่ยนผลบนข้อมูลพัฒนา ยกเว้นที่ระบุไว้
