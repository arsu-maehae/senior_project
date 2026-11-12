# Attacker review — spec 08_clock_offset (draft), 2026-11-12

**Reviewer:** attacker agent (read-only; no t02–t10 data opened) · **Spec:** [08_clock_offset](../specs/08_clock_offset.md) · **Decision:** [043](../decisions/043-clock-offset-method.md) (proposed)

The attacker read the draft before decision 043 and this file existed. Both are written now.

| ID | Severity (attacker) | Finding | Where | Resolution in the spec |
|---|---|---|---|---|
| ATK-01 | blocking | ep-01's offset comes only from the start-of-trial burst. A later step or slew is invisible, and CO-10 covers one trial. | s06_t01; S04/S07 have no CO-10 pairs | **Partly adopted.** `late_gap_s`, `pair_span_s` reported (CO-16); start+end readings (CO-12); a `late_gap` limit goes to step 2 (Q11); COT-13 documents the limit. **Not adopted:** "≥ 2 clusters for `ok`", which would leave ep-01 uncorrected in all 11 measured trials. Evidence against a slew in s06_t01: check pairs 4 min later agree within 0.48 s with the −18.8 s cluster (§10.5). |
| ATK-02 | blocking | Pair deltas are unbounded; one far pair can move a host by minutes; hop logons measure their own hop | hypothetical; reuse outliers 360–400 s | **Adopted:** `MAX_PAIR_DELTA_S = 60` s, `n_dropped_far` (CO-02); 0 measured pairs dropped (max 18.83 s). Q4 gains option (c), "not applied when n ≤ 3". Hop logons are **kept and counted** (`n_pairs_lab_ip`, 0–2 per trial). They measure the target host's clock against dc01, not the source-to-target order. |
| ATK-03 | blocking | Offset uncertainty is not added to the 5 s order check; mixed corrected/raw rows are not marked | not in current data | **Adopted:** `offset_unc_ms`; row-level `clock_unreliable` (CO-09); proposal for T7, flag at 5 s + unc(src) + unc(dst) (§4.1 item 7); identity effect is OPEN Q12 (T7/T9, possibly council). |
| ATK-04 | should-fix | Step 2 on synced reruns (Q8a) cannot confirm parameters for skewed clocks | rerun plan | **Adopted** as text in Q8, plus option (c): one unsynced dev t01 per scenario. |
| ATK-05 | should-fix | Readings: when taken, sign convention, start/end disagreement | rerun plan | **Adopted** in CO-12: start + end on the endpoint vs dc01, stored host − dc01, one sign check, interval rule, drift flag > 2.5 s, rule for repeated readings. |
| ATK-06 | should-fix | The correction can worsen a small offset | s06_t00 (1.22 → 1.57 s) | **Adopted:** net effect per check group reported (§10.5: 5 of 6 improve), no "no harm" claim (CO-13), no-op band OPEN Q10. |
| ATK-07 | should-fix | CO-10 might choose its partner after correction; 5 s pass level; one skewed trial | design | **Adopted:** raw-time join ±60 s with ambiguity reported (CO-10); 2.5 s review level (kill stays 5 s per 032); "rests on one skewed trial" stated (CO-11). |
| ATK-08 | should-fix | Clock steps invisible; boot events are kept | all | **Adopted:** CO-15 `stale` on a boot after the host's last pair (none in the 11 trials, §10.7); Q6 (keep 4616 / Kernel-General 1) stays open for the owner. |
| ATK-09 | note | dc01 reference may step | s04_t00 `dc01_skew_possible` | dc01 status `reference` (unverified); CO-10 uses endpoint pairs only. |
| ATK-10 | note | Test-trial facts appear in edge cases | s02_t03/t04, s06_t04 | Statement in §5: edge cases only, no parameter derived; parameter freeze + COT-17. |
| ATK-11 | note | The corrected window moves edge clipping | gate | New 02_gate test listed (§4.1 item 8); GTA-06 on raw basis (Q7a). |
| ATK-12 | note | Sysmon-only host; retried 4769 | hypothetical | §6 rows, COT-08 / COT-03. |

**Top 3 (attacker):** ATK-01, ATK-02, ATK-03.
**Still open for the owner:** Q2, Q3, Q4, Q6, Q8, Q10, Q12 (spec §8).
