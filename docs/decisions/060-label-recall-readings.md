# 060 — Labelling recall (LBA-04): readings of the expected-technique table

**Date:** 2026-11-17 · **Status:** accepted (T8.3; reading 1 open to owner override) · **Task:** T8.3 · **Relates to:** spec [04_label](../specs/04_label.md) §7 LBA-04, [051](051-link-accuracy-readings.md) item 8, [054](054-t77-out-guard-and-out-option.md), [056](056-sigma-rule-list-lock.md), [058](058-label-implementation-readings.md)

## Context
`src/evaluate/label_recall.py` builds one row per key event of the kinds in spec 04 §7. The table leaves four points
open. Development numbers on the six keyed t00 trials, which are **development numbers, not results**: T1003.001
14/14, T1021.002 5/23, T1570 10/15, T1569.002 8/8, T1021.006 9/9, overall 46/69. Target 4624 rows (41) and
background (12) and benign (31) key rows are reported, never scored.

## Options considered
| Point | Chosen reading | Alternative | Evidence / why |
|---|---|---|---|
| 1 "copied executable (write)" | a 5145 on ADMIN$ or a drive share whose `RelativeTargetName` has an SR-20 executable extension; access type not checked | read `AccessList` to keep only WriteData | the existing test `test_src_evaluate_never_selects_command_text_or_field_json` (051) forbids `src/evaluate` from selecting `field_values_json`, where AccessList lives. Measured once in scratch: the write reading gives T1570 10/10, T1021.002 5/28, overall 46/69 unchanged. The chosen reading scores the 5 non-write reads of the copied file as T1570 misses, so it does not raise recall |
| 2 "admin share" | `ADMIN$`, `IPC$` or a drive share (`X$`) | `ADMIN$` only | ATT&CK T1021.002 names these shares. The 3 attack `IPC$` 5140s become T1021.002 misses, and SR-10 (P1, ADMIN$ only) never labels them (056 L-LB3) |
| 3 column names | `hop_or_step_id` for "hop_id or step_id"; extra columns `role`, `scored`, `match_method` (uid / dup_uid / none), `label_techniques` after the spec columns | the spec columns only | one column name is needed; the extras explain each row |
| 4 a uid named by both a hop and a step | the hop row wins, so it is counted once. Step rows exist only for `lsass_dump` and are scored (LBA-02). WinRM rows come from the key's `target_event_uids` / `port_join_event_uids` | one row per mention | no double count; the image is not re-checked, which would only repeat SR-40 |

A key event outside the label window shows as not labelled. There is no window column.

**What the number means (stage review ATK-S04).** This is **rule coverage of key events**, not detection
recall. T1569.002 (any key 7045 / 4697) and T1021.006 (any key Sysmon 1 / 4688 or 5985 Sysmon 3) come close to full
coverage by construction, because SR-30, SR-31, SR-40 and SR-41 match those event kinds broadly. Benign key rows get the
same labels (service installs 4/4, WinRM 4/4), so the labels do not tell attack and benign apart. Readings 1 and 2
do not raise the T1570 or T1021.002 numbers. They say nothing about the two broad kinds.

## Decision
Adopt readings 1–4. The recall is written by `python -m evaluate --label-recall` to
`out/evaluate/<trial>/label_recall.csv` and `out/evaluate/development/label_recall.md`. `label_recall.csv` joins
`TRIAL_FILES` (054), and each evaluation keeps the other's files in the swap.

## Consequences
- T1021.002 recall is low (5/23) because SR-10 covers only `ADMIN$` (P1) and no locked rule covers `IPC$` or plain
  5140s. This is reported as a limitation, **not tuned**: the rule list is frozen (056).
- The done-when check for T8 uses LBA-02 and LBA-03 (every dump labelled; every attack hop has a labelled
  `context` = 0 node), not a recall level.

## Kill criteria
- The owner allows `AccessList` in `src/evaluate`. Reading 1 then becomes the write reading, with a new record and a
  051 amendment.

## Committee answer
**EN:** We measured how many answer-key events got the expected technique label, before any test data. This is
rule coverage, not detection: some rules match every event of their kind, benign ones too. Where the table was
vague we took the reading that does not raise the number, and we report the low SMB share number as a limitation
instead of changing the rules.
**TH:** เราวัดว่าเหตุการณ์ในเฉลยได้ป้ายเทคนิคตามที่คาดไว้กี่รายการ โดยวัดก่อนใช้ข้อมูลทดสอบใด ๆ ตัวเลขนี้คือความครอบคลุมของกฎ ไม่ใช่ความสามารถในการตรวจจับ เพราะบางกฎจับเหตุการณ์ชนิดนั้นทุกครั้ง รวมถึงเหตุการณ์ปกติด้วย จุดที่ตารางยังไม่ชัด เราเลือกการตีความที่ไม่ทำให้ตัวเลขสูงขึ้น และรายงานค่าของแชร์ SMB ที่ต่ำเป็นข้อจำกัด แทนการแก้กฎ
