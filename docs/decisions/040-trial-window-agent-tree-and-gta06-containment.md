# 040 — Trial window from the agent process tree only; GTA-06 checks start equality and containment

**Date:** 2026-11-11 · **Status:** accepted (owner, 2026-11-11) · **Task:** T6 (6.4, stage A) · **Amends:** 039 item 1, spec 02_gate §2.1, §5, §6, §7 (GTA-06), PLAN 6.4 · **Relates to:** 026, 030, 032, 039

## Context
Decision 039 said `src/trial_window/` computes each window "with the same function the answer-key builder uses" and must equal the key's `agent.run_interval` to the millisecond. That function is `answer_key.build.build_draft`. Its end is the latest of the step times, the hop command times and the hop **target-side** move times (`build.py` l.530–534). It also uses the intended steps (`intended_steps.json`) and the identified hops. The owner rejected reusing it. A read-only pre-check of a tree-only rule on the six t00 trials gave:
- all six starts equal the key's;
- s04, s06 and s07 ends are equal (both are clipped to the manifest export end);
- three ends differ: s02 **+0.976 s** (a later ep-01 `sc.exe` in the tree than the hop's first command), s03 **−2.762 s** and s05 **−2.420 s** (the key end is the hop's target 4624, 2–3 s after the command).

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. Call `build_draft`, take `run_interval` | Equals the key to the ms on all six (checked) | GTA-06 becomes a tautology (key vs itself). Answer-key logic (intended steps, identified hops) feeds the system under test | pre-check 2026-11-11 |
| B. Agent tree only: first run root − 60 s .. last Sysmon 1 descendant + 300 s, manifest clip; GTA-06 = ms-equality | Independent of the key | Fails on s02/s03/s05 by construction: the tree cannot see target-side times | Δ above |
| C. B, with GTA-06 = start equality + every key-hop event inside the window | Independent. It tests what the clip must do: lose no key event | The end is no longer pinned to the key | 0 key-hop events outside on all six; smallest end gap 144.9 s (s07) |

## Decision
Option C. `src/trial_window/` finds the run roots with `answer_key.agent_tree.agent_roots` / `run_start_ts` (Sysmon 1 parent = `C:\Users\Public\splunkd.exe`, plus the 4688 PID tie for an unresolved parent, which s02 ep-01 needs; 30-min walk-back). It walks their Sysmon 1 descendants by ProcessGuid itself. Start = first root − 60 s. End = last Sysmon 1 descendant + 300 s. Both are clipped to the manifest export span. Only generic helpers come from `src/answer_key`: time format, the 60/300 constants, `read_manifest_span`, the run-start walk-back and the read-only DB opener. `build_draft`, intended steps, hops, owner reviews and `ground_truth/` are not used.
- The agent identity (image `C:\Users\Public\splunkd.exe`, server `192.168.50.50:8888`) is lab setup metadata in `src/trial_window/params.py`. It cites `docs/handoff_18.md` l.1439 and `docs/research/agent_evidence.md` l.6–7.
- GTA-06 now checks, on the six t00 trials:
  1. the computed start equals the key's `run_interval` start;
  2. **(pass/fail)** every event uid referenced by the key's hops (all roles, supporting events included) lies inside the window;
  3. it reports the end difference and the smallest gap between a key-hop event and the window end.
- If any key event is outside, the task stops; the rule and margins are not changed.
- S01 uses operator times from `data/operator_times.csv` (`trial_id,start_utc,end_utc`). None are recorded yet, so S01 has no row.
- The clock constants (`CLOCK_CORRECTION_AVAILABLE`, `RAW_TIME_CUTOFF_DATE`) live in `src/trial_window/params.py`, for the gate to import.

## Consequences
The window and the key now come from different code, so GTA-06 is an independent check. The window edges differ from the key's `run_interval` by up to 3 s on three trials, well inside the 300 s end margin. The report must say the window is "computed from the agent process tree", not "equal to the answer key's interval". Info only: s05's ep-02 `agent_start` (07:06:28) is listed as a step in the s06/s07 keys. It falls outside both the computed window and the key's run_interval, by design (026).

## Kill criteria
- A key-hop event falls outside the computed window on any development trial (t00, valid t01).
- A computed start differs from the key's.
- A later trial's last Sysmon 1 descendant is a long-running agent child that stretches the end past the next trial's start; the 026 overlap check would show this.

## Committee answer
**EN:** The window is computed only from the attack agent's own process tree, so the system never reuses the answer key's logic. We check it against the answer key by requiring every answer-key event to fall inside the window. Its end differs from the key's by at most 3 s, far inside the 5-minute margin.
**TH:** ช่วงเวลาของแต่ละรอบคำนวณจาก process tree ของ agent เท่านั้น ระบบจึงไม่ใช้ตรรกะของเฉลยซ้ำ เราตรวจกับเฉลยโดยกำหนดว่าเหตุการณ์ทุกตัวในเฉลยต้องอยู่ในช่วงนี้ ขอบท้ายต่างจากเฉลยไม่เกิน 3 วินาที ซึ่งน้อยกว่าระยะเผื่อ 5 นาทีมาก
