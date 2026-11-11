# 035 — S01 design table for the x10 validator (rerun item 6)

**Date:** 2026-11-11 · **Status:** draft for the owner (design transcribed from the handoff and decision 016; nothing invented) · **Task:** ×10 ingest and validation · **Relates to:** 016 (RDP evidence pending S01 t01), 019, 029 (criteria), 034 (`x10_v2`), rerun plan item 6

## Context
Decision 029 has no S01 design, because S01 had no ×10 trials. S01 is rebuilt in `x10_v2` (decision 034, `docs/lab/rerun_plan.md` item 6), so the validator needs a design table for it. Sources, in order of use:
- `docs/handoff_18.md` §21.5 table: "S01 … now **svc_backup, EP-01→EP-02 RDP** (4624 Type 10)".
- `docs/handoff_18.md` §21.8 item 1: "Run S01 ×10 manually — RDP EP-01→EP-02 as `svc_backup`, **after a clean revert** (so it logs 4624 Type 10 fresh, not Type 7 reconnect)".
- `docs/handoff_18.md` §20.5 and the §21 status table: S01 is manual, "no Caldera adversary".
- `docs/handoff_18.md` line 226–227 (source-side anchor for RDP: `mstsc.exe` Sysmon 3 → destination port 3389) and §7.2 R5 with Correction E4 (a remote Type 3 counts as RDP when corroborated by Sysmon 3 to 3389).
- Decision 016: target side seen in S01 t00 (inbound `svchost.exe` → 3389, `Initiated = false`); the source side `mstsc.exe` → 3389 is expected and its absence is the kill criterion; `docs/research/sysmon_config_check.md` §1 and §5 (the config logs destination port 3389).
- `docs/handoff_18.md` §21.5: LSASS edges are listed for S02, S03, S04, S05 and S07, not for S01.
`docs/research/x10_design_validation.md` was checked: it covers S02–S07 and the S05 quarantine only and has no S01 design. S01 t00 cannot serve as a sanity run: its EP-01 and DC01 files are S02 exports (decision 001).

## Decision — S01 design (one hop, manual)
| Item | Value | Source |
|---|---|---|
| Path hosts | ep-01, ep-02 (ep-03 and dc01 off the path; dc01 is used only for the clock check g) | handoff §21.5 |
| Hop `s01-h1` | RDP, ep-01 → ep-02, lane **manual** (no agent), intended account `svc_backup` | §21.5, §21.8 |
| Step `rdp_source` (b) | Sysmon 3 on ep-01 from `mstsc.exe` to the target IP, destination port 3389, inside the trial run. For RDP this replaces "a command naming the target": the source-side anchor is the connection, not a command line | handoff 226–227; decision 016 |
| Step `logon` (b, c) | 4624 on ep-02 from ep-01's IP by the intended account: logon type 10, or logon type 3 together with inbound Sysmon 3 to 3389 on ep-02 (Correction E4). A type 7 (reconnect) or type 11 logon does not count; the observed types are reported | §21.8, E4, R5 |
| Dumps | none required | §21.5 lists no LSASS edge for S01 |
| Agent evidence (e) | n/a (manual, no Caldera adversary) | §20.5 |
| Benign track (d) | n/a | – |
| Criterion c | FAIL if `svc_backup` never appears in the `logon` step; the observed target-side account is reported next to it (decision 027) | 029 |
| Criteria a, f, g, h, i | as in 029. a: ep-01 and ep-02 are path hosts. h: counts RDP sessions of the same user from the same source naming the same target (extra identifiable → WARN, indistinguishable → FAIL, as N12). f anchors: the `rdp_source` connection and the design target logon | 029 |

## Measurement notes
- The target is named by destination IP (192.168.50.22), not by a command line, because the RDP client may be started from the interface.
- Any rundll32 → lsass access in an S01 run is listed in the evidence and does not change a status, because the design has no dump (see open point 1).

## Open points for the owner
1. **Does S01 include an LSASS dump on ep-01?** The sources above do not say so, and §21.5 lists LSASS edges for the other scenarios only. If yes, a dump step is added by a new record before the S01 trials are run (it matters for the identity rule, Correction K).
2. **Type 3 + 3389 as RDP:** accepted as in Correction E4. If the owner wants only type 10, the `logon` step is tightened by a new record.

## Consequences
The validator gets an `s01` entry and RDP support (new protocol and step types); behaviour for S02–S07 and S05 must not change (checked by re-running all 66 trials and comparing statuses). The `x10_v2` source option for the validator is separate work (rerun plan, "Work needed").

## Kill criteria
If the first S01 trial shows no `mstsc.exe` → 3389 on ep-01 (decision 016's kill criterion), the validator reports `rdp_source` missing (b FAIL) and the Sysmon configuration is checked before more trials are run.

## Committee answer
**EN:** We wrote down the S01 design exactly as the handoff states it, a manual RDP hop from EP-01 to EP-02 as svc_backup, so the S01 repeats can be checked with the same pass criteria as the other scenarios.
**TH:** เราบันทึกการออกแบบ S01 ตามที่ handoff ระบุ คือการเชื่อมต่อ RDP ด้วยมือจาก EP-01 ไป EP-02 ด้วยบัญชี svc_backup เพื่อให้ตรวจรอบ S01 ที่รันซ้ำด้วยเกณฑ์ผ่านเดียวกับสถานการณ์อื่น
