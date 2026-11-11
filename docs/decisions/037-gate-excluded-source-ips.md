# 037 — Gate: sessions from the non-lab workstations .97/.98/.99 are excluded by source IP

**Date:** 2026-11-11 · **Status:** accepted (owner direction 2026-11-11; spec 02_gate draft) · **Task:** T6 (6.1, 6.4) · **Answers:** decision 032's open point on explicit IP exclusion

## Context
At the end of most ×10 trials, `admin_it` network/WinRM logons from 192.168.50.97 (ARSU-MAEHAE), .98 and .99 (DESKTOP-VSUAVJ5) reach the endpoints and start `wsmprovhost.exe` (decision 032; `docs/research/x10_design_validation.md` notes N8, N9). Their purpose (log collection) is inferred. Decision 032 left open whether the trial-window clip alone removes them. It does not: in `s04_t01` the .99 logon (04:12:22 UTC) lies inside the window, which ends at 04:13:01. Left in, these sessions would fire R8 (WinRM) and R4 triggers. The owner directed that they must never reach the gate.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. Window clip only | No extra rule | Misses in-window sessions | `s04_t01` .99 logon inside the window (032) |
| B. Exclude by account `admin_it` | Simple | `admin_it` is a scenario account (S03, S05 hop 2, S06); would delete real hops | decisions 025, 029 |
| C. Exclude by source IP, with the session's events (by logon ID on the same host, map built from the unclipped DB; WinRM 91 / Sysmon 3 by remote address; paired 7045) | Removes the sessions wherever they fall; never touches lab-IP logons | A designed step run from one of these IPs is hidden too | S04 ×10 Track A ran from .99 (`x10_design_validation.md` l.13) |

## Decision
Option C (spec 02_gate GT-02). Reason labels are `excluded_source_ip` / `excluded_source_ip_session`, not "collector", because the purpose is inferred. The out-of-window lookup only removes events, never adds any. An excluded session that also has a service install or a share write is listed in `stats.json` (`excluded_ip_with_artefacts`), and GTA-05 stops and reports to the owner if the `s04_t01` .99 session has one.

## Consequences
In-window sessions from these IPs never become triggers. A designed step run from one of these workstations (the broken S04 ×10 Track A, already marked for a full rerun by the validation) is invisible to the gate; it is listed, not silently lost. On t00 development data no key contains these IPs, so the rule is proven by unit tests until a ×10 trial can be gated (decision 039).

## Kill criteria
If a valid (non-broken) trial shows a designed hop from .97/.98/.99, or a new non-lab IP appears with the same pattern, revisit the list in a new record.

## Committee answer
**EN:** Three workstations outside the lab logged on to every machine at the end of the trials, most likely to collect the logs. We remove their sessions by IP address, not by account, because they used an account that the attack scenarios also use.
**TH:** เครื่องนอกแล็บสามเครื่องล็อกออนเข้าทุกเครื่องตอนท้ายแต่ละรอบ ซึ่งน่าจะเป็นการเก็บล็อก เราตัดเซสชันเหล่านี้ด้วยหมายเลข IP ไม่ใช่ด้วยบัญชี เพราะบัญชีที่ใช้เป็นบัญชีเดียวกับในสถานการณ์โจมตี
