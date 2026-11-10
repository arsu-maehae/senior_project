# 021 — S04 Track A: source session and status in the development key

**Date:** 2026-11-10 · **Status:** proposed, needs owner approval · **Task:** T5 (5.4)

## Context
Decision 018 fixes S04 Track A (`admin_it`, benign) at identity 1. The key needs the session behind Track A and a status. Evidence in `ground_truth/drafts/s04_t00.yaml` (hop `s04-A-h1`, read from `events_dedup` of `s04_t00`; the key code does not use `log_check`):
- At the LSASS read on ep-01 (10:56:56.314Z) `admin_it` has three open sessions: agent session `0x17b18` (type 4, since 10:54:47), desktop sessions `0xd6398` (type 11, since 10:55:16.711) and `0xd663a`.
- The move (target 4624 on ep-02, `admin_it`) is at 10:57:34.190Z, 37.9 s after the dump. Identity computed = 1, also at tolerance 0.
- Commands naming ep-02 under `admin_it` run in desktop session `0xd6398`: chain `explorer.exe → powershell.exe → net.exe`, up to `winlogon.exe`; no `splunkd.exe` ancestor. The commands name `HealthAgentSvc`, `HealthAgent.exe` and `ADMIN$`; target events tied by those names are listed in `session_evidence.target_events_tied_by_name`.
- The agent evidence (`docs/research/agent_evidence.md`) lists splunkd-tree commands naming ep-02 only for `svc_backup` in s04.
- Handoff §19.1 (l.1416), §19.6 (l.1505) and §21.3 (l.1653) say Track A was run manually; §21.5 (l.1713–1714) and Correction H.2 (l.204) say `foothold_admin` (`SandcatAgent_admin`, which runs on ep-01). The data supports the manual reading for this trial.
- Checked by SQL on `events_dedup` of `s04_t00` (Sysmon 1 and 4688 on ep-01, 10:56:30–10:58:30, full `command_line`): commands naming ep-02 (`net use \\192.168.50.22\ADMIN$`, `sc.exe \\192.168.50.22 create/start HealthAg…`) run only in `admin_it` session 877464 (= `0xd6398`, from 10:57:35.275) and, for Track B, in `svc_backup` session 97350 (= `0x17c46`, from 10:57:37.76). No command naming ep-02 runs in `0x17b18` (97048). The target 4624 (10:57:34.190) is 1.1 s before the first Track A command, within the measured cross-host clock offset (decision 014).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Source session `0xd6398`, status `unconfirmed` (owner rule: not in the agent tree), `proposed_role: benign` | Follows the evidence and the owner's independence rule | Track A is a benign hop with no `confirmed` label |
| B. Source session `0x17b18` (agent) | Same account | No command naming ep-02 runs in it |
| C. Add status `confirmed_benign` | Clear negatives for evaluation | Changes the owner's two-value `basis` rule; owner decides (spec section 8) |

## Decision
Option A, marked for owner approval. Identity value 1 (decision 018). The evaluation policy for `unconfirmed` benign hops is the owner's open question in spec 07 section 8.

## Consequences
Track A and Track B tie on identity (decision 018). T9 reports ties as ties.

## Kill criteria
If `0x17b18` is shown to have run a command naming ep-02 near 10:57:34, or the t01 trial shows `admin_it` with no open session at the dump, revise the key (018's kill criterion).

## Committee answer
**EN:** The benign admin move in S04 came from an interactive desktop session on ep-01 that was open when the dump happened, so under our rule it also scores one.
**TH:** การเคลื่อนที่ของผู้ดูแลระบบใน S04 มาจากเซสชันเดสก์ท็อปบน ep-01 ที่เปิดอยู่ตอน dump ตามกฎของเราจึงได้หนึ่งเช่นกัน
