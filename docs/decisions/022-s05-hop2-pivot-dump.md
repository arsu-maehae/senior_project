# 022 — S05 hop 2: ep-02 → ep-03 over WinRM, identity from the ep-02 pivot dump

**Date:** 2026-11-10 · **Status:** proposed, needs owner approval · **Task:** T5 (5.4)

## Context
`ground_truth/drafts/s05_t00.yaml`, hop `s05-h2`, from `events_dedup` of `s05_t00`:
- Source ep-02, target ep-03, WinRM, moving account `admin_it` (target 4624). The agent-tree command on ep-02 (`Invoke-Command`, 07:12:45) names the target; the target host was read from the full command line. Basis `command_names_target`, `confirmed`, tier A (port join on source Sysmon 3), matches the handoff source ep-02.
- The dump used is the second one, on ep-02 (07:11:49.716Z, run by `admin_it`); the first (ep-01, 07:09:43) is not used for this hop. `admin_it` has open sessions `0x138d2f` (type 3, weak) and `0x1c63d2` (type 4, strong; the pivot agent session, 07:06:28) on ep-02 at the dump. The move (07:12:48.154Z) is 58 s after it. Identity = 1.
- Hop 1 (ep-01 → ep-02 SMB, `svc_backup`, 07:10:47) has identity 1 from the ep-01 dump; dump 1 is 64 s earlier.
- The pivot agent (group `pivot_admin`, `admin_it` on ep-02) started at 2026-10-12 07:06:28, before the first dump; it is an `agent_start` step and is not used for the key window start (07:08:43 = dump 1 − 60 s).
- One unconfirmed background `admin_it` SMB logon ep-01 → ep-02 at 07:05:15 (`s05-t1`, identity 0, the move is before any dump).

## Decision
S05 key: path `s05-h1 → s05-h2`, both confirmed, identity 1 and 1. The hop ids follow the handoff step ids, not any tool's numbering.

## Consequences
Hop 2 has the strongest evidence (tier A) of any development hop. The handoff's open item (§24.6 item 5, l.2024: an `admin_it` session open on ep-02 before dump 2) is satisfied, by one strong (type 4) and one weak (type 3) session.

## Kill criteria
Change if the t01 trial shows no `admin_it` session on ep-02 at its dump.

## Committee answer
**EN:** In S05 the second move starts from ep-02, where a second credential read happened while the admin account was signed in, so that hop scores one.
**TH:** ใน S05 การเคลื่อนที่ครั้งที่สองเริ่มจาก ep-02 ซึ่งมีการอ่าน credential ครั้งที่สองขณะบัญชีผู้ดูแลระบบล็อกอินอยู่ hop นั้นจึงได้หนึ่ง
