# 024 — S06: benign paths in the key and the agent account

**Date:** 2026-11-10 · **Status:** proposed, needs owner approval · **Task:** T5 (5.4)

## Context
`ground_truth/drafts/s06_t00.yaml`, from `events_dedup` of `s06_t00` (decision 017: no dump anywhere, identity 0):
- Three hops are `confirmed` with basis `command_names_target`, all in `benign_paths`: `s06-winrm-1` (ep-01 → ep-02, 09:03:01), `s06-winrm-2` (ep-01 → ep-03, 09:03:56), `s06-smb-1` (ep-01 → ep-02, `BenignMon` service, 09:04:30). All identity 0.
- The agent is the `svc_backup` session `0x1682b` running commands with `admin_it` credentials (handoff §19.2 says `SandcatAgent_admin`). Each hop carries `account_mismatch`.
- `s06-smb-1`: the 4697 `BenignMon` is tied by SubjectLogonId to a `svc_backup` logon `3088797` (09:04:30.642Z), so the hop's moving account is `svc_backup` (`handoff_mismatch`). The `admin_it` NTLM logon `3088677` (09:04:30.593Z, the `net use`) is 50 ms earlier and is listed separately as unconfirmed `s06-t3`.
- Three unconfirmed `time_account_only` background `admin_it` logons ep-01 → ep-02 (`s06-t1` 08:59:36, `s06-t2` 09:03:13, `s06-t3` 09:04:30): no command names the target.

## Decision
Benign paths = the three confirmed hops; the three background logons stay `unconfirmed`. All identity 0. Open question for the owner: whether `s06-t3` is the credential connection of the same command as `s06-smb-1` (likely) and should be recorded as its supporting logon.

## Consequences
S06 supplies the check that benign paths rank below attack paths (Correction J). Background logons are neither attack nor benign until the owner rules (spec 07 section 8).

## Kill criteria
Change if any S06 trial shows an LSASS read (decision 017).

## Committee answer
**EN:** The benign scenario has three benign moves and no credential dump, so each scores zero on identity; they are expected to rank below the attack paths, to be measured.
**TH:** สถานการณ์ปกติมีการเคลื่อนที่ปกติสามครั้งและไม่มีการ dump credential ทุกครั้งจึงได้ศูนย์ด้าน identity คาดว่าจะอยู่ต่ำกว่าเส้นทางโจมตี ซึ่งจะวัดผลต่อไป
