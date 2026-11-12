# 03_stitch: input notes for the T7 spec (PLAN 7.1)

**Status:** input notes, not a spec. The T7 spec (`docs/specs/03_stitch.md`) must handle each item below.
**Source:** T6 stage review [02_gate-2026-11-12.md](../reviews/02_gate-2026-11-12.md), findings F2 and F3 (raised by the attacker; recorded on the owner's request, 2026-11-12).
**Data:** development trials only (s02–s07 t00). Counts come from read-only SQL on `data/processed/<trial>.sqlite3` (`events_dedup`) and the gate outputs in `out/gate/<trial>/`, gate run of 2026-11-12.

## IN-01 (F2): one hop produces several 4624 logons

**Observation.** A **sibling** is a remote type-3 4624 on the hop's target host from the same source IP within 2 s of the key's 4624. Most key hops have 2–5 siblings. The gate gives each sibling its own outcome.

| trial | hop | protocol | 4624s in group | spread vs key 4624 | where each sibling lands | accounts |
|---|---|---|---|---|---|---|
| s02_t00 | s02-h1 | SMB (no service) | 3 | 0 … +205 ms | key R4; 2 unmatched | svc_backup ×3 |
| s03_t00 | s03-h1 | WinRM | 5 | 0 … +659 ms | key R8; 4 unmatched | admin_it ×5 |
| s04_t00 | s04-A-h1 | SMB + service | 3 | 0 … +195 ms | key R4; R6; unmatched | admin_it ×3 |
| s04_t00 | s04-B-h1 | SMB + service | 3 | 0 … +273 ms | key R4; R6; unmatched | svc_backup ×3 |
| s04_t00 | s04-t1 | SMB | 1 | – | key R4 | admin_it |
| s05_t00 | s05-h1 | SMB + service | 3 | 0 … +502 ms | key R4; R6; unmatched | svc_backup ×3 |
| s05_t00 | s05-h2 | WinRM | 5 | 0 … +1716 ms | key R8; 4 unmatched | admin_it ×5 |
| s05_t00 | s05-t1 | SMB | 1 | – | key R4 | admin_it |
| s06_t00 | s06-winrm-1 | WinRM | 3 | 0 … +395 ms | key R8; 2 unmatched | admin_it ×3 |
| s06_t00 | s06-winrm-2 | WinRM | 5 | 0 … +484 ms | key R8; 4 unmatched | admin_it ×5 |
| s06_t00 | s06-smb-1 | SMB + service | 3 | −49 … +60 ms | R4 (−49 ms); **key R6**; unmatched | **admin_it** (R4), svc_backup (key, unmatched) |
| s06_t00 | s06-t1 | SMB | 1 | – | key R4 | admin_it |
| s07_t00 | s07-h-x | SMB + service | 3 | 0 … +376 ms | key R4; R6; unmatched | svc_backup ×3 |
| s07_t00 | s07-h-y | SMB + service | 2 | 0 … +49 ms | **key R6**; unmatched | svc_backup ×2 |
| s07_t00 | s07-t1 | SMB | 1 | – | key R4 | admin_it |

The counts:
- SMB service-install hops: 3 logons (share copy → R4, service control → R6, a third with no artefacts → `unmatched_remote`). s07-h-y has 2 because its copy is logged under h-x's session (IN-02).
- WinRM hops: 3–5 logons, up to 1.7 s apart.
- Background `t1` hops: 1 logon.
- The key's chosen 4624 is the R6 sibling in s06-smb-1 and s07-h-y and the R4/R8 one elsewhere. A hop match that uses only one sibling therefore depends on which one the key chose.
- The accounts can differ inside one group: in s06-smb-1 the R4 sibling is admin_it and the key and unmatched siblings are svc_backup (decision 024).

**Related: one source port carries several hops' logons.** The SMB TCP connection from ep-01 stays open across hops:
- s04_t00: port 49734 for the s04-t1, s04-A-h1 and s04-B-h1 key logons.
- s06_t00: port 49736 for the s06-t1 key and the s06-smb-1 R4 sibling.
- s07_t00: port 49736 for the s07-t1 key (09:11:08) and the s07-h-x key (09:17:57, about 7 min later).
- WinRM siblings also reuse ports inside one group (s03-h1: 49760 and 49761 twice each).
- So (source IP, source port) does not identify one hop.

**The T7 spec must:**
1. Group the sibling logons of one hop and state the grouping rule and gap. Choose these in the spec or council from the spreads above (largest observed: 1716 ms, s05-h2). Record the member logon IDs.
2. Attach artefacts (5140/5145, 4697, 7045, wsmprovhost) of any member to the group. Do not drop the R6-only member just because a sibling fired R4.
3. Keep the account a per-member check (`account_match`), never a grouping or join condition (Correction I, decision 013). Mixed-account groups exist (s06-smb-1).
4. Let the T7.6 link evaluation match a key hop when the key's 4624 is any member of the group.
5. Let the tier-A Sysmon 3 port join return several logons for one (IP, port), and state how that sets `candidate_count`.

## IN-02 (F3): a file copy is logged under an earlier hop's session

**Observation (s07_t00).** Path Y reuses path X's `svc_backup` logon on ep-02 (decision 033: seen in 11 of 11 S07 trials).

| logon on ep-02 | gate row | events under this logon ID | time |
|---|---|---|---|
| 0x49cdfa (s07-h-x key) | `s07_t00-g0009` R4, 15 supporting uids, `time_delta_ms` 4 | **h-x:** 1× 5140 IPC$, 1× 5140 ADMIN$, 6× 5145 ADMIN$ (`Xpay.exe`, `\`) = 8 | 09:17:57.757–.961 |
| | | **h-y:** 1× 5140 ADMIN$, 6× 5145 ADMIN$ (`Ypay.exe`, `\`) = 7 | 09:19:33.030–.063 (95.3 s after the h-x 4624) |
| 0x49cedc (h-x sibling) | R6 | 4697 XferService (`C:\Windows\Xpay.exe`) | 09:17:58.084 |
| 0x4b5d51 (s07-h-y key) | `s07_t00-g0011` R6, 1 supporting uid | 4697 SyncService (`C:\Windows\Ypay.exe`); logoff 09:19:33.193 | 09:19:33.183 |
| 0x4b5da5 (h-y sibling) | unmatched | 4672 only | 09:19:33.228 |

So 7 of the 15 supporting uids on h-x's R4 row are h-y's file copy, and h-y's own logons have no share events at all. A T7 tie by SubjectLogonId alone would attach h-y's copy to h-x and leave h-y without its copy.

**The T7 spec must:**
1. Not assign a session's share artefacts to one hop by SubjectLogonId alone when they are far in time from that hop's 4624. State how a long-lived session's artefacts are split, e.g. into time bursts.
2. Allow an artefact burst to attach to a later hop on the same target host, for example by the 5145 file name ↔ 7045/4697 binary name (`Ypay.exe`), the "7045 by time + binary file name" artefact of Correction I. Record the method and `candidate_count` of that attachment.
3. Record the time span of the artefacts attached to a hop, so a 95 s spread is visible. The review suggests a `supporting_span_ms` column, which the gate could also emit; that would be a spec change for 02_gate.
4. Include s07 path Y in the T7.6 link-accuracy check: h-y must get its own copy, and h-x must not get h-y's.
