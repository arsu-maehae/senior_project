# Data reality: linking and identity evidence per scenario (t00, measured 2026-11-10)

Source: `out/log_check/s0N_t00/report.json` and `hop_candidates.csv` from `src/log_check` (spec `docs/specs/00_log_check.md`), run read-only on `data/processed/s0N_t00.sqlite3`. Five numbers per trial were re-derived with independent SQL by the data-checker (all matched). Windows are PROVISIONAL and anchor-derived (decision 012): fine for measuring evidence, **not for evaluation**. Hop lists come from the scenario-account remote logons the script found; the T5 answer keys will confirm which hops are the attack.

## 1. Per-hop evidence

Method codes: **port** = Correction I join (target 4624 IpAddress/IpPort ↔ source Sysmon 3 → ProcessGuid → session); **cmd** = command-line method (source session whose Sysmon 1/4688 command line names the target; the "after the account filter" counts are measurement only — decision 013 makes account a supporting check); **cmd+4648** = cmd with the explicit-credential bridge (LC-04e). Sessions = candidate source sessions before → after the account filter. Identity = Correction K value if this hop is a move after the dump (a session of the moving account open on the source host at the dump).

| Hop | Protocol / auth | Target-side evidence | Source-side evidence | Sessions | Method possible | Kerberos confirm | Dump before move; identity |
|---|---|---|---|---|---|---|---|
| S01 ep-01→ep-02 (07:44–08:07) | RDP? / NTLM | 7 remote 4624 (Type 3, all NTLM, 4 with port 0); inbound `svchost.exe`→3389 Sysmon 3 (4 rows) | **not measurable until S01 t01** (EP-01 file is an S02 export, decision 001) | – | target side only | no (NTLM) | not measurable |
| S02 h1 ep-01→ep-02 svc_backup 05:42:45 | SMB / NTLM, port > 0 | 4624, 5140/5145, PktDropService 7045/4697 | `powershell … \\192.168.50.22\ADMIN$ …; sc.exe \\192.168.50.22 create PktDropService` in 0x25cac3 (agent, type 4), Δ +0.8 s | 1 → 1 | cmd (tier B) | no (NTLM by IP) | ep-01 05:42:00, svc_backup 0x25cac3 open → **1** |
| S03 h1 ep-01→ep-03 admin_it 09:41:36 | WinRM / Kerberos | 4624, WinRM 91 (admin_it, clientIP), wsmprovhost session | `powershell.exe`→5985 Sysmon 3 port join and `Invoke-Command -ComputerName Endpoint-03` in 0x170f6 (agent, type 4) | 1 → 1 | **port (tier A)** and cmd agree | yes | ep-01 09:40:29, admin_it 0x170f6 open → **1** |
| S04 h1 ep-01→ep-02 admin_it 10:55:28 | SMB / NTLM | 4624, 5140/5145 | no command names the target (reason b) | 0 → 0 | none | no | (benign-looking: ~40 s after the admin desktop logon) |
| S04 h2 Track A admin_it 10:57:34 | SMB / NTLM | 4624, 5145 `HealthAgent.exe`, HealthAgentSvc 7045/4697 (ties to exactly this session) | `net use \\192.168.50.22\ADMIN$`, `sc.exe \\192.168.50.22 create HealthAgentSvc` in 0xd6398 (admin desktop, type 11), Δ +1.1 s | **2 → 1** | cmd (tier B) | no | ep-01 10:56:56, admin_it 0x17b18 (agent) and 0xd6398 (desktop) open → **1** |
| S04 h3 Track B svc_backup 10:57:36 | SMB / NTLM | 4624, 5145 `Stage.exe`, UpdaterService 7045/4697 (ties to exactly this session) | `net use \\192.168.50.22\IPC$ … Copy-Item … sc.exe \\192.168.50.22 create UpdaterService` in 0x17c46 (agent, type 4), Δ +0.9 s | **2 → 1** | cmd (tier B) | no | same dump, svc_backup 0x17c46 open → **1** |
| S05 h1 ep-01→ep-02 admin_it 07:05:15 | SMB / NTLM | 4624 | none names the target (reason b) | 0 → 0 | none | no | benign-looking |
| S05 h2 ep-01→ep-02 svc_backup 07:10:47 | SMB / NTLM | 4624, PktDropService 7045/4697 | `net use \\192.168.50.22\IPC$ … PktDrop …` in 0x17e04 (agent), Δ +0.07 s | 1 → 1 | cmd (tier B) | no | ep-01 07:09:43, svc_backup 0x17e04 open → **1** |
| S05 h3 ep-02→ep-03 admin_it 07:12:48 | WinRM / Kerberos | 4624, WinRM 91 (admin_it, 192.168.50.22) | `powershell.exe`→5985 port join, session 0x1c63d2 (agent, type 4) | 1 → 1 | **port (tier A)** and cmd agree | yes | ep-02 07:11:49, admin_it 0x1c63d2 open → **1** |
| S06 h1 admin_it 08:59:36 → ep-02 | SMB / NTLM | 4624 | none names the target | 0 → 0 | none | no | no dump in S06 → **0** |
| S06 h2, h4, h5 admin_it → ep-02 / ep-03 | WinRM, SMB / Kerberos, NTLM | 4624; WinRM 91 on ep-03 (h4) | commands in the svc_backup agent session 0x1682b using admin_it credentials (5–6 Security 4648 rows: TargetUserName admin_it, TargetServerName Endpoint-0N) | 1 → 0 → **1 with 4648 bridge** | cmd+4648 (h2 also port join after the bridge) | h2/h4 yes | no dump → **0** |
| S06 h6 svc_backup → ep-02 | SMB / NTLM | 4624, BenignMon 7045 (`C:\Windows\HealthAgent.exe`) ties to no session | 0x1682b | 1 → 1 | cmd (tier B) | no | **0** |
| S07 h1 admin_it 09:11:08 → ep-02 | SMB / NTLM | 4624 | none names the target | 0 → 0 | none | no | benign-looking |
| S07 h2 svc_backup 09:17:58 (XferService) | SMB / NTLM | 4624, 5145, XferService 7045 (ties to one session) | 0x161a2 (agent), Δ −3.1 s | 1 → 1 | cmd (tier B) | no | ep-01 09:17:06, svc_backup open → **1** |
| S07 h3 svc_backup 09:19:33 (SyncService) | SMB / NTLM | 4624, SyncService 7045 (ties to one session) | same session 0x161a2, Δ +0.3 s | 1 → 1 | cmd (tier B) | no | ep-01 09:18:36, svc_backup open → **1** |

## 2. What the measurements say
1. **Every scenario-account attack hop in S02–S07 has exactly one account-consistent source session.** SMB hops: command-line join only (tier B); WinRM hops: Correction I port join works (tier A) and agrees with the command-line join.
2. **S04 (two tracks 3 s apart):** without the account filter each hop has 2 candidate sessions; with it, 1, and the right one each time. Each service install ties to exactly one target session via the 5145 file name. The owner's fear (admin session linked to the attacker's hop) does not occur on t00 **when the account filter is applied**.
3. **The account filter is not enough in S06:** a svc_backup agent runs admin_it actions with explicit credentials. The plain filter drops the true session (1 → 0); the Security 4648 bridge restores it. Any linking rule needs the 4648 bridge.
4. **SMB hops by IP are NTLM:** every SMB hop (S02, S04, S05, S07) authenticated with NTLM, so the Kerberos LogonGuid confirmation is unavailable for them. WinRM hops (by name) are Kerberos and confirmable (LC-03: 58/61, 117/119, 73/80, 146/152, 109/113, 88/94 of lab-IPv4 remote 4624 confirmed per trial — nearly all are logons on dc01 itself; endpoint confirmations exist only for ep-03 in s03/s05/s06 and ep-02 in s06, 5 each).
5. **Recurring benign look-alike:** in S04, S05, S06, S07 an admin_it SMB logon ep-01→ep-02 appears 30–60 s after the admin desktop logon, and no command names the target (reason b). It will pass the gate (R4) and must be ranked, not dropped (Correction J). Cause not verified (likely Explorer/desktop activity of the interactive admin session).
6. **Identity (Correction K) cannot separate S04 Track A from Track B:** at the S04 dump, admin_it had an agent session (0x17b18, type 4) and a desktop session (0xd6398, type 11) open on ep-01, so both tracks score 1. Same pattern at every ep-01 dump (S02–S05, S07: type-11 admin_it sessions open); not at the S02 ep-02 dump (only svc_backup sessions) nor at the S05 ep-02 dump (admin_it only type 3 and type 4). This is the "exposed ≠ stolen" consequence handoff Correction H.2 predicted; S04's ablation result must be stated with it.
7. **Clock offsets** (4624 − matching DC 4769, p50, mutual-nearest pairs; LC-09): ep-01 −1.1 to +3.4 s, ep-02 −1.7 to +2.7 s, ep-03 +4.0 to +4.5 s; dc01 vs itself 5–6 ms; S04 flagged `dc01_skew_possible`. Offsets change per trial (snapshot revert). Security 4688 and Sysmon 1 agree on every host (median 0 ms). Source commands appear −3.1 to +1.1 s from the target 4624 in the SMB hops. Cross-host time rules need a tolerance of at least 5 s; same-host ordering (dump before the move's command) is unaffected.
8. **S07 accounts:** both S07 service hops come from one svc_backup session; the handoff's svc_sql path (§21.5) is not visible in the t00 data. To settle in the T5 answer key (T5.4).
9. **RDP:** only target-side evidence (S01 t00). Source side not measurable until S01 t01.

## 3. Link method possible, per protocol
| Protocol | Hops (t00) | Method | Expected tier |
|---|---|---|---|
| SMB | S02, S04 ×2, S05 h2, S07 ×2, S06 h5/h6 | cmd (+4648 bridge), target side 4624 + 5145 + 7045 | B (one session after the filter) |
| WinRM | S03, S05 h3, S06 h2/h4 | port (Correction I) and cmd | A |
| RDP | S01 | target side only now | not measurable until S01 t01 |
| none | admin_it background SMB logons (S04–S07 h1) | no source evidence | ranked low, never dropped |

## 4. 4648 coverage (log-check LC-04h, added after decision 013)
| Trial | SMB/WinRM hops | With a 4648 naming the target | Without | 4648 session ≠ command-line session |
|---|---|---|---|---|
| s02 | 1 | 0 | 1 | 0 |
| s03 | 1 | 1 | 0 | 0 |
| s04 | 3 | 0 | 3 | 0 |
| s05 | 3 | 1 | 2 | 0 |
| s06 | 5 | 4 | 1 | 0 |
| s07 | 3 | 0 | 3 | 0 |
- **No SMB attack hop by IP has a naming 4648** (S02 h1, S04 h2/h3, S05 h2, S07 h2/h3): on ep-01 there is no 4648 in the 300 s before or 60 s after these hops, apart from machine-account rows in S04. These hops rely on the command-line method alone (decision 013 kill criterion 3 and limitation L11 apply).
- 4648 exists for the WinRM hops (S03 h1, S05 h3) and for S06's explicit-credential hops (h2, h4, h5), and its session always equals the command-line session (tier B). S06 h6 (svc_backup hop) has a 4648 in the same session but with admin_it credentials, so `account_match = none` → tier D for that row.
