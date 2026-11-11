# ×10 design validation (Step C, decision 029)

**Date:** 2026-11-11 · **Status:** draft for the owner · **Inputs:** 50 ×10 trial DBs (`data/processed/s0N_tNN.sqlite3`), 10 quarantined S05 DBs (`data/processed/quarantine/s05q_tNN.sqlite3`), 6 t00 DBs as a sanity run · **Tool:** `python -m x10_validate run --all` then `report` (commit c71acf4), outputs in `out/x10_validate/` (one JSON per trial with every event uid, time and account behind each status).

The criteria and severities are those of decision 029, fixed before the data was opened. The validator is read-only and independent: it imports nothing from `src/answer_key`, `src/log_check`, `src/data_layout` or any stitcher, and does not read `ground_truth/` (checked by an import test). No answer key was built or changed.

## 1. Summary

| scenario | verdict (029 Decision 3) | why |
|---|---|---|
| S02 | **pass** | all 10 trials have every design step; t03/t04 WARN on missing dc01 Security/Sysmon (g = n/a there) |
| S03 | **replace 1** (s03_t08) | s03_t08 holds only 4.5 min after a reboot: no agent on ep-01, no dump, no move |
| S04 | **full rerun** (10/10 fail b, c, d) | Track B is as designed in all 10. Track A did not run from ep-01: admin_it came over WinRM from a non-lab workstation (192.168.50.99, DESKTOP-VSUAVJ5) and ran `sc create HealthAgentSvc binPath= cmd.exe /c exit` on ep-02 directly; no ADMIN$ binary write |
| S06 | **replace 2** (s06_t09, s06_t10) | t09 has no ep-02/ep-03 logs; t10 has the ep-01 command naming ep-03 but no logon on ep-03 from ep-01 |
| S07 | **full rerun** (10/10 fail c) | path Y never logs `svc_sql` on ep-02; the target-side account is `svc_backup` in all 10 (as in t00, decision 027). All design steps (2 dumps, 2 commands, 2 logons, 2 services) are present |
| S05 (quarantine) | wrong-design claim **supported** | all 10 fail b: hop 1 ep-01 → ep-02 is WinRM (`Invoke-Command`), not SMB; no LSASS dump on ep-01 or ep-02; no service |

WARNs never change a verdict (029). Two WARNs are general: every trial except the partial ones has older trials' events in its files (f), and from 2026-10-26 on, ep-01's clock is 11–27 s behind dc01 (g; see §5).

Two measurement choices in criterion f were made after the data was seen and change f from FAIL to WARN/PASS for most trials. They are listed in §6 for the owner to accept or reject. They do not change any verdict above: no verdict rests on f.

## 2. Per-trial results (criteria a–i)

PASS | WARN | FAIL | n/a. Evidence is abbreviated; the per-trial JSON holds the event uids, times and accounts.

| trial | a | b | c | d | e | f | g | h | i | evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| s02_t01 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s) |
| s02_t02 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s); f(broad, info): overlaps s02_t03 |
| s02_t03 | WARN | PASS | PASS | n/a | PASS | WARN | n/a | PASS | PASS | a: missing dc01/security,dc01/sysmon; f: 2 older cluster(s); f(broad, info): overlaps s02_t02; g: no dc01 Security log: offsets vs dc01 no |
| s02_t04 | WARN | PASS | PASS | n/a | PASS | WARN | n/a | PASS | PASS | a: missing dc01/security,dc01/sysmon; f: 2 older cluster(s); g: no dc01 Security log: offsets vs dc01 no |
| s02_t05 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s) |
| s02_t06 | PASS | PASS | PASS | n/a | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s02_t07; g: pairs>5s {'dc01|ep-03': -5.088, 'ep-01|ep-03': -5.824} |
| s02_t07 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s02_t06,s02_t08 |
| s02_t08 | PASS | PASS | PASS | n/a | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s02_t07,s02_t09; g: pairs>5s {'dc01|ep-03': -6.466, 'ep-01|ep-03': -9.987, 'ep-02|ep-03': -6.468} |
| s02_t09 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s02_t08,s02_t10 |
| s02_t10 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s02_t09 |
| s03_t01 | PASS | PASS | PASS | n/a | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s03_t02; g: pairs>5s {'ep-01|ep-03': -6.161} |
| s03_t02 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s03_t01 |
| s03_t03 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s03_t04 |
| s03_t04 | PASS | PASS | PASS | n/a | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s03_t03,s03_t05; g: pairs>5s {'dc01|ep-03': -5.285, 'ep-01|ep-03': -8.289} |
| s03_t05 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s03_t04 |
| s03_t06 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s03_t07 |
| s03_t07 | PASS | PASS | PASS | n/a | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s03_t06; g: pairs>5s {'dc01|ep-03': -6.3, 'ep-01|ep-03': -9.22, 'ep-02|ep-03': -6.029} |
| s03_t08 | PASS | FAIL | FAIL | n/a | FAIL | WARN | n/a | PASS | WARN | b: missing dump_ep-01 (0/1),s03-h1:command,s03-h1:logon,s03-h1:winrm; c: intended not seen s03-h1; e: no agent beacon on ['ep-01']; f: 1 older cluster(s); f(broad, info): overlaps s05_t00; g: dc01 Security present but no LogonGuid p; i: differs in steps_found,target_accounts,protocols |
| s03_t09 | PASS | PASS | PASS | n/a | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s03_t10; g: pairs>5s {'dc01|ep-03': -5.338} |
| s03_t10 | PASS | PASS | PASS | n/a | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s03_t09 |
| s04_t01 | PASS | FAIL | FAIL | FAIL | PASS | WARN | WARN | PASS | PASS | b: missing s04-A:command,s04-A:binary_write,s04-A:service; c: intended not seen s04-A; d: no ADMIN$ binary write by admin_it on ep-02; f: 2 older cluster(s); g: pairs>5s {'dc01|ep-01': 14.66, 'ep-01|ep-02': -14.104, 'ep-01|ep-03': -17.861} |
| s04_t02 | PASS | FAIL | FAIL | FAIL | PASS | WARN | WARN | PASS | PASS | b: missing s04-A:command,s04-A:binary_write,s04-A:service; c: intended not seen s04-A; d: no ADMIN$ binary write by admin_it on ep-02; f: 2 older cluster(s); f(unclipped, info): overlaps s04_t03; g: pairs>5s {'dc01|ep-01': 12.586, 'ep-01|ep-02': -12.493, 'ep-01|ep-03': -13.256} |
| s04_t03 | PASS | FAIL | FAIL | FAIL | PASS | WARN | WARN | PASS | PASS | b: missing s04-A:command,s04-A:binary_write,s04-A:service; c: intended not seen s04-A; d: no ADMIN$ binary write by admin_it on ep-02; f: 2 older cluster(s); f(unclipped, info): overlaps s04_t02,s04_t04; g: pairs>5s {'dc01|ep-01': 20.191, 'ep-01|ep-02': -20.804, 'ep-01|ep-03': -23.998} |
| s04_t04 | PASS | FAIL | FAIL | FAIL | PASS | WARN | WARN | PASS | PASS | b: missing s04-A:command,s04-A:binary_write,s04-A:service; c: intended not seen s04-A; d: no ADMIN$ binary write by admin_it on ep-02; f: 2 older cluster(s); f(unclipped, info): overlaps s04_t03,s04_t05; g: pairs>5s {'dc01|ep-01': 11.785, 'ep-01|ep-02': -11.782, 'ep-01|ep-03': -13.321} |
| s04_t05 | PASS | FAIL | FAIL | FAIL | PASS | WARN | WARN | PASS | PASS | b: missing s04-A:command,s04-A:binary_write,s04-A:service; c: intended not seen s04-A; d: no ADMIN$ binary write by admin_it on ep-02; f: 2 older cluster(s); f(unclipped, info): overlaps s04_t04,s04_t06; g: pairs>5s {'dc01|ep-01': 13.63, 'ep-01|ep-02': -14.165, 'ep-01|ep-03': -18.199} |
| s04_t06 | PASS | FAIL | FAIL | FAIL | PASS | WARN | WARN | PASS | PASS | b: missing s04-A:command,s04-A:binary_write,s04-A:service; c: intended not seen s04-A; d: no ADMIN$ binary write by admin_it on ep-02; f: 2 older cluster(s); f(unclipped, info): overlaps s04_t05,s04_t07; g: pairs>5s {'dc01|ep-01': 13.919, 'ep-01|ep-02': -14.822, 'ep-01|ep-03': -16.866} |
| s04_t07 | PASS | FAIL | FAIL | FAIL | PASS | WARN | WARN | PASS | PASS | b: missing s04-A:command,s04-A:binary_write,s04-A:service; c: intended not seen s04-A; d: no ADMIN$ binary write by admin_it on ep-02; f: 2 older cluster(s); f(unclipped, info): overlaps s04_t06,s04_t08; g: pairs>5s {'dc01|ep-01': 13.382, 'ep-01|ep-02': -13.455, 'ep-01|ep-03': -16.897} |
| s04_t08 | PASS | FAIL | FAIL | FAIL | PASS | WARN | WARN | PASS | PASS | b: missing s04-A:command,s04-A:binary_write,s04-A:service; c: intended not seen s04-A; d: no ADMIN$ binary write by admin_it on ep-02; f: 2 older cluster(s); f(unclipped, info): overlaps s04_t07,s04_t09; g: pairs>5s {'dc01|ep-01': 12.997, 'ep-01|ep-02': -13.167, 'ep-01|ep-03': -17.222} |
| s04_t09 | PASS | FAIL | FAIL | FAIL | PASS | WARN | WARN | PASS | PASS | b: missing s04-A:command,s04-A:binary_write,s04-A:service; c: intended not seen s04-A; d: no ADMIN$ binary write by admin_it on ep-02; f: 2 older cluster(s); f(unclipped, info): overlaps s04_t08,s04_t10; g: pairs>5s {'dc01|ep-01': 13.084, 'ep-01|ep-02': -13.222, 'ep-01|ep-03': -17.576} |
| s04_t10 | PASS | FAIL | FAIL | FAIL | PASS | WARN | WARN | PASS | PASS | b: missing s04-A:command,s04-A:binary_write,s04-A:service; c: intended not seen s04-A; d: no ADMIN$ binary write by admin_it on ep-02; f: 2 older cluster(s); f(unclipped, info): overlaps s04_t09; g: pairs>5s {'dc01|ep-01': 14.481, 'ep-01|ep-02': -14.639, 'ep-01|ep-03': -17.464} |
| s06_t01 | PASS | PASS | PASS | PASS | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s06_t02; g: pairs>5s {'dc01|ep-01': 18.781, 'ep-01|ep-02': -16.543, 'ep-01|ep-03': -18.825} |
| s06_t02 | PASS | PASS | PASS | PASS | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s06_t01,s06_t03; g: pairs>5s {'dc01|ep-01': 15.158, 'ep-01|ep-02': -16.002, 'ep-01|ep-03': -17.128} |
| s06_t03 | PASS | PASS | PASS | PASS | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s06_t02,s06_t04; g: pairs>5s {'dc01|ep-01': 13.641, 'ep-01|ep-02': -10.749, 'ep-01|ep-03': -13.623} |
| s06_t04 | PASS | PASS | PASS | PASS | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s06_t03; g: pairs>5s {'dc01|ep-01': 24.659, 'ep-01|ep-02': -23.391, 'ep-01|ep-03': -27.01} |
| s06_t05 | PASS | PASS | PASS | PASS | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); g: pairs>5s {'dc01|ep-01': 16.044, 'ep-01|ep-02': -16.055, 'ep-01|ep-03': -16.697} |
| s06_t06 | PASS | PASS | PASS | PASS | PASS | WARN | PASS | PASS | PASS | f: 2 older cluster(s) |
| s06_t07 | PASS | PASS | PASS | PASS | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); g: pairs>5s {'dc01|ep-01': 13.378, 'ep-01|ep-02': -15.175, 'ep-01|ep-03': -14.299} |
| s06_t08 | PASS | PASS | PASS | PASS | PASS | WARN | WARN | PASS | PASS | f: 2 older cluster(s); f(unclipped, info): overlaps s06_t09; g: pairs>5s {'dc01|ep-01': 11.811, 'ep-01|ep-02': -12.824, 'ep-01|ep-03': -11.741} |
| s06_t09 | FAIL | FAIL | WARN | PASS | PASS | PASS | WARN | PASS | WARN | a: missing ep-02/powershell,ep-02/security,ep-02/sysmon,ep-02/system,ep-02/winrm,ep-03/powershell,ep-03/security,ep-03/sysmon,ep-03/system,ep-03/winrm; b: missing s06-winrm-1:logon,s06-winrm-1:winrm,s06-winrm-2:logon,s06-winrm-2:winrm,s06-smb-1:logon,s06-smb-1:service; c: intended not seen s06-winrm-1,s06-winrm-2,s06-smb-1; f(unclipped, info): overlaps s06_t08; g: pairs>5s {'dc01|ep-01': 14.453}; i: differs in hosts_present,steps_found,service_names,target_accounts |
| s06_t10 | PASS | FAIL | WARN | PASS | PASS | WARN | WARN | PASS | WARN | b: missing s06-winrm-2:logon,s06-winrm-2:winrm; c: intended not seen s06-winrm-2; f: 2 older cluster(s); g: pairs>5s {'dc01|ep-01': 12.856, 'ep-01|ep-02': -12.67, 'ep-01|ep-03': -14.463}; i: differs in steps_found,target_accounts |
| s07_t01 | PASS | PASS | FAIL | n/a | PASS | WARN | WARN | PASS | PASS | c: intended not seen s07-Y; f: 2 older cluster(s); f(unclipped, info): overlaps s07_t02; g: pairs>5s {'dc01|ep-01': 12.258, 'ep-01|ep-02': -11.853, 'ep-01|ep-03': -12.204} |
| s07_t02 | PASS | PASS | FAIL | n/a | PASS | WARN | WARN | PASS | PASS | c: intended not seen s07-Y; f: 2 older cluster(s); f(unclipped, info): overlaps s07_t01,s07_t03; g: pairs>5s {'dc01|ep-01': 16.81, 'ep-01|ep-02': -15.729, 'ep-01|ep-03': -19.723} |
| s07_t03 | PASS | PASS | FAIL | n/a | PASS | WARN | WARN | PASS | PASS | c: intended not seen s07-Y; f: 2 older cluster(s); f(unclipped, info): overlaps s07_t02,s07_t04; g: pairs>5s {'dc01|ep-01': 13.706, 'ep-01|ep-02': -12.865, 'ep-01|ep-03': -13.66} |
| s07_t04 | PASS | PASS | FAIL | n/a | PASS | WARN | WARN | PASS | PASS | c: intended not seen s07-Y; f: 2 older cluster(s); f(unclipped, info): overlaps s07_t03,s07_t05; g: pairs>5s {'dc01|ep-01': 17.465, 'ep-01|ep-02': -17.268, 'ep-01|ep-03': -19.611} |
| s07_t05 | PASS | PASS | FAIL | n/a | PASS | WARN | WARN | PASS | PASS | c: intended not seen s07-Y; f: 2 older cluster(s); f(unclipped, info): overlaps s07_t04,s07_t06; g: pairs>5s {'dc01|ep-02': -15.011, 'dc01|ep-03': -12.645, 'ep-01|ep-02': -16.56, 'ep-01|ep-03': -14.194} |
| s07_t06 | PASS | PASS | FAIL | n/a | PASS | WARN | WARN | PASS | PASS | c: intended not seen s07-Y; f: 2 older cluster(s); f(unclipped, info): overlaps s07_t05,s07_t07; g: pairs>5s {'dc01|ep-01': 13.975, 'ep-01|ep-02': -13.671, 'ep-01|ep-03': -16.026} |
| s07_t07 | PASS | PASS | FAIL | n/a | PASS | WARN | WARN | PASS | PASS | c: intended not seen s07-Y; f: 2 older cluster(s); f(unclipped, info): overlaps s07_t06,s07_t08; g: pairs>5s {'dc01|ep-01': 16.518, 'ep-01|ep-02': -14.789, 'ep-01|ep-03': -19.103} |
| s07_t08 | PASS | PASS | FAIL | n/a | PASS | WARN | WARN | PASS | PASS | c: intended not seen s07-Y; f: 2 older cluster(s); f(unclipped, info): overlaps s07_t07; g: pairs>5s {'dc01|ep-01': 14.415, 'ep-01|ep-02': -13.745, 'ep-01|ep-03': -14.72} |
| s07_t09 | PASS | PASS | FAIL | n/a | PASS | WARN | WARN | PASS | PASS | c: intended not seen s07-Y; f: 2 older cluster(s); g: pairs>5s {'dc01|ep-01': 12.971, 'ep-01|ep-02': -11.323, 'ep-01|ep-03': -13.979} |
| s07_t10 | PASS | PASS | FAIL | n/a | PASS | WARN | WARN | PASS | PASS | c: intended not seen s07-Y; f: 2 older cluster(s); g: pairs>5s {'dc01|ep-01': 15.333, 'ep-01|ep-02': -14.963, 'ep-01|ep-03': -18.102} |

### Per-trial facts behind b, c, h, i

| trial | design window (UTC, clipped at export end) | anchors | dumps | services on target | target account per hop (observed; intended) | protocol per hop |
|---|---|---|---|---|---|---|
| s02_t01 | 2026-10-15 05:30:51 → 05:37:46 | dump 1, agent_command 1, remote_4624 4 | dump_ep-01 1/1 | PktDropService | s02-h1: svc_backup (svc_backup) | s02-h1: SMB |
| s02_t02 | 2026-10-15 06:04:45 → 06:10:49 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | PktDropService | s02-h1: svc_backup (svc_backup) | s02-h1: SMB |
| s02_t03 | 2026-10-15 06:15:19 → 06:20:54 | remote_4624 6, dump 1, agent_command 1 | dump_ep-01 1/1 | PktDropService | s02-h1: svc_backup (svc_backup) | s02-h1: SMB |
| s02_t04 | 2026-10-15 06:24:44 → 06:30:57 | dump 1, agent_command 1, remote_4624 4 | dump_ep-01 1/1 | PktDropService | s02-h1: svc_backup (svc_backup) | s02-h1: SMB |
| s02_t05 | 2026-10-15 07:37:27 → 07:40:01 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | PktDropService | s02-h1: svc_backup (svc_backup) | s02-h1: SMB |
| s02_t06 | 2026-10-15 07:55:37 → 07:58:08 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | PktDropService | s02-h1: svc_backup (svc_backup) | s02-h1: SMB |
| s02_t07 | 2026-10-15 08:01:06 → 08:03:58 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | PktDropService | s02-h1: svc_backup (svc_backup) | s02-h1: SMB |
| s02_t08 | 2026-10-15 08:06:38 → 08:09:21 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | PktDropService | s02-h1: svc_backup (svc_backup) | s02-h1: SMB |
| s02_t09 | 2026-10-15 08:11:48 → 08:14:27 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | PktDropService | s02-h1: svc_backup (svc_backup) | s02-h1: SMB |
| s02_t10 | 2026-10-15 08:18:27 → 08:21:12 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | PktDropService | s02-h1: svc_backup (svc_backup) | s02-h1: SMB |
| s03_t01 | 2026-10-15 08:30:45 → 08:33:15 | dump 1, agent_command 1, remote_4624 5 | dump_ep-01 1/1 | – | s03-h1: admin_it (admin_it) | s03-h1: WinRM |
| s03_t02 | 2026-10-15 08:36:09 → 08:43:17 | dump 1, agent_command 1, remote_4624 5 | dump_ep-01 1/1 | – | s03-h1: admin_it (admin_it) | s03-h1: WinRM |
| s03_t03 | 2026-10-15 08:54:51 → 08:57:29 | dump 1, agent_command 1, remote_4624 5 | dump_ep-01 1/1 | – | s03-h1: admin_it (admin_it) | s03-h1: WinRM |
| s03_t04 | 2026-10-15 08:59:48 → 09:02:10 | dump 1, agent_command 1, remote_4624 5 | dump_ep-01 1/1 | – | s03-h1: admin_it (admin_it) | s03-h1: WinRM |
| s03_t05 | 2026-10-15 09:04:44 → 09:10:18 | dump 1, agent_command 1, remote_4624 5 | dump_ep-01 1/1 | – | s03-h1: admin_it (admin_it) | s03-h1: WinRM |
| s03_t06 | 2026-10-15 09:12:26 → 09:14:49 | dump 1, agent_command 1, remote_4624 5 | dump_ep-01 1/1 | – | s03-h1: admin_it (admin_it) | s03-h1: WinRM |
| s03_t07 | 2026-10-15 09:17:14 → 09:19:55 | dump 1, agent_command 1, remote_4624 5 | dump_ep-01 1/1 | – | s03-h1: admin_it (admin_it) | s03-h1: WinRM |
| s03_t08 | 2026-10-12 07:04:15 → 07:10:15 | remote_4624 1 | dump_ep-01 0/1 | – | s03-h1: none (admin_it) | s03-h1: none |
| s03_t09 | 2026-10-15 09:27:35 → 09:32:04 | dump 1, agent_command 1, remote_4624 5 | dump_ep-01 1/1 | – | s03-h1: admin_it (admin_it) | s03-h1: WinRM |
| s03_t10 | 2026-10-15 09:34:18 → 09:36:38 | dump 1, agent_command 1, remote_4624 5 | dump_ep-01 1/1 | – | s03-h1: admin_it (admin_it) | s03-h1: WinRM |
| s04_t01 | 2026-10-26 04:10:24 → 04:13:01 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | UpdaterService | s04-B: svc_backup (svc_backup); s04-A: svc_backup (admin_it) | s04-B: SMB; s04-A: none |
| s04_t02 | 2026-10-26 04:22:06 → 04:24:58 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | UpdaterService | s04-B: svc_backup (svc_backup); s04-A: svc_backup (admin_it) | s04-B: SMB; s04-A: none |
| s04_t03 | 2026-10-26 04:27:03 → 04:29:46 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | UpdaterService | s04-B: svc_backup (svc_backup); s04-A: svc_backup (admin_it) | s04-B: SMB; s04-A: none |
| s04_t04 | 2026-10-26 04:32:30 → 04:35:39 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | UpdaterService | s04-B: svc_backup (svc_backup); s04-A: svc_backup (admin_it) | s04-B: SMB; s04-A: none |
| s04_t05 | 2026-10-26 04:38:24 → 04:41:15 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | UpdaterService | s04-B: svc_backup (svc_backup); s04-A: svc_backup (admin_it) | s04-B: SMB; s04-A: none |
| s04_t06 | 2026-10-26 04:43:26 → 04:46:07 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | UpdaterService | s04-B: svc_backup (svc_backup); s04-A: svc_backup (admin_it) | s04-B: SMB; s04-A: none |
| s04_t07 | 2026-10-26 04:48:13 → 04:51:01 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | UpdaterService | s04-B: svc_backup (svc_backup); s04-A: svc_backup (admin_it) | s04-B: SMB; s04-A: none |
| s04_t08 | 2026-10-26 04:53:30 → 04:56:36 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | UpdaterService | s04-B: svc_backup (svc_backup); s04-A: svc_backup (admin_it) | s04-B: SMB; s04-A: none |
| s04_t09 | 2026-10-26 04:58:58 → 05:02:20 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | UpdaterService | s04-B: svc_backup (svc_backup); s04-A: svc_backup (admin_it) | s04-B: SMB; s04-A: none |
| s04_t10 | 2026-10-26 05:04:35 → 05:07:19 | dump 1, agent_command 1, remote_4624 3 | dump_ep-01 1/1 | UpdaterService | s04-B: svc_backup (svc_backup); s04-A: svc_backup (admin_it) | s04-B: SMB; s04-A: none |
| s06_t01 | 2026-10-27 06:21:10 → 06:24:38 | agent_command 3, remote_4624 13 | – | BenignMon | s06-winrm-1: admin_it (admin_it); s06-winrm-2: admin_it (admin_it); s06-smb-1: svc_backup (admin_it) | s06-winrm-1: WinRM; s06-winrm-2: WinRM; s06-smb-1: SMB |
| s06_t02 | 2026-10-27 06:27:14 → 06:30:58 | agent_command 3, remote_4624 14 | – | BenignMon | s06-winrm-1: admin_it (admin_it); s06-winrm-2: admin_it (admin_it); s06-smb-1: svc_backup (admin_it) | s06-winrm-1: WinRM; s06-winrm-2: WinRM; s06-smb-1: SMB |
| s06_t03 | 2026-10-27 06:33:00 → 06:37:19 | agent_command 3, remote_4624 13 | – | BenignMon | s06-winrm-1: admin_it (admin_it); s06-winrm-2: admin_it (admin_it); s06-smb-1: svc_backup (admin_it) | s06-winrm-1: WinRM; s06-winrm-2: WinRM; s06-smb-1: SMB |
| s06_t04 | 2026-10-27 06:40:18 → 06:43:44 | agent_command 3, remote_4624 13 | – | BenignMon | s06-winrm-1: admin_it (admin_it); s06-winrm-2: admin_it (admin_it); s06-smb-1: svc_backup (admin_it) | s06-winrm-1: WinRM; s06-winrm-2: WinRM; s06-smb-1: SMB |
| s06_t05 | 2026-10-27 06:52:31 → 06:59:14 | agent_command 3, remote_4624 13 | – | BenignMon | s06-winrm-1: admin_it (admin_it); s06-winrm-2: admin_it (admin_it); s06-smb-1: svc_backup (admin_it) | s06-winrm-1: WinRM; s06-winrm-2: WinRM; s06-smb-1: SMB |
| s06_t06 | 2026-10-27 08:10:59 → 08:14:28 | agent_command 3, remote_4624 12 | – | BenignMon | s06-winrm-1: admin_it (admin_it); s06-winrm-2: admin_it (admin_it); s06-smb-1: svc_backup (admin_it) | s06-winrm-1: WinRM; s06-winrm-2: WinRM; s06-smb-1: SMB |
| s06_t07 | 2026-10-27 07:05:33 → 07:10:09 | agent_command 3, remote_4624 13 | – | BenignMon | s06-winrm-1: admin_it (admin_it); s06-winrm-2: admin_it (admin_it); s06-smb-1: svc_backup (admin_it) | s06-winrm-1: WinRM; s06-winrm-2: WinRM; s06-smb-1: SMB |
| s06_t08 | 2026-10-27 07:17:49 → 07:21:24 | agent_command 3, remote_4624 13 | – | BenignMon | s06-winrm-1: admin_it (admin_it); s06-winrm-2: admin_it (admin_it); s06-smb-1: svc_backup (admin_it) | s06-winrm-1: WinRM; s06-winrm-2: WinRM; s06-smb-1: SMB |
| s06_t09 | 2026-10-27 07:24:19 → 07:32:10 | agent_command 3 | – | – | s06-winrm-1: none (admin_it); s06-winrm-2: none (admin_it); s06-smb-1: none (admin_it) | s06-winrm-1: WinRM; s06-winrm-2: WinRM; s06-smb-1: SMB |
| s06_t10 | 2026-10-27 07:59:03 → 08:02:37 | agent_command 3, remote_4624 8 | – | BenignMon | s06-winrm-1: admin_it (admin_it); s06-winrm-2: none (admin_it); s06-smb-1: svc_backup (admin_it) | s06-winrm-1: WinRM; s06-winrm-2: WinRM; s06-smb-1: SMB |
| s07_t01 | 2026-10-27 08:40:57 → 08:45:38 | dump 2, agent_command 2, remote_4624 5 | dump_ep-01 2/2 | SyncService, XferService | s07-X: svc_backup (svc_backup); s07-Y: svc_backup (svc_sql) | s07-X: SMB; s07-Y: SMB |
| s07_t02 | 2026-10-27 08:48:13 → 08:52:37 | dump 2, agent_command 2, remote_4624 5 | dump_ep-01 2/2 | SyncService, XferService | s07-X: svc_backup (svc_backup); s07-Y: svc_backup (svc_sql) | s07-X: SMB; s07-Y: SMB |
| s07_t03 | 2026-10-27 08:55:05 → 08:59:49 | dump 2, agent_command 2, remote_4624 5 | dump_ep-01 2/2 | SyncService, XferService | s07-X: svc_backup (svc_backup); s07-Y: svc_backup (svc_sql) | s07-X: SMB; s07-Y: SMB |
| s07_t04 | 2026-10-27 09:01:54 → 09:06:18 | dump 2, agent_command 2, remote_4624 5 | dump_ep-01 2/2 | SyncService, XferService | s07-X: svc_backup (svc_backup); s07-Y: svc_backup (svc_sql) | s07-X: SMB; s07-Y: SMB |
| s07_t05 | 2026-10-27 09:09:18 → 09:13:39 | dump 2, agent_command 2, remote_4624 5 | dump_ep-01 2/2 | SyncService, XferService | s07-X: svc_backup (svc_backup); s07-Y: svc_backup (svc_sql) | s07-X: SMB; s07-Y: SMB |
| s07_t06 | 2026-10-27 09:15:46 → 09:20:00 | dump 2, agent_command 2, remote_4624 5 | dump_ep-01 2/2 | SyncService, XferService | s07-X: svc_backup (svc_backup); s07-Y: svc_backup (svc_sql) | s07-X: SMB; s07-Y: SMB |
| s07_t07 | 2026-10-27 09:22:17 → 09:27:14 | dump 2, agent_command 2, remote_4624 5 | dump_ep-01 2/2 | SyncService, XferService | s07-X: svc_backup (svc_backup); s07-Y: svc_backup (svc_sql) | s07-X: SMB; s07-Y: SMB |
| s07_t08 | 2026-10-27 09:30:37 → 09:36:49 | dump 2, agent_command 2, remote_4624 5 | dump_ep-01 2/2 | SyncService, XferService | s07-X: svc_backup (svc_backup); s07-Y: svc_backup (svc_sql) | s07-X: SMB; s07-Y: SMB |
| s07_t09 | 2026-10-27 09:39:26 → 09:45:33 | dump 2, agent_command 2, remote_4624 5 | dump_ep-01 2/2 | SyncService, XferService | s07-X: svc_backup (svc_backup); s07-Y: svc_backup (svc_sql) | s07-X: SMB; s07-Y: SMB |
| s07_t10 | 2026-10-27 09:56:44 → 10:02:19 | dump 2, agent_command 2, remote_4624 5 | dump_ep-01 2/2 | SyncService, XferService | s07-X: svc_backup (svc_backup); s07-Y: svc_backup (svc_sql) | s07-X: SMB; s07-Y: SMB |

## 3. Scenario verdicts and draft redo list

| scenario | validated / expected | verdict | failing trials | fails per criterion | all failing share b |
|---|---|---|---|---|---|
| s02 | 10 / 10 | pass | - | - | False |
| s03 | 10 / 10 | replace 1 | s03_t08 | {'b': 1, 'c': 1, 'e': 1} | False |
| s04 | 10 / 10 | full rerun | s04_t01, s04_t02, s04_t03, s04_t04, s04_t05, s04_t06, s04_t07, s04_t08, s04_t09, s04_t10 | {'b': 10, 'c': 10, 'd': 10} | True |
| s06 | 10 / 10 | replace 2 | s06_t09, s06_t10 | {'a': 1, 'b': 2} | True |
| s07 | 10 / 10 | full rerun | s07_t01, s07_t02, s07_t03, s07_t04, s07_t05, s07_t06, s07_t07, s07_t08, s07_t09, s07_t10 | {'c': 10} | False |

**Draft redo list** (replacements are numbered from `trial_11`; broken trials are archived, not deleted; the owner approves):

| scenario | count | reason |
|---|---|---|
| s03 | 1 | s03_t08: b,c,e |
| s04 | 10 (full rerun) | s04_t01: b,c,d; s04_t02: b,c,d; s04_t03: b,c,d; s04_t04: b,c,d; s04_t05: b,c,d; s04_t06: b,c,d; s04_t07: b,c,d; s04_t08: b,c,d; s04_t09: b,c,d; s04_t10: b,c,d |
| s06 | 2 | s06_t09: a,b; s06_t10: b |
| s07 | 10 (full rerun) | s07_t01: c; s07_t02: c; s07_t03: c; s07_t04: c; s07_t05: c; s07_t06: c; s07_t07: c; s07_t08: c; s07_t09: c; s07_t10: c |

## 4. Findings per scenario (evidence)

**S02 — pass.** Dump on ep-01, agent command naming ep-02, `svc_backup` 4624 from 192.168.50.21, ADMIN$ binary write, service `PktDropService` in all 10. t03/t04: no dc01 Security or Sysmon file (a WARN, g n/a as the owner asked).

**S03 — replace 1.** Nine trials show dump → `Invoke-Command` naming ep-03 → `admin_it` 4624 on ep-03 from .21 → WinRM. s03_t08: the DB's last cluster is 2026-10-15 09:20:00–09:24:36 UTC, starting with boot events (6005 on ep-01 09:20:42, ep-03 09:20:53, dc01 09:21:26); splunkd beacons only from ep-02/ep-03 (3), none from ep-01; 597 lsass accesses, all system tools; no 4624 on ep-03 from .21. With no design anchor in that cluster, the validator's window fell on an older fragment (2026-10-12 07:04, one admin_it 4624 on ep-02); the conclusion is the same either way. Most likely the trial was aborted by a reboot.

**S04 — full rerun.** Track B (agent, `svc_backup`, `UpdaterService`) is present in all 10. Track A (manual, decision 021): in every trial `admin_it` logs on to ep-02 as type 3 from **192.168.50.99 (DESKTOP-VSUAVJ5, not a lab VM)**, `wsmprovhost.exe` starts, and in that session `sc.exe create HealthAgentSvc binPath= "C:\Windows\System32\cmd.exe /c exit"`, `sc start`, `sc delete` run (4697 `HealthAgentSvc` by `admin_it`, SubjectLogonId = that logon; checked in t01, t05, t10). There is no admin_it command on ep-01 naming ep-02, no ADMIN$ write by admin_it (5145 ADMIN$ is `svc_backup`/`Stage.exe` only), and the service image is not an `.exe` under `C:\Windows\`. In t00 Track A ran from ep-01 (`net use \\192.168.50.22\ADMIN$`, `HealthAgent.exe` copied, `sc \\192.168.50.22 create`). So b (Track A command, binary write, service), c (admin_it never on ep-02 from ep-01's IP) and d (no ADMIN$ binary write) fail. Track A was performed, but as a different design.

**S06 — replace 2.** t01–t08: both WinRM hops and the SMB hop are present, `BenignMon` created, no rundll32 → lsass (d PASS). `s06-smb-1`'s target-side account is `svc_backup` in all trials (the 4697 SubjectLogonId), as in t00 (decision 024); c passes because an `admin_it` logon from ep-01 is present in the window (N9 counts the whole window). t09: no ep-02/ep-03 folders (a FAIL, b FAIL). t10: ep-01 runs `Invoke-Command -ComputerName Endpoint-03.lab.local` at 08:00:45.88 UTC, but ep-03 has no network 4624 from ep-01 in the run; ep-03 Security continues to 08:02:16.99 (91 s later); the WinRM 91 / `wsmprovhost` on ep-03 at 08:02:21 come from 192.168.50.97, not ep-01. b FAIL (winrm-2 logon and WinRM step), c WARN.

**S07 — full rerun.** Two dumps, two agent commands naming ep-02, two `svc_backup` 4624s from .21, `SyncService` and `XferService` in all 10. `svc_sql` appears only on ep-01 (command lines, 4648, Sysmon 1/3) and dc01 (4768/4769), never on ep-02 (0 rows in t01, t06, t10). Criterion c (design account `svc_sql` for Y, owner's answer) fails in all 10. This is the same pattern as t00 (decision 027): the ability runs with the agent's `svc_backup` token, so a rerun of the same ability will probably log the same; the decision 027 TODO condition ("no trial shows svc_sql on the target") is met.

**Non-lab workstations.** At the end of most trials `admin_it` WinRM sessions from 192.168.50.97 (ARSU-MAEHAE), .98 and .99 (DESKTOP-VSUAVJ5) start `wsmprovhost.exe` on every host (log collection, inferred). They are not part of any design and the validator ignores them for b and c (N8, N9). They will reach the gate as R8 WinRM candidates unless the trial window clip (PLAN T6.4) excludes them.

## 5. Clock offsets (criterion g)

Offsets come from endpoint 4624 ↔ dc01 4769 pairs with the same LogonGuid (N11). In the report, `dc01|ep-01: +24.7` means dc01 minus ep-01, so ep-01 is **behind** dc01. S02/S03 (2026-10-15): within 5 s except ep-03 (5–10 s) in some trials. S04, S05q, S06, S07 (2026-10-26/27): ep-01 is 10–27 s behind dc01 and ep-02/ep-03 in almost every trial; ep-02 is within a few seconds of dc01. This is far beyond the 5 s tolerance of decision 014, which "move after the dump" (Correction K) relies on: the dump is on ep-01 and the move on ep-02. g is a WARN under 029 and does not change a verdict, but decision 014 needs a review before the identity score is computed on these trials (owner question 5).

## 6. Measurement choices made after the data was seen (owner to accept or reject)

029 says any measurement detail beyond the table is recorded as an implementation note, not a new criterion. These two affect statuses:

1. **f window anchors.** The validator brief also counted every endpoint-to-endpoint user 4624 as an anchor. Background `admin_it` logons then stretched the window into the next trial and f failed for most trials. The FAIL now uses the anchors 029 itself names (design commands, dumps, design target logons); the broad window still finds the trial's run and the older clusters, and its overlaps are listed as "f(broad, info)".
2. **f window end clipped at the DB's last event.** Trials ran 5–6 min apart, less than the 60 s lead + 300 s tail, so even design windows of consecutive trials overlap by time although no event is shared (each DB ends at its export, before the next trial's first anchor). The validator clips each window at the export end (precedent: decision 026, export span as outer clip); unclipped overlaps are listed as "f(unclipped, info)". **If the owner rejects the clip, f is FAIL for most S02–S07 trials and every scenario would need a full rerun on f alone.**

## 7. Quarantine: S05 ×10 (decision 030; never scored)

| trial | a | b | c | d | e | f | g | h | i | evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| s05q_t01 | PASS | FAIL | PASS | n/a | FAIL | WARN | WARN | PASS | PASS | b: missing dump_ep-01 (0/1),dump_ep-02 (0/1),s05-h1:command; e: no agent beacon on ['ep-02']; f: 2 older cluster(s); f(unclipped, info): overlaps s05q_t02; g: pairs>5s {'dc01|ep-01': 16.165, 'ep-01|ep-02': -14.962, 'ep-01|ep-03': -20.691, 'ep-02|ep-03': -5.729} |
| s05q_t02 | PASS | FAIL | PASS | n/a | FAIL | WARN | WARN | PASS | PASS | b: missing dump_ep-01 (0/1),dump_ep-02 (0/1),s05-h1:command; e: no agent beacon on ['ep-02']; f: 2 older cluster(s); f(unclipped, info): overlaps s05q_t01; g: pairs>5s {'dc01|ep-01': 10.466, 'ep-01|ep-02': -9.951, 'ep-01|ep-03': -11.2} |
| s05q_t03 | PASS | FAIL | PASS | n/a | FAIL | WARN | WARN | PASS | PASS | b: missing dump_ep-01 (0/1),dump_ep-02 (0/1),s05-h1:command; e: no agent beacon on ['ep-02']; f: 2 older cluster(s); f(unclipped, info): overlaps s05q_t04; g: pairs>5s {'dc01|ep-01': 14.053, 'ep-01|ep-02': -13.981, 'ep-01|ep-03': -16.142} |
| s05q_t04 | PASS | FAIL | PASS | n/a | FAIL | WARN | WARN | PASS | PASS | b: missing dump_ep-01 (0/1),dump_ep-02 (0/1),s05-h1:command; e: no agent beacon on ['ep-02']; f: 2 older cluster(s); f(unclipped, info): overlaps s05q_t03,s05q_t05; g: pairs>5s {'dc01|ep-01': 13.665, 'ep-01|ep-02': -14.76, 'ep-01|ep-03': -18.274} |
| s05q_t05 | PASS | FAIL | PASS | n/a | FAIL | WARN | WARN | PASS | PASS | b: missing dump_ep-01 (0/1),dump_ep-02 (0/1),s05-h1:command; e: no agent beacon on ['ep-02']; f: 2 older cluster(s); f(unclipped, info): overlaps s05q_t04; g: pairs>5s {'dc01|ep-01': 15.302, 'ep-01|ep-02': -15.605, 'ep-01|ep-03': -18.172} |
| s05q_t06 | FAIL | FAIL | FAIL | n/a | FAIL | PASS | WARN | PASS | WARN | a: missing ep-02/powershell,ep-02/security,ep-02/sysmon,ep-02/system,ep-02/winrm,ep-03/powershell,ep-03/security,ep-03/sysmon,ep-03/system,ep-03/winrm; b: missing dump_ep-01 (0/1),dump_ep-02 (0/1),s05-h1:command,s05-h1:logon,s05-h2:command,s05-h2:logon,s05-h2:winrm; c: intended not seen s05-h1,s05-h2; e: no agent beacon on ['ep-02']; g: pairs>5s {'dc01|ep-01': 12.278}; i: differs in hosts_present,steps_found,target_accounts,protocols |
| s05q_t07 | PASS | FAIL | PASS | n/a | FAIL | WARN | WARN | PASS | PASS | b: missing dump_ep-01 (0/1),dump_ep-02 (0/1),s05-h1:command; e: no agent beacon on ['ep-02']; f: 2 older cluster(s); f(unclipped, info): overlaps s05q_t08; g: pairs>5s {'dc01|ep-01': 13.988, 'ep-01|ep-02': -13.985, 'ep-01|ep-03': -15.469} |
| s05q_t08 | PASS | FAIL | PASS | n/a | FAIL | WARN | WARN | PASS | PASS | b: missing dump_ep-01 (0/1),dump_ep-02 (0/1),s05-h1:command; e: no agent beacon on ['ep-02']; f: 2 older cluster(s); f(unclipped, info): overlaps s05q_t07,s05q_t09; g: pairs>5s {'dc01|ep-01': 15.475, 'ep-01|ep-02': -15.832, 'ep-01|ep-03': -17.625} |
| s05q_t09 | PASS | FAIL | PASS | n/a | FAIL | WARN | WARN | PASS | PASS | b: missing dump_ep-01 (0/1),dump_ep-02 (0/1),s05-h1:command; e: no agent beacon on ['ep-02']; f: 2 older cluster(s); f(unclipped, info): overlaps s05q_t08,s05q_t10; g: pairs>5s {'dc01|ep-01': 13.272, 'ep-01|ep-02': -15.267, 'ep-01|ep-03': -15.468} |
| s05q_t10 | PASS | FAIL | PASS | n/a | FAIL | WARN | WARN | PASS | PASS | b: missing dump_ep-01 (0/1),dump_ep-02 (0/1),s05-h1:command; e: no agent beacon on ['ep-02']; f: 2 older cluster(s); f(unclipped, info): overlaps s05q_t09; g: pairs>5s {'dc01|ep-01': 12.978, 'ep-01|ep-02': -12.085, 'ep-01|ep-03': -17.599, 'ep-02|ep-03': -5.514} |

| scenario | validated / expected | verdict | failing trials | fails per criterion | all failing share b |
|---|---|---|---|---|---|
| s05q | 10 / 10 | full rerun | s05q_t01, s05q_t02, s05q_t03, s05q_t04, s05q_t05, s05q_t06, s05q_t07, s05q_t08, s05q_t09, s05q_t10 | {'b': 10, 'e': 10, 'a': 1, 'c': 1} | True |

Evidence (data-checker, s05q_t01): ep-01 runs `Invoke-Command -ComputerName Endpoint-02.lab.local -ScriptBlock { hostname }` as `svc_backup` (4688 06:35:01.5 UTC); ep-01 → 192.168.50.22:5985 (Sysmon 3 ×2); ep-02 has `svc_backup` type 3 Kerberos logons from .21 (×5), WinRM 91 (clientIP 192.168.50.21) and `wsmprovhost.exe`; no 5145 ADMIN$, no 7045/4697 on ep-02; no rundll32 → lsass Sysmon 10 on any host in the whole DB. Hop 2 (WinRM ep-02 → ep-03, `admin_it`) is present. e FAILs because no agent beacon is seen on ep-02, which the design needs for the hop 2 commands. The design (decision 029: SMB hop 1 with dumps on ep-01 and ep-02) was not run, so the wrong-design claim is supported. S05 needs a full rerun (decision 030); the owner decides.

## 8. t00 sanity run (not part of any verdict)

| trial | a | b | c | d | e | f | g | h | i | evidence |
|---|---|---|---|---|---|---|---|---|---|---|
| s02_t00 | WARN | FAIL | PASS | n/a | PASS | PASS | PASS | WARN | WARN | a: missing dc01/powershell,dc01/winrm,ep-01/powershell,ep-01/winrm,ep-02/powershell,ep-02/winrm,ep-03/powershell,ep-03/security,ep-03/sysmon,ep-03/system,ep-03/winrm; b: missing s02-h1:service; h: 0 same-run dup, 2 identifiable(non-user token,self-target); i: differs in hosts_present,steps_found,service_names |
| s03_t00 | WARN | PASS | PASS | n/a | PASS | WARN | PASS | PASS | WARN | a: missing dc01/powershell,dc01/sysmon,dc01/winrm,ep-02/powershell,ep-02/security,ep-02/sysmon,ep-02/system,ep-02/winrm; f: 1 older cluster(s); i: differs in hosts_present |
| s04_t00 | WARN | PASS | PASS | PASS | PASS | PASS | PASS | PASS | WARN | a: missing dc01/powershell,dc01/sysmon,dc01/winrm,ep-01/powershell,ep-01/winrm,ep-02/powershell,ep-02/winrm,ep-03/powershell,ep-03/security,ep-03/sysmon,ep-03/system,ep-03/winrm; i: differs in hosts_present,steps_found,service_names,target_accounts,protocols |
| s05_t00 | WARN | PASS | PASS | n/a | PASS | WARN | PASS | PASS | n/a | a: missing dc01/powershell,dc01/winrm,ep-01/winrm; f: 1 older cluster(s); f(broad, info): overlaps s03_t08 |
| s06_t00 | WARN | PASS | PASS | PASS | PASS | WARN | PASS | PASS | PASS | a: missing dc01/powershell,dc01/sysmon,dc01/system,dc01/winrm,ep-01/system,ep-01/winrm,ep-02/powershell,ep-02/winrm,ep-03/powershell,ep-03/system; f: 2 older cluster(s) |
| s07_t00 | WARN | PASS | FAIL | n/a | PASS | WARN | PASS | PASS | WARN | a: missing dc01/powershell,dc01/sysmon,dc01/system,dc01/winrm,ep-01/system,ep-01/winrm,ep-02/powershell,ep-02/winrm,ep-03/powershell,ep-03/security,ep-03/sysmon,ep-03/system,ep-03/winrm; c: intended not seen s07-Y; f: 1 older cluster(s); i: differs in hosts_present |

The validator reproduces what the approved t00 keys record: s02_t00 b FAIL is the missing service of the real run (decision 025: the stray run created it first, h WARN on the stray SYSTEM/self-target runs); s07_t00 c FAIL is the `svc_backup`-for-Y pattern (decision 027). a WARNs on t00 are because the dry-run export did not include every channel, and t00 criterion a counts DB rows (N14).

## 9. Independent cross-check (data-checker, hand-written SQL, before reading the validator output)

| claim | hand SQL | validator | agree |
|---|---|---|---|
| S04 Track A not from ep-01 (t01, t05, t10) | admin_it 4624 on ep-02 from .99 (×4) (+ .97 ×3 in t05/t10); 5145 ADMIN$ only svc_backup; 0 admin_it commands on ep-01 naming ep-02 | d FAIL, 0 admin_it binary writes | yes |
| S07 svc_sql never on ep-02 (t01, t06, t10) | ep-02 4624 from .21: svc_backup ×5, svc_sql 0; svc_sql only on dc01 and ep-01 | c FAIL, hop Y accounts [svc_backup] | yes |
| s03_t08 has no run | last cluster 09:20:00–09:24:36 after reboot; 0 ep-01 beacons; 0 user-token dumps; 0 4624 on ep-03 from .21 | b, c, e FAIL | yes (window differs, see §4) |
| s06_t10 no ep-03 logon from ep-01 | command 08:00:45.88; 0 network 4624 on ep-03 in run; Security continues to 08:02:16.99 | b FAIL (winrm-2 logon, winrm) | yes |
| s06_t04 clock | ep-01 − dc01 median −25.04 s (2 pairs); ep-02 −1.52 s (12); ep-03 +4.84 s (7) | ep-01 −24.66 s (1); ep-02 −1.27 s (7); ep-03 +2.35 s (2) | yes (ep-03 differs by window width) |
| s05q_t01 hop 1 protocol | WinRM (5985, WinRM 91, wsmprovhost); 0 ADMIN$, 0 services, 0 rundll32→lsass | b FAIL (command, dumps missing) | yes |

## 10. Owner questions

1. **f window (§6):** accept the 029-anchor window and the clip at the export end? (If not, f FAILs almost everywhere.)
2. **Decision 3 "fail on the same design criterion (b)":** implemented as ≥ 6 of 10 failing. S06 has 2 failing trials, both on b, for different reasons (missing files; missing logon). Replace 2 (as reported) or full rerun?
3. **S04 Track A:** rerun with the t00 design (manual SMB from ep-01's desktop session, binary to ADMIN$, `sc \\ep-02 create`), or accept the WinRM-from-a-workstation variant through a new decision record? The current variant comes from a host outside the lab, so its source host has no logs.
4. **S07:** rerun (probably logs `svc_backup` again unless the ability uses `svc_sql` credentials so that the target sees them), or keep the 10 trials and record the limitation (decision 027 TODO)?
5. **Clock offsets of 10–27 s** on 2026-10-26/27: review decision 014 (5 s tolerance) before identity is scored on S04–S07; for reruns, sync the clocks (w32tm) before each run.
6. **s03_t08 and s06_t10:** confirm replacement by `trial_11` (draft redo list).

## 11. Implementation notes (from the validator; 029 "Consequences")

- N1 run window: anchors = agent-tree commands naming a lab endpoint (any host, self-targets included), rundll32->lsass Sysmon 10 dumps by a user token, and 4624 type 3/10 on an endpoint from another endpoint's IP with a user account. Anchors are split into clusters where the gap exceeds 30 min; the trial's own run is the LAST cluster; search window = [first anchor - 60 s, last anchor + 300 s]. Older clusters are reported under f (WARN). The f overlap FAIL uses the 029 design window = [first - 60 s, last + 300 s] over design anchors only (executions of design command steps, user-token dumps in the window, target 4624s tied to design hops); broad-window overlaps are reported, not failed. Both window ends are clipped at the DB's last event (export end; decision 026 amendment uses the export span as an outer clip); overlaps of the unclipped design window are reported, not failed.
- N2 agent tree: Sysmon 1 whose ParentImage is exactly C:\Users\Public\splunkd.exe, plus Sysmon 1 roots with ParentImage '-' tied by a 4688 (same host, same PID, identical command line, parent splunkd, within 3 s); all descendants by ParentProcessGuid. 4688 rows with the same host, PID and command line within 3 s are recorded as corroboration. Only on a host with no Sysmon 1 in the run is the tree built from 4688 by parent PID (marked tree_source=4688_pid_chain).
- N3 one execution = one direct splunkd child (Caldera link) for agent commands; manual commands (not in the agent tree, user token) are grouped by host, logon session and target with gaps <= 120 s.
- N4 naming the target: case-insensitive, boundary-aware match of ep-0N, endpoint-0N, endpoint-0N.lab.local and 192.168.50.2N (192.168.50.2 never matches .22) on the full command line plus the UTF-16LE decoding of any -enc/-EncodedCommand payload.
- N5 protocol of a command: SMB when it names the target in a UNC path (\\target\...) or uses psexec; WinRM when it uses Invoke-Command, New-PSSession, Enter-PSSession, winrs, wsman or -ComputerName.
- N6 hop binding: the target 4624s of a command are those on the target from the source IP, type 3/10, user account, in [command - 10 s, last command + 120 s] (capped at the next command of the same lane naming the same target); when a 5145/4697 whose file or service name appears in the command has a SubjectLogonId equal to a 4624 TargetLogonId (or a wsmprovhost session equals it), only those 4624s are kept (binding logon_id_artifact), else all in the window (binding time_window).
- N7 binary write = 5145 on ADMIN$ whose RelativeTargetName ends .exe/.dll and whose AccessMask has WriteData or AppendData; service created = 7045 or 4697 on the target whose image is an .exe directly under C:\Windows\, logged at or after the hop's first tied 4624 (same host clock).
- N8 WinRM step = WinRM 91 on the target in the command window with clientIP = source IP, or a Sysmon 1 wsmprovhost.exe on the target in the command window whose LogonId is the TargetLogonId of a 4624 from the source IP. WHY: at the end of the x10 trials admin_it WinRM sessions from non-lab workstations (192.168.50.97/.98/.99; log collection, inferred) start wsmprovhost.exe on every host.
- N9 criterion c uses the whole trial window: the intended account must appear in a 4624 (type 3/10) on the target from the source IP, a 5145 on the target from the source IP, or a 4697 on the target whose SubjectLogonId is a logon from the source IP (4697s of other logons are listed as 4697_other_source, not counted); the accounts tied to the hop are reported next to it.
- N10 criterion e: the trial run for agent beacons starts at the first anchor and walks back through splunkd process starts and splunkd->192.168.50.50:8888 Sysmon 3 events while gaps are <= 30 min, never before the end of the previous anchor cluster's window.
- N11 criterion g: endpoint 4624 and dc01 4769 with the same LogonGuid in the window +- 30 min, mutual-nearest pairs per host, offset = host time - dc01 time, median per host; host-pair offset = difference of medians (dc01 = 0). Lower bounds = source command time - target 4624 time when the 4624 is logged first. dc01 Security absent -> n/a (WARN if a lower bound exceeds 5 s).
- N12 criterion h counts executions (N3) of each command step and dumps (N1 grouping, 1 s) of each dump step. Extra runs by the same user on the same source naming the same target -> FAIL; extra runs by another user, by a non-user token, self-targeted, or from another host -> WARN.
- N13 criterion i: shape = hosts with logs, design steps found, service names, target-side accounts per hop, protocols per hop; compared with the most common shape of the scenario's x10 trials (strict majority, at least 2 trials); no majority -> n/a.
- N14 criterion a reads out/ingest/x10/<trial>/ingest.json (files_missing). For t00 with --no-ingest-check it reads the DB's (host, channel) row counts instead, which cannot tell an empty file from a missing one.
- N15 quarantine DBs keep scenario_id s05 / trial_id tNN in their rows; the trial id is taken from the file name (s05q_tNN) per decision 030.

### Open points / not measurable (validator)

- Criterion f window: decision 029 names the window anchors 'agent-child commands of the design, rundll32 -> lsass dumps, target 4624 of design hops' (the f FAIL status uses this design window). The validator brief also counted every endpoint-to-endpoint user 4624 as an anchor (the broad cluster window, used to find the run and older clusters). In back-to-back x10 trials the broad window reaches into the next trial; those overlaps are shown as 'f(broad, info)' and do not set FAIL. Owner decides which window 029 means.
- Criterion f window end: the x10 trials ran about 5-6 min apart, shorter than the 300 s tail plus the 60 s lead, so the literal design windows of consecutive trials overlap although no event is shared (each trial's DB ends at its export, before the next trial's first anchor). The validator clips every window end at the DB's last event (precedent: decision 026 amendment, export span as outer clip); unclipped overlaps are shown as 'f(unclipped, info)'. Owner confirms or rejects the clip.
- Decision 3 'full rerun ... or they fail on the same design criterion (b)': implemented as >= 6 of 10 trials failing (any criterion, or the same criterion); the flag 'all failing trials share b' is shown for the owner when 2-5 trials fail and all of them on b. Owner decides whether that alone means a full rerun.
- Criterion a counts files (ingest.json). An exported but empty channel (0 rows) is listed as 'present_but_no_rows_in_db' and does not change the status.
- Criterion g with dc01 Security present but no LogonGuid pair near the window is reported n/a (not measurable), not PASS.
- Criterion i needs a strict majority of at least 2 x10 trials of the scenario; until then it is n/a.

## 12. Tests

`tests/unit/test_x10_validate.py`, 72 tests, all pass (written from decision 029 by the tester, not from the code); full unit suite passes.
- Import independence: `ast` scan and a fresh-interpreter `sys.modules` check (no `answer_key`, `log_check`, `data_layout`, `evtx_pipeline`, `parsing_normalization`, `*stitch*`); stdlib only; no `ground_truth` / `out/log_check` path in the source.
- Read-only: DB bytes and mtime unchanged after a run; writes through the connection fail.
- One synthetic failing or WARN case per criterion a–i with the 029 severity (incl. S06 c = WARN, g = n/a without dc01 Security, h FAIL vs WARN), the verdict rule (0 → pass, 2 → replace 2, 6 of 10 → full rerun, WARNs never change it), quarantine identity from the file name (030), and real-data checks on s02_t01 (no FAIL) and s02_t03 (a WARN, g n/a).
- Not covered synthetically (tested only through the real runs): the S03, S05 and S07 design chains, the S06 b chain, criterion a from `ingest.json`, the e walk-back and the f clip at the export end.
