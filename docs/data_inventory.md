# Data inventory: dry runs (trial t00)

Generated from `data/manifest.csv` (80 files copied from `data/incoming/dryrun`; 6 ignored, see `docs/decisions/001`–`003`).
Rule for expectations (user, 2026-11-09): DC01 needs Security only (Sysmon, System optional); source and target of each move need Security + Sysmon;
WinRM moves also need WinRM + PowerShell Operational on both ends; SMB service installs also need System on the target; a host that takes no part is **not involved**.
Topology comes from handoff §19–21 (findings files unavailable). Cells: `present (records)`, `real gap`, `optional`, `not involved`, `extra host`, `unconfirmed`.

Layout: `data/raw/<scenario>/<trial>/<host>/<channel>.evtx`; scenarios `s01`–`s07`; dry runs are `t00`, real trials `t01`–`t10`.

## S01 (**target side only — source EP-01 and DC01 files are S02 exports filed under S01**; excluded from the development set): RDP EP-01→EP-02 (handoff §21: svc_backup, 4624 Type 10)

| host | security | sysmon | system | winrm | powershell | psclassic |
|---|---|---|---|---|---|---|
| dc01 | present but S02 copy — not usable for S01 (14823) | present but S02 copy — not usable for S01 (343) | present but S02 copy — not usable for S01 (241) | optional | optional | optional |
| ep-01 | present but S02 copy — not usable for S01 (19301) | present but S02 copy — not usable for S01 (1806) | present but S02 copy — not usable for S01 (132) | optional | optional | optional |
| ep-02 | present (20346) | present (1857) | present (223) | optional | optional | optional |
| ep-03 | present (21582) **extra host** | present (86444) **extra host** | present (2490) **extra host** | present (1895) **extra host** | present (2207) **extra host** | not involved |

## S02: SMB + service EP-01→EP-02 (handoff §19.3: svc_backup→EP-02)

| host | security | sysmon | system | winrm | powershell | psclassic |
|---|---|---|---|---|---|---|
| dc01 | present (14823) | present (343) | present (241) | optional | optional | optional |
| ep-01 | present (19301) | present (1806) | present (132) | optional | optional | optional |
| ep-02 | present (7785) | present (642) | present (117) | optional | optional | optional |
| ep-03 | not involved | not involved | not involved | not involved | not involved | not involved |

## S03: WinRM EP-01→EP-03 (handoff: target changed EP-02→EP-03)

| host | security | sysmon | system | winrm | powershell | psclassic |
|---|---|---|---|---|---|---|
| dc01 | present (47875) | optional | present (762) | optional | optional | optional |
| ep-01 | present (7168) | present (1118) | present (131) | present (43) | present (190) | optional |
| ep-02 | not involved | not involved | not involved | not involved | not involved | not involved |
| ep-03 | present (749542) | present (12933) | present (1440) | present (2280) | present (2059) | optional |

## S04: SMB, two concurrent tracks to EP-02 (handoff §19.4)

| host | security | sysmon | system | winrm | powershell | psclassic |
|---|---|---|---|---|---|---|
| dc01 | present (28917) | optional | present (518) | optional | optional | optional |
| ep-01 | present (6403) | present (812) | present (128) | optional | optional | optional |
| ep-02 | present (7344) | present (618) | present (129) | optional | optional | optional |
| ep-03 | not involved | not involved | not involved | not involved | not involved | not involved |

## S05: SMB EP-01→EP-02, then WinRM EP-02→EP-03

| host | security | sysmon | system | winrm | powershell | psclassic |
|---|---|---|---|---|---|---|
| dc01 | present (43885) | present (800) | present (602) | optional | optional | optional |
| ep-01 | present (29024) | present (2009) | present (184) | optional | present (487) | present (3856) |
| ep-02 | present (46604) | present (992) | present (169) | present (2304) | present (3943) | present (5859) |
| ep-03 | present (774962) | present (13252) | present (1487) | present (2276) | present (2585) | present (5430) |

## S06: benign baseline — hosts unconfirmed, settle in T5

| host | security | sysmon | system | winrm | powershell | psclassic |
|---|---|---|---|---|---|---|
| dc01 | present (32029) unconfirmed | unconfirmed | unconfirmed | unconfirmed | unconfirmed | unconfirmed |
| ep-01 | present (8247) unconfirmed | present (1063) unconfirmed | unconfirmed | unconfirmed | present (151) unconfirmed | unconfirmed |
| ep-02 | present (32543) unconfirmed | present (960) unconfirmed | present (175) unconfirmed | unconfirmed | unconfirmed | unconfirmed |
| ep-03 | present (751299) unconfirmed | present (12947) unconfirmed | unconfirmed | present (2276) unconfirmed | unconfirmed | unconfirmed |

## S07: two SMB paths, both hit EP-02 (handoff: Path Y target EP-03→EP-02)

| host | security | sysmon | system | winrm | powershell | psclassic |
|---|---|---|---|---|---|---|
| dc01 | present (33830) | optional | optional | optional | optional | optional |
| ep-01 | present (8650) | present (1130) | optional | optional | present (71) | optional |
| ep-02 | present (36721) | present (1039) | present (181) | optional | optional | optional |
| ep-03 | not involved | not involved | not involved | not involved | not involved | not involved |

## Flags

- Byte-identical across scenarios: `s01/t00/dc01/security.evtx` = `s02/t00/dc01/security.evtx`
- Byte-identical across scenarios: `s01/t00/dc01/sysmon.evtx` = `s02/t00/dc01/sysmon.evtx`
- Byte-identical across scenarios: `s01/t00/dc01/system.evtx` = `s02/t00/dc01/system.evtx`
- Byte-identical across scenarios: `s01/t00/ep-01/security.evtx` = `s02/t00/ep-01/security.evtx`
- Byte-identical across scenarios: `s01/t00/ep-01/sysmon.evtx` = `s02/t00/ep-01/sysmon.evtx`
- Byte-identical across scenarios: `s01/t00/ep-01/system.evtx` = `s02/t00/ep-01/system.evtx`
- `s01/t00/ep-03/*` ends 2026-09-15; S01 ran 2026-09-24 (decision 001). Kept as extra host, holds no S01-run events.
- `s01/t00/ep-02/*` is `ep-01/Dryrun_S01/EP-02` (covers 2026-09-24); the 2026-09-15 export `ep-02/dryrun_s01` is excluded (decision 001).
- `s06/t00/ep-01/powershell.evtx` was `EP01_PowerShell.evt` with an EVTX header (decision 002).
- First/last event times in the manifest are file bounds, not run windows. The manifest `date` column is file mtime and is **unreliable** (earlier than the last event in most files); do not use it as export time.
- `s01/t00/ep-03` System and WinRM carry computer name `WIN-V4KV8HLJS0B` (pre-rename default name).

- S06 (benign baseline): expected hosts are **unconfirmed — settle in T5 answer keys**. This is not a gap.

## Time coverage (added after fact-check; the presence rule alone is not enough)
| scenario | host | file window (UTC, 2026-09-24) | status |
|---|---|---|---|
| s01 | dc01, ep-01 | 04:54 → 05:50 | **explained:** byte-identical to s02, ends before the S01 hop (S02 exports filed under S01) |
| s01 | ep-02 | 06:06 → 08:17 | target side present: 7 remote Type 3 logons from 192.168.50.21 at 07:44–08:07 |
| s01 | ep-01 Sysmon | 04:54 → 05:50 | 0 connections to port 3389, so the source side of the RDP hop is **missing** |

Not yet checked: time overlap for s02–s07 (to do in T4 with `/log-check`).

## Gap summary

- **S01 t00 ep-01 and dc01: explained, not fixed (decision 001).** The files end at 05:50, 16 minutes before EP-02's window starts, and match S02 byte for byte. User verdict: target side only — source EP-01 and DC01 files are S02 exports filed under S01. S01 t00 is excluded from the development set; S01 t01 replaces it.
- No presence gaps against the rule for S02–S05 and S07. S06 expectations are "unconfirmed — settle in T5 answer keys", not a gap.
