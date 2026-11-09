# Sysmon configuration check (read-only, 2026-11-10)

Input: `docs/lab/sysmon_DC-01.txt.xml` (supplied by the user from DC01). Data: the seven t00 databases `data/processed/s0N_t00.sqlite3` (`events_dedup`) and the raw JSONL under `data/processed/jsonl/`. Scripts were run from the scratchpad; nothing in `src/`, `data/` or `docs/lab/` was changed.

**Short answer:** the Event 3 (network) rules of this file explain every endpoint Sysmon 3 row recorded during the dry runs, and they exclude exactly the missing SMB rows (`System` to 445). But the endpoints cannot have run this file unchanged: it disables Event 10 (ProcessAccess), and every endpoint logged thousands of Event 10 rows. **Verdict: not "consistent with one shared config".** DC01 matches this file; the endpoints ran a modified version whose Event 3 section is indistinguishable from this one in the data.

## 0. What the file is
- It is the configuration XML itself, not the output of `Sysmon64 -c`: it starts with the SwiftOnSecurity header ("sysmon-config … Source version: 74 | Date: 2021-07-08", `https://github.com/SwiftOnSecurity/sysmon-config`), `<Sysmon schemaversion="4.50">`, no fork changes declared. File modification time 2021-10-16.
- Because it is not `-c` output, it shows **no config path and no hash** (see item 3 for both, recovered from the logs).

## 1. Which network connections (Event 3) the file logs
`NetworkConnect onmatch="include"` (84 rules, any one admits the event) and `onmatch="exclude"` (9 rules, any one drops it). The same rules apply to inbound and outbound connections.
- **Include by image path:** begins with `C:\Users`, `C:\Recycle`, `C:\ProgramData`, `C:\Windows\Temp`, `\`, `C:\perflogs`, `C:\intel`, `C:\Windows\fonts`, `C:\Windows\system32\config`.
- **Include by image name:** a list of tools, among them `powershell.exe`, `powershell_ise.exe`, `cmd.exe`, `sc.exe`, `schtasks.exe`, `rundll32.exe`, `wmic.exe`, `net.exe`, `net1.exe`, `reg.exe`, `mshta.exe`, `regsvr32.exe`, `certutil.exe`, `psexec.exe`, `psexesvc.exe`, `mmc.exe`, `cscript.exe`, `wscript.exe` (lines 283–345).
- **Include by destination port:** 22, 23, 25, 143, **3389**, 5800, 5900, 4444, 1080, 3128, 8080, 1723, 9001, 9030 (lines 347–362). **445 and 5985 are not listed.**
- **Exclude:** Defender platform path, Teams, `*.microsoft.com` and two Akamai/NSATC names, two OCSP IPs, `127.0.0.1`, destination IP beginning `fe80:0:0:0` (lines 369–379).

| Connection | Rule that decides | Logged? |
|---|---|---|
| `System` to port 445 (SMB, both ends) | no include rule matches (`System` is not a path, 445 is not a listed port) | **No** |
| `mstsc.exe` to 3389 | `DestinationPort is 3389` [RDP] | **Yes** |
| `powershell.exe` to 5985 | `Image image powershell.exe` | **Yes** |
| inbound RDP on the target (`svchost.exe`, dest port 3389) | `DestinationPort is 3389` | Yes |
| inbound WinRM on the target (`System` or `wsmprovhost.exe`, 5985) | none | No |

## 2. Does the file explain the endpoint data?
Every Sysmon 3 row on ep-01, ep-02 and ep-03 in the seven t00 DBs was evaluated against the rules above (case-insensitive; `image` = full path or file name).

| Trial | ep-01 fits / misfits | ep-02 | ep-03 |
|---|---|---|---|
| s01 | 9 / 0 | 31 / 0 | 23 / **349** |
| s02 | 9 / 0 | 13 / 0 | – |
| s03 | 15 / 0 | – | 242 / **2** |
| s04 | 15 / 0 | 13 / 0 | – |
| s05 | 21 / 0 | 28 / 0 | 248 / 0 |
| s06 | 21 / 0 | 25 / 0 | 236 / 0 |
| s07 | 18 / 0 | 27 / 0 | – |

- **Admitted rows** are `splunkd.exe` in `C:\Users\Public` (ports 5353, 8888; rule `begin with C:\Users`), OneDrive in the user profile, `sc.exe` (135, 49699), `powershell.exe` (5985, 47001, 389, 445, 53, 88, 8888), `cscript.exe`, `mmc.exe`, and inbound `svchost.exe` to 3389 on s01 ep-02 (4 rows, `Initiated = false`).
- **The 349 misfits on s01 ep-03** all lie between 2026-09-11 09:19:09 and 09:41:09, before the Sysmon Event 16 at 09:41:43 that loaded this file (item 3). All 23 rows after the load fit. They come from the earlier configuration, not from this one.
- **The 2 misfits on s03 ep-03** are inbound `svchost.exe` to 5353 at 2026-09-24 09:37:08.293 and .295, 0.13 s before the Sysmon "Started" Event 4 at 09:37:08.426, which looks like a start-up artefact (expected, not verified).
- **Missing SMB rows fit the rules exactly:** no `System`-to-445 connection (source or target side) is admitted by any include rule, which is why s02, s04 and s07 have none (`docs/research/t3_data_findings.md` §1). The only 445 rows recorded are made by `powershell.exe` (image rule) or come from s01 ep-03 before the config load.
- **What does not fit — Event 10:** this file's `ProcessAccess onmatch="include"` is empty (lines 471–475: "Using include with no rules means nothing in this section will be logged"). Yet every endpoint logged Event 10 rows (e.g. s02 ep-01 1,297, s04 ep-02 214, s07 ep-02 468; all lsass readers, including the rundll32 dumps). DC01 logged no Event 10 and no Event 3 in any trial, which matches this file.
- s01 ep-03 (2026-09-03 to 09-15) has **0** Event 10 rows, so in that period ep-03 did run this file; Event 10 appears on ep-03 from the s03 export onward (2026-09-17). Handoff line 1257 ("Sysmon 10 off by default → enable `ProcessAccess`") fits a later change to the endpoint configs. That change left no Event 16 in any exported log (logs were cleared after it).

## 3. Config path, hash and version
- The supplied file shows no path or hash (item 0).
- **Its SHA-256 is `055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162`.**
- That is byte-for-byte the hash in the only Sysmon Event 16 in the data: s01_t00 `ep-03/sysmon.jsonl` line 85568, 2026-09-11 09:41:43, `Configuration = C:\LabTools\Sysmon\sysmonconfig-export.xml`, `ConfigurationFileHash = SHA256=055FEBC6…87162`. So DC01's file and ep-03's 2026-09-11 config are the same file.
- **Sysmon version 15.21, schema 4.91** on every host (Event 4 in every export).
- No Event 16 exists for ep-01, ep-02 or the later ep-03 configs, so the endpoint config used in the dry runs has **no recorded path or hash**.

## 4. Handoff mentions (`docs/handoff_18.md`)
- Line 502: Sysmon "Needs a real config (SwiftOnSecurity / Olaf Hartong) — default logs almost nothing".
- Line 1257: "Sysmon 10 off by default → enable `ProcessAccess`".
- Lines 1449–1450 (E1, E2): VBoxService and svchost access lsass, logged as Sysmon 10, which presupposes ProcessAccess enabled on the endpoints.
- **No config file name, version number or hash** is given anywhere in the handoff.

## 5. Smallest change for S01 ×10, and SMB
- **mstsc.exe to 3389: no change is needed** if the endpoints keep the rule `DestinationPort is 3389`, which is in this file and evidently in the endpoint config (s01 ep-02 logged inbound RDP `svchost.exe` to 3389). The source side (`mstsc.exe` on EP-01) is admitted by the same rule.
- **Before collecting, run `Sysmon64 -c` (no file argument) on EP-01 and EP-02** to print the running rules and hash, and save the output to `docs/lab/`. That removes the guess about the endpoint config.
- **Do not push the DC01 file to the endpoints.** It would turn Event 10 off (empty ProcessAccess include) and lose the LSASS evidence that IdentityCoherence needs (Correction K).
- **SMB for future trials:** add one line to the NetworkConnect include group of the *endpoint* config:
  `<DestinationPort name="SMB" condition="is">445</DestinationPort>`
  and load it with `Sysmon64 -c <file>`, which writes an Event 16 with the new hash. It logs `System` to 445 on the source and the inbound connection on the target. Cost: it also logs all SMB to DC01 (SYSVOL, GPO), so volume rises. Optional, for the WinRM target side: `<DestinationPort name="WinRM" condition="is">5985</DestinationPort>`.
- **It fixes SMB only for trials collected after the change.** S01 is RDP and does not need it. The SMB scenarios S02 to S07 ×10 are already collected without it, so the change helps only if those trials are re-run.

## Implication for later stages
Correction I's SMB anchor (`Image = System` in Sysmon 3) cannot exist in any collected SMB trial: the configuration never logged it. This affects a locked decision, so per CLAUDE.md it needs a council verdict in T4/T7 before the linking design is built (options include linking SMB hops from the target 4624 plus 5145/7045 and the source's command process, or re-running SMB trials with the 445 rule).
