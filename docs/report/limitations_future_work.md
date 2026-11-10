# Report: limitations and future work (running list)

Continues the lists in `docs/handoff_18.md` §22.5 (W1–W6), §24.4 (L7–L9) and §24.5 (F5–F8). New items get the next number. Each item links its evidence.

## Limitations

| # | Limitation | Evidence |
|---|---|---|
| L10 | **SMB connections were not logged by Sysmon.** The configuration (SwiftOnSecurity v74) has no rule for `System` or port 445, so the SMB trials have no source-side Sysmon 3 row. SMB hops are linked from target-side 4624 (source IP, IpPort, account, time), 5140/5145 and 7045, plus the source session whose command line names the target. The source-side join is by command-line target and time, not by port, so it can leave more than one candidate session. Even with Sysmon 3, the SMB connection belongs to `System`, so session attribution would still come from the command process. | Decision 011; `docs/research/sysmon_config_check.md` |
| L11 | **Command-line join generalisation is untested.** The source-session join for SMB works in the lab because the Caldera scripts name targets by literal IP (`net use \\192.168.50.22\…`, `sc.exe \\192.168.50.22 …`). Real attackers may use host lists, encoded or obfuscated commands, WMI/DCOM, or tools run from unlogged hosts; then the join finds no candidate and the hop stays `target_only`. | Decision 013 (owner clarification 2); `docs/research/data_reality.md` |
| L12 | **Identity does not separate S04's two tracks.** The admin account had sessions open on the source host at the dump, so both the admin track and the attack track score 1 (exposed ≠ stolen). The S04 ablation is reported with this limitation; Correction K is unchanged. | Decision 018; handoff Correction H.2 |

## Future work

| # | Item | Evidence |
|---|---|---|
| F9 | **Log port 445 (and 5985 on the target) in Sysmon Event 3** for new collections: one include rule `<DestinationPort name="SMB" condition="is">445</DestinationPort>` in the endpoint config, loaded with `Sysmon64 -c` (records an Event 16 with the new hash). It gives a source-port join for SMB hops; the session still comes from the command process. | Decision 011; `docs/research/sysmon_config_check.md` §5 |
