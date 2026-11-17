# Citations for the order-reference templates R1-R5 (spec 05 §5.1)

Date of research: 2026-11-18. ATT&CK pages were read on attack.mitre.org; the versions page lists v20.1 (13 Oct 2026) as current. The technique pages below show "Last Modified 12 May 2026" or later (v19 content, unchanged text in v20.x as far as the pages show). Quotes come from fetched page text; a few are fragments because the fetch tool truncates. Nothing here is derived from lab logs.

## Question
Which public sources support each consecutive transition in R1-R5, which transitions have no support, and are the tactic mappings (T1078, T1550.002) current and defensible?

## Answer
- Supported by ATT&CK pages plus at least one CISA/DFIR report: T1003.001 -> T1021.002 (R1, R3), T1003.001 -> T1021.001 (R2), T1021.002 -> T1570 and T1021.002 -> T1569.002 (R1, R3, R4), T1570 -> T1569.002 (R4).
- Supported only by composition or by weak evidence: T1078 -> T1003.001 (R1, R2, R5; campaign-level only), T1003.001 -> T1550.002 (R4; Mimikatz page lists both, no sentence states the order), T1550.002 -> T1021.002 (R4; no primary source names PtH with SMB/PsExec), T1003.001 -> T1021.006 (R5; generic "Valid Accounts" text only; no read report shows dump then WinRM).
- NOT supported by any source I read: T1021.001 -> T1569.002 (R2). ATT&CK T1569.002 does not mention RDP. The nearest evidence (BlackSuit) shows RDP-based execution of the ransomware, not service creation after RDP.
- Tactics: T1078 now lists Stealth, Persistence, Privilege Escalation, Initial Access (v3.0). T1550.002 now lists Lateral Movement only (v2.0). "Defense Evasion" was split in v19 (28 Apr 2026) into Stealth (TA0005, keeps the old ID) and Defense Impairment (TA0112). So the old "Defense Evasion" label on T1078 is now "Stealth", and T1550.002 lost it.
- T1078 -> initial-access is defensible (first listed tactic, only listed tactic that is about getting a foothold, and sorts before credential-access in the matrix). Caveat below on mid-chain use.

## Options and per-template evidence

### Transition-level evidence

| Transition | Templates | Source and supporting text | Strength |
|---|---|---|---|
| T1078 -> T1003.001 | R1 R2 R5 | ATT&CK T1003.001: credential material "can be harvested by an administrative user or SYSTEM and used to conduct" lateral movement (a valid privileged account is needed before the dump). Operation Wocao (C0014) has both "used valid VPN credentials to gain initial access" and Mimikatz/ProcDump credential dumping. CISA AA25-071A (Medusa): phishing to steal credentials for initial access, later "use Mimikatz, the Windows Task Manager, and comsvcs.dll for LSASS dumping". | Campaign-level order only. No source states "valid account, then LSASS dump" as one sequence. |
| T1003.001 -> T1021.002 | R1 R3 R4 | ATT&CK T1003.001 (credentials "used to conduct" lateral movement). CISA AA25-071A: "Medusa actors use Mimikatz ... for LSASS dumping [T1003.001] to harvest credentials ... and aid lateral movement"; "When provided with valid username and password credentials, Medusa actors use PsExec to: Execute an already existing local file on a remote machine with system-level privileges." The DFIR Report, Nitrogen/BlackCat: "The Cobalt Strike beacon was then used to dump domain credentials from LSASS", later "executing another batch script via PSEXEC on multiple remote hosts". | Good (dump first, PsExec later; SMB is implied by PsExec/ADMIN$ per S0029). |
| T1003.001 -> T1021.001 | R2 | ATT&CK T1021.001: "Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP." Aquatic Panda: "leveraged stolen credentials to move laterally via RDP". CISA AA25-071A: "Medusa actors use RDP ... to log into an interactive session with a system and move laterally." | Good. |
| T1021.002 -> T1569.002 | R1 R4 | ATT&CK S0029 PsExec: "writes programs to the ADMIN$ network share to execute commands on remote systems" (T1021.002) and "can be used to execute binaries on remote systems using a temporary Windows service" (T1569.002). ATT&CK T1021.002 description names Service Execution as an execution technique that relies on authenticated SMB/RPC sessions. | Good. |
| T1021.002 -> T1570 | R3 R4 | ATT&CK T1570: copying "using inherent file sharing protocols"; "file sharing over SMB/Windows Admin Shares". T1021.002 procedure examples: APT3 "will copy files over to Windows Admin Shares (like ADMIN$) as part of lateral movement." S0029: "can be used to download or upload a file over a network share." | Good (same SMB session; T1570 is the file-copy half). |
| T1570 -> T1569.002 | R4 | The DFIR Report, Nitrogen: "remotely copy the ransomware binary to the target machines before running the second batch script". DFIR Report, BlackSuit: "The psexec module functions by uploading a binary to the target system" and event 7045 shows the service created. Qilin / Netwalker on T1570 page: PsExec used to distribute the payload. | Good for copy-then-execute. ATT&CK itself gives no ordering sentence. |
| T1003.001 -> T1550.002 | R4 | ATT&CK Mimikatz S0002 lists both: T1003.001 "contains functionality to acquire information about credentials in many ways, including from the LSASS Memory" and T1550.002 "SEKURLSA::Pth module can impersonate a user, with only a password hash, to execute arbitrary commands." ATT&CK T1550.002: material is "typically created after a successful login and cached" so stolen material is used without the password. APT41 on T1550.002: "uses tools such as Mimikatz to enable lateral movement via captured password hashes." | Moderate. The dump-then-hash-reuse order follows from the definition, but no report I read states it as a sequence. |
| T1550.002 -> T1021.002 | R4 | ATT&CK T1550.002 says reuse is "to move laterally ... and bypass normal system access controls". ATT&CK T1021.002 describes the SMB/admin-share move. No ATT&CK, CISA or DFIR page I read joins pass-the-hash to SMB/PsExec in one sentence. | Weak. UNVERIFIED as a stated sequence. Impacket's psexec.py -hashes option is widely documented, but I could not read the Impacket source (fetch blocked) and the search hits were blogs. |
| T1003.001 -> T1021.006 | R5 | ATT&CK T1021.006: "Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM)." Procedure examples (Storm-0501 Evil-WinRM, APT29, Wizard Spider) do not mention a prior dump. Microsoft Storm-0501 blog: "The threat actor also performed a DCSync attack" and "Lateral movement was facilitated using Evil-WinRM" (DCSync, not LSASS, and no stated order). | Weak. Generic T1003.001 text ("used to conduct" lateral movement) covers it, but no WinRM-specific dump-then-move source was found. |
| T1021.001 -> T1569.002 | R2 | None. ATT&CK T1569.002 (PsExec, sc.exe with remote servers) does not mention RDP. BlackSuit (The DFIR Report): "BlackSuit ransomware was deployed by copying files over SMB to admin shares and executing them through RDP sessions"; the service-creation (7045) evidence there belongs to the Cobalt Strike psexec module, not to the RDP step. | NOT SUPPORTED. |

### Per-template summary

| Template | Supported links | Unsupported / weak links | Citations (1-3) |
|---|---|---|---|
| R1 T1078 -> T1003.001 -> T1021.002 -> T1569.002 | T1003.001 -> T1021.002; T1021.002 -> T1569.002 | T1078 -> T1003.001 is campaign-level only | [S0029 PsExec](https://attack.mitre.org/software/S0029/): "writes programs to the ADMIN$ network share to execute commands on remote systems"; "execute binaries on remote systems using a temporary Windows service". [CISA AA25-071A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a): Mimikatz/comsvcs.dll LSASS dumping "to harvest credentials ... and aid lateral movement"; "use PsExec" with valid credentials. [Operation Wocao C0014](https://attack.mitre.org/campaigns/C0014/): valid VPN credentials, then Mimikatz/ProcDump, then smbexec.py/psexec.py, then "created services on remote systems". |
| R2 T1078 -> T1003.001 -> T1021.001 -> T1569.002 | T1003.001 -> T1021.001 | T1021.001 -> T1569.002 unsupported; T1078 -> T1003.001 campaign-level | [T1021.001 RDP](https://attack.mitre.org/techniques/T1021/001/): "Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP." [CISA AA25-071A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a): Medusa RDP lateral movement. [PYSA/Mespinoza, The DFIR Report](https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/): "Credentials were dumped manually via Task Manager as they RDPed into each system" (shows dumping and RDP interleaved per host). |
| R3 T1003.001 -> T1021.002 -> T1570 | both | none | [T1021.002](https://attack.mitre.org/techniques/T1021/002/): APT3 "will copy files over to Windows Admin Shares (like ADMIN$) as part of lateral movement". [T1570](https://attack.mitre.org/techniques/T1570/): "file sharing over SMB/Windows Admin Shares"; PsExec "download or upload a file over a network share" ([S0029](https://attack.mitre.org/software/S0029/)). [CISA AA25-071A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) for dump -> move. |
| R4 T1003.001 -> T1550.002 -> T1021.002 -> T1570 -> T1569.002 | T1021.002 -> T1570; T1570 -> T1569.002; T1021.002 -> T1569.002 (so the PsExec tail is supported) | T1003.001 -> T1550.002 moderate; T1550.002 -> T1021.002 weak | [S0002 Mimikatz](https://attack.mitre.org/software/S0002/): lists T1003.001 and T1550.002 ("can impersonate a user, with only a password hash, to execute arbitrary commands"). [S0029 PsExec](https://attack.mitre.org/software/S0029/): T1021.002, T1570, T1569.002 entries. [The DFIR Report, Nitrogen/BlackCat](https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware/): LSASS dump, then "remotely copy the ransomware binary to the target machines before running the second batch script" via PsExec. |
| R5 T1078 -> T1003.001 -> T1021.006 | T1021.006 depends on valid accounts | T1003.001 -> T1021.006 weak; T1078 -> T1003.001 campaign-level | [T1021.006 WinRM](https://attack.mitre.org/techniques/T1021/006/): "Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM)." [T1003.001](https://attack.mitre.org/techniques/T1003/001/): credential material used "to conduct" lateral movement. [Microsoft, Storm-0501](https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/): "Lateral movement was facilitated using Evil-WinRM". |

## Suggested corrections (only where a source supports one)
- R2: the tail T1021.001 -> T1569.002 has no support. A source-supported alternative is the two-step R2' `T1078 -> T1003.001 -> T1021.001` (this is the first three steps of R2, and R5's shape). If the owner wants RDP followed by execution, the only read evidence (BlackSuit) is RDP-based ransomware execution, which has no ATT&CK technique among your set; do not invent one. Decision for the owner: shorten R2 or mark its last edge UNVERIFIED.
- R4: the order of the PtH step relative to the SMB move (T1550.002 before T1021.002) is a logical dependency (ATT&CK defines T1550.002 as reuse of material "to move laterally"), not a sourced sequence. Keep it with an explicit "weak" note, or cite Impacket/Mimikatz documentation after verifying it (UNVERIFIED here).
- R5: keep, with the note that only T1021.006 -> credentials dependence is sourced. No read report shows LSASS dump immediately before WinRM.
- Linear templates simplify a repeating pattern. PYSA shows dump, then RDP, then dump on the next host; templates should be read as "within one hop window". This is an inference, not a source claim.

## Tactics and mapping questions

| Item | Finding | Source |
|---|---|---|
| T1078 tactics (v3.0, modified 12 May 2026) | Stealth, Persistence, Privilege Escalation, Initial Access. Lateral Movement is not listed. | [T1078](https://attack.mitre.org/techniques/T1078/) |
| T1550.002 tactics (v2.0, modified 12 May 2026) | Lateral Movement (TA0008) only. The parent T1550 also lists only Lateral Movement. The April 2026 update page lists T1550.002 under major version changes (v1.3 -> v2.0). Before v19 it carried Defense Evasion too; that is my recollection and the page does not state the removal (UNVERIFIED). | [T1550.002](https://attack.mitre.org/techniques/T1550/002/), [Updates April 2026](https://attack.mitre.org/resources/updates/updates-april-2026/) |
| Defense Evasion rename | Yes. v19 (28 Apr 2026) split Defense Evasion into Stealth (TA0005, same ID) and Defense Impairment (TA0112). The enterprise matrix now has 15 tactics in this order: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Stealth, Defense Impairment, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact. The 28 Apr date and the TA0112 ID come from a secondary summary of MITRE's update page (the primary page names the split but not the date or ID). | [Enterprise tactics](https://attack.mitre.org/tactics/enterprise/), [Updates April 2026](https://attack.mitre.org/resources/updates/updates-april-2026/), [Versions](https://attack.mitre.org/resources/versions/) |

### Is T1078 -> initial-access defensible at the start of a lateral-movement chain?
- Yes, as a single tactic. It is the only listed tactic about obtaining the foothold; ATT&CK's Initial Access page says techniques "use various entry vectors to gain their initial foothold within a network". Campaign evidence matches: Wocao "used valid VPN credentials to gain initial access"; APT29 "used a compromised account to access an organization's VPN infrastructure".
- Why not the others: Persistence and Stealth describe keeping or hiding access, which is not what the template position expresses. Privilege Escalation is plausible (T1003.001 needs an administrative user or SYSTEM, and Wocao used "domain credentials, including domain admin, for lateral movement and privilege escalation"), but it is a weaker fit for a path's first node.
- Caveat: ATT&CK also uses T1078 for credentials reused during lateral movement (Wocao T1078.002; FIN6 "To move laterally on a victim network, FIN6 has used credentials stolen from various systems"). ATT&CK does not list Lateral Movement as a T1078 tactic, so no single listed tactic captures that use. If a T1078-labelled node can appear mid-path, a stage rank of "initial-access" will place it before credential-access even when it follows the dump. State this limit in the decision record.
- Because the matrix orders Initial Access, Execution, Persistence, Privilege Escalation before Credential Access, any of initial-access or privilege-escalation gives the same relative order against T1003.001. The choice matters only for labelling, not for these templates.

### Ordering trap for T1569.002
In the matrix, Execution (TA0002) sits before Lateral Movement (TA0008). The templates put T1569.002 (execution) after T1021.x (lateral-movement). Sources support that order (PsExec connects first, then starts the service), so the order table must be written by hand and must not be derived from matrix column order. This is consistent with the project's "our tactic-order table" rule; flag it in the decision record so the table is not sorted by TA number.

## Recommendation
Keep R1, R3 as cited. Keep R4 and R5 with the weak links noted in the decision record. Shorten R2 or mark T1021.001 -> T1569.002 as unsupported; do not cite it as sourced. Keep T1078 -> initial-access with the mid-path caveat. Update the spec wording: T1550.002 is now lateral-movement only, and "defense-evasion" should not be used for T1078 (use "stealth" if the label is ever needed).

## Limits of this research
- Several fetches summarise pages through a small model and return fragments; quotes are short and unverified against the raw HTML.
- The Impacket psexec.py source page fetch was blocked, so Impacket's hash option is not verified here.
- Did not find a primary report showing LSASS dump then WinRM.
- The Medusa advisory is a CISA/FBI/MS-ISAC product; its ATT&CK table does not map T1078.

## Sources
- [ATT&CK T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [ATT&CK T1078.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [ATT&CK T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [ATT&CK T1550.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [ATT&CK T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [ATT&CK T1021.001 RDP](https://attack.mitre.org/techniques/T1021/001/)
- [ATT&CK T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [ATT&CK T1021.006 Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/)
- [ATT&CK T1569.002 Service Execution](https://attack.mitre.org/techniques/T1569/002/)
- [ATT&CK T1570 Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [ATT&CK S0029 PsExec](https://attack.mitre.org/software/S0029/)
- [ATT&CK S0002 Mimikatz](https://attack.mitre.org/software/S0002/)
- [ATT&CK S0357 Impacket](https://attack.mitre.org/software/S0357/)
- [ATT&CK G0102 Wizard Spider](https://attack.mitre.org/groups/G0102/)
- [ATT&CK G0016 APT29](https://attack.mitre.org/groups/G0016/)
- [ATT&CK G0037 FIN6](https://attack.mitre.org/groups/G0037/)
- [ATT&CK C0014 Operation Wocao](https://attack.mitre.org/campaigns/C0014/)
- [ATT&CK Enterprise tactics](https://attack.mitre.org/tactics/enterprise/)
- [ATT&CK TA0001 Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [ATT&CK Updates April 2026](https://attack.mitre.org/resources/updates/updates-april-2026/)
- [ATT&CK versions](https://attack.mitre.org/resources/versions/)
- [CISA AA25-071A Medusa ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a)
- [CISA AA22-277A Impacket and exfiltration tool](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-277a) (read; used only to confirm it does NOT describe credential dumping or PtH)
- [The DFIR Report: Nitrogen campaign / BlackCat](https://thedfirreport.com/2024/09/30/nitrogen-campaign-drops-sliver-and-ends-with-blackcat-ransomware/)
- [The DFIR Report: BlackSuit](https://thedfirreport.com/?p=37582)
- [The DFIR Report: PYSA/Mespinoza](https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/)
- [Microsoft: Storm-0501 evolving techniques](https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/)
- [Mimikatz wiki, sekurlsa module](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa)
- UNVERIFIED / not read as primary: Impacket psexec.py source (fetch blocked); Cymulate/NHI Mgmt/Elastic secondary summaries of ATT&CK v19 (used only to cross-check the split date and TA0112 ID).
