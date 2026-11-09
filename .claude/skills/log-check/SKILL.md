---
description: Run the standard read-only data checks on one trial database before stitching or when results look wrong.
disable-model-invocation: true
---
# Log check: $ARGUMENTS   (a trial id such as s04_t01, or a path to a trial DB)

Use the `data-checker` agent. Open the database read-only. Run and report:

1. Event counts by channel and event_id; total rows in `events` vs `events_dedup`.
2. 4624 with LogonType 3 or 10 and a remote IpAddress: count, and the share with IpPort, valid LogonGuid,
   zero LogonGuid, and each AuthenticationPackageName (Kerberos / NTLM).
3. Kerberos confirmation: target 4624 whose LogonGuid matches a DC 4769 LogonGuid.
4. SMB: source Sysmon 3 with Image = System and DestinationPort 445, and how many match a target 4624
   by (SourceIp = IpAddress, SourcePort = IpPort, |Δt| ≤ 5 s).
5. RDP: Sysmon 3 from mstsc.exe to port 3389, and the matching target 4624 (Type 10, or remote Type 3).
6. WinRM: Sysmon 3 from powershell.exe to 5985/5986; wsmprovhost.exe Sysmon 1 on the target and its LogonId.
7. Sessions: target 4624 TargetLogonId found as Sysmon 1 LogonId on the same host.
8. Dumps: Sysmon 10 with TargetImage lsass.exe (time, host, source image, user) and the accounts with
   a logon session open on that host at that time (4624 before, no 4634/4647 before).
9. Answer-key anchors: every event_uid / record listed in ground_truth for this trial is present.

Finish with a table: check · result · OK / PROBLEM · effect on stitching or identity.
