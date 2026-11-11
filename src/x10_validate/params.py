"""Constants of the validator. Every value cites where it comes from.

WHY one module: the measurement rules that decision 029 leaves to the validator ("implementation
notes") must be visible in one place and printed in every output, so the owner can audit them.
"""
from __future__ import annotations

# Lab addressing (handoff host table; agent_evidence.md).
HOST_IP: dict[str, str] = {"ep-01": "192.168.50.21", "ep-02": "192.168.50.22", "ep-03": "192.168.50.23"}
IP_HOST: dict[str, str] = {ip: host for host, ip in HOST_IP.items()}
ENDPOINTS: tuple[str, ...] = ("ep-01", "ep-02", "ep-03")
HOSTS: tuple[str, ...] = ("ep-01", "ep-02", "ep-03", "dc01")          # decision 029: keep dc01
CHANNELS: tuple[str, ...] = ("security", "system", "sysmon", "powershell", "winrm")

# Caldera agent (docs/research/agent_evidence.md).
AGENT_IMAGE = "c:\\users\\public\\splunkd.exe"
CALDERA_IP = "192.168.50.50"
CALDERA_PORT = 8888

# Time rules.
TRIAL_GAP_S = 1800.0        # anchors further apart than 30 min belong to different trials (decision 026)
MARGIN_BEFORE_S = 60.0      # window = [first anchor - 60 s, last anchor + 300 s] (decision 029, f)
MARGIN_AFTER_S = 300.0
PID_TIE_S = 3.0             # Sysmon 1 root with ParentImage '-' tied to splunkd by a 4688 (spec 07 AK-01)
CMD_BEFORE_S = 10.0         # a target 4624 at t belongs to a command in [t - 120 s, t + 10 s] (spec 07 params)
CMD_AFTER_S = 120.0
CROSS_HOST_TOL_S = 5.0      # decision 014
CLOCK_WARN_S = 5.0          # decision 029, g
CLOCK_PAD_S = 1800.0        # LogonGuid pairs are searched in the window +- 30 min (implementation note)
DUMP_PAIR_S = 1.0           # Sysmon 10 records within 1 s are one dump (spec 07 AK-10)
MANUAL_GAP_S = 120.0        # manual commands of one session closer than this are one execution

# Account classes.
NON_USER_ACCOUNTS = frozenset({"", "system", "local service", "network service", "localsystem",
                               "anonymous logon", "-", "dwm-1", "umfd-0", "umfd-1"})

# Binary names that are tools, not payloads (used only to read payload names out of command lines).
TOOL_BINARIES = frozenset({"powershell.exe", "pwsh.exe", "cmd.exe", "sc.exe", "net.exe", "net1.exe",
                           "rundll32.exe", "wsmprovhost.exe", "conhost.exe", "splunkd.exe", "svchost.exe",
                           "winrs.exe", "reg.exe", "schtasks.exe", "wmic.exe", "whoami.exe", "copy.exe"})

WRITE_MASK = 0x2 | 0x4      # 5145 AccessMask WriteData | AppendData counts as a write

IMPLEMENTATION_NOTES: tuple[str, ...] = (
    "N1 run window: anchors = agent-tree commands naming a lab endpoint (any host, self-targets included), "
    "rundll32->lsass Sysmon 10 dumps by a user token, and 4624 type 3/10 on an endpoint from another "
    "endpoint's IP with a user account. Anchors are split into clusters where the gap exceeds 30 min; "
    "the trial's own run is the LAST cluster; search window = [first anchor - 60 s, last anchor + 300 s]. "
    "Older clusters are reported under f (WARN). The f overlap FAIL uses the 029 design window = "
    "[first - 60 s, last + 300 s] over design anchors only (executions of design command steps, user-token "
    "dumps in the window, target 4624s tied to design hops); broad-window overlaps are reported, not failed. "
    "Both window ends are clipped at the DB's last event (export end; decision 026 amendment uses the "
    "export span as an outer clip); overlaps of the unclipped design window are reported, not failed.",
    "N2 agent tree: Sysmon 1 whose ParentImage is exactly C:\\Users\\Public\\splunkd.exe, plus Sysmon 1 "
    "roots with ParentImage '-' tied by a 4688 (same host, same PID, identical command line, parent "
    "splunkd, within 3 s); all descendants by ParentProcessGuid. 4688 rows with the same host, PID and "
    "command line within 3 s are recorded as corroboration. Only on a host with no Sysmon 1 in the run "
    "is the tree built from 4688 by parent PID (marked tree_source=4688_pid_chain).",
    "N3 one execution = one direct splunkd child (Caldera link) for agent commands; manual commands "
    "(not in the agent tree, user token) are grouped by host, logon session and target with gaps <= 120 s.",
    "N4 naming the target: case-insensitive, boundary-aware match of ep-0N, endpoint-0N, "
    "endpoint-0N.lab.local and 192.168.50.2N (192.168.50.2 never matches .22) on the full command line "
    "plus the UTF-16LE decoding of any -enc/-EncodedCommand payload.",
    "N5 protocol of a command: SMB when it names the target in a UNC path (\\\\target\\...) or uses psexec; "
    "WinRM when it uses Invoke-Command, New-PSSession, Enter-PSSession, winrs, wsman or -ComputerName.",
    "N6 hop binding: the target 4624s of a command are those on the target from the source IP, type 3/10, "
    "user account, in [command - 10 s, last command + 120 s] (capped at the next command of the same "
    "lane naming the same target); when a 5145/4697 whose file or service name appears in the command "
    "has a SubjectLogonId equal to a 4624 TargetLogonId (or a wsmprovhost session equals it), only those "
    "4624s are kept (binding logon_id_artifact), else all in the window (binding time_window).",
    "N7 binary write = 5145 on ADMIN$ whose RelativeTargetName ends .exe/.dll and whose AccessMask has "
    "WriteData or AppendData; service created = 7045 or 4697 on the target whose image is an .exe "
    "directly under C:\\Windows\\, logged at or after the hop's first tied 4624 (same host clock).",
    "N8 WinRM step = WinRM 91 on the target in the command window with clientIP = source IP, or a Sysmon 1 "
    "wsmprovhost.exe on the target in the command window whose LogonId is the TargetLogonId of a 4624 from "
    "the source IP. WHY: at the end of the x10 trials admin_it WinRM sessions from non-lab workstations "
    "(192.168.50.97/.98/.99; log collection, inferred) start wsmprovhost.exe on every host.",
    "N9 criterion c uses the whole trial window: the intended account must appear in a 4624 (type 3/10) on "
    "the target from the source IP, a 5145 on the target from the source IP, or a 4697 on the target whose "
    "SubjectLogonId is a logon from the source IP (4697s of other logons are listed as 4697_other_source, "
    "not counted); the accounts tied to the hop are reported next to it.",
    "N10 criterion e: the trial run for agent beacons starts at the first anchor and walks back through "
    "splunkd process starts and splunkd->192.168.50.50:8888 Sysmon 3 events while gaps are <= 30 min, "
    "never before the end of the previous anchor cluster's window.",
    "N11 criterion g: endpoint 4624 and dc01 4769 with the same LogonGuid in the window +- 30 min, "
    "mutual-nearest pairs per host, offset = host time - dc01 time, median per host; host-pair offset "
    "= difference of medians (dc01 = 0). Lower bounds = source command time - target 4624 time when the "
    "4624 is logged first. dc01 Security absent -> n/a (WARN if a lower bound exceeds 5 s).",
    "N12 criterion h counts executions (N3) of each command step and dumps (N1 grouping, 1 s) of each "
    "dump step. Extra runs by the same user on the same source naming the same target -> FAIL; extra "
    "runs by another user, by a non-user token, self-targeted, or from another host -> WARN.",
    "N13 criterion i: shape = hosts with logs, design steps found, service names, target-side accounts "
    "per hop, protocols per hop; compared with the most common shape of the scenario's x10 trials "
    "(strict majority, at least 2 trials); no majority -> n/a.",
    "N14 criterion a reads out/ingest/x10/<trial>/ingest.json (files_missing). For t00 with "
    "--no-ingest-check it reads the DB's (host, channel) row counts instead, which cannot tell an empty "
    "file from a missing one.",
    "N15 quarantine DBs keep scenario_id s05 / trial_id tNN in their rows; the trial id is taken from "
    "the file name (s05q_tNN) per decision 030.",
)
