"""Design steps per scenario, transcribed from decision 029 (Decision 2, "Design steps") and 035 (S01).

WHY data, not code: the design is fixed before the data was seen (029), so it is written once as
a table that the owner can compare line by line with the decision record.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HopDesign:
    """One designed cross-host move and the target-side steps that must follow it."""
    hop_id: str
    protocol: str                 # SMB | WinRM | RDP (RDP: decision 035, handled in ``rdp``)
    source: str
    target: str
    lane: str                     # agent (Caldera, splunkd tree) | manual (interactive session)
    intended_account: str
    steps: tuple[str, ...]        # subset of command, logon, binary_write, service, winrm; RDP: rdp_source, logon
    note: str = ""


@dataclass(frozen=True)
class DumpDesign:
    """A designed LSASS read (rundll32 -> lsass, user token) on one host."""
    step_id: str
    host: str
    count: int
    account: str | None = None    # only S05 ep-02 names the dumping account


@dataclass(frozen=True)
class ScenarioDesign:
    """Everything decision 029 fixes for one scenario."""
    scenario: str
    path_hosts: tuple[str, ...]
    dumps: tuple[DumpDesign, ...]
    hops: tuple[HopDesign, ...]
    benign: str | None            # s04_track_a | s06_no_dump | None
    caldera_hosts: tuple[str, ...]
    c_severity: str = "FAIL"      # S06: WARN (owner: benign control)
    source: str = "decision 029"


_SMB_FULL = ("command", "logon", "binary_write", "service")

DESIGNS: dict[str, ScenarioDesign] = {
    "s01": ScenarioDesign(
        "s01", ("ep-01", "ep-02"),
        (),
        (HopDesign("s01-h1", "RDP", "ep-01", "ep-02", "manual", "svc_backup", ("rdp_source", "logon"),
                   "manual RDP, no agent (decision 035)"),),
        None, (), source="decision 035"),
    "s02":ScenarioDesign(
        "s02", ("ep-01", "ep-02"),
        (DumpDesign("dump_ep-01", "ep-01", 1),),
        (HopDesign("s02-h1", "SMB", "ep-01", "ep-02", "agent", "svc_backup", _SMB_FULL),),
        None, ("ep-01",)),
    "s03": ScenarioDesign(
        "s03", ("ep-01", "ep-03"),
        (DumpDesign("dump_ep-01", "ep-01", 1),),
        (HopDesign("s03-h1", "WinRM", "ep-01", "ep-03", "agent", "admin_it", ("command", "logon", "winrm"),
                   "source ep-01 (decision 025)"),),
        None, ("ep-01",)),
    "s04": ScenarioDesign(
        "s04", ("ep-01", "ep-02"),
        (DumpDesign("dump_ep-01", "ep-01", 1),),
        (HopDesign("s04-B", "SMB", "ep-01", "ep-02", "agent", "svc_backup", _SMB_FULL, "Track B"),
         HopDesign("s04-A", "SMB", "ep-01", "ep-02", "manual", "admin_it", _SMB_FULL,
                   "Track A, manual (decision 021); no agent evidence required")),
        "s04_track_a", ("ep-01",)),
    "s06": ScenarioDesign(
        "s06", ("ep-01", "ep-02", "ep-03"),
        (),
        (HopDesign("s06-winrm-1", "WinRM", "ep-01", "ep-02", "agent", "admin_it", ("command", "logon", "winrm")),
         HopDesign("s06-winrm-2", "WinRM", "ep-01", "ep-03", "agent", "admin_it", ("command", "logon", "winrm")),
         HopDesign("s06-smb-1", "SMB", "ep-01", "ep-02", "agent", "admin_it", ("command", "logon", "service"),
                   "SMB service install (decision 024)")),
        "s06_no_dump", ("ep-01",), c_severity="WARN"),
    "s07": ScenarioDesign(
        "s07", ("ep-01", "ep-02"),
        (DumpDesign("dump_ep-01", "ep-01", 2),),
        (HopDesign("s07-X", "SMB", "ep-01", "ep-02", "agent", "svc_backup", ("command", "logon", "service"), "path X"),
         HopDesign("s07-Y", "SMB", "ep-01", "ep-02", "agent", "svc_sql", ("command", "logon", "service"),
                   "path Y; design svc_sql, t00 logged svc_backup (decision 027)")),
        None, ("ep-01",)),
    "s05": ScenarioDesign(
        "s05", ("ep-01", "ep-02", "ep-03"),
        (DumpDesign("dump_ep-01", "ep-01", 1), DumpDesign("dump_ep-02", "ep-02", 1, "admin_it")),
        (HopDesign("s05-h1", "SMB", "ep-01", "ep-02", "agent", "svc_backup", ("command", "logon")),
         HopDesign("s05-h2", "WinRM", "ep-02", "ep-03", "agent", "admin_it", ("command", "logon", "winrm"))),
        None, ("ep-01", "ep-02"), source="decision 029 (quarantine only, decision 030)"),
}


def design_for(scenario: str) -> ScenarioDesign:
    """The design of a scenario; refuses scenarios that no decision defines (S01: 035, S02-S07: 029)."""
    if scenario not in DESIGNS:
        raise KeyError(f"no design in decision 029 or 035 for scenario {scenario!r}")
    return DESIGNS[scenario]


def hop_groups(design: ScenarioDesign) -> dict[tuple[str, str, str, str], list[HopDesign]]:
    """Hops that compete for the same commands: same source, target, protocol and lane.

    WHY: S07 has two identical SMB hops ep-01 -> ep-02; their commands are assigned in time order,
    and any further execution of that step is a duplicate run (criterion h).
    """
    out: dict[tuple[str, str, str, str], list[HopDesign]] = {}
    for hop in design.hops:
        out.setdefault((hop.source, hop.target, hop.protocol, hop.lane), []).append(hop)
    return out
