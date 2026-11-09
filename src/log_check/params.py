"""Parameters of the log check (spec docs/specs/00_log_check.md §5).

All tunable values live in ONE frozen dataclass so that every run is reproducible from
its parameters and a sensitivity run (LC-04d) can derive a modified copy with
``dataclasses.replace`` instead of mutating global state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class Expectation:
    """What the expectation table (§5) says a scenario should contain.

    LC-12 needs this to decide PROBLEM (expected evidence missing) vs INFO (nothing expected).
    """

    smb_hops: int = 0
    winrm_hops: int = 0
    rdp_hops: int = 0
    dumps: bool = True


def _ro(mapping: dict) -> Mapping:
    """Wrap a dict read-only so the frozen dataclass cannot be mutated through its fields."""
    return MappingProxyType(dict(mapping))


@dataclass(frozen=True)
class Params:
    """Spec §5 defaults. Times are seconds unless the name says otherwise."""

    # WN-01: run day per scenario (handoff §19).
    run_day: Mapping[str, str] = field(default_factory=lambda: _ro({
        "s01": "2026-09-24", "s02": "2026-09-24", "s03": "2026-09-24", "s04": "2026-09-24",
        "s05": "2026-10-12", "s06": "2026-10-12", "s07": "2026-10-12",
    }))
    scenario_accounts: tuple[str, ...] = ("svc_backup", "admin_it", "svc_sql")
    host_ip: Mapping[str, str] = field(default_factory=lambda: _ro({
        "dc01": "192.168.50.10", "ep-01": "192.168.50.21",
        "ep-02": "192.168.50.22", "ep-03": "192.168.50.23",
    }))
    endpoint_hosts: tuple[str, ...] = ("ep-01", "ep-02", "ep-03")
    lab_ipv4_prefix: str = "192.168.50."
    margin_before_s: float = 600.0
    margin_after_s: float = 600.0
    cluster_gap_s: float = 1200.0
    hop_group_s: float = 10.0
    cmd_before_s: float = 120.0
    cmd_after_s: float = 10.0
    port_join_s: float = 5.0
    session_lookback_s: float = 21600.0
    # LC-04d sensitivity grid.
    cmd_after_grid: tuple[float, ...] = (10.0, 30.0, 300.0)
    cmd_before_grid: tuple[float, ...] = (30.0, 120.0, 300.0)
    # Fixed tolerances written into the rules themselves (not tunable in §5, kept here so
    # no magic number hides in the code).
    dump_pair_s: float = 1.0          # LC-08: 0x1410 + 0x1fffff within 1 s is one dump
    process_collapse_s: float = 2.0   # LC-04: Sysmon 1 + 4688 of one process
    service_dedup_s: float = 2.0      # LC-04c: 4697 + 7045 of one service
    rdp_inbound_s: float = 5.0        # LC-05: inbound 3389 -> 4624 within 5 s
    cross_channel_s: float = 5.0      # LC-09: 4688 vs Sysmon 1
    post_dump_cmd_s: float = 600.0    # LC-08b: command in the 10 min after the dump
    sysmon_gap_flag_s: float = 60.0   # LC-09: rows with record-time gap > 60 s
    skew_agree_ms: float = 1000.0     # LC-09: dc01_skew_possible
    margin_alt_s: float = 300.0       # §5: "counts at 300 s too"
    expectations: Mapping[str, Expectation] = field(default_factory=lambda: _ro({
        "s01": Expectation(rdp_hops=1),
        "s02": Expectation(smb_hops=1),
        "s03": Expectation(winrm_hops=1),
        "s04": Expectation(smb_hops=2),
        "s05": Expectation(smb_hops=1, winrm_hops=1),
        "s06": Expectation(dumps=False),
        "s07": Expectation(smb_hops=2),
    }))

    # §5 note: S01 t00 is reference only (decision 001: EP-01/DC01 files are S02 exports), so
    # checks that need its source host or a dump report NOT_MEASURABLE, not PROBLEM.
    reference_only_trials: Mapping[str, str] = field(default_factory=lambda: _ro({
        "s01_t00": "reference only (decision 001: ep-01/dc01 files are S02 exports)",
    }))

    def expectation_for(self, scenario: str) -> Expectation:
        """Unknown scenarios expect nothing, so their checks report INFO rather than PROBLEM."""
        return self.expectations.get(scenario, Expectation(dumps=False))

    def ip_to_host(self) -> dict[str, str]:
        """Reverse HOST_IP lookup used to name the source host of a remote logon."""
        return {ip: host for host, ip in self.host_ip.items()}


DEFAULT_PARAMS = Params()
