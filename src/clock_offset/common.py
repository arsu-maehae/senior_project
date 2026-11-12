"""Small pure helpers shared by the clock offset modules: event kinds, GUID / IP forms, exact rounding.

WHY a module of its own: the pairing, the estimate and the CO-10 check must agree on what a
GUID-bearing 4624 is, how an IP is compared and how microseconds become whole ms, so these live
in one place. Nothing here imports the gate, because the gate will import ``clock_offset.correct``
(spec 08 section 4.1) and the dependency must point one way only.
"""
from __future__ import annotations

import ipaddress
from fractions import Fraction
from typing import Any, Mapping

from gate.timeutil import US_PER_MS, US_PER_S

from . import params

Number = int | Fraction


def is_event(row: Mapping, channel: str, event_id: int) -> bool:
    """Channel and event id together: event ids alone collide across channels (System 1 vs Sysmon 1)."""
    return row.get("channel") == channel and row.get("event_id") == event_id


def norm_guid(value: Any) -> str | None:
    """LogonGuid in comparison form: lower-case, no braces; NULL, blank or all-zero -> None (CO-02).

    WHY None for zero: an all-zero GUID is what Windows writes when there is no Kerberos logon, so
    it would pair unrelated events; the DB already stores it as NULL, this guards synthetic input.
    """
    if value is None:
        return None
    text = str(value).strip().strip("{}").strip().lower()
    if not text or set(text) <= {"0", "-"}:
        return None
    return text


def norm_ip(value: Any) -> str | None:
    """IP text for comparisons, same rule as ``gate.classify.norm_ip``: blank or ``-`` -> None,
    ``::ffff:a.b.c.d`` -> ``a.b.c.d``, anything else unchanged.

    WHY re-stated and not imported: the gate will import this package (spec 08 section 4.1), so
    importing ``gate.classify`` here would tie the two packages both ways. The rule is short and
    fixed by spec 02_gate section 2 / decision 041.
    """
    if value is None:
        return None
    text = str(value).strip()
    if text in ("", "-"):
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped) if mapped is not None else text


def lab_ip_set(lab_ips: Mapping[str, str] = params.LAB_HOST_IPS) -> frozenset[str]:
    """Every lab host IP in ``norm_ip`` form, so both sides of a membership test are normalised."""
    return frozenset(ip for ip in (norm_ip(v) for v in lab_ips.values()) if ip is not None)


def host_of_ip(value: Any, lab_ips: Mapping[str, str] = params.LAB_HOST_IPS) -> str | None:
    """Lab host name for an IP (normalised), or None when the IP is not a lab host."""
    ip = norm_ip(value)
    for host, host_ip in lab_ips.items():
        if ip is not None and norm_ip(host_ip) == ip:
            return host
    return None


def round_half_away(x: Number) -> int:
    """Round to the nearest integer, halves away from zero (spec: ms values are rounded, not truncated).

    WHY not ``round``: Python rounds halves to even, which would make -2.5 ms and +2.5 ms round to
    different magnitudes; a median of two deltas is often exactly half a microsecond step.
    """
    f = Fraction(x)
    mag = int((abs(f) + Fraction(1, 2)) // 1)
    return -mag if f < 0 else mag


def us_to_ms(us: Number) -> int:
    """Microseconds (exact) to whole milliseconds, halves away from zero."""
    return round_half_away(Fraction(us) / US_PER_MS)


def us_to_s(us: Number) -> int:
    """Microseconds (exact) to whole seconds, halves away from zero (late_gap_s, pair_span_s)."""
    return round_half_away(Fraction(us) / US_PER_S)


def s_to_us(seconds: float) -> int:
    """Parameter in seconds to integer microseconds (2.5 -> 2_500_000), rounded, never truncated."""
    return round_half_away(Fraction(str(seconds)) * US_PER_S)
