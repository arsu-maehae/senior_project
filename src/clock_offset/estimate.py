"""Per-host offset estimate, stability and status (spec 08 CO-05..CO-08, CO-15, CO-16; section 3 columns).

WHY exact arithmetic (``Fraction`` over integer microseconds): the median of an even number of
deltas is often half a microsecond, and the status test ``loo_shift > MAX_LOO_SHIFT_S`` must not
depend on float error at the boundary. Values become whole ms only when a row is written.
Pure: no file is read or written here.
"""
from __future__ import annotations

from fractions import Fraction
from typing import Any, Mapping, Sequence

from . import params
from .common import lab_ip_set, s_to_us, us_to_ms, us_to_s
from .pairs import HostPairs, is_lab_ip_logon

Row = dict[str, Any]


def median(values: Sequence[int]) -> Fraction:
    """Median of integer values, exact (mean of the two middle values for an even count)."""
    if not values:
        raise ValueError("median of no values")
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return Fraction(s[mid]) if n % 2 else Fraction(s[mid - 1] + s[mid], 2)


def quantile(values: Sequence[int], p: float) -> Fraction:
    """Linear-interpolation quantile at position (n-1)*p (same as numpy's default), exact.

    WHY this definition: it is the common default, so a reviewer can recompute q1/q3 with numpy.
    The quartiles are reported only; no decision uses them (CO-06).
    """
    if not values:
        raise ValueError("quantile of no values")
    s = sorted(values)
    pos = Fraction(len(s) - 1) * Fraction(str(p))
    lo = int(pos)
    frac = pos - lo
    if lo + 1 >= len(s):
        return Fraction(s[lo])
    return s[lo] + (s[lo + 1] - s[lo]) * frac


def loo_shift(values: Sequence[int]) -> Fraction | None:
    """Largest |median(all) - median(all but one)| over the values (CO-06); None for fewer than 2.

    WHY: it says how much one pair can move the estimate. With 2 pairs it is half their gap, so a
    2-pair host whose deltas differ by more than 5 s becomes ``wide``.
    """
    if len(values) < 2:
        return None
    full = median(values)
    return max(abs(full - median(list(values[:i]) + list(values[i + 1:]))) for i in range(len(values)))


def status_for(n_pairs: int, shift: Fraction | None, stale: bool,
               min_pairs: int = params.MIN_PAIRS, max_loo_shift_s: float = params.MAX_LOO_SHIFT_S) -> str:
    """Endpoint status: stale (CO-15, any kept pair) > none (CO-07) > wide (CO-06) > ok.

    WHY stale first: a restart after the last pair means even a large sample describes an old
    clock; stale and none are both not applied, stale names the reason.
    """
    if stale and n_pairs > 0:
        return params.STATUS_STALE
    if n_pairs < min_pairs:
        return params.STATUS_NONE
    if shift is not None and shift > s_to_us(max_loo_shift_s):
        return params.STATUS_WIDE
    return params.STATUS_OK


def distribution(deltas: Sequence[int]) -> dict[str, int | None]:
    """min/q1/median/q3/max and loo_shift in whole ms (empty when there is no pair)."""
    if not deltas:
        return {k: None for k in ("min_ms", "q1_ms", "median_ms", "q3_ms", "max_ms", "loo_shift_ms")}
    shift = loo_shift(deltas)
    return {"min_ms": us_to_ms(min(deltas)), "q1_ms": us_to_ms(quantile(deltas, 0.25)),
            "median_ms": us_to_ms(median(deltas)), "q3_ms": us_to_ms(quantile(deltas, 0.75)),
            "max_ms": us_to_ms(max(deltas)), "loo_shift_ms": None if shift is None else us_to_ms(shift)}


def endpoint_row(trial_id: str, hp: HostPairs, host_has_events: bool, last_agent_us: int | None,
                 common: Mapping[str, Any]) -> Row:
    """One offsets row for an endpoint (spec 08 section 3).

    ``offset_ms`` is set only for applied statuses (ok, wide); none and stale keep the distribution
    columns for audit but no offset. ``late_gap_s`` = last agent event - last paired 4624 (CO-16),
    where ``last_agent_us`` is the Sysmon 1 that set the raw window end (= raw window end - 300 s).
    WHY the raw end and not the manifest-clipped end: the column shows how far the estimate is
    extrapolated towards the attack; a clipped end - 300 s can lie minutes before the last agent step.
    """
    deltas = [p.delta_us for p in hp.kept]
    shift = loo_shift(deltas)
    status = status_for(len(deltas), shift, hp.stale)
    dist = distribution(deltas)
    applied = status in params.CORRECTED_STATUSES
    t_first = min((p.e4624["us"] for p in hp.kept), default=None)
    t_last = max((p.e4624["us"] for p in hp.kept), default=None)
    lab = lab_ip_set()
    row: Row = {"trial_id": trial_id, "host": hp.host,
                "offset_ms": dist["median_ms"] if applied else None, "offset_status": status,
                "offset_unc_ms": dist["loo_shift_ms"], "n_pairs": len(deltas), "n_dropped_far": len(hp.dropped_far),
                "n_pairs_lab_ip": sum(1 for p in hp.kept if is_lab_ip_logon(p, lab)),
                "late_gap_s": (us_to_s(last_agent_us - t_last) if t_last is not None and last_agent_us is not None
                               else None),
                **dist,
                "pair_span_s": us_to_s(t_last - t_first) if t_last is not None and t_first is not None else None,
                "host_has_events": host_has_events}
    row.update(common)
    return row


def reference_row(trial_id: str, host_has_events: bool, common: Mapping[str, Any],
                  host: str = params.REFERENCE_HOST) -> Row:
    """dc01 row: offset 0 and uncertainty 0 by definition, status ``reference`` (unverified, CO-05)."""
    row: Row = {"trial_id": trial_id, "host": host, "offset_ms": 0, "offset_status": params.STATUS_REFERENCE,
                "offset_unc_ms": 0, "n_pairs": 0, "n_dropped_far": 0, "n_pairs_lab_ip": 0, "late_gap_s": None,
                "min_ms": None, "q1_ms": None, "median_ms": None, "q3_ms": None, "max_ms": None,
                "loo_shift_ms": None, "pair_span_s": None, "host_has_events": host_has_events}
    row.update(common)
    return row


def common_columns(search_start_utc: str, search_end_utc: str, db_sha256: str) -> dict[str, str]:
    """Columns equal on every row of one trial."""
    return {"method": params.METHOD, "search_start_utc": search_start_utc, "search_end_utc": search_end_utc,
            "db_sha256": db_sha256, "tool_version": params.TOOL_VERSION}


def offsets_rows(trial_id: str, host_pairs: Mapping[str, HostPairs], has_events: Mapping[str, bool],
                 last_agent_us: int | None, common: Mapping[str, Any]) -> list[Row]:
    """The four offsets rows (dc01 + endpoints), sorted by host (CO-14)."""
    rows = [reference_row(trial_id, has_events.get(params.REFERENCE_HOST, False), common)]
    rows += [endpoint_row(trial_id, hp, has_events.get(h, False), last_agent_us, common)
             for h, hp in host_pairs.items()]
    return sorted(rows, key=lambda r: r["host"])


def clock_flag(rows: Sequence[Mapping]) -> list[str]:
    """Hosts with status none/wide/stale that have events in the window, sorted (CO-08).

    WHY only hosts with events: a host whose logs were not exported has nothing to correct.
    """
    return sorted(r["host"] for r in rows
                  if r["offset_status"] in params.UNRELIABLE_STATUSES and r["host_has_events"])
