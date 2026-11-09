"""UTC time helpers.

The DB stores `event_utc` as ISO strings with 6 fractional digits and a trailing `Z`
(e.g. `2026-09-24T10:57:36.855353Z`). Keeping one parse/format pair here means the SQL
range filters (string comparison) and the Python arithmetic always agree.
"""

from __future__ import annotations

import math
from datetime import date, datetime, timedelta, timezone
from typing import Sequence


def parse_utc(value: str) -> datetime:
    """Parse a stored UTC string into an aware datetime (accepts `Z` and missing fraction)."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def to_db(value: datetime) -> str:
    """Format exactly like the DB column so SQL string comparison is a time comparison."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def to_display(value: datetime | None) -> str | None:
    """Millisecond precision for reports and CSV (spec §3 example `...36.855Z`)."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def delta_ms(later: datetime, earlier: datetime) -> int:
    """Signed difference in whole milliseconds, truncated toward zero.

    Truncation (not rounding) reproduces the spec §3 example: 37.762000 − 36.855353 s → 906.
    """
    return int((later - earlier) / timedelta(milliseconds=1))


def day_bounds(day: str) -> tuple[datetime, datetime]:
    """[00:00, next 00:00) of a run day, used for WN-02 anchors and the RUN_DAY_ONLY window."""
    start = datetime.combine(date.fromisoformat(day), datetime.min.time(), tzinfo=timezone.utc)
    return start, start + timedelta(days=1)


def seconds(value: float) -> timedelta:
    """Short alias so window arithmetic reads like the spec (`t - seconds(CMD_BEFORE_S)`)."""
    return timedelta(seconds=value)


def percentile(values: Sequence[float], pct: float) -> float | None:
    """Linear-interpolated percentile (same as numpy's default) without a numpy dependency."""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * pct / 100.0
    low, high = math.floor(rank), math.ceil(rank)
    frac = rank - low
    return float(ordered[low] + (ordered[high] - ordered[low]) * frac)


def summarise(values: Sequence[float], pcts: Sequence[float] = (5, 50, 95), digits: int = 1) -> dict:
    """n, min, max and the requested percentiles; empty input gives n = 0 and None values."""
    out: dict = {"n": len(values)}
    for pct in pcts:
        out[f"p{int(pct)}"] = _round(percentile(values, pct), digits)
    out["min"] = _round(min(values), digits) if values else None
    out["max"] = _round(max(values), digits) if values else None
    return out


def _round(value: float | None, digits: int) -> float | None:
    """Keep JSON readable (milliseconds to one decimal by default)."""
    return None if value is None else round(value, digits)
