"""UTC instant helpers for the gate (spec 02_gate section 2: times compared as parsed instants, never text).

WHY the gate has its own parser: the DB holds ``...Z`` text with up to 6 fraction digits, while
other tools write ``+00:00``; ``datetime.fromisoformat`` accepts both. Instants are kept as
integer microseconds since the epoch so window edges and 5 s tolerances are exact (no float error
at the inclusive boundary, decision 041).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_US = timedelta(microseconds=1)
US_PER_S = 1_000_000
US_PER_MS = 1_000


def parse_utc(text: str) -> datetime:
    """ISO-8601 text to a tz-aware UTC datetime; raises ValueError for empty or zone-less text.

    WHY reject zone-less text: every DB time carries a zone (NF-23); a missing zone means the
    input is not what the gate was written for, and guessing UTC could shift a whole trial.
    """
    if text is None or not str(text).strip():
        raise ValueError("empty timestamp")
    dt = datetime.fromisoformat(str(text).strip())
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"timestamp without a time zone: {text!r}")
    return dt.astimezone(timezone.utc)


def to_us(text: str) -> int:
    """ISO text to integer microseconds since the epoch (the gate's comparable instant)."""
    return (parse_utc(text) - _EPOCH) // _US


def seconds_to_us(seconds: float) -> int:
    """Tolerance in seconds to integer microseconds (5.0 -> 5_000_000), rounded, not truncated."""
    return int(round(seconds * US_PER_S))


def fmt_us(us: int) -> str:
    """Microsecond instant to ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` (display in reports only)."""
    return (_EPOCH + timedelta(microseconds=us)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def delta_ms(later_us: int, earlier_us: int) -> int:
    """(later - earlier) in whole milliseconds, rounded (spec 3 time_delta_ms)."""
    return int(round((later_us - earlier_us) / US_PER_MS))
