"""Small UTC time helpers (pure)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def parse_utc(text: str) -> datetime:
    """Parse the DB's ISO-8601 ``...Z`` strings (6 or fewer fractional digits)."""
    t = text.rstrip("Z")
    fmt = "%Y-%m-%dT%H:%M:%S.%f" if "." in t else "%Y-%m-%dT%H:%M:%S"
    return datetime.strptime(t, fmt).replace(tzinfo=timezone.utc)


def fmt_utc(dt: datetime) -> str:
    """Format as ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def add_s(text: str, seconds: float) -> str:
    """Shift a timestamp string by ``seconds``."""
    return fmt_utc(parse_utc(text) + timedelta(seconds=seconds))


def delta_ms(a: str, b: str) -> int:
    """b - a in milliseconds."""
    return round((parse_utc(b) - parse_utc(a)).total_seconds() * 1000)
