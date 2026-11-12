"""CO-12: parse the rerun clock readings (``w32tm /stripchart`` text) and assign them by time (spec 08).

WHY a pure parser: the readings are the only independent check of the offsets on hosts with no
WinRM hop (CO-11b, CO-12), so every value must be traceable to its raw line, and the sign
convention must be visible and changeable without editing code. Nothing here writes a file;
``read_reading_file`` only reads the copy under ``data/raw/<scenario>/<trial>/<host>/clock.txt``
(spec 08 section 4.2), and ``parse_stripchart`` works on text so tests need no file at all.

Format handled (English Windows ``w32tm /stripchart /computer:dc01 ...``)::

    Tracking dc01.lab.local [192.168.50.10:123].
    Collecting 5 samples.
    The current time is 23/11/2026 08:00:00.
    08:00:00, d:+00.0012345s o:-14.6543210s  [   *       |           ]
    08:00:02, error: 0x800705B4

    SE Asia Standard Time

One ``Tracking`` header starts a session; the session value is the median of its samples' ``o:``.
``/dataonly`` sample lines (``08:00:00, -14.6543210s``) are read as the offset too. The last line is the
output of ``tzutil /g`` appended by the lab procedure (owner D7): the Windows time-zone name, which turns
the local wall-clock times printed by w32tm into UTC. Without that line the caller must pass ``tz``;
with neither, or with an unknown name and no ``tz``, the file is ``invalid``.

Sign and time zone are confirmed at the first rerun session (spec 08 CO-12).
"""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from dataclasses import replace
from datetime import date, datetime, time, timedelta, timezone, tzinfo
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path
from typing import Sequence

from .common import round_half_away

# ---------------------------------------------------------------- constants (new; params.py is frozen)

# ASSUMED: ``o:`` = dc01 - local, so host - dc01 = -o. To be confirmed once, at the first rerun
# session, on a host whose LogonGuid estimate is |x| > 2 s (spec 08 CO-12). Pass ``sign=+1`` to
# ``parse_stripchart`` to flip it without a code change.
SIGN_CONVENTION: int = -1
# The reference clock must be dc01 (CO-12): a host name starting with dc01, or its lab IP.
REFERENCE_NAME_PREFIX = "dc01"
REFERENCE_IP = "192.168.50.10"

# Windows time-zone name (``tzutil /g``) -> (IANA key, fixed UTC offset in minutes or None when the zone has
# daylight saving time). WHY fixed offsets: the venv has no ``tzdata`` package, so ``zoneinfo`` cannot load
# IANA zones on Windows; a zone without DST is exactly its fixed offset, so the result does not depend on
# the environment. A DST zone is used only when ``zoneinfo`` can load it; otherwise it is refused.
WINDOWS_TZ: dict[str, tuple[str, int | None]] = {
    "SE Asia Standard Time": ("Asia/Bangkok", 7 * 60),
    "UTC": ("UTC", 0),
    "Greenwich Standard Time": ("Atlantic/Reykjavik", 0),
    "Myanmar Standard Time": ("Asia/Yangon", 6 * 60 + 30),
    "India Standard Time": ("Asia/Kolkata", 5 * 60 + 30),
    "Singapore Standard Time": ("Asia/Singapore", 8 * 60),
    "China Standard Time": ("Asia/Shanghai", 8 * 60),
    "Taipei Standard Time": ("Asia/Taipei", 8 * 60),
    "W. Australia Standard Time": ("Australia/Perth", 8 * 60),
    "Tokyo Standard Time": ("Asia/Tokyo", 9 * 60),
    "Korea Standard Time": ("Asia/Seoul", 9 * 60),
    "GMT Standard Time": ("Europe/London", None),
    "W. Europe Standard Time": ("Europe/Berlin", None),
    "Romance Standard Time": ("Europe/Paris", None),
    "Eastern Standard Time": ("America/New_York", None),
    "Central Standard Time": ("America/Chicago", None),
    "Mountain Standard Time": ("America/Denver", None),
    "Pacific Standard Time": ("America/Los_Angeles", None),
    "AUS Eastern Standard Time": ("Australia/Sydney", None),
}
TZ_SOURCE_FILE = "file"
TZ_SOURCE_ARGUMENT = "argument"

STATUS_VALID = "valid"
STATUS_INVALID = "invalid"

_US_PER_S = 1_000_000

_TRACKING = re.compile(r"^\s*Tracking\s+(?P<target>.+?)\s*\.?\s*$", re.IGNORECASE)
_TARGET_PARTS = re.compile(r"^(?P<name>[^\s\[]+)?\s*(?:\[(?P<addr>[^\]]*)\])?")
_COLLECTING = re.compile(r"^\s*Collecting\s+(?P<n>\d+)\s+samples?", re.IGNORECASE)
_CURRENT = re.compile(r"^\s*The current time is\s+(?P<text>.+?)\s*\.?\s*$", re.IGNORECASE)
_TOD = r"(?P<h>\d{1,2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\s*(?P<ampm>[AaPp]\.?[Mm]\.?))?"
_SAMPLE_HEAD = re.compile(r"^\s*" + _TOD + r"\s*,\s*(?P<rest>.*)$")
_SECONDS = r"[+-]?\d+(?:[.,]\d+)?"  # comma: locales with a decimal comma
_D_FIELD = re.compile(r"\bd:\s*(?P<v>" + _SECONDS + r")s", re.IGNORECASE)
_O_FIELD = re.compile(r"\bo:\s*(?P<v>" + _SECONDS + r")s", re.IGNORECASE)
_DATAONLY = re.compile(r"^(?P<v>" + _SECONDS + r")s\b")
_ERROR = re.compile(r"^\s*error\b", re.IGNORECASE)
_DATE = re.compile(r"(?P<a>\d{1,4})[/.\-](?P<b>\d{1,2})[/.\-](?P<c>\d{1,4})")
# ``tzutil /g`` output: a Windows zone id (``... Standard Time`` or ``UTC``/``UTC+12``), optionally with
# ``_dstoff`` (automatic DST switched off), optionally after an echoed ``tzutil /g`` prompt.
_TZ_LINE = re.compile(r"^\s*(?:\S*>\s*)?(?:tzutil(?:\.exe)?\s+/g\s*[:>]?\s*)?"
                      r"(?P<name>[A-Za-z][A-Za-z0-9 .()+\-]*? Standard Time|UTC(?:[+-]\d{2})?)"
                      r"(?P<dstoff>_dstoff)?\s*$", re.IGNORECASE)


# ---------------------------------------------------------------- result types

@dataclass(frozen=True)
class Sample:
    """One sample line: its local time of day, the delay ``d:`` and the raw offset ``o:`` (seconds)."""
    time_text: str
    local_time: time
    delay_s: Decimal | None
    o_s: Decimal
    raw_line: str


@dataclass(frozen=True)
class Session:
    """One stripchart run (one ``Tracking`` header) with its samples and derived value.

    ``median_o_us`` is the median raw ``o:`` (integer µs, halves away from zero);
    ``offset_host_minus_dc01_ms`` = ``sign`` * median ``o:``, in whole ms. ``local_start`` is the
    host's local wall-clock time (the clock being measured, so it is off by the offset itself);
    ``utc_start`` is set only when a date and a time zone are known.
    """
    index: int
    target: str
    target_ok: bool
    target_reason: str | None
    requested_samples: int | None
    current_time_raw: str | None
    date: date | None
    date_reason: str | None
    samples: tuple[Sample, ...]
    error_count: int
    unparsed_lines: tuple[str, ...]
    median_o_us: int | None
    offset_host_minus_dc01_ms: int | None
    sign: int
    local_start: datetime | None
    utc_start: datetime | None
    raw_text: str

    @property
    def sample_count(self) -> int:
        """Number of samples with an offset value (error lines are not samples)."""
        return len(self.samples)

    @property
    def usable(self) -> bool:
        """A session counts for CO-12 only when it measured dc01 and has at least one sample."""
        return self.target_ok and self.median_o_us is not None


@dataclass(frozen=True)
class ReadingFile:
    """A parsed reading file: ``invalid`` (with reasons) when it has no session, any session does not track
    dc01 (CO-12, spec 08 section 4.2: such a file is still copied, and reported invalid here), or no time
    zone is known (owner D7). ``tz_name`` is the file's ``tzutil /g`` name, ``tz_key`` the zone used and
    ``tz_source`` where it came from (``file`` / ``argument``); ``notes`` explain choices that do not
    invalidate the file (e.g. an unknown zone name replaced by the caller's ``tz``)."""
    status: str
    reasons: tuple[str, ...]
    sessions: tuple[Session, ...]
    encoding: str | None = None
    path: str | None = None
    tz_name: str | None = None
    tz_key: str | None = None
    tz_source: str | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Assignment:
    """Readings assigned by time (CO-12). ``start``: last usable session before the run (and before the
    sync, when there is one); ``end``: first after the run end; ``post_sync``: first after the sync.
    ``unplaced``: sessions without a UTC time; ``unusable``: not dc01 or no samples; ``unassigned``:
    usable and timed but not chosen (e.g. taken during the run)."""
    start: Session | None
    end: Session | None
    post_sync: Session | None
    unplaced: tuple[Session, ...] = field(default=())
    unusable: tuple[Session, ...] = field(default=())
    unassigned: tuple[Session, ...] = field(default=())


# ---------------------------------------------------------------- decoding

def decode_bytes(data: bytes) -> tuple[str, str]:
    """(text, encoding name). BOM first (UTF-16 LE/BE, UTF-8), then BOM-less UTF-16 LE (many NULs at odd
    positions), then UTF-8, then Latin-1 as a lossless last resort.

    WHY: w32tm output redirected by PowerShell 5 is UTF-16 LE with a BOM; ``cmd >`` gives the OEM code
    page, which for this ASCII-only output decodes the same as UTF-8 / Latin-1.
    """
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le"), "utf-16-le-bom"
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be"), "utf-16-be-bom"
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8"), "utf-8-bom"
    if len(data) >= 4 and data[1::2].count(0) > len(data) // 4:
        return data.decode("utf-16-le"), "utf-16-le"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def read_reading_file(path: Path) -> tuple[str, str]:
    """(text, encoding) of a reading file; only reads (the copy under data/raw is never edited)."""
    return decode_bytes(Path(path).read_bytes())


# ---------------------------------------------------------------- small parsers

def check_target(target: str) -> tuple[bool, str | None]:
    """(ok, reason): the tracked host must be dc01 (name starting with dc01, any case) or 192.168.50.10.

    WHY strict: a reading taken against another server (or on dc01 against an endpoint, ATK-05)
    measures a different pair of clocks, so it must never be compared with the host - dc01 offset.
    """
    m = _TARGET_PARTS.match(target.strip())
    name = (m.group("name") or "").strip() if m else ""
    addr = (m.group("addr") or "").strip() if m else ""
    ip = addr.rsplit(":", 1)[0] if addr.count(":") == 1 else addr
    if name.lower().startswith(REFERENCE_NAME_PREFIX) or name == REFERENCE_IP or ip == REFERENCE_IP:
        return True, None
    return False, f"Tracking target {target!r} is not dc01 ({REFERENCE_NAME_PREFIX}* or {REFERENCE_IP})"


def seconds_to_us(text: str) -> int:
    """Signed decimal seconds text (``-14.6543210``) to integer µs, exact, halves away from zero."""
    return round_half_away(Fraction(Decimal(text)) * _US_PER_S)


def parse_time_of_day(h: str, m: str, s: str, ampm: str | None) -> time | None:
    """Clock time from its parts (12-hour form with AM/PM accepted), or None when out of range."""
    hour, minute, sec = int(h), int(m), int(s)
    if ampm:
        pm = ampm.lower().startswith("p")
        if not 1 <= hour <= 12:
            return None
        hour = (hour % 12) + (12 if pm else 0)
    if hour > 23 or minute > 59 or sec > 59:
        return None
    return time(hour, minute, sec)


def parse_date_text(text: str) -> tuple[date | None, str | None]:
    """(date, reason) from the "The current time is" text; a date is returned only when unambiguous.

    yyyy-mm-dd is read as such; with the year last, the day-month order is fixed only when one of
    the two numbers is > 12 (dd/mm/yyyy or mm/dd/yyyy). Equal numbers (05/05) are unambiguous too.
    WHY not guess: the lab locale is not recorded, and a swapped day/month would move a reading by
    weeks and assign it to the wrong trial phase. Years outside 2000..2099 (e.g. a Buddhist-era
    2569) are not converted.
    """
    m = _DATE.search(text)
    if not m:
        return None, f"no date found in {text!r}"
    a, b, c = m.group("a"), m.group("b"), m.group("c")
    if len(a) == 4:
        y, mo, d = int(a), int(b), int(c)
    elif len(c) == 4:
        y, x1, x2 = int(c), int(a), int(b)
        if x1 > 12 and x2 <= 12:
            d, mo = x1, x2
        elif x2 > 12 and x1 <= 12:
            mo, d = x1, x2
        elif x1 == x2:
            d = mo = x1
        else:
            return None, f"ambiguous day/month in {m.group(0)!r}; pass the date"
    else:
        return None, f"two-digit year in {m.group(0)!r}; pass the date"
    if not 2000 <= y <= 2099:
        return None, f"year {y} outside 2000..2099 in {m.group(0)!r}; pass the date"
    try:
        return date(y, mo, d), None
    except ValueError:
        return None, f"not a calendar date: {m.group(0)!r}"


def parse_current_time(text: str) -> tuple[date | None, str | None, time | None]:
    """(date, date reason, time of day) from the "The current time is ..." text."""
    d, reason = parse_date_text(text)
    t = None
    m = re.search(_TOD, text)
    if m:
        t = parse_time_of_day(m.group("h"), m.group("m"), m.group("s"), m.group("ampm"))
    return d, reason, t


def parse_sample(line: str) -> tuple[str, Sample | None]:
    """("sample", Sample) / ("error", None) / ("other", None) for one line after a Tracking header."""
    m = _SAMPLE_HEAD.match(line)
    if not m:
        return "other", None
    rest = m.group("rest").strip()
    if _ERROR.match(rest):
        return "error", None
    tod = parse_time_of_day(m.group("h"), m.group("m"), m.group("s"), m.group("ampm"))
    o = _O_FIELD.search(rest) or _DATAONLY.match(rest)
    if tod is None or o is None:
        return "other", None
    d = _D_FIELD.search(rest)
    try:
        o_val = Decimal(o.group("v").replace(",", "."))
        d_val = Decimal(d.group("v").replace(",", ".")) if d else None
    except InvalidOperation:
        return "other", None
    time_text = line[m.start("h"):m.end("ampm") if m.group("ampm") else m.end("s")]
    return "sample", Sample(time_text, tod, d_val, o_val, line.rstrip())


def median_us(values_us: Sequence[int]) -> int | None:
    """Median in integer µs (the mean of the two middle values rounded halves away from zero)."""
    if not values_us:
        return None
    return round_half_away(Fraction(statistics.median_low(values_us) + statistics.median_high(values_us), 2))


def to_ms(us: int) -> int:
    """µs to whole ms, halves away from zero."""
    return round_half_away(Fraction(us, 1000))


# ---------------------------------------------------------------- sessions

def split_sessions(lines: Sequence[str]) -> tuple[list[list[str]], list[str]]:
    """(sessions as line lists, each starting with its Tracking line; lines before the first header)."""
    sessions: list[list[str]] = []
    preamble: list[str] = []
    for line in lines:
        if _TRACKING.match(line):
            sessions.append([line])
        elif sessions:
            sessions[-1].append(line)
        else:
            preamble.append(line)
    return sessions, preamble


def local_times(day: date | None, start_tod: time | None, samples: Sequence[Sample]) -> datetime | None:
    """Local start datetime of a session: the current-time line, else the first sample, on ``day``.

    WHY a day is required: a time of day alone cannot be compared with the run window.
    """
    tod = start_tod or (samples[0].local_time if samples else None)
    if day is None or tod is None:
        return None
    return datetime.combine(day, tod)


def to_utc(local: datetime | None, tz: tzinfo | None) -> datetime | None:
    """Local wall-clock datetime to aware UTC with the given zone (None when either is missing)."""
    if local is None or tz is None:
        return None
    return local.replace(tzinfo=tz).astimezone(timezone.utc)


def parse_session(index: int, lines: Sequence[str], sign: int, given_date: date | None,
                  tz: tzinfo | None) -> Session:
    """One session from its lines (first line = Tracking header)."""
    target = _TRACKING.match(lines[0]).group("target")  # type: ignore[union-attr]
    ok, reason = check_target(target)
    requested = current_raw = None
    day: date | None = None
    date_reason: str | None = None
    start_tod: time | None = None
    samples: list[Sample] = []
    errors = 0
    unparsed: list[str] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if (m := _COLLECTING.match(line)):
            requested = int(m.group("n"))
        elif (m := _CURRENT.match(line)):
            current_raw = m.group("text")
            day, date_reason, start_tod = parse_current_time(current_raw)
        else:
            kind, s = parse_sample(line)
            if kind == "sample" and s is not None:
                samples.append(s)
            elif kind == "error":
                errors += 1
            else:
                unparsed.append(line.rstrip())
    day, date_reason = resolve_date(day, date_reason, given_date)
    med = median_us([seconds_to_us(str(s.o_s)) for s in samples])
    local = local_times(day, start_tod, samples)
    return Session(index=index, target=target, target_ok=ok, target_reason=reason, requested_samples=requested,
                   current_time_raw=current_raw, date=day, date_reason=date_reason, samples=tuple(samples),
                   error_count=errors, unparsed_lines=tuple(unparsed), median_o_us=med,
                   offset_host_minus_dc01_ms=None if med is None else to_ms(sign * med), sign=sign,
                   local_start=local, utc_start=to_utc(local, tz), raw_text="\n".join(l.rstrip() for l in lines))


def resolve_date(parsed: date | None, reason: str | None, given: date | None) -> tuple[date | None, str | None]:
    """The session date: the parsed one when unambiguous, else the caller's; a disagreement is not resolved.

    WHY no override on conflict: if the file says 23/11 and the caller says 24/11, one of them is
    wrong, and picking either silently could assign the reading to the wrong phase.
    """
    if parsed is not None and given is not None and parsed != given:
        return None, f"file date {parsed.isoformat()} differs from the given date {given.isoformat()}"
    if parsed is not None:
        return parsed, None
    if given is not None:
        return given, None
    return None, reason or "no 'The current time is' line; pass the date"


def tz_lines(lines: Sequence[str]) -> tuple[list[tuple[str, bool]], list[str]]:
    """([(zone name, dstoff)] of every ``tzutil /g`` line, the other lines). Header and sample lines never
    match (they start with ``Tracking`` or a time of day)."""
    found: list[tuple[str, bool]] = []
    rest: list[str] = []
    for line in lines:
        m = None if _TRACKING.match(line) or _SAMPLE_HEAD.match(line) else _TZ_LINE.match(line)
        if m:
            found.append((m.group("name").strip(), bool(m.group("dstoff"))))
        else:
            rest.append(line)
    return found, rest


def fixed_zone(minutes: int, label: str) -> timezone:
    """A fixed-offset zone named after its Windows name (for display only)."""
    return timezone(timedelta(minutes=minutes), label)


def resolve_windows_tz(name: str, dstoff: bool = False) -> tuple[tzinfo | None, str | None, str | None]:
    """(tzinfo, key, reason) for a Windows zone name; tzinfo None with a reason when it cannot be used.

    No-DST zones use their fixed offset (environment-independent). A DST zone needs ``zoneinfo`` with the
    IANA data and is refused otherwise; ``_dstoff`` on a DST zone (DST switched off by hand) is refused,
    because neither the fixed nor the IANA rules describe that clock.
    """
    entry = next((v for k, v in WINDOWS_TZ.items() if k.lower() == name.lower()), None)
    if entry is None:
        return None, None, f"unknown Windows time zone name {name!r}"
    iana, fixed = entry
    if fixed is not None:
        sign = "+" if fixed >= 0 else "-"
        key = f"UTC{sign}{abs(fixed) // 60:02d}:{abs(fixed) % 60:02d} (fixed; {iana})"
        return fixed_zone(fixed, name), key, None
    if dstoff:
        return None, None, f"{name}_dstoff: a DST zone with DST switched off is not supported; pass tz"
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        try:
            return ZoneInfo(iana), iana, None
        except (ZoneInfoNotFoundError, ValueError):
            pass
    except ImportError:  # pragma: no cover - zoneinfo is in the standard library from 3.9
        pass
    return None, None, f"{name} has daylight saving time and zoneinfo cannot load {iana} (no tzdata); pass tz"


def choose_tz(found: Sequence[tuple[str, bool]], given: tzinfo | None
              ) -> tuple[tzinfo | None, str | None, str | None, str | None, list[str], list[str]]:
    """(tz, tz_name, tz_key, tz_source, reasons, notes) from the file's tzutil lines and the caller's ``tz``.

    The file line wins when it is known; the caller's ``tz`` is used when the line is missing or unknown.
    Several different names, or no usable zone at all, invalidate the file (owner D7).
    """
    names = sorted({(n.lower(), d) for n, d in found})
    if len(names) > 1:
        return None, None, None, None, [f"several tzutil /g names in the file: {[n for n, _ in found]}"], []
    if names:
        name, dstoff = found[0]
        zone, key, why = resolve_windows_tz(name, dstoff)
        if zone is not None:
            return zone, name, key, TZ_SOURCE_FILE, [], []
        if given is not None:
            return given, name, str(given), TZ_SOURCE_ARGUMENT, [], [f"{why}; the given tz is used"]
        return None, name, None, None, [why or "time zone not usable"], []
    if given is not None:
        return given, None, str(given), TZ_SOURCE_ARGUMENT, [], []
    return None, None, None, None, ["no 'tzutil /g' line in the file and no tz argument: local times "
                                    "cannot be converted to UTC"], []


def tz_conflict(file_tz: tzinfo, given: tzinfo, at: datetime | None) -> str | None:
    """Reason when the file's zone and the caller's ``tz`` give different UTC offsets at ``at`` (local)."""
    if at is None:
        return None
    a, b = at.replace(tzinfo=file_tz).utcoffset(), at.replace(tzinfo=given).utcoffset()
    if a != b:
        return f"file time zone (UTC offset {a}) differs from the given tz (UTC offset {b})"
    return None


def parse_stripchart(text: str, *, sign: int = SIGN_CONVENTION, date: date | None = None,
                     tz: tzinfo | None = None, encoding: str | None = None, path: str | None = None) -> ReadingFile:
    """Parse a whole reading file's text into sessions (pure).

    ``sign``: host - dc01 = sign * o (default SIGN_CONVENTION, assumed -1). ``date``: used when the
    file's date is missing or ambiguous. ``tz``: the host's local zone, used when the file has no
    ``tzutil /g`` line or an unknown name; when both are known they must agree (otherwise invalid).
    """
    if sign not in (-1, 1):
        raise ValueError("sign must be -1 or +1")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").lstrip("\ufeff").split("\n")
    found, lines = tz_lines(lines)
    blocks, _preamble = split_sessions(lines)
    local_sessions = [parse_session(i, b, sign, date, None) for i, b in enumerate(blocks)]
    zone, tz_name, tz_key, tz_source, reasons, notes = choose_tz(found, tz)
    if zone is not None and tz is not None and tz_source == TZ_SOURCE_FILE:
        first_local = next((s.local_start for s in local_sessions if s.local_start is not None), None)
        conflict = tz_conflict(zone, tz, first_local)
        if conflict:
            reasons.append(conflict)
            zone = None
    sessions = tuple(replace(s, utc_start=to_utc(s.local_start, zone)) for s in local_sessions)
    if not sessions:
        reasons.insert(0, "no 'Tracking' line: not a w32tm /stripchart output")
    reasons += [f"session {s.index}: {s.target_reason}" for s in sessions if not s.target_ok]
    return ReadingFile(STATUS_INVALID if reasons else STATUS_VALID, tuple(reasons), sessions, encoding, path,
                       tz_name, tz_key if zone is not None else None, tz_source if zone is not None else None,
                       tuple(notes))


def parse_reading_file(path: Path, *, sign: int = SIGN_CONVENTION, date: date | None = None,
                       tz: tzinfo | None = None) -> ReadingFile:
    """Read (only) and parse one ``clock.txt``."""
    text, enc = read_reading_file(path)
    return parse_stripchart(text, sign=sign, date=date, tz=tz, encoding=enc, path=Path(path).as_posix())


# ---------------------------------------------------------------- assignment by time

def _require_aware(name: str, value: datetime | None) -> None:
    """Instants must carry a zone: comparing naive local times with UTC would shift by the zone offset."""
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise ValueError(f"{name} must be timezone-aware")


def assign_readings(readings: Sequence[Session], run_start_utc: datetime, run_end_utc: datetime,
                    sync_utc: datetime | None = None) -> Assignment:
    """Assign sessions to start / end / post-sync by time (CO-12).

    start = last usable session strictly before the run start, and strictly before the sync when one
    is given. WHY the sync bound: on t02-t10 the order is reading, sync, reading, run, so "last before
    the run" would be the post-sync reading, which no longer shows the skew the start reading is for.
    end = first usable session strictly after the run end (a reading after collection is after it).
    post_sync = first usable session strictly after the sync. Ties in time keep file order.
    """
    for n, v in (("run_start_utc", run_start_utc), ("run_end_utc", run_end_utc), ("sync_utc", sync_utc)):
        _require_aware(n, v)
    if run_end_utc < run_start_utc:
        raise ValueError("run_end_utc is before run_start_utc")
    unusable = tuple(s for s in readings if not s.usable)
    unplaced = tuple(s for s in readings if s.usable and s.utc_start is None)
    timed = sorted((s for s in readings if s.usable and s.utc_start is not None),
                   key=lambda s: s.utc_start)  # type: ignore[arg-type,return-value]
    start_limit = run_start_utc if sync_utc is None else min(run_start_utc, sync_utc)
    before = [s for s in timed if s.utc_start < start_limit]  # type: ignore[operator]
    start = before[-1] if before else None
    end = next((s for s in timed if s.utc_start > run_end_utc), None)  # type: ignore[operator]
    post = None if sync_utc is None else next((s for s in timed if s.utc_start > sync_utc), None)  # type: ignore[operator]
    chosen = {id(x) for x in (start, end, post) if x is not None}
    rest = tuple(s for s in timed if id(s) not in chosen)
    return Assignment(start, end, post, unplaced, unusable, rest)
