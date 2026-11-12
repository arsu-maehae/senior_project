"""The one shared corrected-time function and the offsets-file reader (spec 08 CO-09, CO-17; section 4.1).

WHY one module: CO-09 requires every consumer (trial_window, the gate, T7) to compute
``event_utc_corrected = event_utc - offset_ms(host)`` with the same pure function, so a host is
never corrected one way in the window and another way in the gate. The same holds for the event-level
``clock_unreliable`` of owner D5 (``event_unreliable``). Everything here is pure except ``load_offsets``
and ``load_clock_changes``, which read only the path they are given.
"""
from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping

from gate.timeutil import US_PER_MS

from . import params
from .changes import CLOCK_CHANGES_COLUMNS, ClockChange, before_counted, change_from_row

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class HostOffset:
    """One host's row of the offsets file, as the consumers need it."""
    host: str
    status: str
    offset_ms: int | None
    offset_unc_ms: int | None
    host_has_events: bool

    @property
    def applied(self) -> bool:
        """True when the offset is subtracted (reference, ok, wide; CO-06: wide is corrected)."""
        return self.status in params.CORRECTED_STATUSES and self.offset_ms is not None


@dataclass(frozen=True)
class Offsets:
    """The offsets of one trial plus the hashes that tie them to their inputs (spec 08 section 4.1 item 3).

    ``db_sha256`` is the DB the offsets were computed from; ``file_sha256`` is the hash of the
    offsets file bytes ("" when built in memory), which trial_window records as ``offsets_sha256``.
    """
    trial_id: str
    db_sha256: str
    file_sha256: str
    hosts: Mapping[str, HostOffset]

    @property
    def clock_flag(self) -> list[str]:
        """Hosts with status none/wide/stale that have events in the window, sorted (CO-08)."""
        return sorted(h for h, o in self.hosts.items()
                      if o.status in params.UNRELIABLE_STATUSES and o.host_has_events)


# ---------------------------------------------------------------- cell parsing

def _int_cell(value: Any) -> int | None:
    """CSV cell or native value to int; empty / None -> None."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"boolean where an integer was expected: {value!r}")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text) if text else None


def _bool_cell(value: Any) -> bool:
    """CSV cell (``true``/``false``) or native bool to bool; anything else is an error, never a guess."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "false"):
        return text == "true"
    raise ValueError(f"not a boolean cell: {value!r}")


# ---------------------------------------------------------------- building

def offsets_from_rows(rows: Iterable[Mapping[str, Any]], file_sha256: str = "") -> Offsets:
    """Offsets from offsets rows (CSV dicts or the in-memory rows of ``estimate.offsets_rows``).

    WHY one builder for both: the CO-10 check uses the offsets just computed, the consumers use the
    file, and both must go through the same parsing so they cannot disagree. All rows must share one
    trial id and one db_sha256, and a status must be one of the spec values.
    """
    hosts: dict[str, HostOffset] = {}
    trials, shas = set(), set()
    for r in rows:
        status = str(r["offset_status"]).strip()
        if status not in params.STATUSES:
            raise ValueError(f"unknown offset_status {status!r} for host {r.get('host')!r}")
        host = str(r["host"]).strip()
        if host in hosts:
            raise ValueError(f"duplicate host row {host!r}")
        hosts[host] = HostOffset(host, status, _int_cell(r.get("offset_ms")), _int_cell(r.get("offset_unc_ms")),
                                 _bool_cell(r["host_has_events"]))
        trials.add(str(r["trial_id"]).strip())
        shas.add(str(r["db_sha256"]).strip())
    if len(trials) != 1 or len(shas) != 1:
        raise ValueError(f"offsets rows must name one trial and one DB hash (trials {sorted(trials)}, "
                         f"hashes {sorted(shas)})")
    return Offsets(trials.pop(), shas.pop(), file_sha256, MappingProxyType(hosts))


def parse_offsets_text(text: str, file_sha256: str = "") -> Offsets:
    """Offsets from the CSV text of a ``<trial>.clock_offsets.csv`` file; the header must match section 3."""
    reader = csv.DictReader(io.StringIO(text))
    if tuple(reader.fieldnames or ()) != params.OFFSETS_COLUMNS:
        raise ValueError(f"offsets header {reader.fieldnames} differs from spec 08 section 3")
    return offsets_from_rows(list(reader), file_sha256)


def load_offsets(path: Path) -> Offsets:
    """Read ``<trial>.clock_offsets.csv``; ``file_sha256`` is the SHA-256 of the exact file bytes."""
    data = Path(path).read_bytes()
    return parse_offsets_text(data.decode("utf-8"), hashlib.sha256(data).hexdigest())


# ---------------------------------------------------------------- consumers (CO-09, CO-17)

def corrected_us(us: int, host: str, offsets: Offsets) -> int:
    """``event_utc_corrected`` in integer microseconds: us - offset_ms * 1000 when the host's offset is
    applied (reference, ok, wide); unchanged for none, stale or a host not in the file (CO-09)."""
    o = offsets.hosts.get(host)
    if o is None or not o.applied:
        return us
    assert o.offset_ms is not None
    return us - o.offset_ms * US_PER_MS


def is_unreliable(host: str, offsets: Offsets) -> bool:
    """True when the host's time cannot be trusted for cross-host comparison: status none, wide or
    stale, or a host the offsets file does not know (CO-09: never assume a clock is fine)."""
    o = offsets.hosts.get(host)
    return o is None or o.status in params.UNRELIABLE_STATUSES


def clock_unreliable(*hosts: str, offsets: Offsets) -> bool:
    """Row-level ``clock_unreliable``: true when any host of a cross-host row is unreliable (CO-09, ATK-03)."""
    return any(is_unreliable(h, offsets) for h in hosts)


def co17_refusal(offsets: Offsets, window_start_us: int, co17_date=params.CO17_DATE) -> str | None:
    """Reason text if the trial must be refused under CO-17, else None.

    A window starting on or after 2026-10-26 (date in UTC) is refused when a host with events in the
    window is uncorrected (none or stale): raw times there may be up to 27 s wrong (decision 032).
    A wide host is corrected and runs (owner Q2).
    """
    start_date = (_EPOCH + timedelta(microseconds=window_start_us)).date()   # exact, no float division
    if start_date < co17_date:
        return None
    bad = sorted(h for h, o in offsets.hosts.items()
                 if o.host_has_events and o.status in (params.STATUS_NONE, params.STATUS_STALE))
    if not bad:
        return None
    detail = ", ".join(f"{h} ({offsets.hosts[h].status})" for h in bad)
    return (f"window starts on or after {co17_date.isoformat()} and host(s) with events are not corrected: "
            f"{detail} (spec 08 CO-17)")


# ---------------------------------------------------------------- clock changes (owner D5)

@dataclass(frozen=True)
class ClockChanges:
    """The clock changes of one trial (``<trial>.clock_changes.csv``) and the hash of the file bytes.

    Iterable, so it can be passed wherever a sequence of ``ClockChange`` is expected.
    """
    trial_id: str | None
    file_sha256: str
    changes: tuple[ClockChange, ...]

    def __iter__(self) -> Iterator[ClockChange]:
        return iter(self.changes)


def parse_clock_changes_text(text: str, file_sha256: str = "") -> ClockChanges:
    """ClockChanges from the CSV text of a clock_changes file; the header must match exactly.

    WHY strict: a consumer that silently read a file with other columns could mark the wrong events
    unreliable; one trial per file, as for the offsets file.
    """
    reader = csv.DictReader(io.StringIO(text))
    if tuple(reader.fieldnames or ()) != CLOCK_CHANGES_COLUMNS:
        raise ValueError(f"clock_changes header {reader.fieldnames} differs from {list(CLOCK_CHANGES_COLUMNS)}")
    rows = list(reader)
    trials = {str(r["trial_id"]).strip() for r in rows}
    if len(trials) > 1:
        raise ValueError(f"clock_changes rows name several trials: {sorted(trials)}")
    return ClockChanges(trials.pop() if trials else None, file_sha256, tuple(change_from_row(r) for r in rows))


def load_clock_changes(path: Path) -> ClockChanges:
    """Read ``<trial>.clock_changes.csv``; ``file_sha256`` is the SHA-256 of the exact file bytes."""
    data = Path(path).read_bytes()
    return parse_clock_changes_text(data.decode("utf-8"), hashlib.sha256(data).hexdigest())


def before_counted_change(host: str, recorded_us: int, changes: Iterable[ClockChange]) -> bool:
    """True when an event of ``host`` recorded at ``recorded_us`` was logged before a counted clock change on
    that host: recorded time in [last boot before the change, max(previous_time, change time)); for a backward
    step up to previous_time inclusive, because the overlap holds events of both clocks (owner D4/D5).

    WHY: the host's single offset describes its clock after the change, so such an event's corrected time
    is not trustworthy. Boots are not clock changes and are not in the file; routine changes do not count.
    """
    return before_counted(host, recorded_us, changes)


def event_unreliable(host: str, recorded_us: int, offsets: Offsets, changes: Iterable[ClockChange] = ()) -> bool:
    """Event-level ``clock_unreliable`` (D5): the host is unreliable (none / wide / stale / unknown) OR the
    event was logged before a counted clock change on its host. ``corrected_us`` is unchanged by this."""
    return is_unreliable(host, offsets) or before_counted_change(host, recorded_us, changes)
