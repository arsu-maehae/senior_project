"""Per-host clock files of the x10_v2 reruns: find, name-check, hash, and list in the manifest (spec 08 section 4.2).

The lab saves one ``<HOST>_clock.txt`` per VM per trial directly in the trial folder (``EP-01_clock.txt`` ...). The
ingest copies it byte for byte to ``data/raw/<s>/<t>/<host>/clock.txt`` and adds a manifest row ``channel=clock``.
The file is NEVER parsed or split here: ``clock_offset.readings`` reads it later (CO-12), so the raw copy stays the
evidence and a parser fix never needs a re-ingest.

Everything in this module is a small function; the only disk access is the explicit read of a file or folder given.
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from data_layout import layout as L

# CO-12: readings are taken on the endpoints; dc01 is the reference clock ("Tracking dc01") and has no file.
EXPECTED_CLOCK_HOSTS: tuple[str, ...] = ("ep-01", "ep-02", "ep-03")

_CLOCK_NAME_RE = re.compile(r"^(?P<host>.+)_clock\.txt$", re.IGNORECASE)
_EVENT_LOG_SUFFIXES = (".evtx", ".evt")


@dataclass(frozen=True)
class ClockScan:
    """Result of looking at one trial folder (read-only)."""
    found: dict[str, Path]       # host -> the one clock file directly in the trial folder
    refused: list[str]           # one reason per problem; each names the offending file
    missing_hosts: list[str]     # EXPECTED_CLOCK_HOSTS without a file (not a refusal; sorted)


def clock_host(name: str) -> str | None:
    """``EP-01_clock.txt`` -> ``ep-01`` via ``layout.normalise_host``; None for any other name or host.

    WHY: the host must come from the file name through the same normaliser as the EVTX folders, and a name that
    does not fit exactly is never guessed (a wrong host would put one machine's clock on another)."""
    m = _CLOCK_NAME_RE.match(name)
    if not m:
        return None
    host = L.normalise_host(m.group("host"))
    return host if host in EXPECTED_CLOCK_HOSTS else None


def looks_like_clock_file(name: str) -> bool:
    """True for anything that was clearly meant as a clock file, including misnamed ones (``clock.txt``).

    WHY: a misnamed file must be reported and refused, not silently ignored (it would look like a missing reading)."""
    low = name.lower()
    return "clock" in low and not low.endswith(_EVENT_LOG_SUFFIXES)


def _rel(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def scan_trial_folder(trial_dir: Path) -> ClockScan:
    """Walk the trial folder and sort every clock-like file into found / refused; list missing hosts.

    Refused: a clock-like name that does not parse, an unknown host, two files for one host (neither is picked),
    and any clock-like file below a subfolder (the spec says the trial folder itself)."""
    by_host: dict[str, list[Path]] = {}
    refused: list[str] = []
    for p in sorted(x for x in trial_dir.rglob("*") if x.is_file() and looks_like_clock_file(x.name)):
        rel = _rel(p, trial_dir)
        if p.parent != trial_dir:
            refused.append(f"clock file {rel!r} is inside a subfolder; it must be directly in the trial folder")
            continue
        host = clock_host(p.name)
        if host is None:
            refused.append(f"clock file {rel!r}: name is not <HOST>_clock.txt with a host in "
                           f"{', '.join(EXPECTED_CLOCK_HOSTS)}")
            continue
        by_host.setdefault(host, []).append(p)
    found: dict[str, Path] = {}
    for host, paths in sorted(by_host.items()):
        if len(paths) > 1:
            refused.append(f"clock files {', '.join(repr(_rel(p, trial_dir)) for p in paths)} all map to {host}; "
                           "not guessing which one is the reading")
        else:
            found[host] = paths[0]
    missing = [h for h in EXPECTED_CLOCK_HOSTS if h not in found]
    return ClockScan(found, refused, missing)


def clock_manifest_row(path: Path, dest_rel: str, scenario: str, trial: str, host: str,
                       source_path: str) -> dict[str, object]:
    """One manifest row for a clock file in raw; exactly ``layout.MANIFEST_COLUMNS``.

    WHY records / first_event_utc / last_event_utc are empty: the export-span code (lab_common.manifest) keeps only
    rows with event times, so a clock row can never stretch a trial's export window (spec 08 section 4.2)."""
    mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = {"path": dest_rel, "sha256": L.sha256_file(path), "size": path.stat().st_size, "scenario": scenario, "trial": trial,
           "host": host, "channel": "clock", "source_path": source_path, "date": mtime,
           "records": "", "first_event_utc": "", "last_event_utc": ""}
    return {c: row[c] for c in L.MANIFEST_COLUMNS}


def append_clock_rows(manifest: Path, rows: Sequence[Mapping[str, object]]) -> int:
    """Append rows whose ``path`` is not yet listed; returns the number added.

    Existing bytes are never changed and the file's own line ending is kept (CRLF for the real manifest). A
    manifest an append would corrupt (BOM, empty, no final newline) is refused with ValueError before any write.
    The caller holds the manifest lock; idempotent so a resumed ingest does not duplicate rows."""
    existing_bytes = manifest.read_bytes() if manifest.exists() else None
    listed: set[str] = set()
    eol = "\r\n"
    if existing_bytes is not None:
        L.check_manifest_appendable(existing_bytes, manifest.name)
        eol = L.manifest_line_ending(existing_bytes)
        listed = {r["path"] for r in csv.DictReader(io.StringIO(existing_bytes.decode("utf-8"), newline=""))}
    new = [r for r in rows if r["path"] not in listed]
    if not new:
        return 0
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, L.MANIFEST_COLUMNS, lineterminator=eol)
        if existing_bytes is None:
            w.writeheader()
        w.writerows(new)
    return len(new)
