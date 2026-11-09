"""Pure helpers for the data-layout stage (no hidden I/O beyond explicit file reads/writes)."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Optional

EVTX_MAGIC = b"ElfFile\x00"
LEGACY_MAGIC = b"LfLe"

CHANNELS: dict[str, str] = {
    "security": "security",
    "system": "system",
    "microsoft-windows-sysmon/operational": "sysmon",
    "microsoft-windows-winrm/operational": "winrm",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "psclassic",
}

MAP_COLUMNS = ["source_path", "scenario", "trial", "host", "channel",
               "dest_path", "action", "reason"]
MANIFEST_COLUMNS = ["path", "sha256", "size", "scenario", "trial", "host", "channel",
                    "source_path", "date", "records", "first_event_utc", "last_event_utc"]

_HOST_RE = re.compile(r"^(?:(dc)-?0*(\d)|(?:ep|endpoint)-?0*(\d))$", re.IGNORECASE)
_SCEN_RE = re.compile(r"(?<![a-z0-9])s0(\d)(?![0-9])", re.IGNORECASE)


@dataclass(frozen=True)
class MapRow:
    source_path: str
    scenario: str
    trial: str
    host: str
    channel: str
    dest_path: str
    action: str
    reason: str


@dataclass(frozen=True)
class LogInfo:
    """What we learn by reading an EVTX once."""
    channel: str          # raw Channel of first record ("" if no records)
    computer: str         # raw Computer of first record
    records: int
    first_utc: str
    last_utc: str


# ---------- name parsing ----------

def normalise_host(text: str) -> Optional[str]:
    """Map a folder name or Computer FQDN to dc01/ep-0N, or None.

    WHY: hosts appear as DC-01, EP01, ENDPOINT-02, Endpoint-01.lab.local; joins need one spelling."""
    label = text.strip().split(".")[0]
    m = _HOST_RE.match(label)
    if not m:
        return None
    return f"dc0{m.group(2)}" if m.group(1) else f"ep-0{m.group(3)}"


def find_scenario(parts: Iterable[str]) -> Optional[str]:
    """Find s0N (case-insensitive) in any path component, e.g. Dryrun_S03 -> s03."""
    for p in parts:
        m = _SCEN_RE.search(p)
        if m:
            return f"s0{m.group(1)}"
    return None


def host_from_parts(dir_parts: list[str]) -> Optional[str]:
    """Host = the deepest folder that names a host (first folder normally; a deeper
    EP-02 inside ep-01/Dryrun_S01 overrides it, because the export is of that machine)."""
    host = None
    for p in dir_parts:
        host = normalise_host(p) or host
    return host


def channel_from_raw(raw: str) -> Optional[str]:
    """Channel is taken from the record, never the file name (names are unreliable)."""
    return CHANNELS.get(raw.strip().lower())


def is_vmware(parts: list[str]) -> bool:
    return (parts[-1].lower().startswith("vmware-")
            or any(p in ("DiagOutputDir", "vmware-SYSTEM") for p in parts[:-1]))


def read_magic(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read(8)


def scan_evtx(path: Path) -> LogInfo:
    """Parse the file once: first record's Channel/Computer plus count and time span."""
    from evtx import PyEvtxParser
    channel = computer = first = last = ""
    n = 0
    for rec in PyEvtxParser(str(path)).records_json():
        if n == 0:
            sysd = json.loads(rec["data"]).get("Event", {}).get("System", {})
            channel = str(sysd.get("Channel", ""))
            computer = str(sysd.get("Computer", ""))
        ts = _utc(rec["timestamp"])
        first = ts if not first or ts < first else first
        last = ts if ts > last else last
        n += 1
    return LogInfo(channel, computer, n, first, last)


def _utc(ts: str) -> str:
    """Normalise parser timestamps to ISO-8601 Z so string comparison orders correctly."""
    if not ts:
        return ""
    s = ts.strip().removesuffix(" UTC").replace("Z", "+00:00")
    # python 3.11 fromisoformat accepts up to 6 fractional digits only on some builds;
    # the parser emits 7 (100 ns ticks), so truncate to microseconds.
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------- mapping ----------

def classify_file(rel: PurePosixPath, magic: bytes,
                  info_loader: Callable[[], LogInfo], trial: str,
                  scenario_arg: Optional[str] = None) -> MapRow:
    """Decide copy/ignore for one file. info_loader is lazy so non-logs are never parsed."""
    parts = list(rel.parts)
    src = rel.as_posix()

    def ign(reason: str, scen: str = "", host: str = "", chan: str = "") -> MapRow:
        return MapRow(src, scen, trial, host, chan, "", "ignore", reason)

    if is_vmware(parts):
        return ign("VMware file, not an event log")
    scenario = scenario_arg or find_scenario(parts)
    host = host_from_parts(parts[:-1]) or ""
    if magic[:4] == LEGACY_MAGIC:
        return ign("legacy EVT not supported", scenario or "", host)
    if magic != EVTX_MAGIC:
        return ign("not an event log", scenario or "", host)
    if not scenario:
        return ign("no scenario (s0N) in path", "", host)
    if not host:
        return ign("no host in path", scenario)
    try:
        info = info_loader()
    except Exception as exc:  # corrupt file: report, do not crash the walk
        return ign(f"unreadable EVTX: {exc}", scenario, host)
    chan = channel_from_raw(info.channel)
    if chan is None:
        return ign(f"unknown channel {info.channel!r}" if info.channel
                   else "no records, channel unknown", scenario, host)
    notes = []
    if rel.suffix.lower() == ".evt":
        notes.append("EVTX header, renamed from .evt")
    comp = normalise_host(info.computer) if info.computer else None
    if comp and comp != host:
        notes.append(f"Computer {info.computer!r} -> {comp} disagrees with path host {host}; kept path host")
    elif not comp and info.computer:
        notes.append(f"Computer {info.computer!r} not a lab name; kept path host")
    dest = f"{scenario}/{trial}/{host}/{chan}.evtx"
    return MapRow(src, scenario, trial, host, chan, dest, "copy", "; ".join(notes) or "ok")


def apply_overrides(rows: list[MapRow], overrides: dict[str, dict[str, str]]) -> list[MapRow]:
    """An override row replaces action/reason (and dest_path if given) for its source_path."""
    out = []
    for r in rows:
        o = overrides.get(r.source_path)
        if o is None:
            out.append(r)
            continue
        action = o["action"].strip()
        dest = (o.get("dest_path") or "").strip() or (r.dest_path if action == "copy" else "")
        out.append(replace(r, action=action, reason=(o.get("reason") or "").strip() or "override",
                           dest_path=dest))
    return out


def find_collisions(rows: list[MapRow]) -> dict[str, list[str]]:
    """dest_path -> source paths, for dests claimed by more than one copy row."""
    seen: dict[str, list[str]] = {}
    for r in rows:
        if r.action == "copy":
            seen.setdefault(r.dest_path, []).append(r.source_path)
    return {d: s for d, s in seen.items() if len(s) > 1}


def build_mapping(source: Path, trial: str, scenario_arg: Optional[str] = None,
                  overrides: Optional[dict[str, dict[str, str]]] = None) -> list[MapRow]:
    """Walk source (read-only), classify every file, apply overrides, reject collisions."""
    rows = []
    for p in sorted(x for x in source.rglob("*") if x.is_file()):
        rel = PurePosixPath(p.relative_to(source).as_posix())
        rows.append(classify_file(rel, read_magic(p), lambda p=p: scan_evtx(p), trial, scenario_arg))
    rows = apply_overrides(rows, overrides or {})
    bad = find_collisions(rows)
    if bad:
        msg = "; ".join(f"{d} <- {' AND '.join(s)}" for d, s in bad.items())
        raise ValueError(f"dest_path collision (add an override to ignore one): {msg}")
    return sorted(rows, key=lambda r: (r.dest_path == "", r.dest_path, r.source_path))


def read_overrides(path: Path) -> dict[str, dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return {r["source_path"]: r for r in csv.DictReader(f)}


def write_rows(path: Path, columns: list[str], rows: Iterable[dict[str, object]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, columns)
        w.writeheader()
        w.writerows(rows)


def read_mapping(path: Path) -> list[MapRow]:
    with open(path, newline="", encoding="utf-8") as f:
        return [MapRow(**{k: r[k] for k in MAP_COLUMNS}) for r in csv.DictReader(f)]


# ---------- copy ----------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_dest(raw_root: Path, dest_rel: str) -> Path:
    """Resolve dest and refuse anything outside raw_root or inside data/incoming."""
    root = raw_root.resolve()
    dest = (root / dest_rel).resolve()
    if dest != root and root not in dest.parents:
        raise ValueError(f"dest escapes raw root: {dest_rel}")
    parts = [p.lower() for p in dest.parts]
    for i in range(len(parts) - 1):
        if parts[i] == "data" and parts[i + 1] == "incoming":
            raise ValueError(f"dest inside data/incoming: {dest_rel}")
    return dest


def copy_one(src: Path, dest: Path) -> str:
    """Copy via temp name, publish with os.replace only if dest is absent, verify sha256.

    WHY: raw evidence must never be overwritten or left half-written."""
    if dest.exists():
        raise FileExistsError(f"refusing to overwrite {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    try:
        shutil.copyfile(src, tmp)
        want = sha256_file(src)
        if sha256_file(tmp) != want:
            raise IOError(f"sha256 mismatch copying {src}")
        if dest.exists():
            raise FileExistsError(f"refusing to overwrite {dest}")
        st = src.stat()
        os.utime(tmp, ns=(st.st_atime_ns, st.st_mtime_ns))  # keep export time for manifest date
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()
    return want


def copy_all(source: Path, rows: list[MapRow], raw_root: Path) -> tuple[int, int, list[str]]:
    """Copy every action=copy row. Returns (copied, ignored, errors); continues past errors."""
    copied = ignored = 0
    errors: list[str] = []
    for r in rows:
        if r.action != "copy":
            ignored += 1
            continue
        try:
            copy_one(source / r.source_path, safe_dest(raw_root, r.dest_path))
            copied += 1
        except Exception as exc:
            errors.append(f"{r.source_path} -> {r.dest_path}: {exc}")
    return copied, ignored, errors


# ---------- manifest ----------

def manifest_row(raw_root: Path, r: MapRow) -> dict[str, object]:
    """One manifest line for a copied file; all facts come from the file in raw, not the source."""
    p = safe_dest(raw_root, r.dest_path)
    info = scan_evtx(p)
    mtime = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"path": r.dest_path, "sha256": sha256_file(p), "size": p.stat().st_size,
            "scenario": r.scenario, "trial": r.trial, "host": r.host, "channel": r.channel,
            "source_path": r.source_path, "date": mtime, "records": info.records,
            "first_event_utc": info.first_utc, "last_event_utc": info.last_utc}


def append_manifest(raw_root: Path, rows: list[MapRow], out: Path) -> tuple[int, int]:
    """Append rows for paths not yet listed; existing lines are never rewritten. Returns (added, skipped)."""
    existing: set[str] = set()
    if out.exists():
        with open(out, newline="", encoding="utf-8") as f:
            existing = {r["path"] for r in csv.DictReader(f)}
    new = [manifest_row(raw_root, r) for r in rows
           if r.action == "copy" and r.dest_path not in existing]
    skipped = sum(1 for r in rows if r.action == "copy") - len(new)
    if new:
        out.parent.mkdir(parents=True, exist_ok=True)
        fresh = not out.exists()
        with open(out, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, MANIFEST_COLUMNS)
            if fresh:
                w.writeheader()
            w.writerows(new)
    return len(new), skipped
