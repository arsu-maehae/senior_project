"""Synthetic repos for the archive and retire-failed tests (T6c Task 3; plan 2026-11-15, attacker review 2026-11-15).

Everything here is tiny fake bytes in a tmp folder: the archive tool only hashes and moves bytes, so no real EVTX,
no real data and no t02-t10 data are read. Layout facts come from the task brief (data/manifest.csv is CRLF, no BOM,
ends with CRLF; old rows have source_path ``x10/S04/trial_01/...``, v2 rows ``x10_v2/S04/trial_01/...``; the
manifest ``path`` is ``s04/t01/ep-01/security.evtx`` for both).

``build_v1``      the old S04/S07 copies on the normal paths, plus staying trials and look-alikes.
``build_failed``  a failed x10_v2 attempt that was ingested, with its attempt folder under data/incoming/x10_v2_failed.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

COLUMNS = ["path", "sha256", "size", "scenario", "trial", "host", "channel", "source_path", "date", "records",
           "first_event_utc", "last_event_utc"]
HEADER_LINE = ",".join(COLUMNS).encode()
HOSTDIR = {"dc01": "DC01", "ep-01": "ENDPOINT-01"}
CHAN_NAME = {"security": "Security", "sysmon": "Microsoft-Windows-SysmonOperational"}
EVTX = (("dc01", "security"), ("ep-01", "security"), ("ep-01", "sysmon"))
V1_LABEL = "archive_x10_v1"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def blob(tag: str) -> bytes:
    """Distinct fake file content per tag (so every sha256 in a world is unique)."""
    return (f"synthetic file {tag}\n").encode() * 3


def csv_line(row: dict) -> bytes:
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow([row.get(c, "") for c in COLUMNS])
    return buf.getvalue().encode()


def manifest_bytes(lines: list[bytes]) -> bytes:
    return HEADER_LINE + b"\r\n" + b"".join(line + b"\r\n" for line in lines)


def split_manifest(data: bytes) -> list[bytes]:
    """Data lines of a CRLF manifest (header dropped); asserts the file ends with CRLF."""
    assert data.endswith(b"\r\n"), "manifest must end with CRLF"
    parts = data.split(b"\r\n")
    assert parts[-1] == b"" and parts[0] == HEADER_LINE
    return parts[1:-1]


def scen_dir(s: str) -> str:
    return "S0" + s[-1]          # s04 -> S04


def trial_dir(t: str) -> str:
    return "trial_" + t[1:]      # t01 -> trial_01


def write(repo: Path, rel: str, data: bytes) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def tree(root: Path, exclude: tuple[str, ...] = ()) -> dict[str, str | None]:
    """Every file (sha256) and every directory (None) under root, posix relative paths."""
    out: dict[str, str | None] = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if any(rel == e or rel.startswith(e.rstrip("/") + "/") for e in exclude):
            continue
        out[rel] = sha(p.read_bytes()) if p.is_file() else None
    return out


def files_of(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def make_link(link: Path, target: Path) -> bool:
    """Directory symlink or NTFS junction; False when neither can be created here (the test then skips)."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        return r.returncode == 0 and link.exists()
    return False


@dataclass
class World:
    repo: Path
    label: str
    initial: dict[str, bytes] = field(default_factory=dict)      # every file at build time, relative posix
    moved: list[str] = field(default_factory=list)               # files the preset moves
    ids: list[str] = field(default_factory=list)                 # trial ids the preset moves
    lines: list[bytes] = field(default_factory=list)             # all manifest data lines in order
    moved_lines: list[bytes] = field(default_factory=list)
    manifest: bytes = b""

    @property
    def stay(self) -> list[str]:
        return [p for p in self.initial if p not in set(self.moved)]

    def dest_of(self, rel: str) -> str:
        return dest_rel(rel, self.label)


def dest_rel(rel: str, label: str) -> str:
    """Where a source file goes in the archive (plan table of Task 3; ingest/validate rules in the module docstring
    of data_layout.archive)."""
    parts = rel.split("/")
    if parts[:2] == ["data", "raw"]:
        return "/".join(["data", "raw", label] + parts[2:])
    if parts[:3] == ["data", "processed", "jsonl"]:
        return "/".join(["data", "processed", label, "jsonl"] + parts[3:])
    if parts[:2] == ["data", "processed"]:
        return "/".join(["data", "processed", label] + parts[2:])
    if parts[:3] == ["out", "ingest", "x10_v2"]:
        return "/".join(["out", "ingest", label] + parts[3:])
    if parts[:2] == ["out", "x10_validate_v2"]:
        return "/".join(["out", "x10_validate_v2", label] + parts[2:])
    if parts[0] == "out" and parts[1] in ("normalise", "clock_offset"):
        return "/".join(["out", parts[1], label] + parts[2:])
    raise AssertionError(f"no archive destination defined for {rel}")


# ============================================================================ V1 world

def _add_old_trial(w: World, files: dict[str, bytes], s: str, t: str, *, moved: bool, clock_csv: bool = False,
                   source_prefix: str = "x10", scenario_col: str | None = None, trial_col: str | None = None) -> None:
    """One old trial: raw evtx + DB + JSONL + normalise (+ clock csv/out), manifest rows, ingest.json, validator json."""
    tid = f"{s}_{t}"
    mv: list[str] = []
    copied = []
    for host, chan in EVTX:
        data = blob(f"{tid}-{host}-{chan}")
        dest = f"{s}/{t}/{host}/{chan}.evtx"
        src = (f"{source_prefix}/{scen_dir(s)}/{trial_dir(t)}/{HOSTDIR[host]}/{HOSTDIR[host]}_{CHAN_NAME[chan]}.evtx")
        files[f"data/raw/{dest}"] = data
        mv.append(f"data/raw/{dest}")
        files[f"data/incoming/{src}"] = data
        copied.append({"source_path": src, "dest_path": dest, "host": host, "channel": chan, "sha256": sha(data),
                       "size": len(data), "action": "copied", "reason": "ok"})
        line = csv_line({"path": dest, "sha256": sha(data), "size": len(data), "scenario": scenario_col or s,
                         "trial": trial_col or t, "host": host, "channel": chan, "source_path": src,
                         "date": "2026-10-01T00:00:00Z", "records": "10",
                         "first_event_utc": "2026-10-01T00:00:01.000000Z",
                         "last_event_utc": "2026-10-01T00:09:01.000000Z"})
        w.lines.append(line)
        if moved:
            w.moved_lines.append(line)
    files[f"data/processed/{tid}.sqlite3"] = blob(f"{tid}-db")
    mv.append(f"data/processed/{tid}.sqlite3")
    for name in ("dc01_security.jsonl", "ep-01_security.jsonl", "converter_manifest.json"):
        files[f"data/processed/jsonl/{tid}/{name}"] = blob(f"{tid}-jsonl-{name}")
        mv.append(f"data/processed/jsonl/{tid}/{name}")
    for name in ("import_report.json", "ep-01/security.json"):
        files[f"out/normalise/{tid}/{name}"] = blob(f"{tid}-norm-{name}")
        mv.append(f"out/normalise/{tid}/{name}")
    if clock_csv:
        for name in ("clock_offsets.csv", "clock_changes.csv"):
            files[f"data/processed/{tid}.{name}"] = blob(f"{tid}-{name}")
            mv.append(f"data/processed/{tid}.{name}")
        files[f"out/clock_offset/{tid}/clock_offset.json"] = blob(f"{tid}-clock-out")
        mv.append(f"out/clock_offset/{tid}/clock_offset.json")
    ingest = {"trial_id": tid, "scenario": s, "trial": t, "status": "ok", "error": None, "files_copied": copied,
              "files_ignored": [], "reconcile": {"ok": True}}
    files[f"out/ingest/x10/{tid}/ingest.json"] = (json.dumps(ingest, indent=2) + "\n").encode()
    files[f"out/ingest/x10/{tid}/ingest.md"] = blob(f"{tid}-ingest-md")
    files[f"out/x10_validate/{tid}.json"] = (json.dumps({"trial_id": tid, "criteria": {"a": {"status": "PASS"}}})
                                             + "\n").encode()
    if moved:
        w.moved += mv
        w.ids.append(tid)


def build_v1(tmp: Path) -> World:
    """Old S04/S07 copies. Moved: s04 t01 t02 t10, s07 t01 t05. Stay: t00 of s04/s07, s02 t01, s03 t01, look-alikes
    s04 t1 / t010 / t11, s14 t01, s040 t01."""
    w = World(tmp, V1_LABEL)
    files: dict[str, bytes] = {}
    # a quoted field with a comma: the byte-exact split must not re-quote or re-order
    w.lines.append(csv_line({"path": "s01/t00/dc01/security.evtx", "sha256": sha(b"s01"), "size": "3",
                             "scenario": "s01", "trial": "t00", "host": "dc01", "channel": "security",
                             "source_path": 'DC01/dryrun,"s01"/export.evtx', "date": "2026-09-23T18:19:38Z",
                             "records": "1", "first_event_utc": "", "last_event_utc": ""}))
    files["data/raw/s01/t00/dc01/security.evtx"] = b"s01"
    plan = [("s02", "t01", False, False), ("s03", "t01", False, False), ("s04", "t00", False, False),
            ("s04", "t01", True, True), ("s04", "t1", False, False), ("s04", "t02", True, False),
            ("s04", "t010", False, False), ("s04", "t10", True, False), ("s04", "t11", False, False),
            ("s07", "t00", False, False), ("s07", "t01", True, True), ("s07", "t05", True, False),
            ("s14", "t01", False, False), ("s040", "t01", False, False)]
    for s, t, moved, clk in plan:
        _add_old_trial(w, files, s, t, moved=moved, clock_csv=clk)
    files["data/trial_windows.csv"] = b"trial_id,start_utc\r\ns04_t00,2026-10-01T00:00:00Z\r\n"
    files["docs/lab/test_set.csv"] = b"trial_id,scenario,split,accepted_date\n"
    files["ground_truth/approved/s04_t00.yaml"] = b"approved: true\n"
    w.manifest = manifest_bytes(w.lines)
    files["data/manifest.csv"] = w.manifest
    files["data/manifest_quarantine.csv"] = HEADER_LINE + b"\r\n"
    w.initial = files
    for rel, data in files.items():
        write(tmp, rel, data)
    return w


# ============================================================================ failed attempt world

@dataclass
class FailedWorld(World):
    scenario: str = "s04"
    trial: str = "t01"
    attempt: int = 1
    variant: str = "a"
    attempt_files: dict[str, bytes] = field(default_factory=dict)    # relative to data/incoming/x10_v2_failed/<S>/attempt_N

    @property
    def tid(self) -> str:
        return f"{self.scenario}_{self.trial}"

    @property
    def attempt_dir(self) -> Path:
        return self.repo / "data" / "incoming" / "x10_v2_failed" / scen_dir(self.scenario) / f"attempt_{self.attempt}"


def failed_label(scenario: str, attempt: int) -> str:
    return f"x10_v2_failed_{scenario}_attempt_{attempt}"


def add_failed_trial(repo: Path, *, scenario: str = "s04", trial: str = "t01", attempt: int = 1, variant: str = "a",
                     partial: bool = False, ingest_status: str | None = None, validator: str | None = "fail",
                     with_incoming_attempt: bool = True) -> FailedWorld:
    """Write one ingested v2 trial (and its attempt folder) into an existing repo, appending its manifest rows.

    partial=True: the ingest stopped before the manifest append and before the DB: status error, files_copied empty,
    only two raw files, no DB, ``.sqlite3.tmp`` / ``-wal`` / ``-shm``, one half JSONL file, no manifest rows.
    validator: "fail" (a FAIL criterion), "pass" (no FAIL), None (no validator file)."""
    s, t = scenario, trial
    tid = f"{s}_{t}"
    w = FailedWorld(repo, failed_label(s, attempt), scenario=s, trial=t, attempt=attempt, variant=variant)
    status = ingest_status or ("error" if partial else "ok")
    files: dict[str, bytes] = {}
    mv: list[str] = []
    copied = []
    evtx = EVTX[:2] if partial else EVTX
    inc_base = f"x10_v2/{scen_dir(s)}/{trial_dir(t)}"
    for host, chan in EVTX:
        data = blob(f"v2-{tid}-{variant}-{host}-{chan}")
        name = f"{HOSTDIR[host]}/{HOSTDIR[host]}_{CHAN_NAME[chan]}.evtx"
        w.attempt_files[name] = data                     # the attempt folder holds all three, even when partial
        if (host, chan) not in evtx:
            continue
        dest = f"{s}/{t}/{host}/{chan}.evtx"
        files[f"data/raw/{dest}"] = data
        mv.append(f"data/raw/{dest}")
        copied.append({"source_path": f"{inc_base}/{name}", "dest_path": dest, "host": host, "channel": chan,
                       "sha256": sha(data), "size": len(data), "action": "copied", "reason": "ok"})
        if not partial:
            w.lines.append(csv_line({"path": dest, "sha256": sha(data), "size": len(data), "scenario": s,
                                     "trial": t, "host": host, "channel": chan, "source_path": f"{inc_base}/{name}",
                                     "date": "2026-11-20T00:00:00Z", "records": "10",
                                     "first_event_utc": "2026-11-20T00:00:01.000000Z",
                                     "last_event_utc": "2026-11-20T00:09:01.000000Z"}))
            w.moved_lines.append(w.lines[-1])
    clock = blob(f"v2-{tid}-{variant}-clock")
    w.attempt_files["EP-01_clock.txt"] = clock
    w.attempt_files["notes.txt"] = blob(f"v2-{tid}-{variant}-notes")        # an ignored non-log file in the folder
    clock_copied = []
    if not partial:
        files[f"data/raw/{s}/{t}/ep-01/clock.txt"] = clock
        mv.append(f"data/raw/{s}/{t}/ep-01/clock.txt")
        clock_copied = [{"source_path": f"{inc_base}/EP-01_clock.txt", "dest_path": f"{s}/{t}/ep-01/clock.txt",
                         "sha256": sha(clock)}]
        w.lines.append(csv_line({"path": f"{s}/{t}/ep-01/clock.txt", "sha256": sha(clock), "size": len(clock),
                                 "scenario": s, "trial": t, "host": "ep-01", "channel": "clock",
                                 "source_path": f"{inc_base}/EP-01_clock.txt", "date": "2026-11-20T00:00:00Z"}))
        w.moved_lines.append(w.lines[-1])
    if partial:
        files[f"data/processed/{tid}.sqlite3.tmp"] = blob(f"{tid}-{variant}-dbtmp")
        files[f"data/processed/{tid}.sqlite3.tmp-wal"] = blob(f"{tid}-{variant}-wal")
        files[f"data/processed/{tid}.sqlite3.tmp-shm"] = blob(f"{tid}-{variant}-shm")
        files[f"data/processed/jsonl/{tid}/dc01_security.jsonl"] = blob(f"{tid}-{variant}-half")
        mv += [f"data/processed/{tid}.sqlite3.tmp", f"data/processed/{tid}.sqlite3.tmp-wal",
               f"data/processed/{tid}.sqlite3.tmp-shm", f"data/processed/jsonl/{tid}/dc01_security.jsonl"]
    else:
        files[f"data/processed/{tid}.sqlite3"] = blob(f"{tid}-{variant}-db")
        mv.append(f"data/processed/{tid}.sqlite3")
        for name in ("dc01_security.jsonl", "ep-01_security.jsonl", "converter_manifest.json"):
            files[f"data/processed/jsonl/{tid}/{name}"] = blob(f"{tid}-{variant}-jsonl-{name}")
            mv.append(f"data/processed/jsonl/{tid}/{name}")
        for name in ("import_report.json", "ep-01/security.json"):
            files[f"out/normalise/{tid}/{name}"] = blob(f"{tid}-{variant}-norm-{name}")
            mv.append(f"out/normalise/{tid}/{name}")
        for name in ("clock_offsets.csv", "clock_changes.csv"):
            files[f"data/processed/{tid}.{name}"] = blob(f"{tid}-{variant}-{name}")
            mv.append(f"data/processed/{tid}.{name}")
        files[f"out/clock_offset/{tid}/clock_offset.json"] = blob(f"{tid}-{variant}-clock-out")
        mv.append(f"out/clock_offset/{tid}/clock_offset.json")
    ingest = {"trial_id": tid, "scenario": s, "trial": t, "source": "x10_v2", "status": status,
              "error": "IngestError: boom" if status == "error" else None,
              "source_dir": f"data/incoming/{inc_base}", "files_copied": [] if partial else copied,
              "files_ignored": [], "clock_files": {"copied": clock_copied, "ignored": [], "missing_hosts": []}}
    files[f"out/ingest/x10_v2/{tid}/ingest.json"] = (json.dumps(ingest, indent=2) + "\n").encode()
    files[f"out/ingest/x10_v2/{tid}/ingest.md"] = blob(f"{tid}-{variant}-ingest-md")
    mv += [f"out/ingest/x10_v2/{tid}/ingest.json", f"out/ingest/x10_v2/{tid}/ingest.md"]
    if validator is not None:
        crit = {"a": {"status": "PASS", "evidence": {}}, "b": {"status": "FAIL" if validator == "fail" else "PASS",
                                                                   "evidence": {}}}
        files[f"out/x10_validate_v2/{tid}.json"] = (json.dumps({"trial_id": tid, "criteria": crit}) + "\n").encode()
        mv.append(f"out/x10_validate_v2/{tid}.json")
    w.moved = mv
    w.ids = [tid]
    for rel, data in files.items():
        write(repo, rel, data)
    if with_incoming_attempt:
        for name, data in w.attempt_files.items():
            write(repo, f"data/incoming/x10_v2_failed/{scen_dir(s)}/attempt_{attempt}/{name}", data)
    w.initial = dict(files)
    # manifest: append the new lines to whatever is there (CRLF), keep the world's view of the whole file
    mp = repo / "data" / "manifest.csv"
    cur = mp.read_bytes() if mp.exists() else HEADER_LINE + b"\r\n"
    mp.write_bytes(cur + b"".join(line + b"\r\n" for line in w.lines))
    w.manifest = mp.read_bytes()
    return w


def build_failed(tmp: Path, **kw) -> FailedWorld:
    """A repo with other, staying content (v1 t00 rows, a v1 row of s04 t02, an accepted v2 s05 t01) plus one failed
    attempt of s04 t01 (see add_failed_trial for the keyword arguments)."""
    base_lines: list[bytes] = []
    files: dict[str, bytes] = {}
    stay_rows = [("s04", "t00", "x10"), ("s04", "t02", "x10"), ("s05", "t01", "x10_v2")]
    for s, t, prefix in stay_rows:
        for host, chan in EVTX[:2]:
            dest = f"{s}/{t}/{host}/{chan}.evtx"
            data = blob(f"stay-{s}-{t}-{host}-{chan}")
            files[f"data/raw/{dest}"] = data
            base_lines.append(csv_line({"path": dest, "sha256": sha(data), "size": len(data), "scenario": s,
                                        "trial": t, "host": host, "channel": chan,
                                        "source_path": f"{prefix}/{scen_dir(s)}/{trial_dir(t)}/{HOSTDIR[host]}/x.evtx",
                                        "date": "2026-10-01T00:00:00Z", "records": "10",
                                        "first_event_utc": "2026-10-01T00:00:01.000000Z",
                                        "last_event_utc": "2026-10-01T00:09:01.000000Z"}))
        files[f"data/processed/{s}_{t}.sqlite3"] = blob(f"stay-db-{s}-{t}")
        files[f"data/processed/jsonl/{s}_{t}/dc01_security.jsonl"] = blob(f"stay-jsonl-{s}-{t}")
        files[f"out/normalise/{s}_{t}/import_report.json"] = blob(f"stay-norm-{s}-{t}")
    files["out/ingest/x10_v2/s05_t01/ingest.json"] = (json.dumps({"trial_id": "s05_t01", "source": "x10_v2",
                                                                  "status": "ok", "files_copied": []}) + "\n").encode()
    files["out/x10_validate_v2/s05_t01.json"] = b'{"trial_id": "s05_t01", "criteria": {}}\n'
    files["data/trial_windows.csv"] = b"trial_id,start_utc\r\ns02_t00,2026-10-01T00:00:00Z\r\n"
    files["docs/lab/test_set.csv"] = (b"trial_id,scenario,split,accepted_date\n"
                                      b"s05_t01,s05,development,2026-11-20\n")
    files["ground_truth/approved/s04_t00.yaml"] = b"approved: true\n"
    files["data/incoming/x10/S04/trial_02/ENDPOINT-01/x.evtx"] = blob("old-incoming")
    for rel, data in files.items():
        write(tmp, rel, data)
    (tmp / "data" / "manifest.csv").write_bytes(manifest_bytes(base_lines))
    return add_failed_trial(tmp, **kw)
