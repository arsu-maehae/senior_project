"""Batch ingest driver for the x10 trials: incoming -> raw copy -> manifest -> JSONL -> per-trial SQLite.

Run from the repo root:  PYTHONPATH=src python -m data_layout.batch --dry-run
(or `python -m data_layout.cli batch ...`).  Reuses layout.py (classify/copy/manifest) and
evtx_pipeline (convert, run_trial_import); nothing here re-implements them.

Sources: `--source x10` (default; decisions 029/030) or `--source x10_v2` (the reruns, decisions 034/052).
x10_v2 adds guards that refuse to write before anything is touched: shadow guard (an old copy still holds the
trial id), stale attempt (incoming bytes differ from the recorded ingest), manifest lock and byte checks, and the
per-host clock files (`clock_files.py`). x10 behaviour is unchanged.

Layout (decisions 029/030):
  data/incoming/<source>/S0N/trial_NN/<HOST>/*.evtx       read-only, hashed before and after
  data/raw/s0N/tNN/<host>/<channel>.evtx                   + rows appended to data/manifest.csv
  data/processed/jsonl/s0N_tNN/                            converter output
  data/processed/s0N_tNN.sqlite3                           import-trial output
  S05_WRONG_DESIGN_DO_NOT_USE -> data/raw/quarantine/s05/tNN, data/manifest_quarantine.csv,
  data/processed/jsonl/quarantine/s05_tNN, data/processed/quarantine/s05q_tNN.sqlite3
  out/ingest/<source>/<trial_id>/ingest.json + ingest.md  per-trial report
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Optional, Sequence

from data_layout import batch_report as R
from data_layout import clock_files
from data_layout import layout as L

SCENARIO_RE = re.compile(r"^S0(\d)$")
TRIAL_RE = re.compile(r"^trial_(\d{2})$")
# Decision 030: the only quarantined folder; maps to its real scenario number.
QUARANTINE_FOLDERS: dict[str, str] = {"S05_WRONG_DESIGN_DO_NOT_USE": "s05"}
SOURCES: tuple[str, ...] = ("x10", "x10_v2")
STRICT_SOURCES: frozenset[str] = frozenset({"x10_v2"})   # sources that get the guards and the clock files
V2_SOURCE_PREFIX = "x10_v2/"                              # manifest source_path of a v2 row
LOCK_NAME_SUFFIX = ".lock"


class IngestError(RuntimeError):
    """Any condition that must stop a trial (raw conflict, manifest misuse, failed check)."""


class IncomingChanged(IngestError):
    """An incoming file changed while we worked: stop the whole batch, never continue."""


class StaleAttempt(IngestError):
    """The incoming files differ from what the existing ingest of this trial id recorded."""


@dataclass(frozen=True)
class Roots:
    """Every directory the batch reads or writes, derived from the repo root (no globals)."""
    repo: Path
    incoming: Path
    source: Path         # data/incoming/<source_name>
    source_name: str     # x10 | x10_v2
    raw: Path
    processed: Path
    manifest: Path
    manifest_quarantine: Path
    ingest_out: Path
    normalise_out: Path

    @classmethod
    def from_repo(cls, repo: Path, source: str = "x10") -> "Roots":
        """All paths for one incoming source; the reports go to out/ingest/<source> so v1 and v2 never mix."""
        if source not in SOURCES:
            raise ValueError(f"unknown source {source!r}; choose from {SOURCES}")
        repo = repo.resolve()
        data = repo / "data"
        return cls(repo, data / "incoming", data / "incoming" / source, source, data / "raw", data / "processed",
                   data / "manifest.csv", data / "manifest_quarantine.csv",
                   repo / "out" / "ingest" / source, repo / "out" / "normalise")

    @property
    def strict(self) -> bool:
        """True for the sources that get the shadow/stale/lock guards and clock files (x10_v2)."""
        return self.source_name in STRICT_SOURCES


@dataclass(frozen=True)
class TrialPlan:
    """Where one trial comes from and where each of its outputs goes."""
    trial_id: str        # s02_t01, or s05q_t01 for quarantine
    scenario: str        # s0N (real scenario; for quarantine the DB rows carry s05/tNN, see run_import)
    trial: str           # tNN
    quarantine: bool
    source_dir: Path
    raw_rel: str         # trial folder relative to data/raw: s02/t01 or quarantine/s05/t01
    raw_dir: Path
    jsonl_dir: Path
    database: Path
    manifest: Path
    normalise_dir: Path  # import-trial report root
    out_dir: Path


# ---------- discovery and planning (pure apart from listing folders) ----------

def scenario_of_folder(name: str, allow_quarantine: bool = True) -> Optional[tuple[str, bool]]:
    """S02 -> (s02, False); the quarantine folder -> (s05, True) if allowed; anything else -> None."""
    if allow_quarantine and name in QUARANTINE_FOLDERS:
        return QUARANTINE_FOLDERS[name], True
    m = SCENARIO_RE.match(name)
    return (f"s0{m.group(1)}", False) if m else None


def trial_of_folder(name: str) -> Optional[str]:
    """trial_01 -> t01 (decision 029: trial_NN = tNN)."""
    m = TRIAL_RE.match(name)
    return f"t{m.group(1)}" if m else None


def plan_trial(roots: Roots, source_dir: Path, scenario: str, trial: str, quarantine: bool) -> TrialPlan:
    """Build every path for one trial; quarantine paths follow decision 030 exactly."""
    if quarantine:
        trial_id = f"{scenario}q_{trial}"
        raw_rel = f"quarantine/{scenario}/{trial}"
        jsonl_dir = roots.processed / "jsonl" / "quarantine" / f"{scenario}_{trial}"
        database = roots.processed / "quarantine" / f"{trial_id}.sqlite3"
        manifest, normalise = roots.manifest_quarantine, roots.normalise_out / "quarantine"
    else:
        trial_id = f"{scenario}_{trial}"
        raw_rel = f"{scenario}/{trial}"
        jsonl_dir = roots.processed / "jsonl" / trial_id
        database = roots.processed / f"{trial_id}.sqlite3"
        manifest, normalise = roots.manifest, roots.normalise_out
    plan = TrialPlan(trial_id, scenario, trial, quarantine, source_dir, raw_rel, roots.raw / raw_rel,
                     jsonl_dir, database, manifest, normalise, roots.ingest_out / trial_id)
    check_write_paths(roots, plan)
    return plan


def check_write_paths(roots: Roots, plan: TrialPlan) -> None:
    """Refuse a plan that would write into data/incoming, ground_truth, or mix quarantine into manifest.csv.

    WHY: CLAUDE.md data rules; decision 030 (no quarantined row in data/manifest.csv)."""
    allowed = (roots.raw, roots.processed, roots.ingest_out, roots.normalise_out)
    targets = (plan.raw_dir, plan.jsonl_dir, plan.database, plan.normalise_dir, plan.out_dir)
    for t in targets:
        if not any(t == a or a in t.parents for a in allowed):
            raise IngestError(f"{plan.trial_id}: write target outside allowed roots: {t}")
        if roots.incoming in t.parents or (roots.repo / "ground_truth") in t.parents:
            raise IngestError(f"{plan.trial_id}: write target in a protected folder: {t}")
    if plan.quarantine != (plan.manifest == roots.manifest_quarantine):
        raise IngestError(f"{plan.trial_id}: quarantine flag and manifest file disagree")
    if plan.quarantine != plan.raw_rel.startswith("quarantine/"):
        raise IngestError(f"{plan.trial_id}: quarantine flag and raw path disagree")


def discover_trials(roots: Roots) -> tuple[list[TrialPlan], list[str]]:
    """List trial folders under data/incoming/<source>; unknown folders are reported, never guessed.

    The quarantine folder (decision 030) belongs to x10 only; under x10_v2 it is a skipped-folder note. A source
    folder that does not exist yet (no rerun delivered) is simply 0 trials."""
    plans: list[TrialPlan] = []
    notes: list[str] = []
    if not roots.source.is_dir():
        return plans, notes
    for scen_dir in sorted(p for p in roots.source.iterdir() if p.is_dir()):
        scen = scenario_of_folder(scen_dir.name, allow_quarantine=not roots.strict)
        if scen is None:
            why = ("not S0N" if roots.strict else "not S0N or a known quarantine folder")
            notes.append(f"skipped folder {scen_dir.name!r}: {why}")
            continue
        for trial_dir in sorted(p for p in scen_dir.iterdir() if p.is_dir()):
            trial = trial_of_folder(trial_dir.name)
            if trial is None:
                notes.append(f"skipped folder {scen_dir.name}/{trial_dir.name}: not trial_NN")
                continue
            plans.append(plan_trial(roots, trial_dir, scen[0], trial, scen[1]))
    return plans, notes


def select_trials(plans: list[TrialPlan], only: Sequence[str], scenarios: Sequence[str]) -> list[TrialPlan]:
    """Apply --only and --scenarios; an unknown --only id is an error (a typo must not silently do nothing)."""
    ids = {p.trial_id for p in plans}
    unknown = [o for o in only if o not in ids]
    if unknown:
        raise IngestError(f"--only names unknown trial ids: {unknown}")
    wanted = {s.lower() for s in scenarios}
    out = []
    for p in plans:
        if only and p.trial_id not in only:
            continue
        if wanted and not ({p.scenario, p.trial_id.split("_")[0]} & wanted):
            continue
        out.append(p)
    return out


# ---------- state ----------

def read_json(path: Path) -> Optional[dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def manifest_paths(manifest: Path) -> set[str]:
    if not manifest.exists():
        return set()
    with open(manifest, newline="", encoding="utf-8") as f:
        return {r["path"] for r in csv.DictReader(f) if r.get("path")}


def trial_state(plan: TrialPlan) -> str:
    """complete = DB exists, ingest.json says ok, every copied file (and clock file) is in the manifest; else
    partial/new.

    WHY: requirement 6 (resumable); a trial is only skipped when all three agree. Clock files (x10_v2) count too,
    so a crash between the evtx rows and the clock rows is not mistaken for a finished trial."""
    report = read_json(plan.out_dir / "ingest.json")
    if plan.database.exists() and report and report.get("status") == "ok":
        listed = manifest_paths(plan.manifest)
        copied = list(report.get("files_copied", [])) + list((report.get("clock_files") or {}).get("copied", []))
        if all(f["dest_path"] in listed for f in copied):
            return "complete"
    touched = (plan.raw_dir, plan.jsonl_dir, plan.database, plan.out_dir / "ingest.json")
    return "partial" if any(p.exists() for p in touched) else "new"


# ---------- incoming: hash and map (read-only) ----------

def hash_tree(source_dir: Path, rel_to: Path) -> dict[str, str]:
    """sha256 of every file under source_dir, keyed by its path relative to rel_to (posix)."""
    return {p.relative_to(rel_to).as_posix(): L.sha256_file(p)
            for p in sorted(source_dir.rglob("*")) if p.is_file()}


def first_record_info(path: Path) -> L.LogInfo:
    """Channel and Computer of the first record only (records/time span are filled by the manifest step).

    WHY: classify_file needs only the channel; a full scan of a 0.5 GiB Security log here
    would parse it a third time."""
    from evtx import PyEvtxParser
    for rec in PyEvtxParser(str(path)).records_json():
        sysd = json.loads(rec["data"]).get("Event", {}).get("System", {})
        return L.LogInfo(str(sysd.get("Channel", "")), str(sysd.get("Computer", "")), 0, "", "")
    return L.LogInfo("", "", 0, "", "")


def map_trial(roots: Roots, plan: TrialPlan) -> list[L.MapRow]:
    """Classify each incoming file with layout.classify_file; quarantine dests get the quarantine/ prefix."""
    rows = []
    for p in sorted(x for x in plan.source_dir.rglob("*") if x.is_file()):
        rel = PurePosixPath(p.relative_to(roots.incoming).as_posix())
        row = L.classify_file(rel, L.read_magic(p), lambda p=p: first_record_info(p), plan.trial, plan.scenario)
        if row.action == "copy" and plan.quarantine:
            row = replace(row, dest_path=f"quarantine/{row.dest_path}")
        rows.append(row)
    bad = L.find_collisions(rows)
    if bad:
        raise IngestError(f"{plan.trial_id}: two files map to one dest: {bad}")
    for r in rows:
        if r.action == "copy" and not r.dest_path.startswith(plan.raw_rel + "/"):
            raise IngestError(f"{plan.trial_id}: dest {r.dest_path} outside {plan.raw_rel}")
    return rows


def trial_rel(plan: TrialPlan, dest_path: str) -> str:
    """s02/t01/dc01/security.evtx -> dc01/security.evtx (the key the converter and import use)."""
    return dest_path[len(plan.raw_rel) + 1:]


# ---------- raw copy and manifest ----------

def copy_rows(roots: Roots, rows: list[L.MapRow], incoming_sha: dict[str, str]) -> list[dict[str, Any]]:
    """Copy (never move) each copy row; an existing raw file is accepted only if its hash matches.

    WHY: data/raw is never edited after the copy, so a resume must verify, not overwrite."""
    out = []
    for r in rows:
        if r.action != "copy":
            continue
        dest = L.safe_dest(roots.raw, r.dest_path)
        want = incoming_sha[r.source_path]
        if dest.exists():
            sha, action = L.sha256_file(dest), "already_present_verified"
            if sha != want:
                raise IngestError(f"raw file {r.dest_path} exists with a different sha256; refusing to touch it")
        else:
            sha, action = L.copy_one(roots.incoming / r.source_path, dest), "copied"
            if sha != want:
                raise IncomingChanged(f"{r.source_path} hash changed between the pre-hash and the copy")
        out.append({"source_path": r.source_path, "dest_path": r.dest_path, "host": r.host,
                    "channel": r.channel, "sha256": sha, "size": dest.stat().st_size,
                    "action": action, "reason": r.reason})
    return out


def append_manifest_rows(roots: Roots, plan: TrialPlan, rows: list[L.MapRow],
                         keep_line_ending: bool = False) -> dict[str, dict[str, str]]:
    """Append this trial's rows via layout.append_manifest and prove the old lines were not touched.

    WHY: existing t00 rows must never change (requirement 3); quarantined rows must never
    reach data/manifest.csv (decision 030). With ``keep_line_ending`` (x10_v2) the new lines use the manifest's
    own ending, so a CRLF manifest stays CRLF byte for byte."""
    copy = [r for r in rows if r.action == "copy"]
    if any(r.dest_path.startswith("quarantine/") for r in copy) != plan.quarantine:
        raise IngestError(f"{plan.trial_id}: quarantine rows would go to the wrong manifest")
    before = plan.manifest.read_bytes() if plan.manifest.exists() else b""
    if keep_line_ending and before:
        L.append_manifest(roots.raw, copy, plan.manifest, lineterminator=L.manifest_line_ending(before))
    else:
        L.append_manifest(roots.raw, copy, plan.manifest)
    after = plan.manifest.read_bytes()
    if not after.startswith(before):
        raise IngestError(f"{plan.manifest}: existing lines changed during append")
    with open(plan.manifest, newline="", encoding="utf-8") as f:
        listed = {r["path"]: r for r in csv.DictReader(f)}
    return {trial_rel(plan, r.dest_path): listed[r.dest_path] for r in copy if r.dest_path in listed}


# ---------- x10_v2 guards: every check runs before the first write ----------

def read_manifest_rows(manifest: Path) -> list[dict[str, str]]:
    """All rows of a manifest (empty list when the file does not exist)."""
    if not manifest.exists():
        return []
    with open(manifest, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def is_v2_row(row: dict[str, str]) -> bool:
    """A manifest row written by an x10_v2 ingest: ``source_path`` starts exactly with ``x10_v2/``.

    WHY the trailing slash: ``x10_v2_failed/...`` or ``x10_v20/...`` must not count as a v2 row."""
    return (row.get("source_path") or "").startswith(V2_SOURCE_PREFIX)


def trial_manifest_rows(plan: TrialPlan, rows: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    """Rows that belong to this trial id: same scenario and trial columns, or a path under its raw folder."""
    prefix = plan.raw_rel + "/"
    return [r for r in rows if ((r.get("scenario"), r.get("trial")) == (plan.scenario, plan.trial)
                                or (r.get("path") or "").startswith(prefix))]


def lock_path(manifest: Path) -> Path:
    """data/manifest.csv.lock (a different name from every manifest, so it is never read as one)."""
    return manifest.with_name(manifest.name + LOCK_NAME_SUFFIX)


def lock_error(manifest: Path) -> IngestError:
    return IngestError(f"manifest lock {lock_path(manifest)} exists: another ingest or archive may be running, or a "
                       "run was killed; check, then delete the lock file by hand. Nothing was written")


def check_lock_free(manifest: Path) -> None:
    """Refuse early (before any copy) when a lock file is already there; the lock itself is taken later."""
    if lock_path(manifest).exists():
        raise lock_error(manifest)


@contextmanager
def manifest_lock(manifest: Path) -> Iterator[None]:
    """Hold data/manifest.csv.lock (created exclusively) while the manifest is appended; always removed after.

    WHY: two writers (a batch and the archive step) must not interleave appends; O_EXCL makes the take atomic.
    A pre-existing lock is never removed by us: it may belong to a live process."""
    lock = lock_path(manifest)
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise lock_error(manifest) from None
    try:
        try:
            os.write(fd, f"pid {os.getpid()} {utc_now()}\n".encode("ascii"))
        finally:
            os.close(fd)
        yield
    finally:
        lock.unlink(missing_ok=True)


def check_manifest_ready(manifest: Path) -> None:
    """Refuse a manifest an append would damage (BOM, empty, no final newline) before any write."""
    if manifest.exists():
        try:
            L.check_manifest_appendable(manifest.read_bytes(), manifest.name)
        except ValueError as exc:
            raise IngestError(str(exc)) from None


def expected_raw_hashes(roots: Roots, plan: TrialPlan, pre: dict[str, str],
                        scan: clock_files.ClockScan) -> dict[str, str]:
    """dest path (relative to data/raw) -> sha256 of every raw file this incoming trial would produce."""
    out = {r.dest_path: pre[r.source_path] for r in map_trial(roots, plan) if r.action == "copy"}
    for host, src in scan.found.items():
        out[f"{plan.raw_rel}/{host}/clock.txt"] = pre[src.relative_to(roots.incoming).as_posix()]
    return out


def foreign_raw_files(roots: Roots, plan: TrialPlan, expected: dict[str, str]) -> list[str]:
    """Raw files under the trial folder that are not byte-identical to what this incoming trial would write.

    ``.part`` leftovers of an interrupted copy are not evidence and are ignored."""
    out = []
    if plan.raw_dir.is_dir():
        for p in sorted(x for x in plan.raw_dir.rglob("*") if x.is_file() and not x.name.endswith(".part")):
            rel = p.relative_to(roots.raw).as_posix()
            if expected.get(rel) != L.sha256_file(p):
                out.append(rel)
    return out


def check_not_shadowing(roots: Roots, plan: TrialPlan, pre: dict[str, str], scan: clock_files.ClockScan) -> None:
    """Refuse when an old (x10) copy still holds this trial id on the normal paths.

    WHY: the reruns reuse ids (s04_t01 ...). Without this, --force would remove the old DB and the new files
    would sit next to old evidence. Refuses when (1) data/manifest.csv has a row of this scenario/trial whose
    source_path does not start with x10_v2/ (also a mixed old+v2 set), or (2) the DB exists, or the raw folder
    holds foreign files, while no manifest row of the trial is a v2 row. A raw folder whose every file is
    byte-identical to this incoming trial is an interrupted v2 copy and may resume. Never deletes anything."""
    mine = trial_manifest_rows(plan, read_manifest_rows(plan.manifest))
    hint = "old copy still on the normal path; run the archive (or retire-failed) first"
    old = [r for r in mine if not is_v2_row(r)]
    if old:
        raise IngestError(f"{plan.trial_id}: {hint}: {len(old)} manifest row(s) with source_path not under "
                          f"{V2_SOURCE_PREFIX} (e.g. {old[0].get('source_path')!r})")
    if mine:
        return
    if plan.database.exists():
        raise IngestError(f"{plan.trial_id}: {hint}: {plan.database.name} exists and no manifest row is from "
                          f"{V2_SOURCE_PREFIX}")
    foreign = (foreign_raw_files(roots, plan, expected_raw_hashes(roots, plan, pre, scan))
               if plan.raw_dir.exists() else [])
    if foreign:
        raise IngestError(f"{plan.trial_id}: {hint}: raw folder {plan.raw_rel}/ holds {len(foreign)} file(s) that are "
                          f"not this attempt's (e.g. {foreign[0]}) and no manifest row is from {V2_SOURCE_PREFIX}")


def recorded_sources(report: Optional[dict[str, Any]]) -> dict[str, str]:
    """source_path -> sha256 that an earlier ingest.json recorded (evtx and clock files).

    A stale-refusal report keeps the evidence of the attempt it refused under ``previous_attempt``, so a second
    run after the refusal still has something to compare with."""
    out: dict[str, str] = {}
    for part in (report or {}, (report or {}).get("previous_attempt") or {}):
        listed = list(part.get("files_copied", [])) + list((part.get("clock_files") or {}).get("copied", []))
        for f in listed:
            out.setdefault(f["source_path"], f["sha256"])
    return out


def stale_files(recorded: dict[str, str], pre: dict[str, str]) -> list[str]:
    """Recorded incoming files whose bytes now differ (or that are gone): the folder holds another attempt."""
    return sorted(k for k, sha in recorded.items() if pre.get(k) != sha)


def check_not_stale(plan: TrialPlan, pre: dict[str, str], prior: Optional[dict[str, Any]]) -> None:
    """Refuse when the incoming files are not the ones the existing ingest of this id was built from.

    WHY: a failed attempt that was not retired would otherwise print "complete, skipped" for its replacement
    (its rows are v2, so the shadow guard passes). The old DB is never touched on this path."""
    changed = stale_files(recorded_sources(prior), pre)
    if changed:
        raise StaleAttempt(f"{plan.trial_id}: stale attempt: {len(changed)} incoming file(s) differ from the recorded "
                           f"ingest (e.g. {changed[0]}); run retire-failed for the old attempt first. "
                           "Nothing was changed")


def previous_attempt_summary(prior: Optional[dict[str, Any]]) -> dict[str, Any]:
    """What to keep of an earlier ingest.json when a refusal report replaces it (audit and the next stale check).

    Flat on purpose: every recorded source file with its sha256, including those the earlier report itself carried
    over, so repeated refusals never lose the evidence (a nested chain would be read only one level deep)."""
    prior = prior or {}
    return {"status": prior.get("status"), "started_utc": prior.get("started_utc"),
            "files_copied": [{"source_path": k, "sha256": v} for k, v in sorted(recorded_sources(prior).items())]}


def preflight(roots: Roots, plan: TrialPlan, pre: dict[str, str],
              prior: Optional[dict[str, Any]]) -> clock_files.ClockScan:
    """All x10_v2 refusals in one place, before the first write; returns the clock-file scan.

    Order: clock-file names (input errors), manifest bytes, manifest lock, shadow guard, stale attempt."""
    scan = clock_files.scan_trial_folder(plan.source_dir)
    if scan.refused:
        raise IngestError(f"{plan.trial_id}: clock files refused: " + "; ".join(scan.refused))
    check_manifest_ready(plan.manifest)
    check_lock_free(plan.manifest)
    check_not_shadowing(roots, plan, pre, scan)
    check_not_stale(plan, pre, prior)
    return scan


def copy_clock_files(roots: Roots, plan: TrialPlan, scan: clock_files.ClockScan,
                     pre: dict[str, str]) -> list[dict[str, Any]]:
    """Copy each host's clock file byte for byte to raw/<s>/<t>/<host>/clock.txt (never parsed, never overwritten).

    WHY: the readings are evidence for the clock step; an existing raw file is accepted only on an identical hash
    (a resume), otherwise the trial stops."""
    out = []
    for host, src in sorted(scan.found.items()):
        source_path = src.relative_to(roots.incoming).as_posix()
        dest_rel = f"{plan.raw_rel}/{host}/clock.txt"
        dest = L.safe_dest(roots.raw, dest_rel)
        want = pre[source_path]
        if dest.exists():
            sha, action = L.sha256_file(dest), "already_present_verified"
            if sha != want:
                raise IngestError(f"clock file {dest_rel} exists with a different sha256; refusing to overwrite it")
        else:
            sha, action = L.copy_one(src, dest), "copied"
            if sha != want:
                raise IncomingChanged(f"{source_path} hash changed between the pre-hash and the copy")
        out.append({"source_path": source_path, "dest_path": dest_rel, "host": host, "channel": "clock",
                    "sha256": sha, "size": dest.stat().st_size, "action": action})
    return out


def append_clock_manifest_rows(roots: Roots, plan: TrialPlan, copied: list[dict[str, Any]]) -> int:
    """Add the clock rows (channel=clock, no event times) through ``clock_files.append_clock_rows``."""
    rows = [clock_files.clock_manifest_row(L.safe_dest(roots.raw, c["dest_path"]), c["dest_path"], plan.scenario,
                                           plan.trial, c["host"], c["source_path"]) for c in copied]
    return clock_files.append_clock_rows(plan.manifest, rows)


def clock_report(scan: clock_files.ClockScan) -> dict[str, Any]:
    """The ``clock_files`` section of ingest.json before copying (``copied`` is filled in by the copy).

    ``ignored`` stays empty: every clock-like file is either copied or refuses the trial."""
    return {"copied": [], "ignored": [], "missing_hosts": list(scan.missing_hosts)}


def clock_warnings(scan: clock_files.ClockScan) -> list[str]:
    """A missing clock file is a note, not a failure (owner ruling 2026-11-15, decision 052 item 5)."""
    if not scan.missing_hosts:
        return []
    return [f"no clock file for {', '.join(scan.missing_hosts)} (<HOST>_clock.txt, spec 08 CO-12): the clock step "
            "will report no reading for these hosts"]


# ---------- JSONL and DB (reused pipeline) ----------

def remove_derived(roots: Roots, path: Path) -> None:
    """Delete a JSONL folder or DB we are about to rebuild; only ever inside data/processed."""
    if roots.processed not in path.resolve().parents:
        raise IngestError(f"refusing to delete outside data/processed: {path}")
    if path.is_dir():
        shutil.rmtree(path)
    else:
        for suffix in ("", ".tmp", "-wal", "-shm", ".tmp-wal", ".tmp-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)


def run_convert(roots: Roots, plan: TrialPlan) -> dict[str, Any]:
    """EVTX -> JSONL with evtx_pipeline.decoder.convert (full mode); stale output is rebuilt from raw."""
    from evtx_pipeline.decoder import convert
    if plan.jsonl_dir.exists():
        remove_derived(roots, plan.jsonl_dir)
    cmd = (f"data_layout.batch -> evtx_pipeline convert --input {plan.raw_dir.relative_to(roots.repo).as_posix()}"
           f" --output {plan.jsonl_dir.relative_to(roots.repo).as_posix()}")
    return convert(plan.raw_dir, plan.jsonl_dir, smoke=False, overwrite=False, command=cmd)


def run_import(plan: TrialPlan) -> dict[str, Any]:
    """JSONL -> SQLite with evtx_pipeline.trial_import.run_trial_import.

    The import requires the JSONL folder to be named <scenario>_<trial> and the raw input
    root to end in <scenario>/<trial>, so quarantined DB rows carry scenario_id s05 and
    trial_id tNN; the quarantine is marked by the file name s05q_tNN and its folder."""
    from evtx_pipeline.trial_import import run_trial_import
    return run_trial_import(plan.jsonl_dir, plan.scenario, plan.trial, plan.database, plan.normalise_dir)


# ---------- reporting ----------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def dir_size(path: Path) -> Optional[int]:
    if not path.exists():
        return None
    if path.is_file():
        return path.stat().st_size
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


@contextmanager
def timed(phases: dict[str, float], name: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        phases[name] = round(time.perf_counter() - start, 2)


def base_report(roots: Roots, plan: TrialPlan) -> dict[str, Any]:
    rel = lambda p: p.relative_to(roots.repo).as_posix()
    report = {"trial_id": plan.trial_id, "scenario": plan.scenario, "trial": plan.trial,
              "source": roots.source_name,
              "quarantine": plan.quarantine, "status": "running", "error": None,
              "source_dir": rel(plan.source_dir), "raw_dir": rel(plan.raw_dir), "jsonl_dir": rel(plan.jsonl_dir),
              "database": rel(plan.database), "manifest": rel(plan.manifest),
              "db_scenario_id": plan.scenario, "db_trial_id": plan.trial,
              "started_utc": utc_now(), "phase_seconds": {}, "files_copied": [], "files_ignored": [],
              "files_missing": [], "extra_files": [], "converter": [], "import": None, "reconcile": None}
    if roots.strict:
        report["warnings"] = []
    return report


def summarise_mapping(report: dict[str, Any], rows: list[L.MapRow], copied: list[dict[str, Any]]) -> None:
    """Fill files_ignored / files_missing / extra_files from the mapping and the copy result."""
    present = [(c["host"], c["channel"]) for c in copied]
    ignored = [{"source_path": r.source_path, "host": r.host, "reason": r.reason}
               for r in rows if r.action != "copy"]
    report["files_ignored"] = ignored
    report["files_missing"] = R.missing_slots(present, ignored)
    report["extra_files"] = R.extra_files(present)


def converter_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    keys = ("relative_path", "size_bytes", "attempted_record_count", "emitted_event_count", "parse_error_count",
            "status", "pre_run_sha256", "post_run_sha256", "unaccounted_records_reason")
    return [{k: row.get(k) for k in keys} for row in manifest.get("selected_inputs", [])]


def reconcile(plan: TrialPlan, report: dict[str, Any], manifest_rows: dict[str, dict[str, str]],
              import_report: dict[str, Any], incoming_sha: dict[str, str]) -> dict[str, Any]:
    copied = {trial_rel(plan, c["dest_path"]): c for c in report["files_copied"]}
    conv = {c["relative_path"]: c for c in report["converter"]}
    imp = {p["relative_path"]: p for p in import_report.get("per_file", [])}
    checks = (R.file_checks(copied, manifest_rows, conv, imp, incoming_sha)
              + R.trial_checks(import_report, len(copied), len(conv)))
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_reports(plan: TrialPlan, report: dict[str, Any]) -> None:
    write_text_atomic(plan.out_dir / "ingest.json", json.dumps(report, indent=2) + "\n")
    write_text_atomic(plan.out_dir / "ingest.md", R.render_markdown(report))


# ---------- one trial ----------

def ingest_steps(roots: Roots, plan: TrialPlan, report: dict[str, Any], pre: dict[str, str],
                 scan: Optional[clock_files.ClockScan] = None) -> None:
    """map -> copy -> manifest -> convert -> import -> reconcile; raises on the first failure.

    ``scan`` is given for x10_v2 only: the clock files are then copied after the event logs and their manifest
    rows are appended in the same locked section as the event-log rows."""
    phases = report["phase_seconds"]
    with timed(phases, "map"):
        rows = map_trial(roots, plan)
    with timed(phases, "copy"):
        report["files_copied"] = copy_rows(roots, rows, pre)
        if scan is not None:
            report["clock_files"]["copied"] = copy_clock_files(roots, plan, scan, pre)
    clock_sources = {c["source_path"] for c in report.get("clock_files", {}).get("copied", [])}
    summarise_mapping(report, [r for r in rows if r.source_path not in clock_sources], report["files_copied"])
    with timed(phases, "manifest"):
        if scan is None:
            manifest_rows = append_manifest_rows(roots, plan, rows)
        else:
            with manifest_lock(plan.manifest):
                manifest_rows = append_manifest_rows(roots, plan, rows, keep_line_ending=True)
                append_clock_manifest_rows(roots, plan, report["clock_files"]["copied"])
    with timed(phases, "convert"):
        manifest = run_convert(roots, plan)
    report["converter"] = converter_rows(manifest)
    report["converter_totals"] = manifest.get("totals")
    with timed(phases, "import"):
        imp = run_import(plan)
    report["import"] = {k: imp.get(k) for k in ("events", "events_dedup", "duplicates_exact", "duplicates_near",
                                                "duration_seconds", "checks", "per_file", "status")}
    report["reconcile"] = reconcile(plan, report, manifest_rows, imp, pre)
    if not report["reconcile"]["ok"]:
        raise IngestError("row accounting does not reconcile (see reconcile.checks)")


def ingest_trial(roots: Roots, plan: TrialPlan, force: bool,
                 pre: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """Process one trial and always write its report; incoming hashes are compared at the end.

    ``pre`` (incoming hashes) may be passed in by a caller that already computed it. For x10_v2 every refusal
    (clock files, manifest bytes, lock, shadow guard, stale attempt) happens first, so a refused trial writes
    nothing but its report and --force can never reach ``remove_derived`` for an old or stale copy."""
    started = time.perf_counter()
    report = base_report(roots, plan)
    if pre is None:
        pre = hash_tree(plan.source_dir, roots.incoming)
    report["sizes_bytes"] = {"incoming": sum((roots.incoming / k).stat().st_size for k in pre)}
    prior = read_json(plan.out_dir / "ingest.json") if roots.strict else None
    try:
        scan = None
        if roots.strict:
            scan = preflight(roots, plan, pre, prior)
            report["clock_files"] = clock_report(scan)
            report["warnings"] = clock_warnings(scan)
        if plan.database.exists():
            if not force:
                raise IngestError(f"{plan.database} exists but the trial is not complete; rerun with --force")
            remove_derived(roots, plan.database)
        ingest_steps(roots, plan, report, pre, scan)
        report["status"] = "ok"
    except Exception as exc:  # the report must survive any failure
        report["status"], report["error"] = "error", f"{type(exc).__name__}: {str(exc)[:500]}"
        if isinstance(exc, StaleAttempt):
            report["previous_attempt"] = previous_attempt_summary(prior)
    finally:
        report["incoming_hashes"] = R.hash_diff(pre, hash_tree(plan.source_dir, roots.incoming))
        if not report["incoming_hashes"]["unchanged"]:
            report["status"], report["error"] = "error", "INCOMING FILES CHANGED: " + str(report["error"])
        report["sizes_bytes"].update({"raw": dir_size(plan.raw_dir), "jsonl": dir_size(plan.jsonl_dir),
                                      "database": dir_size(plan.database)})
        report["finished_utc"] = utc_now()
        report["duration_seconds"] = round(time.perf_counter() - started, 2)
        write_reports(plan, report)
    return report


# ---------- dry run ----------

def plan_lines(roots: Roots, plan: TrialPlan) -> list[str]:
    """Describe a trial without parsing or writing: channels guessed from file names only."""
    files = sorted(p for p in plan.source_dir.rglob("*") if p.is_file())
    present = []
    for p in files:
        host = L.host_from_parts(list(p.relative_to(plan.source_dir).parts[:-1]))
        chan = R.channel_hint_from_name(p.name)
        if host and chan:
            present.append((host, chan))
    missing = R.missing_slots(present)
    size = sum(p.stat().st_size for p in files)
    lines = [f"{plan.trial_id:10} {trial_state(plan):8} {len(files):2} files {size / (1 << 30):6.2f} GiB  "
             f"{plan.source_dir.relative_to(roots.repo).as_posix()} -> {plan.raw_dir.relative_to(roots.repo).as_posix()}"
             f" | {plan.database.relative_to(roots.repo).as_posix()} | manifest {plan.manifest.name}"]
    if missing:
        lines.append("           missing (by file name): " + ", ".join(f"{m['host']}/{m['channel']}" for m in missing))
    return lines


# ---------- CLI ----------

def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2],
                   help="repo root (default: two levels above src/data_layout)")
    p.add_argument("--source", choices=SOURCES, default="x10",
                   help="incoming folder under data/incoming: x10 (default) or x10_v2 (the reruns; adds the "
                        "shadow/stale/lock guards and the per-host clock files)")
    p.add_argument("--only", action="append", default=[], metavar="TRIAL_ID",
                   help="process only this trial id (s02_t01, s05q_t03); repeatable")
    p.add_argument("--scenarios", nargs="+", default=[], metavar="S0N",
                   help="process only these scenarios (s02 ... s07; s05 or s05q = quarantine)")
    p.add_argument("--force", action="store_true", help="rebuild complete trials (JSONL and DB; raw is only verified)")
    p.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
    p.add_argument("--keep-going", action="store_true",
                   help="continue after a failed trial (an incoming-hash change always stops)")


def is_stale(roots: Roots, plan: TrialPlan, pre: Optional[dict[str, str]]) -> bool:
    """x10_v2 only: do the incoming files differ from the existing ingest of this id?

    WHY: a complete-looking trial must not be skipped when its incoming folder now holds another attempt; the
    trial then goes to ``ingest_trial``, which refuses it with the stale message."""
    if not roots.strict or pre is None:
        return False
    return bool(stale_files(recorded_sources(read_json(plan.out_dir / "ingest.json")), pre))


def run(a: argparse.Namespace) -> int:
    """Entry point shared by `python -m data_layout.batch` and `data_layout.cli batch`."""
    roots = Roots.from_repo(a.repo, a.source)
    plans, notes = discover_trials(roots)
    try:
        selected = select_trials(plans, a.only, [s for x in a.scenarios for s in x.split(",") if s])
    except IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for n in notes:
        print(f"note: {n}")
    if a.dry_run:
        for plan in selected:
            print("\n".join(plan_lines(roots, plan)))
        print(f"{len(selected)} trials selected (dry run, nothing written)")
        return 0
    failed = 0
    for plan in selected:
        pre = hash_tree(plan.source_dir, roots.incoming) if roots.strict else None
        if trial_state(plan) == "complete" and not a.force and not is_stale(roots, plan, pre):
            print(f"{plan.trial_id}: complete, skipped (use --force to rebuild)")
            continue
        print(f"{plan.trial_id}: ingesting ...", flush=True)
        rep = ingest_trial(roots, plan, a.force, pre)
        print(f"{plan.trial_id}: {rep['status']} in {rep['duration_seconds']} s; copied {len(rep['files_copied'])}, "
              f"missing {len(rep['files_missing'])}; events {(rep['import'] or {}).get('events')}"
              + (f"; {rep['error']}" if rep["error"] else ""), flush=True)
        if rep["status"] != "ok":
            failed += 1
            if not rep["incoming_hashes"]["unchanged"] or not a.keep_going:
                return 1
    return 1 if failed else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="data_layout.batch", description=__doc__.splitlines()[0])
    add_arguments(p)
    return run(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
