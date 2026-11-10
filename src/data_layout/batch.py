"""Batch ingest driver for the x10 trials: incoming -> raw copy -> manifest -> JSONL -> per-trial SQLite.

Run from the repo root:  PYTHONPATH=src python -m data_layout.batch --dry-run
(or `python -m data_layout.cli batch ...`).  Reuses layout.py (classify/copy/manifest) and
evtx_pipeline (convert, run_trial_import); nothing here re-implements them.

Layout (decisions 029/030):
  data/incoming/x10/S0N/trial_NN/<HOST>/*.evtx            read-only, hashed before and after
  data/raw/s0N/tNN/<host>/<channel>.evtx                   + rows appended to data/manifest.csv
  data/processed/jsonl/s0N_tNN/                            converter output
  data/processed/s0N_tNN.sqlite3                           import-trial output
  S05_WRONG_DESIGN_DO_NOT_USE -> data/raw/quarantine/s05/tNN, data/manifest_quarantine.csv,
  data/processed/jsonl/quarantine/s05_tNN, data/processed/quarantine/s05q_tNN.sqlite3
  out/ingest/x10/<trial_id>/ingest.json + ingest.md       per-trial report
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
from data_layout import layout as L

SCENARIO_RE = re.compile(r"^S0(\d)$")
TRIAL_RE = re.compile(r"^trial_(\d{2})$")
# Decision 030: the only quarantined folder; maps to its real scenario number.
QUARANTINE_FOLDERS: dict[str, str] = {"S05_WRONG_DESIGN_DO_NOT_USE": "s05"}


class IngestError(RuntimeError):
    """Any condition that must stop a trial (raw conflict, manifest misuse, failed check)."""


class IncomingChanged(IngestError):
    """An incoming file changed while we worked: stop the whole batch, never continue."""


@dataclass(frozen=True)
class Roots:
    """Every directory the batch reads or writes, derived from the repo root (no globals)."""
    repo: Path
    incoming: Path
    x10: Path
    raw: Path
    processed: Path
    manifest: Path
    manifest_quarantine: Path
    ingest_out: Path
    normalise_out: Path

    @classmethod
    def from_repo(cls, repo: Path) -> "Roots":
        repo = repo.resolve()
        data = repo / "data"
        return cls(repo, data / "incoming", data / "incoming" / "x10", data / "raw", data / "processed",
                   data / "manifest.csv", data / "manifest_quarantine.csv",
                   repo / "out" / "ingest" / "x10", repo / "out" / "normalise")


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

def scenario_of_folder(name: str) -> Optional[tuple[str, bool]]:
    """S02 -> (s02, False); the quarantine folder -> (s05, True); anything else -> None."""
    if name in QUARANTINE_FOLDERS:
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
    """List trial folders under data/incoming/x10; unknown folders are reported, never guessed."""
    plans: list[TrialPlan] = []
    notes: list[str] = []
    for scen_dir in sorted(p for p in roots.x10.iterdir() if p.is_dir()):
        scen = scenario_of_folder(scen_dir.name)
        if scen is None:
            notes.append(f"skipped folder {scen_dir.name!r}: not S0N or a known quarantine folder")
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
        return {r["path"] for r in csv.DictReader(f)}


def trial_state(plan: TrialPlan) -> str:
    """complete = DB exists, ingest.json says ok, every copied file is in the manifest; else partial/new.

    WHY: requirement 6 (resumable); a trial is only skipped when all three agree."""
    report = read_json(plan.out_dir / "ingest.json")
    if plan.database.exists() and report and report.get("status") == "ok":
        listed = manifest_paths(plan.manifest)
        if all(f["dest_path"] in listed for f in report.get("files_copied", [])):
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


def append_manifest_rows(roots: Roots, plan: TrialPlan, rows: list[L.MapRow]) -> dict[str, dict[str, str]]:
    """Append this trial's rows via layout.append_manifest and prove the old lines were not touched.

    WHY: existing t00 rows must never change (requirement 3); quarantined rows must never
    reach data/manifest.csv (decision 030)."""
    copy = [r for r in rows if r.action == "copy"]
    if any(r.dest_path.startswith("quarantine/") for r in copy) != plan.quarantine:
        raise IngestError(f"{plan.trial_id}: quarantine rows would go to the wrong manifest")
    before = plan.manifest.read_bytes() if plan.manifest.exists() else b""
    L.append_manifest(roots.raw, copy, plan.manifest)
    after = plan.manifest.read_bytes()
    if not after.startswith(before):
        raise IngestError(f"{plan.manifest}: existing lines changed during append")
    with open(plan.manifest, newline="", encoding="utf-8") as f:
        listed = {r["path"]: r for r in csv.DictReader(f)}
    return {trial_rel(plan, r.dest_path): listed[r.dest_path] for r in copy if r.dest_path in listed}


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
    return {"trial_id": plan.trial_id, "scenario": plan.scenario, "trial": plan.trial,
            "quarantine": plan.quarantine, "status": "running", "error": None,
            "source_dir": rel(plan.source_dir), "raw_dir": rel(plan.raw_dir), "jsonl_dir": rel(plan.jsonl_dir),
            "database": rel(plan.database), "manifest": rel(plan.manifest),
            "db_scenario_id": plan.scenario, "db_trial_id": plan.trial,
            "started_utc": utc_now(), "phase_seconds": {}, "files_copied": [], "files_ignored": [],
            "files_missing": [], "extra_files": [], "converter": [], "import": None, "reconcile": None}


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

def ingest_steps(roots: Roots, plan: TrialPlan, report: dict[str, Any], pre: dict[str, str]) -> None:
    """map -> copy -> manifest -> convert -> import -> reconcile; raises on the first failure."""
    phases = report["phase_seconds"]
    with timed(phases, "map"):
        rows = map_trial(roots, plan)
    with timed(phases, "copy"):
        report["files_copied"] = copy_rows(roots, rows, pre)
    summarise_mapping(report, rows, report["files_copied"])
    with timed(phases, "manifest"):
        manifest_rows = append_manifest_rows(roots, plan, rows)
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


def ingest_trial(roots: Roots, plan: TrialPlan, force: bool) -> dict[str, Any]:
    """Process one trial and always write its report; incoming hashes are compared at the end."""
    started = time.perf_counter()
    report = base_report(roots, plan)
    pre = hash_tree(plan.source_dir, roots.incoming)
    report["sizes_bytes"] = {"incoming": sum((roots.incoming / k).stat().st_size for k in pre)}
    try:
        if plan.database.exists():
            if not force:
                raise IngestError(f"{plan.database} exists but the trial is not complete; rerun with --force")
            remove_derived(roots, plan.database)
        ingest_steps(roots, plan, report, pre)
        report["status"] = "ok"
    except Exception as exc:  # the report must survive any failure
        report["status"], report["error"] = "error", f"{type(exc).__name__}: {str(exc)[:500]}"
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
    p.add_argument("--only", action="append", default=[], metavar="TRIAL_ID",
                   help="process only this trial id (s02_t01, s05q_t03); repeatable")
    p.add_argument("--scenarios", nargs="+", default=[], metavar="S0N",
                   help="process only these scenarios (s02 ... s07; s05 or s05q = quarantine)")
    p.add_argument("--force", action="store_true", help="rebuild complete trials (JSONL and DB; raw is only verified)")
    p.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
    p.add_argument("--keep-going", action="store_true",
                   help="continue after a failed trial (an incoming-hash change always stops)")


def run(a: argparse.Namespace) -> int:
    """Entry point shared by `python -m data_layout.batch` and `data_layout.cli batch`."""
    roots = Roots.from_repo(a.repo)
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
        if trial_state(plan) == "complete" and not a.force:
            print(f"{plan.trial_id}: complete, skipped (use --force to rebuild)")
            continue
        print(f"{plan.trial_id}: ingesting ...", flush=True)
        rep = ingest_trial(roots, plan, a.force)
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
