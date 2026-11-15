"""CLI: ``python -m x10_validate run [--source S] [--trials ...] [--all] [--no-ingest-check]`` and ``... report``.

WHY all I/O here: the criteria are pure functions; this module only finds DBs, reads ingest.json,
opens DBs read-only and writes JSON/markdown under ``out/x10_validate/`` (source x10, default) or
``out/x10_validate_v2/`` (source x10_v2, the reruns of decisions 034/052); never ``data/`` or ``docs/``.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from . import db
from .cross import apply_cross
from .design import DESIGNS, design_for
from .report import failing_summary, render, render_v2
from .validate import validate_trial

REPO = Path(__file__).resolve().parents[2]
TRIAL_RE = re.compile(r"^(s0\d)(q?)_(t\d\d)$")
X10_SCENARIOS = ("s02", "s03", "s04", "s06", "s07")
X10_TRIALS = tuple(f"t{n:02d}" for n in range(1, 11))
X10_V2_SCENARIOS = ("s01", "s04", "s05", "s07")   # decision 034 / 052; S01 design: decision 036
X10_V2_MIN_ACCEPTED = 5                            # decision 052 item 3


@dataclass(frozen=True)
class Source:
    """Where one batch of trials comes from and where its results go (no globals: passed to every function)."""
    name: str                       # x10 | x10_v2; also the folder under out/ingest/
    scenarios: tuple[str, ...]      # expected scenarios (the "not ingested" list)
    trials: tuple[str, ...]
    out_name: str                   # folder under out/ this tool writes to
    quarantine: bool                # quarantined S05 (decision 030) belongs to x10 only
    minimum: int | None = None      # decision 052 minimum accepted trials per scenario (v2 only)
    incoming_prefix: str | None = None   # v2: a report's source_dir must start with this


X10 = Source("x10", X10_SCENARIOS, X10_TRIALS, "x10_validate", True)
X10_V2 = Source("x10_v2", X10_V2_SCENARIOS, X10_TRIALS, "x10_validate_v2", False,
                X10_V2_MIN_ACCEPTED, "data/incoming/x10_v2/")
SOURCES: dict[str, Source] = {s.name: s for s in (X10, X10_V2)}


def parse_trial(trial_id: str) -> tuple[str, bool, str]:
    """``s02_t01`` -> (s02, False, t01); ``s05q_t03`` -> (s05, True, t03). Identity comes from the name (030)."""
    m = TRIAL_RE.match(trial_id)
    if not m:
        raise ValueError(f"not a trial id: {trial_id!r}")
    return m.group(1), m.group(2) == "q", m.group(3)


def db_path(repo: Path, trial_id: str) -> Path:
    """data/processed/<trial>.sqlite3, or data/processed/quarantine/s05q_tNN.sqlite3 (decision 030)."""
    _, quarantine, _ = parse_trial(trial_id)
    base = repo / "data" / "processed"
    return (base / "quarantine" if quarantine else base) / f"{trial_id}.sqlite3"


def ingest_path(repo: Path, trial_id: str, source: Source = X10) -> Path:
    return repo / "out" / "ingest" / source.name / trial_id / "ingest.json"


def source_mismatch(rep: dict, source: Source) -> str | None:
    """Why an ingest report does not belong to ``source`` (None = it does; always None for x10).

    WHY: data/processed/<id>.sqlite3 is shared between the old x10 trials and the x10_v2 reruns. A v2 run must
    never validate a DB whose last ingest came from the old folder (an archive that was skipped), so the report
    has to say ``source: x10_v2`` and name a source_dir under data/incoming/x10_v2/."""
    if source.incoming_prefix is None:
        return None
    if rep.get("source") != source.name:
        return f"ingest report source is {rep.get('source')!r}, not {source.name!r}"
    if not str(rep.get("source_dir", "")).startswith(source.incoming_prefix):
        return f"ingest report source_dir {rep.get('source_dir')!r} is not under {source.incoming_prefix}"
    return None


def load_ingest(repo: Path, trial_id: str, source: Source = X10) -> tuple[dict | None, str | None]:
    """(report, None) when ingest.json exists, parses and belongs to ``source``; else (None, reason).

    The status is NOT checked here (``read_ingest`` does that); ``discover`` uses this to find v2 trials."""
    p = ingest_path(repo, trial_id, source)
    if not p.is_file():
        return None, f"no out/ingest/{source.name}/<trial>/ingest.json"
    try:
        rep = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"ingest.json unreadable: {exc}"
    if not isinstance(rep, dict):
        return None, "ingest.json is not a JSON object"
    why = source_mismatch(rep, source)
    return (None, why) if why else (rep, None)


def read_ingest(repo: Path, trial_id: str, source: Source = X10) -> tuple[dict | None, str | None]:
    """(ingest report, None) when it exists, belongs to ``source`` and says ok, else (None, reason)."""
    rep, why = load_ingest(repo, trial_id, source)
    if rep is None:
        return None, why
    if rep.get("status") != "ok":
        return None, f"ingest status {rep.get('status')!r}"
    return rep, None


def out_dir(repo: Path, source: Source = X10) -> Path:
    """The only directory this tool writes to (per source, so v1 and v2 results never mix)."""
    return repo / "out" / source.out_name


def _safe_write(repo: Path, path: Path, text: str, source: Source = X10) -> None:
    """Write under the source's out dir only (CLAUDE.md data rules: never data/ or docs/)."""
    root = out_dir(repo, source).resolve()
    if root not in path.resolve().parents:
        raise SystemExit(f"refusing to write outside {root}: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def discover(repo: Path, source: Source = X10) -> list[str]:
    """Trial ids with a DB (t00 and scenarios without a 029 design excluded).

    x10: x10 and quarantine DBs, as before. x10_v2: only s01/s04/s05/s07 DBs that have an ingest report of
    the x10_v2 source (the DB path is shared with the old trials), never quarantine."""
    base = repo / "data" / "processed"
    ids = [p.stem for p in base.glob("s0?_t??.sqlite3")]
    if source.quarantine:
        ids += [p.stem for p in (base / "quarantine").glob("s05q_t??.sqlite3")]
    keep = []
    for t in ids:
        try:
            scen, _, tr = parse_trial(t)
        except ValueError:
            continue
        if tr == "t00" or scen not in DESIGNS:
            continue
        if source.incoming_prefix is not None and (
                scen not in source.scenarios or load_ingest(repo, t, source)[0] is None):
            continue
        keep.append(t)
    return sorted(keep)


def expected_trial_ids(source: Source) -> list[str]:
    """Trials the report lists when they are not ingested: all 10 for x10; for x10_v2 only the minimum of 052."""
    trials = source.trials[:source.minimum] if source.minimum else source.trials
    ids = [f"{s}_{t}" for s in source.scenarios for t in trials]
    return ids + ([f"s05q_{t}" for t in source.trials] if source.quarantine else [])


def not_ingested(repo: Path, source: Source = X10) -> list[dict]:
    """Expected trials (and any DB found) without an ok ingest.json of this source."""
    out = []
    for t in sorted(set(expected_trial_ids(source)) | set(discover(repo, source))):
        rep, why = read_ingest(repo, t, source)
        if rep is None:
            has_db = db_path(repo, t).is_file()
            out.append({"trial_id": t, "reason": f"{why}; DB {'present' if has_db else 'absent'}"})
    return out


def validate_one(repo: Path, trial_id: str, ingest: dict | None) -> dict:
    """Open one DB read-only, validate it, and attach provenance and runtime."""
    scen, quarantine, _ = parse_trial(trial_id)
    path = db_path(repo, trial_id)
    t0 = time.perf_counter()
    con = db.open_ro(path)
    try:
        rows = db.load_rows(con)
        counts = db.host_channel_counts(con)
        span = db.db_span(con)
    finally:
        con.close()
    res = validate_trial(trial_id, scen, quarantine, design_for(scen), rows, counts, span, ingest)
    res["db_path"] = path.relative_to(repo).as_posix()
    res["db_sha256"] = db.sha256_file(path)
    res["ingest_checked"] = ingest is not None
    res["generated_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    res["runtime_s"] = round(time.perf_counter() - t0, 2)
    return res


def load_results(repo: Path, source: Source = X10) -> list[dict]:
    """Every per-trial JSON already written for this source."""
    out = []
    for p in sorted(out_dir(repo, source).glob("*.json")):
        if TRIAL_RE.match(p.stem):
            out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


def write_results(repo: Path, results: Sequence[dict], source: Source = X10) -> None:
    for r in results:
        _safe_write(repo, out_dir(repo, source) / f"{r['trial_id']}.json",
                    json.dumps(r, indent=1, ensure_ascii=False), source)


def cmd_run(repo: Path, trials: Sequence[str], run_all: bool, no_ingest_check: bool,
            source: Source = X10) -> int:
    """Validate the chosen trials, then refresh the cross-trial parts (f overlap, i) of all results."""
    if no_ingest_check and source.incoming_prefix is not None:
        raise SystemExit(f"--no-ingest-check is for the x10 t00 sanity runs only, not source {source.name}")
    chosen = sorted(set(trials) | (set(discover(repo, source)) if run_all else set()))
    if not chosen:
        print("nothing to do: give --trials or --all", file=sys.stderr)
        return 2
    skipped, done = [], []
    for t in chosen:
        scen, _, tr = parse_trial(t)
        if no_ingest_check and tr != "t00":
            raise SystemExit(f"--no-ingest-check is allowed for t00 trials only, not {t}")
        if not db_path(repo, t).is_file():
            skipped.append((t, "no DB"))
            continue
        ingest = None
        if not no_ingest_check:
            ingest, why = read_ingest(repo, t, source)
            if ingest is None:
                skipped.append((t, f"not ingested: {why}"))
                continue
        res = validate_one(repo, t, ingest)
        write_results(repo, [res], source)
        done.append(t)
        print(f"{t}: {res['runtime_s']} s, fails {[c for c in 'abcdefghi' if res['criteria'][c]['status'] == 'FAIL']}")
    merged = apply_cross(load_results(repo, source))
    write_results(repo, merged, source)
    for t, why in skipped:
        print(f"{t}: skipped ({why})")
    summary = failing_summary([r for r in merged if r["trial_id"] in done])
    print(json.dumps({"validated": done, "failing_criteria": summary}, indent=1))
    return 0


def cmd_report(repo: Path, source: Source = X10) -> int:
    """Write report.md under the source's out dir from all per-trial results of that source."""
    results = apply_cross(load_results(repo, source))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    if source.minimum is None:
        text = render(results, not_ingested(repo, source), now)
    else:
        text = render_v2(results, not_ingested(repo, source), now, source.scenarios, source.minimum)
    _safe_write(repo, out_dir(repo, source) / "report.md", text, source)
    print(f"wrote {out_dir(repo, source) / 'report.md'} ({len(results)} trial result(s))")
    return 0


def main(argv: Sequence[str] | None = None, repo: Path = REPO) -> int:
    """Entry point; ``repo`` is a parameter so tests can point it at a temp copy."""
    ap = argparse.ArgumentParser(prog="python -m x10_validate", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    src_help = "x10 (default; out/x10_validate) or x10_v2 (the reruns; out/x10_validate_v2)"
    run = sub.add_parser("run", help="validate trials -> out/x10_validate[_v2]/<trial>.json")
    run.add_argument("--source", choices=sorted(SOURCES), default="x10", help=src_help)
    run.add_argument("--trials", nargs="*", default=[], help="trial ids such as s02_t01 s05q_t03 s02_t00")
    run.add_argument("--all", action="store_true", help="every x10 and quarantine DB found (t00 excluded)")
    run.add_argument("--no-ingest-check", action="store_true",
                     help="t00 only: skip ingest.json; criterion a then uses DB row counts")
    rpt = sub.add_parser("report", help="write out/x10_validate[_v2]/report.md")
    rpt.add_argument("--source", choices=sorted(SOURCES), default="x10", help=src_help)
    args = ap.parse_args(argv)
    source = SOURCES[args.source]
    if args.cmd == "run":
        return cmd_run(repo, args.trials, args.all, args.no_ingest_check, source)
    return cmd_report(repo, source)
