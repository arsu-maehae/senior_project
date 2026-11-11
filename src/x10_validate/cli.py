"""CLI: ``python -m x10_validate run [--trials ...] [--all] [--no-ingest-check]`` and ``... report``.

WHY all I/O here: the criteria are pure functions; this module only finds DBs, reads ingest.json,
opens DBs read-only and writes JSON/markdown under ``out/x10_validate/`` (never ``data/`` or ``docs/``).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from . import db
from .cross import apply_cross
from .design import DESIGNS, design_for
from .report import failing_summary, render
from .validate import validate_trial

REPO = Path(__file__).resolve().parents[2]
TRIAL_RE = re.compile(r"^(s0\d)(q?)_(t\d\d)$")
X10_SCENARIOS = ("s02", "s03", "s04", "s06", "s07")
X10_TRIALS = tuple(f"t{n:02d}" for n in range(1, 11))


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


def ingest_path(repo: Path, trial_id: str) -> Path:
    return repo / "out" / "ingest" / "x10" / trial_id / "ingest.json"


def read_ingest(repo: Path, trial_id: str) -> tuple[dict | None, str | None]:
    """(ingest report, None) when it exists and says ok, else (None, reason)."""
    p = ingest_path(repo, trial_id)
    if not p.is_file():
        return None, "no out/ingest/x10/<trial>/ingest.json"
    try:
        rep = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"ingest.json unreadable: {exc}"
    if rep.get("status") != "ok":
        return None, f"ingest status {rep.get('status')!r}"
    return rep, None


def out_dir(repo: Path) -> Path:
    """The only directory this tool writes to."""
    return repo / "out" / "x10_validate"


def _safe_write(repo: Path, path: Path, text: str) -> None:
    """Write under out/x10_validate only (CLAUDE.md data rules: never data/ or docs/)."""
    root = out_dir(repo).resolve()
    if root not in path.resolve().parents:
        raise SystemExit(f"refusing to write outside {root}: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def discover(repo: Path) -> list[str]:
    """x10 and quarantine trial ids with a DB (t00 and scenarios without a 029 design excluded)."""
    base = repo / "data" / "processed"
    ids = [p.stem for p in base.glob("s0?_t??.sqlite3")] + [p.stem for p in (base / "quarantine").glob("s05q_t??.sqlite3")]
    keep = []
    for t in ids:
        try:
            scen, _, tr = parse_trial(t)
        except ValueError:
            continue
        if tr != "t00" and scen in DESIGNS:
            keep.append(t)
    return sorted(keep)


def not_ingested(repo: Path) -> list[dict]:
    """Expected x10 trials (and any DB found) without an ok ingest.json."""
    expected = [f"{s}_{t}" for s in X10_SCENARIOS for t in X10_TRIALS] + [f"s05q_{t}" for t in X10_TRIALS]
    out = []
    for t in sorted(set(expected) | set(discover(repo))):
        rep, why = read_ingest(repo, t)
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


def load_results(repo: Path) -> list[dict]:
    """Every per-trial JSON already written."""
    out = []
    for p in sorted(out_dir(repo).glob("*.json")):
        if TRIAL_RE.match(p.stem):
            out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


def write_results(repo: Path, results: Sequence[dict]) -> None:
    for r in results:
        _safe_write(repo, out_dir(repo) / f"{r['trial_id']}.json", json.dumps(r, indent=1, ensure_ascii=False))


def cmd_run(repo: Path, trials: Sequence[str], run_all: bool, no_ingest_check: bool) -> int:
    """Validate the chosen trials, then refresh the cross-trial parts (f overlap, i) of all results."""
    chosen = sorted(set(trials) | (set(discover(repo)) if run_all else set()))
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
            ingest, why = read_ingest(repo, t)
            if ingest is None:
                skipped.append((t, f"not ingested: {why}"))
                continue
        res = validate_one(repo, t, ingest)
        write_results(repo, [res])
        done.append(t)
        print(f"{t}: {res['runtime_s']} s, fails {[c for c in 'abcdefghi' if res['criteria'][c]['status'] == 'FAIL']}")
    merged = apply_cross(load_results(repo))
    write_results(repo, merged)
    for t, why in skipped:
        print(f"{t}: skipped ({why})")
    summary = failing_summary([r for r in merged if r["trial_id"] in done])
    print(json.dumps({"validated": done, "failing_criteria": summary}, indent=1))
    return 0


def cmd_report(repo: Path) -> int:
    """Write out/x10_validate/report.md from all per-trial results."""
    results = apply_cross(load_results(repo))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    text = render(results, not_ingested(repo), now)
    _safe_write(repo, out_dir(repo) / "report.md", text)
    print(f"wrote {out_dir(repo) / 'report.md'} ({len(results)} trial result(s))")
    return 0


def main(argv: Sequence[str] | None = None, repo: Path = REPO) -> int:
    """Entry point; ``repo`` is a parameter so tests can point it at a temp copy."""
    ap = argparse.ArgumentParser(prog="python -m x10_validate", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="validate trials -> out/x10_validate/<trial>.json")
    run.add_argument("--trials", nargs="*", default=[], help="trial ids such as s02_t01 s05q_t03 s02_t00")
    run.add_argument("--all", action="store_true", help="every x10 and quarantine DB found (t00 excluded)")
    run.add_argument("--no-ingest-check", action="store_true",
                     help="t00 only: skip ingest.json; criterion a then uses DB row counts")
    sub.add_parser("report", help="write out/x10_validate/report.md")
    args = ap.parse_args(argv)
    if args.cmd == "run":
        return cmd_run(repo, args.trials, args.all, args.no_ingest_check)
    return cmd_report(repo)
