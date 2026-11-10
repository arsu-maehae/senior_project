"""CLI: ``python -m answer_key build|verify --trial s02_t00`` (run with src on the path / cwd=src).

Drafts are written as JSON, which is valid YAML 1.2 (PyYAML is not installed), to
``ground_truth/drafts/<trial>.yaml`` only; verify writes ``out/answer_key/<trial>/``.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from . import db
from .build import build_draft
from .verify import load_draft, to_markdown, verify

REPO = Path(__file__).resolve().parents[2]
INTENDED = Path(__file__).with_name("intended_steps.json")


def safe_draft_path(repo: Path, trial: str) -> Path:
    """Draft path under ground_truth/drafts; refuses anything under approved/ (AK-14)."""
    out = (repo / "ground_truth" / "drafts" / f"{trial}.yaml").resolve()
    approved = (repo / "ground_truth" / "approved").resolve()
    if approved in out.parents or out == approved:
        raise SystemExit(f"refusing to write under {approved}")
    if (repo / "ground_truth" / "drafts").resolve() not in out.parents:
        raise SystemExit("draft must be under ground_truth/drafts")
    return out


def read_provisional(repo: Path, trial: str) -> dict | None:
    """Provisional window row for the trial, if any (search bound only)."""
    p = repo / "docs" / "research" / "provisional_windows.csv"
    if not p.exists():
        return None
    with open(p, newline="", encoding="utf-8") as fh:
        return next((r for r in csv.DictReader(fh) if r["trial_id"] == trial), None)


def cmd_build(trial: str, repo: Path) -> Path:
    """Build and write one draft."""
    out = safe_draft_path(repo, trial)
    dbp = repo / "data" / "processed" / f"{trial}.sqlite3"
    intended = json.loads(INTENDED.read_text(encoding="utf-8"))
    with db.guarded(dbp) as (con, sha):
        rows = db.load_events(con)
        draft = build_draft(rows, trial, intended, sha, read_provisional(repo, trial))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(draft, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out


def cmd_verify(trial: str, repo: Path) -> dict:
    """Verify one draft against its DB and write verify.json / verify.md."""
    draft = load_draft(repo / "ground_truth" / "drafts" / f"{trial}.yaml")
    rep = verify(draft, repo / "data" / "processed" / f"{trial}.sqlite3")
    d = repo / "out" / "answer_key" / trial
    d.mkdir(parents=True, exist_ok=True)
    (d / "verify.json").write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    (d / "verify.md").write_text(to_markdown(rep), encoding="utf-8")
    return rep


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="answer_key")
    ap.add_argument("action", choices=["build", "verify"])
    ap.add_argument("--trial", required=True)
    ap.add_argument("--repo", type=Path, default=REPO)
    a = ap.parse_args(argv)
    if a.action == "build":
        print(cmd_build(a.trial, a.repo))
        return 0
    rep = cmd_verify(a.trial, a.repo)
    print(json.dumps({k: rep[k] for k in ("trial_id", "ok", "checked", "out_of_window", "per_kind")}))
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
