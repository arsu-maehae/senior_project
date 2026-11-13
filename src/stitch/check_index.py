"""Development check of T7.2: ``python -m stitch.check_index --trial <id> [--repo PATH]`` (cwd=src or PYTHONPATH=src).

Runs ST-00 (``check_allowed``), the read-only scan (``load_scan``) and the index (``build_index``), and writes
``out/stitch_check/<trial_id>/t72_index.json``: counts only, no names, images or command text, sorted keys, no
timestamps, so two runs on the same inputs give the same bytes (plan T7.2 section 2). It is not a spec 03
output file. WHY build first and write last: on any refusal nothing may be written (spec 2), so the folder is
created only after every check has passed and the JSON text is complete. A refusal prints
``refused: <reason>`` to stderr and exits 2.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from gate.run import display_path

from .errors import StitchError
from .index import build_index, index_counts, params_dict
from .inputs import CheckedInputs, check_allowed, load_scan, trial_paths
from .params import CHECK_OUT_REL, TOOL_VERSION, StitchParams

REPO = Path(__file__).resolve().parents[2]
CHECK_FILE = "t72_index.json"

# Window facts written instead of the whole row (coordinator, T7.2 task 4): the row's ``rule`` text names the
# agent image, and the check file carries no names or images.
WINDOW_KEYS: tuple[str, ...] = ("start_utc", "end_utc", "time_basis", "window_source", "db_sha256",
                                "offsets_sha256", "clock_changes_sha256")


def window_summary(row: Mapping[str, Any]) -> dict[str, Any]:
    """The ``WINDOW_KEYS`` values of the window row; a key the row lacks is left out, never invented."""
    return {k: row[k] for k in WINDOW_KEYS if k in row}


def check_extra(repo: Path, db: Path, checked: CheckedInputs, sha_before: str, sha_after: str,
                params: StitchParams) -> dict[str, Any]:
    """The file-level facts of the check file: tool version, DB path (repo-relative) and hashes, gate stats hash,
    window summary and parameters. WHY repo-relative: the bytes must not depend on where the repo lives."""
    return {
        "tool_version": TOOL_VERSION,
        "db": {"path": display_path(db, repo), "sha256_before": sha_before, "sha256_after": sha_after},
        "gate_stats_sha256": checked.gate_stats_sha256,
        "window": window_summary(checked.window_row),
        "parameters": params_dict(params),
    }


def run_check(repo: Path, trial_id: str, params: StitchParams = StitchParams()) -> dict[str, Any]:
    """ST-00, scan and index for one trial; returns the check-file dict and writes nothing.

    Raises StitchError on any refusal (development allowlist first, decision 046).
    """
    paths = trial_paths(Path(repo), trial_id)
    checked = check_allowed(paths, params)
    scan, before, after = load_scan(checked, paths, params)
    index = build_index(trial_id, scan, params)
    return index_counts(index, check_extra(Path(repo), paths.db, checked, before, after, params))


def check_text(data: Mapping[str, Any]) -> str:
    """The exact file text: sorted keys, indent 1, one trailing newline (byte-identical across runs)."""
    return json.dumps(data, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def write_check(repo: Path, trial_id: str, data: Mapping[str, Any]) -> Path:
    """Write ``out/stitch_check/<trial_id>/t72_index.json`` (UTF-8, LF) and return its path.

    WHY a temporary file and ``os.replace``: an existing check file is either kept whole or replaced whole,
    never left half-written. The text is built before the folder is created.
    """
    text = check_text(data)
    out_dir = Path(repo) / CHECK_OUT_REL / trial_id
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / CHECK_FILE
    tmp = out_dir / (CHECK_FILE + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, target)
    return target


def _reason(exc: StitchError) -> str:
    """Refusal text without a doubled ``refused:`` prefix (most StitchError messages already start with it)."""
    text = str(exc)
    return text[len("refused: "):] if text.startswith("refused: ") else text


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run, write. Exit 0 on success, 2 on a refusal (reason on stderr, nothing written)."""
    ap = argparse.ArgumentParser(prog="stitch.check_index", description=__doc__)
    ap.add_argument("--trial", required=True)
    ap.add_argument("--repo", type=Path, default=REPO)
    a = ap.parse_args(argv)
    repo = a.repo.resolve()
    try:
        data = run_check(repo, a.trial)
    except StitchError as exc:
        print(f"refused: {_reason(exc)}", file=sys.stderr)
        return 2
    path = write_check(repo, a.trial, data)
    s, p = data["sessions"], data["processes"]
    print(f"{a.trial}: {sum(s['per_host'].values())} session(s), window_view {s['window_view']}, "
          f"{p['processes']} process(es), {p['collapsed_pairs']} collapsed pair(s)")
    print(f"wrote {display_path(path, repo)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
