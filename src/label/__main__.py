"""Label stage CLI (spec 04_label), run from the repository root after ``pip install -e .``:

    python -m label --trial <id> [--repo PATH] [--out PATH]
    python -m label --development [--repo PATH]

``--trial`` labels one development trial into ``out/label/<trial>/`` (or the ``--out`` folder); ``--development``
labels every trial of ``clock_offset.params.DEVELOPMENT_TRIALS``, all in memory first, then writes each folder, so
one refusal writes nothing at all.

The allowlist is checked before any file is opened (LB-00; decisions 046, 053): a test trial is refused with exit 2
and nothing is created. Every other refusal of spec 2 also exits 2 and writes nothing. A ``--out`` folder is checked
after the refusals and before anything is written (``lab_common.outdir``, decision 054): inside the repository it must
lie strictly below ``out/``, and an existing folder may hold only the seven output names, because the folder swap
deletes the old folder. Folders are rebuilt through a temporary sibling and a rename (``stitch.__main__``).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from gate.run import display_path
from lab_common.outdir import out_target_refusal
from stitch.__main__ import replace_folder

from .errors import LabelError
from .inputs import check_allowlist
from .outputs import OUTPUT_FILES
from .params import ALLOWED_TRIALS
from .run import default_out_dir, label_trial

REPO = Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    """Arguments: exactly one of --trial / --development."""
    ap = argparse.ArgumentParser(prog="label", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--trial")
    mode.add_argument("--development", action="store_true")
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--out", type=Path, default=None,
                    help="output folder for --trial (default out/label/<trial>); replaced whole on every run")
    return ap


def _one(repo: Path, trial: str, out: Path | None) -> int:
    """Label and write one trial; the allowlist comes before anything else."""
    check_allowlist(trial)
    res = label_trial(repo, trial)
    target = default_out_dir(repo, trial)
    if out is not None:
        target = out.resolve()
        reason = out_target_refusal(target, repo, OUTPUT_FILES)
        if reason:
            raise LabelError(f"refused: {reason}")
    replace_folder(target, res.files)
    print(display_path(target, repo))
    return 0


def _development(repo: Path) -> int:
    """Label all development trials in memory, then write each folder."""
    for trial in ALLOWED_TRIALS:
        check_allowlist(trial)
    results = [label_trial(repo, t) for t in ALLOWED_TRIALS]
    for res in results:
        target = default_out_dir(repo, res.trial_id)
        replace_folder(target, res.files)
        print(display_path(target, repo))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 0 on success (prints the folders written), 2 on a refusal (reason on stderr, nothing written)."""
    a = _parser().parse_args(argv)
    repo = a.repo.resolve()
    try:
        if a.development:
            if a.out is not None:
                raise LabelError("refused: --out applies to --trial only")
            return _development(repo)
        return _one(repo, a.trial, a.out)
    except LabelError as exc:
        text = str(exc)
        print(text if text.startswith("refused") else f"refused: {text}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
