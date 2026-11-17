"""Inputs of the development ranking check (PLAN T9.5; spec 05_score SCA-06, section 5.2, section 7.3; decisions 065,
066): the score stage files of one trial, checked against the score ``run_info.json`` and against the stitch files
the score stage read.

WHY refusals like ``inputs`` / ``label_inputs``: a rank number is only meaningful for exactly the ranked list, stitch
paths and key it names. A ranked list regenerated after the score run, or a score run made on other stitch files
than the ones read here (``path_nodes.csv`` gives the node sets), would give numbers about something else, so the
run stops and writes nothing. Nothing here imports ``score`` or ``stitch`` (decision 051 item 1 spirit; T9.5 brief):
both are read as files.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .inputs import EvalError, KeyData, StitchData, sha256_bytes
from .params import SCORE_OUT_REL

__all__ = ["ScoreData", "SCORE_RUN_INFO", "RANKED_FILE", "B0_FILE", "UNITS_FILE", "RANKED_COLUMNS", "B0_COLUMNS",
           "UNITS_COLUMNS", "PATH_VARIANTS", "default_score_dir", "load_score", "check_score_against_stitch",
           "check_key_against_stitch", "default_params"]

SCORE_RUN_INFO = "run_info.json"
RANKED_FILE = "ranked_paths.csv"
B0_FILE = "b0_ranked.csv"
UNITS_FILE = "path_node_units.csv"
# The variants of ranked_paths.csv (spec 05 section 3.6); spelled here because evaluate must not import score.
PATH_VARIANTS: tuple[str, ...] = ("full", "b1", "b2")
# The columns this check reads (spec 05 sections 3.1, 3.3, 3.6); a header without one of them is refused.
RANKED_COLUMNS: tuple[str, ...] = ("trial_id", "variant", "rank", "tie_size", "path_id", "score", "edge_score",
                                   "seq_len", "node_score", "identity_coherence", "hop_ids")
B0_COLUMNS: tuple[str, ...] = ("trial_id", "variant", "rank", "tie_size", "unit_id", "event_uids", "score")
UNITS_COLUMNS: tuple[str, ...] = ("path_id", "count_key", "event_uids")
_SCORE_FILES: tuple[str, ...] = (RANKED_FILE, B0_FILE, UNITS_FILE)
# The score parameters the sweep's default point is read from (score run_info.json ``parameters``).
_PARAM_NAMES: tuple[str, ...] = ("lam", "w1", "w2", "w3")


@dataclass(frozen=True)
class ScoreData:
    """The three score files of one trial (rows as written) with the hashes that pin them."""
    score_dir: Path
    ranked: tuple[Mapping[str, str], ...]
    b0: tuple[Mapping[str, str], ...]
    units: tuple[Mapping[str, str], ...]
    run_info: Mapping[str, Any]
    run_info_sha256: str
    file_sha256: Mapping[str, str]


def default_score_dir(repo: Path, trial: str) -> Path:
    """``out/score/<trial>``."""
    return Path(repo) / SCORE_OUT_REL / trial


def _read(path: Path) -> bytes:
    """File bytes; EvalError when the file is missing."""
    if not path.is_file():
        raise EvalError(f"refused: score file {path.as_posix()} is missing")
    return path.read_bytes()


def _parse(name: str, data: bytes, columns: Sequence[str]) -> tuple[dict[str, str], ...]:
    """CSV bytes to row dicts as written; EvalError on bad text, a missing column or a ragged row."""
    try:
        reader = csv.DictReader(io.StringIO(data.decode("utf-8"), newline=""))
        rows = tuple(dict(r) for r in reader)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise EvalError(f"refused: score file {name} is not readable CSV ({exc})") from None
    missing = [c for c in columns if c not in (reader.fieldnames or [])]
    if missing:
        raise EvalError(f"refused: score file {name} lacks column(s) {', '.join(missing)}")
    for i, r in enumerate(rows, start=1):
        if None in r or any(v is None for v in r.values()):
            raise EvalError(f"refused: score file {name} data row {i} has a field count that differs from the header")
    return rows


def _run_info(raw: bytes) -> dict[str, Any]:
    """The score ``run_info.json`` as a dict; EvalError when it is not a JSON object with a files map."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvalError(f"refused: score run_info.json is not JSON ({exc})") from None
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise EvalError("refused: score run_info.json is not an object with a files map")
    return data


def _check_trial_rows(name: str, rows: Sequence[Mapping[str, str]], trial: str) -> None:
    """Every row with a ``trial_id`` column must belong to the trial (a file copied from another trial is refused)."""
    for i, r in enumerate(rows, start=1):
        if "trial_id" in r and r["trial_id"] != trial:
            raise EvalError(f"refused: score file {name} data row {i} belongs to another trial")


def load_score(score_dir: Path, trial: str) -> ScoreData:
    """Read and check the three score files of one trial against the score ``run_info.json`` (trial id, SHA-256 of
    each file). WHY the hash check: ``run_info.json`` is written last with the hash of every file, so a file edited
    or regenerated afterwards is caught before it is evaluated (same rule as ``inputs.load_stitch``)."""
    d = Path(score_dir)
    raw_info = _read(d / SCORE_RUN_INFO)
    info = _run_info(raw_info)
    if info.get("trial_id") != trial:
        raise EvalError(f"refused: score run_info.json trial_id {info.get('trial_id')!r} differs from the trial "
                        f"{trial}")
    raw = {n: _read(d / n) for n in _SCORE_FILES}
    shas = {n: sha256_bytes(b) for n, b in raw.items()}
    for name in _SCORE_FILES:
        want = (info["files"].get(name) or {}).get("sha256") if isinstance(info["files"].get(name), dict) else None
        if shas[name] != want:
            raise EvalError(f"refused: score file {name} SHA-256 {shas[name]} differs from its run_info.json")
    ranked = _parse(RANKED_FILE, raw[RANKED_FILE], RANKED_COLUMNS)
    b0 = _parse(B0_FILE, raw[B0_FILE], B0_COLUMNS)
    units = _parse(UNITS_FILE, raw[UNITS_FILE], UNITS_COLUMNS)
    _check_trial_rows(RANKED_FILE, ranked, trial)
    _check_trial_rows(B0_FILE, b0, trial)
    return ScoreData(score_dir=d, ranked=ranked, b0=b0, units=units, run_info=info,
                     run_info_sha256=sha256_bytes(raw_info), file_sha256=dict(sorted(shas.items())))


def check_score_against_stitch(score: ScoreData, stitch: StitchData) -> None:
    """The score run must have read exactly the stitch files read here (score run_info ``inputs.stitch``), and every
    variant must rank every stitch path exactly once (SC-04). Pure.

    WHY: the node sets come from ``path_nodes.csv`` and the hop sets from ``ranked_paths.csv``; if the stitcher ran
    again after the score stage, the two would describe different paths.
    """
    recorded = (score.run_info.get("inputs") or {}).get("stitch")
    if not isinstance(recorded, dict) or not recorded:
        raise EvalError("refused: score run_info.json records no inputs.stitch hashes")
    for name, sha in sorted(recorded.items()):
        if stitch.file_sha256.get(name) != sha:
            raise EvalError(f"refused: stitch file {name} differs from the one the score stage read")
    want = sorted(p["path_id"] for p in stitch.paths)
    for variant in PATH_VARIANTS:
        got = sorted(r["path_id"] for r in score.ranked if r["variant"] == variant)
        if got != want:
            raise EvalError(f"refused: score variant {variant} does not rank every stitch path exactly once (SC-04)")


def check_key_against_stitch(key: KeyData | None, stitch: StitchData) -> None:
    """A keyed trial's key must be built from the DB the stitcher read (key ``db_sha256`` = stitch run_info
    ``db.sha256_after``). Pure. WHY: this check opens no DB, so the two recorded hashes are compared instead; a key of
    another DB state would map its hops onto the wrong stitch hops."""
    if key is None:
        return
    db = stitch.run_info.get("db")
    want = db.get("sha256_after") if isinstance(db, Mapping) else None
    if key.data.get("db_sha256") != want:
        raise EvalError("refused: the key's db_sha256 differs from stitch run_info db.sha256_after")


def default_params(score: ScoreData) -> dict[str, float]:
    """{lam, w1, w2, w3} the score run used (its run_info ``parameters``). WHY read, not imported: the sweep's default
    point must be the one that produced ``ranked_paths.csv``, and evaluate must not import score."""
    params = score.run_info.get("parameters")
    out: dict[str, float] = {}
    for name in _PARAM_NAMES:
        value = params.get(name) if isinstance(params, Mapping) else None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise EvalError(f"refused: score run_info.json has no numeric parameters.{name}")
        out[name] = float(value)
    return out
