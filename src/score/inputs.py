"""Score stage inputs: the spec 05_score section 2 files and the SC-01 / SC-02 / SC-03 refusals.

Reads only files of earlier stages under ``out/stitch/<t>/`` and ``out/label/<t>/`` (plus the order table in
``order.py``). SC-03: ``src/score`` never opens a path under ``ground_truth/`` or ``data/`` and opens no database; no
such path is built anywhere in this package.

Freshness (SC-02) is checked three ways, so every byte the scorer reads belongs to one stitch run and one label run:
(a) the label ``run_info.json`` ``stitch_files_sha256`` must equal the current SHA-256 of each stitch file it lists
(the label stage read exactly these stitch outputs); (b) each stitch CSV the scorer reads must have the SHA-256 the
stitch ``run_info.json`` records (``paths.csv`` and ``path_edges.csv`` are not in the label's list); (c) each label
CSV read must have the SHA-256 the label ``run_info.json`` records.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from stitch.outputs import IDENTITY_COLUMNS

from .errors import ScoreError
from .params import ALLOWED_TRIALS, LABEL_OUT_REL, STITCH_OUT_REL

__all__ = ["RUN_INFO", "STITCH_CSV_COLUMNS", "LABEL_CSV_COLUMNS", "ScoreInputs", "check_allowlist", "stitch_dir",
           "label_dir", "read_bytes", "parse_csv", "parse_json", "check_recorded_hashes", "check_label_stitch_hashes",
           "load_inputs"]

RUN_INFO = "run_info.json"

# Spec 2, the columns used from each file; a file lacking one is refused (SC-02), so a missing column can never turn
# into silent empty values. hop_identity.csv: all columns of spec 03 (ST-60..64), the stitcher's own tuple.
STITCH_CSV_COLUMNS: Mapping[str, tuple[str, ...]] = {
    "paths.csv": ("path_id", "hop_ids", "hosts", "n_hops", "isolated", "merged_from", "edge_types"),
    "path_edges.csv": ("path_id", "from_hop_id", "to_hop_id", "link_type", "time_delta_ms", "clock_unreliable"),
    "hops.csv": ("hop_id", "first_utc_corrected", "source_host", "target_host", "protocol", "member_accounts",
                 "best_tier", "candidate_count", "multi_chain_parent", "clock_unreliable"),
    "hop_identity.csv": tuple(IDENTITY_COLUMNS),
}
LABEL_CSV_COLUMNS: Mapping[str, tuple[str, ...]] = {
    "node_labels.csv": ("path_id", "hop_id", "role", "context", "event_uid", "labelled", "rule_ids", "techniques",
                        "max_level_value"),
    "event_labels.csv": ("event_uid", "count_key", "rule_id", "technique", "tactics", "level_value",
                         "event_utc_corrected", "host"),
}

Rows = list[dict[str, str]]


@dataclass
class ScoreInputs:
    """Every input table of one trial (text values as written) and the SHA-256 of each file read."""
    trial_id: str
    paths: Rows = field(default_factory=list)
    path_edges: Rows = field(default_factory=list)
    hops: Rows = field(default_factory=list)
    hop_identity: Rows = field(default_factory=list)
    node_labels: Rows = field(default_factory=list)
    event_labels: Rows = field(default_factory=list)
    stitch_sha256: dict[str, str] = field(default_factory=dict)
    label_sha256: dict[str, str] = field(default_factory=dict)


def check_allowlist(trial_id: str) -> None:
    """SC-01 / decisions 019, 046: refuse a trial outside ``DEVELOPMENT_TRIALS`` before any file is opened or stat-ed,
    so test data can never be read while T9 is built."""
    if trial_id not in ALLOWED_TRIALS:
        raise ScoreError(f"refused: {trial_id!r} is not a development trial; the scorer runs on "
                         f"{', '.join(ALLOWED_TRIALS)} only until T10 (SC-01, decisions 019, 046)")


def stitch_dir(repo: Path, trial_id: str) -> Path:
    """``out/stitch/<trial_id>`` (spec 2)."""
    return Path(repo) / STITCH_OUT_REL / trial_id


def label_dir(repo: Path, trial_id: str) -> Path:
    """``out/label/<trial_id>`` (spec 2)."""
    return Path(repo) / LABEL_OUT_REL / trial_id


def read_bytes(path: Path) -> tuple[bytes, str]:
    """The exact bytes of a file and their SHA-256; ScoreError when the file is missing or unreadable (SC-02)."""
    p = Path(path)
    if not p.is_file():
        raise ScoreError(f"refused: required input missing: {p.parent.name}/{p.name}")
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ScoreError(f"refused: cannot read {p}: {exc}") from exc
    return data, hashlib.sha256(data).hexdigest()


def parse_csv(name: str, data: bytes, required: Sequence[str]) -> Rows:
    """All rows of a CSV as text. Refused when the header lacks a ``required`` column or a row's field count differs
    from the header (SC-02). Pure."""
    try:
        reader = csv.DictReader(io.StringIO(data.decode("utf-8"), newline=""))
        rows = [dict(r) for r in reader]
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ScoreError(f"refused: cannot parse {name}: {exc}") from exc
    missing = [c for c in required if c not in (reader.fieldnames or [])]
    if missing:
        raise ScoreError(f"refused: {name} lacks required column(s): {', '.join(missing)}")
    for i, r in enumerate(rows, start=1):
        if None in r or any(v is None for v in r.values()):
            raise ScoreError(f"refused: {name} data row {i} has a field count that differs from the header")
    return rows


def parse_json(name: str, data: bytes) -> dict[str, Any]:
    """A JSON object; ScoreError otherwise. Pure."""
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ScoreError(f"refused: cannot parse {name}: {exc}") from exc
    if not isinstance(obj, dict):
        raise ScoreError(f"refused: {name} is not a JSON object")
    return obj


def check_recorded_hashes(stage: str, run_info: Mapping[str, Any], current: Mapping[str, str]) -> None:
    """SC-02 (b), (c): each file in ``current`` must have the SHA-256 its stage's ``run_info.json`` ``files`` records.
    WHY: run_info is written last with every file's hash, so a file regenerated or edited afterwards belongs to
    another run and must not be scored. Pure."""
    files = run_info.get("files")
    for name, sha in sorted(current.items()):
        rec = files.get(name) if isinstance(files, Mapping) else None
        want = rec.get("sha256") if isinstance(rec, Mapping) else None
        if not isinstance(want, str) or not want:
            raise ScoreError(f"refused: {stage} run_info.json records no SHA-256 for {name}")
        if want.lower() != sha.lower():
            raise ScoreError(f"refused: {stage} {name} SHA-256 {sha} differs from {stage} run_info.json {want}")


def check_label_stitch_hashes(label_run_info: Mapping[str, Any], current: Mapping[str, str]) -> None:
    """SC-02 (a): the label run's ``stitch_files_sha256`` must equal the current SHA-256 of every stitch file it
    lists. WHY: after a stitch re-run the labels describe other nodes; scoring them would mix two input states. Pure;
    ``current`` maps every listed name to its current hash (missing names were refused when read)."""
    listed = label_run_info.get("stitch_files_sha256")
    if not isinstance(listed, Mapping) or not listed:
        raise ScoreError("refused: label run_info.json lacks stitch_files_sha256")
    for name, want in sorted(listed.items()):
        have = current.get(name)
        if have is None or str(want).lower() != have.lower():
            raise ScoreError(f"refused: label run_info.json stitch_files_sha256[{name}] {want} differs from the "
                             f"current stitch file {have}; re-run the label stage")


def load_inputs(repo: Path, trial_id: str) -> ScoreInputs:
    """Read every spec 2 file of one trial and run every SC-01 / SC-02 refusal. Raises ScoreError; writes nothing.

    Order: allowlist (no file touched before it, SC-01); stitch run_info and CSVs (presence, columns, hash against
    the stitch run_info); label run_info and CSVs (same); every stitch file the label run lists, hashed and compared
    (SC-02 (a))."""
    check_allowlist(trial_id)
    sdir, ldir = stitch_dir(repo, trial_id), label_dir(repo, trial_id)
    inp = ScoreInputs(trial_id=trial_id)
    s_data, inp.stitch_sha256[RUN_INFO] = read_bytes(sdir / RUN_INFO)
    s_info = parse_json(f"stitch/{RUN_INFO}", s_data)
    for name, attr in (("paths.csv", "paths"), ("path_edges.csv", "path_edges"), ("hops.csv", "hops"),
                       ("hop_identity.csv", "hop_identity")):
        data, inp.stitch_sha256[name] = read_bytes(sdir / name)
        setattr(inp, attr, parse_csv(name, data, STITCH_CSV_COLUMNS[name]))
    check_recorded_hashes("stitch", s_info, {n: h for n, h in inp.stitch_sha256.items() if n != RUN_INFO})
    l_data, inp.label_sha256[RUN_INFO] = read_bytes(ldir / RUN_INFO)
    l_info = parse_json(f"label/{RUN_INFO}", l_data)
    for name, attr in (("node_labels.csv", "node_labels"), ("event_labels.csv", "event_labels")):
        data, inp.label_sha256[name] = read_bytes(ldir / name)
        setattr(inp, attr, parse_csv(name, data, LABEL_CSV_COLUMNS[name]))
    check_recorded_hashes("label", l_info, {n: h for n, h in inp.label_sha256.items() if n != RUN_INFO})
    listed = l_info.get("stitch_files_sha256")
    current = dict(inp.stitch_sha256)
    if isinstance(listed, Mapping):
        for name in sorted(listed):
            if Path(str(name)).name != name:        # a plain file name only: never a path outside out/stitch/<t>/
                raise ScoreError(f"refused: label run_info.json stitch_files_sha256 names a path, not a file: {name!r}")
            if name not in current:
                _data, current[name] = read_bytes(sdir / str(name))
    check_label_stitch_hashes(l_info, current)
    inp.stitch_sha256 = dict(sorted(current.items()))
    return inp
