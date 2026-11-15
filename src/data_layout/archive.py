"""One-time archive of the old S04/S07 copies (preset V1) and `retire-failed` (failed x10_v2 attempts).

Why this exists (decision 034 with the 052 amendment; attacker review x10_archive_tooling 2026-11-15): the x10_v2
reruns reuse the trial ids s04_t01 ... s07_t10. The old per-trial files must leave the normal paths with proof that
nothing was lost, and a failed v2 attempt must leave them so that its trial number can be reused (decision 052 item 6).
One generic core serves both presets; a preset is an `ArchiveSpec`.

Order of one run (every step is resumable; every refusal happens before the first write):
  plan      read-only: select, classify, hash, run every pre-check, refuse or return a plan
  journal   out/<label>/journal.json: every file with source path, sha256 and size, plus the manifest lines. Written
            (and fsync'd) BEFORE the first copy, so a crash after a delete never loses the hashes
  copy      layout.copy_one per file (temp name, sha check, never overwrites), fsync, re-hash the destination
  manifest  data/manifest_<label>.csv (archive rows, `<label>/` prefix), then data/manifest.csv rewritten at byte level
            with exactly the moved lines removed, under data/manifest.csv.lock
  delete    os.unlink per journal-listed file whose destination was re-hashed equal; rmdir only when empty
  report    out/<label>/archive_report.json and .md, one line appended to run_log.jsonl

Layout of the archive (label L): data/raw/L/..., data/processed/L/<name>, data/processed/L/jsonl/<id>/,
out/normalise/L/<id>/, out/clock_offset/L/<id>/; failed attempts also out/ingest/L/<id>/ and
out/x10_validate_v2/L/<id>.json. out/ingest/x10/<id>/ and out/x10_validate/<id>.json of V1 ids STAY (plan); the batch
treats ids listed in out/archive_x10_v1/archive_report.json as "archived, skipped" (batch.archived_trial_ids).

Safety rules: dry run by default (the CLI needs --execute); a refusal leaves the tree byte-identical; never rmtree;
symlinks and junctions are refused on both sides; a PermissionError on delete is retried a few times and then left for
the next run (exit code non-zero unless expected == verified); `data/incoming` is only ever read.
"""
from __future__ import annotations

import csv
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from data_layout import batch
from data_layout import layout as L

CRLF = b"\r\n"
BOM = b"\xef\xbb\xbf"
V1_LABEL = batch.ARCHIVE_V1_LABEL
V1_PREFIX = "x10/"
V2_PREFIX = batch.V2_SOURCE_PREFIX
FAILED_SCENARIOS = ("s01", "s04", "s05", "s07")      # decision 034/052: the scenarios rerun in x10_v2
SCENARIO_RE = re.compile(r"s0[1-9]")
TRIAL_RE = re.compile(r"t(?:0[1-9]|10)")             # t00 is never selectable (decision 034: t00 stays)
LABEL_RE = re.compile(r"[a-z0-9_]+")
TRIAL_ID_LIKE_RE = re.compile(r"s0\d(?:q)?_t\d\d")
JOURNAL_VERSION = 1
UNLINK_ATTEMPTS = 5                                  # bounded retry for a locked file (antivirus, open handle)
UNLINK_PAUSE_S = 0.2
REPARSE_POINT = 0x400                                # FILE_ATTRIBUTE_REPARSE_POINT: NTFS junctions and symlinks
KINDS = ("raw", "db", "derived", "jsonl", "normalise", "clock_offset", "ingest", "validate", "sidecar", "other")
# out/<stage>/ folders that are handled by name (moved, or deliberately left in place); every other stage that holds
# a path named after a selected id is a live per-trial output and blocks the run.
OWN_OUT_STAGES = frozenset({"normalise", "clock_offset", "ingest", "x10_validate", "x10_validate_v2"})
ARCHIVE_OUT_PREFIXES = ("archive_", "x10_v2_failed_")


class ArchiveError(Exception):
    """Every refusal and every incomplete run; a refusal leaves the whole tree untouched."""


# ============================================================================ specs and results

@dataclass(frozen=True)
class ArchiveSpec:
    """What one archive run selects. ``tolerant`` presets (failed attempts) list missing/extra items in the report
    instead of refusing, because a failed ingest may stop half-way (review item 4)."""
    label: str
    scenarios: tuple[str, ...]
    trials: tuple[str, ...]
    source_prefix: str
    tolerant: bool = False
    attempt: Optional[int] = None

    def __post_init__(self) -> None:
        """Reject anything unsafe at construction (review item 10); a spec that selects t00 cannot exist."""
        object.__setattr__(self, "scenarios", tuple(self.scenarios))
        object.__setattr__(self, "trials", tuple(self.trials))
        if not (isinstance(self.label, str) and LABEL_RE.fullmatch(self.label)):
            raise ValueError(f"unsafe archive label: {self.label!r}")
        if TRIAL_ID_LIKE_RE.match(self.label) or batch.TRIAL_RE.match(self.label):
            raise ValueError(f"archive label looks like a trial id: {self.label!r}")
        if not self.scenarios or not self.trials:
            raise ValueError("an archive spec needs at least one scenario and one trial")
        for s in self.scenarios:
            if not (isinstance(s, str) and SCENARIO_RE.fullmatch(s)):
                raise ValueError(f"bad scenario {s!r}")
        for t in self.trials:
            if not (isinstance(t, str) and TRIAL_RE.fullmatch(t)):
                raise ValueError(f"bad trial {t!r}: only t01..t10 can be archived (t00 never)")
        if not (self.source_prefix.endswith("/") and ".." not in self.source_prefix):
            raise ValueError(f"source_prefix must end with '/' and contain no '..': {self.source_prefix!r}")


V1 = ArchiveSpec(V1_LABEL, ("s04", "s07"), tuple(f"t{n:02d}" for n in range(1, 11)), V1_PREFIX)


def failed_attempt_spec(scenario: str, trial: str, attempt: int) -> ArchiveSpec:
    """Spec for retiring ONE failed x10_v2 attempt (decision 052 item 6).

    WHY strict arguments: this tool deletes files, so the scenario must be one of the rerun scenarios, the trial
    t01..t10 and the attempt a positive int; `..`, separators and look-alikes (t1, t010) are ValueErrors."""
    if not (isinstance(scenario, str) and scenario in FAILED_SCENARIOS):
        raise ValueError(f"scenario must be one of {FAILED_SCENARIOS}, got {scenario!r}")
    if not (isinstance(trial, str) and TRIAL_RE.fullmatch(trial)):
        raise ValueError(f"trial must be t01..t10, got {trial!r}")
    if not (type(attempt) is int and attempt > 0):
        raise ValueError(f"attempt must be a positive int, got {attempt!r}")
    return ArchiveSpec(f"x10_v2_failed_{scenario}_attempt_{attempt}", (scenario,), (trial,), V2_PREFIX,
                       tolerant=True, attempt=attempt)


@dataclass(frozen=True)
class FileEntry:
    """One per-trial file: where it is, where it goes, and the bytes it must have in both places."""
    path: str        # repo-relative posix source path
    dest: str        # repo-relative posix destination
    sha256: str
    size: int
    kind: str        # one of KINDS
    trial_id: str


@dataclass(frozen=True)
class ArchivePlan:
    """Result of `plan_archive`. ``mode``: fresh (no journal yet), resume (journal, work left), done (complete)."""
    spec: ArchiveSpec
    mode: str
    entries: tuple[FileEntry, ...]
    trials: tuple[str, ...]
    manifest_header: str
    manifest_lines: tuple[str, ...]     # moved manifest lines, unique, in manifest order
    missing: tuple[str, ...]            # tolerant presets: expected items that are absent
    extra: tuple[str, ...]              # tolerant presets: items moved that no record names
    orphans: tuple[str, ...]            # `.part` files seen: never moved, never counted
    states: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class ArchiveResult:
    """``ok`` is exactly ``expected == verified`` (and expected > 0 for verify)."""
    ok: bool
    expected: int
    verified: int
    status: str
    problems: tuple[str, ...] = ()
    noop: bool = False


def _checkpoint(name: str) -> None:
    """Test hook, called between the steps of `execute_archive` (looked up at call time; a no-op in production)."""


# ============================================================================ small filesystem helpers

def is_link(path: Path) -> bool:
    """True for a symlink or an NTFS junction (any reparse point).

    WHY: Python 3.11 has no os.path.isjunction, and a junction would send a copy or a delete outside the repo."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & REPARSE_POINT)


def link_error(path: Path) -> ArchiveError:
    return ArchiveError(f"{path} is a symlink or junction (reparse point); refusing to follow it")


def walk_files(root: Path) -> list[Path]:
    """Every file under ``root`` (sorted); raises on any link, the root included; [] when ``root`` is absent."""
    if not os.path.lexists(root):
        return []
    if is_link(root):
        raise link_error(root)
    if root.is_file():
        return [root]
    out: list[Path] = []
    stack = [root]
    while stack:
        folder = stack.pop()
        with os.scandir(folder) as it:
            children = sorted(it, key=lambda e: e.name)
        for e in children:
            p = Path(e.path)
            if is_link(p):
                raise link_error(p)
            if e.is_dir(follow_symlinks=False):
                stack.append(p)
            else:
                out.append(p)
    return sorted(out)


def rel_posix(roots: batch.Roots, path: Path) -> str:
    return path.relative_to(roots.repo).as_posix()


def fsync_file(path: Path) -> None:
    """Flush a finished file to disk (opened r+b because Windows needs write access for fsync)."""
    with open(path, "r+b") as f:
        os.fsync(f.fileno())


def write_atomic(path: Path, data: bytes) -> None:
    """Write via a temp file in the same folder, fsync, then os.replace; the temp file never survives."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def append_line(path: Path, line: str) -> None:
    """Append one line to a log (never overwrites earlier lines) and fsync."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "ab") as f:
        f.write(line.encode("utf-8") + b"\n")
        f.flush()
        os.fsync(f.fileno())


def check_dest_chain(roots: batch.Roots, rel: str) -> None:
    """Refuse a destination whose folders below data/raw, data/processed or out/<stage> are links or escape the repo.

    WHY: a junction as ``data/raw/<label>`` would make the copy land outside the repo (review item 8). The two
    top components (data/raw, out/ingest, ...) are the repo's own folders and are not inspected."""
    parts = rel.split("/")
    if ".." in parts or rel.startswith("/") or ":" in parts[0]:
        raise ArchiveError(f"unsafe destination path: {rel}")
    for n in range(3, len(parts)):
        folder = roots.repo.joinpath(*parts[:n])
        if is_link(folder):
            raise link_error(folder)


def dest_for(label: str, rel: str) -> str:
    """Source path -> archive path (plan table of Task 3). Raises for a path outside the known per-trial roots."""
    p = rel.split("/")
    if p[:2] == ["data", "raw"]:
        return "/".join(["data", "raw", label] + p[2:])
    if p[:3] == ["data", "processed", "jsonl"]:
        return "/".join(["data", "processed", label, "jsonl"] + p[3:])
    if p[:2] == ["data", "processed"]:
        return "/".join(["data", "processed", label] + p[2:])
    if p[:3] == ["out", "ingest", "x10_v2"]:
        return "/".join(["out", "ingest", label] + p[3:])
    if p[:2] == ["out", "x10_validate_v2"]:
        return "/".join(["out", "x10_validate_v2", label] + p[2:])
    if p[0] == "out" and len(p) > 2 and p[1] in ("normalise", "clock_offset"):
        return "/".join(["out", p[1], label] + p[2:])
    raise ArchiveError(f"no archive destination defined for {rel}")


def prune_top(rel: str) -> Optional[str]:
    """The per-trial folder of a source path; emptied folders are removed up to and including it, never above."""
    p = rel.split("/")
    if p[:2] == ["data", "raw"] and len(p) > 4:
        return "/".join(p[:4])
    if p[:3] == ["data", "processed", "jsonl"] and len(p) > 4:
        return "/".join(p[:4])
    if p[0] == "out" and len(p) > 3 and p[1] in ("normalise", "clock_offset"):
        return "/".join(p[:3])
    if p[:3] == ["out", "ingest", "x10_v2"] and len(p) > 4:
        return "/".join(p[:4])
    return None


# ============================================================================ manifest bytes

@dataclass(frozen=True)
class ManifestBytes:
    """A manifest split at byte level on CRLF: the header line and the data lines, with their parsed fields."""
    header: bytes
    lines: tuple[bytes, ...]
    rows: tuple[dict[str, str], ...]


def check_manifest_bytes(data: bytes, name: str) -> None:
    """Refuse a manifest the byte-exact rewrite could damage: BOM, empty, not CRLF-terminated, bare LF inside.

    WHY: the split/rejoin is on b"\\r\\n"; anything else would silently change the lines we promise to keep."""
    if data.startswith(BOM):
        raise ArchiveError(f"{name}: starts with a BOM; refusing to rewrite it")
    if data == b"":
        raise ArchiveError(f"{name}: is empty (no header); refusing to rewrite it")
    if not data.endswith(CRLF):
        raise ArchiveError(f"{name}: does not end in a CRLF newline (last row unterminated or LF-only endings)")
    if b"\n" in data.replace(CRLF, b""):
        raise ArchiveError(f"{name}: mixes bare LF with CRLF line endings; refusing to rewrite it")


def parse_manifest(data: bytes, name: str) -> ManifestBytes:
    """Split ``data`` into header and lines and parse every line; a line that does not parse is a refusal."""
    check_manifest_bytes(data, name)
    parts = data.split(CRLF)[:-1]
    try:
        header = next(csv.reader([parts[0].decode("utf-8")]))
    except (UnicodeDecodeError, StopIteration, csv.Error) as exc:
        raise ArchiveError(f"{name}: unreadable header: {exc}") from None
    need = {"path", "sha256", "scenario", "trial", "source_path"}
    if not need <= set(header):
        raise ArchiveError(f"{name}: header lacks columns {sorted(need - set(header))}")
    rows: list[dict[str, str]] = []
    for n, line in enumerate(parts[1:], start=2):
        try:
            fields = next(csv.reader([line.decode("utf-8")]), [])
        except (UnicodeDecodeError, csv.Error) as exc:
            raise ArchiveError(f"{name}: line {n} unreadable: {exc}") from None
        if len(fields) != len(header):
            raise ArchiveError(f"{name}: line {n} has {len(fields)} fields, header has {len(header)}")
        rows.append(dict(zip(header, fields)))
    return ManifestBytes(parts[0], tuple(parts[1:]), tuple(rows))


def load_manifest(roots: batch.Roots) -> Optional[ManifestBytes]:
    """data/manifest.csv parsed, or None when the file does not exist."""
    if not roots.manifest.exists():
        return None
    return parse_manifest(roots.manifest.read_bytes(), roots.manifest.name)


def archive_manifest_path(roots: batch.Roots, spec: ArchiveSpec) -> Path:
    """data/manifest_<label>.csv: a name pattern different from manifest.csv, so no consumer reads it as the manifest."""
    return roots.manifest.with_name(f"manifest_{spec.label}.csv")


def prefixed(label: str, line: bytes) -> bytes:
    """An archive manifest line: the original bytes with the path prefixed `<label>/` (nothing else changes)."""
    if line.startswith(b'"'):
        raise ArchiveError(f"manifest line starts with a quoted path; cannot prefix it safely: {line[:60]!r}")
    return f"{label}/".encode("utf-8") + line


# ============================================================================ selection and classification

def trial_candidates(mb: ManifestBytes, scenario: str, trial: str) -> list[int]:
    """Row indexes that look like they belong to this trial: scenario+trial columns OR the path under `s/t/`.

    WHY OR: the later AND check then reports a row that only half matches instead of silently skipping it."""
    prefix = f"{scenario}/{trial}/"
    return [i for i, r in enumerate(mb.rows)
            if (r["scenario"].casefold(), r["trial"].casefold()) == (scenario, trial)
            or r["path"].casefold().startswith(prefix)]


def row_is_own(spec: ArchiveSpec, row: dict[str, str], scenario: str, trial: str) -> bool:
    """AND of scenario, trial, path prefix `s/t/` and source_path prefix with a trailing slash (review item 10)."""
    return ((row["scenario"].casefold(), row["trial"].casefold()) == (scenario, trial)
            and row["path"].casefold().startswith(f"{scenario}/{trial}/")
            and row["source_path"].startswith(spec.source_prefix))


def scan_trial_paths(roots: batch.Roots, spec: ArchiveSpec, scenario: str,
                     trial: str) -> tuple[list[tuple[str, Path]], list[Path]]:
    """Every per-trial file on the normal paths as (kind, path), plus the `.part` orphans (never evidence).

    Looks at: data/raw/<s>/<t>/, data/processed/<id>.* (direct children only), data/processed/jsonl/<id>/,
    out/normalise/<id>/, out/clock_offset/<id>/ and, for failed attempts, out/ingest/x10_v2/<id>/ and
    out/x10_validate_v2/<id>*. Any link is a refusal."""
    tid = f"{scenario}_{trial}"
    files: list[tuple[str, Path]] = []
    orphans: list[Path] = []

    def add(kind: str, root: Path) -> None:
        for p in walk_files(root):
            if p.name.endswith(".part"):
                orphans.append(p)
            else:
                files.append((kind, p))

    add("raw", roots.raw / scenario / trial)
    if roots.processed.is_dir():
        for child in sorted(roots.processed.iterdir()):
            cf = child.name.casefold()
            if cf == tid or cf.startswith(tid + "."):
                add(processed_kind(cf, tid), child)
    add("jsonl", roots.processed / "jsonl" / tid)
    add("normalise", roots.normalise_out / tid)
    add("clock_offset", roots.repo / "out" / "clock_offset" / tid)
    if spec.tolerant:
        add("ingest", roots.repo / "out" / "ingest" / "x10_v2" / tid)
        vdir = roots.repo / "out" / "x10_validate_v2"
        if vdir.is_dir():
            for child in sorted(vdir.iterdir()):
                cf = child.name.casefold()
                if child.is_file() and (cf == tid or cf.startswith(tid + ".")):
                    add("validate", child)
    return files, orphans


def processed_kind(name_cf: str, tid: str) -> str:
    """Classify a data/processed/<id>.* name: the DB, a clock csv bound to it, a SQLite sidecar, or unknown."""
    if name_cf == f"{tid}.sqlite3":
        return "db"
    if name_cf in (f"{tid}.clock_offsets.csv", f"{tid}.clock_changes.csv"):
        return "derived"
    if name_cf in (f"{tid}.sqlite3-wal", f"{tid}.sqlite3-shm"):
        return "sidecar"
    return "other"


def live_outputs(roots: batch.Roots, spec: ArchiveSpec, tid: str) -> list[str]:
    """Paths named after the id in any out/<stage>/ that this tool does not manage (gate, stitch, evaluate, ...).

    WHY: such an output would silently describe a trial whose data just left (review items 1 and 3)."""
    out_dir = roots.repo / "out"
    found: list[str] = []
    if not out_dir.is_dir():
        return found
    for stage in sorted(out_dir.iterdir()):
        if not stage.is_dir() or stage.name in OWN_OUT_STAGES or stage.name == spec.label \
                or stage.name.startswith(ARCHIVE_OUT_PREFIXES):
            continue
        with os.scandir(stage) as it:
            for child in sorted(it, key=lambda e: e.name):
                cf = child.name.casefold()
                if cf == tid or cf.startswith(tid + "."):
                    found.append(f"out/{stage.name}/{child.name}")
    return found


def hash_file(path: Path) -> tuple[str, int]:
    return L.sha256_file(path), path.stat().st_size


# ---------- ingest.json (the record of what the ingest copied) ----------

def load_ingest(roots: batch.Roots, spec: ArchiveSpec, tid: str) -> Optional[dict[str, Any]]:
    """The ingest report of this id: out/ingest/x10/<id> for V1, out/ingest/x10_v2/<id> for a failed attempt."""
    source = "x10_v2" if spec.tolerant else "x10"
    return batch.read_json(roots.repo / "out" / "ingest" / source / tid / "ingest.json")


def recorded_files(ingest: dict[str, Any]) -> dict[str, dict[str, str]]:
    """dest_path -> {sha256, source_path} for ``files_copied`` and ``clock_files.copied``.

    A destination listed twice with different hashes is a refusal: the record contradicts itself."""
    out: dict[str, dict[str, str]] = {}
    listed = list(ingest.get("files_copied") or []) + list((ingest.get("clock_files") or {}).get("copied") or [])
    for f in listed:
        if not isinstance(f, dict) or not f.get("dest_path") or not f.get("sha256"):
            raise ArchiveError(f"ingest.json: malformed file entry {f!r}")
        rec = {"sha256": f["sha256"], "source_path": f.get("source_path") or ""}
        if out.setdefault(f["dest_path"], rec)["sha256"] != rec["sha256"]:
            raise ArchiveError(f"ingest.json lists {f['dest_path']} twice with different sha256")
    return out


def validator_has_fail(roots: batch.Roots, tid: str) -> bool:
    """True when out/x10_validate_v2/<id>.json has a criterion with status FAIL."""
    result = batch.read_json(roots.repo / "out" / "x10_validate_v2" / f"{tid}.json")
    crit = result.get("criteria") if isinstance(result, dict) else None
    values = crit.values() if isinstance(crit, dict) else (crit or [])
    return any(isinstance(c, dict) and c.get("status") == "FAIL" for c in values)


def test_set_lists(roots: batch.Roots, tid: str) -> bool:
    """True when docs/lab/test_set.csv names this id (an accepted trial is never retired; decision 052 item 4)."""
    path = roots.repo / "docs" / "lab" / "test_set.csv"
    if not path.exists():
        return False
    with open(path, newline="", encoding="utf-8-sig") as f:
        return any(r and r[0].strip() == tid for r in csv.reader(f))


def trial_windows_lists(roots: batch.Roots, tid: str) -> bool:
    """True when data/trial_windows.csv has a row for this id (first column); a live row blocks a retire."""
    path = roots.repo / "data" / "trial_windows.csv"
    if not path.exists():
        return False
    with open(path, newline="", encoding="utf-8-sig") as f:
        return any(r and r[0].strip() == tid for r in csv.reader(f))


# ---------- proof that a trial is the failed attempt ----------

def incoming_names(scenario: str, trial: str) -> tuple[str, str]:
    """s04, t01 -> (S04, trial_01): the folder names under data/incoming/x10_v2[_failed]/."""
    return scenario.upper(), f"trial_{trial[1:]}"


def hash_folder(folder: Path) -> dict[str, str]:
    """sha256 of every file under ``folder`` keyed by posix path relative to it (read-only)."""
    return {p.relative_to(folder).as_posix(): L.sha256_file(p) for p in walk_files(folder)}


def check_attempt_proof(roots: batch.Roots, spec: ArchiveSpec, scenario: str, trial: str,
                        records: list[tuple[str, str, str]], raw_shas: dict[str, str]) -> None:
    """Prove that the ingested copies are the failed attempt kept by the owner (review item 1).

    ``records`` = (dest path, sha256, source_path) from ingest.json and the manifest rows; ``raw_shas`` = every raw
    file on disk. The sha256 of each record must equal the attempt-folder file it names, and every raw file must
    equal SOME file of the attempt folder (also when no record names it). Refuses when the incoming trial folder
    still holds the same files: the owner has not moved it yet, so it is not a finished failure."""
    scen, folder = incoming_names(scenario, trial)
    attempt_dir = roots.incoming / "x10_v2_failed" / scen / f"attempt_{spec.attempt}"
    if not attempt_dir.is_dir():
        raise ArchiveError(f"{scenario}_{trial}: attempt folder {attempt_dir.relative_to(roots.repo).as_posix()} "
                           "does not exist (the owner moves the failed folder there by hand first)")
    attempt = hash_folder(attempt_dir)
    base = f"{V2_PREFIX}{scen}/{folder}/"
    for dest, sha, source in records:
        if not source.startswith(base):
            raise ArchiveError(f"{dest}: source_path {source!r} is not under {base}")
        if attempt.get(source[len(base):]) != sha:
            raise ArchiveError(f"{dest}: sha256 differs from the attempt folder file {source[len(base):]!r} "
                               "(or the file is missing there); this is not the failed attempt")
    known = set(attempt.values())
    for rel, sha in sorted(raw_shas.items()):
        if sha not in known:
            raise ArchiveError(f"data/raw/{rel} matches no file of the attempt folder; this is not the failed attempt")
    current = roots.incoming / "x10_v2" / scen / folder
    if current.is_dir():
        same = [r for r, p in ((q.relative_to(current).as_posix(), q) for q in walk_files(current))
                if r in attempt and p.stat().st_size == (attempt_dir / r).stat().st_size
                and L.sha256_file(p) == attempt[r]]
        if same:
            raise ArchiveError(f"data/incoming/x10_v2/{scen}/{folder} still holds the same files as the attempt "
                               f"folder (e.g. {same[0]}); move the failed folder first")


def check_failed_gate(roots: batch.Roots, scenario: str, trial: str, ingest: dict[str, Any]) -> None:
    """The conditions of review item 1 that do not need hashing, in one place (all refusals)."""
    tid = f"{scenario}_{trial}"
    if ingest.get("source") != "x10_v2":
        raise ArchiveError(f"{tid}: ingest.json source is {ingest.get('source')!r}, must be exactly 'x10_v2'")
    if test_set_lists(roots, tid):
        raise ArchiveError(f"{tid}: listed in docs/lab/test_set.csv (accepted trial); never retired")
    if ingest.get("status") != "error" and not validator_has_fail(roots, tid):
        raise ArchiveError(f"{tid}: neither an ingest status 'error' nor a validator FAIL; not a failed trial")
    if trial_windows_lists(roots, tid):
        raise ArchiveError(f"{tid}: data/trial_windows.csv still has a row for it (live path)")


# ============================================================================ per-trial inventory

@dataclass(frozen=True)
class TrialInventory:
    tid: str
    entries: tuple[FileEntry, ...]
    lines: tuple[bytes, ...]
    missing: tuple[str, ...]
    extra: tuple[str, ...]
    orphans: tuple[str, ...]


def select_rows(spec: ArchiveSpec, mb: ManifestBytes, scenario: str, trial: str,
                found: bool) -> Optional[list[int]]:
    """Indexes of this trial's own rows; None when the trial only has v2 rows and no old files (not ours).

    Refuses (a) "archive too late": v2 rows next to old files, (b) any other row of the trial that is not selected
    (e.g. a failed-attempt retire meeting old x10/ rows)."""
    tid = f"{scenario}_{trial}"
    cand = trial_candidates(mb, scenario, trial)
    own = [i for i in cand if row_is_own(spec, mb.rows[i], scenario, trial)]
    foreign = [i for i in cand if i not in set(own)]
    v2 = [i for i in foreign if mb.rows[i]["source_path"].startswith(V2_PREFIX)] \
        if spec.source_prefix != V2_PREFIX else []
    others = [i for i in foreign if i not in set(v2)]
    if others:
        r = mb.rows[others[0]]
        raise ArchiveError(f"{tid}: manifest row {r['path']!r} (source_path {r['source_path']!r}) does not match "
                           f"the selection (prefix {spec.source_prefix!r}); refusing to guess")
    if v2:
        if own or found:
            raise ArchiveError(f"{tid}: archive too late: x10_v2 rows are already in data/manifest.csv, so the "
                               "normal paths may hold the new trial; nothing was moved")
        return None
    return own


def duplicate_conflicts(mb: ManifestBytes, own: list[int]) -> None:
    """Rows with the same path are all moved when identical; a different sha256 for one path is a refusal."""
    seen: dict[str, str] = {}
    for i in own:
        r = mb.rows[i]
        if seen.setdefault(r["path"], r["sha256"]) != r["sha256"]:
            raise ArchiveError(f"manifest has two rows for {r['path']} with different sha256")


def classify_raw(roots: batch.Roots, spec: ArchiveSpec, tid: str, found: list[tuple[str, Path]],
                 row_sha: dict[str, str], recorded: dict[str, dict[str, str]],
                 shas: dict[Path, str]) -> tuple[list[str], list[str], dict[str, str]]:
    """Check each raw file against manifest row and ingest record; returns (missing, extra, raw_shas by raw-rel).

    Strict (V1): every raw file must be named by a manifest row, row sha = ingest sha = file sha, and every named
    file must exist. Tolerant: unnamed files are `extra`, absent named files `missing`; a sha that contradicts a
    record is a refusal in both."""
    missing: list[str] = []
    extra: list[str] = []
    raw_shas: dict[str, str] = {}
    present: set[str] = set()
    for kind, p in found:
        if kind != "raw":
            continue
        rel = p.relative_to(roots.raw).as_posix()
        sha = shas[p]
        raw_shas[rel] = sha
        present.add(rel)
        if rel not in row_sha and rel not in recorded:
            if not spec.tolerant:
                raise ArchiveError(f"{tid}: unclassified raw file {rel}: no manifest row and no ingest record")
            extra.append(rel_posix(roots, p))
            continue
        if rel in row_sha and row_sha[rel] != sha:
            raise ArchiveError(f"{tid}: {rel} sha256 differs from its data/manifest.csv row")
        if rel in recorded and recorded[rel]["sha256"] != sha:
            raise ArchiveError(f"{tid}: {rel} sha256 differs from ingest.json files_copied")
        if not spec.tolerant and (rel not in row_sha or rel not in recorded) and not rel.endswith("/clock.txt"):
            raise ArchiveError(f"{tid}: {rel} is not in both the manifest and ingest.json (v1 set not proven)")
    for rel in sorted((set(row_sha) | set(recorded)) - present):
        if not spec.tolerant:
            raise ArchiveError(f"{tid}: listed raw file is missing: data/raw/{rel}")
        missing.append(f"data/raw/{rel}")
    return missing, extra, raw_shas


def check_listed_paths(scenario: str, trial: str, names: Sequence[str], what: str) -> None:
    """Every manifest path and ingest dest_path must lie under `s/t/` (a path elsewhere is never ours)."""
    for n in names:
        if not n.casefold().startswith(f"{scenario}/{trial}/"):
            raise ArchiveError(f"{scenario}_{trial}: {what} path {n!r} is outside {scenario}/{trial}/")


def inventory_trial(roots: batch.Roots, spec: ArchiveSpec, mb: Optional[ManifestBytes], scenario: str,
                    trial: str) -> Optional[TrialInventory]:
    """Select, classify, hash and gate one trial. None = the trial is not present (skipped); else an inventory.

    Raises ArchiveError for every refusal; reads only, writes nothing."""
    tid = f"{scenario}_{trial}"
    mb = mb or ManifestBytes(b"", (), ())
    files, orphan_paths = scan_trial_paths(roots, spec, scenario, trial)
    own = select_rows(spec, mb, scenario, trial, bool(files))
    if own is None or (not own and not files):
        return None
    if not spec.tolerant and (roots.repo / "out" / "ingest" / "x10_v2" / tid).exists():
        raise ArchiveError(f"{tid}: archive too late: out/ingest/x10_v2/{tid} exists; nothing was moved")
    live = live_outputs(roots, spec, tid)
    if live:
        raise ArchiveError(f"{tid}: live per-trial output outside this tool's scope: {live[0]} "
                           f"({len(live)} found); remove or archive it first")
    ingest = load_ingest(roots, spec, tid)
    if ingest is None:
        raise ArchiveError(f"{tid}: ingest.json is missing or unreadable "
                           f"(out/ingest/{'x10_v2' if spec.tolerant else 'x10'}/{tid}/ingest.json)")
    if not spec.tolerant and ingest.get("source") == "x10_v2":
        raise ArchiveError(f"{tid}: ingest.json says source x10_v2, not the old copy")
    if spec.tolerant:
        check_failed_gate(roots, scenario, trial, ingest)
    duplicate_conflicts(mb, own)
    row_sha = {mb.rows[i]["path"]: mb.rows[i]["sha256"] for i in own}
    recorded = recorded_files(ingest)
    check_listed_paths(scenario, trial, list(row_sha), "manifest")
    check_listed_paths(scenario, trial, list(recorded), "ingest.json")
    if not spec.tolerant and not own:
        raise ArchiveError(f"{tid}: no manifest row with source_path under {spec.source_prefix!r}")
    shas = {p: L.sha256_file(p) for _, p in files}
    missing, extra, raw_shas = classify_raw(roots, spec, tid, files, row_sha, recorded, shas)
    if spec.tolerant:
        records = [(d, r["sha256"], r["source_path"]) for d, r in recorded.items()]
        records += [(mb.rows[i]["path"], mb.rows[i]["sha256"], mb.rows[i]["source_path"]) for i in own]
        check_attempt_proof(roots, spec, scenario, trial, records, raw_shas)
    kinds = {k for k, _ in files}
    for kind, p in files:
        if kind == "sidecar" and not spec.tolerant:
            raise ArchiveError(f"{tid}: SQLite sidecar {p.name} beside the DB (-wal/-shm): the DB may be in use")
        if kind == "other" and not spec.tolerant:
            raise ArchiveError(f"{tid}: unclassified file {rel_posix(roots, p)}")
        if kind in ("sidecar", "other"):
            extra.append(rel_posix(roots, p))
    if "db" not in kinds:
        db = f"data/processed/{tid}.sqlite3"
        if not spec.tolerant:
            raise ArchiveError(f"{tid}: DB {db} is missing (the clock csvs are bound to it; they move together)")
        if ingest.get("status") == "ok":
            missing.append(db)
    entries = tuple(sorted(
        (FileEntry(rel_posix(roots, p), dest_for(spec.label, rel_posix(roots, p)), shas[p], p.stat().st_size, k, tid)
         for k, p in files), key=lambda e: (KINDS.index(e.kind), e.path)))
    seen: set[bytes] = set()
    lines = tuple(ln for ln in (mb.lines[i] for i in own) if not (ln in seen or seen.add(ln)))
    return TrialInventory(tid, entries, lines, tuple(sorted(missing)), tuple(sorted(set(extra))),
                          tuple(sorted(rel_posix(roots, p) for p in orphan_paths)))


# ============================================================================ planning

def lock_free(roots: batch.Roots) -> None:
    """Refuse while data/manifest.csv.lock exists (shared with the batch ingest); never removes it."""
    try:
        batch.check_lock_free(roots.manifest)
    except batch.IngestError as exc:
        raise ArchiveError(str(exc)) from None


def journal_path(roots: batch.Roots, spec: ArchiveSpec) -> Path:
    return roots.repo / "out" / spec.label / "journal.json"


def load_journal(path: Path) -> Optional[dict[str, Any]]:
    """The journal as a dict; None when absent. A journal that exists but does not parse is a refusal."""
    if not os.path.lexists(path):
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ArchiveError(f"journal {path} is unreadable: {exc}") from None
    if not isinstance(data, dict) or data.get("version") != JOURNAL_VERSION or "entries" not in data:
        raise ArchiveError(f"journal {path} has an unknown format")
    return data


def entries_from_journal(journal: dict[str, Any]) -> tuple[FileEntry, ...]:
    return tuple(FileEntry(e["path"], e["dest"], e["sha256"], int(e["size"]), e["kind"], e["trial_id"])
                 for e in journal["entries"])


def journal_document(plan: ArchivePlan) -> dict[str, Any]:
    """The journal body: every source with its hash and size, the manifest lines, and the report lists."""
    return {"version": JOURNAL_VERSION, "label": plan.spec.label, "created_utc": batch.utc_now(),
            "spec": {"scenarios": list(plan.spec.scenarios), "trials": list(plan.spec.trials),
                     "source_prefix": plan.spec.source_prefix, "tolerant": plan.spec.tolerant,
                     "attempt": plan.spec.attempt},
            "trials": list(plan.trials),
            "entries": [{"path": e.path, "dest": e.dest, "sha256": e.sha256, "size": e.size, "kind": e.kind,
                         "trial_id": e.trial_id} for e in plan.entries],
            "manifest": {"header": plan.manifest_header, "lines": list(plan.manifest_lines)},
            "missing": list(plan.missing), "extra": list(plan.extra), "orphans": list(plan.orphans)}


def entry_state(roots: batch.Roots, e: FileEntry) -> str:
    """pending (source only), copied (both, equal to the journal) or moved (destination only, equal to the journal).

    Raises when a present file differs from the journal hash or when both are gone: a resume then deletes nothing."""
    src, dest = roots.repo / e.path, roots.repo / e.dest
    src_here, dest_here = os.path.lexists(src), os.path.lexists(dest)
    if dest_here:
        if is_link(dest) or not dest.is_file():
            raise ArchiveError(f"destination {e.dest} is not a regular file")
        if L.sha256_file(dest) != e.sha256:
            raise ArchiveError(f"destination {e.dest} differs from the journal sha256; nothing more is deleted")
    if src_here:
        if is_link(src):
            raise link_error(src)
        if L.sha256_file(src) != e.sha256:
            raise ArchiveError(f"source {e.path} changed since the journal was written; refusing")
    if src_here and dest_here:
        return "copied"
    if dest_here:
        return "moved"
    if src_here:
        return "pending"
    raise ArchiveError(f"{e.path}: source and destination are both gone")


def plan_from_journal(roots: batch.Roots, spec: ArchiveSpec, journal: dict[str, Any]) -> ArchivePlan:
    """A plan rebuilt from the journal (resume or done); every file is checked against the journal hashes."""
    if journal.get("label") != spec.label:
        raise ArchiveError(f"journal label {journal.get('label')!r} does not match {spec.label!r}")
    entries = entries_from_journal(journal)
    man = journal.get("manifest") or {}
    report = batch.read_json(roots.repo / "out" / spec.label / "archive_report.json")
    complete = (isinstance(report, dict) and report.get("status") == "ok"
                and report.get("expected") == report.get("verified") == len(entries))
    base = dict(spec=spec, entries=entries, trials=tuple(journal.get("trials", ())),
                manifest_header=man.get("header", ""), manifest_lines=tuple(man.get("lines", ())),
                missing=tuple(journal.get("missing", ())), extra=tuple(journal.get("extra", ())),
                orphans=tuple(journal.get("orphans", ())))
    if complete:
        bad = verify_entries(roots, entries)[1]
        if bad:
            raise ArchiveError(f"the report says ok but the archive is damaged ({bad[0]}); run archive-verify")
        return ArchivePlan(mode="done", **base)
    lock_free(roots)
    counts: dict[str, int] = {}
    for e in entries:
        st = entry_state(roots, e)
        counts[st] = counts.get(st, 0) + 1
    return ArchivePlan(mode="resume", states=tuple(sorted(counts.items())), **base)


def check_destinations(roots: batch.Roots, entries: Sequence[FileEntry]) -> None:
    """No two files share a destination; no destination folder is a link; an existing destination must be identical."""
    seen: dict[str, str] = {}
    for e in entries:
        key = e.dest.casefold()
        if key in seen:
            raise ArchiveError(f"two sources map to one destination: {seen[key]} and {e.path} -> {e.dest}")
        seen[key] = e.path
        check_dest_chain(roots, e.dest)
        dest = roots.repo / e.dest
        if os.path.lexists(dest):
            if is_link(dest) or not dest.is_file():
                raise ArchiveError(f"destination {e.dest} exists and is not a regular file")
            if L.sha256_file(dest) != e.sha256:
                raise ArchiveError(f"destination {e.dest} exists with a different sha256; refusing to touch it")


def plan_archive(roots: batch.Roots, spec: ArchiveSpec) -> ArchivePlan:
    """Select, classify, hash and run every pre-check; return a plan or raise ArchiveError. Writes NOTHING.

    WHY pure: the dry run and the real run share this function, so what the dry run prints is what the real run
    would do; and a refusal here leaves the tree byte-identical (not even an empty folder is created)."""
    if is_link(roots.repo / "out" / spec.label):
        raise link_error(roots.repo / "out" / spec.label)
    journal = load_journal(journal_path(roots, spec))
    if journal is not None:
        return plan_from_journal(roots, spec, journal)
    if os.path.lexists(archive_manifest_path(roots, spec)):
        raise ArchiveError(f"{archive_manifest_path(roots, spec).name} exists but there is no journal; "
                           "unknown state, refusing")
    lock_free(roots)
    mb = load_manifest(roots)
    invs = [inv for s in spec.scenarios for t in spec.trials
            if (inv := inventory_trial(roots, spec, mb, s, t)) is not None]
    if not invs:
        raise ArchiveError(f"nothing to archive: no trial of {spec.scenarios} x {spec.trials} found")
    entries = tuple(e for inv in invs for e in inv.entries)
    check_destinations(roots, entries)
    lines: list[bytes] = []
    for inv in invs:
        lines += [ln for ln in inv.lines if ln not in lines]
    header = mb.header.decode("utf-8") if mb else ""
    orphans = {o for inv in invs for o in inv.orphans}
    orphans |= {e.dest + ".part" for e in entries if os.path.lexists(roots.repo / (e.dest + ".part"))}
    return ArchivePlan(spec, "fresh", entries, tuple(inv.tid for inv in invs), header,
                       tuple(ln.decode("utf-8") for ln in lines),
                       tuple(m for inv in invs for m in inv.missing), tuple(x for inv in invs for x in inv.extra),
                       tuple(sorted(orphans)))


# ============================================================================ execution

def copy_entry(roots: batch.Roots, e: FileEntry) -> str:
    """Make sure the destination holds the journal bytes; returns "copied" (source still there) or "moved".

    Copies with layout.copy_one (temp name, sha check, no overwrite), fsyncs, and re-hashes the destination. A copy
    whose hash differs from the journal is removed again and raises, so nothing is ever deleted after it."""
    src, dest = roots.repo / e.path, roots.repo / e.dest
    state = entry_state(roots, e) if os.path.lexists(dest) else None
    if state is not None:
        fsync_file(dest)
        return "copied" if state == "copied" else "moved"
    if not os.path.lexists(src):
        raise ArchiveError(f"{e.path}: source is gone and the destination does not exist")
    check_dest_chain(roots, e.dest)
    try:
        got = L.copy_one(src, dest)
    except (OSError, ValueError) as exc:
        raise ArchiveError(f"copy of {e.path} failed: {exc}") from None
    if got == e.sha256:
        fsync_file(dest)
        got = L.sha256_file(dest)             # re-hash the published, flushed destination
    if got != e.sha256:
        os.unlink(dest)
        raise ArchiveError(f"{e.path}: the copy does not match the journal sha256 (source changed?); copy removed")
    return "copied"


def write_archive_manifest(roots: batch.Roots, spec: ArchiveSpec, header: bytes, lines: Sequence[bytes]) -> int:
    """data/manifest_<label>.csv with the moved rows (CRLF, `<label>/` prefix); idempotent, atomic, fsync'd.

    Rows already present are not added again (a crash between this step and the main rewrite must not duplicate
    them); a row with the same path but different bytes is a refusal."""
    path = archive_manifest_path(roots, spec)
    new = [prefixed(spec.label, ln) for ln in lines]
    if path.exists():
        data = path.read_bytes()
        have = parse_manifest(data, path.name)
        if have.header != header:
            raise ArchiveError(f"{path.name}: header differs from data/manifest.csv")
        by_path = {r["path"]: ln for r, ln in zip(have.rows, have.lines)}
        add = []
        for ln in new:
            key = next(csv.reader([ln.decode("utf-8")]))[0]
            if key in by_path and by_path[key] != ln:
                raise ArchiveError(f"{path.name}: has a different row for {key}")
            if key not in by_path:
                add.append(ln)
        if not add:
            return 0
        write_atomic(path, data + b"".join(ln + CRLF for ln in add))
        return len(add)
    write_atomic(path, header + CRLF + b"".join(ln + CRLF for ln in new))
    return len(new)


def rewrite_main_manifest(roots: batch.Roots, moved: set[bytes]) -> int:
    """Remove exactly the moved lines from data/manifest.csv at byte level; returns how many lines were removed.

    Held under data/manifest.csv.lock. Just before os.replace the on-disk bytes must still equal the bytes read at
    the start, otherwise a batch appended meanwhile and the rewrite is refused (the appended bytes survive)."""
    manifest = roots.manifest
    try:
        with batch.manifest_lock(manifest):
            before = manifest.read_bytes()
            mb = parse_manifest(before, manifest.name)
            kept = [ln for ln in mb.lines if ln not in moved]
            removed = len(mb.lines) - len(kept)
            if removed == 0:
                return 0
            new = mb.header + CRLF + b"".join(ln + CRLF for ln in kept)
            if parse_manifest(new, manifest.name).lines != tuple(kept):
                raise ArchiveError("internal check failed: rewritten manifest lines differ from the kept lines")
            tmp = manifest.with_name(f"{manifest.name}.{os.getpid()}.archive.tmp")
            try:
                with open(tmp, "wb") as f:
                    f.write(new)
                    f.flush()
                    os.fsync(f.fileno())
                _checkpoint("before_main_manifest_replace")
                if manifest.read_bytes() != before:
                    raise ArchiveError("data/manifest.csv changed while it was being rewritten (a batch appended?); "
                                       "nothing was replaced, run again")
                os.replace(tmp, manifest)
            except PermissionError as exc:
                raise ArchiveError(f"cannot replace data/manifest.csv (open elsewhere?): {exc}") from None
            finally:
                if os.path.lexists(tmp):
                    os.unlink(tmp)
            return removed
    except batch.IngestError as exc:
        raise ArchiveError(str(exc)) from None


def unlink_with_retry(path: Path) -> Optional[str]:
    """os.unlink with a bounded retry on PermissionError; None on success, else the reason (left for the next run)."""
    last = ""
    for _ in range(UNLINK_ATTEMPTS):
        try:
            os.unlink(path)
            return None
        except FileNotFoundError:
            return None
        except PermissionError as exc:
            last = f"PermissionError: {exc}"
            time.sleep(UNLINK_PAUSE_S)
        except OSError as exc:
            return f"{type(exc).__name__}: {exc}"
    return f"{last} (after {UNLINK_ATTEMPTS} attempts)"


def prune_empty_dirs(roots: batch.Roots, e: FileEntry) -> None:
    """rmdir the emptied folders above a moved file, up to its per-trial folder; a non-empty folder stays."""
    top = prune_top(e.path)
    if top is None:
        return
    folder = (roots.repo / e.path).parent
    stop = roots.repo / top
    while folder == stop or stop in folder.parents:
        try:
            os.rmdir(folder)
        except OSError:
            return
        folder = folder.parent


def delete_sources(roots: batch.Roots, entries: Sequence[FileEntry], actions: dict[str, str]) -> list[str]:
    """Unlink each source whose destination was re-hashed equal (action "copied"); never rmtree, never unlisted files."""
    problems: list[str] = []
    for e in entries:
        if actions.get(e.path) != "copied":
            continue
        why = unlink_with_retry(roots.repo / e.path)
        if why is None:
            actions[e.path] = "moved"
        else:
            actions[e.path] = "locked"
            problems.append(f"{e.path}: {why}")
    for e in entries:
        if actions.get(e.path) == "moved":
            prune_empty_dirs(roots, e)
    return problems


def report_document(plan: ArchivePlan, actions: dict[str, str], status: str, verified: int,
                    problems: Sequence[str]) -> dict[str, Any]:
    """archive_report.json: every path with sha256, size and action, plus the counts the exit code is based on."""
    return {"label": plan.spec.label, "status": status, "generated_utc": batch.utc_now(),
            "expected": len(plan.entries), "verified": verified, "trials": sorted(plan.trials),
            "manifest_rows": len(plan.manifest_lines),
            "files": [{"path": e.path, "dest": e.dest, "sha256": e.sha256, "size": e.size, "kind": e.kind,
                       "action": actions.get(e.path, "pending")} for e in plan.entries],
            "missing": list(plan.missing), "extra": list(plan.extra), "orphans": list(plan.orphans),
            "problems": list(problems)}


def render_report_markdown(rep: dict[str, Any]) -> str:
    """A short human summary of the report (counts per kind and every missing/extra/orphan/problem item)."""
    kinds: dict[str, int] = {}
    for f in rep["files"]:
        kinds[f["kind"]] = kinds.get(f["kind"], 0) + 1
    lines = [f"# Archive report: {rep['label']}", "", f"- status: {rep['status']}",
             f"- expected: {rep['expected']}, verified: {rep['verified']}",
             f"- trials ({len(rep['trials'])}): {', '.join(rep['trials'])}",
             f"- manifest rows moved: {rep['manifest_rows']}",
             "- files by kind: " + ", ".join(f"{k} {n}" for k, n in sorted(kinds.items()))]
    for title, key in (("Missing (expected, absent)", "missing"), ("Extra (moved, named by no record)", "extra"),
                       ("Orphans (.part, not moved)", "orphans"), ("Problems", "problems")):
        if rep[key]:
            lines += ["", f"## {title}", ""] + [f"- {x}" for x in rep[key]]
    return "\n".join(lines) + "\n"


def append_run_log(roots: batch.Roots, spec: ArchiveSpec, entry: dict[str, Any]) -> None:
    """One JSON line per run that did work, appended (the report is overwritten, the log never is)."""
    append_line(roots.repo / "out" / spec.label / "run_log.jsonl", json.dumps(entry, sort_keys=True))


def execute_archive(roots: batch.Roots, plan: ArchivePlan) -> ArchiveResult:
    """Run the plan: journal, copy, manifests, delete, report. Resumable; raises ArchiveError unless complete.

    A plan in mode "done" is a no-op that writes nothing. A crash at any point leaves every source either intact
    or, once its destination was re-hashed against the journal, deletable on the next run."""
    spec, n = plan.spec, len(plan.entries)
    if plan.mode == "done":
        return ArchiveResult(True, n, n, "ok", (), noop=True)
    lock_free(roots)
    started = batch.utc_now()
    jpath = journal_path(roots, spec)
    if plan.mode == "fresh":
        if os.path.lexists(jpath):
            raise ArchiveError("a journal appeared after the plan was made; run again")
        write_atomic(jpath, (json.dumps(journal_document(plan), indent=1) + "\n").encode("utf-8"))
    actions: dict[str, str] = {}
    log: dict[str, Any] = {"started_utc": started, "mode": plan.mode, "label": spec.label, "expected": n}
    try:
        for e in plan.entries:
            actions[e.path] = copy_entry(roots, e)
        _checkpoint("after_copy")
        header = plan.manifest_header.encode("utf-8")
        lines = [ln.encode("utf-8") for ln in plan.manifest_lines]
        if lines:
            write_archive_manifest(roots, spec, header, lines)
        _checkpoint("after_archive_manifest")
        if lines:
            rewrite_main_manifest(roots, set(lines))
        _checkpoint("after_main_manifest")
    except ArchiveError as exc:
        append_run_log(roots, spec, {**log, "finished_utc": batch.utc_now(), "status": "error", "error": str(exc)})
        raise
    _checkpoint("before_delete")
    problems = delete_sources(roots, plan.entries, actions)
    verified = sum(1 for a in actions.values() if a == "moved")
    status = "ok" if verified == n else "incomplete"
    rep = report_document(plan, actions, status, verified, problems)
    out = roots.repo / "out" / spec.label
    write_atomic(out / "archive_report.json", (json.dumps(rep, indent=1) + "\n").encode("utf-8"))
    write_atomic(out / "archive_report.md", render_report_markdown(rep).encode("utf-8"))
    append_run_log(roots, spec, {**log, "finished_utc": batch.utc_now(), "status": status, "verified": verified,
                                 "problems": problems})
    if status != "ok":
        raise ArchiveError(f"incomplete: {verified} of {n} files verified and moved; see {out.name}/archive_report.json "
                           f"(run again after the problem is fixed): {problems[:3]}")
    return ArchiveResult(True, n, verified, status, ())


# ============================================================================ verify

def verify_entries(roots: batch.Roots, entries: Sequence[FileEntry],
                   reference: Optional[Callable[[FileEntry], Optional[str]]] = None) -> tuple[int, list[str]]:
    """(verified, problems): a destination counts when it is a regular file whose sha256 equals the journal.

    ``reference`` may return a problem text for an entry whose hash contradicts another record (V1 raw files vs the
    original ingest.json). Looks at the archive side only."""
    verified, problems = 0, []
    for e in entries:
        dest = roots.repo / e.dest
        if not os.path.lexists(dest) or is_link(dest) or not dest.is_file():
            problems.append(f"{e.dest}: missing or not a regular file")
        elif L.sha256_file(dest) != e.sha256:
            problems.append(f"{e.dest}: sha256 differs from the journal")
        elif (why := reference(e) if reference else None):
            problems.append(f"{e.dest}: {why}")
        else:
            verified += 1
    return verified, problems


def v1_reference(roots: batch.Roots, spec: ArchiveSpec) -> Callable[[FileEntry], Optional[str]]:
    """Raw entries of a V1 archive are also compared with the ORIGINAL out/ingest/x10/<id>/ingest.json sha256."""
    cache: dict[str, Optional[dict[str, dict[str, str]]]] = {}

    def check(e: FileEntry) -> Optional[str]:
        if e.kind != "raw":
            return None
        if e.trial_id not in cache:
            try:
                ing = load_ingest(roots, spec, e.trial_id)
                cache[e.trial_id] = recorded_files(ing) if ing is not None else None
            except ArchiveError:
                cache[e.trial_id] = None
        rec = cache[e.trial_id]
        if rec is None:
            return f"original out/ingest/x10/{e.trial_id}/ingest.json is missing or unreadable"
        want = rec.get(e.path[len("data/raw/"):])
        if want is not None and want["sha256"] != e.sha256:
            return "sha256 differs from the original ingest.json"
        return None
    return check


def verify_archive(roots: batch.Roots, spec: ArchiveSpec) -> ArchiveResult:
    """Read-only check of the ARCHIVE side: every journal entry's destination re-hashed, the archive manifest present.

    WHY archive side only: after the v2 ingest the normal paths hold other bytes under the same names. An empty or
    half archive (no journal, a missing file or manifest) is never ok; ok means expected == verified > 0."""
    try:
        journal = load_journal(journal_path(roots, spec))
    except ArchiveError as exc:
        return ArchiveResult(False, 0, 0, "journal unreadable", (str(exc),))
    if journal is None:
        return ArchiveResult(False, 0, 0, "no archive", (f"journal out/{spec.label}/journal.json is missing",))
    entries = entries_from_journal(journal)
    verified, problems = verify_entries(roots, entries, None if spec.tolerant else v1_reference(roots, spec))
    lines = (journal.get("manifest") or {}).get("lines") or []
    if lines:
        path = archive_manifest_path(roots, spec)
        try:
            have = set(parse_manifest(path.read_bytes(), path.name).lines) if path.exists() else set()
        except ArchiveError as exc:
            have = set()
            problems.append(str(exc))
        if not path.exists():
            problems.append(f"archive manifest {path.name} is missing")
        elif not all(prefixed(spec.label, ln.encode("utf-8")) in have for ln in lines):
            problems.append(f"archive manifest {path.name} lacks rows of the journal")
    ok = bool(entries) and verified == len(entries) and not problems
    return ArchiveResult(ok, len(entries), verified, "ok" if ok else "not ok", tuple(problems))


# ============================================================================ command line

def describe_plan(plan: ArchivePlan) -> list[str]:
    """What a run would do (or has done), for the dry run and the start of --execute; ASCII only."""
    spec = plan.spec
    kinds: dict[str, int] = {}
    for e in plan.entries:
        kinds[e.kind] = kinds.get(e.kind, 0) + 1
    size = sum(e.size for e in plan.entries)
    lines = [f"archive {spec.label}: mode {plan.mode}",
             f"trials ({len(plan.trials)}): {', '.join(plan.trials)}",
             f"files: {len(plan.entries)} ({size / (1 << 20):.1f} MiB) by kind: "
             + ", ".join(f"{k} {n}" for k, n in sorted(kinds.items())),
             f"manifest rows to move: {len(plan.manifest_lines)} -> data/manifest_{spec.label}.csv"]
    if plan.states:
        lines.append("resume state: " + ", ".join(f"{k} {n}" for k, n in plan.states))
    if plan.mode == "done":
        lines.append("already complete and verified: nothing to do")
    for title, items in (("missing", plan.missing), ("extra", plan.extra), ("orphans (.part, not moved)", plan.orphans)):
        if items:
            lines.append(f"{title}: {len(items)}" + "".join(f"\n  {x}" for x in items[:10]))
    return lines


def run_spec(repo: Path, spec: ArchiveSpec, execute: bool) -> int:
    """CLI core: dry run by default; exit 0 only when the plan is clean (dry run) or expected == verified (execute)."""
    roots = batch.Roots.from_repo(repo)
    try:
        plan = plan_archive(roots, spec)
    except ArchiveError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        print("nothing was written")
        return 1
    print("\n".join(describe_plan(plan)))
    if not execute:
        print("dry run: nothing was written (add --execute to move the files)")
        return 0
    try:
        res = execute_archive(roots, plan)
    except ArchiveError as exc:
        print(f"not complete: {exc}", file=sys.stderr)
        return 1
    print(f"{'no-op' if res.noop else 'done'}: expected {res.expected}, verified {res.verified}, status {res.status}")
    return 0 if res.ok and res.expected == res.verified else 1


def run_verify(repo: Path, spec: ArchiveSpec) -> int:
    """CLI core for archive-verify: exit 0 only when expected == verified and expected > 0."""
    res = verify_archive(batch.Roots.from_repo(repo), spec)
    print(f"verify {spec.label}: expected {res.expected}, verified {res.verified}, {'OK' if res.ok else 'NOT OK'}")
    for p in res.problems[:20]:
        print(f"  problem: {p}")
    return 0 if res.ok and res.expected > 0 and res.expected == res.verified else 1
