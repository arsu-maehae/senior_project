"""Comparison of a scratch run with the committed ``out/`` (spec 06 DR-03, DR-06, DR-07 as amended by decision 074).

WHY one explicit list (``NORMALISED``) and a chained proof: DR-07 allows normalising only named keys / columns, and
a hash may only be hidden if it is shown to be what it claims to be. Two kinds of value are normalised:

- timestamps (``generated_utc``; gate's ``run_utc``): replaced, nothing to prove;
- provenance hashes of a timestamped ``run_info.json``: accepted only if (1) in the scratch run the value equals the
  SHA-256 of the scratch ``run_info.json`` it names, (2) in the committed ``out/`` it equals the SHA-256 of the
  committed ``run_info.json`` it names, and (3) that ``run_info.json`` pair is itself identical or equal after
  normalising (recursively, so a chain score -> label -> stitch is proved link by link). Otherwise the file differs.

Every other byte must match: JSON is compared as parsed objects with only the named paths replaced; markdown and CSV
are compared as text with only the named column's cells replaced (a CSV line that does not survive a csv round trip
unchanged is not normalised at all). Reading goes through a ``Reader`` callable, so the logic is testable with a
dict; ``disk_comparer`` binds it to two folders.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

__all__ = ["NormRule", "NORMALISED", "PLACEHOLDER", "RUN_INFO", "FileResult", "Replaced", "Reader", "Lister",
           "folder_rel", "rules_for", "normalise_json", "normalise_table", "first_diff", "csv_diff_columns",
           "Comparer", "disk_comparer", "IDENTICAL", "EQUAL_NORMALISED", "EOL_ONLY", "DIFFERS", "MISSING", "NEW",
           "PASSING", "ALLOWED_NEW", "is_match", "ISO_UTC", "is_iso_utc", "COMMITTED", "SCRATCH"]

PLACEHOLDER = "<normalised>"
RUN_INFO = "run_info.json"
COMMITTED, SCRATCH = "committed", "scratch"
IDENTICAL = "identical"
EQUAL_NORMALISED = "equal after normalising"
EOL_ONLY = "differs (line endings only)"
DIFFERS = "differs"
MISSING = "differs (missing in scratch)"
NEW = "new"
# Statuses that count as a match for the final verdict. NEW is a mismatch (ATK-EV-17) unless the (folder, name) is
# in ALLOWED_NEW: a file the committed out/ lacks means the committed copy is incomplete or the chain writes more
# than it documents. Empty: results.md / results.csv are committed now and compare normally.
PASSING = frozenset({IDENTICAL, EQUAL_NORMALISED})
ALLOWED_NEW: frozenset[tuple[str, str]] = frozenset()
_PAIR_OK = PASSING
# ATK-EV-24: a timestamp value is normalised only if both runs wrote an ISO-8601 UTC instant there.
ISO_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z")


def is_iso_utc(value: Any) -> bool:
    """True iff ``value`` is a string holding exactly one ISO-8601 UTC instant (``...T..:..:..[.fff]Z``). Pure."""
    return isinstance(value, str) and ISO_UTC.fullmatch(value) is not None


@dataclass(frozen=True)
class NormRule:
    """One normalised value: in ``file`` of the folder kinds ``kinds``, the JSON value at ``path`` or the table column
    ``column`` (markdown or CSV; the row's ``trial_id`` cell names the trial). ``target`` = the stage whose
    ``run_info.json`` the hash names ("" for a timestamp); ``hex_len`` = digits written (rank.md shows 16)."""
    kinds: tuple[str, ...]
    file: str
    path: tuple[str, ...] = ()
    column: str = ""
    target: str = ""
    hex_len: int = 64

    @property
    def label(self) -> str:
        """Readable name for the report: the dotted JSON path or ``column <name>``."""
        return ".".join(self.path) if self.path else f"column {self.column}"


_TIMED = ("stitch", "label", "score", "evaluate", "evaluate_dev")
# Decision 074: the one list of normalised values (spec DR-03 as amended). Nothing else is ever normalised.
NORMALISED: tuple[NormRule, ...] = (
    NormRule(_TIMED, RUN_INFO, path=("generated_utc",)),
    NormRule(("gate",), RUN_INFO, path=("run_utc",)),
    NormRule(("label",), RUN_INFO, path=("stitch_files_sha256", RUN_INFO), target="stitch"),
    NormRule(("score",), RUN_INFO, path=("inputs", "label", RUN_INFO), target="label"),
    NormRule(("score",), RUN_INFO, path=("inputs", "stitch", RUN_INFO), target="stitch"),
    NormRule(("evaluate",), RUN_INFO, path=("inputs", "stitch_run_info_sha256"), target="stitch"),
    NormRule(("evaluate",), RUN_INFO, path=("inputs", "stitch_files", RUN_INFO), target="stitch"),
    NormRule(("evaluate_dev",), "rank.md", column="score_run_info_sha256", target="score", hex_len=16),
    NormRule(("evaluate_dev",), "label_recall.md", column="label_run_info_sha256", target="label"),
    NormRule(("evaluate",), "label_recall.csv", column="label_run_sha256", target="label"),
)


@dataclass(frozen=True)
class Replaced:
    """One replaced value: the rule, the old value and the trial whose ``run_info.json`` it names."""
    rule: NormRule
    value: Any
    trial: str


@dataclass
class FileResult:
    """The comparison of one file: ``status``, ``detail`` (first differing line or the failed proof) and, per rule
    label, how many values were replaced and how many of those differed between the two runs."""
    kind: str
    folder: str
    name: str
    status: str
    detail: str = ""
    substitutions: dict[str, int] = field(default_factory=dict)
    differing: dict[str, int] = field(default_factory=dict)


# (side, repo-relative POSIX path) -> bytes or None; (side, folder) -> file names in it.
Reader = Callable[[str, str], "bytes | None"]
Lister = Callable[[str, str], "set[str]"]


def is_match(r: "FileResult", allowed_new: frozenset[tuple[str, str]] = ALLOWED_NEW) -> bool:
    """The final verdict for one file: identical or equal after normalising; NEW only if explicitly allowed. Pure."""
    return r.status in PASSING or (r.status == NEW and (r.folder, r.name) in allowed_new)


def folder_rel(kind: str, trial: str) -> str:
    """Repo-relative folder of a kind: ``out/<stage>/<trial>``, or ``out/evaluate/development``. Pure."""
    return "out/evaluate/development" if kind == "evaluate_dev" else f"out/{kind}/{trial}"


def rules_for(kind: str, name: str, rules: Sequence[NormRule] = NORMALISED) -> list[NormRule]:
    """The rules that apply to file ``name`` in a folder of kind ``kind``. Pure."""
    return [r for r in rules if kind in r.kinds and r.file == name]


# ---------------------------------------------------------------- normalisers (pure)

def _replace_path(obj: Any, path: Sequence[str]) -> list[Any]:
    """Replace the value at ``path`` in ``obj`` (in place) by PLACEHOLDER; return the old value(s)."""
    if not path or not isinstance(obj, dict) or path[0] not in obj:
        return []
    if len(path) > 1:
        return _replace_path(obj[path[0]], path[1:])
    old = obj[path[0]]
    obj[path[0]] = PLACEHOLDER
    return [old]


def normalise_json(text: str, rules: Sequence[NormRule], trial: str) -> tuple[Any, list[Replaced]]:
    """(parsed object with the rule paths replaced, replaced values). Pure."""
    obj = json.loads(text)
    out: list[Replaced] = []
    for r in rules:
        out += [Replaced(r, v, trial) for v in _replace_path(obj, r.path)]
    return obj, out


def _md_cells(line: str) -> list[str]:
    """The cells of a markdown table row ``| a | b |``."""
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _csv_cells(line: str) -> list[str] | None:
    """The cells of one CSV line, or None if writing them back does not give the same line (then the line cannot
    be normalised without touching other bytes)."""
    cells = next(csv.reader([line]), [])
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow(cells)
    return cells if buf.getvalue() == line else None


def _csv_line(cells: Sequence[str]) -> str:
    """One CSV line from cells (no terminator)."""
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow(cells)
    return buf.getvalue()


def normalise_table(text: str, rules: Sequence[NormRule], is_csv: bool) -> tuple[str, list[Replaced], list[str]]:
    """Replace the cells of each rule's column (markdown: in every table whose header names it; CSV: the file's
    header) and return (text, replaced values, problems). Rows need a ``trial_id`` cell, which names the trial of
    the hash. Only those cells change; every other byte is kept (DR-07). Pure."""
    lines = text.split("\n")
    out: list[Replaced] = []
    problems: list[str] = []
    for r in (r for r in rules if r.column):
        col = tid = None
        in_table = False
        for i, line in enumerate(lines):
            if is_csv:
                if line == "":
                    continue
                cells = _csv_cells(line)
                if cells is None:
                    problems.append(f"line {i + 1} does not survive a csv round trip")
                    continue
            else:
                if not line.startswith("|"):
                    col = tid = None
                    in_table = False
                    continue
                cells = _md_cells(line)
            if not in_table:                       # the first row of a table (or of the CSV) is its header
                in_table = True
                col = cells.index(r.column) if r.column in cells else None
                tid = cells.index("trial_id") if "trial_id" in cells else None
                if col is not None and tid is None:
                    problems.append(f"table naming {r.column} has no trial_id column")
                continue
            if col is None or tid is None or col >= len(cells):
                continue
            if not is_csv and set(line.replace("|", "").strip()) <= {"-", ":", " "}:
                continue
            out.append(Replaced(r, cells[col], cells[tid]))
            cells[col] = PLACEHOLDER
            lines[i] = _csv_line(cells) if is_csv else "| " + " | ".join(cells) + " |"
    return "\n".join(lines), out, problems


def first_diff(a: str, b: str, width: int = 160) -> str:
    """``line N: committed=... scratch=...`` for the first differing line of two texts. Pure."""
    la, lb = a.split("\n"), b.split("\n")
    for i in range(max(len(la), len(lb))):
        x = la[i] if i < len(la) else "<end of file>"
        y = lb[i] if i < len(lb) else "<end of file>"
        if x != y:
            return f"line {i + 1}: committed={x[:width]!r} scratch={y[:width]!r}"
    return "texts differ only in a trailing newline"


def csv_diff_columns(a: str, b: str) -> str:
    """Diagnosis only: ``; differing columns: [...] in N rows`` when both CSVs share header and row count. Pure."""
    ra, rb = list(csv.reader(io.StringIO(a))), list(csv.reader(io.StringIO(b)))
    if not ra or not rb or ra[0] != rb[0] or len(ra) != len(rb):
        return "; header or row count differs"
    cols: set[str] = set()
    rows = 0
    for x, y in zip(ra[1:], rb[1:]):
        bad = {ra[0][i] for i in range(min(len(x), len(y))) if x[i] != y[i]}
        if bad or len(x) != len(y):
            rows += 1
            cols |= bad
    return f"; differing columns: {sorted(cols)} in {rows} of {len(ra) - 1} rows"


def _counts(ra: Sequence[Replaced], rb: Sequence[Replaced]) -> tuple[dict[str, int], dict[str, int]]:
    """(label -> values replaced in the scratch file, label -> values that differ between the two runs)."""
    subs: dict[str, int] = {}
    diff: dict[str, int] = {}
    for x in rb:
        subs[x.rule.label] = subs.get(x.rule.label, 0) + 1
    for x, y in zip(ra, rb):
        if x.value != y.value:
            diff[y.rule.label] = diff.get(y.rule.label, 0) + 1
    for k in subs:
        diff.setdefault(k, 0)
    return subs, diff


# ---------------------------------------------------------------- comparison with the chained proof

@dataclass
class Comparer:
    """Compares files of the committed and the scratch tree through ``read`` / ``names``; the memo makes the
    recursive proof check each ``run_info.json`` pair once (and is local to one comparison run)."""
    read: Reader
    names: Lister
    memo: dict[tuple[str, str, str], FileResult] = field(default_factory=dict)

    def _proof(self, side: str, x: Replaced) -> list[str]:
        """Steps (1)/(2) and (3) for one replaced hash on one side; problems or []."""
        rel = f"{folder_rel(x.rule.target, x.trial)}/{RUN_INFO}"
        data = self.read(side, rel)
        if data is None:
            return [f"{side} {x.rule.label}: {rel} is missing"]
        want = hashlib.sha256(data).hexdigest()[: x.rule.hex_len]
        out = [] if x.value == want else [f"{side} {x.rule.label}={str(x.value)[:16]}... is not the SHA-256 of {rel}"]
        pair = self.compare_file(x.rule.target, x.trial, RUN_INFO)
        if pair.status not in _PAIR_OK:
            out.append(f"{rel} pair is {pair.status}")
        return out

    def compare_file(self, kind: str, trial: str, name: str) -> FileResult:
        """DR-03 / DR-07 / decision 074 for one file (memoised)."""
        key = (kind, trial, name)
        if key not in self.memo:
            self.memo[key] = self._compare(kind, trial, name)
        return self.memo[key]

    def _compare(self, kind: str, trial: str, name: str) -> FileResult:
        """The comparison itself; see the module docstring."""
        folder = folder_rel(kind, trial)
        res = FileResult(kind, folder, name, IDENTICAL)
        real, new = self.read(COMMITTED, f"{folder}/{name}"), self.read(SCRATCH, f"{folder}/{name}")
        if new is None:
            res.status = MISSING
            return res
        if real is None:
            res.status = NEW
            return res
        if real == new:
            return res
        a, b = real.decode("utf-8", errors="replace"), new.decode("utf-8", errors="replace")
        if a.replace("\r\n", "\n") == b.replace("\r\n", "\n"):
            res.status = EOL_ONLY
            return res
        rules = rules_for(kind, name)
        if not rules:
            res.status, res.detail = DIFFERS, first_diff(a, b)
            if name.endswith(".csv"):
                res.detail += csv_diff_columns(a, b)
            return res
        problems: list[str] = []
        if name.endswith(".json"):
            oa, ra = normalise_json(a, rules, trial)
            ob, rb = normalise_json(b, rules, trial)
            # ATK-EV-24: compare the serialised objects, so 1, 1.0 and true stay different (== would equate them).
            ta, tb = json.dumps(oa, indent=1, sort_keys=True), json.dumps(ob, indent=1, sort_keys=True)
            equal = ta == tb
        else:
            is_csv = name.endswith(".csv")
            ta, ra, pa = normalise_table(a, rules, is_csv)
            tb, rb, pb = normalise_table(b, rules, is_csv)
            problems += [f"committed: {x}" for x in pa] + [f"scratch: {x}" for x in pb]
            equal = ta == tb
        res.substitutions, res.differing = _counts(ra, rb)
        if not equal:
            res.status, res.detail = DIFFERS, first_diff(ta, tb)
            return res
        for side, reps in ((COMMITTED, ra), (SCRATCH, rb)):
            for x in reps:
                if not x.rule.target and not is_iso_utc(x.value):
                    problems.append(f"{side} {x.rule.label}={str(x.value)[:40]!r} is not an ISO-8601 UTC instant")
                elif x.rule.target:
                    problems += self._proof(side, x)
        if problems:
            res.status = DIFFERS
            res.detail = "proof failed: " + "; ".join(problems[:4]) + (" ..." if len(problems) > 4 else "")
            return res
        res.status = EQUAL_NORMALISED
        return res

    def compare_folder(self, kind: str, trial: str) -> list[FileResult]:
        """Every file of one folder in both directions (DR-06): missing in scratch = differs, only in scratch =
        new."""
        folder = folder_rel(kind, trial)
        names = self.names(COMMITTED, folder) | self.names(SCRATCH, folder)
        return [self.compare_file(kind, trial, n) for n in sorted(names)]


def disk_comparer(committed_root: Path, scratch_root: Path) -> Comparer:
    """A Comparer reading the committed repo and the scratch repo from disk (read-only)."""
    roots = {COMMITTED: Path(committed_root), SCRATCH: Path(scratch_root)}

    def read(side: str, rel: str) -> bytes | None:
        path = roots[side] / rel
        return path.read_bytes() if path.is_file() else None

    def names(side: str, folder: str) -> set[str]:
        path = roots[side] / folder
        return {f.name for f in path.iterdir() if f.is_file()} if path.is_dir() else set()

    return Comparer(read, names)
