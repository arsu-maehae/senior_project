"""Rule files and their manifest: load, validate, pin (spec 04_label sections 3.3-3.5, LB-04, LB-05, LB-07, LB-10,
LB-13; decisions 056, 057).

WHY these checks before any event is read: the rule list is locked (056). A run must use exactly the files of
``rules/manifest.csv``, each with the SHA-256 the manifest pins, and every rule must lie inside the matcher's
subset. Anything else is refused, so a label can always be traced to one pinned rule file.

Hashes are taken over LF-normalised bytes (LB-13): a CRLF checkout of the same file hashes the same. Rule files are
read only with ``yaml.safe_load`` (057). ``build_manifest_rows`` recomputes the manifest from the files and the
locked table ``params.RULE_TABLE``; the run refuses a manifest that differs from it, and the same function wrote
the committed ``manifest.csv`` (``python -m label.rules --write-manifest``).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from stitch.outputs import csv_text

from .errors import LabelError
from .matcher import Detection, compile_detection
from .params import (LEVEL_VALUE, LICENSE_DRL, LICENSE_OWN, MANIFEST_COLUMNS, MANIFEST_FILE, OWN_RULE_LEVEL,
                     RULE_TABLE, RULES_DIR, SIGMA_COMMIT, SOURCE_OWN, RuleEntry)

__all__ = ["LogSource", "LOGSOURCES", "Rule", "RuleSet", "lf_bytes", "lf_sha256", "technique_tags", "tactic_tags",
           "parse_logsource", "parse_rule", "manifest_row", "build_manifest_rows", "manifest_text",
           "parse_manifest_text", "check_rule_files", "load_rules", "main"]

_TECH = re.compile(r"^t\d{4}(\.\d{3})?$")
_TACTIC = re.compile(r"^[a-z]+(-[a-z]+)*$")
_ALLOWED_LOGSOURCE_KEYS = frozenset({"product", "category", "service", "definition"})
_REQUIRED_KEYS = ("title", "id", "logsource", "detection", "level", "tags")
_REFUSED_KEYS = ("correlation", "filter")          # Sigma correlation / filter meta-rules (LB-02)


# ---------------------------------------------------------------- logsource (LB-04)

@dataclass(frozen=True)
class LogSource:
    """Where a rule applies: (channel, event id or None for every event of the channel)."""
    name: str
    targets: tuple[tuple[str, int | None], ...]

    def applies(self, channel: str, event_id: int) -> bool:
        """True when an event of this channel and id is in the rule's logsource."""
        return any(channel == ch and (eid is None or eid == event_id) for ch, eid in self.targets)

    def process_creation_4688(self, channel: str, event_id: int) -> bool:
        """True for a ``process_creation`` rule on Security 4688, which uses the 4688 field names (LB-04)."""
        return self.name == "category:process_creation" and channel == "Security" and event_id == 4688


# LB-04: the only logsources the labeller understands.
LOGSOURCES: Mapping[str, tuple[tuple[str, int | None], ...]] = {
    "category:process_access": (("Sysmon", 10),),
    "category:process_creation": (("Sysmon", 1), ("Security", 4688)),
    "category:network_connection": (("Sysmon", 3),),
    "category:ps_module": (("PowerShell", 4103),),
    "service:security": (("Security", None),),
    "service:system": (("System", None),),
}


def parse_logsource(block: Any) -> LogSource:
    """A rule's ``logsource`` -> LogSource. Refuses anything outside LB-04 (other product, both or neither of
    category / service, unknown keys)."""
    if not isinstance(block, dict) or not set(block) <= _ALLOWED_LOGSOURCE_KEYS:
        raise LabelError(f"refused: logsource {block!r} is outside LB-04")
    if block.get("product") != "windows" or ("category" in block) == ("service" in block):
        raise LabelError(f"refused: logsource {block!r} is outside LB-04")
    name = f"category:{block['category']}" if "category" in block else f"service:{block['service']}"
    if name not in LOGSOURCES:
        raise LabelError(f"refused: logsource {name} is outside LB-04")
    return LogSource(name=name, targets=LOGSOURCES[name])


# ---------------------------------------------------------------- tags

def _tag_list(tags: Any) -> list[str]:
    """The ``tags`` list as lower-case strings; refused when it is not a list of strings."""
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise LabelError(f"refused: tags {tags!r} is not a list of strings")
    return [t.strip().lower() for t in tags]


def technique_tags(tags: Any) -> tuple[str, ...]:
    """ATT&CK technique ids of the tags, in tag order (``attack.t1003.001`` -> ``T1003.001``)."""
    out = []
    for t in _tag_list(tags):
        if t.startswith("attack.") and _TECH.match(t[7:]):
            out.append(t[7:].upper())
    return tuple(out)


def tactic_tags(tags: Any) -> tuple[str, ...]:
    """ATT&CK tactic names of the tags, in tag order (``attack.lateral-movement``). Software / group ids
    (``attack.s0002``) and technique ids are not tactics."""
    out = []
    for t in _tag_list(tags):
        if t.startswith("attack.") and _TACTIC.match(t[7:]):
            out.append(t[7:])
    return tuple(out)


# ---------------------------------------------------------------- one rule

@dataclass(frozen=True)
class Rule:
    """A validated, compiled rule plus its manifest metadata (the label columns of spec 3.4)."""
    rule_id: str
    file: str
    title: str
    source: str
    sigma_id: str
    technique: str
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    level: str
    level_value: int
    logsource: LogSource
    detection: Detection


def lf_bytes(data: bytes) -> bytes:
    """Bytes with CRLF (and lone CR) line ends turned into LF (LB-13)."""
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def lf_sha256(data: bytes) -> str:
    """SHA-256 of the LF-normalised bytes (LB-13): a CRLF checkout cannot change a pin."""
    return hashlib.sha256(lf_bytes(data)).hexdigest()


def _load_yaml(text: str, file: str) -> dict[str, Any]:
    """``yaml.safe_load`` only (decision 057); one mapping document."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise LabelError(f"refused: rule file {file} is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise LabelError(f"refused: rule file {file} is not one YAML mapping")
    missing = [k for k in _REQUIRED_KEYS if k not in doc]
    refused = [k for k in _REFUSED_KEYS if k in doc]
    if missing or refused:
        raise LabelError(f"refused: rule file {file}: missing {missing}, refused keys {refused}")
    return doc


def parse_rule(text: str, entry: RuleEntry, manifest: Mapping[str, str] | None = None) -> Rule:
    """Validate and compile one rule file text. Refuses a level outside the Sigma set, an own rule whose level is not
    ``OWN_RULE_LEVEL`` (LB-07), and any logsource, field, modifier or condition outside LB-04 / LB-05.

    ``manifest`` (the row as read) supplies the label metadata when given; else it is computed (``manifest_row``
    without the hash), so tests can parse a rule without a manifest.
    """
    doc = _load_yaml(text, entry.file)
    level = doc.get("level")
    if level not in LEVEL_VALUE:
        raise LabelError(f"refused: rule {entry.rule_id} level {level!r} is not a Sigma level")
    if entry.source == SOURCE_OWN and level != OWN_RULE_LEVEL:
        raise LabelError(f"refused: own rule {entry.rule_id} level {level!r} is not {OWN_RULE_LEVEL!r} (LB-07)")
    meta = dict(manifest) if manifest is not None else _meta(entry, doc)
    try:
        detection = compile_detection(doc["detection"])
    except LabelError as exc:
        raise LabelError(f"{exc} (rule {entry.rule_id}, {entry.file})") from exc
    return Rule(rule_id=entry.rule_id, file=entry.file, title=str(doc["title"]), source=entry.source,
                sigma_id=meta["sigma_id"], technique=meta["technique"],
                techniques=tuple(t for t in meta["techniques"].split(";") if t),
                tactics=tuple(t for t in meta["tactics"].split(";") if t), level=str(level),
                level_value=LEVEL_VALUE[str(level)], logsource=parse_logsource(doc["logsource"]),
                detection=detection)


# ---------------------------------------------------------------- manifest

def _related_ids(doc: Mapping[str, Any], kind: str) -> list[str]:
    """Ids of the ``related`` entries of type ``kind``."""
    rel = doc.get("related") or []
    return [str(r.get("id")) for r in rel if isinstance(r, dict) and r.get("type") == kind]


def _check_identity(entry: RuleEntry, doc: Mapping[str, Any]) -> None:
    """Spec 3.3: an unchanged SigmaHQ rule keeps its id; an adapted one has a new id and names the original under
    ``related`` (type ``derived``); an own rule has no SigmaHQ id. Also the primary technique must be a tag."""
    rid = str(doc.get("id"))
    if entry.source == SOURCE_OWN:
        ok = entry.sigma_id == ""
    elif entry.adapted:
        ok = rid != entry.sigma_id and entry.sigma_id in _related_ids(doc, "derived")
    else:
        ok = rid == entry.sigma_id
    if not ok:
        raise LabelError(f"refused: rule {entry.rule_id} id {rid!r} disagrees with the locked table (spec 3.3)")
    if entry.technique not in technique_tags(doc.get("tags")):
        raise LabelError(f"refused: rule {entry.rule_id} primary technique {entry.technique} is not among its tags")


def _meta(entry: RuleEntry, doc: Mapping[str, Any]) -> dict[str, str]:
    """Every manifest column except ``sha256`` for one rule (spec 3.4)."""
    _check_identity(entry, doc)
    refs = doc.get("references") or []
    own = entry.source == SOURCE_OWN
    return {
        "rule_id": entry.rule_id,
        "file": entry.file,
        "source": entry.source,
        "sigma_id": entry.sigma_id,
        "sigma_commit": "" if own else SIGMA_COMMIT,
        "title": str(doc.get("title", "")),
        "author": str(doc.get("author", "")),
        "license": LICENSE_OWN if own else LICENSE_DRL,
        "references": ";".join(str(r) for r in refs),
        "technique": entry.technique,
        "techniques": ";".join(technique_tags(doc.get("tags"))),
        "tactics": ";".join(tactic_tags(doc.get("tags"))),
        "level": str(doc.get("level", "")),
    }


def manifest_row(entry: RuleEntry, data: bytes) -> dict[str, str]:
    """The manifest row of one rule file (its raw bytes), columns in ``MANIFEST_COLUMNS`` order."""
    doc = _load_yaml(lf_bytes(data).decode("utf-8"), entry.file)
    meta = _meta(entry, doc)
    meta["sha256"] = lf_sha256(data)
    return {c: meta[c] for c in MANIFEST_COLUMNS}


def build_manifest_rows(rules_dir: Path = RULES_DIR,
                        table: Sequence[RuleEntry] = RULE_TABLE) -> list[dict[str, str]]:
    """The manifest recomputed from the rule files and the locked table, in table order. LabelError when a table
    file is missing."""
    rows = []
    for entry in table:
        path = Path(rules_dir) / entry.file
        if not path.is_file():
            raise LabelError(f"refused: rule {entry.rule_id} has no file {entry.file} (LB-10)")
        rows.append(manifest_row(entry, path.read_bytes()))
    return rows


def manifest_text(rows: Sequence[Mapping[str, str]]) -> str:
    """CSV text of the manifest (``\\n`` line ends, spec columns)."""
    return csv_text(MANIFEST_COLUMNS, rows)


def parse_manifest_text(text: str) -> list[dict[str, str]]:
    """Rows of a manifest text; refused when its header is not exactly ``MANIFEST_COLUMNS``."""
    reader = csv.DictReader(io.StringIO(text))
    if tuple(reader.fieldnames or ()) != MANIFEST_COLUMNS:
        raise LabelError(f"refused: manifest columns {reader.fieldnames} differ from spec 3.4")
    return [dict(r) for r in reader]


def check_rule_files(rules_dir: Path, manifest_rows: Sequence[Mapping[str, str]]) -> None:
    """LB-10: the folder holds only ``manifest.csv`` and rule files; every ``*.yml`` has a manifest row and every
    row a file; rule ids and files are unique; each file's LF SHA-256 equals its row."""
    d = Path(rules_dir)
    names = sorted(p.name for p in d.iterdir())
    foreign = [n for n in names if n != MANIFEST_FILE and not n.endswith(".yml")]
    if foreign:
        raise LabelError(f"refused: rules folder holds files that are not rules: {', '.join(foreign)}")
    files = {n for n in names if n.endswith(".yml")}
    listed = [r["file"] for r in manifest_rows]
    ids = [r["rule_id"] for r in manifest_rows]
    if len(set(listed)) != len(listed) or len(set(ids)) != len(ids):
        raise LabelError("refused: manifest lists a rule id or file twice (LB-10)")
    if files != set(listed):
        raise LabelError(f"refused: rule files without a manifest row {sorted(files - set(listed))}, manifest rows "
                         f"without a file {sorted(set(listed) - files)} (LB-10)")
    for r in manifest_rows:
        got = lf_sha256((d / r["file"]).read_bytes())
        if got != r["sha256"]:
            raise LabelError(f"refused: rule file {r['file']} SHA-256 {got} differs from the manifest (LB-10)")


@dataclass(frozen=True)
class RuleSet:
    """The rules a run uses, the manifest rows and text as read (LF), and the manifest's LF SHA-256."""
    rules: tuple[Rule, ...]
    manifest_rows: tuple[dict[str, str], ...]
    manifest_text: str
    manifest_sha256: str


def _row_differences(a: Mapping[str, str], b: Mapping[str, str]) -> list[str]:
    """Columns whose values differ between two manifest rows."""
    return [c for c in MANIFEST_COLUMNS if a.get(c) != b.get(c)]


def load_rules(rules_dir: Path = RULES_DIR, table: Sequence[RuleEntry] = RULE_TABLE) -> RuleSet:
    """Read the manifest, check the files against it (LB-10), check it equals the manifest recomputed from the files
    and the locked table, and compile every rule (LB-04, LB-05). LabelError on any refusal."""
    d = Path(rules_dir)
    mpath = d / MANIFEST_FILE
    if not mpath.is_file():
        raise LabelError(f"refused: rules manifest not found: {mpath}")
    raw = mpath.read_bytes()
    text = lf_bytes(raw).decode("utf-8")
    rows = parse_manifest_text(text)
    check_rule_files(d, rows)
    want = build_manifest_rows(d, table)
    if [r["rule_id"] for r in rows] != [r["rule_id"] for r in want]:
        raise LabelError("refused: manifest rule ids differ from the locked list (decision 056, LB-10)")
    for got, exp in zip(rows, want):
        diff = _row_differences(got, exp)
        if diff:
            raise LabelError(f"refused: manifest row {got['rule_id']} differs in {', '.join(diff)} (LB-10)")
    by_id = {e.rule_id: e for e in table}
    rules = tuple(parse_rule(lf_bytes((d / r["file"]).read_bytes()).decode("utf-8"), by_id[r["rule_id"]], r)
                  for r in rows)
    return RuleSet(rules=rules, manifest_rows=tuple(rows), manifest_text=text, manifest_sha256=lf_sha256(raw))


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m label.rules --write-manifest`` rewrites ``rules/manifest.csv`` from the files (after a decision
    record changes a rule); ``--check`` loads and validates the rules. Exit 2 on a refusal."""
    ap = argparse.ArgumentParser(prog="label.rules")
    ap.add_argument("--write-manifest", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    try:
        if a.write_manifest:
            text = manifest_text(build_manifest_rows(RULES_DIR))
            with open(RULES_DIR / MANIFEST_FILE, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        rs = load_rules(RULES_DIR)
    except LabelError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"{len(rs.rules)} rules, manifest sha256 {rs.manifest_sha256}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
