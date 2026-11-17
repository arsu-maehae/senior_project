"""Output texts of the link accuracy module and the folder swap (PLAN T7.6; decision 051 item 8).

WHY texts first, disk last: on a refusal nothing may be written, so every file is complete in memory before the
folder is touched; and every file but ``run_info.json`` must be byte-identical between runs, so the texts hold no
timestamp, sorted JSON keys and ``\\n`` line ends only. The ``.md`` files carry ids, hosts, vocabularies and
counts only: no command text and no account, image or name text (051 item 8).
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import shutil
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .inputs import EvalError
from .link_accuracy import FACT_COLUMNS, HOP_COUNTS, KEYED_COLUMNS, KEYED_COUNTS, TOTAL_COLUMNS, SCOPES
from .params import PROTOCOL_GROUP_ORDER, SPLIT_DEVELOPMENT, TIER_ORDER

__all__ = ["KEYED_FILE", "FACTS_FILE", "TOTALS_FILE", "JSON_FILE", "MD_FILE", "RUN_INFO_FILE", "SUMMARY_CSV",
           "SUMMARY_MD", "LABEL_RECALL_FILE", "LABEL_RECALL_MD", "SUMMARY_COLUMNS", "SENTENCES", "md_header",
           "csv_text", "json_text", "file_facts",
           "trial_json", "trial_md", "summary_rows", "summary_md", "kept_file_refusal", "replace_folder"]

KEYED_FILE = "link_accuracy_hops.csv"
FACTS_FILE = "link_facts_hops.csv"
TOTALS_FILE = "link_accuracy_totals.csv"
JSON_FILE = "link_accuracy.json"
MD_FILE = "link_accuracy.md"
RUN_INFO_FILE = "run_info.json"
SUMMARY_CSV = "link_accuracy_summary.csv"
SUMMARY_MD = "link_accuracy_summary.md"
# Labelling recall (PLAN T8.3; spec 04 LBA-04): one CSV per keyed trial folder, one report in the summary folder.
LABEL_RECALL_FILE = "label_recall.csv"
LABEL_RECALL_MD = "label_recall.md"

# The three statements every report carries (051 item 8; spec 03 STA-05, L-ST1; spec 07 section 8).
SENTENCES: tuple[str, ...] = (
    "WinRM tier A (port join) is reported apart from tier B.",
    "Tier B on SMB is agreement with the command-line rule the key also uses, not accuracy "
    "(spec 03 L-ST1, spec 07 §8).",
    "The identity value here is computed from stitch facts for comparison only; T9 owns IdentityCoherence "
    "(decision 051 item 7).",
)

# Keyed-row columns shown in the .md (no account column: 051 item 8).
_MD_KEYED = ("key_hop_id", "key_role", "key_protocol", "key_source_host", "key_target_host", "match", "hop_id",
             "key_logons_in_hop", "protocol_group", "best_tier", "candidate_count", "key_sessions_hex",
             "key_session_uid_source", "session_compare", "among_candidates", "rank1", "only_candidate",
             "rank1_tier", "rank1_methods", "key_session_tier", "expected_target_only", "target_only_ok",
             "evidence_before_range", "port_cmd_agree", "identity_expected", "identity_value", "identity_match")
# Fact columns shown in the .md of an unkeyed trial (identity_values holds account text, so it stays in the CSV).
_MD_FACTS = ("hop_id", "source_host", "target_host", "protocol_group", "is_seed", "in_path", "user_e2e",
             "member_count", "best_tier", "candidate_count", "rank1_sessions_hex", "rank1_tier", "rank1_methods",
             "tie", "target_only_reason", "evidence_before_range", "evidence_after_range", "port_cmd_agree")
_HEADLINE_KEYED = ("key_hops", "matched", "match_multiple", "match_unmatched", "with_key_session", "among",
                   "rank1_correct", "rank1_tied_correct", "rank1_wrong", "rank1_no_candidate", "only_candidate",
                   "compare_logon_uid", "compare_host_logon_id", "compare_ambiguous_boot", "background",
                   "background_target_only_ok", "identity_match", "identity_q9_dependent")
SUMMARY_COLUMNS: tuple[str, ...] = ("row_kind",) + KEYED_COLUMNS + tuple(c for c in TOTAL_COLUMNS
                                                                         if c not in KEYED_COLUMNS)


# ---------------------------------------------------------------- generic text

def csv_text(columns: Sequence[str], rows: Iterable[Mapping[str, str]]) -> str:
    """Header then rows, ``\\n`` line ends; ValueError when a row's keys differ from ``columns`` or a value is not
    str (the column lists are the contract)."""
    cols = list(columns)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(cols)
    for row in rows:
        if set(row) != set(cols):
            raise ValueError(f"row keys differ from the columns: {sorted(set(row) ^ set(cols))}")
        values = [row[c] for c in cols]
        if not all(isinstance(v, str) for v in values):
            raise ValueError("every CSV value must be a str")
        w.writerow(values)
    return buf.getvalue()


def json_text(data: Mapping[str, Any]) -> str:
    """Sorted keys, indent 1, one trailing newline: the same spelling on every run."""
    return json.dumps(data, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def file_facts(files: Mapping[str, tuple[str, int | None]]) -> dict[str, dict[str, Any]]:
    """name -> {sha256 of the UTF-8 text, rows (data rows of a CSV, else None)}, for run_info.json."""
    return {n: {"sha256": hashlib.sha256(t.encode("utf-8")).hexdigest(), "rows": k}
            for n, (t, k) in sorted(files.items())}


def md_header(split: str, trial: str | None) -> str:
    """First line of every .md: the DEVELOPMENT label (decision 019) or the TEST label with the trial."""
    if split == SPLIT_DEVELOPMENT:
        return "# DEVELOPMENT — not a result (decision 019)"
    return f"# TEST — trial {trial}" if trial else "# TEST"


def _md_table(columns: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """A Markdown table; empty cells shown as ``-`` so the table stays readable."""
    lines = ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    for r in rows:
        lines.append("| " + " | ".join(str(r.get(c, "")) or "-" for c in columns) + " |")
    return lines


def _totals_table(totals: Sequence[Mapping[str, str]]) -> list[str]:
    """Totals per scope, each with its own count columns."""
    out: list[str] = []
    for scope in SCOPES:
        rows = [r for r in totals if r["scope"] == scope]
        if not rows:
            continue
        names = KEYED_COUNTS if scope == "keyed" else HOP_COUNTS
        out += ["", f"### {scope}", ""] + _md_table(("protocol_group", "tier") + names, rows)
    return out


# ---------------------------------------------------------------- one trial

def trial_json(trial: str, split: str, key: Mapping[str, Any] | None, head: Mapping[str, Any],
               totals: Sequence[Mapping[str, str]], row_counts: Mapping[str, int]) -> dict[str, Any]:
    """The link_accuracy.json dict: counts and headline numbers, no timestamp."""
    return {"trial_id": trial, "split": split, "key": dict(key) if key else None, "headline": dict(head),
            "rows": dict(sorted(row_counts.items())), "totals": [dict(r) for r in totals]}


def _headline_lines(head: Mapping[str, Any]) -> list[str]:
    """Headline numbers as Markdown bullets (counts and ids only)."""
    lines: list[str] = []
    if head.get("keyed"):
        lines.append("- " + ", ".join(f"{k} {head[k]}" for k in _HEADLINE_KEYED if k in head))
        lines.append("- key uid source: " + ", ".join(f"{k} {v}" for k, v in sorted(head["key_uid_source"].items())))
        tiers = "; ".join(f"{g}: " + ", ".join(f"{t} {n}" for t, n in sorted(v.items()))
                          for g, v in sorted(head["key_session_tiers"].items()))
        lines.append(f"- key-session tiers by protocol group: {tiers or 'none'}")
        ebr = ", ".join(f"{k} {v}" for k, v in sorted(head["evidence_before_range_keyed"].items()))
        lines.append(f"- key hops with evidence_before_range > 0: {ebr or 'none'}")
    for scope in ("all_hops", "user_e2e_hops"):
        lines.append(f"- {scope}: " + ", ".join(f"{k} {v}" for k, v in head[scope].items()))
    return lines


def trial_md(trial: str, split: str, key: Mapping[str, Any] | None, head: Mapping[str, Any],
             keyed: Sequence[Mapping[str, str]] | None, facts: Sequence[Mapping[str, str]],
             totals: Sequence[Mapping[str, str]]) -> str:
    """The link_accuracy.md text of one trial."""
    lines = [md_header(split, trial), "", f"Link accuracy, trial {trial}, split {split} (decision 051).", ""]
    if key:
        lines.append(f"Key: {key['path']} (SHA-256 {key['sha256']}, lock {key['lock']}).")
    else:
        lines.append("No approved key: facts and totals only, no right / wrong columns (decision 051 item 8).")
    lines += [""] + list(SENTENCES) + ["", "## Headline", ""] + _headline_lines(head)
    if keyed is not None:
        lines += ["", "## Key hops", ""] + _md_table(_MD_KEYED, keyed)
    else:
        lines += ["", "## Hops (facts)", ""] + _md_table(_MD_FACTS, facts)
    lines += ["", "## Totals"] + _totals_table(totals)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- development summary

def _sum_totals(totals: Iterable[Mapping[str, str]], split: str) -> list[dict[str, str]]:
    """Totals of several trials summed per (scope, protocol_group, tier); trial_id = ``all``."""
    acc: dict[tuple[str, str, str], dict[str, int]] = {}
    for r in totals:
        names = KEYED_COUNTS if r["scope"] == "keyed" else HOP_COUNTS
        slot = acc.setdefault((r["scope"], r["protocol_group"], r["tier"]), {n: 0 for n in names})
        for n in names:
            slot[n] += int(r[n] or 0)

    def order(k: tuple[str, str, str]) -> tuple:
        s, g, t = k
        gi = (PROTOCOL_GROUP_ORDER.index(g), "") if g in PROTOCOL_GROUP_ORDER else (len(PROTOCOL_GROUP_ORDER), g)
        ti = (TIER_ORDER.index(t), "") if t in TIER_ORDER else (len(TIER_ORDER), t)
        return (SCOPES.index(s), g == "all", gi, ti)

    out: list[dict[str, str]] = []
    for k in sorted(acc, key=order):
        row = {c: "" for c in TOTAL_COLUMNS}
        row.update(split=split, trial_id="all", scope=k[0], protocol_group=k[1], tier=k[2])
        row.update({n: str(v) for n, v in acc[k].items()})
        out.append(row)
    return out


def summary_rows(keyed: Sequence[Mapping[str, str]], totals: Sequence[Mapping[str, str]],
                 split: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """(summary CSV rows, summed totals): every keyed row (``row_kind`` = hop), then the summed totals
    (``row_kind`` = total). One CSV with the union of both column lists; a column foreign to a row kind is
    empty."""
    summed = _sum_totals(totals, split)
    rows: list[dict[str, str]] = []
    for r in keyed:
        row = {c: "" for c in SUMMARY_COLUMNS}
        row.update(r, row_kind="hop")
        rows.append(row)
    for r in summed:
        row = {c: "" for c in SUMMARY_COLUMNS}
        row.update(r, row_kind="total")
        rows.append(row)
    return rows, summed


def summary_md(split: str, per_trial: Sequence[tuple[str, Mapping[str, Any]]], head: Mapping[str, Any],
               summed: Sequence[Mapping[str, str]]) -> str:
    """The development summary .md: header, statements, summed headline, one line per trial, summed totals."""
    lines = [md_header(split, None), "", f"Link accuracy over {len(per_trial)} trials, split {split} "
             "(decision 051).", ""] + list(SENTENCES) + ["", "## Headline (summed)", ""] + _headline_lines(head)
    cols = ("trial_id", "keyed", "key_hops", "matched", "with_key_session", "among", "rank1_correct",
            "only_candidate", "compare_logon_uid", "background_target_only_ok", "identity_match",
            "identity_q9_dependent", "hops", "user_e2e_hops")
    table = []
    for trial, h in per_trial:
        r: dict[str, Any] = {c: h[c] for c in cols if c in KEYED_COUNTS and c in h}
        r.update(trial_id=trial, keyed="yes" if h.get("keyed") else "no", hops=h["all_hops"]["hops"],
                 user_e2e_hops=h["user_e2e_hops"]["hops"])
        table.append(r)
    lines += ["", "## Per trial", ""] + _md_table(cols, table)
    lines += ["", "## Totals (summed)"] + _totals_table(summed)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- folder swap

def _remove(path: Path) -> None:
    """Delete a leftover of an interrupted run (ours by name only)."""
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _csv_trial_ids(path: Path) -> set[str] | None:
    """The distinct ``trial_id`` values of a CSV, or None when it has no such column or cannot be read."""
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            if "trial_id" not in (reader.fieldnames or []):
                return None
            return {r["trial_id"] for r in reader}
    except (OSError, UnicodeDecodeError, csv.Error):
        return None


def kept_file_refusal(target: Path, files: Mapping[str, str], keep: Iterable[str], trial_id: str) -> str | None:
    """Why the files ``replace_folder`` would carry over from ``target`` do not belong to ``trial_id``, else None
    (stage review S06).

    WHY: the carry-over copies the other evaluation's files into the new folder. With ``--out`` naming another
    trial's folder, those would be another trial's outputs presented under this trial. Every kept CSV must have a
    ``trial_id`` column whose values all equal ``trial_id`` (a header-only CSV passes); every kept JSON object must
    have ``trial_id`` = ``trial_id``. Other kept files (``.md``) are not read. Reads only; names files, never content.
    """
    for name in sorted(set(keep) - set(files)):
        path = Path(target) / name
        if not path.is_file():
            continue
        if name.endswith(".csv"):
            ids = _csv_trial_ids(path)
            if ids is None or not ids <= {trial_id}:
                return f"kept file {name} in {Path(target).name} is not an output of trial {trial_id}"
        elif name.endswith(".json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                data = None
            if not isinstance(data, dict) or data.get("trial_id") != trial_id:
                return f"kept file {name} in {Path(target).name} is not an output of trial {trial_id}"
    return None


def replace_folder(target: Path, files: Mapping[str, str], keep: Iterable[str] = (),
                   trial_id: str | None = None) -> None:
    """Write ``files`` into a fresh ``.<name>.tmp`` sibling, then swap it in for ``target``.

    WHY: the folder is rebuilt on each run, and a reader must never see a mix of old and new files. If the swap
    fails the old folder is renamed back.

    ``keep`` names files of the OTHER evaluation that shares the folder (link accuracy and labelling recall, T8.3):
    an existing ``target/<name>`` in ``keep`` and not in ``files`` is copied unchanged (bytes and times) into the new
    folder before the swap, so running either evaluation never deletes the other's output. Anything else in the old
    folder is still dropped, as before. With ``trial_id`` given, the kept files must belong to that trial
    (``kept_file_refusal``); otherwise EvalError before anything is written.
    """
    target = Path(target)
    keep = tuple(keep)
    if trial_id is not None:
        reason = kept_file_refusal(target, files, keep, trial_id)
        if reason:
            raise EvalError(f"refused: {reason}")
    parent = target.parent
    tmp, old = parent / f".{target.name}.tmp", parent / f".{target.name}.old"
    parent.mkdir(parents=True, exist_ok=True)
    _remove(tmp)
    _remove(old)
    tmp.mkdir()
    for name, text in sorted(files.items()):
        with open(tmp / name, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    for name in sorted(set(keep) - set(files)):
        if (target / name).is_file():
            shutil.copy2(target / name, tmp / name)
    had_old = target.exists()
    if had_old:
        target.rename(old)
    try:
        tmp.rename(target)
    except OSError:
        if had_old:
            old.rename(target)
        raise
    if had_old:
        shutil.rmtree(old)
