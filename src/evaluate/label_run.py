"""Labelling recall of one trial: every check and read first, then the rows and texts; writes nothing (PLAN T8.3).

Order: label files (event_labels.csv against its run_info.json) -> approved key (the existing loader, never a draft)
-> keyed only: DB SHA-256 against the label run and the key -> read-only query of the key's SMB share columns ->
DB SHA-256 again. A trial without a key is never opened in the DB: it gives label counts only (spec 04 LBA-04).
WHY the same refusal style as ``run.evaluate_trial``: a refusal must leave the disk untouched, and the CLI alone
holds the development allowlist so that tests can call this core directly.
"""
from __future__ import annotations

from pathlib import Path

from . import label_recall as lr
from .inputs import EvalError, KeyData, check_db_unchanged, db_path, load_key, open_db_ro, sha256_file
from .label_inputs import LabelData, check_label_db, load_labels, query_share_facts
from .params import LABEL_OUT_REL

__all__ = ["default_label_dir", "label_trial", "recall_from_inputs"]


def default_label_dir(repo: Path, trial: str) -> Path:
    """``out/label/<trial>``."""
    return Path(repo) / LABEL_OUT_REL / trial


def _inputs(labels: LabelData, key: KeyData | None, db_sha: str | None) -> dict[str, str]:
    """The input hashes the report names for one trial (no timestamp, so the report stays byte-identical)."""
    out = {"event_labels_sha256": labels.event_labels_sha256, "label_run_info_sha256": labels.run_info_sha256}
    if key is not None:
        out["key_sha256"] = key.sha256
    if db_sha is not None:
        out["db_sha256"] = db_sha
    return out


def recall_from_inputs(trial: str, split: str, labels: LabelData, key: KeyData | None,
                       shares: dict[str, lr.ShareFacts], db_sha: str | None) -> lr.TrialRecall:
    """The TrialRecall of already-checked inputs. Pure."""
    counts = lr.label_counts(labels.rows)
    if key is None:
        return lr.TrialRecall(trial, split, None, counts, {}, _inputs(labels, None, db_sha))
    rows = lr.recall_rows(trial, key.data, shares, labels.rows, label_run_sha256=labels.run_info_sha256)
    unkinded = lr.unkinded_counts(key.data, (r["event_uid"] for r in rows))
    return lr.TrialRecall(trial, split, tuple(rows), counts, unkinded, _inputs(labels, key, db_sha))


def label_trial(repo: Path, trial: str, split: str, label_dir: Path | None = None) -> lr.TrialRecall:
    """Check and read every input of one trial and build its recall; writes nothing. The allowlist is NOT checked
    here (the CLI checks it first, ``inputs.check_trial_allowed``)."""
    repo = Path(repo)
    labels = load_labels(label_dir or default_label_dir(repo, trial), trial)
    key = load_key(repo, trial, split)
    if key is None:
        return recall_from_inputs(trial, split, labels, None, {}, None)
    dbf = db_path(repo, trial)
    if not dbf.is_file():
        raise EvalError(f"refused: DB {dbf.as_posix()} is missing")
    before = sha256_file(dbf)
    check_label_db(before, labels, key)
    conn = open_db_ro(dbf)
    try:
        shares = query_share_facts(conn, lr.share_uids_needed(key.data))
    finally:
        conn.close()
    after = sha256_file(dbf)
    check_db_unchanged(before, after)
    return recall_from_inputs(trial, split, labels, key, shares, before)
