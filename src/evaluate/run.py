"""Core of the link accuracy module: one trial in, all output texts out (decision 051).

``evaluate_trial`` does every check and every read first (stitch files, key, key lock, DB hash bracket), then
builds the rows and texts with the pure modules; nothing is written here. WHY: a refusal must leave the disk
untouched (051 item 2), and the core must run with ``split = "test"`` at T10 (and in synthetic tests now) while
the CLI alone holds the development allowlist (051 item 1).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import link_accuracy as la
from . import writers as w
from .inputs import (BootRow, EvalError, EventRow, KeyData, LogonRow, StitchData, check_db_hash, check_db_unchanged,
                     db_path, load_key, load_stitch, open_db_ro, query_boots, query_events, query_logons,
                     repo_relative, sha256_file)
from .keys import KeySession, key_sessions, match_key_hop, session_lookup_requests, sysmon1_agent_uids
from .params import EVAL_OUT_REL, STITCH_OUT_REL, STITCH_RUN_INFO, SUMMARY_DIR_NAME, TOOL_VERSION

__all__ = ["DbFacts", "TrialResult", "default_stitch_dir", "default_out_dir", "summary_dir", "read_db_facts",
           "evaluate_trial", "build_rows", "build_files", "run_info", "summary_files", "utc_now"]


@dataclass(frozen=True)
class DbFacts:
    """What the key reading needs from the DB, queried once inside the hash bracket."""
    events: Mapping[str, EventRow] = field(default_factory=dict)
    logons: Mapping[tuple[str, int], Sequence[LogonRow]] = field(default_factory=dict)
    boots: Mapping[str, Sequence[BootRow]] = field(default_factory=dict)


@dataclass(frozen=True)
class TrialResult:
    """Everything one evaluated trial produced. ``files`` holds every output text, run_info.json included."""
    trial_id: str
    split: str
    keyed_rows: tuple[dict[str, str], ...] | None
    fact_rows: tuple[dict[str, str], ...]
    total_rows: tuple[dict[str, str], ...]
    headline: Mapping[str, Any]
    run_info: Mapping[str, Any]
    files: Mapping[str, str]


def default_stitch_dir(repo: Path, trial: str) -> Path:
    """``out/stitch/<trial>``."""
    return Path(repo) / STITCH_OUT_REL / trial


def default_out_dir(repo: Path, trial: str) -> Path:
    """``out/evaluate/<trial>``."""
    return Path(repo) / EVAL_OUT_REL / trial


def summary_dir(repo: Path) -> Path:
    """``out/evaluate/development``."""
    return Path(repo) / EVAL_OUT_REL / SUMMARY_DIR_NAME


def utc_now() -> str:
    """Current UTC instant, for run_info.json only."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- reads

def _boot_group_s(stitch: StitchData) -> float:
    """``parameters.boot_group_s`` of the stitch run (051 item 4: read, never imported)."""
    try:
        return float(stitch.run_info["parameters"]["boot_group_s"])
    except (KeyError, TypeError, ValueError):
        raise EvalError("refused: stitch run_info.json has no parameters.boot_group_s") from None


def read_db_facts(conn: Any, key: KeyData | None) -> DbFacts:
    """Query the Sysmon 1 session ids of the key's agent events, then the 4624s and boot events of every key
    source session (051 item 4). Unkeyed: nothing is queried."""
    if key is None:
        return DbFacts()
    ek = key.data.get("event_keys") or {}
    hops = key.data.get("hops") or []
    events = query_events(conn, [u for kh in hops for u in sysmon1_agent_uids(kh, ek)])
    requests = {(h, lid) for kh in hops for h, lid, _ in session_lookup_requests(kh, ek, events)}
    logons = {(h, lid): query_logons(conn, h, lid) for h, lid in sorted(requests)}
    boots = {h: query_boots(conn, h) for h in sorted({h for h, _ in requests})}
    return DbFacts(events=events, logons=logons, boots=boots)


def _check_stitch_trial(stitch: StitchData, trial: str) -> None:
    """The stitch folder must be the one of this trial (its run_info ``trial_id``)."""
    got = stitch.run_info.get("trial_id")
    if got != trial:
        raise EvalError(f"refused: stitch run_info.json trial_id {got!r} differs from the trial {trial}")


# ---------------------------------------------------------------- rows (pure)

def build_rows(trial: str, split: str, stitch: StitchData, key: KeyData | None, db: DbFacts
               ) -> tuple[list[dict[str, str]] | None, list[dict[str, str]], list[dict[str, str]]]:
    """(keyed rows or None, fact rows, total rows). Pure. Keyed rows follow the key's hop order; fact rows the
    hops.csv order."""
    links = la.rows_by_hop(stitch.links)
    hops = {h["hop_id"]: h for h in stitch.hops}
    keyed: list[dict[str, str]] | None = None
    key_of_hop: dict[str, list[str]] = {}
    if key is not None:
        keyed = []
        ek = key.data.get("event_keys") or {}
        bgs = _boot_group_s(stitch)
        for kh in key.data.get("hops") or []:
            match = match_key_hop(kh, stitch.hops)
            hop = hops[match.hop_ids[0]] if match.outcome == "matched" else None
            for hid in match.hop_ids:
                key_of_hop.setdefault(hid, []).append(str(kh.get("hop_id", "")))
            sessions: list[KeySession] = key_sessions(kh, ek, db.events, db.logons, db.boots, bgs)
            keyed.append(la.keyed_row(split, trial, kh, ek, match, hop,
                                      links.get(hop["hop_id"], []) if hop else [], sessions, stitch.hop_identity))
    facts = [la.fact_row(split, trial, h, links.get(h["hop_id"], []), stitch.hop_identity,
                         key_of_hop.get(h["hop_id"], [])) for h in stitch.hops]
    totals = la.total_rows(split, trial, keyed, facts)
    return keyed, facts, totals


# ---------------------------------------------------------------- texts (pure)

def _key_info(key: KeyData | None) -> dict[str, str] | None:
    """{path, sha256, lock} of the key, or None."""
    return None if key is None else {"path": key.path_rel, "sha256": key.sha256, "lock": key.lock}


def build_files(trial: str, split: str, key: KeyData | None, keyed: Sequence[dict[str, str]] | None,
                facts: Sequence[dict[str, str]], totals: Sequence[dict[str, str]]
                ) -> tuple[dict[str, tuple[str, int | None]], dict[str, Any]]:
    """(name -> (text, data rows), headline) of every output file except run_info.json. Pure.
    ``link_accuracy_hops.csv`` exists only for a keyed trial (051 item 8)."""
    head = la.headline(keyed, facts)
    files: dict[str, tuple[str, int | None]] = {}
    if keyed is not None:
        files[w.KEYED_FILE] = (w.csv_text(la.KEYED_COLUMNS, keyed), len(keyed))
    files[w.FACTS_FILE] = (w.csv_text(la.FACT_COLUMNS, facts), len(facts))
    files[w.TOTALS_FILE] = (w.csv_text(la.TOTAL_COLUMNS, totals), len(totals))
    counts = {n: k for n, (_t, k) in files.items() if k is not None}
    files[w.JSON_FILE] = (w.json_text(w.trial_json(trial, split, _key_info(key), head, totals, counts)), None)
    files[w.MD_FILE] = (w.trial_md(trial, split, _key_info(key), head, keyed, facts, totals), None)
    return files, head


def run_info(repo: Path, trial: str, split: str, stitch: StitchData, db_file: Path, before: str, after: str,
             key: KeyData | None, files: Mapping[str, tuple[str, int | None]], generated_utc: str) -> dict[str, Any]:
    """The run_info.json dict: the only file with a timestamp; every input with its SHA-256."""
    return {"generated_utc": generated_utc, "tool_version": TOOL_VERSION, "trial_id": trial, "split": split,
            "inputs": {"stitch_dir": repo_relative(stitch.stitch_dir, repo),
                       "stitch_files": dict(stitch.file_sha256),
                       "stitch_run_info_sha256": stitch.file_sha256[STITCH_RUN_INFO],
                       "db": {"path": repo_relative(db_file, repo), "sha256_before": before, "sha256_after": after},
                       "key": _key_info(key)},
            "files": w.file_facts(files)}


# ---------------------------------------------------------------- one trial

def evaluate_trial(repo: Path, trial: str, split: str, stitch_dir: Path, key_lock_path: Path | None = None,
                   generated_utc: str | None = None) -> TrialResult:
    """Check and read every input of one trial, then build every output text; writes nothing (051 items 1-9).

    Order: stitch files (hashes vs their run_info) -> key (and key lock for split = test) -> DB SHA-256 vs the
    stitch run and the key -> read-only queries -> DB SHA-256 again. Any EvalError stops the run. The allowlist is
    NOT checked here: the CLI checks it (``inputs.check_trial_allowed``) so that tests can run split = test.
    """
    repo = Path(repo)
    stitch = load_stitch(Path(stitch_dir))
    _check_stitch_trial(stitch, trial)
    key = load_key(repo, trial, split, key_lock_path)
    _boot_group_s(stitch)
    dbf = db_path(repo, trial)
    if not dbf.is_file():
        raise EvalError(f"refused: DB {dbf.as_posix()} is missing")
    before = sha256_file(dbf)
    check_db_hash(before, stitch.run_info, key)
    conn = open_db_ro(dbf)
    try:
        facts_db = read_db_facts(conn, key)
    finally:
        conn.close()
    after = sha256_file(dbf)
    check_db_unchanged(before, after)
    keyed, facts, totals = build_rows(trial, split, stitch, key, facts_db)
    files, head = build_files(trial, split, key, keyed, facts, totals)
    info = run_info(repo, trial, split, stitch, dbf, before, after, key, files, generated_utc or utc_now())
    texts = {n: t for n, (t, _k) in files.items()}
    texts[w.RUN_INFO_FILE] = w.json_text(info)
    return TrialResult(trial_id=trial, split=split, keyed_rows=None if keyed is None else tuple(keyed),
                       fact_rows=tuple(facts), total_rows=tuple(totals), headline=head, run_info=info, files=texts)


# ---------------------------------------------------------------- development summary

def _sum_headlines(heads: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Headline numbers summed over trials (ints added; dicts merged by adding; per-hop dicts unioned)."""
    out: dict[str, Any] = {"keyed": any(h.get("keyed") for h in heads)}

    def add(dst: dict, src: Mapping) -> None:
        for k, v in src.items():
            if isinstance(v, bool):
                continue
            if isinstance(v, int):
                dst[k] = dst.get(k, 0) + v
            elif isinstance(v, Mapping):
                add(dst.setdefault(k, {}), v)

    for h in heads:
        add(out, h)
    for k in ("key_uid_source", "key_session_tiers", "evidence_before_range_keyed"):
        out.setdefault(k, {})
    return out


def summary_files(results: Sequence[TrialResult], split: str, generated_utc: str) -> dict[str, str]:
    """Texts of ``out/evaluate/development/``: summary CSV (every keyed row, then the summed totals), summary .md,
    and a run_info.json naming every trial output by SHA-256. Pure."""
    keyed = [r for res in results for r in (res.keyed_rows or ())]
    totals = [r for res in results for r in res.total_rows]
    rows, summed = w.summary_rows(keyed, totals, split)
    head = _sum_headlines([res.headline for res in results])
    files: dict[str, tuple[str, int | None]] = {
        w.SUMMARY_CSV: (w.csv_text(w.SUMMARY_COLUMNS, rows), len(rows)),
        w.SUMMARY_MD: (w.summary_md(split, [(res.trial_id, res.headline) for res in results], head, summed), None)}
    info = {"generated_utc": generated_utc, "tool_version": TOOL_VERSION, "split": split,
            "trials": {res.trial_id: res.run_info["files"] for res in results}, "files": w.file_facts(files)}
    texts = {n: t for n, (t, _k) in files.items()}
    texts[w.RUN_INFO_FILE] = w.json_text(info)
    return texts
