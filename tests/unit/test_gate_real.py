"""Real-data acceptance tests GTA-00 .. GTA-05 and GTA-07 for the gate stage (docs/specs/02_gate.md section 7,
"Real-data tests"), on clock-corrected times (T6b.2, decision 043).

Development data only (decision 019): the six t00 trials s02..s07. The gate is run into a temporary directory and the
result is compared with the CLI outputs already in `out/gate/<trial>/`. The approved answer keys are read by THIS
TEST only (`src/gate` never opens `ground_truth/`, GTT-14). GTA-06 (raw basis) lives in
`tests/unit/test_trial_window.py`.

Read-only on the real files: `data/trial_windows.csv`, `data/processed/*` and `out/gate/<trial>/` are only READ (a
module fixture checks their hashes before and after); every gate / window run writes into a temporary directory, and
the report goes to `out/gate_tests/gta_report.md`.

Expectations are built from the spec and the answer keys. The trigger-type event set of GTA-04 is computed here from
the DB per spec section 3 (dispositions definition), not with the gate's own classifier.

All tests are `@pytest.mark.slow`. Nothing is changed to make a test pass; a failure is reported as it is.
`test_gta_report` writes `out/gate_tests/gta_report.md` (report only, asserts nothing beyond the file being written).
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from gate.inputs import GateError  # noqa: E402
from gate.run import run_gate  # noqa: E402
from trial_window import __main__ as tw_main  # noqa: E402

TRIALS = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00"]
PROCESSED = REPO / "data" / "processed"
WINDOWS = REPO / "data" / "trial_windows.csv"
OUT_GATE = REPO / "out" / "gate"
OUT_REPORT = REPO / "out" / "gate_tests"          # the report is NOT written under out/gate (read-only for tests)
APPROVED = REPO / "ground_truth" / "approved"
#: spec 08 CO-09: statuses whose offset is subtracted; none / stale keep the raw time.
APPLIED_STATUSES = frozenset({"reference", "ok", "wide"})
NEAR_WINDOW_US = 300_000_000                       # spec 5 NEAR_WINDOW_S = 300 s
HEX64 = re.compile(r"^[0-9a-f]{64}$")

#: GT-02: non-lab workstations, compared after strip and `::ffff:` normalisation (spec section 2).
EXCLUDED_IPS = frozenset({"192.168.50.97", "192.168.50.98", "192.168.50.99"})
BYTE_COMPARED_FILES = ["triggers.csv", "unmatched_remote.csv", "dispositions.csv", "supporting.csv", "stats.json",
                       "report.md"]
CSV_FILES = ["triggers.csv", "unmatched_remote.csv", "dispositions.csv", "supporting.csv"]
DISPOSITION_NAMES = ["excluded_source_ip", "excluded_source_ip_session", "interactive_logon", "system_logon_id",
                     "loopback_or_self", "paired_excluded", "trigger", "supporting", "unmatched_remote", "no_rule"]
GTA02_HOP = "s05-t1"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_US = timedelta(microseconds=1)


# ------------------------------------------------------------------------------------------------ small helpers

def to_us(text: str) -> int:
    """ISO text (Z or offset, ms or us) to integer microseconds since the epoch: a parsed instant, never text."""
    dt = datetime.fromisoformat(str(text).strip())
    if dt.tzinfo is None:
        raise ValueError(f"timestamp without zone: {text!r}")
    return (dt.astimezone(timezone.utc) - _EPOCH) // _US


def norm_ip(value: Any) -> str | None:
    """Spec section 2: strip, `::ffff:a.b.c.d` -> `a.b.c.d`; blank, `-` and NULL are None (never equal to anything)."""
    if value is None:
        return None
    text = str(value).strip()
    if text in ("", "-"):
        return None
    if text.lower().startswith("::ffff:") and "." in text:
        text = text[7:]
    return text


def logon_int(value: Any) -> int | None:
    """Integer logon ID from an int, a numeric text or a hex text (`0x1a9231`); None for NULL/blank."""
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def read_csv(path: Path) -> list[dict[str, str]]:
    """All rows of a CSV file as dicts (text)."""
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def open_ro(trial: str) -> sqlite3.Connection:
    """Read-only connection to the trial DB (URI mode=ro), rows as sqlite3.Row."""
    con = sqlite3.connect(f"file:{(PROCESSED / f'{trial}.sqlite3').as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


_OFFSETS: dict[str, dict[str, tuple[int | None, str]]] = {}


def offsets_of(trial: str) -> dict[str, tuple[int | None, str]]:
    """host -> (offset_ms or None, status) from data/processed/<trial>.clock_offsets.csv (read by the test itself)."""
    if trial not in _OFFSETS:
        path = PROCESSED / f"{trial}.clock_offsets.csv"
        out: dict[str, tuple[int | None, str]] = {}
        if path.exists():
            for r in read_csv(path):
                out[r["host"]] = (int(r["offset_ms"]) if r["offset_ms"].strip() else None, r["offset_status"])
        _OFFSETS[trial] = out
    return _OFFSETS[trial]


def corrected_us(trial: str, host: str, raw_us: int) -> int:
    """Spec 08 CO-09, computed here independently: raw - offset_ms for reference / ok / wide, raw for none / stale."""
    offset, status = offsets_of(trial).get(host, (None, "none"))
    return raw_us - offset * 1000 if status in APPLIED_STATUSES and offset is not None else raw_us


def sha256_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _real_files() -> list[Path]:
    """The real files these tests must only read: the window file and every file of out/gate/<trial>/."""
    files = [WINDOWS]
    for t in TRIALS:
        d = OUT_GATE / t
        if d.is_dir():
            files += sorted(d.iterdir())
    return [f for f in files if f.is_file()]


@pytest.fixture(scope="module", autouse=True)
def real_files_are_only_read():
    """Teardown check: no test of this module changed data/trial_windows.csv or anything under out/gate/<trial>/."""
    before = {f: sha256_of(f) for f in _real_files()}
    yield
    after = {f: sha256_of(f) for f in _real_files()}
    assert before == after, f"a test wrote a real file: {sorted(str(f) for f in set(before) ^ set(after))} " \
                            f"{sorted(str(f) for f in before if f in after and before[f] != after[f])}"


def window_row(trial: str) -> dict[str, str] | None:
    """The trial's row of data/trial_windows.csv, or None."""
    if not WINDOWS.exists():
        return None
    for row in read_csv(WINDOWS):
        if row["trial_id"] == trial:
            return row
    return None


def window_us(row: dict[str, str]) -> tuple[int, int]:
    """(start, end + 1 ms) in microseconds: `start <= t < end + 1 ms` (GT-01)."""
    return to_us(row["start_utc"]), to_us(row["end_utc"]) + 1000


def load_key(trial: str) -> dict:
    """Approved answer key (JSON text in a .yaml file). Read by the test only."""
    p = APPROVED / f"{trial}.yaml"
    if not p.exists():
        pytest.skip(f"{p} missing")
    return json.loads(p.read_text(encoding="utf-8"))


def key_hops(trial: str) -> list[dict]:
    """The hops of the approved key of `trial`, [] if the key file is absent (used at collection time)."""
    p = APPROVED / f"{trial}.yaml"
    return json.loads(p.read_text(encoding="utf-8"))["hops"] if p.exists() else []


def _hop_params() -> list[Any]:
    """pytest params (trial, hop_id) for every key hop of the six trials, one test id per hop."""
    return [pytest.param(t, h["hop_id"], id=f"{t}-{h['hop_id']}") for t in TRIALS for h in key_hops(t)]


# ------------------------------------------------------------------------------------------------ gate run fixture

@dataclass
class GateRun:
    """One gate run into a temporary directory, with its outputs parsed."""

    trial: str
    out_dir: Path
    window: dict[str, str]
    triggers: list[dict[str, str]]
    unmatched: list[dict[str, str]]
    supporting: list[dict[str, str]]
    dispositions: list[dict[str, str]]
    stats: dict
    error: str | None = None
    csv_text: dict[str, str] = field(default_factory=dict)


@pytest.fixture(scope="module")
def gate_runs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, GateRun | str]:
    """Runs `gate.run.run_gate` once per trial into a temp dir. Value is a GateRun, or a text for a trial that
    cannot be run (`SKIP: ...` data missing, `ERROR: ...` the gate refused / failed)."""
    root = tmp_path_factory.mktemp("gate_real")
    runs: dict[str, GateRun | str] = {}
    for trial in TRIALS:
        db = PROCESSED / f"{trial}.sqlite3"
        win = window_row(trial)
        if not db.exists():
            runs[trial] = f"SKIP: {db} missing"
            continue
        if win is None:
            runs[trial] = f"SKIP: no row for {trial} in {WINDOWS}"
            continue
        try:
            run_gate(trial, db, WINDOWS, root, repo=REPO)
        except GateError as exc:
            runs[trial] = f"ERROR: GateError: {exc}"
            continue
        out = root / trial
        runs[trial] = GateRun(
            trial=trial, out_dir=out, window=win,
            triggers=read_csv(out / "triggers.csv"), unmatched=read_csv(out / "unmatched_remote.csv"),
            supporting=read_csv(out / "supporting.csv"), dispositions=read_csv(out / "dispositions.csv"),
            stats=json.loads((out / "stats.json").read_text(encoding="utf-8")),
            csv_text={n: (out / n).read_text(encoding="utf-8") for n in CSV_FILES})
    return runs


def need(runs: dict[str, GateRun | str], trial: str) -> GateRun:
    """The GateRun of `trial`; skip if its data is missing, fail if the gate itself refused or crashed."""
    r = runs[trial]
    if isinstance(r, str):
        if r.startswith("SKIP"):
            pytest.skip(r)
        pytest.fail(f"{trial}: {r}")
    return r


# ------------------------------------------------------------------------------------------------ hop resolution

def db_rows(con: sqlite3.Connection, uids: Iterable[str]) -> dict[str, sqlite3.Row]:
    """events_dedup rows for the given uids (uids absent from the view are simply missing)."""
    uids = sorted(set(uids))
    out: dict[str, sqlite3.Row] = {}
    for i in range(0, len(uids), 500):
        chunk = uids[i:i + 500]
        q = "SELECT * FROM events_dedup WHERE event_uid IN (%s)" % ",".join("?" * len(chunk))
        for row in con.execute(q, chunk):
            out[row["event_uid"]] = row
    return out


def resolve_hop(trial: str, hop: dict, con: sqlite3.Connection) -> tuple[str, str]:
    """(kind, uid) of the hop's gate anchor: kind `4624` (the single 4624 in `target_event_uids` on `target_host` with
    the hop's target logon ID, compared as integers) or `7045` (a hop with no such 4624 but exactly one 7045 on the
    target host). Fails loudly, listing the candidates, if neither is unique."""
    want = logon_int(hop["target_logon_id"])
    rows = db_rows(con, hop["target_event_uids"])
    c4624 = [u for u, r in rows.items() if r["event_id"] == 4624 and r["channel"] == "Security"
             and r["host"] == hop["target_host"] and logon_int(r["target_logon_id"]) == want]
    if len(c4624) == 1:
        return "4624", c4624[0]
    if len(c4624) > 1:
        pytest.fail(f"{trial} {hop['hop_id']}: {len(c4624)} 4624 candidates for logon {hop['target_logon_id']} on "
                    f"{hop['target_host']}: {sorted(c4624)}")
    c7045 = [u for u, r in rows.items() if r["event_id"] == 7045 and r["host"] == hop["target_host"]]
    if len(c7045) == 1:
        return "7045", c7045[0]
    listing = [(u, r["host"], r["channel"], r["event_id"], r["target_logon_id"]) for u, r in rows.items()]
    pytest.fail(f"{trial} {hop['hop_id']}: no unique 4624 (0 found) and {len(c7045)} 7045 on {hop['target_host']} "
                f"for logon {hop['target_logon_id']}; target events in DB: {listing}; "
                f"{len(hop['target_event_uids']) - len(rows)} key uid(s) not in events_dedup")


def trigger_rows_for(run: GateRun, kind: str, uid: str) -> list[dict[str, str]]:
    """triggers.csv rows tied to the hop: `anchor_logon_uid` == uid (4624 hop) or `trigger_event_uid` == uid (7045)."""
    col = "anchor_logon_uid" if kind == "4624" else "trigger_event_uid"
    return [r for r in run.triggers if r[col] == uid]


def loose_trigger_rows_for(run: GateRun, uid: str) -> list[dict[str, str]]:
    """triggers.csv rows that name the uid as anchor or as trigger event (background hops, report)."""
    return [r for r in run.triggers if uid in (r["anchor_logon_uid"], r["trigger_event_uid"])]


def unmatched_rows_for(run: GateRun, uid: str) -> list[dict[str, str]]:
    """unmatched_remote.csv rows of the 4624 `uid` (columns `anchor_logon_uid` and `trigger_event_uid`)."""
    return [r for r in run.unmatched if uid in (r["anchor_logon_uid"], r["trigger_event_uid"])]


def hop_by_id(trial: str, hop_id: str) -> dict:
    """The key hop `hop_id` of `trial`."""
    hops = [h for h in load_key(trial)["hops"] if h["hop_id"] == hop_id]
    assert len(hops) == 1, f"{trial}: {len(hops)} hops named {hop_id}"
    return hops[0]


# ------------------------------------------------------------------------------------------------ test 0: outputs

@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_gta00_outputs_match_cli_run(gate_runs, trial):
    """Every output file except run_info.json is byte-identical between this run and `out/gate/<trial>/` (GTT-08)."""
    run = need(gate_runs, trial)
    cli = OUT_GATE / trial
    if not cli.exists():
        pytest.skip(f"{cli} missing (CLI not run for {trial})")
    diffs = []
    for name in BYTE_COMPARED_FILES:
        a, b = run.out_dir / name, cli / name
        if not b.exists():
            diffs.append(f"{name}: missing in {cli}")
        elif a.read_bytes() != b.read_bytes():
            diffs.append(f"{name}: differs ({a.stat().st_size} vs {b.stat().st_size} bytes)")
    assert diffs == [], f"{trial}: " + "; ".join(diffs)


# ------------------------------------------------------------------------------------------------ GTA-01

def _hop_state(run: GateRun, hop: dict, con: sqlite3.Connection) -> dict[str, Any]:
    """Where the hop is: kind, uid, strict trigger rows (anchor / 7045 trigger), loose trigger rows, unmatched rows."""
    kind, uid = resolve_hop(run.trial, hop, con)
    return {"kind": kind, "uid": uid, "strict": trigger_rows_for(run, kind, uid),
            "loose": loose_trigger_rows_for(run, uid), "unmatched": unmatched_rows_for(run, uid)}


@pytest.mark.slow
@pytest.mark.parametrize("trial,hop_id", _hop_params())
def test_gta01_hop_is_not_a_miss(gate_runs, trial, hop_id):
    """GTA-01, miss check: EVERY key hop (attack, benign, background) is in triggers.csv (by anchor or trigger uid)
    or in unmatched_remote.csv. A hop in neither file is a MISS, which stops the task (CLAUDE.md stop rule)."""
    run = need(gate_runs, trial)
    hop = hop_by_id(trial, hop_id)
    con = open_ro(trial)
    try:
        st = _hop_state(run, hop, con)
    finally:
        con.close()
    assert st["loose"] or st["unmatched"], (
        f"MISS: {trial} {hop_id} ({hop['role']}, {hop['protocol']}, target {hop['target_host']}, logon "
        f"{hop['target_logon_id']}, {st['kind']} uid {st['uid']}) is in neither triggers.csv nor unmatched_remote.csv")


@pytest.mark.slow
@pytest.mark.parametrize("trial,hop_id", _hop_params())
def test_gta01_hop_has_trigger_row(gate_runs, trial, hop_id):
    """GTA-01, trigger check: an ATTACK or BENIGN hop has a triggers.csv row whose `anchor_logon_uid` is the hop's
    target 4624 uid (a 7045-only hop: `trigger_event_uid` is the 7045). A BACKGROUND hop passes if it is in
    triggers.csv (anchor or trigger uid) or in unmatched_remote.csv. An attack/benign hop found only in
    unmatched_remote.csv fails here with a message saying so (owner review, not a stop)."""
    run = need(gate_runs, trial)
    hop = hop_by_id(trial, hop_id)
    con = open_ro(trial)
    try:
        st = _hop_state(run, hop, con)
    finally:
        con.close()
    label = f"{trial} {hop_id} ({hop['role']}, {hop['protocol']}, {st['kind']} uid {st['uid']})"
    if hop["role"] == "background":
        assert st["loose"] or st["unmatched"], f"MISS: {label} is in neither file"
        return
    assert hop["role"] in ("attack", "benign"), f"{label}: unknown role {hop['role']!r}"
    if st["strict"]:
        return
    if st["unmatched"]:
        pytest.fail(f"ONLY-UNMATCHED (owner review, not a stop): {label} has no triggers.csv row with the hop's "
                    f"{'anchor' if st['kind'] == '4624' else 'trigger event'} uid; it is in unmatched_remote.csv "
                    f"({[(u['trigger_id'], u['method'], u['gate_tier']) for u in st['unmatched']]})")
    pytest.fail(f"MISS: {label} is in neither triggers.csv nor unmatched_remote.csv")


# ------------------------------------------------------------------------------------------------ GTA-02

def _find_in_db(trial: str, uid: str, ref: sqlite3.Row) -> list[sqlite3.Row]:
    """The reference 4624 in another trial's DB: same uid, else (host, record_id, event_utc) of the reference."""
    con = open_ro(trial)
    try:
        by_uid = list(con.execute("SELECT * FROM events_dedup WHERE event_uid = ?", (uid,)))
        if by_uid:
            return by_uid
        return list(con.execute("SELECT * FROM events_dedup WHERE host = ? AND record_id = ? AND event_utc = ? "
                                "AND event_id = 4624", (ref["host"], ref["record_id"], ref["event_utc"])))
    finally:
        con.close()


def gta02_facts(runs: dict[str, GateRun | str]) -> dict[str, Any]:
    """Facts for GTA-02 (key hop s05-t1 = admin_it, ep-02, type 3 from 192.168.50.21, 07:05:15.541). Never raises for
    missing data: problems are listed in `problems`."""
    facts: dict[str, Any] = {"problems": [], "trials": {}}
    try:
        hop = hop_by_id("s05_t00", GTA02_HOP)
        con = open_ro("s05_t00")
        try:
            kind, uid = resolve_hop("s05_t00", hop, con)
            ref = con.execute("SELECT * FROM events_dedup WHERE event_uid = ?", (uid,)).fetchone()
        finally:
            con.close()
    except BaseException as exc:  # pytest.fail / skip raise BaseException subclasses
        facts["problems"].append(f"cannot resolve key hop {GTA02_HOP} in s05_t00: {exc}")
        return facts
    facts.update(uid=uid, kind=kind, host=ref["host"], record_id=ref["record_id"], event_utc=ref["event_utc"],
                 logon_type=ref["logon_type"], source_ip=ref["source_ip"], account=ref["account_name"],
                 key_move_time=hop["move_time_utc"], key_account=hop["account"], key_source_ip=hop["source_ip"])
    for trial in ("s05_t00", "s06_t00", "s07_t00"):
        info: dict[str, Any] = {"in_db": False}
        facts["trials"][trial] = info
        if not (PROCESSED / f"{trial}.sqlite3").exists():
            facts["problems"].append(f"{trial}: DB missing")
            continue
        found = _find_in_db(trial, uid, ref)
        info["matches"] = [r["event_uid"] for r in found]
        info["in_db"] = len(found) == 1
        info["uid_equal"] = bool(found) and found[0]["event_uid"] == uid
        run = runs.get(trial)
        if isinstance(run, str) or run is None:
            facts["problems"].append(f"{trial}: no gate run ({run})")
            continue
        if len(found) != 1:
            continue
        row = found[0]
        lo, hi = window_us(run.window)
        t = corrected_us(trial, row["host"], to_us(row["event_utc"]))       # the window is on corrected times
        info.update(event_utc=row["event_utc"], inside=lo <= t < hi, window=(run.window["start_utc"],
                                                                              run.window["end_utc"]))
        mine = row["event_uid"]
        in_files = [n for n in CSV_FILES if mine in run.csv_text[n] or uid in run.csv_text[n]]
        info["in_files"] = in_files
        info["trigger_rules"] = sorted({r["rule"] for r in loose_trigger_rows_for(run, mine)})
        info["trigger_tiers"] = sorted({r["gate_tier"] for r in loose_trigger_rows_for(run, mine)})
        info["unmatched"] = [(u["trigger_id"], u["method"], u["gate_tier"]) for u in unmatched_rows_for(run, mine)]
        info["dispositions"] = sorted({d["disposition"] for d in run.dispositions if d["event_uid"] == mine})
    return facts


@pytest.mark.slow
def test_gta02_s05_t1_logon_in_three_dbs_and_window_behaviour(gate_runs):
    """GTA-02: the admin_it type 3 logon on ep-02 from 192.168.50.21 at 07:05:15.541 (key hop s05-t1) is in the s05,
    s06 and s07 t00 DBs. In s06 and s07 it is outside the window and its uid is in no row of any output CSV. In s05 it
    is inside the window and has a trigger or an unmatched_remote row (the rule is reported)."""
    for t in ("s05_t00", "s06_t00", "s07_t00"):
        need(gate_runs, t)
    f = gta02_facts(gate_runs)
    assert f["problems"] == [], f"GTA-02 setup problems: {f['problems']}"
    assert f["host"] == "ep-02" and f["logon_type"] == 3 and norm_ip(f["source_ip"]) == "192.168.50.21" \
        and f["account"] == "admin_it", f"key hop s05-t1 resolves to an unexpected 4624: {f}"
    assert abs(to_us(f["event_utc"]) - to_us(f["key_move_time"])) < 1000, \
        f"4624 time {f['event_utc']} != key move time {f['key_move_time']}"
    errs: list[str] = []
    for t, info in f["trials"].items():
        if not info["in_db"]:
            errs.append(f"{t}: the 4624 is not in the DB exactly once (matches: {info.get('matches')})")
            continue
        if t == "s05_t00":
            if not info["inside"]:
                errs.append(f"{t}: {info['event_utc']} is outside the window {info['window']}")
            if not (info["trigger_rules"] or info["unmatched"]):
                errs.append(f"{t}: in neither triggers.csv nor unmatched_remote.csv (files containing uid: "
                            f"{info['in_files']})")
        else:
            if info["inside"]:
                errs.append(f"{t}: {info['event_utc']} is INSIDE the window {info['window']}")
            if info["in_files"]:
                errs.append(f"{t}: the uid appears in output file(s) {info['in_files']}")
    assert errs == [], "GTA-02: " + "; ".join(errs)


# ------------------------------------------------------------------------------------------------ GTA-03

def _parse_or_fail(text: str, what: str) -> int:
    """to_us, but with a message naming the offending value."""
    try:
        return to_us(text)
    except (ValueError, TypeError) as exc:
        pytest.fail(f"{what}: unparseable time {text!r} ({exc})")


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_gta03_rows_inside_window_and_no_excluded_ip(gate_runs, trial):
    """GTA-03 (T6b.2): no row of triggers.csv, unmatched_remote.csv or supporting.csv has `event_utc_corrected` outside
    `start <= t < end + 1 ms` (corrected window) or an excluded `source_ip` (.97/.98/.99, after strip and `::ffff:`
    normalisation); no `stats.json` `tier_d_ip_lookup` entry has an excluded IP among its `source_ips`."""
    run = need(gate_runs, trial)
    lo, hi = window_us(run.window)
    problems: list[str] = []
    for name, rows in (("triggers.csv", run.triggers), ("unmatched_remote.csv", run.unmatched),
                       ("supporting.csv", run.supporting)):
        for i, r in enumerate(rows, start=2):
            t = _parse_or_fail(r["event_utc_corrected"], f"{name} line {i}")
            uid = r.get("trigger_event_uid") or r.get("event_uid")
            if not lo <= t < hi:
                problems.append(f"{name} line {i} uid {uid}: event_utc_corrected {r['event_utc_corrected']} outside "
                                f"[{run.window['start_utc']}, {run.window['end_utc']}+1ms)")
            if norm_ip(r.get("source_ip")) in EXCLUDED_IPS:
                problems.append(f"{name} line {i} uid {uid}: excluded source_ip {r['source_ip']}")
    for e in run.stats["tier_d_ip_lookup"]:
        bad = [ip for ip in e["source_ips"] if norm_ip(ip) in EXCLUDED_IPS]
        if bad:
            problems.append(f"tier_d_ip_lookup {e['trigger_id']} ({e['host']} {e['logon_id_hex']}): excluded {bad}")
    assert problems == [], f"{trial}:\n" + "\n".join(problems)


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_gta03b_event_utc_corrected_is_event_utc_minus_the_hosts_offset_in_every_csv(gate_runs, trial):
    """GTA-03 / CO-09 on real data: in all four CSVs `event_utc_corrected` = `event_utc` - offset_ms(host) (offset from
    the trial offsets file, read here; none / stale hosts keep raw), to the microsecond."""
    run = need(gate_runs, trial)
    bad: list[str] = []
    for name, rows in (("triggers.csv", run.triggers), ("unmatched_remote.csv", run.unmatched),
                       ("dispositions.csv", run.dispositions), ("supporting.csv", run.supporting)):
        for i, r in enumerate(rows, start=2):
            want = corrected_us(trial, r["host"], to_us(r["event_utc"]))
            if to_us(r["event_utc_corrected"]) != want:
                bad.append(f"{name} line {i} ({r['host']}): {r['event_utc_corrected']} != "
                           f"{r['event_utc']} - offset")
    assert bad == [], f"{trial}: {len(bad)} row(s)\n" + "\n".join(bad[:10])


# ------------------------------------------------------------------------------------------------ clock facts

@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_clock_today_facts_no_unreliable_row_no_flag_no_clock_change(gate_runs, trial):
    """Today's facts on the six t00 trials (spec 08 section 10, decision 043 item 9): `clock_unreliable` is 0 in every row of
    all four CSVs, the window `clock_flag` is empty and `clock_change_in_window` is false. If one of these changes the
    owner must review the trial (a flagged row means a host with status none / wide / stale, or events logged before a
    counted clock change, is in the window)."""
    run = need(gate_runs, trial)
    msg = "today's fact (T6b.2 corrected rerun) no longer holds: owner review needed"
    assert run.window["clock_flag"] == "", f"{trial}: window clock_flag {run.window['clock_flag']!r}; {msg}"
    assert run.window["clock_change_in_window"] == "false", f"{trial}: clock_change_in_window; {msg}"
    for name, rows in (("triggers.csv", run.triggers), ("unmatched_remote.csv", run.unmatched),
                       ("dispositions.csv", run.dispositions), ("supporting.csv", run.supporting)):
        flagged = [r for r in rows if r["clock_unreliable"] != "0"]
        assert flagged == [], f"{trial} {name}: {len(flagged)} row(s) with clock_unreliable = 1; {msg}"
        assert {r["clock_flag"] for r in rows} <= {""}, f"{trial} {name}: clock_flag set; {msg}"
        assert {r["clock_change_in_window"] for r in rows} <= {"false"}, f"{trial} {name}: change flag; {msg}"
    ur = run.stats["clock"]["unreliable_rows"]
    assert ur == {"triggers": 0, "unmatched_remote": 0, "dispositions": 0, "supporting": 0}, f"{trial}: {ur}; {msg}"
    assert run.stats["time_basis"] == "corrected" and run.window["time_basis"] == "corrected"


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_window_row_hashes_match_the_clock_files_and_stats_clock_key(gate_runs, trial):
    """Spec 2.1 / 3.1 on real data: the window row `offsets_sha256` / `clock_changes_sha256` equal the SHA-256 of the
    trial files in data/processed, and the stats `clock` key reports the same hashes and the offsets of all four hosts."""
    run = need(gate_runs, trial)
    o, c = PROCESSED / f"{trial}.clock_offsets.csv", PROCESSED / f"{trial}.clock_changes.csv"
    assert run.window["offsets_sha256"] == sha256_of(o) and run.window["clock_changes_sha256"] == sha256_of(c)
    ck = run.stats["clock"]
    assert ck["offsets_sha256"] == sha256_of(o) and ck["clock_changes_sha256"] == sha256_of(c)
    assert set(ck["offsets"]) == set(offsets_of(trial)) == {"dc01", "ep-01", "ep-02", "ep-03"}
    for host, (off, status) in offsets_of(trial).items():
        assert ck["offsets"][host]["offset_ms"] == off and ck["offsets"][host]["offset_status"] == status


# ------------------------------------------------------------------------------------------------ GTA-04

def _ends(value: Any, suffix: str) -> bool:
    """Case-insensitive suffix test, NULL-safe."""
    return value is not None and str(value).lower().endswith(suffix)


def trigger_type_all(trial: str) -> dict[str, tuple[str, int, int]]:
    """uid -> (host, event_id, raw event_utc in us) of EVERY trigger-type event of the DB, per spec section 3 (dispositions.csv):
    4624 type 2/3/10/11; Security 5140/5145; System 7045; Security 4697; Sysmon 1 whose image or parent_image ends
    `\\wsmprovhost.exe`; WinRM 91; Sysmon 3 with destination_port 3389. Computed from the DB alone, no window."""
    out: dict[str, tuple[str, int, int]] = {}
    con = open_ro(trial)
    try:
        for r in con.execute("SELECT event_uid, host, channel, event_id, event_utc, logon_type, image, parent_image, "
                             "destination_port FROM events_dedup"):
            ch, eid = r["channel"], r["event_id"]
            is_trig = (
                (ch == "Security" and eid == 4624 and r["logon_type"] in (2, 3, 10, 11))
                or (ch == "Security" and eid in (5140, 5145, 4697))
                or (ch == "System" and eid == 7045)
                or (ch == "WinRM" and eid == 91)
                or (ch == "Sysmon" and eid == 1 and (_ends(r["image"], "\\wsmprovhost.exe")
                                                     or _ends(r["parent_image"], "\\wsmprovhost.exe")))
                or (ch == "Sysmon" and eid == 3 and r["destination_port"] is not None
                    and str(r["destination_port"]).strip() == "3389"))
            if is_trig:
                if r["event_uid"] in out:
                    pytest.fail(f"{trial}: uid {r['event_uid']} appears twice in events_dedup")
                out[r["event_uid"]] = (r["host"], eid, to_us(r["event_utc"]))
    finally:
        con.close()
    return out


def trigger_type_events(trial: str, window: dict[str, str]) -> dict[str, tuple[str, int]]:
    """uid -> (host, event_id) of every trigger-type event whose CORRECTED time (spec 08 CO-09, computed here from the
    offsets file) is in the corrected window `start <= t < end + 1 ms`."""
    lo, hi = window_us(window)
    return {u: (h, e) for u, (h, e, raw) in trigger_type_all(trial).items()
            if lo <= corrected_us(trial, h, raw) < hi}


def near_window_counts(trial: str, lo: int, hi: int, *, corrected: bool) -> dict[str, dict[str, int]]:
    """host -> {before, after} counts of trigger-type events up to 300 s outside the edges (spec 3: NEAR_WINDOW_S), on
    corrected or raw times; `lo`, `hi` = start and end + 1 ms in us. Hosts with no count are left out."""
    out: dict[str, dict[str, int]] = {}
    for h, _eid, raw in trigger_type_all(trial).values():
        t = corrected_us(trial, h, raw) if corrected else raw
        side = "before" if lo - NEAR_WINDOW_US <= t < lo else "after" if hi <= t < hi + NEAR_WINDOW_US else None
        if side:
            out.setdefault(h, {"before": 0, "after": 0})[side] += 1
    return out


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_gta04_dispositions_partition_trigger_type_events(gate_runs, trial):
    """GTA-04 / GTT-11 on real data: dispositions.csv has exactly one row per in-window trigger-type event (the set is
    recomputed here from the DB per spec section 3), uses only the ten spec names, and its size equals
    `stats.events.trigger_type_in_window` (total and per host)."""
    run = need(gate_runs, trial)
    expected = trigger_type_events(trial, run.window)
    uids = [d["event_uid"] for d in run.dispositions]
    dup = sorted(u for u, n in Counter(uids).items() if n > 1)
    missing = sorted(set(expected) - set(uids))
    extra = sorted(set(uids) - set(expected))
    assert dup == [], f"{trial}: uids with more than one disposition row: {dup[:10]} ({len(dup)})"
    assert missing == [], f"{trial}: trigger-type events with no disposition row: {missing[:10]} ({len(missing)})"
    assert extra == [], f"{trial}: disposition rows for non-trigger-type or out-of-window events: {extra[:10]} ({len(extra)})"
    bad_names = sorted({d["disposition"] for d in run.dispositions} - set(DISPOSITION_NAMES))
    assert bad_names == [], f"{trial}: unknown disposition names {bad_names}"
    ev = run.stats["events"]
    assert ev["trigger_type_in_window"] == len(expected) == len(run.dispositions), \
        f"{trial}: stats {ev['trigger_type_in_window']}, independent {len(expected)}, rows {len(run.dispositions)}"
    per_host = Counter(h for h, _ in expected.values())
    assert {h: n for h, n in ev["trigger_type_in_window_per_host"].items() if n} == dict(per_host), \
        f"{trial}: per-host stats {ev['trigger_type_in_window_per_host']} vs independent {dict(per_host)}"


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_gta04_stats_equal_file_counts(gate_runs, trial):
    """GTA-04: `stats.json` disposition counts equal the file counts (total and per host); `triggers`,
    `unmatched_remote` and `supporting` totals (and per rule / per host) equal the CSV row counts."""
    run = need(gate_runs, trial)
    s = run.stats
    file_total = Counter(d["disposition"] for d in run.dispositions)
    stats_total = {k: v for k, v in s["dispositions"]["total"].items()}
    assert set(stats_total) == set(DISPOSITION_NAMES), f"{trial}: stats disposition names {sorted(stats_total)}"
    assert stats_total == {n: file_total.get(n, 0) for n in DISPOSITION_NAMES}, \
        f"{trial}: stats total {stats_total} vs file {dict(file_total)}"
    file_host: dict[str, Counter] = defaultdict(Counter)
    for d in run.dispositions:
        file_host[d["host"]][d["disposition"]] += 1
    stats_host = {h: {k: v for k, v in c.items() if v} for h, c in s["dispositions"]["per_host"].items()}
    stats_host = {h: c for h, c in stats_host.items() if c}
    assert stats_host == {h: dict(c) for h, c in file_host.items()}, \
        f"{trial}: per-host stats {stats_host} vs file { {h: dict(c) for h, c in file_host.items()} }"
    assert s["triggers"]["total"] == len(run.triggers), f"{trial}: triggers {s['triggers']['total']} vs {len(run.triggers)}"
    assert {k: v for k, v in s["triggers"]["per_rule"].items() if v} == dict(Counter(r["rule"] for r in run.triggers)),         f"{trial}: per_rule {s['triggers']['per_rule']} vs file {dict(Counter(r['rule'] for r in run.triggers))}"
    assert s["unmatched_remote"]["total"] == len(run.unmatched), \
        f"{trial}: unmatched {s['unmatched_remote']['total']} vs {len(run.unmatched)}"
    assert {h: n for h, n in s["unmatched_remote"]["per_host"].items() if n} == dict(Counter(r["host"] for r in run.unmatched)), \
        f"{trial}: unmatched per host {s['unmatched_remote']['per_host']}"
    assert s["supporting"]["total"] == len(run.supporting), \
        f"{trial}: supporting {s['supporting']['total']} vs {len(run.supporting)}"
    assert {k: v for k, v in s["supporting"]["per_rule"].items() if v} == dict(Counter(r["rule"] for r in run.supporting)), \
        f"{trial}: supporting per rule {s['supporting']['per_rule']}"


# ------------------------------------------------------------------------------------------------ GTA-05

GTA05_SKIP = "no development trial with a .97/.98/.99 session (s04_t01 is clock-only, never gated)"


def _excluded_ip_logons(trial: str) -> list[sqlite3.Row]:
    """4624s of the DB whose source_ip (normalised) is .97/.98/.99, whole DB."""
    con = open_ro(trial)
    try:
        return [r for r in con.execute("SELECT * FROM events_dedup WHERE channel = 'Security' AND event_id = 4624")
                if norm_ip(r["source_ip"]) in EXCLUDED_IPS]
    finally:
        con.close()


@pytest.mark.slow
def test_gta05_excluded_ip_logons_on_every_gated_development_trial(gate_runs):
    """GTA-05 (amended, T6b.2): on EVERY development trial gated that has a 4624 from 192.168.50.97/.98/.99, each such logon
    inside the window is `excluded_source_ip`; if that session has a 4697, 7045 or share write (checked from the DB by
    logon id, and in the gate `excluded_ip_with_artefacts`) the test stops and reports to the owner. Skipped with the
    reason below until such a trial exists (none of the t00 trials has one; s04_t01 is clock-only, never gated)."""
    seen: list[str] = []
    for trial in TRIALS:
        run = gate_runs.get(trial)
        if not isinstance(run, GateRun):
            continue
        logons = _excluded_ip_logons(trial)
        if not logons:
            continue
        seen.append(trial)
        lo, hi = window_us(run.window)
        disp = {d["event_uid"]: d["disposition"] for d in run.dispositions}
        for r in logons:
            t = corrected_us(trial, r["host"], to_us(r["event_utc"]))
            if lo <= t < hi:
                assert disp.get(r["event_uid"]) == "excluded_source_ip", \
                    f"{trial}: .97/.98/.99 logon {r['event_uid']} is {disp.get(r['event_uid'])!r}, not excluded_source_ip"
        con = open_ro(trial)
        try:
            lids = {(r["host"], logon_int(r["target_logon_id"])) for r in logons if logon_int(r["target_logon_id"])}
            arts = [(x["event_uid"], x["event_id"]) for x in con.execute(
                "SELECT event_uid, host, event_id, subject_logon_id FROM events_dedup WHERE channel = 'Security' "
                "AND event_id IN (4697, 5140, 5145)") if (x["host"], logon_int(x["subject_logon_id"])) in lids]
        finally:
            con.close()
        if arts or run.stats["excluded"]["excluded_ip_with_artefacts"]:
            pytest.fail(f"STOP, report to the owner: {trial}: an excluded-IP session has a service install or share "
                        f"write: DB events {arts}, gate excluded_ip_with_artefacts "
                        f"{run.stats['excluded']['excluded_ip_with_artefacts']}")
    if not seen:
        pytest.skip(GTA05_SKIP)


# ------------------------------------------------------------------------------------------------ report

def _hop_report_rows(runs: dict[str, GateRun | str]) -> list[list[str]]:
    """One row per key hop: trial, hop_id, role, protocol, uid[:12], move time, where, gate tier(s)."""
    rows: list[list[str]] = []
    for trial in TRIALS:
        run = runs.get(trial)
        for h in key_hops(trial):
            base = [trial, h["hop_id"], h["role"], h["protocol"]]
            if not isinstance(run, GateRun):
                rows.append(base + ["n/a", h["move_time_utc"], f"NO RUN ({run})", ""])
                continue
            con = open_ro(trial)
            try:
                try:
                    kind, uid = resolve_hop(trial, h, con)
                except BaseException as exc:
                    rows.append(base + ["UNRESOLVED", h["move_time_utc"], f"UNRESOLVED: {str(exc)[:120]}", ""])
                    continue
            finally:
                con.close()
            trig, unm = loose_trigger_rows_for(run, uid), unmatched_rows_for(run, uid)
            where = []
            if trig:
                where.append("triggers.csv [" + ",".join(sorted({r["rule"] for r in trig})) + "]")
            if unm:
                where.append("unmatched_remote.csv")
            tiers = sorted({r["gate_tier"] for r in trig + unm})
            rows.append(base + [f"{uid[:12]}{'' if kind == '4624' else ' (7045)'}", h["move_time_utc"],
                                " + ".join(where) or "NEITHER", ",".join(tiers)])
    return rows


def _md_table(header: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """A markdown table."""
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(c).replace("|", "/") for c in row) + " |" for row in rows]
    return "\n".join(lines)


def _sysmon3_3389(trial: str, window: dict[str, str] | None) -> dict[str, int]:
    """Counts of Sysmon 3 events on port 3389 in the whole DB and in the window (`initiated` NULL/blank variant too)."""
    con = open_ro(trial)
    try:
        rows = list(con.execute("SELECT event_uid, event_utc, initiated, source_port, destination_port FROM events_dedup "
                                "WHERE channel = 'Sysmon' AND event_id = 3 AND (CAST(destination_port AS TEXT) = '3389' "
                                "OR CAST(source_port AS TEXT) = '3389')"))
    finally:
        con.close()
    lo, hi = window_us(window) if window else (0, 0)

    def blank(r: sqlite3.Row) -> bool:
        return r["initiated"] is None or str(r["initiated"]).strip() == ""

    return {"all_3389_whole_db": len(rows), "all_3389_in_window": sum(lo <= to_us(r["event_utc"]) < hi for r in rows),
            "initiated_blank_whole_db": sum(blank(r) for r in rows),
            "initiated_blank_in_window": sum(blank(r) and lo <= to_us(r["event_utc"]) < hi for r in rows)}


def near_window_rows(runs: dict[str, GateRun | str], raw_windows: dict[str, dict[str, str]]) -> list[list[str]]:
    """Per trial: near_window counts (host: before/after) on the raw basis (raw window from trial_window, raw times) and on the
    corrected basis (gate stats, and the independent recount of this test)."""
    rows = []
    for trial in TRIALS:
        run = runs.get(trial)
        raw_w = raw_windows.get(trial)
        if not isinstance(run, GateRun) or raw_w is None:
            rows.append([trial, "n/a", "n/a", "n/a", "n/a"])
            continue

        def fmt(d: dict[str, dict[str, int]]) -> str:
            return "; ".join(f"{h} {c['before']}/{c['after']}" for h, c in sorted(d.items()) if c["before"] or c["after"]) or "-"
        lo, hi = window_us(raw_w)
        raw_counts = near_window_counts(trial, lo, hi, corrected=False)
        clo, chi = window_us(run.window)
        cor_counts = near_window_counts(trial, clo, chi, corrected=True)
        stats_counts = {h: c for h, c in run.stats["near_window"].items() if c["before"] or c["after"]}
        rows.append([trial, f"{raw_w['start_utc']} .. {raw_w['end_utc']}", fmt(raw_counts),
                     f"{run.window['start_utc']} .. {run.window['end_utc']}",
                     f"{fmt(stats_counts)} (recount {'equal' if cor_counts == stats_counts else 'DIFFERS: ' + fmt(cor_counts)})"])
    return rows


def build_report(runs: dict[str, GateRun | str], raw_windows: dict[str, dict[str, str]] | None = None) -> str:
    """The GTA report text (markdown)."""
    parts = ["# Gate real-data acceptance report (GTA-01..GTA-05, GTA-07)", "",
             "Development trials s02..s07 t00, clock-corrected times (T6b.2). Gate run by the test into a temp dir "
             "(byte-compared with `out/gate/<trial>/` by `test_gta00_outputs_match_cli_run`).", ""]
    summary = []
    for trial in TRIALS:
        run = runs.get(trial)
        if not isinstance(run, GateRun):
            summary.append([trial, f"no run: {run}", "", "", "", ""])
            continue
        s = run.stats
        disp = Counter((d["event_id"], d["disposition"]) for d in run.dispositions)
        n_excl_4624 = disp.get(("4624", "excluded_source_ip"), 0)
        n_excl_sess = sum(n for (_, name), n in disp.items() if name == "excluded_source_ip_session")
        per_rule = Counter(r["rule"] for r in run.triggers)
        summary.append([trial, f"{len(run.triggers)} " + json.dumps(dict(sorted(per_rule.items()))),
                        len(run.unmatched), n_excl_4624, n_excl_sess,
                        f"{len(s['excluded']['excluded_ip_with_artefacts'])}; per_ip={json.dumps(s['excluded']['per_ip'])}"])
    parts += ["## Triggers, unmatched remote and excluded-IP sessions", "",
              _md_table(["trial", "triggers total and per rule", "unmatched_remote total",
                         "4624 `excluded_source_ip`", "events `excluded_source_ip_session`",
                         "`excluded_ip_with_artefacts` entries; stats excluded.per_ip"], summary), ""]
    parts += ["## Key hops (approved answer keys)", "",
              _md_table(["trial", "hop_id", "role", "protocol", "target 4624 uid (12)", "move time (key)", "where",
                         "gate_tier(s)"], _hop_report_rows(runs)), ""]
    s3 = []
    for trial in TRIALS:
        run = runs.get(trial)
        if not (PROCESSED / f"{trial}.sqlite3").exists():
            s3.append([trial, "DB missing", "", "", ""])
            continue
        c = _sysmon3_3389(trial, run.window if isinstance(run, GateRun) else window_row(trial))
        s3.append([trial, c["all_3389_whole_db"], c["initiated_blank_whole_db"], c["initiated_blank_in_window"],
                   c["all_3389_in_window"]])
    parts += ["## Sysmon 3 on port 3389 (destination_port or source_port = 3389)", "",
              "`initiated` NULL/blank is the case of the spec 2 note on RDP by IP under NLA. A 0 in the blank columns "
              "means no such event; the first column says whether there is any 3389 Sysmon 3 at all.", "",
              _md_table(["trial", "all 3389 Sysmon 3, whole DB", "initiated NULL/blank, whole DB",
                         "initiated NULL/blank, in window", "all 3389 Sysmon 3, in window"], s3), ""]
    parts += ["## near_window counts (trigger-type events up to 300 s outside an edge; host before/after)", "",
              "Raw basis: the raw window (trial_window, GTA-06 basis) and raw event times, counted by this test. Corrected "
              "basis: the window row of `data/trial_windows.csv`, the gate `stats.json` counts, and this test's recount.", "",
              _md_table(["trial", "raw window", "raw near_window", "corrected window", "corrected near_window"],
                        near_window_rows(runs, raw_windows or {})), ""]
    f = gta02_facts(runs)
    parts += ["## GTA-02 (key hop s05-t1)", ""]
    if f["problems"] and "uid" not in f:
        parts.append("Could not evaluate: " + "; ".join(f["problems"]))
    else:
        parts.append(f"4624 uid `{f['uid']}`, host {f['host']}, record_id {f['record_id']}, time {f['event_utc']}, "
                     f"type {f['logon_type']}, source {f['source_ip']}, account {f['account']}.")
        parts.append("")
        parts.append(_md_table(["trial", "in DB once", "same uid", "event_utc", "inside window", "window",
                                "output CSVs containing the uid", "rules / unmatched / dispositions"],
                               [[t, i.get("in_db"), i.get("uid_equal", ""), i.get("event_utc", ""), i.get("inside", ""),
                                 " .. ".join(i.get("window", ())), ",".join(i.get("in_files", [])) or "none",
                                 f"rules={i.get('trigger_rules')} tiers={i.get('trigger_tiers')} "
                                 f"unmatched={i.get('unmatched')} dispositions={i.get('dispositions')}"]
                                for t, i in f["trials"].items()]))
        if f["problems"]:
            parts += ["", "Problems: " + "; ".join(f["problems"])]
    return "\n".join(parts) + "\n"


@pytest.fixture(scope="module")
def raw_windows(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, str]]:
    """trial -> raw-basis window row (trial_window, `time_basis="raw"`, the GTA-06 basis), written to a temp dir only."""
    out = tmp_path_factory.mktemp("raw_windows") / "w.csv"
    trials = [t for t in TRIALS if (PROCESSED / f"{t}.sqlite3").exists()]
    if not trials:
        return {}
    res = tw_main.run(REPO, trials, REPO / "data" / "operator_times.csv", out, time_basis="raw")
    return {r["trial_id"]: r for r in res["rows"]}


@pytest.mark.slow
def test_gta_report(gate_runs, raw_windows):
    """Report only: writes and prints `out/gate_tests/gta_report.md` (not under out/gate: tests only read that folder)."""
    text = build_report(gate_runs, raw_windows)
    OUT_REPORT.mkdir(parents=True, exist_ok=True)
    dest = OUT_REPORT / "gta_report.md"
    dest.write_text(text, encoding="utf-8")
    print("\n" + text)
    assert dest.exists()


# ------------------------------------------------------------------------------------------------ GTA-07

def key_uids(trial: str) -> set[str]:
    """Every event uid under the key hops (attack, benign, background, with supporting events); content hashes
    (a key path containing `sha256`) are not event uids."""
    found: set[str] = set()

    def walk(obj: Any, path: tuple[str, ...]) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, path + (str(k),))
        elif isinstance(obj, list):
            for v in obj:
                walk(v, path)
        elif isinstance(obj, str) and HEX64.match(obj) and not any("sha256" in q.lower() for q in path):
            found.add(obj)

    walk(load_key(trial)["hops"], ())
    return found


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_gta07_every_key_hop_event_is_inside_the_corrected_window(gate_runs, trial):
    """GTA-07 (new, spec 08 4.1 item 8 / ATK-11): on the corrected basis every key-hop event (attack, benign, background,
    with supporting events) has its `event_utc_corrected` (event_utc - offset of its host, computed here from the offsets
    file) inside the corrected window `start <= t < end + 1 ms` of `data/trial_windows.csv`, so the clip removes none."""
    run = need(gate_runs, trial)
    uids = sorted(key_uids(trial))
    assert uids, f"{trial}: no uid under the key hops"
    lo, hi = window_us(run.window)
    con = open_ro(trial)
    try:
        rows = db_rows(con, uids)
    finally:
        con.close()
    missing = [u for u in uids if u not in rows]
    assert missing == [], f"{trial}: key-hop uids missing from events_dedup: {missing}"
    outside = []
    for u in uids:
        r = rows[u]
        t = corrected_us(trial, r["host"], to_us(r["event_utc"]))
        if not lo <= t < hi:
            outside.append(f"uid={u} host={r['host']} event_id={r['event_id']} event_utc={r['event_utc']} "
                           f"corrected_us={t} (window {run.window['start_utc']} .. {run.window['end_utc']})")
    assert outside == [], f"{trial}: {len(outside)} key-hop event(s) clipped on the corrected basis:\n" + "\n".join(outside)


@pytest.mark.slow
@pytest.mark.parametrize("trial,hop_id", _hop_params())
def test_gta07_every_key_hop_has_its_trigger_row_at_tier_a(gate_runs, trial, hop_id):
    """GTA-07 (new) / GTA-01: on the corrected basis each of the 15 key hops (attack, benign and background) has a
    `triggers.csv` row tied to its target 4624 (by `anchor_logon_uid`; a 7045-only hop by `trigger_event_uid`) and that
    row is at `gate_tier` A."""
    run = need(gate_runs, trial)
    hop = hop_by_id(trial, hop_id)
    con = open_ro(trial)
    try:
        st = _hop_state(run, hop, con)
    finally:
        con.close()
    label = f"{trial} {hop_id} ({hop['role']}, {hop['protocol']}, {st['kind']} uid {st['uid']})"
    assert st["strict"], (f"{label}: no triggers.csv row"
                          f"{' (it is in unmatched_remote.csv)' if st['unmatched'] else ' and not in unmatched_remote.csv'}")
    tiers = sorted({r["gate_tier"] for r in st["strict"]})
    assert "A" in tiers, f"{label}: trigger row(s) at tier(s) {tiers}, expected A"


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_gta07_near_window_counts_raw_and_corrected_are_reported_and_the_corrected_recount_agrees(
        gate_runs, raw_windows, trial):
    """GTA-07 (new): `near_window` counts on the raw and on the corrected basis are reported per trial (printed here and in
    `out/gate_tests/gta_report.md`). The corrected counts of the gate (`stats.json`) must equal an independent recount from
    the DB, the offsets file and the corrected window; the raw counts are report-only."""
    run = need(gate_runs, trial)
    if trial not in raw_windows:
        pytest.skip(f"no raw-basis window for {trial}")
    lo, hi = window_us(raw_windows[trial])
    raw = near_window_counts(trial, lo, hi, corrected=False)
    clo, chi = window_us(run.window)
    cor = near_window_counts(trial, clo, chi, corrected=True)
    stats = {h: c for h, c in run.stats["near_window"].items() if c["before"] or c["after"]}
    print(f"{trial}: near_window raw basis {raw}; corrected basis (gate) {stats}")
    assert cor == stats, f"{trial}: gate near_window {stats} != independent recount {cor}"
