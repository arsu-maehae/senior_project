"""Real-data acceptance tests for T7.2 (plan section 6, A1-A9): sessions (ST-10) and process trees (ST-11) on the nine
development trials. Every test is slow and parametrised over `clock_offset.params.DEVELOPMENT_TRIALS` only; no
t02-t10 trial is ever read. The tests read the approved t00 keys (`ground_truth/approved/*.yaml`, JSON content) to
check answer-key events; `src/stitch` never does. Nothing is written under the repo except by the A1 refusal check,
which must write nothing. Assertions and messages carry counts, IDs and uids only, never command text.

Written from the plan, the spec (ST-01, ST-10, ST-11, ST-63 data side) and decisions 046 and 047, not from the
implementation. Each trial's index is built ONCE per session (`loaded`); `run_check` is run once more in A2 to prove
the result is reproducible.

How the key's source session is read (A5): the approved keys give `session_evidence` / `source_session_logon_id` only
for s04-A-h1 (1 hop). Every one of the 11 keyed hops that have a source session lists the Sysmon 1 events of the agent
command on the source host in `agent_event_uids` (for s04-A-h1 these are exactly `session_evidence.command_event_uids`).
The key source session is therefore the session of that command's process. The strict reading is also tested.
"""
from __future__ import annotations

import builtins
import contextlib
import csv
import functools
import json
import os
import pathlib
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from answer_key.db import sha256_file  # noqa: E402
from clock_offset import params as co_params  # noqa: E402
from clock_offset.correct import before_counted_change, event_unreliable  # noqa: E402
from gate.timeutil import to_us  # noqa: E402
from stitch.check_index import check_extra, main as check_main, run_check, write_check  # noqa: E402
from stitch.index import build_index, index_counts  # noqa: E402
from stitch.inputs import check_allowed, load_scan, trial_paths  # noqa: E402
from stitch.params import StitchParams  # noqa: E402
from stitch.sessions import state_at, window_open  # noqa: E402

pytestmark = pytest.mark.slow

DEV = list(co_params.DEVELOPMENT_TRIALS)
DEV_T00 = [t for t in DEV if t.endswith("_t00")]
PARAMS = StitchParams()
APPROVED = REPO / "ground_truth" / "approved"
LOOKBACK_KINDS = {("Security", 4624), ("Security", 4634), ("Security", 4647), ("Security", 1102),
                  ("System", 41), ("System", 1074), ("System", 6005), ("System", 6006), ("System", 6008)}
US_2S = 2_000_000


# ------------------------------------------------------------------------------------------------ loading (once)
@dataclass
class Loaded:
    trial: str
    paths: Any
    checked: Any
    scan: Any
    sha_before: str
    sha_after: str
    index: Any
    counts: dict
    rows: list[dict]                      # in_window + lookback, as kept
    by_uid: dict[str, dict]               # every uid of every kept row -> its kept row


@functools.lru_cache(maxsize=None)
def _loaded(trial: str) -> Loaded:
    assert trial in DEV, trial            # belt and braces: only development trials, ever
    paths = trial_paths(REPO, trial)
    if not paths.db.is_file() or not (paths.gate_dir / "stats.json").is_file():
        return None                       # type: ignore[return-value]   # the caller skips
    checked = check_allowed(paths)
    scan, before, after = load_scan(checked, paths)
    index = build_index(trial, scan, PARAMS)
    counts = index_counts(index, check_extra(REPO, paths.db, checked, before, after, PARAMS))
    rows = scan.in_window + scan.lookback
    by_uid = {u: r for r in rows for u in r["event_uids"]}
    return Loaded(trial, paths, checked, scan, before, after, index, counts, rows, by_uid)


def loaded(trial: str) -> Loaded:
    got = _loaded(trial)
    if got is None:
        pytest.skip(f"{trial}: trial DB or gate output missing")
    return got


def sessions_of(ld: Loaded) -> list:
    return list(ld.index.sessions.sessions.values())


def load_key(trial: str) -> dict:
    path = APPROVED / f"{trial}.yaml"
    if not path.is_file():
        pytest.skip(f"no approved key for {trial}")
    return json.loads(path.read_text(encoding="utf-8"))


@contextlib.contextmanager
def watch_fs(needle: str, monkeypatch):
    """Record every filesystem or sqlite call whose first argument contains `needle`, then delegate."""
    seen: list[str] = []

    def wrap(obj, name):
        orig = getattr(obj, name)

        def inner(*args, **kw):
            try:
                text = str(args[0]) if args else ""
            except Exception:  # noqa: BLE001
                text = ""
            if needle in text:
                seen.append(f"{name}({text})")
            return orig(*args, **kw)
        monkeypatch.setattr(obj, name, inner)

    with monkeypatch.context():
        wrap(builtins, "open")
        for n in ("stat", "lstat", "scandir", "listdir"):
            wrap(os, n)
        for n in ("exists", "isfile", "isdir"):
            wrap(os.path, n)
        for n in ("stat", "exists", "is_file", "is_dir", "open", "read_bytes", "read_text", "mkdir", "iterdir"):
            wrap(pathlib.Path, n)
        wrap(sqlite3, "connect")
        yield seen


# ================================================================================================ A1
@pytest.mark.parametrize("trial", ["s02_t02", "s03_t05", "s07_t10", "s06_t02"])
def test_a1_a_test_trial_is_refused_before_any_file_of_it_is_opened_and_nothing_is_written(trial, monkeypatch):
    assert trial not in DEV
    out_root = REPO / "out" / "stitch_check"
    listing_before = sorted(p.name for p in out_root.iterdir()) if out_root.is_dir() else None
    with watch_fs(trial, monkeypatch) as seen:
        code = check_main(["--trial", trial, "--repo", str(REPO)])
    assert code == 2
    assert seen == [], f"{trial}: {len(seen)} filesystem call(s) on a path of the refused trial"
    assert not (out_root / trial).exists()
    listing_after = sorted(p.name for p in out_root.iterdir()) if out_root.is_dir() else None
    assert listing_after == listing_before


# ================================================================================================ A2
@pytest.mark.parametrize("trial", DEV)
def test_a2_run_check_is_reproducible_and_leaves_the_db_unchanged(trial):
    ld = loaded(trial)
    db = ld.paths.db
    sha_pre = sha256_file(db)
    data = run_check(REPO, trial)                                  # an independent second run
    assert data == ld.counts
    assert json.dumps(data, sort_keys=True) == json.dumps(ld.counts, sort_keys=True)
    gate_sha = json.loads((ld.paths.gate_dir / "stats.json").read_text(encoding="utf-8"))["db"]["sha256_after"]
    assert data["db"]["sha256_before"] == data["db"]["sha256_after"] == gate_sha == sha_pre
    assert sha256_file(db) == sha_pre
    assert "rule" not in data["window"]
    text = json.dumps(data, sort_keys=True)
    for bad in (".exe", "C:", "\\"):
        assert bad not in text, f"{trial}: check data contains {bad!r}"


@pytest.mark.parametrize("trial", DEV)
def test_a2_write_check_text_is_byte_identical_for_equal_data(trial, tmp_path):
    ld = loaded(trial)
    first = write_check(tmp_path / "a", trial, ld.counts).read_bytes()
    second = write_check(tmp_path / "b", trial, run_check(REPO, trial)).read_bytes()
    assert first == second


# ================================================================================================ A3
@pytest.mark.parametrize("trial", DEV)
def test_a3_every_in_window_4624_opens_exactly_one_session(trial):
    ld = loaded(trial)
    opens: dict[str, int] = {}
    for s in sessions_of(ld):
        for u in s.open_uids:
            opens[u] = opens.get(u, 0) + 1
    logons = [r for r in ld.scan.in_window if r["channel"] == "Security" and r["event_id"] == 4624
              and r["target_logon_id"] is not None]
    assert logons, f"{trial}: no in-window 4624"
    bad = sorted(u for r in logons for u in r["event_uids"] if opens.get(u, 0) != 1)
    assert bad == [], f"{trial}: {len(bad)} 4624 uid(s) not in exactly one session, e.g. {bad[:5]}"
    null_ids = [r for r in ld.scan.in_window if r["channel"] == "Security" and r["event_id"] == 4624
                and r["target_logon_id"] is None]
    assert not [u for r in null_ids for u in r["event_uids"] if u in opens]


@pytest.mark.parametrize("trial", DEV)
def test_a3_session_keys_are_unique_and_no_close_precedes_its_open(trial):
    ld = loaded(trial)
    ss = sessions_of(ld)
    assert len({s.key for s in ss}) == len(ss) == len(ld.index.sessions.sessions)
    assert all(k == s.key for k, s in ld.index.sessions.sessions.items())
    early = [s.key for s in ss if s.open_known and s.close_us_raw is not None and s.close_us_raw < s.open_us_raw]
    assert early == [], f"{trial}: close before open in {early[:5]}"


@pytest.mark.parametrize("trial", DEV)
def test_a3_counts_equal_a_recount_from_the_sessions(trial):
    ld = loaded(trial)
    ss = sessions_of(ld)
    c = ld.index.sessions.counts
    known = [s for s in ss if s.open_known]
    assert c["open_in_window"] == sum(1 for s in known if not s.opened_before_window)
    assert c["opened_before_window"] == sum(1 for s in known if s.opened_before_window)
    assert c["open_unknown"] == sum(1 for s in ss if not s.open_known)
    assert c["system"] == sum(1 for s in ss if s.is_system)
    assert c["close_kind"] == {k: sum(1 for s in ss if s.close_kind == k) for k in ("4634", "4647", "boot", "none")}
    assert sum(c["close_kind"].values()) == len(ss)
    assert sum(c["per_host"].values()) == len(ss)
    assert ld.counts["sessions"] == json.loads(json.dumps(c))
    print(f"A3 {trial}: sessions {len(ss)}, open_in_window {c['open_in_window']}, "
          f"before_window {c['opened_before_window']}, unknown {c['open_unknown']}, system {c['system']}")


# ================================================================================================ A4
def gate_remote_logon_uids(trial: str) -> tuple[list[tuple[str, str]], int]:
    """(host, logon uid) of every gate remote logon, and the count of trigger rows with no anchor (not a logon).

    triggers.csv: `anchor_logon_uid` where non-empty; unmatched_remote.csv: its `anchor_logon_uid`, else its
    `trigger_event_uid` (the logon itself; spec 02_gate section 3)."""
    gate_dir = REPO / "out" / "gate" / trial
    out: list[tuple[str, str]] = []
    no_anchor = 0
    for name in ("triggers", "unmatched_remote"):
        with open(gate_dir / f"{name}.csv", newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                uid = (r.get("anchor_logon_uid") or "").strip()
                if not uid and name == "unmatched_remote":
                    uid = (r.get("trigger_event_uid") or "").strip()
                if uid:
                    out.append((r["host"], uid))
                else:
                    no_anchor += 1
    return out, no_anchor


@pytest.mark.parametrize("trial", DEV)
def test_a4_every_gate_remote_logon_maps_to_a_session_on_its_host(trial):
    ld = loaded(trial)
    logons, no_anchor = gate_remote_logon_uids(trial)
    assert logons, f"{trial}: no gate remote logon"
    by_host_uid: dict[tuple[str, str], list] = {}
    for s in sessions_of(ld):
        for u in s.open_uids:
            by_host_uid.setdefault((s.host, u), []).append(s.key)
    missing = sorted({(h, u) for h, u in logons if (h, u) not in by_host_uid})
    multi = sorted({(h, u) for h, u in logons if len(by_host_uid.get((h, u), [])) > 1})
    print(f"A4 {trial}: gate remote logons {len(logons)} (unique {len(set(logons))}), "
          f"rows with no anchor {no_anchor}, mapped {len(set(logons)) - len(missing)}, missing {len(missing)}")
    assert missing == [], f"{trial}: {len(missing)} gate logon(s) with no session on their host, e.g. {missing[:5]}"
    assert multi == [], f"{trial}: logon(s) in several sessions {multi[:5]}"


# ================================================================================================ A5 (t00 keys)
def key_source_hops(key: dict) -> list[dict]:
    """The keyed hops that have a key source session: those with agent command events on the source host (11 on t00)."""
    return [h for h in key["hops"] if h.get("agent_event_uids")]


def agent_sessions(ld: Loaded, hop: dict) -> tuple[set, int]:
    """Session keys of the processes of the hop's agent command events (Sysmon 1 uids), and how many uids were found."""
    keys, found = set(), 0
    for pk, p in ld.index.processes.processes.items():
        if set(p.sysmon1_uids) & set(hop["agent_event_uids"]):
            found += 1
            keys.add(p.session_key)
    return keys, found


@pytest.mark.parametrize("trial", DEV_T00)
def test_a5_key_source_session_exists_has_the_key_type_and_a_process(trial):
    ld = loaded(trial)
    key = load_key(trial)
    ek = key["event_keys"]
    for hop in key_source_hops(key):
        hid = hop["hop_id"]
        for u in hop["agent_event_uids"]:
            assert ek[u]["host"] == hop["command_host"] and ek[u]["channel"] == "Sysmon" and ek[u]["event_id"] == 1
            assert u in ld.by_uid, f"{trial} {hid}: agent event {u} is not an in-window event"
        keys, found = agent_sessions(ld, hop)
        assert found >= 1, f"{trial} {hid}: no process for the agent command events"
        assert None not in keys, f"{trial} {hid}: an agent command process has no session"
        assert len(keys) == 1, f"{trial} {hid}: agent command events in {len(keys)} sessions {sorted(keys)}"
        (skey,) = keys
        sess = ld.index.sessions.sessions[skey]
        assert skey[0] == hop["command_host"], f"{trial} {hid}: session on {skey[0]}, key host {hop['command_host']}"
        assert ld.index.processes.by_session.get(skey), f"{trial} {hid}: session {sess.logon_id_hex} has no process"
        assert ld.index.processes.events_of_session(skey), f"{trial} {hid}: no events in session"
        print(f"A5 {trial} {hid}: session {sess.logon_id_hex} type {sess.logon_type} open_known {sess.open_known} "
              f"system {sess.is_system} processes {len(ld.index.processes.by_session[skey])}")
        ev = hop.get("session_evidence")
        if ev:                                              # the strict reading: only s04-A-h1 on t00
            assert sess.open_known, f"{trial} {hid}: key session {ev['session_id']} has no 4624"
            assert ev["session_logon_uid"] in sess.open_uids, f"{trial} {hid}: key logon uid not in open_uids"
            assert sess.logon_type == ev["session_logon_type"], \
                f"{trial} {hid}: type {sess.logon_type}, key {ev['session_logon_type']}"
            assert sess.logon_id_hex == ev["session_id"] == hop["source_session_logon_id"]


def test_a5_total_of_keyed_hops_with_a_key_source_session_is_11():
    n_agent = n_strict = 0
    for t in DEV_T00:
        key = load_key(t)
        n_agent += len(key_source_hops(key))
        n_strict += sum(1 for h in key["hops"] if h.get("session_evidence") or h.get("source_session_logon_id"))
    print(f"A5 keyed hops with a source session: agent-command reading {n_agent}, strict "
          f"session_evidence/source_session_logon_id reading {n_strict}")
    assert n_agent == 11


# ================================================================================================ A6 (t00 keys)
def identity_hops(key: dict) -> list[dict]:
    return [h for h in key["hops"] if (h.get("identity_basis") or {}).get("dump_event_uid")]


@pytest.mark.parametrize("trial", DEV_T00)
def test_a6_key_open_sessions_are_open_at_the_dump_without_a_pre_window_open(trial):
    ld = loaded(trial)
    key = load_key(trial)
    idx = ld.index.sessions
    for hop in identity_hops(key):
        hid, ib = hop["hop_id"], hop["identity_basis"]
        dump_host = ib["dump_host"]
        row = ld.by_uid.get(ib["dump_event_uid"])
        assert row is not None, f"{trial} {hid}: dump event {ib['dump_event_uid']} is not an in-window event"
        assert row["channel"] == "Sysmon" and row["event_id"] == 10 and row["host"] == dump_host
        assert row["in_window"], f"{trial} {hid}: dump event is outside the window"
        assert row["us_raw"] == to_us(ib["dump_time_utc"]), \
            f"{trial} {hid}: dump event_utc {row['event_utc']} differs from the key {ib['dump_time_utc']}"
        dump_us = row["us_raw"]
        key_ids = set()
        for os_ in ib["open_sessions"]:
            lid = os_["logon_id"]
            key_ids.add(lid)
            s = idx.session_at(dump_host, lid, dump_us)
            assert s is not None, f"{trial} {hid}: no session {os_['logon_id_hex']} on {dump_host} at the dump"
            assert state_at(s, dump_us) == "open", \
                f"{trial} {hid}: session {os_['logon_id_hex']} is {state_at(s, dump_us)} at the dump"
            assert s.opened_before_window is False, f"{trial} {hid}: {os_['logon_id_hex']} needs a pre-window open"
            assert os_["event_uid"] in s.open_uids, f"{trial} {hid}: key open uid not in the session's open_uids"
            assert s.logon_type == os_["logon_type"]
        for hexid in ib["end_unknown_ids"]:
            s = idx.session_at(dump_host, hexid, dump_us)
            assert s is not None and state_at(s, dump_us) == "end_unknown", f"{trial} {hid}: {hexid}"
        extras = sorted(
            s.logon_id_hex for s in idx.sessions.values()
            if s.host == dump_host and s.open_known and not s.is_system and s.account == ib.get("dump_account")
            and s.logon_id not in key_ids and state_at(s, dump_us) == "open")
        print(f"A6 {trial} {hid}: key open sessions {len(key_ids)}, extra open sessions of the same account "
              f"at the dump (not in the key) {len(extras)} {extras}")


def test_a6_total_of_key_open_sessions_is_13():
    total = hops = 0
    for t in DEV_T00:
        for h in identity_hops(load_key(t)):
            hops += 1
            total += len(h["identity_basis"]["open_sessions"])
    print(f"A6 hops with a dump {hops}, key open sessions {total}")
    assert (hops, total) == (8, 13)


# ================================================================================================ A7
@pytest.mark.parametrize("trial", DEV)
def test_a7_collapsed_processes_share_host_and_pid_within_2s(trial):
    ld = loaded(trial)
    pairs = [p for p in ld.index.processes.processes.values() if p.sysmon1_uids and p.sec4688_uids]
    bad = []
    for p in pairs:
        s_rows = [ld.by_uid[u] for u in p.sysmon1_uids]
        e_rows = [ld.by_uid[u] for u in p.sec4688_uids]
        same = all(r["host"] == p.host and r["process_id"] == p.process_id and r["process_id"] is not None
                   for r in s_rows + e_rows)
        close = min(abs(a["us_raw"] - b["us_raw"]) for a in s_rows for b in e_rows) <= US_2S
        if not (same and close):
            bad.append((p.key, p.sysmon1_uids, p.sec4688_uids))
    c = ld.index.processes.counts
    print(f"A7 {trial}: collapsed {len(pairs)}, sysmon1_only {c['sysmon1_only']}, sec4688_only {c['sec4688_only']}, "
          f"ambiguous_pairs {c['ambiguous_pairs']}")
    assert bad == [], f"{trial}: {len(bad)} collapsed process(es) break host / pid / 2 s, e.g. {bad[:3]}"
    assert len(pairs) == c["collapsed_pairs"]


@pytest.mark.parametrize("trial", DEV)
def test_a7_session_rule_disagreements_are_zero(trial):
    ld = loaded(trial)
    assert ld.counts["processes"]["session_rule_disagreements"] == 0


# ================================================================================================ A8
@pytest.mark.parametrize("trial", DEV)
def test_a8_no_pre_window_uid_reaches_a_process_a_session_event_or_a_link_field(trial):
    ld = loaded(trial)
    lookback = {u for r in ld.scan.lookback for u in r["event_uids"]}
    assert lookback, f"{trial}: no look-back row"
    in_process = set()
    for p in ld.index.processes.processes.values():
        in_process |= set(p.sysmon1_uids) | set(p.sec4688_uids)
        for v in p.event_uids_by_kind.values():
            in_process |= set(v)
    assert in_process & lookback == set(), f"{trial}: {len(in_process & lookback)} look-back uid(s) in processes"
    in_events = set()
    for s in sessions_of(ld):
        in_events |= set(ld.index.processes.events_of_session(s.key))
    assert in_events & lookback == set(), f"{trial}: look-back uid(s) in events_of_session"
    in_link = set()
    for s in ld.index.sessions.window_view():
        uids, _, _ = window_open(s)
        in_link |= set(uids)
    assert in_link & lookback == set(), f"{trial}: {len(in_link & lookback)} look-back uid(s) in window_open"


@pytest.mark.parametrize("trial", DEV)
def test_a8_look_back_holds_only_the_look_back_kinds(trial):
    ld = loaded(trial)
    kinds = {(r["channel"], r["event_id"]) for r in ld.scan.lookback}
    assert kinds <= LOOKBACK_KINDS, f"{trial}: unexpected look-back kind(s) {sorted(kinds - LOOKBACK_KINDS)}"
    assert all(not r["in_window"] for r in ld.scan.lookback)
    assert all(r["in_window"] for r in ld.scan.in_window)
    assert not [r for r in ld.scan.lookback if r["us"] >= ld.checked.end_us]       # before the window only


# ================================================================================================ A9
def test_a9_s06_t01_every_ep03_row_is_clock_unreliable():
    ld = loaded("s06_t01")
    assert ld.checked.clock.offsets.hosts["ep-03"].status == "wide"
    rows = [r for r in ld.rows if r["host"] == "ep-03"]
    assert rows, "s06_t01: no ep-03 row kept"
    bad = sorted(u for r in rows if r["clock_unreliable"] != 1 for u in r["event_uids"])
    print(f"A9 s06_t01: ep-03 rows kept {len(rows)}, flagged {len(rows) - len(bad)}")
    assert bad == [], f"s06_t01: {len(bad)} ep-03 row(s) not flagged, e.g. {bad[:5]}"


@pytest.mark.parametrize("trial", DEV)
def test_a9_flag_follows_the_offsets_status_and_counted_clock_changes(trial):
    ld = loaded(trial)
    offsets, changes = ld.checked.clock.offsets, ld.checked.clock.changes
    wrong, ok_flagged_without_change = [], []
    for r in ld.rows:
        want = int(event_unreliable(r["host"], r["us_raw"], offsets, changes))
        if r["clock_unreliable"] != want:
            wrong.append((r["host"], r["event_uid"]))
        status = offsets.hosts[r["host"]].status if r["host"] in offsets.hosts else None
        if status in ("ok", "reference") and r["clock_unreliable"] == 1 \
                and not before_counted_change(r["host"], r["us_raw"], changes):
            ok_flagged_without_change.append((r["host"], r["event_uid"]))
    flagged = {}
    for r in ld.rows:
        if r["clock_unreliable"]:
            flagged[r["host"]] = flagged.get(r["host"], 0) + 1
    print(f"A9 {trial}: flagged rows per host {dict(sorted(flagged.items()))}, "
          f"statuses {({h: o.status for h, o in sorted(offsets.hosts.items())})}")
    assert wrong == [], f"{trial}: {len(wrong)} row(s) differ from event_unreliable, e.g. {wrong[:5]}"
    assert ok_flagged_without_change == [], \
        f"{trial}: {len(ok_flagged_without_change)} ok/reference row(s) flagged without a counted change"
    assert ld.counts["clock_unreliable_events"] == dict(sorted(
        (h, sum(1 for r in ld.scan.in_window if r["host"] == h and r["clock_unreliable"]))
        for h in {r["host"] for r in ld.scan.in_window if r["clock_unreliable"]}))
