"""Tests for the T6b.2 step `src/clock_offset/` (spec docs/specs/08_clock_offset.md sections 3, 4, 6, 7;
decision docs/decisions/043-clock-offset-method.md).

Written from the spec and the decision. The code was read only for public function names, signatures and the
column names of the DB view. Part A: synthetic trials (COT-xx, fast; each builds a tiny SQLite DB with table
`events` and view `events_dedup` in tmp_path). Part B: real data on the development and clock-only trials
(COA-xx, slow; a hard allowlist of trial DBs, nothing else is opened).

Test names carry the spec id: test_cot05_..., test_coa01_...
"""
from __future__ import annotations

import ast
import builtins
import csv
import hashlib
import io
import itertools
import json
import os
import re
import shutil
import sqlite3
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from fractions import Fraction
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from clock_offset import __main__ as co_main  # noqa: E402
from clock_offset import changes as ch  # noqa: E402
from clock_offset import common, correct, estimate, pairs, readings, run  # noqa: E402
from clock_offset import scan as co_scan  # noqa: E402
from answer_key import db as ak_db  # noqa: E402
from gate.inputs import GateError  # noqa: E402
from gate.run import run_gate  # noqa: E402
from gate.timeutil import fmt_us, to_us  # noqa: E402
from trial_window import __main__ as tw_main  # noqa: E402
from trial_window import window as tw_window  # noqa: E402

SRC_CO = REPO / "src" / "clock_offset"
PROCESSED = REPO / "data" / "processed"

# Spec 08 section 3: the offsets file columns, in order (typed here, not imported).
OFFSETS_HEADER = ["trial_id", "host", "offset_ms", "offset_status", "offset_unc_ms", "n_pairs", "n_dropped_far",
                  "n_pairs_lab_ip", "late_gap_s", "min_ms", "q1_ms", "median_ms", "q3_ms", "max_ms",
                  "loo_shift_ms", "pair_span_s", "host_has_events", "method", "search_start_utc",
                  "search_end_utc", "db_sha256", "tool_version", "clock_changes_sha256", "clock_scan"]
PAIRS_HEADER = ["host", "event_uid_4624", "event_uid_4769", "logon_guid", "t_4624_utc", "t_4769_utc", "delta_ms",
                "logon_type", "account_name", "service_name", "method", "candidate_count", "time_delta_ms"]
METHOD = "logonguid_4624_4769_mutual_nearest_median"
INT_COLUMNS = ["offset_ms", "offset_unc_ms", "n_pairs", "n_dropped_far", "n_pairs_lab_ip", "late_gap_s", "min_ms",
               "q1_ms", "median_ms", "q3_ms", "max_ms", "loo_shift_ms", "pair_span_s"]
STATUSES = {"reference", "ok", "wide", "stale", "none"}

LAB_IP = {"dc01": "192.168.50.10", "ep-01": "192.168.50.21", "ep-02": "192.168.50.22", "ep-03": "192.168.50.23"}
SPLUNKD = r"C:\Users\Public\splunkd.exe"

# ------------------------------------------------------------------------------------------ time helpers

BASE = datetime(2026, 9, 24, 5, 0, 0, tzinfo=timezone.utc)      # before the 2026-10-26 date of CO-17


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}Z"


def at(seconds: float) -> str:
    """ISO text of BASE + seconds (millisecond exact)."""
    return iso(BASE + timedelta(milliseconds=round(seconds * 1000)))


def edge(seconds: float) -> str:
    """Window-edge / search-span text `...mmmZ` for BASE + seconds."""
    dt = BASE + timedelta(milliseconds=round(seconds * 1000))
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ------------------------------------------------------------------------------------------ synthetic rows

COLUMNS = ["event_uid", "timestamp_utc", "event_utc", "host", "channel", "event_id", "record_id", "account_name",
           "process_guid", "parent_process_guid", "process_id", "image", "parent_image", "command_line",
           "destination_ip", "destination_port", "source_ip", "source_port", "logon_guid", "logon_guid_state",
           "logon_type", "service_name", "source_relative_path", "source_line", "source_sha256"]


def ev(uid: str, host: str, channel: str, event_id: int, t: float, **kw) -> dict:
    row = {c: None for c in COLUMNS}
    row.update({"event_uid": uid, "host": host, "channel": channel, "event_id": event_id,
                "timestamp_utc": at(t), "event_utc": at(t)})
    row.update(kw)
    return row


def agent_rows() -> list[dict]:
    """splunkd root on ep-01 at t=0 and a child at t=100: raw window [-60, 400], search span +-1800 s."""
    return [ev("agent-root", "ep-01", "Sysmon", 1, 0, process_guid="{r1}", parent_process_guid="{rp}",
               parent_image=SPLUNKD, image=r"C:\Windows\System32\cmd.exe", command_line="cmd /c x",
               account_name="svc"),
            ev("agent-last", "ep-01", "Sysmon", 1, 100, process_guid="{c1}", parent_process_guid="{r1}",
               parent_image=r"C:\Windows\System32\cmd.exe", image="whoami.exe", command_line="whoami",
               account_name="svc")]


HOST_NO = {"ep-01": 1, "ep-02": 2, "ep-03": 3, "dc01": 9}


def guid(host: str, i: int, prefix: int = 0) -> str:
    return f"{HOST_NO[host] + prefix * 16:08x}-0000-0000-0000-{i:012x}"


def host_pairs(host: str, deltas_ms: list[int], start: float = 10.0, step: float = 5.0, prefix: int = 0,
               ltype: int = 3, source_ip: str | None = None, tag: str = "") -> list[dict]:
    """One endpoint 4624 and one dc01 4769 per delta; 4624 time = 4769 time + delta (host clock - dc01 clock)."""
    out = []
    for i, d in enumerate(deltas_ms):
        t_dc = start + i * step
        g = guid(host, i, prefix)
        out.append(ev(f"{host}-4624-{tag}{i}", host, "Security", 4624, t_dc + d / 1000, logon_guid=g,
                      logon_type=ltype, account_name="svc_sql", source_ip=source_ip))
        out.append(ev(f"dc01-4769-{host}-{tag}{i}", "dc01", "Security", 4769, t_dc, logon_guid=g,
                      service_name="ENDPOINT-01$", account_name="svc_sql"))
    return out


def sysmon_noise(host: str, t: float, uid: str | None = None) -> dict:
    return ev(uid or f"{host}-sysmon-{t}", host, "Sysmon", 1, t, process_guid="{n-" + f"{host}{t}" + "}",
              parent_process_guid="{explorer}", parent_image=r"C:\Windows\explorer.exe", image="notepad.exe",
              command_line="notepad", account_name="user")


def write_db(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    cols = ", ".join(f'"{c}"' for c in COLUMNS)
    con.execute(f"CREATE TABLE events ({cols})")
    for i, r in enumerate(rows):
        r = dict(r)
        r["record_id"] = i + 1
        con.execute(f"INSERT INTO events VALUES ({', '.join('?' * len(COLUMNS))})", [r[c] for c in COLUMNS])
    con.execute("CREATE VIEW events_dedup AS SELECT * FROM events")
    con.commit()
    con.close()


def make_repo(root: Path, rows: list[dict], trial: str = "s02_t00", name: str = "repo", files=None,
              manifest=None, exports=None) -> Path:
    """Synthetic repo: the DB, optional JSONL lines of DB clock-change rows (`files`), a manifest
    (`manifest`: list of (host, channel, sha)) and export JSONL files (`exports`: {(host, stem): [records]})."""
    repo = root / name
    write_db(repo / "data" / "processed" / f"{trial}.sqlite3", rows)
    if files is not None:
        files.write(repo, trial)
    if manifest is not None:
        write_manifest(repo, trial, manifest)
    for (host, stem), recs in (exports or {}).items():
        write_export(repo, trial, host, stem, recs)
    return repo


def measure(root: Path, rows: list[dict], trial: str = "s02_t00", write: bool = False, name: str = "repo",
            scan: bool = True, **repo_kw):
    """(repo, run() result) for one synthetic trial."""
    repo = make_repo(root, rows, trial, name, **repo_kw)
    res = run.run(repo, [trial], write=write, scan=scan)
    assert trial in res["rows"], res["refused"]
    return repo, res


SHA = "ab" * 32
MANIFEST_COLS = ["path", "sha256", "size", "scenario", "trial", "host", "channel", "source_path", "date", "records",
                 "first_event_utc", "last_event_utc"]


def write_manifest(repo: Path, trial: str, entries: list[tuple[str, str, str]]) -> None:
    """data/manifest.csv rows (host, channel, sha256) for the trial; no export span (first/last empty)."""
    scenario, tr = trial.split("_", 1)
    (repo / "data").mkdir(parents=True, exist_ok=True)
    with open(repo / "data" / "manifest.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=MANIFEST_COLS, lineterminator="\n")
        w.writeheader()
        for host, channel, sha_ in entries:
            w.writerow({"path": f"{scenario}/{tr}/{host}/{channel}.evtx", "sha256": sha_, "size": 1,
                        "scenario": scenario, "trial": tr, "host": host, "channel": channel, "source_path": "x",
                        "date": "2026-09-24", "records": 1, "first_event_utc": "", "last_event_utc": ""})


def write_export(repo: Path, trial: str, host: str, stem: str, records: list[dict]) -> Path:
    p = repo / "data" / "processed" / "jsonl" / trial / "per_file" / host / f"{stem}.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8", newline="\n")
    return p


def shift_times(t: float, shift_ms: int) -> tuple[str, str]:
    """(previous, new) clock text of a change recorded at t (seconds after BASE): new - previous = shift_ms."""
    new = BASE + timedelta(milliseconds=round(t * 1000))
    return iso(new - timedelta(milliseconds=shift_ms)), iso(new)


def mkrec(channel: str, event_id: int, t: float, provider: str | None, shift_ms: int | None = None, sha: str = SHA,
          idx: int = 1, ts: str | None = None, prev: str | None = None, new: str | None = None) -> dict:
    """A decoded export record of a clock-change event (system / event_data / source blocks)."""
    sysb: dict = {"channel": channel, "event_id": str(event_id), "timestamp_raw": ts or at(t)}
    if provider is not None:
        sysb["provider"] = provider
    if shift_ms is not None:
        prev, new = shift_times(t, shift_ms)
    pn = "PreviousTime" if channel == "Security" else "OldTime"
    data = ([{"name": pn, "value": prev}] if prev is not None else []) + (
        [{"name": "NewTime", "value": new}] if new is not None else [])
    return {"system": sysb, "event_data": data, "source": {"sha256": sha, "record_index": idx}}


KG = "Microsoft-Windows-Kernel-General"
SEC = "Microsoft-Windows-Security-Auditing"


class ChangeFiles:
    """DB clock-change rows (4616 / System 1) with the JSONL lines their source_relative_path/source_line point to."""

    def __init__(self) -> None:
        self.lines: dict[tuple[str, str], list[dict]] = {}

    def row(self, uid: str, host: str, channel: str, event_id: int, t: float, shift_ms: int | None,
            sha: str = SHA) -> dict:
        stem = "security" if channel == "Security" else "system"
        recs = self.lines.setdefault((host, stem), [])
        recs.append(mkrec(channel, event_id, t, SEC if channel == "Security" else KG, shift_ms, sha, len(recs) + 1))
        return ev(uid, host, channel, event_id, t, source_relative_path=f"{host}/{stem}.evtx",
                  source_line=len(recs), source_sha256=sha)

    def write(self, repo: Path, trial: str) -> None:
        for (host, stem), recs in self.lines.items():
            write_export(repo, trial, host, stem, recs)


def hrow(res: dict, host: str, trial: str = "s02_t00") -> dict:
    return next(r for r in res["rows"][trial] if r["host"] == host)


def flag(res: dict, trial: str = "s02_t00") -> list[str]:
    return list(res["stats"][trial]["clock_flag"])


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_csv(path: Path) -> tuple[list[str], list[dict]]:
    with open(path, newline="", encoding="utf-8") as fh:
        r = csv.DictReader(fh)
        rows = list(r)
        return list(r.fieldnames or []), rows


def key_paths_with(obj, needle: str, path: tuple = ()) -> list[str]:
    """Key paths of `obj` (nested dict/list) whose value is, or contains, the string `needle`."""
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            found += key_paths_with(v, needle, path + (str(k),))
    elif isinstance(obj, list):
        for v in obj:
            found += key_paths_with(v, needle, path)
    elif isinstance(obj, str) and obj == needle:
        found.append("/".join(path))
    return found


# ====================================================================================== COT-01 refusals (CO-01)

def _no_output(repo: Path, trial: str) -> bool:
    return (not (repo / "data" / "processed" / f"{trial}.clock_offsets.csv").exists()
            and not (repo / "out" / "clock_offset" / trial).exists())


def test_cot01_refusal_function_names_each_case(tmp_path):
    """COT-01: s05q_* (decision 030), a quarantine path and s01_t00 (decision 019) are refused with a reason."""
    repo = tmp_path / "repo"
    assert run.refusal(repo, "s05q_t01")
    assert run.refusal(repo, "s05q_t00")
    assert "quarantine" in run.refusal(repo, "s05q_t01").lower()
    assert run.refusal(repo, "quarantine/s05_t01")                   # a quarantine/ path part below the repo
    s01 = run.refusal(repo, "s01_t00")
    assert s01 and "019" in s01
    assert run.refusal(repo, "s02_t00") is None                      # every other trial may be measured
    assert run.refusal(repo, "s06_t01") is None
    assert run.refusal(repo, "s04_t10") is None


def test_cot01_run_refuses_and_writes_nothing(tmp_path):
    """COT-01: run() reports the refusal, returns no rows and writes no offsets file and no out/ folder."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900])
    repo = tmp_path / "repo"
    for t in ("s05q_t01", "s01_t00"):
        write_db(repo / "data" / "processed" / f"{t}.sqlite3", rows)
    res = run.run(repo, ["s05q_t01", "s01_t00"], write=True)
    assert set(res["refused"]) == {"s05q_t01", "s01_t00"}
    assert all(res["refused"].values())
    assert res["rows"] == {} and res["pairs"] == {} and res["stats"] == {}
    for t in ("s05q_t01", "s01_t00"):
        assert _no_output(repo, t)
    assert not (repo / "out").exists()
    assert sorted(p.name for p in (repo / "data" / "processed").iterdir()) == ["s01_t00.sqlite3", "s05q_t01.sqlite3"]


def test_cot01_cli_prints_refused_and_writes_nothing(tmp_path, capsys):
    """COT-01: the command line reports REFUSED for a refused trial and writes no file for it."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900])
    repo = make_repo(tmp_path, rows, "s01_t00")
    rc = co_main.main(["--trials", "s01_t00", "--repo", str(repo)])
    out = capsys.readouterr().out
    assert rc in (0, None)
    assert "s01_t00" in out and "REFUSED" in out
    assert _no_output(repo, "s01_t00")


def test_cot01_allowed_trial_beside_refused_still_measured(tmp_path):
    """COT-01: a refused trial does not stop an allowed one in the same call."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900])
    repo = make_repo(tmp_path, rows, "s02_t00")
    write_db(repo / "data" / "processed" / "s05q_t01.sqlite3", rows)
    res = run.run(repo, ["s05q_t01", "s02_t00"], write=True)
    assert set(res["rows"]) == {"s02_t00"} and set(res["refused"]) == {"s05q_t01"}
    assert (repo / "data" / "processed" / "s02_t00.clock_offsets.csv").exists()
    assert _no_output(repo, "s05q_t01")


# ====================================================================================== COT-02 evidence (CO-02)

@pytest.mark.parametrize("value,expected", [
    (None, None), ("", None), ("   ", None), ("00000000-0000-0000-0000-000000000000", None),
    ("{00000000-0000-0000-0000-000000000000}", None),
    ("{ABCDEF01-2222-3333-4444-555555555555}", "abcdef01-2222-3333-4444-555555555555"),
    ("ABCDEF01-2222-3333-4444-555555555555", "abcdef01-2222-3333-4444-555555555555"),
    ("abcdef01-2222-3333-4444-555555555555", "abcdef01-2222-3333-4444-555555555555"),
])
def test_cot02_norm_guid(value, expected):
    """COT-02: NULL / blank / all-zero GUID gives None (never pairs); case and braces are normalised."""
    assert common.norm_guid(value) == expected


def test_cot02_null_and_zero_guid_never_pair(tmp_path):
    """COT-02: 4624s and 4769s with NULL or all-zero GUIDs never pair, even though they 'match' each other."""
    zero = "00000000-0000-0000-0000-000000000000"
    rows = agent_rows()
    for i in range(4):
        rows.append(ev(f"z4624-{i}", "ep-01", "Security", 4624, 10 + i, logon_guid=None, logon_guid_state="zero",
                       logon_type=3))
        rows.append(ev(f"z4769-{i}", "dc01", "Security", 4769, 10 + i, logon_guid=None, logon_guid_state="zero"))
        rows.append(ev(f"zz4624-{i}", "ep-02", "Security", 4624, 20 + i, logon_guid=zero, logon_guid_state="zero",
                       logon_type=3))
        rows.append(ev(f"zz4769-{i}", "dc01", "Security", 4769, 20 + i, logon_guid=zero, logon_guid_state="zero"))
    _, res = measure(tmp_path, rows)
    assert res["pairs"]["s02_t00"] == []
    for h in ("ep-01", "ep-02"):
        assert hrow(res, h)["n_pairs"] == 0
        assert hrow(res, h)["offset_status"] == "none"
        assert hrow(res, h)["offset_ms"] is None


def test_cot02_guid_case_and_braces_pair(tmp_path):
    """COT-02: an upper-case braced GUID on the 4624 pairs with the lower-case GUID on the 4769."""
    rows = agent_rows()
    for i, d in enumerate([-3000, -3100]):
        g = guid("ep-01", i)
        rows.append(ev(f"a{i}", "ep-01", "Security", 4624, 10 + 5 * i + d / 1000, logon_guid="{" + g.upper() + "}",
                       logon_type=3))
        rows.append(ev(f"b{i}", "dc01", "Security", 4769, 10 + 5 * i, logon_guid=g))
    _, res = measure(tmp_path, rows)
    assert hrow(res, "ep-01")["n_pairs"] == 2
    assert {p["logon_guid"] for p in res["pairs"]["s02_t00"]} == {guid("ep-01", 0), guid("ep-01", 1)}


def test_cot02_only_4624_on_endpoints_and_4769_on_dc01_pair(tmp_path):
    """COT-02: a dc01 4624, an endpoint 4769, a dc01 4768 and a 4648 with the same GUID never pair."""
    g = guid("ep-01", 1)
    rows = agent_rows() + [
        ev("dc-4624", "dc01", "Security", 4624, 10, logon_guid=g, logon_type=3),
        ev("ep-4769", "ep-01", "Security", 4769, 10, logon_guid=g),
        ev("dc-4768", "dc01", "Security", 4768, 10, logon_guid=g),
        ev("ep-4648", "ep-01", "Security", 4648, 10, logon_guid=g),
        ev("sys-ep-01", "ep-01", "System", 7045, 10, logon_guid=g)]
    _, res = measure(tmp_path, rows)
    assert res["pairs"]["s02_t00"] == []
    assert all(hrow(res, h)["n_pairs"] == 0 for h in ("ep-01", "ep-02", "ep-03"))


def test_cot02_search_span_is_agent_window_plus_minus_1800s_and_dc_edge_120s(tmp_path):
    """COT-02 + section 3: span = raw agent window [-60, 400] +- 1800 s; 4769s may lie 120 s beyond the edges."""
    far = 2200 - 0.5                                   # 4624 half a second inside the span end (2200)
    rows = agent_rows() + host_pairs("ep-01", [-4000, -4100])                       # two ordinary pairs
    # edge pair inside the DC margin: 4624 at 2199.5, partner 4769 50 s beyond the span end (delta -50 s)
    rows += [ev("edge-a", "ep-01", "Security", 4624, far, logon_guid=guid("ep-01", 50), logon_type=3),
             ev("edge-b", "dc01", "Security", 4769, far + 50, logon_guid=guid("ep-01", 50))]
    # partner 130 s beyond the edge: outside the 120 s margin (and over 60 s apart), never used
    rows += [ev("edge2-a", "ep-01", "Security", 4624, far - 1, logon_guid=guid("ep-01", 51), logon_type=3),
             ev("edge2-b", "dc01", "Security", 4769, 2200 + 130, logon_guid=guid("ep-01", 51))]
    # 4624 outside the span (2300 > 2200): never paired, even with a close partner
    rows += [ev("out-a", "ep-01", "Security", 4624, 2300, logon_guid=guid("ep-01", 52), logon_type=3),
             ev("out-b", "dc01", "Security", 4769, 2300, logon_guid=guid("ep-01", 52))]
    # 4624 before the span start (-1860): never paired
    rows += [ev("pre-a", "ep-01", "Security", 4624, -1900, logon_guid=guid("ep-01", 53), logon_type=3),
             ev("pre-b", "dc01", "Security", 4769, -1900, logon_guid=guid("ep-01", 53))]
    _, res = measure(tmp_path, rows)
    used = {p["event_uid_4624"] for p in res["pairs"]["s02_t00"]}
    assert "edge-a" in used
    assert not used & {"edge2-a", "out-a", "pre-a"}
    r = hrow(res, "ep-01")
    assert r["search_start_utc"] == edge(-60 - 1800) and r["search_end_utc"] == edge(400 + 1800)


def test_cot02_hop_logon_from_lab_ip_is_kept_and_counted(tmp_path):
    """COT-02: hop logons (4624 from a lab IP) are kept and counted in n_pairs_lab_ip."""
    rows = agent_rows() + host_pairs("ep-01", [-4000, -4100, -3900], source_ip=LAB_IP["ep-02"])
    rows += host_pairs("ep-01", [-4000], start=40, prefix=3, source_ip="::ffff:192.168.50.10", tag="m")
    rows += host_pairs("ep-01", [-4000], start=50, prefix=4, source_ip="10.9.9.9", tag="x")
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert r["n_pairs"] == 5
    assert r["n_pairs_lab_ip"] == 4                      # 3 from ep-02, 1 from dc01 (IPv4-mapped form); 10.9.9.9 is not a lab host


# ====================================================================================== COT-03 pairing (CO-03, CO-14)

def _r(uid: str, t_s: float, g: str = "g1", host: str = "ep-01") -> dict:
    return {"event_uid": uid, "us": int(round(t_s * 1_000_000)), "logon_guid": g, "host": host}


def test_cot03_reused_guid_gives_one_to_one_not_all_combinations():
    """COT-03: a GUID on three 4624s and three 4769s yields three pairs (never 3 x 3), each event once."""
    a = [_r(f"a{i}", 10 + 10 * i) for i in range(3)]
    b = [_r(f"b{i}", 10.5 + 10 * i) for i in range(3)]
    got = pairs.mutual_nearest(a, b)
    assert sorted((x["event_uid"], y["event_uid"]) for x, y in got) == [("a0", "b0"), ("a1", "b1"), ("a2", "b2")]
    assert len({x["event_uid"] for x, _ in got}) == len(got) == len({y["event_uid"] for _, y in got})


def test_cot03_more_4624_than_4769_only_the_closest_pairs():
    """COT-03: three 4624s share one 4769: only the 4624 closest to it pairs."""
    a = [_r("a0", 0), _r("a1", 9), _r("a2", 30)]
    b = [_r("b0", 10)]
    got = pairs.mutual_nearest(a, b)
    assert [(x["event_uid"], y["event_uid"]) for x, y in got] == [("a1", "b0")]


def test_cot03_not_mutual_is_not_paired():
    """COT-03: a pair needs each to be the other's nearest. a0 and a1 both prefer b0; b0 prefers a1."""
    a = [_r("a0", 0), _r("a1", 4)]
    b = [_r("b0", 5), _r("b1", 100)]
    got = pairs.mutual_nearest(a, b)
    assert [(x["event_uid"], y["event_uid"]) for x, y in got] == [("a1", "b0")]


def test_cot03_retried_4769_a_few_ms_apart_keeps_one():
    """COT-03 / ATK-12: a 4769 retried a few ms apart with the same GUID: one pair with the nearer one."""
    a = [_r("a0", 10.000)]
    b = [_r("b0", 10.500), _r("b1", 10.505)]
    got = pairs.mutual_nearest(a, b)
    assert [(x["event_uid"], y["event_uid"]) for x, y in got] == [("a0", "b0")]


def test_cot03_ties_broken_by_event_uid():
    """COT-03 / CO-14: equal distances are broken by the smaller event_uid, on either side, in any input order."""
    for b in itertools.permutations([_r("b-2", 11), _r("b-1", 9)]):
        got = pairs.mutual_nearest([_r("a", 10)], list(b))
        assert [(x["event_uid"], y["event_uid"]) for x, y in got] == [("a", "b-1")]
    for a in itertools.permutations([_r("a-2", 11), _r("a-1", 9)]):
        got = pairs.mutual_nearest(list(a), [_r("b", 10)])
        assert [(x["event_uid"], y["event_uid"]) for x, y in got] == [("a-1", "b")]


def test_cot03_pairs_stay_inside_their_guid():
    """COT-03: different GUIDs never pair, however close in time."""
    got = pairs.mutual_nearest([_r("a", 10, "g1")], [_r("b", 10, "g2")])
    assert got == []


def test_cot03_pipeline_reused_guids_each_event_used_once(tmp_path):
    """COT-03 through run(): GUID reused by 3 4624s and 3 4769s plus a 4769 retry: counts and unique uids."""
    rows = agent_rows()
    g = guid("ep-01", 7)
    for i in range(3):                                         # reused GUID, 4624 1 s behind its 4769
        rows.append(ev(f"r4624-{i}", "ep-01", "Security", 4624, 20 + 10 * i - 1, logon_guid=g, logon_type=3))
        rows.append(ev(f"r4769-{i}", "dc01", "Security", 4769, 20 + 10 * i, logon_guid=g))
    g2 = guid("ep-01", 8)                                      # retried 4769, a few ms apart
    rows.append(ev("t4624", "ep-01", "Security", 4624, 70 - 1, logon_guid=g2, logon_type=3))
    rows.append(ev("t4769-a", "dc01", "Security", 4769, 70.000, logon_guid=g2))
    rows.append(ev("t4769-b", "dc01", "Security", 4769, 70.004, logon_guid=g2))
    _, res = measure(tmp_path, rows)
    prs = res["pairs"]["s02_t00"]
    assert len(prs) == 4
    assert len({p["event_uid_4624"] for p in prs}) == 4 and len({p["event_uid_4769"] for p in prs}) == 4
    assert {p["delta_ms"] for p in prs} == {-1000}
    retry = next(p for p in prs if p["event_uid_4624"] == "t4624")
    assert retry["event_uid_4769"] == "t4769-a"
    assert retry["candidate_count"] == 2                      # 4769s with that GUID in the span
    assert next(p for p in prs if p["event_uid_4624"] == "r4624-0")["candidate_count"] == 3
    assert hrow(res, "ep-01")["n_pairs"] == 4


def test_cot03_pipeline_tie_is_deterministic_in_any_row_order(tmp_path):
    """COT-14: ties by event_uid give the same pairs.csv whatever the row order in the DB."""
    g = guid("ep-01", 1)
    base = agent_rows() + [ev("a", "ep-01", "Security", 4624, 20, logon_guid=g, logon_type=3),
                           ev("b-2", "dc01", "Security", 4769, 21, logon_guid=g),
                           ev("b-1", "dc01", "Security", 4769, 19, logon_guid=g)]
    base += host_pairs("ep-01", [-2000], start=40, prefix=2)
    outs = []
    for i, rows in enumerate([base, list(reversed(base))]):
        _, res = measure(tmp_path, rows, name=f"r{i}")
        outs.append([(p["event_uid_4624"], p["event_uid_4769"]) for p in res["pairs"]["s02_t00"]])
    assert outs[0] == outs[1]
    assert ("a", "b-1") in outs[0]


# ====================================================================================== COT-04 delta sign (CO-04)

def test_cot04_host_behind_dc01_negative_offset_corrected_later(tmp_path):
    """COT-04: 4624 logged 10 s EARLIER than the dc01 4769 (host behind) gives delta and offset -10000 ms;
    corrected time = event_utc - offset is 10 s LATER."""
    rows = agent_rows() + host_pairs("ep-01", [-10000, -10010, -9990])
    _, res = measure(tmp_path, rows)
    prs = res["pairs"]["s02_t00"]
    assert [p["delta_ms"] for p in prs] == [-10000, -10010, -9990]
    assert all(p["time_delta_ms"] == p["delta_ms"] for p in prs)
    r = hrow(res, "ep-01")
    assert r["offset_status"] == "ok" and r["offset_ms"] == -10000
    offsets = correct.offsets_from_rows(res["rows"]["s02_t00"])
    t = to_us(at(50))
    assert correct.corrected_us(t, "ep-01", offsets) == t + 10_000_000
    assert correct.corrected_us(t, "dc01", offsets) == t


def test_cot04_host_ahead_of_dc01_positive_offset_corrected_earlier(tmp_path):
    """COT-04: a host AHEAD of dc01 gets a positive offset and a corrected time earlier than the raw one."""
    rows = agent_rows() + host_pairs("ep-02", [3000, 3100, 2900])
    rows.append(ev("ep-02-any", "ep-02", "Sysmon", 3, 50))
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-02")
    assert r["offset_ms"] == 3000
    offsets = correct.offsets_from_rows(res["rows"]["s02_t00"])
    t = to_us(at(50))
    assert correct.corrected_us(t, "ep-02", offsets) == t - 3_000_000


# ====================================================================================== COT-05 median, loo_shift, quartiles

def _loo_brute(values: list[int]) -> Fraction:
    full = estimate.median(values)
    return max(abs(full - estimate.median(values[:i] + values[i + 1:])) for i in range(len(values)))


@pytest.mark.parametrize("values,med", [([5], 5), ([3, 1], 2), ([1, 2, 3], 2), ([4, 1, 3, 2], Fraction(5, 2)),
                                        ([-10, -4, 7], -4), ([-18781, -15260, -18828], -18781)])
def test_cot05_median(values, med):
    """COT-05: the median (mean of the two middle values for an even count), exact."""
    assert estimate.median(values) == med


def test_cot05_loo_shift_two_values_is_half_the_gap():
    """COT-05 (CO-06): with n = 2, loo_shift is half the gap between the two pairs."""
    assert estimate.loo_shift([0, 4_000_000]) == 2_000_000
    assert estimate.loo_shift([4_000_000, 0]) == 2_000_000
    assert estimate.loo_shift([-14_010_000, -10_510_000]) == 1_750_000      # s07_t01 ep-01 example in spec 6


def test_cot05_loo_shift_odd_and_even():
    """COT-05: loo_shift = max over left-out pairs of |median(all) - median(rest)|, odd and even n."""
    for values in ([0, 1, 10], [0, 2, 4, 100], [5, 5, 5], [1, 2, 3, 4, 5], [0, 0, 0, 9, 9, 9], [-5, 1, 2, 3]):
        assert estimate.loo_shift(values) == _loo_brute(values), values
    assert estimate.loo_shift([0, 1, 10]) == Fraction(9, 2)                 # left out: 0 -> 5.5, 1 -> 5, 10 -> 0.5
    assert estimate.loo_shift([5, 5, 5]) == 0


def test_cot05_loo_shift_needs_two_values():
    """COT-05: a single value has no stability value."""
    assert estimate.loo_shift([123]) is None


def test_cot05_distribution_quartiles_in_ms(tmp_path):
    """COT-05: min, q1, median, q3, max of the pair deltas in the offsets row (deltas 1..5 s, n = 5)."""
    rows = agent_rows() + host_pairs("ep-01", [1000, 2000, 3000, 4000, 5000])
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert (r["min_ms"], r["q1_ms"], r["median_ms"], r["q3_ms"], r["max_ms"]) == (1000, 2000, 3000, 4000, 5000)
    assert r["offset_ms"] == 3000 == r["median_ms"]
    assert r["offset_unc_ms"] == r["loo_shift_ms"] == 500                 # median 3 -> 2.5 / 3.5 / 3 when one pair is left out
    assert r["n_pairs"] == 5 and r["pair_span_s"] == 24                    # 4624s at 11, 17, 23, 29, 35 s


def test_cot05_quartiles_ordered_and_bound_the_median():
    """COT-05: min <= q1 <= median <= q3 <= max for any sample."""
    for values in ([5_000, 1_000, 9_000], [1_000, 2_000], [0, 10_000, 11_000, 12_000, 100_000, 101_000],
                   [-3_000, -3_000, -3_000, 8_000]):
        d = estimate.distribution(values)
        assert d["min_ms"] <= d["q1_ms"] <= d["median_ms"] <= d["q3_ms"] <= d["max_ms"]
    d = estimate.distribution([1_000_000, 2_000_000, 9_000_000, 20_000_000, 21_000_000, 22_000_000])
    assert d["min_ms"] <= d["q1_ms"] <= d["median_ms"] <= d["q3_ms"] <= d["max_ms"]
    assert d["median_ms"] == 14500


def test_cot05_median_not_min_or_mean(tmp_path):
    """COT-05: the estimate is the median, not the minimum and not the mean (two-sided scatter)."""
    rows = agent_rows() + host_pairs("ep-01", [-4000, 500, 700, 800, 9000])
    _, res = measure(tmp_path, rows)
    assert hrow(res, "ep-01")["offset_ms"] == 700
    assert hrow(res, "ep-01")["offset_ms"] not in (-4000, round(sum([-4000, 500, 700, 800, 9000]) / 5))


# ====================================================================================== COT-06 wide (CO-06)

def test_cot06_wide_above_2_5s_strict_boundary(tmp_path):
    """COT-06: loo_shift exactly 2.5 s is ok; 2.501 s is wide (strictly greater)."""
    _, ok = measure(tmp_path, agent_rows() + host_pairs("ep-01", [0, 5000]), name="ok")
    assert hrow(ok, "ep-01")["offset_status"] == "ok"
    assert hrow(ok, "ep-01")["offset_unc_ms"] == 2500
    _, wide = measure(tmp_path, agent_rows() + host_pairs("ep-01", [0, 5002]), name="wide")
    assert hrow(wide, "ep-01")["offset_status"] == "wide"
    assert hrow(wide, "ep-01")["offset_unc_ms"] == 2501


def test_cot06_wide_host_is_corrected_and_flagged(tmp_path):
    """COT-06 (owner Q4): a wide host is corrected (offset_ms set), never left raw, and the trial is flagged."""
    rows = agent_rows() + host_pairs("ep-01", [-1000, 0, 7000])
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert r["offset_status"] == "wide"
    assert r["offset_ms"] == 0                                 # median of -1, 0, 7 s
    assert r["offset_unc_ms"] is not None and r["offset_unc_ms"] > 2500
    assert flag(res) == ["ep-01"]
    offsets = correct.offsets_from_rows(res["rows"]["s02_t00"])
    t = to_us(at(50))
    assert correct.corrected_us(t, "ep-01", offsets) == t - r["offset_ms"] * 1000


def test_cot06_status_function_boundaries():
    """COT-06/07: status_for(n_pairs, loo_shift_us, stale) at the documented boundaries."""
    assert estimate.status_for(2, Fraction(2_500_000), False) == "ok"
    assert estimate.status_for(2, Fraction(2_500_001), False) == "wide"
    assert estimate.status_for(1, None, False) == "none"
    assert estimate.status_for(0, None, False) == "none"
    assert estimate.status_for(5, Fraction(0), True) == "stale"


# ====================================================================================== COT-07 MIN_PAIRS (CO-07)

def test_cot07_one_pair_is_none_with_delta_still_reported(tmp_path):
    """COT-07: 1 pair -> status none, offset empty, trial flagged; the single delta stays in pairs.csv."""
    rows = agent_rows() + host_pairs("ep-02", [-6000]) + [sysmon_noise("ep-02", 60)]
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-02")
    assert r["offset_status"] == "none" and r["offset_ms"] is None
    assert r["n_pairs"] == 1
    assert r["median_ms"] == -6000                             # reported for audit only
    assert [p["delta_ms"] for p in res["pairs"]["s02_t00"] if p["host"] == "ep-02"] == [-6000]
    assert "ep-02" in flag(res)
    offsets = correct.offsets_from_rows(res["rows"]["s02_t00"])
    t = to_us(at(50))
    assert correct.corrected_us(t, "ep-02", offsets) == t       # raw times for that host


def test_cot07_two_pairs_is_ok(tmp_path):
    """COT-07: 2 pairs (MIN_PAIRS = 2) -> status ok with an offset."""
    rows = agent_rows() + host_pairs("ep-02", [-6000, -6200]) + [sysmon_noise("ep-02", 60)]
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-02")
    assert r["offset_status"] == "ok" and r["offset_ms"] == -6100 and r["n_pairs"] == 2
    assert "ep-02" not in flag(res)


# ====================================================================================== COT-08 flag scope (CO-08)

def test_cot08_host_without_events_is_none_not_flagged(tmp_path):
    """COT-08: a host with no event in the window: none, host_has_events false, not in clock_flag."""
    rows = agent_rows() + host_pairs("ep-01", [-3000, -3100])
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-03")
    assert r["offset_status"] == "none" and r["offset_ms"] is None and r["n_pairs"] == 0
    assert r["host_has_events"] is False
    assert "ep-03" not in flag(res) and "ep-02" not in flag(res)
    assert flag(res) == []


def test_cot08_event_outside_window_does_not_count_as_events(tmp_path):
    """COT-08: 'has events in the trial window' - an event after the window end (400 s) or before its start does not count."""
    rows = agent_rows() + host_pairs("ep-01", [-3000, -3100]) + [sysmon_noise("ep-03", 500), sysmon_noise("ep-02", -61)]
    _, res = measure(tmp_path, rows)
    assert hrow(res, "ep-03")["host_has_events"] is False and hrow(res, "ep-02")["host_has_events"] is False
    assert flag(res) == []


def test_cot08_sysmon_only_host_is_none_with_events_and_flagged(tmp_path):
    """COT-08 / ATK-12: Sysmon but no Security events in the window: none, host_has_events true, flagged."""
    rows = agent_rows() + host_pairs("ep-01", [-3000, -3100]) + [sysmon_noise("ep-02", 50)]
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-02")
    assert r["offset_status"] == "none" and r["host_has_events"] is True
    assert flag(res) == ["ep-02"]


def test_cot08_wide_stale_none_with_events_all_flagged_ok_not(tmp_path):
    """COT-08: the flag lists none, wide and stale hosts that have events, sorted; ok and reference never."""
    rows = agent_rows()
    rows += host_pairs("ep-01", [-3000, -3100])                                    # ok
    rows += host_pairs("ep-02", [0, 9000], prefix=1) + [sysmon_noise("ep-02", 50)]  # wide
    rows += [sysmon_noise("ep-03", 50)]                                             # none with events
    _, res = measure(tmp_path, rows)
    assert hrow(res, "ep-01")["offset_status"] == "ok"
    assert hrow(res, "ep-02")["offset_status"] == "wide"
    assert hrow(res, "ep-03")["offset_status"] == "none"
    assert flag(res) == ["ep-02", "ep-03"]
    assert hrow(res, "dc01")["offset_status"] == "reference"


# ====================================================================================== COT-09 no dc01 4769 (section 6)

def test_cot09_no_dc01_4769_every_endpoint_none_trial_flagged(tmp_path):
    """COT-09: no dc01 4769 at all -> every endpoint none, no pair, trial flagged for the hosts with events."""
    rows = agent_rows()
    for h in ("ep-01", "ep-02", "ep-03"):
        for i in range(3):
            rows.append(ev(f"{h}-{i}", h, "Security", 4624, 10 + i, logon_guid=guid(h, i), logon_type=3))
    rows.append(ev("dc-other", "dc01", "Security", 4768, 12, logon_guid=guid("ep-01", 0)))
    _, res = measure(tmp_path, rows)
    for h in ("ep-01", "ep-02", "ep-03"):
        r = hrow(res, h)
        assert r["offset_status"] == "none" and r["offset_ms"] is None and r["n_pairs"] == 0
    assert res["pairs"]["s02_t00"] == []
    assert flag(res) == ["ep-01", "ep-02", "ep-03"]


# ====================================================================================== COT-10 determinism (CO-14)

def _rich_rows() -> list[dict]:
    rows = agent_rows() + host_pairs("ep-01", [-15000, -15200, -14800, -14000])
    rows += host_pairs("ep-02", [500, 700, 600], prefix=1) + [sysmon_noise("ep-03", 40)]
    rows += [ev("s3", "ep-01", "Sysmon", 3, 200, destination_ip=LAB_IP["ep-02"], destination_port=5985,
                source_port=49000),
             ev("t4624", "ep-02", "Security", 4624, 200.5, logon_type=3, source_ip=LAB_IP["ep-01"], source_port=49000,
                account_name="admin_it")]
    return rows


OUT_FILES = ("pairs.csv", "stats.json", "report.md", "clock_events.csv", "clock_scan.json")


def test_cot10_two_runs_byte_identical(tmp_path):
    """COT-10: two runs of the same DB give byte-identical offsets CSV, pairs.csv, stats.json and report.md."""
    repo, _ = measure(tmp_path, _rich_rows(), write=True)
    off = repo / "data" / "processed" / "s02_t00.clock_offsets.csv"
    out = repo / "out" / "clock_offset" / "s02_t00"
    first = {n: (out / n).read_bytes() for n in OUT_FILES}
    first["offsets"] = off.read_bytes()
    chg = repo / "data" / "processed" / "s02_t00.clock_changes.csv"
    first["changes"] = chg.read_bytes()
    run.run(repo, ["s02_t00"], write=True)
    assert off.read_bytes() == first["offsets"]
    assert chg.read_bytes() == first["changes"]
    for n in OUT_FILES:
        assert (out / n).read_bytes() == first[n], n


def test_cot10_same_db_in_another_folder_gives_identical_files(tmp_path):
    """COT-10: copying the repo to another path and re-running gives identical files (no path or clock in the output)."""
    repo, _ = measure(tmp_path, _rich_rows(), write=True)
    repo2 = tmp_path / "copy"
    shutil.copytree(repo / "data", repo2 / "data",
                    ignore=shutil.ignore_patterns("*.clock_offsets.csv", "*.clock_changes.csv"))
    run.run(repo2, ["s02_t00"], write=True)
    for suffix in ("clock_offsets", "clock_changes"):
        assert (repo / f"data/processed/s02_t00.{suffix}.csv").read_bytes() == (
            repo2 / f"data/processed/s02_t00.{suffix}.csv").read_bytes(), suffix
    for n in OUT_FILES:
        assert (repo / "out/clock_offset/s02_t00" / n).read_bytes() == (repo2 / "out/clock_offset/s02_t00" / n).read_bytes(), n


def test_cot10_row_order_in_db_does_not_change_result(tmp_path):
    """COT-10: the DB row order does not change offsets or pairs (ignoring the DB hash columns)."""
    rows = _rich_rows()
    results = []
    for i, rr in enumerate([rows, list(reversed(rows))]):
        repo, res = measure(tmp_path, rr, write=True, name=f"o{i}")
        _, off = read_csv(repo / "data/processed/s02_t00.clock_offsets.csv")
        _, prs = read_csv(repo / "out/clock_offset/s02_t00/pairs.csv")
        results.append(([{k: v for k, v in r.items() if k != "db_sha256"} for r in off], prs))
    assert results[0] == results[1]


def test_cot10_rerun_rebuilds_files(tmp_path):
    """Section 3: the offsets file is rebuilt on every run (a stale or altered file is overwritten)."""
    repo, _ = measure(tmp_path, _rich_rows(), write=True)
    off = repo / "data" / "processed" / "s02_t00.clock_offsets.csv"
    good = off.read_bytes()
    off.write_text("garbage\n", encoding="utf-8")
    (repo / "out/clock_offset/s02_t00/pairs.csv").write_text("garbage\n", encoding="utf-8")
    run.run(repo, ["s02_t00"], write=True)
    assert off.read_bytes() == good
    assert (repo / "out/clock_offset/s02_t00/pairs.csv").read_text(encoding="utf-8").startswith("host,event_uid_4624")


# ====================================================================================== COT-11 read-only, no ground_truth

class _Recorder:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def add(self, target) -> None:
        if isinstance(target, int):
            return
        try:
            s = os.fsdecode(os.fspath(target))
        except TypeError:
            return
        if s.startswith("file:"):                     # sqlite URI: file:D:/x/y.sqlite3?mode=ro
            s = s[len("file:"):].split("?", 1)[0]
            if re.match(r"^/+[A-Za-z]:", s):
                s = s.lstrip("/")
        self.paths.append(s)


def _install_recorders(mp: pytest.MonkeyPatch, rec: _Recorder) -> None:
    orig_open, orig_io_open, orig_os_open = builtins.open, io.open, os.open
    orig_connect = sqlite3.connect
    orig_popen, orig_rt, orig_rb = Path.open, Path.read_text, Path.read_bytes

    def w_open(file, *a, **k):
        rec.add(file)
        return orig_open(file, *a, **k)

    def w_io_open(file, *a, **k):
        rec.add(file)
        return orig_io_open(file, *a, **k)

    def w_os_open(path, *a, **k):
        rec.add(path)
        return orig_os_open(path, *a, **k)

    def w_connect(database, *a, **k):
        rec.add(database)
        return orig_connect(database, *a, **k)

    def w_p_open(self, *a, **k):
        rec.add(self)
        return orig_popen(self, *a, **k)

    def w_p_rt(self, *a, **k):
        rec.add(self)
        return orig_rt(self, *a, **k)

    def w_p_rb(self, *a, **k):
        rec.add(self)
        return orig_rb(self, *a, **k)

    mp.setattr(builtins, "open", w_open)
    mp.setattr(io, "open", w_io_open)
    mp.setattr(os, "open", w_os_open)
    mp.setattr(sqlite3, "connect", w_connect)
    mp.setattr(Path, "open", w_p_open)
    mp.setattr(Path, "read_text", w_p_rt)
    mp.setattr(Path, "read_bytes", w_p_rb)


def _under(path: str, root: Path) -> bool:
    try:
        Path(path).resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def test_cot11_recorder_sees_opens(tmp_path, monkeypatch):
    """COT-11 (self-check): the wrappers really record opens, so 'no ground_truth path' is meaningful."""
    rec = _Recorder()
    _install_recorders(monkeypatch, rec)
    p = tmp_path / "x.txt"
    p.write_text("a", encoding="utf-8")
    with open(p, encoding="utf-8") as fh:
        fh.read()
    sqlite3.connect(tmp_path / "y.db").close()
    assert any(Path(x) == p for x in rec.paths) and any(Path(x).name == "y.db" for x in rec.paths)


def test_cot11_db_hash_unchanged_and_recorded(tmp_path):
    """COT-11: the DB hash is the same before and after a run, and stats / offsets file name that hash."""
    repo = make_repo(tmp_path, _rich_rows())
    db = repo / "data" / "processed" / "s02_t00.sqlite3"
    before = sha(db)
    res = run.run(repo, ["s02_t00"], write=True)
    assert sha(db) == before
    st = res["stats"]["s02_t00"]
    assert st["db"]["sha256_before"] == before == st["db"]["sha256_after"]
    _, off = read_csv(repo / "data/processed/s02_t00.clock_offsets.csv")
    assert {r["db_sha256"] for r in off} == {before}
    assert sorted(p.name for p in db.parent.iterdir()) == sorted(
        ["s02_t00.sqlite3", "s02_t00.clock_offsets.csv", "s02_t00.clock_changes.csv"]), (
        "run wrote something else into data/processed")


def test_cot11_db_opened_read_only(tmp_path):
    """COT-11: the step opens the DB read-only (a write through the same code path would fail); no -wal/-journal left."""
    repo = make_repo(tmp_path, _rich_rows())
    db = repo / "data" / "processed" / "s02_t00.sqlite3"
    run.run(repo, ["s02_t00"], write=True)
    assert not list(db.parent.glob("*-wal")) and not list(db.parent.glob("*-journal"))
    with pytest.raises(sqlite3.OperationalError):
        con = sqlite3.connect("file:" + db.resolve().as_posix() + "?mode=ro", uri=True)
        try:
            con.execute("DELETE FROM events")
        finally:
            con.close()


def test_cot11_run_and_cli_never_open_ground_truth(tmp_path, monkeypatch):
    """COT-11: run() and main() open no path under ground_truth/ (and no path with that component)."""
    repo = make_repo(tmp_path, _rich_rows())
    rec = _Recorder()
    with monkeypatch.context() as mp:
        _install_recorders(mp, rec)
        run.run(repo, ["s02_t00"], write=True)
        rc = co_main.main(["--trials", "s02_t00", "--repo", str(repo)])
    assert rc in (0, None)
    assert any(Path(x).name == "s02_t00.sqlite3" for x in rec.paths), "recorder did not see the DB open"
    bad = [p for p in rec.paths if _under(p, REPO / "ground_truth") or "ground_truth" in Path(p).parts]
    assert bad == [], f"clock_offset opened ground_truth paths: {bad}"


def test_cot11_source_text_has_no_ground_truth_string():
    """COT-11: no src/clock_offset/*.py contains the string 'ground_truth' (same scan as GTT-14b)."""
    files = sorted(SRC_CO.glob("*.py"))
    assert files
    hits = [f.name for f in files if "ground_truth" in f.read_text(encoding="utf-8")]
    assert hits == [], f"src/clock_offset mentions ground_truth in: {hits}"


def test_cot11_no_code_reference_to_ground_truth_or_answer_key_builders():
    """COT-11 (docstring-insensitive): no import, string literal (outside docstrings) or path mentions ground_truth,
    and no import of the key builder / finish / verify / overlap."""
    banned_mods = {"answer_key.finish", "answer_key.verify", "answer_key.overlap", "answer_key.build"}
    offenders: list[str] = []
    for f in sorted(SRC_CO.glob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                body = node.body
                if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                    docstrings.add(id(body[0].value))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                if "ground_truth" in node.value or "approved" in node.value:
                    offenders.append(f"{f.name}: string {node.value!r}")
            if isinstance(node, ast.Import):
                offenders += [f"{f.name}: import {a.name}" for a in node.names if a.name in banned_mods]
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                names = {a.name for a in node.names}
                if mod in banned_mods or (mod == "answer_key" and names & {"finish", "verify", "overlap", "build"}):
                    offenders.append(f"{f.name}: from {mod} import {sorted(names)}")
    assert offenders == [], offenders


# ====================================================================================== COT-12 corrected-time function

def _offsets(spec: dict[str, tuple[str, int | None, bool]], trial: str = "s02_t00") -> correct.Offsets:
    rows = [{"trial_id": trial, "host": h, "offset_status": st, "offset_ms": off, "offset_unc_ms": 0,
             "host_has_events": ev_, "db_sha256": "ab" * 32} for h, (st, off, ev_) in spec.items()]
    return correct.offsets_from_rows(rows)


ALL_STATUSES = {"dc01": ("reference", 0, True), "ep-01": ("ok", -18000, True), "ep-02": ("wide", 2500, True),
                "ep-03": ("none", None, True)}


@pytest.mark.parametrize("status,applied", [("ok", True), ("wide", True), ("reference", True), ("none", False),
                                            ("stale", False)])
def test_cot12_corrected_time_by_status(status, applied):
    """COT-12: ok / wide / reference subtract offset_ms; none and stale leave the time unchanged."""
    off = 0 if status == "reference" else (None if status == "none" else 4321)
    o = _offsets({"ep-01": (status, off, True), "dc01": ("reference", 0, True)})
    t = to_us("2026-09-24T05:00:50.123456Z")
    expected = t - 4321 * 1000 if applied and status != "reference" else t
    assert correct.corrected_us(t, "ep-01", o) == expected


def test_cot12_unknown_host_unchanged():
    """COT-12: a host the file does not list is left unchanged."""
    o = _offsets(ALL_STATUSES)
    t = to_us("2026-09-24T05:00:50.000000Z")
    assert correct.corrected_us(t, "ws-99", o) == t


def test_cot12_negative_offset_moves_later_exact_us():
    """COT-12 / CO-09: corrected = event_utc - offset_ms (negative offset -> later), exact in microseconds."""
    o = _offsets(ALL_STATUSES)
    t = to_us("2026-09-24T05:00:50.123456Z")
    assert correct.corrected_us(t, "ep-01", o) == t + 18_000_000
    assert correct.corrected_us(t, "ep-02", o) == t - 2_500_000        # wide is corrected
    assert correct.corrected_us(t, "ep-03", o) == t                    # none is raw
    assert correct.corrected_us(t, "dc01", o) == t


def test_cot12_mixed_host_row_is_clock_unreliable():
    """COT-12 / CO-09: a cross-host row is clock_unreliable when either host is none, wide or stale."""
    o = _offsets({**ALL_STATUSES, "ep-04": ("stale", None, True)})
    assert correct.clock_unreliable("ep-01", "ep-03", offsets=o) is True      # ok + none
    assert correct.clock_unreliable("ep-03", "ep-01", offsets=o) is True
    assert correct.clock_unreliable("ep-01", "ep-02", offsets=o) is True      # ok + wide
    assert correct.clock_unreliable("ep-01", "ep-04", offsets=o) is True      # ok + stale
    assert correct.clock_unreliable("ep-03", "ep-04", offsets=o) is True
    assert correct.clock_unreliable("ep-01", "dc01", offsets=o) is False      # ok + reference
    assert correct.clock_unreliable("ep-01", "ep-01", offsets=o) is False


def test_cot12_offsets_file_roundtrip_and_header(tmp_path):
    """COT-12 / section 3: the written offsets CSV loads back with the same statuses, offsets and flag."""
    repo, res = measure(tmp_path, _rich_rows(), write=True)
    path = repo / "data" / "processed" / "s02_t00.clock_offsets.csv"
    o = correct.load_offsets(path)
    assert o.trial_id == "s02_t00"
    assert o.db_sha256 == sha(repo / "data/processed/s02_t00.sqlite3")
    assert o.file_sha256 == sha(path)
    for r in res["rows"]["s02_t00"]:
        h = o.hosts[r["host"]]
        assert h.status == r["offset_status"] and h.offset_ms == r["offset_ms"]
        assert h.host_has_events == r["host_has_events"]
    assert o.clock_flag == flag(res)


def test_cot12_unknown_status_and_bad_header_rejected():
    """COT-12: a status outside the five spec values, or a header that differs from section 3, is an error."""
    with pytest.raises(ValueError):
        _offsets({"ep-01": ("maybe", 1, True)})
    with pytest.raises(ValueError):
        correct.parse_offsets_text("trial_id,host\ns02_t00,ep-01\n")


# ====================================================================================== COT-13 step after the burst (ATK-01)

def test_cot13_clock_step_after_burst_stays_ok_late_gap_reported(tmp_path):
    """COT-13: pairs only in the start burst; a 12 s step afterwards is invisible: status stays ok, offset unchanged,
    late_gap_s = last agent event (t = 100 s) - last paired 4624 is reported (documents the limit)."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5000, -5000], start=10, step=5)
    # after the step: ep-01's events are 12 s earlier than before, with no LogonGuid pair to show it
    for i in range(4):
        rows.append(ev(f"step-{i}", "ep-01", "Security", 4624, 60 + 10 * i - 12, logon_guid=None,
                       logon_guid_state="zero", logon_type=3))
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert r["offset_status"] == "ok" and r["offset_ms"] == -5000
    assert r["n_pairs"] == 3
    assert r["late_gap_s"] == 100 - (20 - 5)                # last paired 4624 at 15 s (host clock)
    assert r["pair_span_s"] == 10
    assert "ep-01" not in flag(res)


# ====================================================================================== COT-14 MAX_PAIR_DELTA_S

def test_cot14_far_pair_dropped_and_counted(tmp_path):
    """COT-14: a pair 600 s apart is dropped and counted in n_dropped_far; the other pairs still give the offset."""
    rows = agent_rows() + host_pairs("ep-01", [-4000, -4100, -3900, 600_000])
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert r["n_dropped_far"] == 1 and r["n_pairs"] == 3
    assert r["offset_status"] == "ok" and r["offset_ms"] == -4000
    assert r["max_ms"] == -3900                               # the 600 s pair is not in the distribution
    assert all(abs(p["delta_ms"]) <= 60_000 for p in res["pairs"]["s02_t00"])


def test_cot14_boundary_60s_kept_60_001_dropped(tmp_path):
    """COT-14: |delta| > 60 s is dropped; exactly 60 s is kept."""
    _, keep = measure(tmp_path, agent_rows() + host_pairs("ep-01", [2000, 3000, 60_000]), name="k")
    assert hrow(keep, "ep-01")["n_dropped_far"] == 0 and hrow(keep, "ep-01")["n_pairs"] == 3
    _, drop = measure(tmp_path, agent_rows() + host_pairs("ep-01", [2000, 3000, 60_001]), name="d")
    assert hrow(drop, "ep-01")["n_dropped_far"] == 1 and hrow(drop, "ep-01")["n_pairs"] == 2
    _, neg = measure(tmp_path, agent_rows() + host_pairs("ep-01", [2000, 3000, -60_001]), name="n")
    assert hrow(neg, "ep-01")["n_dropped_far"] == 1


def test_cot14_two_pairs_300s_apart_lose_one_so_none(tmp_path):
    """COT-14: 2 pairs 300 s apart (2 s and 302 s): the 302 s pair is dropped, 1 pair is left -> none."""
    rows = agent_rows() + host_pairs("ep-01", [2000, 302_000]) + [sysmon_noise("ep-01", 30)]
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert r["n_dropped_far"] == 1 and r["n_pairs"] == 1
    assert r["offset_status"] == "none" and r["offset_ms"] is None
    assert "ep-01" in flag(res)


# ====================================================================================== COT-15 CO-10 check (raw join)

def _check_trial(extra: list[dict], ep02_deltas=(0, 100, -100), src_t: float = 185) -> list[dict]:
    """ep-01 behind dc01 by 15 s (3 pairs), ep-02 in step with dc01; true time 200 s = ep-01 clock 185 s."""
    rows = agent_rows() + host_pairs("ep-01", [-15000, -15200, -14800])
    if ep02_deltas:
        rows += host_pairs("ep-02", list(ep02_deltas), prefix=1, start=20)
    rows += [sysmon_noise("ep-02", 30)]
    rows.append(ev("s3-a", "ep-01", "Sysmon", 3, src_t, destination_ip=LAB_IP["ep-02"], destination_port=5985,
                   source_port=49000))
    return rows + extra


def _tgt(uid: str, t: float, port: int = 49000, src_ip: str = LAB_IP["ep-01"]) -> dict:
    return ev(uid, "ep-02", "Security", 4624, t, logon_type=3, source_ip=src_ip, source_port=port,
              account_name="admin_it")


def test_cot15_check_row_raw_and_corrected_delta(tmp_path):
    """COT-15: Sysmon 3 on ep-01 -> 4624 on ep-02 by IpPort: raw delta = target - source on host clocks (15.5 s),
    corrected delta uses both offsets (0.5 s); |raw| vs |corrected| reported, method and candidate_count recorded."""
    _, res = measure(tmp_path, _check_trial([_tgt("t-a", 200.5)]))
    chk = res["stats"]["s02_t00"]["check"]
    assert len(chk["rows"]) == 1
    c = chk["rows"][0]
    assert (c["source_host"], c["target_host"], c["destination_port"]) == ("ep-01", "ep-02", 5985)
    assert c["event_uid_sysmon3"] == "s3-a" and c["event_uid_4624"] == "t-a"
    assert c["raw_delta_ms"] == 15_500 and c["time_delta_ms"] == 15_500
    assert c["corrected_delta_ms"] == 500
    assert c["abs_raw_ms"] == 15_500 and c["abs_corrected_ms"] == 500
    assert c["candidate_count"] == 1 and c["ambiguous"] is False
    assert c["method"]
    assert c["clock_unreliable"] is False
    s = chk["summary"]
    assert (s["groups"], s["pairs"]) == (1, 1)
    assert s["worst_raw_abs_ms"] == 15_500 and s["worst_corrected_abs_ms"] == 500


def test_cot15_join_on_raw_time_within_60s_and_ambiguity_reported(tmp_path):
    """COT-15 (ATK-07): the join uses RAW time +-60 s. Two candidates with the source's port within 60 s: the
    raw-nearest one is taken (not the one that would be nearest after correction), candidate_count = 2, ambiguous.
    A candidate 100 s away, one from another source IP and one with another port are not candidates."""
    extra = [_tgt("raw-near", 187.0),          # raw delta 2 s; corrected delta -13 s
             _tgt("corr-near", 200.3),         # raw delta 15.3 s; corrected delta +0.3 s (nearest if joined on corrected)
             _tgt("too-far", 285.0),           # raw delta 100 s: outside +-60 s
             _tgt("other-ip", 186.0, src_ip=LAB_IP["ep-03"]),
             _tgt("other-port", 186.5, port=49001)]
    _, res = measure(tmp_path, _check_trial(extra))
    c = res["stats"]["s02_t00"]["check"]["rows"][0]
    assert c["event_uid_4624"] == "raw-near"
    assert c["candidate_count"] == 2 and c["ambiguous"] is True
    assert c["raw_delta_ms"] == 2000 and c["corrected_delta_ms"] == -13_000
    assert res["stats"]["s02_t00"]["check"]["summary"]["ambiguous_count"] == 1


def test_cot15_boundary_60s_raw_join(tmp_path):
    """COT-15: a target 4624 exactly 60 s (raw) after the connection joins; 60.001 s does not."""
    _, hit = measure(tmp_path, _check_trial([_tgt("edge", 245.0)]), name="hit")
    assert len(hit["stats"]["s02_t00"]["check"]["rows"]) == 1
    _, miss = measure(tmp_path, _check_trial([_tgt("edge", 245.001)]), name="miss")
    assert miss["stats"]["s02_t00"]["check"]["rows"] == []
    assert miss["stats"]["s02_t00"]["check"]["summary"]["unjoined_sysmon3"] == 1


def test_cot15_corrected_delta_null_when_a_host_is_uncorrected(tmp_path):
    """COT-15: when one host of a check pair is uncorrected (ep-02 with 1 pair -> none), the corrected delta is
    empty and the row is clock_unreliable; the raw delta is still given."""
    rows = _check_trial([_tgt("t-a", 200.5)], ep02_deltas=(0,))
    _, res = measure(tmp_path, rows)
    assert hrow(res, "ep-02")["offset_status"] == "none"
    c = res["stats"]["s02_t00"]["check"]["rows"][0]
    assert c["corrected_delta_ms"] is None and c["abs_corrected_ms"] is None
    assert c["raw_delta_ms"] == 15_500
    assert c["clock_unreliable"] is True
    assert res["stats"]["s02_t00"]["check"]["summary"]["uncorrected_count"] == 1


def test_cot15_check_pairs_never_enter_the_estimate_and_dc01_is_excluded(tmp_path):
    """COT-15 (ATK-09): CO-10 pairs do not change the estimate; a Sysmon 3 from an endpoint to dc01:445 or to a
    non-check port is not a check pair."""
    plain = _check_trial([])
    extra = [_tgt("t-a", 200.5),
             ev("s3-dc", "ep-01", "Sysmon", 3, 190, destination_ip=LAB_IP["dc01"], destination_port=445,
                source_port=49100),
             ev("s3-80", "ep-01", "Sysmon", 3, 191, destination_ip=LAB_IP["ep-02"], destination_port=80,
                source_port=49200),
             ev("t-dc", "dc01", "Security", 4624, 190.5, logon_type=3, source_ip=LAB_IP["ep-01"], source_port=49100)]
    _, a = measure(tmp_path, plain, name="a")
    _, b = measure(tmp_path, _check_trial(extra), name="b")
    assert [(r["offset_ms"], r["n_pairs"]) for r in a["rows"]["s02_t00"]] == [
        (r["offset_ms"], r["n_pairs"]) for r in b["rows"]["s02_t00"]]
    rows = b["stats"]["s02_t00"]["check"]["rows"]
    assert [r["event_uid_sysmon3"] for r in rows] == ["s3-a"]


# ====================================================================================== COT-16 reboots (CO-15)

@pytest.mark.parametrize("event_id", [41, 1074, 6005, 6006, 6008])
def test_cot16_boot_after_last_pair_inside_window_is_stale(tmp_path, event_id):
    """COT-16: a System boot/shutdown event after the host's last pair, inside the window: stale, offset empty, flagged."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900])
    rows.append(ev("boot", "ep-01", "System", event_id, 50))
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert r["offset_status"] == "stale" and r["offset_ms"] is None
    assert "ep-01" in flag(res)
    offsets = correct.offsets_from_rows(res["rows"]["s02_t00"])
    t = to_us(at(50))
    assert correct.corrected_us(t, "ep-01", offsets) == t       # not applied
    assert correct.clock_unreliable("ep-01", "dc01", offsets=offsets) is True


def test_cot16_boot_after_window_end_or_on_other_host_is_not_stale(tmp_path):
    """COT-16: a boot after the window end (400 s) is not 'inside the window'; a boot on another host does not
    touch this host."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900]) + host_pairs("ep-02", [100, 200], prefix=1)
    rows += [ev("boot-late", "ep-01", "System", 6005, 500), ev("boot-other", "ep-03", "System", 6005, 50),
             ev("boot-dc", "dc01", "System", 6005, 50)]
    _, res = measure(tmp_path, rows)
    assert hrow(res, "ep-01")["offset_status"] == "ok"
    assert hrow(res, "ep-02")["offset_status"] == "ok"


def test_cot16_sysmon_event_with_boot_id_is_not_a_boot(tmp_path):
    """COT-16: only the System channel counts: a Sysmon / Security event with id 6005 is not a boot, and the
    agent's own Sysmon 1 after the pairs does not make ep-01 stale."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900])
    rows += [ev("fake", "ep-01", "Sysmon", 6005, 50), ev("fake2", "ep-01", "Security", 41, 55)]
    _, res = measure(tmp_path, rows)
    assert hrow(res, "ep-01")["offset_status"] == "ok"


def test_cot16_boot_between_pair_groups_drops_the_earlier_pairs(tmp_path):
    """COT-16 (CO-15): only pairs after the host's last boot are used. Group 1 (2 pairs, -5 s) lies before a boot,
    group 2 (3 pairs, -9 s) after it: the earlier pairs are dropped, status ok, offset from group 2 only."""
    rows = agent_rows()
    rows += host_pairs("ep-01", [-5000, -5000], start=10, step=5, tag="g1")                # 4624s at 5 s and 10 s
    rows += host_pairs("ep-01", [-9000, -9000, -9000], start=30, step=5, prefix=1, tag="g2")  # 4624s at 21, 26, 31 s
    rows.append(ev("boot", "ep-01", "System", 6005, 15))
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert r["n_pairs"] == 3 and r["offset_ms"] == -9000 and r["offset_status"] == "ok"
    assert all(p["event_uid_4624"].startswith("ep-01-4624-g2") for p in res["pairs"]["s02_t00"])


# ====================================================================================== COT-18 clock-change events (CO-18)

@pytest.mark.parametrize("channel,event_id", [("Security", 4616), ("System", 1)])
def test_cot18_clock_change_after_last_pair_is_stale(tmp_path, channel, event_id):
    """COT-18: a Security 4616 or a System 1 after the host's last pair (inside the window): stale."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900])
    rows.append(ev("chg", "ep-01", channel, event_id, 50))
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert r["offset_status"] == "stale" and r["offset_ms"] is None
    assert "ep-01" in flag(res)


@pytest.mark.parametrize("channel,event_id", [("Security", 4616), ("System", 1)])
def test_cot18_clock_change_before_later_pairs_drops_earlier_pairs(tmp_path, channel, event_id):
    """COT-18: a clock change between two pair groups drops the earlier pairs and is not stale."""
    rows = agent_rows()
    rows += host_pairs("ep-01", [-5000, -5000], start=10, step=5, tag="g1")
    rows += host_pairs("ep-01", [-9000, -9000, -9000], start=30, step=5, prefix=1, tag="g2")
    rows.append(ev("chg", "ep-01", channel, event_id, 15))
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert r["offset_status"] == "ok" and r["n_pairs"] == 3 and r["offset_ms"] == -9000
    assert "ep-01" not in flag(res)


def test_cot18_change_between_pair_groups_is_between_pairs_flags_and_is_not_expected(tmp_path):
    """COT-18 / CO-19 as amended (owner 2026-11-12, review SF-1): a 4616 between the two pair groups drops the earlier
    pairs (offset from group 2 only) but, judged against the host's ORIGINAL pairs (4624s at 5 s .. 31 s), it is
    `between_pairs` and sets `clock_change_in_window`; it is not listed as expected and not as stale."""
    rows = agent_rows()
    rows += host_pairs("ep-01", [-5000, -5000], start=10, step=5, tag="g1")
    rows += host_pairs("ep-01", [-9000, -9000, -9000], start=30, step=5, prefix=1, tag="g2")
    rows.append(ev("resync-4616", "ep-01", "Security", 4616, 15))
    _, res = measure(tmp_path, rows)
    paths = key_paths_with(res["stats"]["s02_t00"], "resync-4616")
    assert not any("expected" in p for p in paths), paths
    assert not any("stale" in p for p in paths), paths
    r = hrow(res, "ep-01")
    assert r["offset_status"] == "ok" and r["n_pairs"] == 3 and r["offset_ms"] == -9000    # the earlier pairs are dropped
    (row,) = [c for c in change_rows_of(res) if c["event_uid_or_record"] == "resync-4616"]
    assert row["classification"] == "between_pairs" and row["counted"] is True
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is True


def test_cot18_change_before_the_first_original_pair_is_expected_and_does_not_flag(tmp_path):
    """COT-18 / CO-15 / CO-19: a counted 4616 before the host's very first original pair (first 4624 at 5 s) is listed as
    expected (a snapshot-revert catch-up, or a planned resync), not as stale; it drops no pair and does not set the flag."""
    rows = agent_rows()
    rows += host_pairs("ep-01", [-5000, -5000], start=10, step=5, tag="g1")
    rows += host_pairs("ep-01", [-9000, -9000, -9000], start=30, step=5, prefix=1, tag="g2")
    rows.append(ev("resync-4616", "ep-01", "Security", 4616, 2))
    _, res = measure(tmp_path, rows)
    paths = key_paths_with(res["stats"]["s02_t00"], "resync-4616")
    assert any("expected" in p for p in paths), paths
    assert not any("stale" in p for p in paths), paths
    assert hrow(res, "ep-01")["offset_status"] == "ok" and hrow(res, "ep-01")["n_pairs"] == 5
    (row,) = [c for c in change_rows_of(res) if c["event_uid_or_record"] == "resync-4616"]
    assert row["classification"] == "expected_before_first_pair"
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is False


@pytest.mark.parametrize("t,cls", [(4.999, "expected_before_first_pair"), (5.0, "between_pairs"),
                                   (30.999, "between_pairs"), (31.001, "after_last_pair")])
def test_cot18_original_pair_bounds_boundaries(tmp_path, t, cls):
    """CO-19 (owner 2026-11-12): 'first pair' and 'last pair' are the original pairs' 4624 instants (5.0 s and 31.0 s).
    Only a change strictly before the very first one is expected; at it or after it (up to the last) is between_pairs;
    after the last is after_last_pair, whatever the cut then does to the pairs."""
    files = ChangeFiles()
    _, res = measure(tmp_path, two_groups([files.row("chg", "ep-01", "Security", 4616, t, 5000)]), files=files)
    (row,) = [c for c in change_rows_of(res) if c["event_uid_or_record"] == "chg"]
    assert row["classification"] == cls
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is (cls != "expected_before_first_pair")


def test_cot18_system_1_and_sysmon_1_are_different_events(tmp_path):
    """COT-18: System event 1 (a time change) is not Sysmon event 1: the agent's Sysmon 1 never makes a host stale,
    on any host."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900])
    rows.append(sysmon_noise("ep-01", 60))
    _, res = measure(tmp_path, rows)
    assert hrow(res, "ep-01")["offset_status"] == "ok"


# ====================================================================================== COT-17 params freeze (ATK-10)

def test_cot17_params_hash_matches_decision_043():
    """COT-17: SHA-256 of src/clock_offset/params.py (CRLF -> LF) equals `params_sha256:` in decision 043."""
    text = (REPO / "docs" / "decisions" / "043-clock-offset-method.md").read_text(encoding="utf-8")
    m = re.search(r"params_sha256:\s*`?([0-9a-f]{64})`?", text)
    assert m, "no params_sha256 line in decision 043"
    data = (SRC_CO / "params.py").read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(data).hexdigest() == m.group(1)


def test_cot17_hash_written_to_stats_matches_decision_043(tmp_path):
    """COT-17: the params hash a run writes into stats.json is the one recorded in decision 043."""
    text = (REPO / "docs" / "decisions" / "043-clock-offset-method.md").read_text(encoding="utf-8")
    recorded = re.search(r"params_sha256:\s*`?([0-9a-f]{64})`?", text).group(1)
    _, res = measure(tmp_path, _rich_rows())
    assert res["stats"]["s02_t00"]["parameters"]["params_sha256"] == recorded


def test_cot17_parameter_values_in_spec_section_5():
    """Spec section 5: the frozen parameter values."""
    from clock_offset import params
    assert params.PAIR_PAD_S == 1800 and params.DC_EDGE_S == 120
    assert params.MIN_PAIRS == 2 and params.MAX_LOO_SHIFT_S == 2.5 and params.READING_AGREE_S == 2.5
    assert tuple(params.CHECK_PORTS) == (445, 3389, 5985, 5986)
    assert params.MAX_PAIR_DELTA_S == 60 and params.CHECK_JOIN_S == 60 and params.CHECK_REVIEW_S == 2.5
    assert params.MIN_CLOCK_STEP_MS == 1000                      # owner D1 (provisional, spec 08 section 5)
    assert params.METHOD == METHOD
    assert set(params.STATUSES) == STATUSES
    assert tuple(params.OFFSETS_COLUMNS) == tuple(OFFSETS_HEADER)
    assert tuple(params.PAIRS_COLUMNS) == tuple(PAIRS_HEADER)


# ====================================================================================== COT-20 CO-17 refusal

def _o17(**hosts: tuple[str, int | None, bool]) -> correct.Offsets:
    spec = {"dc01": ("reference", 0, True)}
    spec.update({h.replace("_", "-"): v for h, v in hosts.items()})
    return _offsets(spec)


START_AFTER = to_us("2026-10-26T04:00:00.000Z")


@pytest.mark.parametrize("status,off", [("none", None), ("stale", None)])
def test_cot20_refusal_on_or_after_cutoff_for_none_or_stale_host_with_events(status, off):
    """COT-20 (CO-17): window start on/after 2026-10-26 and a none/stale host with events -> refusal naming it."""
    o = _o17(ep_01=("ok", -14000, True), ep_02=(status, off, True), ep_03=("ok", 100, True))
    reason = correct.co17_refusal(o, START_AFTER)
    assert reason and "ep-02" in reason and status in reason
    assert "ep-01" not in reason and "ep-03" not in reason


def test_cot20_cutoff_boundary_exact():
    """COT-20: 2026-10-26T00:00:00.000Z is refused (on the date), 2026-10-25T23:59:59.999999Z is not."""
    o = _o17(ep_01=("none", None, True))
    assert correct.co17_refusal(o, to_us("2026-10-26T00:00:00.000Z"))
    assert correct.co17_refusal(o, to_us("2026-10-25T23:59:59.999999Z")) is None


def test_cot20_no_refusal_before_cutoff_date():
    """COT-20: before the date the trial runs on raw times (flag carried), so no refusal."""
    o = _o17(ep_01=("none", None, True), ep_02=("stale", None, True))
    assert correct.co17_refusal(o, to_us("2026-09-24T05:00:00.000Z")) is None


def test_cot20_wide_host_runs():
    """COT-20: a wide host is corrected and runs: no refusal, even after the date."""
    o = _o17(ep_01=("wide", -14000, True), ep_02=("ok", 0, True))
    assert correct.co17_refusal(o, START_AFTER) is None


def test_cot20_none_host_without_events_no_refusal():
    """COT-20 (CO-08): a none host with no events in the window has nothing to correct: no refusal."""
    o = _o17(ep_01=("ok", -14000, True), ep_02=("none", None, False), ep_03=("stale", None, False))
    assert correct.co17_refusal(o, START_AFTER) is None


def test_cot20_all_ok_no_refusal_and_reference_never_refused():
    """COT-20: ok hosts and the reference host never cause a refusal."""
    o = _o17(ep_01=("ok", -14000, True), ep_02=("ok", 0, True), ep_03=("ok", 5, True))
    assert correct.co17_refusal(o, START_AFTER) is None


def test_cot20_refusal_through_run_preview_matches(tmp_path):
    """COT-20: stats.json carries the CO-17 preview; a synthetic trial on 2026-09-24 has none."""
    _, res = measure(tmp_path, agent_rows() + host_pairs("ep-01", [-5000]))
    st = res["stats"]["s02_t00"]
    assert st["co17_refusal_preview"] is None
    assert flag(res) == ["ep-01"]


# ====================================================================================== section 3 contract

def test_contract_offsets_csv_header_rows_types(tmp_path):
    """Section 3: header = the spec column list in order; 4 rows sorted by host; dc01 = 0 / reference; cell types."""
    repo, res = measure(tmp_path, _rich_rows(), write=True)
    header, body = read_csv(repo / "data" / "processed" / "s02_t00.clock_offsets.csv")
    assert header == OFFSETS_HEADER
    assert [r["host"] for r in body] == ["dc01", "ep-01", "ep-02", "ep-03"]
    assert [r["host"] for r in body] == sorted(r["host"] for r in body)
    dc = body[0]
    assert dc["offset_ms"] == "0" and dc["offset_status"] == "reference"
    for r in body:
        assert r["trial_id"] == "s02_t00" and r["method"] == METHOD
        assert r["offset_status"] in STATUSES
        assert r["host_has_events"] in ("true", "false")
        for c in INT_COLUMNS:
            assert r[c] == "" or re.fullmatch(r"-?\d+", r[c]), (c, r[c])
        assert r["db_sha256"] == sha(repo / "data/processed/s02_t00.sqlite3")
        assert r["tool_version"]
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", r["search_start_utc"])
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", r["search_end_utc"])
        assert (r["offset_ms"] == "") == (r["offset_status"] in ("none", "stale"))
        # review SF-3 / SF-4: the two trial-level binding columns, repeated on every row
        assert r["clock_changes_sha256"] == sha(repo / "data/processed/s02_t00.clock_changes.csv")
        assert r["clock_scan"] == "complete"
    ep1, ep2, ep3 = body[1], body[2], body[3]
    assert ep1["offset_status"] == "ok" and ep1["n_pairs"] == "4"
    assert ep3["offset_status"] == "none" and ep3["offset_ms"] == "" and ep3["n_pairs"] == "0"
    assert ep3["median_ms"] == "" and ep3["loo_shift_ms"] == "" and ep3["late_gap_s"] == ""
    # the CSV is the in-memory result
    assert [r["offset_status"] for r in body] == [r["offset_status"] for r in res["rows"]["s02_t00"]]
    assert b"\r" not in (repo / "data/processed/s02_t00.clock_offsets.csv").read_bytes()


def test_contract_pairs_csv_columns_counts_and_links(tmp_path):
    """Section 3: pairs.csv has the spec columns; one row per used pair (none lost, none duplicated); every row records
    method, candidate_count, time_delta_ms and both event uids; the uids exist in the DB."""
    repo, res = measure(tmp_path, _rich_rows(), write=True)
    header, body = read_csv(repo / "out/clock_offset/s02_t00/pairs.csv")
    assert header == PAIRS_HEADER
    n_expected = sum(int(r["n_pairs"]) for r in res["rows"]["s02_t00"])
    assert len(body) == n_expected == 7
    keys = [(r["event_uid_4624"], r["event_uid_4769"]) for r in body]
    assert len(set(keys)) == len(keys)
    assert len({r["event_uid_4624"] for r in body}) == len(body) == len({r["event_uid_4769"] for r in body})
    con = sqlite3.connect(repo / "data/processed/s02_t00.sqlite3")
    uids = {u for (u,) in con.execute("SELECT event_uid FROM events_dedup")}
    con.close()
    for r in body:
        assert r["method"] == METHOD and r["candidate_count"] == "1" and r["time_delta_ms"] == r["delta_ms"]
        assert r["event_uid_4624"] in uids and r["event_uid_4769"] in uids
        assert r["host"] in ("ep-01", "ep-02")
        assert r["logon_guid"] == r["logon_guid"].lower() and "{" not in r["logon_guid"]
        assert r["logon_type"] == "3" and r["account_name"] == "svc_sql" and r["service_name"] == "ENDPOINT-01$"
    assert [r["host"] for r in body] == sorted(r["host"] for r in body)
    for r in body:                                           # delta = 4624 - 4769 on the original times
        d = (datetime.fromisoformat(r["t_4624_utc"].replace("Z", "+00:00"))
             - datetime.fromisoformat(r["t_4769_utc"].replace("Z", "+00:00")))
        assert round(d.total_seconds() * 1000) == int(r["delta_ms"])


def test_contract_stats_and_report_files_exist(tmp_path):
    """Section 3: out/clock_offset/<trial>/ holds pairs.csv, stats.json (with clock_flag and the CO-10 check) and report.md."""
    repo, res = measure(tmp_path, _rich_rows(), write=True)
    out = repo / "out" / "clock_offset" / "s02_t00"
    for n in OUT_FILES:
        assert (out / n).exists(), n
    st = json.loads((out / "stats.json").read_text(encoding="utf-8"))
    assert st["clock_flag"] == flag(res)
    assert "check" in st and "summary" in st["check"]
    assert st["check"]["summary"]["pairs"] == 1
    rep = (out / "report.md").read_text(encoding="utf-8")
    assert "ep-01" in rep and "s02_t00" in rep
    for banned in ("reduces false positives", "detects stolen", "identifies the attacker"):
        assert banned not in rep.lower()


def test_contract_original_times_never_changed_and_no_gate_columns(tmp_path):
    """CO-09 / section 3: pairs.csv keeps the original event_utc text; no gate_tier / confidence_tier columns."""
    repo, res = measure(tmp_path, _rich_rows(), write=True)
    header, body = read_csv(repo / "out/clock_offset/s02_t00/pairs.csv")
    assert not {"gate_tier", "confidence_tier"} & set(header)
    assert body[0]["t_4624_utc"] in {r["event_utc"] for r in _rich_rows()}


def test_contract_stats_trial_role_for_synthetic_trial(tmp_path):
    """COA-04 helper: a development trial id is labelled development, a clock-only id clock-only, others other."""
    assert run.trial_role("s02_t00") == "development"
    assert run.trial_role("s06_t01") == "development"
    assert run.trial_role("s04_t01") == "clock-only" and run.trial_role("s07_t01") == "clock-only"
    assert run.trial_role("s02_t05") == "other"


def test_contract_trial_without_agent_root_is_refused_not_invented(tmp_path):
    """Section 2: the search span comes from the agent window; a DB with no agent root gives no offsets file."""
    repo = make_repo(tmp_path, host_pairs("ep-01", [-5000, -5100, -4900]))
    res = run.run(repo, ["s02_t00"], write=True)
    assert "s02_t00" in res["refused"] and "s02_t00" not in res["rows"]
    assert _no_output(repo, "s02_t00")


def test_contract_cli_runs_and_prints_rows(tmp_path, capsys):
    """CLI: main(--trials --repo) writes the files and prints one line per host."""
    repo = make_repo(tmp_path, _rich_rows())
    rc = co_main.main(["--trials", "s02_t00", "--repo", str(repo)])
    out = capsys.readouterr().out
    assert rc in (0, None)
    assert (repo / "data/processed/s02_t00.clock_offsets.csv").exists()
    assert "ep-01" in out and "ok" in out


def test_contract_missing_db_for_allowed_trial_is_an_error_and_writes_nothing(tmp_path):
    """Section 2: an allowed trial without a DB is a hard error (nothing written, not even for the other trial)."""
    repo = make_repo(tmp_path, _rich_rows())
    with pytest.raises(run.ClockOffsetError):
        run.run(repo, ["s02_t00", "s03_t00"], write=True)
    assert _no_output(repo, "s02_t00")


# ====================================================================================== B. real data (COA)

ALLOWLIST = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00", "s02_t01", "s03_t01", "s06_t01",
             "s04_t01", "s07_t01"]
DEVELOPMENT = ALLOWLIST[:9]
CLOCK_ONLY = ALLOWLIST[9:]

# T6b.1 reference (ms): host -> (n_pairs, median_ms); n = 0 -> no median.
REFERENCE = {
    "s02_t00": {"ep-01": (6, 1676.478), "ep-02": (3, 246.518), "ep-03": (0, None)},
    "s03_t00": {"ep-01": (6, 2610.994), "ep-02": (0, None), "ep-03": (4, 3803.286)},
    "s04_t00": {"ep-01": (6, -1140.990), "ep-02": (3, -1660.837), "ep-03": (0, None)},
    "s05_t00": {"ep-01": (4, 795.184), "ep-02": (23, 2684.085), "ep-03": (5, 4534.648)},
    "s06_t00": {"ep-01": (6, -677.513), "ep-02": (12, 2097.960), "ep-03": (5, 3795.259)},
    "s07_t00": {"ep-01": (6, 3367.142), "ep-02": (13, 74.227), "ep-03": (0, None)},
    "s02_t01": {"ep-01": (2, 3759.825), "ep-02": (10, 744.491), "ep-03": (2, 3546.960)},
    "s03_t01": {"ep-01": (5, -2249.166), "ep-02": (10, 1880.019), "ep-03": (3, 3912.333)},
    "s06_t01": {"ep-01": (5, -18780.755), "ep-02": (8, -2238.388), "ep-03": (3, 44.356)},
    "s04_t01": {"ep-01": (5, -14659.622), "ep-02": (5, -555.786), "ep-03": (2, 3201.088)},
    "s07_t01": {"ep-01": (2, -12257.962), "ep-02": (6, -405.121), "ep-03": (1, -53.793)},
}
NO_LOGS = [("s02_t00", "ep-03"), ("s04_t00", "ep-03"), ("s07_t00", "ep-03"), ("s03_t00", "ep-02")]


def _db(trial: str) -> Path:
    assert trial in ALLOWLIST, f"{trial} is not on the test's real-data allowlist"
    p = PROCESSED / f"{trial}.sqlite3"
    if not p.exists():
        pytest.skip(f"{p} missing")
    return p


@pytest.fixture(scope="module")
def real():
    """Runs the step once on the 11 allowlisted trials, in memory (write=False), recording every opened path."""
    for t in ALLOWLIST:
        _db(t)
    before = {t: sha(PROCESSED / f"{t}.sqlite3") for t in ALLOWLIST}
    rec = _Recorder()
    with pytest.MonkeyPatch.context() as mp:
        _install_recorders(mp, rec)
        res = run.run(REPO, list(ALLOWLIST), write=False, scan=False)      # the export scan has its own fixture
    after = {t: sha(PROCESSED / f"{t}.sqlite3") for t in ALLOWLIST}
    return {"res": res, "paths": rec.paths, "before": before, "after": after}


def _rows(real, trial: str) -> dict[str, dict]:
    return {r["host"]: r for r in real["res"]["rows"][trial]}


@pytest.mark.slow
def test_coa_real_only_allowlisted_dbs_opened_and_no_ground_truth(real):
    """Real-data guard: only the 11 allowlisted trial DBs are opened (no t02-t10, no S05 quarantine, no S01) and
    nothing under ground_truth/ is opened; DB hashes are unchanged after the run (COT-11)."""
    dbs = {Path(p).name for p in real["paths"] if p.lower().endswith(".sqlite3")}
    assert dbs == {f"{t}.sqlite3" for t in ALLOWLIST}, sorted(dbs ^ {f"{t}.sqlite3" for t in ALLOWLIST})
    bad = [p for p in real["paths"] if _under(p, REPO / "ground_truth") or "ground_truth" in Path(p).parts]
    assert bad == []
    assert real["before"] == real["after"]
    assert real["res"]["refused"] == {}
    assert set(real["res"]["rows"]) == set(ALLOWLIST)
    for t in ALLOWLIST:
        st = real["res"]["stats"][t]
        assert st["db"]["sha256_before"] == real["before"][t] == st["db"]["sha256_after"]


@pytest.mark.slow
@pytest.mark.parametrize("trial", ALLOWLIST)
def test_coa01_offsets_equal_t6b1_reference(real, trial):
    """COA-01: offset_ms and n_pairs equal the T6b.1 reference within 1 ms (1-pair hosts: offset empty, median reported)."""
    rows = _rows(real, trial)
    assert set(rows) == {"dc01", "ep-01", "ep-02", "ep-03"}
    problems = []
    for host, (n, med) in REFERENCE[trial].items():
        r = rows[host]
        if r["n_pairs"] != n:
            problems.append(f"{host}: n_pairs {r['n_pairs']} != {n}")
        if n == 0:
            if r["offset_status"] != "none" or r["offset_ms"] is not None:
                problems.append(f"{host}: expected none/empty, got {r['offset_status']}/{r['offset_ms']}")
        elif n == 1:
            if r["offset_status"] != "none" or r["offset_ms"] is not None:
                problems.append(f"{host}: 1 pair must be none/empty, got {r['offset_status']}/{r['offset_ms']}")
            if r["median_ms"] is None or abs(r["median_ms"] - med) > 1:
                problems.append(f"{host}: median_ms {r['median_ms']} vs {med}")
        else:
            if r["offset_ms"] is None or abs(r["offset_ms"] - med) > 1:
                problems.append(f"{host}: offset_ms {r['offset_ms']} vs {med} (event_uids: "
                                f"{[p['event_uid_4624'] for p in real['res']['pairs'][trial] if p['host'] == host]})")
            if r["offset_status"] not in ("ok", "wide"):
                problems.append(f"{host}: status {r['offset_status']}")
    assert not problems, f"{trial}: " + "; ".join(problems)
    assert rows["dc01"]["offset_ms"] == 0 and rows["dc01"]["offset_status"] == "reference"


@pytest.mark.slow
@pytest.mark.parametrize("trial", ALLOWLIST)
def test_coa_contract_no_pair_lost_or_duplicated(real, trial):
    """Section 3 on real data: pairs rows = sum of n_pairs; each event used once; delta = 4624 - 4769; far pairs bounded."""
    prs = real["res"]["pairs"][trial]
    rows = real["res"]["rows"][trial]
    assert len(prs) == sum(r["n_pairs"] for r in rows)
    assert len({p["event_uid_4624"] for p in prs}) == len(prs)
    for host in {p["host"] for p in prs}:                        # CO-03: each event used at most once PER HOST
        mine = [p for p in prs if p["host"] == host]
        assert len({p["event_uid_4769"] for p in mine}) == len(mine), host
    assert all(abs(p["delta_ms"]) <= 60_000 for p in prs)
    assert all(p["method"] == METHOD and p["time_delta_ms"] == p["delta_ms"] and p["candidate_count"] >= 1
               for p in prs)
    assert [r["host"] for r in rows] == sorted(r["host"] for r in rows)
    assert sum(r["n_dropped_far"] for r in rows) == 0           # spec 10.7: 60 s drops no measured pair


def _check_rows(real, trials) -> list[tuple[str, dict]]:
    return [(t, c) for t in trials for c in real["res"]["stats"][t]["check"]["rows"]]


@pytest.mark.slow
def test_coa02_co10_every_corrected_delta_within_5s(real):
    """COA-02 (CO-11a kill criterion): on the 9 development trials every corrected |delta| <= 5 s; 6 groups / 18 pairs."""
    chk = _check_rows(real, DEVELOPMENT)
    groups = {(t, c["source_host"], c["target_host"], c["destination_port"]) for t, c in chk}
    worst_raw = max(c["abs_raw_ms"] for _, c in chk)
    corr = [c["abs_corrected_ms"] for _, c in chk]
    print(f"\nCOA-02: {len(groups)} groups, {len(chk)} pairs, worst raw {worst_raw} ms, worst corrected {max(corr)} ms")
    assert all(x is not None for x in corr), "a development check pair could not be corrected"
    over = [(t, c["event_uid_sysmon3"], c["event_uid_4624"], c["abs_corrected_ms"]) for t, c in chk
            if c["abs_corrected_ms"] > 5000]
    assert over == [], f"kill criterion (a) hit: {over}"
    assert (len(groups), len(chk)) == (6, 18)
    assert not any(c["kill"] for _, c in chk)


@pytest.mark.slow
def test_coa02_co10_no_pair_above_review_level_and_summary_matches(real):
    """COA-02 (spec 10.5): no check pair is above the 2.5 s review level; worst raw ~18.35 s, worst corrected ~1.58 s."""
    chk = _check_rows(real, DEVELOPMENT)
    assert not [c for _, c in chk if c["review"]]
    worst_raw = max(c["abs_raw_ms"] for _, c in chk)
    worst_corr = max(c["abs_corrected_ms"] for _, c in chk)
    assert 18_000 <= worst_raw <= 18_700
    assert worst_corr <= 2500
    assert abs(worst_corr - 1580) <= 20
    for t in DEVELOPMENT:
        s = real["res"]["stats"][t]["check"]["summary"]
        assert s["kill_count"] == 0 and s["uncorrected_count"] == 0


@pytest.mark.slow
def test_coa02_co10_clock_only_trials_have_no_check_pairs(real):
    """Spec 10.5: s04_t01 and s07_t01 have no endpoint-to-endpoint check pair (0 groups)."""
    assert _check_rows(real, CLOCK_ONLY) == []


@pytest.mark.slow
def test_coa03_s06_t01_ep01_offset_and_winrm_check_pairs(real):
    """COA-03: s06_t01 ep-01 offset in [-19.5, -18.0] s and ok; the ep-01 -> ep-02 / ep-03 WinRM pairs go from
    raw ~16.7 / ~18.3 s to corrected |delta| <= 1 s."""
    r = _rows(real, "s06_t01")["ep-01"]
    assert r["offset_status"] == "ok"
    assert -19_500 <= r["offset_ms"] <= -18_000
    chk = [c for c in real["res"]["stats"]["s06_t01"]["check"]["rows"] if c["source_host"] == "ep-01"]
    to02 = [c for c in chk if c["target_host"] == "ep-02" and c["destination_port"] == 5985]
    to03 = [c for c in chk if c["target_host"] == "ep-03" and c["destination_port"] == 5985]
    assert to02 and to03
    assert 16_000 <= max(c["abs_raw_ms"] for c in to02) <= 17_500
    assert 17_500 <= max(c["abs_raw_ms"] for c in to03) <= 19_000
    for c in to02 + to03:
        assert c["abs_corrected_ms"] <= 1000, c
        assert c["abs_corrected_ms"] < c["abs_raw_ms"] and c["net_effect"] == "better"


@pytest.mark.slow
def test_coa04_clock_only_trials_produce_rows_and_are_labelled(real):
    """COA-04: s04_t01 and s07_t01 produce offsets rows and are labelled clock-only; the development trials are not."""
    for t in CLOCK_ONLY:
        assert real["res"]["stats"][t]["trial_role"] == "clock-only"
        assert len(real["res"]["rows"][t]) == 4
        assert real["res"]["pairs"][t]
    for t in DEVELOPMENT:
        assert real["res"]["stats"][t]["trial_role"] == "development"
    assert _rows(real, "s04_t01")["ep-01"]["offset_status"] == "ok"
    assert _rows(real, "s04_t01")["ep-01"]["offset_ms"] < -14_000
    assert _rows(real, "s07_t01")["ep-01"]["offset_ms"] < -12_000


@pytest.mark.slow
@pytest.mark.parametrize("trial,host", NO_LOGS)
def test_coa06_hosts_without_exported_logs_none_and_not_flagged(real, trial, host):
    """COA-06: the four hosts with no exported logs are none, host_has_events false, and not in clock_flag."""
    r = _rows(real, trial)[host]
    assert r["offset_status"] == "none" and r["offset_ms"] is None and r["n_pairs"] == 0
    assert r["host_has_events"] is False
    assert host not in real["res"]["stats"][trial]["clock_flag"]


@pytest.mark.slow
def test_coa_s06_t01_ep03_wide_and_s07_t01_ep03_none(real):
    """Spec 10.1 / 5: s06_t01 ep-03 is wide (loo shift 2.97 s > 2.5 s, still corrected, flagged); s07_t01 ep-03 has
    1 pair -> none, flagged."""
    r = _rows(real, "s06_t01")["ep-03"]
    assert r["offset_status"] == "wide" and r["offset_ms"] is not None
    assert 2500 < r["offset_unc_ms"] <= 3200
    assert "ep-03" in real["res"]["stats"]["s06_t01"]["clock_flag"]
    r7 = _rows(real, "s07_t01")["ep-03"]
    assert r7["offset_status"] == "none" and r7["offset_ms"] is None and r7["n_pairs"] == 1
    assert r7["host_has_events"] is True
    assert "ep-03" in real["res"]["stats"]["s07_t01"]["clock_flag"]


@pytest.mark.slow
def test_coa_clock_flag_matches_status_and_events_on_all_trials(real):
    """CO-08 on real data: clock_flag = hosts with status none/wide/stale that have events, for every trial."""
    for t in ALLOWLIST:
        rows = real["res"]["rows"][t]
        expect = sorted(r["host"] for r in rows if r["offset_status"] in ("none", "wide", "stale")
                        and r["host_has_events"])
        assert real["res"]["stats"][t]["clock_flag"] == expect, t
        assert "dc01" not in expect


@pytest.mark.slow
def test_coa_written_files_match_in_memory_result_on_real_trial(real, tmp_path):
    """Contract on a real trial: running into a COPY of the DB tree (tmp repo) writes an offsets file equal to the
    in-memory rows. The real data/processed is not written."""
    trial = "s02_t01"
    repo = tmp_path / "repo"
    (repo / "data" / "processed").mkdir(parents=True)
    shutil.copy(_db(trial), repo / "data" / "processed" / f"{trial}.sqlite3")
    if (REPO / "data" / "manifest.csv").exists():
        shutil.copy(REPO / "data" / "manifest.csv", repo / "data" / "manifest.csv")
    res = run.run(repo, [trial], write=True, scan=True)       # SF-3: a write needs the scan (no JSONL exports in the copy)
    header, body = read_csv(repo / "data" / "processed" / f"{trial}.clock_offsets.csv")
    assert header == OFFSETS_HEADER and len(body) == 4
    for csv_row, mem in zip(body, real["res"]["rows"][trial]):
        assert csv_row["host"] == mem["host"] and csv_row["offset_status"] == mem["offset_status"]
        assert csv_row["offset_ms"] == ("" if mem["offset_ms"] is None else str(mem["offset_ms"]))
        assert csv_row["n_pairs"] == str(mem["n_pairs"])
    assert res["stats"][trial]["clock_flag"] == real["res"]["stats"][trial]["clock_flag"]
    # SF-3 / SF-4: the copy has no exports although data/manifest.csv lists them, so the scan is incomplete and the
    # offsets file says so; the changes hash names the changes file written in the same run.
    chg_sha = sha(repo / "data" / "processed" / f"{trial}.clock_changes.csv")
    assert {r["clock_scan"] for r in body} == {"incomplete"} and {r["clock_changes_sha256"] for r in body} == {chg_sha}
    assert res["stats"][trial]["clock_scan"] == "incomplete" and res["stats"][trial]["clock_change_in_window"] is None


# ====================================================================================== D1/D2: counted changes

CHANGES_HEADER = ["trial_id", "host", "channel", "event_id", "change_utc", "previous_time", "new_time", "shift_ms",
                  "counted", "classification", "last_boot_before_utc", "source", "event_uid_or_record",
                  "source_sha256"]
SPEC_CHANGES_COLUMNS = ["trial_id", "host", "change_utc", "previous_time", "new_time", "shift_ms", "counted",
                        "classification", "source", "event_uid_or_record", "source_sha256"]
EVENTS_HEADER = ["host", "channel", "event_id", "provider", "timestamp_raw", "previous_time", "new_time", "shift_ms",
                 "counted", "classification", "record_index", "source_sha256"]
SPEC_EVENTS_COLUMNS = ["host", "channel", "event_id", "provider", "timestamp_raw", "previous_time", "new_time",
                       "shift_ms", "record_index", "source_sha256"]


def is_subsequence(sub: list[str], full: list[str]) -> bool:
    it = iter(full)
    return all(any(x == y for y in it) for x in sub)


def two_groups(extra: list[dict], g1: int = -5000, g2: int = -9000) -> list[dict]:
    """ep-01: 2 pairs at -5 s (4624s at 5 s and 10 s), 3 pairs at -9 s (4624s at 21, 26, 31 s)."""
    rows = agent_rows()
    rows += host_pairs("ep-01", [g1, g1], start=10, step=5, tag="g1")
    rows += host_pairs("ep-01", [g2, g2, g2], start=30, step=5, prefix=1, tag="g2")
    return rows + extra


def change_rows_of(res: dict, trial: str = "s02_t00") -> list[dict]:
    return res["clock"][trial]["changes_rows"]


@pytest.mark.parametrize("shift", [999, -999, 2, -2, 1, 0])
def test_d1_routine_change_below_1s_changes_nothing(tmp_path, shift):
    """D1: a clock change with |shift| < 1000 ms (Windows time-service adjustment) is routine: nothing is dropped,
    the host is not stale, the change is listed with counted false and classification routine."""
    files = ChangeFiles()
    rows = two_groups([files.row("chg", "ep-01", "Security", 4616, 15, shift)])
    _, res = measure(tmp_path, rows, files=files)
    r = hrow(res, "ep-01")
    assert r["n_pairs"] == 5 and r["offset_status"] == "ok"
    assert "ep-01" not in flag(res)
    (row,) = [c for c in change_rows_of(res) if c["event_uid_or_record"] == "chg"]
    assert row["counted"] is False and row["classification"] == "routine" and row["shift_ms"] == shift
    assert "chg" in res["stats"]["s02_t00"]["evidence"]["per_host"]["ep-01"]["routine_clock_change_uids"]
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is False


@pytest.mark.parametrize("shift,counted", [(999, False), (-999, False), (1000, True), (-1000, True),
                                           (1001, True), (8480, True), (-8480, True)])
def test_d1_boundary_999_vs_1000_ms(tmp_path, shift, counted):
    """D1 / D2: |shift| = 999 ms does not count, 1000 ms does (>= MIN_CLOCK_STEP_MS, both directions). A counted
    change between the pair groups drops the earlier two pairs and is `between_pairs` (original-pairs rule); an uncounted
    one drops none and is `routine`."""
    files = ChangeFiles()
    rows = two_groups([files.row("chg", "ep-01", "System", 1, 15, shift)])
    _, res = measure(tmp_path, rows, files=files)
    r = hrow(res, "ep-01")
    (row,) = [c for c in change_rows_of(res) if c["event_uid_or_record"] == "chg"]
    assert row["counted"] is counted
    if counted:
        assert r["n_pairs"] == 3 and r["offset_ms"] == -9000 and r["offset_status"] == "ok"
        # owner 2026-11-12 (review SF-1, CO-19): the classification uses the ORIGINAL pairs (4624s at 5 s .. 31 s), so a
        # counted change at 15 s is between them: `between_pairs` and it flags, although the cut drops the earlier two.
        assert row["classification"] == "between_pairs"
        assert res["stats"]["s02_t00"]["clock_change_in_window"] is True
    else:
        assert r["n_pairs"] == 5 and row["classification"] == "routine"


@pytest.mark.parametrize("channel,event_id", [("Security", 4616), ("System", 1)])
def test_d1_unknown_shift_counts(tmp_path, channel, event_id):
    """D1: a clock change whose shift cannot be read counts: no pointer, a missing JSONL file, or a record without
    PreviousTime/NewTime. The reason is listed in stats."""
    rows = two_groups([ev("nopointer", "ep-01", channel, event_id, 15)])
    _, res = measure(tmp_path, rows)
    r = hrow(res, "ep-01")
    assert r["n_pairs"] == 3 and r["offset_ms"] == -9000
    (row,) = [c for c in change_rows_of(res) if c["event_uid_or_record"] == "nopointer"]
    assert row["counted"] is True and row["shift_ms"] is None
    unresolved = res["stats"]["s02_t00"]["clock_change_scan"]["db_shift_unresolved"]
    assert [u["event_uid"] for u in unresolved] == ["nopointer"] and unresolved[0]["reason"]


def test_d1_unknown_shift_missing_file_and_missing_fields_count(tmp_path):
    """D1: a pointer to a missing JSONL file, and a JSONL record with no NewTime, both give an unknown (counted) change."""
    files = ChangeFiles()
    gone = files.row("gone", "ep-01", "Security", 4616, 12, 5000)
    files.lines.clear()                                             # the file is never written
    files2 = ChangeFiles()
    no_new = files2.row("nonew", "ep-01", "System", 1, 15, 5000)
    files2.lines[("ep-01", "system")][0] = mkrec("System", 1, 15, KG, prev=at(10))        # OldTime only
    rows = two_groups([gone, no_new])
    _, res = measure(tmp_path, rows, files=files2)
    by = {c["event_uid_or_record"]: c for c in change_rows_of(res)}
    assert by["gone"]["counted"] is True and by["gone"]["shift_ms"] is None
    assert by["nonew"]["counted"] is True and by["nonew"]["shift_ms"] is None


def test_d1_boot_always_counts_even_with_no_shift(tmp_path):
    """D1: boots always count (no shift involved): a boot between the groups drops the earlier pairs."""
    rows = two_groups([ev("boot", "ep-01", "System", 6005, 15)])
    _, res = measure(tmp_path, rows)
    assert hrow(res, "ep-01")["n_pairs"] == 3


def test_d2_shift_read_from_jsonl_pointer_exact(tmp_path):
    """D2: the shift of a DB 4616 / System 1 row is read from its JSONL line (PreviousTime/NewTime, OldTime/NewTime)."""
    files = ChangeFiles()
    rows = two_groups([files.row("sec", "ep-01", "Security", 4616, 15, 8480),
                       files.row("sys", "ep-01", "System", 1, 16, -3000)])
    _, res = measure(tmp_path, rows, files=files)
    by = {c["event_uid_or_record"]: c for c in change_rows_of(res)}
    assert by["sec"]["shift_ms"] == 8480 and by["sys"]["shift_ms"] == -3000
    assert by["sec"]["source"] == "db" and by["sec"]["channel"] == "Security" and by["sec"]["event_id"] == 4616
    assert by["sys"]["channel"] == "System" and by["sys"]["event_id"] == 1


def test_d2_pointer_to_another_event_is_unknown(tmp_path):
    """D2: a pointer whose JSONL line is another event (different sha256) gives an unknown shift, which counts."""
    files = ChangeFiles()
    row = files.row("chg", "ep-01", "Security", 4616, 15, 500)       # routine if believed
    row["source_sha256"] = "cd" * 32                                 # the row says another EVTX file
    _, res = measure(tmp_path, two_groups([row]), files=files)
    (c,) = [c for c in change_rows_of(res) if c["event_uid_or_record"] == "chg"]
    assert c["shift_ms"] is None and c["counted"] is True


def test_d2_change_after_last_pair_is_stale_only_when_counted(tmp_path):
    """D2: a counted change after the last kept pair, inside the window, is stale; a routine one is not."""
    _, a = measure(tmp_path, two_groups([ChangeFiles().row("x", "ep-01", "Security", 4616, 50, 5000)]), name="a",
                   files=None)       # no pointer file on disk -> unknown -> counts
    assert hrow(a, "ep-01")["offset_status"] == "stale"
    files = ChangeFiles()
    _, b = measure(tmp_path, two_groups([files.row("x", "ep-01", "Security", 4616, 50, 2)]), name="b", files=files)
    assert hrow(b, "ep-01")["offset_status"] == "ok" and hrow(b, "ep-01")["n_pairs"] == 5


def test_d2_change_at_or_before_pair_drops_it_strictly_after_stays(tmp_path):
    """D2: 'drops every pair at or before it': the 4624s at 21 s are dropped by a change at 21 s; one at 20.999 s keeps them."""
    for t, n in ((21.0, 2), (20.999, 3)):
        files = ChangeFiles()
        rows = two_groups([files.row("chg", "ep-01", "Security", 4616, t, 5000)])
        _, res = measure(tmp_path, rows, files=files, name=f"t{t}")
        assert hrow(res, "ep-01")["n_pairs"] == n, (t, hrow(res, "ep-01")["n_pairs"])


def test_d2_fewer_than_min_pairs_after_cut_is_none(tmp_path):
    """D2: fewer than MIN_PAIRS left after the cut gives none (a counted change at 26.5 s leaves one pair)."""
    files = ChangeFiles()
    rows = two_groups([files.row("chg", "ep-01", "Security", 4616, 26.5, 5000)])
    _, res = measure(tmp_path, rows, files=files)
    r = hrow(res, "ep-01")
    assert r["n_pairs"] == 1 and r["offset_status"] == "none" and r["offset_ms"] is None
    assert "ep-01" in flag(res)


# ====================================================================================== D3: clock_change_in_window

def _flag_case(tmp_path, name: str, db_rows: list[dict], files=None, exports=None, manifest=None):
    _, res = measure(tmp_path, agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900]) + db_rows, name=name,
                     files=files, exports=exports, manifest=manifest)
    return res


def _export_case(tmp_path, name: str, host: str, t: float, shift_ms: int, channel: str = "Security"):
    stem, event_id, provider = ("security", 4616, SEC) if channel == "Security" else ("system", 1, KG)
    rec = mkrec(channel, event_id, t, provider, shift_ms)
    return _flag_case(tmp_path, name, [], exports={(host, stem): [rec]}, manifest=[(host, stem, SHA)])


@pytest.mark.parametrize("host,t,shift,cls,flagged", [
    ("ep-01", 2, 5000, "expected_before_first_pair", False),     # before the first pair (5.0 s): the planned resync
    ("ep-01", 12, 5000, "between_pairs", True),                  # between the first (5.0 s) and last (15.1 s) pair
    ("ep-01", 50, 5000, "after_last_pair", True),
    ("ep-01", 12, 2, "routine", False),
    ("ep-01", 50, -999, "routine", False),
    ("ep-03", 30, 5000, "no_pairs", True),                       # host without pairs
    ("dc01", 30, 5000, "no_pairs", True),                        # dc01 has no pairs by definition
    ("ep-03", 30, 2, "routine", False),
])
def test_d3_flag_by_classification_export(tmp_path, host, t, shift, cls, flagged):
    """D3: clock_change_in_window is set only by a counted change after the host's first pair (between_pairs,
    after_last_pair) or on a host with no pairs (no_pairs, dc01 included); expected and routine do not set it."""
    res = _export_case(tmp_path, "c", host, t, shift)
    rows = change_rows_of(res)
    assert [r["classification"] for r in rows] == [cls]
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is flagged
    assert res["clock"]["s02_t00"]["flag"] is flagged
    ev_rows = res["clock"]["s02_t00"]["events_rows"]
    assert [r["classification"] for r in ev_rows] == [cls]


def test_d3_flag_after_last_pair_from_db_row_and_stale(tmp_path):
    """D3 + D2 from a DB row: a counted 4616 after the last pair is stale and sets the flag."""
    files = ChangeFiles()
    res = _flag_case(tmp_path, "d", [files.row("chg", "ep-01", "Security", 4616, 50, 5000)], files=files)
    assert hrow(res, "ep-01")["offset_status"] == "stale"
    assert [r["classification"] for r in change_rows_of(res)] == ["after_last_pair"]
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is True


def test_d3_flag_no_pairs_from_db_rows_ep03_and_dc01(tmp_path):
    """D3: a counted change in the DB on a host with no pairs (ep-03, dc01) sets the flag."""
    for host in ("ep-03", "dc01"):
        files = ChangeFiles()
        res = _flag_case(tmp_path, host, [files.row("chg", host, "System", 1, 30, 5000)], files=files)
        assert [r["classification"] for r in change_rows_of(res)] == ["no_pairs"], host
        assert res["stats"]["s02_t00"]["clock_change_in_window"] is True, host


def test_d3_flag_not_set_for_expected_db_row(tmp_path):
    """D3: a counted DB change before the first pair is `expected`, listed, and does not set the flag."""
    files = ChangeFiles()
    res = _flag_case(tmp_path, "e", [files.row("chg", "ep-01", "Security", 4616, 2, 8000)], files=files)
    assert [r["classification"] for r in change_rows_of(res)] == ["expected_before_first_pair"]
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is False
    assert "chg" in res["stats"]["s02_t00"]["evidence"]["per_host"]["ep-01"]["expected_clock_change_uids"]
    assert hrow(res, "ep-01")["offset_status"] == "ok"


def test_d3_flag_without_export_scan_is_none_unless_db_flags(tmp_path):
    """D3: with scan=False the exports were not read: the flag is None (unknown) unless a DB row already flags."""
    _, res = measure(tmp_path, agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900]), scan=False)
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is None
    assert res["stats"]["s02_t00"]["clock_change_scan"]["export_scan_run"] is False
    files = ChangeFiles()
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900]) + [files.row("c", "ep-01", "Security", 4616, 50, 5000)]
    _, res2 = measure(tmp_path, rows, scan=False, files=files, name="two")
    assert res2["stats"]["s02_t00"]["clock_change_in_window"] is True


def test_d3_scan_false_with_write_raises_and_writes_nothing(tmp_path):
    """SF-3 (replaces the D6 reading): the files in data/processed are written only by a run with the export scan, so
    run(write=True, scan=False) raises ClockOffsetError and writes nothing: no offsets, no clock_changes, no out/ folder."""
    files = ChangeFiles()
    rows = two_groups([files.row("chg", "ep-01", "Security", 4616, 15, 8000)])
    repo = make_repo(tmp_path, rows, files=files)
    before = _snapshot(repo)
    with pytest.raises(run.ClockOffsetError):
        run.run(repo, ["s02_t00"], write=True, scan=False)
    assert _snapshot(repo) == before
    assert _no_output(repo, "s02_t00")
    assert not (repo / "data/processed/s02_t00.clock_changes.csv").exists()
    assert not (repo / "out").exists()


# ====================================================================================== D4 pre-step counts

def _row(uid: str, host: str, t: float) -> dict:
    return {"event_uid": uid, "host": host, "us": to_us(at(t))}


def test_d4_pre_step_counts_real_time_and_literal():
    """D4: (a) host events logged before the step (recorded in [last boot before, max(previous, step)) ) whose real
    time (recorded + shift) lies in the window; (b) the literal count recorded in [window start, step time)."""
    boot = to_us(at(70))
    prev, new = shift_times(150, 30_000)                           # forward step of 30 s at recorded 150
    c = replace(ch.make_change(host="ep-01", channel="Security", event_id=4616, change_us=to_us(at(150)),
                               previous_time=prev, new_time=new, source="db", ref="u", source_sha256=None),
                last_boot_before_us=boot)
    events = [_row("before-boot", "ep-01", 60), _row("a1", "ep-01", 75), _row("a2", "ep-01", 140),
              _row("a3", "ep-01", 149), _row("after", "ep-01", 151), _row("other-host", "ep-02", 140)]
    out = ch.pre_step(events, c, to_us(at(100)), to_us(at(200)) + 1000)
    assert out["logged_before_count"] == 3                          # 75, 140, 149 (60 is before the boot)
    assert out["a_event_uids"] == ["a1", "a2", "a3"]                # real: 105, 170, 179, all in [100, 200]
    assert out["a_real_time_in_window_count"] == 3
    assert out["b_literal_in_window_before_step_count"] == 2        # 140, 149 recorded in [100, 150)
    assert out["b_event_uids"] == ["a2", "a3"]
    c2 = replace(c, shift_ms=None, previous_us=None)
    assert ch.pre_step(events, c2, to_us(at(100)), to_us(at(200)) + 1000)["a_real_time_in_window_count"] is None


def test_d4_pre_steps_listed_for_counted_changes_in_window_only(tmp_path):
    """D4: clock_scan.json / the result list pre-step counts for each counted change inside the agent window; a huge
    forward shift moves the real time out of the window, so (a) is 0 while (b) counts the recorded events."""
    files = ChangeFiles()
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900])
    rows += [files.row("big", "ep-01", "Security", 4616, 50, 500_000),         # counted, in window
             files.row("small", "ep-01", "System", 1, 60, 3),                  # routine: not listed
             files.row("late", "ep-01", "System", 1, 900, 5000)]               # counted but after the window end
    repo, res = measure(tmp_path, rows, files=files, write=True)
    steps = res["clock"]["s02_t00"]["pre_steps"]
    assert [s["event_uid_or_record"] for s in steps] == ["big"]
    s = steps[0]
    assert s["host"] == "ep-01" and s["shift_ms"] == 500_000
    assert s["logged_before_count"] == 4                            # agent root at 0 s and the 4624s at 5.0, 9.9, 15.1 s
    assert s["a_real_time_in_window_count"] == 0 and s["b_literal_in_window_before_step_count"] == 4
    doc = json.loads((repo / "out/clock_offset/s02_t00/clock_scan.json").read_text(encoding="utf-8"))
    assert [p["event_uid_or_record"] for p in doc["pre_step"]] == ["big"]


# ====================================================================================== D5: events before a counted change

def _cc(host: str = "ep-01", change_s: float = 100.0, shift_ms: int = 5000, boot_s: float | None = None) -> ch.ClockChange:
    prev, new = shift_times(change_s, shift_ms)
    c = ch.make_change(host=host, channel="Security", event_id=4616, change_us=to_us(at(change_s)),
                       previous_time=prev, new_time=new, source="db", ref="u", source_sha256=None)
    return replace(c, last_boot_before_us=None if boot_s is None else to_us(at(boot_s)))


def test_d5_forward_step_interval_ends_at_the_change():
    """D5: forward step: events recorded before the change are unreliable, the change instant and later are not."""
    c = _cc(shift_ms=5000)
    t = to_us(at(100.0))
    assert correct.before_counted_change("ep-01", t - 1, [c]) is True
    assert correct.before_counted_change("ep-01", t, [c]) is False
    assert correct.before_counted_change("ep-01", t + 1_000_000, [c]) is False
    assert correct.before_counted_change("ep-01", to_us(at(0.0)), [c]) is True            # no boot: unbounded below


def test_d5_backward_step_interval_runs_to_previous_time_inclusive():
    """D5: backward step (new clock earlier): the overlap [change, previous_time] holds events of both clocks, so the
    whole interval up to previous_time INCLUSIVE is unreliable."""
    c = _cc(shift_ms=-5000)                                       # change recorded at 100 s, previous time 105 s
    assert c.previous_us == to_us(at(105.0))
    for t in (50.0, 99.0, 100.0, 102.0, 105.0):
        assert correct.before_counted_change("ep-01", to_us(at(t)), [c]) is True, t
    assert correct.before_counted_change("ep-01", to_us(at(105.0)) + 1, [c]) is False
    assert correct.before_counted_change("ep-01", to_us(at(106.0)), [c]) is False


def test_d5_last_boot_is_the_lower_bound():
    """D5: events recorded before the host's last boot before the change are not 'before the change'."""
    c = _cc(shift_ms=5000, boot_s=80.0)
    assert correct.before_counted_change("ep-01", to_us(at(79.9)), [c]) is False
    assert correct.before_counted_change("ep-01", to_us(at(80.0)), [c]) is True
    assert correct.before_counted_change("ep-01", to_us(at(99.9)), [c]) is True


def test_d5_other_host_routine_and_empty_do_not_count():
    """D5: only the change's own host, and only a counted change, makes an event unreliable."""
    t = to_us(at(50.0))
    assert correct.before_counted_change("ep-02", t, [_cc(host="ep-01")]) is False
    assert correct.before_counted_change("ep-01", t, [_cc(shift_ms=500)]) is False        # routine
    assert correct.before_counted_change("ep-01", t, []) is False
    assert correct.before_counted_change("ep-01", t, [_cc(shift_ms=500), _cc(change_s=120, shift_ms=-2000)]) is True


def test_d5_event_unreliable_combines_host_status_and_position():
    """D5: event_unreliable = host unreliable (none / wide / stale / unknown) OR logged before a counted change;
    corrected_us is unchanged by the change."""
    o = _offsets({"dc01": ("reference", 0, True), "ep-01": ("ok", -18000, True), "ep-02": ("none", None, True)})
    c = _cc(shift_ms=5000)
    before, after = to_us(at(50.0)), to_us(at(150.0))
    assert correct.event_unreliable("ep-01", before, o, [c]) is True
    assert correct.event_unreliable("ep-01", after, o, [c]) is False
    assert correct.event_unreliable("ep-01", before, o) is False                           # no changes given
    assert correct.event_unreliable("ep-02", after, o, [c]) is True                        # none host
    assert correct.event_unreliable("dc01", before, o, [c]) is False                       # c is ep-01's change
    assert correct.corrected_us(before, "ep-01", o) == before + 18_000_000                 # offset applied as before


def test_d5_boots_are_not_clock_changes(tmp_path):
    """D5: a boot is not listed in the changes file and does not make earlier events clock_unreliable."""
    rows = two_groups([ev("boot", "ep-01", "System", 6005, 15)])
    repo, res = measure(tmp_path, rows, write=True)
    assert change_rows_of(res) == []
    _, body = read_csv(repo / "data/processed/s02_t00.clock_changes.csv")
    assert body == []
    o = correct.offsets_from_rows(res["rows"]["s02_t00"])
    assert correct.event_unreliable("ep-01", to_us(at(5.0)), o, res["clock"]["s02_t00"]["changes"]) is False


def test_d5_last_boot_before_recorded_in_file(tmp_path):
    """D5: the file records the host's last boot before each change (the lower end of the interval)."""
    files = ChangeFiles()
    rows = two_groups([files.row("chg", "ep-01", "Security", 4616, 15, 8000),
                       ev("boot-early", "ep-01", "System", 6005, 1), ev("boot-mid", "ep-01", "System", 6005, 12),
                       ev("boot-late", "ep-01", "System", 6005, 18), ev("boot-other-host", "ep-02", "System", 6005, 14)])
    repo, res = measure(tmp_path, rows, files=files, write=True)
    _, body = read_csv(repo / "data/processed/s02_t00.clock_changes.csv")
    assert body[0]["last_boot_before_utc"].startswith("2026-09-24T05:00:12")


def test_d5_changes_csv_header_rows_sorted_and_roundtrip(tmp_path):
    """D5: header = the documented columns (the owner's list is a subsequence of it); rows sorted by host then
    change_utc; source db|export; loads back with correct.load_clock_changes."""
    files = ChangeFiles()
    rows = two_groups([files.row("late", "ep-02", "System", 1, 40, 5000), files.row("early", "ep-02", "Security", 4616, 20, 6000),
                       files.row("ep1", "ep-01", "Security", 4616, 30, 7000), files.row("dcx", "dc01", "Security", 4616, 5, 2)])
    exports = {("ep-03", "security"): [mkrec("Security", 4616, 33, SEC, 9000, idx=7)]}
    repo, res = measure(tmp_path, rows, files=files, write=True, exports=exports,
                        manifest=[("ep-03", "security", SHA)])
    path = repo / "data" / "processed" / "s02_t00.clock_changes.csv"
    header, body = read_csv(path)
    assert header == CHANGES_HEADER
    assert is_subsequence(SPEC_CHANGES_COLUMNS, header)
    assert [(r["host"], r["event_uid_or_record"]) for r in body] == [
        ("dc01", "dcx"), ("ep-01", "ep1"), ("ep-02", "early"), ("ep-02", "late"), ("ep-03", "7")]
    assert [r["source"] for r in body] == ["db", "db", "db", "db", "export"]
    assert [r["counted"] for r in body] == ["false", "true", "true", "true", "true"]
    assert body[4]["source_sha256"] == SHA and body[0]["trial_id"] == "s02_t00"
    assert b"\r" not in path.read_bytes()
    loaded = correct.load_clock_changes(path)
    assert loaded.trial_id == "s02_t00" and loaded.file_sha256 == sha(path)
    assert [(c.host, c.counted, c.source) for c in loaded.changes] == [(r["host"], r["counted"] == "true", r["source"])
                                                                       for r in body]
    with pytest.raises(ValueError):
        correct.parse_clock_changes_text("trial_id,host\ns02_t00,ep-01\n")


def test_d5_changes_csv_byte_identical_rerun_and_other_folder(tmp_path):
    """D5: the changes file is byte-identical on rerun and when the repo is copied elsewhere."""
    files = ChangeFiles()
    rows = two_groups([files.row("chg", "ep-01", "Security", 4616, 15, 8000), files.row("r", "ep-01", "System", 1, 17, 2)])
    repo, _ = measure(tmp_path, rows, files=files, write=True)
    f = repo / "data/processed/s02_t00.clock_changes.csv"
    first = f.read_bytes()
    run.run(repo, ["s02_t00"], write=True)
    assert f.read_bytes() == first and first.count(b"\n") == 3
    repo2 = tmp_path / "copy"
    shutil.copytree(repo / "data", repo2 / "data", ignore=shutil.ignore_patterns("*.clock_*.csv"))
    run.run(repo2, ["s02_t00"], write=True)
    assert (repo2 / "data/processed/s02_t00.clock_changes.csv").read_bytes() == first


def _check_with_change(tmp_path, name: str, src_t: float, change_t: float, shift_ms: int) -> dict:
    files = ChangeFiles()
    rows = _check_trial([_tgt("t-a", src_t + 0.5), files.row("chg", "ep-01", "Security", 4616, change_t, shift_ms)],
                        src_t=src_t)
    _, res = measure(tmp_path, rows, files=files, name=name)
    assert hrow(res, "ep-01")["offset_status"] == "ok" and hrow(res, "ep-02")["offset_status"] == "ok", name
    (c,) = res["stats"]["s02_t00"]["check"]["rows"]
    return c


def test_d5_check_row_unreliable_when_source_precedes_a_counted_change(tmp_path):
    """D5 / CO-10: the check row is clock_unreliable when the source event was logged before a counted change on its
    host, although the offsets are ok. A change before the source (the planned resync) does not mark it."""
    base = _check_with_change(tmp_path, "base", 185, 420, 2)                 # routine change: nothing
    assert base["clock_unreliable"] is False
    after_src = _check_with_change(tmp_path, "after", 185, 450, 8000)         # change after the event, outside the window
    assert after_src["clock_unreliable"] is True
    before_src = _check_with_change(tmp_path, "before", 185, -100, 8000)      # change before the event
    assert before_src["clock_unreliable"] is False


def test_d5_check_row_backward_step_overlap(tmp_path):
    """D5 / CO-10: a backward step marks events up to previous_time (overlap); a forward step of the same size recorded
    at the same instant does not reach the source event."""
    back = _check_with_change(tmp_path, "back", 30, -100, -150_000)          # change at -100 s, previous time +50 s
    fwd = _check_with_change(tmp_path, "fwd", 30, -100, 150_000)             # previous time -250 s
    assert back["clock_unreliable"] is True
    assert fwd["clock_unreliable"] is False


def test_d5_check_row_unreliable_when_target_precedes_change(tmp_path):
    """D5 / CO-10: the same rule for the target 4624's host."""
    files = ChangeFiles()
    rows = _check_trial([_tgt("t-a", 200.5), files.row("chg", "ep-02", "Security", 4616, 450, 8000)])
    _, res = measure(tmp_path, rows, files=files)
    (c,) = res["stats"]["s02_t00"]["check"]["rows"]
    assert c["clock_unreliable"] is True and c["corrected_delta_ms"] is not None


# ====================================================================================== COT-19 scan (CO-19)

LO, HI = to_us(at(-1860)), to_us(at(2200))


def test_cot19_finds_4616_and_kernel_general_system1_inside_span():
    """COT-19: a Security 4616 and a Microsoft-Windows-Kernel-General System 1 inside the span are hits, with the host,
    channel, id, provider, timestamp, previous/new time, shift, record index and source sha256."""
    recs = [mkrec("Security", 4616, 100, SEC, 8480, idx=11), mkrec("System", 1, 200, KG, -3000, idx=12)]
    fs = co_scan.scan_records(recs, "ep-02", LO, HI)
    assert [(h.channel, h.event_id, h.provider, h.shift_ms, h.record_index) for h in fs.hits] == [
        ("Security", "4616", SEC, 8480, 11), ("System", "1", KG, -3000, 12)]
    h = fs.hits[0]
    assert h.host == "ep-02" and h.timestamp_raw == at(100) and h.us == to_us(at(100)) and h.source_sha256 == SHA
    assert h.previous_time and h.new_time
    assert fs.sha256_values == frozenset({SHA}) and fs.n_records == 2


def test_cot19_ignores_outside_span_other_provider_and_other_events():
    """COT-19: records outside the span, a System 1 of another provider (or with none), and other events are not hits;
    the span edges are inclusive."""
    recs = [mkrec("Security", 4616, -1861, SEC, 5000, idx=1),                 # just before the span
            mkrec("Security", 4616, 2201, SEC, 5000, idx=2),                  # just after
            mkrec("System", 1, 100, "Microsoft-Windows-Power-Troubleshooter", 5000, idx=3),
            mkrec("System", 1, 101, None, 5000, idx=4),                       # no provider
            mkrec("Security", 4624, 102, SEC, None, idx=5),                   # another event
            mkrec("System", 6005, 103, "EventLog", None, idx=6),
            mkrec("Microsoft-Windows-Sysmon/Operational", 1, 104, "Microsoft-Windows-Sysmon", None, idx=7),
            mkrec("Security", 4616, -1860, SEC, 5000, idx=8),                 # exactly at the span start: in
            mkrec("System", 1, 2200, KG.upper(), 5000, idx=9)]                # exactly at the span end; provider case
    fs = co_scan.scan_records(recs, "ep-01", LO, HI)
    assert sorted(h.record_index for h in fs.hits) == [8, 9]
    assert fs.n_candidates_out_of_span == 2


def test_cot19_shift_from_previoustime_newtime_and_oldtime_newtime():
    """COT-19: shift_ms = NewTime - PreviousTime (4616) or NewTime - OldTime (System 1), signed, with the 7/9-digit
    fractions the event logs; a record without both times has no shift."""
    r1 = mkrec("Security", 4616, 100, SEC, prev="2026-09-24T05:37:49.000000000Z", new="2026-09-24T05:37:57.480000000Z")
    r2 = mkrec("System", 1, 101, KG, prev="2026-09-24T05:37:57.4800000Z", new="2026-09-24T05:37:49.0000000Z")
    r3 = mkrec("Security", 4616, 102, SEC, prev="2026-09-24T05:00:00.000Z", new="2026-09-24T05:00:00.002Z")
    r4 = mkrec("Security", 4616, 103, SEC, prev="2026-09-24T05:00:00.000Z")
    wrong = mkrec("Security", 4616, 104, SEC, 5000)
    wrong["event_data"] = [{"name": "OldTime", "value": at(100)}, {"name": "NewTime", "value": at(105)}]    # wrong name for 4616
    fs = co_scan.scan_records([r1, r2, r3, r4, wrong], "ep-01", LO, HI)
    assert [h.shift_ms for h in fs.hits] == [8480, -8480, 2, None, None]


def test_cot19_classification_and_counted_columns(tmp_path):
    """COT-19: clock_events.csv holds every hit with `counted` (|shift| >= 1000 ms or unknown) and its classification
    against the host's kept pairs (4624s at 5.0 .. 15.1 s on ep-01); the header has the spec columns."""
    recs = [mkrec("Security", 4616, 2, SEC, 8000, idx=1),                    # before the first pair
            mkrec("Security", 4616, 8, SEC, 999, idx=2),                     # routine (just below 1 s)
            mkrec("System", 1, 12, KG, -1000, idx=3),                        # between the pairs, counted
            mkrec("Security", 4616, 14, SEC, prev=at(1), idx=4),             # unknown shift: counted, between
            mkrec("Security", 4616, 50, SEC, 5000, idx=5)]                   # after the last pair
    sec = [r for r in recs if r["system"]["channel"] == "Security"]
    sysr = [r for r in recs if r["system"]["channel"] == "System"]
    repo, res = measure(tmp_path, agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900]), write=True,
                        exports={("ep-01", "security"): sec, ("ep-01", "system"): sysr},
                        manifest=[("ep-01", "security", SHA), ("ep-01", "system", SHA)])
    header, body = read_csv(repo / "out/clock_offset/s02_t00/clock_events.csv")
    assert header == EVENTS_HEADER and is_subsequence(SPEC_EVENTS_COLUMNS, header)
    by = {r["record_index"]: r for r in body}
    assert [by[i]["classification"] for i in "12345"] == [
        "expected_before_first_pair", "routine", "between_pairs", "between_pairs", "after_last_pair"]
    assert [by[i]["counted"] for i in "12345"] == ["true", "false", "true", "true", "true"]
    assert by["3"]["shift_ms"] == "-1000" and by["4"]["shift_ms"] == "" and by["2"]["shift_ms"] == "999"
    assert all(r["host"] == "ep-01" and r["source_sha256"] == SHA for r in body)
    assert [r["timestamp_raw"] for r in body] == sorted(r["timestamp_raw"] for r in body)       # time order
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is True
    counts = res["stats"]["s02_t00"]["clock_change_scan"]
    assert counts["routine_count"] == 1 and counts["expected_count"] == 1 and counts["unexpected_count"] == 3


def test_cot19_skips_file_whose_sha256_is_not_in_the_manifest(tmp_path):
    """COT-19: a file whose records' sha256 is not the manifest's (also: mixed sha, a record without sha, a manifest
    file with no export) is skipped with a reason, its hits are not used, and coverage is reported incomplete."""
    other = "cd" * 32
    exports = {
        ("ep-01", "security"): [mkrec("Security", 4616, 12, SEC, 5000, idx=1)],                     # ok
        ("ep-02", "security"): [mkrec("Security", 4616, 12, SEC, 5000, sha=other, idx=1)],          # not the manifest sha
        ("ep-03", "system"): [mkrec("System", 1, 12, KG, 5000, sha=SHA, idx=1),
                              mkrec("System", 1, 13, KG, 5000, sha=other, idx=2)],                  # mixed
    }
    nosha = mkrec("Security", 4616, 14, SEC, 5000, idx=1)
    del nosha["source"]["sha256"]
    exports[("ep-03", "security")] = [nosha]
    manifest = [("ep-01", "security", SHA), ("ep-02", "security", SHA), ("ep-03", "system", SHA),
                ("ep-03", "security", SHA), ("dc01", "security", SHA)]                              # dc01: no export
    repo, res = measure(tmp_path, agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900]), write=True,
                        exports=exports, manifest=manifest)
    doc = json.loads((repo / "out/clock_offset/s02_t00/clock_scan.json").read_text(encoding="utf-8"))
    skipped = {Path(s["path"]).parent.name + "/" + Path(s["path"]).stem: s["reason"] for s in doc["files_skipped"]}
    assert set(skipped) == {"ep-02/security", "ep-03/system", "ep-03/security", "dc01/security"}
    assert all(skipped.values())
    assert other in skipped["ep-02/security"] and "manifest" in skipped["ep-02/security"]
    assert "several" in skipped["ep-03/system"] or "sha256" in skipped["ep-03/system"]
    assert "without" in skipped["ep-03/security"]
    assert "not found" in skipped["dc01/security"]
    assert doc["coverage_complete"] is False and [Path(f["path"]).parent.name for f in doc["files_read"]] == ["ep-01"]
    _, events = read_csv(repo / "out/clock_offset/s02_t00/clock_events.csv")
    assert [r["host"] for r in events] == ["ep-01"]                   # no hit from a skipped file
    assert res["stats"]["s02_t00"]["clock_change_scan"]["files_skipped"] == 4
    assert [r["host"] for r in change_rows_of(res)] == ["ep-01"]


def test_cot19_file_without_manifest_row_is_skipped(tmp_path):
    """COT-19: an export for a host/channel the manifest does not list cannot be matched: skipped, hits unused."""
    _, res = measure(tmp_path, agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900]),
                     exports={("ep-02", "security"): [mkrec("Security", 4616, 12, SEC, 5000)],
                              ("ep-01", "security"): [mkrec("Security", 4624, 12, SEC, None)]},
                     manifest=[("ep-01", "security", SHA)])
    assert res["stats"]["s02_t00"]["clock_change_scan"]["files_skipped"] == 1
    assert change_rows_of(res) == []


def _snapshot(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*"))
            if p.is_file()}


def test_cot19_writes_nothing_outside_out_clock_offset(tmp_path, monkeypatch):
    """COT-19: the standalone scan writes only out/clock_offset/<trial>/clock_events.csv and clock_scan.json: every
    file open for writing, and every changed file in the repo, is under that folder; the DB, the exports, the
    manifest, the offsets and the changes files are untouched."""
    exports = {("ep-01", "security"): [mkrec("Security", 4616, 12, SEC, 5000, idx=1)]}
    repo = make_repo(tmp_path, agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900]), exports=exports,
                     manifest=[("ep-01", "security", SHA)])
    run.run(repo, ["s02_t00"], write=True)                           # offsets, changes, pairs.csv for the bounds
    for f in ("clock_events.csv", "clock_scan.json"):
        (repo / "out/clock_offset/s02_t00" / f).unlink()
    before = _snapshot(repo)
    writes: list[str] = []
    orig_open, orig_io, orig_popen = builtins.open, io.open, Path.open

    def wrap(orig):
        def w(file, *a, **k):
            mode = k.get("mode", a[0] if a else "r")
            if any(c in str(mode) for c in "wax+") and isinstance(file, (str, bytes, os.PathLike)):
                writes.append(os.fsdecode(os.fspath(file)))
            return orig(file, *a, **k)
        return w

    def w_popen(self, *a, **k):
        mode = k.get("mode", a[0] if a else "r")
        if any(c in str(mode) for c in "wax+"):
            writes.append(str(self))
        return orig_popen(self, *a, **k)

    with monkeypatch.context() as mp:
        mp.setattr(builtins, "open", wrap(orig_open))
        mp.setattr(io, "open", wrap(orig_io))
        mp.setattr(Path, "open", w_popen)
        out = co_scan.run_scan(repo, ["s02_t00"], write=True)
    assert "s02_t00" in out["results"]
    after = _snapshot(repo)
    changed = sorted(k for k in after if before.get(k) != after[k])
    assert changed == ["out/clock_offset/s02_t00/clock_events.csv", "out/clock_offset/s02_t00/clock_scan.json"]
    assert sorted(set(before) - set(after)) == []
    assert writes, "recorder saw no write"
    root = (repo / "out" / "clock_offset").resolve()
    assert all(_under(w, root) for w in writes), [w for w in writes if not _under(w, root)]


def test_cot19_scan_files_equal_those_of_the_step(tmp_path):
    """COT-19: the standalone scan writes the same bytes as run() does (same classification, same bounds)."""
    exports = {("ep-01", "security"): [mkrec("Security", 4616, 12, SEC, 5000, idx=1),
                                       mkrec("Security", 4616, 40, SEC, 2, idx=2)]}
    repo = make_repo(tmp_path, agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900]), exports=exports,
                     manifest=[("ep-01", "security", SHA)])
    run.run(repo, ["s02_t00"], write=True)
    out = repo / "out/clock_offset/s02_t00"
    first = {f: (out / f).read_bytes() for f in ("clock_events.csv", "clock_scan.json")}
    co_scan.run_scan(repo, ["s02_t00"], write=True)
    assert {f: (out / f).read_bytes() for f in first} == first


def test_cot19_scan_refuses_like_the_step(tmp_path):
    """COT-19 / CO-01: the scan refuses quarantined and excluded trials and writes nothing for them."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900])
    repo = tmp_path / "repo"
    for t in ("s05q_t01", "s01_t00"):
        write_db(repo / "data" / "processed" / f"{t}.sqlite3", rows)
    out = co_scan.run_scan(repo, ["s05q_t01", "s01_t00"], write=True)
    assert set(out["refused"]) == {"s05q_t01", "s01_t00"} and out["results"] == {}
    assert not (repo / "out").exists()


# ====================================================================================== review SF-1: export hits cut and stale

OTHER_SHA = "cd" * 32


def _sf_case(tmp_path, name: str, sec=(), sysr=(), db_extra=(), files=None, trial: str = "s02_t00", write: bool = False):
    """ep-01 with the two pair groups of `two_groups` (4624s at 5, 10 | 21, 26, 31 s) and clock-change records only in
    the exports (`sec`: Security records, `sysr`: System records), listed in the manifest with the records' sha256."""
    exports, manifest = {}, []
    if sec:
        exports[("ep-01", "security")] = list(sec)
        manifest.append(("ep-01", "security", SHA))
    if sysr:
        exports[("ep-01", "system")] = list(sysr)
        manifest.append(("ep-01", "system", SHA))
    return measure(tmp_path, two_groups(list(db_extra)), trial=trial, name=name, files=files, exports=exports or None,
                   manifest=manifest or None, write=write)


@pytest.mark.parametrize("channel,event_id,provider", [("Security", 4616, SEC), ("System", 1, KG)])
def test_sf1_counted_export_hit_between_pair_groups_drops_the_earlier_pairs(tmp_path, channel, event_id, provider):
    """SF-1 / CO-15: a counted clock change found only in the exports, between ep-01's two pair groups, cuts like a DB row:
    the earlier two pairs are dropped (offset from group 2, -9000 ms), the status is ok, the change is `between_pairs` and
    the trial flag is true (original-pairs rule), and ep-01 is not in clock_flag (it is corrected)."""
    rec = mkrec(channel, event_id, 15, provider, 5000, idx=7)
    kw = {"sec": [rec]} if channel == "Security" else {"sysr": [rec]}
    _, res = _sf_case(tmp_path, "a", **kw)
    r = hrow(res, "ep-01")
    assert r["n_pairs"] == 3 and r["offset_ms"] == -9000 and r["offset_status"] == "ok"
    ev1 = res["stats"]["s02_t00"]["evidence"]["per_host"]["ep-01"]
    assert ev1["n_dropped_before_change"] == 2 and ev1["change_cut_event_uid"]
    (row,) = change_rows_of(res)
    assert row["source"] == "export" and row["classification"] == "between_pairs" and row["counted"] is True
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is True
    assert "ep-01" not in flag(res)


def test_sf1_export_hit_between_pairs_only_changes_the_estimate_when_it_cuts(tmp_path):
    """SF-1: without the export hit ep-01 uses all 5 pairs; with it, 3 (the median happens to be -9000 ms in both, so the pair
    count is the observable). The hit is the only difference between the two runs."""
    _, plain = _sf_case(tmp_path, "plain")
    _, hit = _sf_case(tmp_path, "hit", sec=[mkrec("Security", 4616, 15, SEC, 5000)])
    assert hrow(plain, "ep-01")["n_pairs"] == 5 and hrow(hit, "ep-01")["n_pairs"] == 3


def test_sf1_counted_export_hit_after_the_last_pair_is_stale(tmp_path, monkeypatch):
    """SF-1 / CO-15 / CO-17: a counted export hit after ep-01's last pair (31 s), inside the window, makes ep-01 `stale`
    (offset empty, flagged, listed in the stale uids) and the change is `after_last_pair`. In a trial on or after
    2026-10-26 the CO-17 preview refuses it; the same trial before that date is not refused."""
    _, res = _sf_case(tmp_path, "a", sec=[mkrec("Security", 4616, 50, SEC, 5000)])
    r = hrow(res, "ep-01")
    assert r["offset_status"] == "stale" and r["offset_ms"] is None and "ep-01" in flag(res)
    assert len(res["stats"]["s02_t00"]["evidence"]["per_host"]["ep-01"]["stale_event_uids"]) == 1
    assert [c["classification"] for c in change_rows_of(res)] == ["after_last_pair"]
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is True
    assert res["stats"]["s02_t00"]["co17_refusal_preview"] is None            # 2026-09-24: before the date
    # the same trial on 2026-10-27: CO-17 refuses it
    monkeypatch.setattr(sys.modules[__name__], "BASE", datetime(2026, 10, 27, 6, 0, 0, tzinfo=timezone.utc))
    _, late = _sf_case(tmp_path, "late", sec=[mkrec("Security", 4616, 50, SEC, 5000)])
    reason = late["stats"]["s02_t00"]["co17_refusal_preview"]
    assert reason and "CO-17" in reason and "ep-01" in reason and "stale" in reason
    offsets = correct.offsets_from_rows(late["rows"]["s02_t00"])
    assert correct.co17_refusal(offsets, to_us(at(-60))) == reason


@pytest.mark.parametrize("shift", [999, -999, 2, 0])
def test_sf1_routine_export_hit_changes_nothing(tmp_path, shift):
    """SF-1 / CO-15: an export hit with |shift| < 1 s is routine: no pair dropped, no stale, no flag, listed as routine."""
    for t, name in ((15, "between"), (50, "after")):
        _, res = _sf_case(tmp_path, name, sec=[mkrec("Security", 4616, t, SEC, shift)])
        r = hrow(res, "ep-01")
        assert r["n_pairs"] == 5 and r["offset_status"] == "ok", (t, r["n_pairs"], r["offset_status"])
        assert [(c["classification"], c["counted"]) for c in change_rows_of(res)] == [("routine", False)]
        assert res["stats"]["s02_t00"]["clock_change_in_window"] is False
        assert "ep-01" not in flag(res)


def test_sf1_unknown_shift_export_hit_counts(tmp_path):
    """SF-1 / CO-15: an export hit whose previous/new time cannot be read counts (owner D1, conservative): between the
    groups it cuts the earlier pairs, after the last pair it makes the host stale."""
    unknown = mkrec("Security", 4616, 15, SEC, prev=at(1))                      # PreviousTime only: no shift
    _, mid = _sf_case(tmp_path, "mid", sec=[unknown])
    assert hrow(mid, "ep-01")["n_pairs"] == 3 and hrow(mid, "ep-01")["offset_ms"] == -9000
    (row,) = change_rows_of(mid)
    assert row["counted"] is True and row["shift_ms"] is None and row["classification"] == "between_pairs"
    late = mkrec("Security", 4616, 50, SEC, prev=at(1))
    _, after = _sf_case(tmp_path, "after", sec=[late])
    assert hrow(after, "ep-01")["offset_status"] == "stale"


def test_sf1_export_hit_before_the_first_pair_is_expected_and_cuts_nothing(tmp_path):
    """SF-1 / CO-19: a counted export hit before ep-01's very first original pair (5.0 s) is `expected`: no flag, all 5
    pairs kept."""
    _, res = _sf_case(tmp_path, "a", sec=[mkrec("Security", 4616, 2, SEC, 8480)])
    assert hrow(res, "ep-01")["n_pairs"] == 5 and hrow(res, "ep-01")["offset_status"] == "ok"
    assert [c["classification"] for c in change_rows_of(res)] == ["expected_before_first_pair"]
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is False


def test_sf1_hit_of_a_skipped_file_does_not_cut(tmp_path):
    """SF-1 / CO-19: a hit in an export whose sha256 is not the manifest's is not used (the file is skipped), so it cannot cut
    or make a host stale; the scan is then incomplete (SF-4)."""
    rec = mkrec("Security", 4616, 15, SEC, 5000, sha=OTHER_SHA)
    exports = {("ep-01", "security"): [rec]}
    _, res = measure(tmp_path, two_groups([]), exports=exports, manifest=[("ep-01", "security", SHA)])
    assert hrow(res, "ep-01")["n_pairs"] == 5 and change_rows_of(res) == []
    assert res["stats"]["s02_t00"]["clock_scan"] == "incomplete"


def test_sf1_db_row_and_export_record_of_the_same_change_count_once_for_cut_and_stale(tmp_path):
    """SF-1 / CO-15: a post-CO-18 DB row and the export record it came from (same host, channel, event id, instant) are
    one change: the cut drops the earlier pairs once (3 left, not fewer), and a stale host lists ONE stale uid."""
    for t, name in ((15, "mid"), (50, "late")):
        files = ChangeFiles()
        rows = two_groups([files.row("chg", "ep-01", "Security", 4616, t, 5000)])
        # the export is the very JSONL file the DB row points to, listed in the manifest
        _, res = measure(tmp_path, rows, name=name, files=files, manifest=[("ep-01", "security", SHA)])
        ev1 = res["stats"]["s02_t00"]["evidence"]["per_host"]["ep-01"]
        if t == 15:
            assert hrow(res, "ep-01")["n_pairs"] == 3 and ev1["n_dropped_before_change"] == 2
            assert ev1["stale_event_uids"] == []
        else:
            assert hrow(res, "ep-01")["offset_status"] == "stale"
            assert len(ev1["stale_event_uids"]) == 1, ev1["stale_event_uids"]
        assert res["stats"]["s02_t00"]["clock_scan"] == "complete"


def test_sf1_db_row_and_export_record_not_the_same_instant_are_two_changes(tmp_path):
    """SF-1: dedup is on host, channel, event id AND instant: a DB row at 12 s and an export record at 15 s are two
    changes, and the later one is the cut (the earlier two pairs go; a stale uid is not listed)."""
    files = ChangeFiles()
    rows = two_groups([files.row("chg", "ep-01", "Security", 4616, 12, 5000)])
    files.lines[("ep-01", "security")].append(mkrec("Security", 4616, 15, SEC, 5000, idx=2))
    _, res = measure(tmp_path, rows, files=files, manifest=[("ep-01", "security", SHA)])
    assert hrow(res, "ep-01")["n_pairs"] == 3
    classes = sorted(c["classification"] for c in change_rows_of(res))
    assert classes.count("between_pairs") == len(classes) >= 2


# ====================================================================================== review SF-3: scan required, binding columns

def test_sf3_cli_rejects_no_scan_and_writes_nothing(tmp_path):
    """SF-3: the former `--no-scan` option is removed: the CLI exits with status 2 (unrecognised argument) and writes nothing."""
    repo = make_repo(tmp_path, _rich_rows())
    before = _snapshot(repo)
    with pytest.raises(SystemExit) as ei:
        co_main.main(["--trials", "s02_t00", "--repo", str(repo), "--no-scan"])
    assert ei.value.code == 2
    assert _snapshot(repo) == before and not (repo / "out").exists()


def test_sf3_run_scan_false_without_write_is_still_available_but_says_incomplete(tmp_path):
    """SF-3 / SF-4: scan=False stays usable in memory (write=False) for tests; it reports `clock_scan = incomplete`
    and no clock_change_in_window, so a scan-less result can never look complete."""
    _, res = measure(tmp_path, _rich_rows(), scan=False)
    assert res["stats"]["s02_t00"]["clock_scan"] == "incomplete"
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is None
    assert {r["clock_scan"] for r in res["rows"]["s02_t00"]} == {"incomplete"}


def test_sf3_offsets_file_carries_the_hash_of_the_changes_file_and_the_scan_state(tmp_path):
    """SF-3 / SF-4: every row of the written offsets file has clock_changes_sha256 = SHA-256 of the clock_changes.csv bytes
    written in the same run, and clock_scan; the columns are the last two of the header, in that order. The hash follows the
    changes file's content (an export hit makes it different from a header-only file)."""
    plain_repo, _ = _sf_case(tmp_path, "plain", write=True)
    hit_repo, _ = _sf_case(tmp_path, "hit", sec=[mkrec("Security", 4616, 15, SEC, 5000)], write=True)
    shas = {}
    for name, repo in (("plain", plain_repo), ("hit", hit_repo)):
        header, body = read_csv(repo / "data/processed/s02_t00.clock_offsets.csv")
        assert header[-2:] == ["clock_changes_sha256", "clock_scan"]
        want = hashlib.sha256((repo / "data/processed/s02_t00.clock_changes.csv").read_bytes()).hexdigest()
        assert len(body) == 4 and {r["clock_changes_sha256"] for r in body} == {want}
        assert {r["clock_scan"] for r in body} == {"complete"}
        shas[name] = want
    assert shas["plain"] != shas["hit"]


def test_sf3_binding_columns_are_deterministic_on_rerun(tmp_path):
    """SF-3 / CO-14: the same inputs give byte-identical offsets and changes files, binding columns included."""
    repo, _ = _sf_case(tmp_path, "a", sec=[mkrec("Security", 4616, 15, SEC, 5000)], write=True)
    names = ("data/processed/s02_t00.clock_offsets.csv", "data/processed/s02_t00.clock_changes.csv")
    first = {n: (repo / n).read_bytes() for n in names}
    run.run(repo, ["s02_t00"], write=True)
    assert {n: (repo / n).read_bytes() for n in names} == first


def _gate_windows_csv(repo: Path, trial: str) -> Path:
    """A one-row trial_windows.csv built from the clock files now on disk (their hashes recorded in the row), so a gate
    refusal can only come from the clock-file checks, not from a hash mismatch in the window row."""
    clock = tw_window.load_clock_files(run.offsets_path(repo, trial), run.changes_path(repo, trial))
    edges = tw_window.WindowResult(edge(-60), edge(400), None, None, edge(-60), edge(400), False, False)
    row = tw_window.window_row(trial, edges, "computed_agent_run", "synthetic", sha(run.db_path(repo, trial)),
                               "corrected", tw_window.clock_columns(clock))
    out = repo / "data" / "trial_windows.csv"
    tw_window.write_csv([row], out)
    return out


def _both_refuse(repo: Path, trial: str, tmp_path: Path, *words: str) -> None:
    """trial_window gives no row and a SKIPPED reason; the gate raises GateError and creates nothing under out/gate."""
    res = tw_main.run(repo, [trial], tmp_path / "no_operator.csv", tmp_path / "w.csv")
    assert res["rows"] == [] and trial in res["skipped"], res
    windows = _gate_windows_csv(repo, trial)
    gate_out = repo / "out" / "gate"
    with pytest.raises(GateError) as ei:
        run_gate(trial, run.db_path(repo, trial), windows, gate_out, repo=repo)
    assert not gate_out.exists()
    for w in words:
        assert w in res["skipped"][trial], (w, res["skipped"][trial])
        assert w in str(ei.value), (w, str(ei.value))


def _rewrite_csv(path: Path, fn) -> None:
    header, body = read_csv(path)
    for r in body:
        fn(r)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=header, lineterminator="\n")
        w.writeheader()
        w.writerows(body)


def test_sf3_chain_changes_file_copied_from_another_trial_is_refused_by_window_and_gate(tmp_path):
    """SF-3: a clock_changes.csv copied over from another trial's run (its rows name that trial, its hash is not the one
    the offsets file records) makes trial_window and the gate refuse, with nothing written."""
    repo, _ = _sf_case(tmp_path, "a", sec=[mkrec("Security", 4616, 15, SEC, 5000)], write=True)
    other, _ = _sf_case(tmp_path, "b", sec=[mkrec("Security", 4616, 50, SEC, 5000)], trial="s03_t00", write=True)
    shutil.copyfile(other / "data/processed/s03_t00.clock_changes.csv", repo / "data/processed/s02_t00.clock_changes.csv")
    _both_refuse(repo, "s02_t00", tmp_path, "s03_t00")


def test_sf3_chain_edited_changes_file_hash_mismatch_is_refused(tmp_path):
    """SF-3: a clock_changes.csv of the right trial whose bytes differ from the run that wrote the offsets file (here: its
    classification edited) is a hash mismatch: refused by window and gate."""
    repo, _ = _sf_case(tmp_path, "a", sec=[mkrec("Security", 4616, 15, SEC, 5000)], write=True)
    _rewrite_csv(repo / "data/processed/s02_t00.clock_changes.csv",
                 lambda r: r.update(classification="routine", counted="false"))
    _both_refuse(repo, "s02_t00", tmp_path, "clock_changes_sha256")


def test_sf3_chain_offsets_rows_naming_another_trial_are_refused(tmp_path):
    """SF-3: an offsets file whose rows name another trial is refused by window and gate."""
    repo, _ = _sf_case(tmp_path, "a", write=True)
    _rewrite_csv(repo / "data/processed/s02_t00.clock_offsets.csv", lambda r: r.update(trial_id="s03_t00"))
    _both_refuse(repo, "s02_t00", tmp_path, "s03_t00")


@pytest.mark.parametrize("status", ["ok", "wide"])
def test_sf3_chain_ok_or_wide_row_without_offset_ms_is_refused(tmp_path, status):
    """SF-3: a row with status ok/wide but an empty offset_ms is refused by window and gate (a silent uncorrected host)."""
    rows = agent_rows() + host_pairs("ep-01", [-5000, -5100, -4900]) + host_pairs("ep-02", [100, 200], prefix=1)
    repo, res = measure(tmp_path, rows, write=True)
    assert hrow(res, "ep-02")["offset_status"] == "ok"

    def blank(r: dict) -> None:
        if r["host"] == "ep-02":
            r["offset_status"], r["offset_ms"] = status, ""

    _rewrite_csv(repo / "data/processed/s02_t00.clock_offsets.csv", blank)
    _both_refuse(repo, "s02_t00", tmp_path, "offset_ms", "ep-02")


# ====================================================================================== review SF-4: incomplete scan

SEC_OK = lambda: [mkrec("Security", 4616, 2, SEC, 5000, idx=1)]       # noqa: E731  an `expected` hit, so the flag is False


def _sf4_setup(kind: str, tmp_path: Path):
    """(repo, listed host/channel that must appear among the skipped files or None) for one kind of hole."""
    manifest = [("ep-01", "security", SHA), ("ep-01", "system", SHA)]
    sys_rec = lambda **kw: mkrec("System", 1, 12, KG, 5000, **kw)    # noqa: E731
    exports = {("ep-01", "security"): SEC_OK()}
    if kind == "system_export_missing":
        pass
    elif kind == "system_sha_not_in_manifest":
        exports[("ep-01", "system")] = [sys_rec(sha=OTHER_SHA)]
    elif kind == "system_mixed_sha":
        exports[("ep-01", "system")] = [sys_rec(sha=SHA), sys_rec(sha=OTHER_SHA, idx=2)]
    elif kind == "system_no_records":
        exports[("ep-01", "system")] = []
    elif kind == "system_record_without_sha":
        rec = sys_rec()
        del rec["source"]["sha256"]
        exports[("ep-01", "system")] = [rec]
    else:
        raise AssertionError(kind)
    repo = make_repo(tmp_path, two_groups([]), name=kind, exports=exports, manifest=manifest)
    return repo, ("ep-01", "system")


HOLES = ["system_export_missing", "system_sha_not_in_manifest", "system_mixed_sha", "system_no_records",
         "system_record_without_sha"]


@pytest.mark.parametrize("kind", HOLES)
def test_sf4_manifest_listed_export_skipped_makes_the_scan_incomplete_and_refuses(tmp_path, kind):
    """SF-4 / CO-19: a security/system export the manifest lists that is missing, empty, has a sha256 the manifest does not
    list, mixed sha256 values or a record without sha256, makes the scan `incomplete`: offsets rows say so,
    clock_change_in_window is null, clock_scan.json lists the skipped file (listed in the manifest), and trial_window and
    the gate refuse with the clock_scan.json reason, writing nothing."""
    repo, (host, stem) = _sf4_setup(kind, tmp_path)
    res = run.run(repo, ["s02_t00"], write=True)
    st = res["stats"]["s02_t00"]
    assert st["clock_scan"] == "incomplete" and st["clock_change_in_window"] is None
    assert {r["clock_scan"] for r in res["rows"]["s02_t00"]} == {"incomplete"}
    _, body = read_csv(repo / "data/processed/s02_t00.clock_offsets.csv")
    assert {r["clock_scan"] for r in body} == {"incomplete"}
    doc = json.loads((repo / "out/clock_offset/s02_t00/clock_scan.json").read_text(encoding="utf-8"))
    assert doc["clock_scan"] == "incomplete" and doc["clock_change_in_window"] is None
    skipped = [f for f in doc["files_skipped"] if f["path"].endswith(f"{host}/{stem}.jsonl")]
    assert len(skipped) == 1 and skipped[0]["reason"] and skipped[0]["manifest_listed"] is True
    assert doc["manifest_files_skipped"] == 1
    # the owner decides on the trial: the files exist, the consumers refuse with the pointer to clock_scan.json
    _both_refuse(repo, "s02_t00", tmp_path, "incomplete", "clock_scan.json", "s02_t00")


def test_sf4_a_known_change_does_not_make_an_incomplete_scan_look_known(tmp_path):
    """SF-4: with a hole, even a counted between-pairs hit in a readable file leaves clock_change_in_window null (unknown),
    not true and not false."""
    exports = {("ep-01", "security"): [mkrec("Security", 4616, 15, SEC, 5000)],
               ("ep-01", "system"): [mkrec("System", 1, 12, KG, 5000, sha=OTHER_SHA)]}
    _, res = measure(tmp_path, two_groups([]), exports=exports,
                     manifest=[("ep-01", "security", SHA), ("ep-01", "system", SHA)])
    assert res["stats"]["s02_t00"]["clock_scan"] == "incomplete"
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is None
    assert [c["classification"] for c in change_rows_of(res)] == ["between_pairs"]       # the readable hit is still listed


@pytest.mark.parametrize("kind", ["garbage", "missing", "blank"])
@pytest.mark.parametrize("channel", ["Security", "System"])
def test_sf4_clock_change_record_with_no_parseable_time_makes_the_scan_incomplete(tmp_path, kind, channel):
    """SF-4 / CO-19: a Security 4616 / Kernel-General System 1 record whose time cannot be parsed cannot be placed in the span,
    so the scan is incomplete (counted in clock_change_records_without_time), clock_change_in_window is null, and the
    consumers refuse. No file is skipped by the manifest check."""
    event_id, provider, stem = (4616, SEC, "security") if channel == "Security" else (1, KG, "system")
    rec = mkrec(channel, event_id, 12, provider, 5000)
    if kind == "garbage":
        rec["system"]["timestamp_raw"] = "not a time"
    elif kind == "missing":
        del rec["system"]["timestamp_raw"]
    else:
        rec["system"]["timestamp_raw"] = "   "
    repo = make_repo(tmp_path, two_groups([]), exports={("ep-01", stem): [rec]}, manifest=[("ep-01", stem, SHA)])
    res = run.run(repo, ["s02_t00"], write=True)
    st = res["stats"]["s02_t00"]
    assert st["clock_scan"] == "incomplete" and st["clock_change_in_window"] is None
    doc = json.loads((repo / "out/clock_offset/s02_t00/clock_scan.json").read_text(encoding="utf-8"))
    assert doc["clock_scan"] == "incomplete" and doc["clock_change_records_without_time"] == 1
    assert doc["files_skipped"] == [] and doc["manifest_files_skipped"] == 0
    _both_refuse(repo, "s02_t00", tmp_path, "incomplete", "clock_scan.json")


def test_sf4_other_events_without_a_time_do_not_make_the_scan_incomplete(tmp_path):
    """SF-4: only clock-change records need a parseable time: a 4624 or a System 6005 with a broken timestamp is not a
    clock-change record, so the scan stays complete."""
    junk = [mkrec("Security", 4624, 12, SEC), mkrec("System", 6005, 13, "EventLog"),
            mkrec("System", 1, 14, "Microsoft-Windows-Power-Troubleshooter", 5000)]
    for r in junk:
        r["system"]["timestamp_raw"] = "not a time"
    repo = make_repo(tmp_path, two_groups([]), exports={("ep-01", "security"): junk[:1], ("ep-01", "system"): junk[1:]},
                     manifest=[("ep-01", "security", SHA), ("ep-01", "system", SHA)])
    res = run.run(repo, ["s02_t00"], write=True)
    assert res["stats"]["s02_t00"]["clock_scan"] == "complete"
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is False
    assert tw_window.clock_refusal(tw_window.load_clock_files(run.offsets_path(repo, "s02_t00"),
                                                              run.changes_path(repo, "s02_t00")),
                                   None, sha(run.db_path(repo, "s02_t00")), trial_id="s02_t00") is None


def test_sf4_host_or_channel_with_no_file_in_the_manifest_is_not_incomplete(tmp_path):
    """SF-4: a host/channel the manifest does not list is not a skipped file: an export on disk that the manifest does not
    know (ep-02 security), a manifest without dc01 or ep-03, and a manifest that lists nothing for the trial all leave the
    scan `complete`. The unknown export is still reported as skipped (manifest_listed false), as before."""
    exports = {("ep-01", "security"): SEC_OK(), ("ep-02", "security"): [mkrec("Security", 4616, 15, SEC, 5000)]}
    repo = make_repo(tmp_path, two_groups([]), name="a", exports=exports, manifest=[("ep-01", "security", SHA)])
    res = run.run(repo, ["s02_t00"], write=True)
    assert res["stats"]["s02_t00"]["clock_scan"] == "complete"
    assert res["stats"]["s02_t00"]["clock_change_in_window"] is False
    assert change_rows_of(res) and all(c["host"] == "ep-01" for c in change_rows_of(res))      # the ep-02 hit is unused
    doc = json.loads((repo / "out/clock_offset/s02_t00/clock_scan.json").read_text(encoding="utf-8"))
    unknown = [f for f in doc["files_skipped"] if f["path"].endswith("ep-02/security.jsonl")]
    assert len(unknown) == 1 and unknown[0]["manifest_listed"] is False and doc["manifest_files_skipped"] == 0
    clock = tw_window.load_clock_files(run.offsets_path(repo, "s02_t00"), run.changes_path(repo, "s02_t00"))
    assert tw_window.clock_refusal(clock, None, sha(run.db_path(repo, "s02_t00")), trial_id="s02_t00") is None
    # a manifest with no row for the trial at all
    repo2 = make_repo(tmp_path, two_groups([]), name="b", exports={("ep-01", "security"): SEC_OK()}, manifest=[])
    res2 = run.run(repo2, ["s02_t00"], write=False)
    assert res2["stats"]["s02_t00"]["clock_scan"] == "complete"


# ====================================================================================== COT-21 readings (CO-12)

LOCAL_DATE = "23/11/2026"


def block(clock: str = "08:00:00", o_values=(-14.0, -15.0, -16.0), target: str = "dc01.lab.local [192.168.50.10:123]",
          date_text: str | None = LOCAL_DATE, errors: int = 0) -> str:
    lines = [f"Tracking {target}.", f"Collecting {len(o_values)} samples."]
    if date_text:
        lines.append(f"The current time is {date_text} {clock}.")
    h, m, s = (int(x) for x in clock.split(":"))
    sec = h * 3600 + m * 60 + s
    for i, o in enumerate(o_values):
        t = sec + 2 * i
        lines.append(f"{t // 3600:02d}:{t % 3600 // 60:02d}:{t % 60:02d}, d:+00.0010000s o:{o:+.7f}s  [   *       |    ]")
    for j in range(errors):
        t = sec + 2 * (len(o_values) + j)
        lines.append(f"{t // 3600:02d}:{t % 3600 // 60:02d}:{t % 60:02d}, error: 0x800705B4")
    return "\n".join(lines) + "\n"


UTC7 = timezone(timedelta(hours=7))
UTC8 = timezone(timedelta(hours=8))


def utc(y, mo, d, h, mi, s=0) -> datetime:
    return datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)


@pytest.mark.parametrize("target", ["dc01.lab.local [192.168.50.10:123]", "dc01 [192.168.50.10:123]",
                                    "DC01.LAB.LOCAL [192.168.50.10:123]", "192.168.50.10",
                                    "192.168.50.10 [192.168.50.10:123]"])
def test_cot21_target_dc01_or_its_ip_is_valid(target):
    """COT-21: the `Tracking` target must name dc01 (name or 192.168.50.10) for the file to be valid."""
    rf = readings.parse_stripchart(block(target=target) + "UTC\n")
    assert rf.status == "valid", rf.reasons
    assert rf.sessions[0].target_ok and rf.sessions[0].usable


@pytest.mark.parametrize("target", ["time.windows.com [40.119.6.228:123]", "ep-01.lab.local [192.168.50.21:123]",
                                    "192.168.50.11", "dc02.lab.local [192.168.50.11:123]"])
def test_cot21_other_target_is_invalid(target):
    """COT-21: time.windows.com, an endpoint or another IP as target makes the file invalid, with a reason naming it."""
    rf = readings.parse_stripchart(block(target=target) + "UTC\n")
    assert rf.status == "invalid"
    assert any("not dc01" in r or target.split(" ")[0] in r for r in rf.reasons), rf.reasons
    assert not rf.sessions[0].usable


def test_cot21_one_non_dc01_session_invalidates_the_file():
    """COT-21: a file with a dc01 session and a time.windows.com session is invalid, and the second is unusable."""
    rf = readings.parse_stripchart(block() + block("08:05:00", target="time.windows.com [1.2.3.4:123]") + "UTC\n")
    assert rf.status == "invalid"
    assert [s.usable for s in rf.sessions] == [True, False]


def test_cot21_no_tracking_line_is_invalid():
    """COT-21: text that is not a w32tm /stripchart output is invalid."""
    assert readings.parse_stripchart("hello\nUTC\n").status == "invalid"


def test_cot21_o_values_median_and_sign():
    """COT-21: the session value is the median of the `o:` samples; host - dc01 = sign * o (the sign is a parameter)."""
    text = block(o_values=(-14.0, -15.0, -16.4)) + "UTC\n"
    neg = readings.parse_stripchart(text, sign=-1).sessions[0]
    pos = readings.parse_stripchart(text, sign=+1).sessions[0]
    assert neg.sample_count == 3 and neg.median_o_us == -15_000_000
    assert pos.offset_host_minus_dc01_ms == -15_000 and neg.offset_host_minus_dc01_ms == 15_000
    assert pos.sign == 1 and neg.sign == -1
    default = readings.parse_stripchart(text).sessions[0]
    assert default.sign == readings.SIGN_CONVENTION == -1 and default.offset_host_minus_dc01_ms == 15_000
    with pytest.raises(ValueError):
        readings.parse_stripchart(text, sign=2)


def test_cot21_median_of_even_count_and_delay_and_dataonly():
    """COT-21: an even count gives the mean of the two middle values; `d:` is kept; /dataonly lines are read as `o`."""
    even = readings.parse_stripchart(block(o_values=(-14.0, -16.0)) + "UTC\n", sign=+1).sessions[0]
    assert even.median_o_us == -15_000_000 and even.samples[0].delay_s is not None
    only = ("Tracking dc01.lab.local [192.168.50.10:123].\nCollecting 2 samples.\n"
            f"The current time is {LOCAL_DATE} 08:00:00.\n08:00:00, -14.5000000s\n08:00:02, -15.5000000s\nUTC\n")
    s = readings.parse_stripchart(only, sign=+1).sessions[0]
    assert s.sample_count == 2 and s.median_o_us == -15_000_000


def test_cot21_error_lines_are_skipped_and_counted():
    """COT-21: `error: 0x800705B4` sample lines are not samples; they are counted. Unparsed junk is kept apart."""
    text = block(o_values=(-14.0, -16.0), errors=3) + "garbage line\n" + "UTC\n"
    s = readings.parse_stripchart(text, sign=+1).sessions[0]
    assert s.sample_count == 2 and s.error_count == 3
    assert s.median_o_us == -15_000_000 and "garbage line" in s.unparsed_lines
    only_errors = readings.parse_stripchart(block(o_values=(), errors=2) + "UTC\n").sessions[0]
    assert only_errors.sample_count == 0 and only_errors.error_count == 2 and only_errors.usable is False


def test_cot21_utf16_le_bom_crlf_equals_utf8(tmp_path):
    """COT-21: a UTF-16 LE file with BOM and CRLF line ends parses to the same readings as the UTF-8 file."""
    text = block() + block("08:20:00", o_values=(-1.5, -2.5)) + "\nSE Asia Standard Time\n"
    p16 = tmp_path / "a_clock.txt"
    p8 = tmp_path / "b_clock.txt"
    p16.write_bytes(b"\xff\xfe" + text.replace("\n", "\r\n").encode("utf-16-le"))
    p8.write_bytes(text.encode("utf-8"))
    a, b = readings.parse_reading_file(p16), readings.parse_reading_file(p8)
    assert a.encoding != b.encoding and a.encoding and "utf-16" in a.encoding
    def key(rf):
        return (rf.status, rf.reasons, rf.tz_name, [(s.target, s.median_o_us, s.offset_host_minus_dc01_ms, s.utc_start,
                                                      s.sample_count, s.error_count) for s in rf.sessions])
    assert key(a) == key(b) and a.status == "valid" and len(a.sessions) == 2
    crlf8 = readings.parse_stripchart(text.replace("\n", "\r\n"))
    assert key(crlf8) == key(b)


def test_cot21_tzutil_se_asia_converts_local_to_utc_plus7():
    """COT-21: with a `tzutil /g` line `SE Asia Standard Time`, local 08:00 (UTC+7) is 01:00 UTC."""
    rf = readings.parse_stripchart(block("08:00:00") + "\nSE Asia Standard Time\n")
    assert rf.status == "valid" and rf.tz_name == "SE Asia Standard Time" and rf.tz_source == "file"
    assert rf.sessions[0].utc_start == utc(2026, 11, 23, 1, 0, 0)
    rf2 = readings.parse_stripchart(block("00:30:00") + "SE Asia Standard Time\r\n")           # crosses midnight in UTC
    assert rf2.sessions[0].utc_start == utc(2026, 11, 22, 17, 30, 0)
    utc_file = readings.parse_stripchart(block("08:00:00") + "UTC\n")
    assert utc_file.sessions[0].utc_start == utc(2026, 11, 23, 8, 0, 0)


def test_cot21_missing_tz_line_without_argument_is_invalid():
    """COT-21 (D7): no `tzutil /g` line and no tz argument: invalid (local times cannot be placed in UTC)."""
    rf = readings.parse_stripchart(block())
    assert rf.status == "invalid" and any("tz" in r.lower() for r in rf.reasons)
    assert rf.sessions[0].utc_start is None


def test_cot21_missing_tz_line_with_argument_is_valid():
    """COT-21 (D7): no line but a tz argument: valid, the argument is used and the source says so."""
    rf = readings.parse_stripchart(block("08:00:00"), tz=UTC7)
    assert rf.status == "valid" and rf.tz_source == "argument"
    assert rf.sessions[0].utc_start == utc(2026, 11, 23, 1, 0, 0)


def test_cot21_unknown_zone_name_invalid_without_argument_valid_with_one():
    """COT-21 (D7): an unknown Windows zone name with no argument is invalid; with an argument the argument is used."""
    text = block("08:00:00") + "Klingon Standard Time\n"
    bad = readings.parse_stripchart(text)
    assert bad.status == "invalid" and any("Klingon" in r for r in bad.reasons)
    good = readings.parse_stripchart(text, tz=UTC7)
    assert good.status == "valid" and good.tz_source == "argument"
    assert good.sessions[0].utc_start == utc(2026, 11, 23, 1, 0, 0)


def test_cot21_conflicting_zone_name_and_argument_invalid():
    """COT-21 (D7): the file says SE Asia (UTC+7) and the caller says UTC+8: invalid; an agreeing argument is fine."""
    text = block("08:00:00") + "SE Asia Standard Time\n"
    bad = readings.parse_stripchart(text, tz=UTC8)
    assert bad.status == "invalid" and any("differs" in r or "tz" in r.lower() for r in bad.reasons)
    ok = readings.parse_stripchart(text, tz=UTC7)
    assert ok.status == "valid" and ok.sessions[0].utc_start == utc(2026, 11, 23, 1, 0, 0)


def test_cot21_windows_zone_table_maps_without_dst_database():
    """COT-21 (D7): the zone table maps a Windows name to fixed offsets for zones without DST (the venv has no tzdata)."""
    z, key, why = readings.resolve_windows_tz("SE Asia Standard Time")
    assert why is None and z is not None
    assert datetime(2026, 11, 23, 8, 0).replace(tzinfo=z).astimezone(timezone.utc) == utc(2026, 11, 23, 1, 0)
    z2, _, why2 = readings.resolve_windows_tz("Not A Zone Standard Time")
    assert z2 is None and why2


def _sessions(text: str, tz=timezone.utc) -> list:
    rf = readings.parse_stripchart(text, tz=tz)
    assert rf.status == "valid", rf.reasons
    return list(rf.sessions)


def test_cot21_assignment_unsynced_t01_start_and_end():
    """COT-21 / CO-12 (t01, not synced): the reading before the run is `start`, the one after collection is `end`;
    there is no post-sync reading."""
    ss = _sessions(block("08:00:00") + block("08:20:00"))
    a = readings.assign_readings(ss, utc(2026, 11, 23, 8, 5), utc(2026, 11, 23, 8, 15))
    assert a.start is ss[0] and a.end is ss[1] and a.post_sync is None
    assert not a.unplaced and not a.unusable and not a.unassigned


def test_cot21_assignment_synced_t02_start_post_sync_end():
    """COT-21 / CO-12 (t02-t10, synced): reading, sync, reading: start is the reading before the sync, post_sync the
    first after it; an end reading after the run is assigned too."""
    ss = _sessions(block("08:00:00") + block("08:03:00", o_values=(-0.1, -0.2, -0.3)) + block("08:20:00"))
    sync, run_a, run_b = utc(2026, 11, 23, 8, 2), utc(2026, 11, 23, 8, 5), utc(2026, 11, 23, 8, 15)
    a = readings.assign_readings(ss, run_a, run_b, sync)
    assert a.start is ss[0] and a.post_sync is ss[1] and a.end is ss[2]
    b = readings.assign_readings(ss[:2], run_a, run_b, sync)                     # no reading after the run
    assert b.start is ss[0] and b.post_sync is ss[1] and b.end is None
    c = readings.assign_readings(ss[:2], run_a, run_b)                           # without the sync time: last before the run
    assert c.start is ss[1] and c.post_sync is None


def test_cot21_assignment_during_run_unusable_and_unplaced():
    """COT-21: a reading taken during the run is unassigned, a non-dc01 session is unusable, a session without a date
    (so no UTC time) is unplaced."""
    text = (block("08:00:00") + block("08:10:00") + block("08:30:00", target="time.windows.com [1.2.3.4:123]")
            + block("08:40:00", date_text=None))
    rf = readings.parse_stripchart(text, tz=timezone.utc)
    assert rf.status == "invalid"                                             # a non-dc01 session is in the file
    ss = list(rf.sessions)
    a = readings.assign_readings(ss, utc(2026, 11, 23, 8, 5), utc(2026, 11, 23, 8, 15))
    assert a.start is ss[0] and a.unassigned == (ss[1],) and a.unusable == (ss[2],) and a.unplaced == (ss[3],)
    assert a.end is None


def test_cot21_assignment_requires_aware_instants_and_ordered_run():
    """COT-21: naive datetimes are refused (a naive local time would shift by the zone offset); end before start too."""
    ss = _sessions(block("08:00:00"))
    with pytest.raises(ValueError):
        readings.assign_readings(ss, datetime(2026, 11, 23, 8, 5), utc(2026, 11, 23, 8, 15))
    with pytest.raises(ValueError):
        readings.assign_readings(ss, utc(2026, 11, 23, 8, 15), utc(2026, 11, 23, 8, 5))


def test_cot21_assignment_uses_utc_after_zone_conversion():
    """COT-21: sessions printed in UTC+7 local time are placed by their UTC instant: local 08:00 is before a run that
    starts at 02:00 UTC (09:00 local), and local 09:20 is after it ends at 02:15 UTC."""
    ss = _sessions(block("08:00:00") + block("09:20:00"), tz=UTC7)
    a = readings.assign_readings(ss, utc(2026, 11, 23, 2, 0), utc(2026, 11, 23, 2, 15))
    assert a.start is ss[0] and a.end is ss[1]


# ====================================================================================== real data: scan (COA-07, COA-08)

JSONL_ROOT = (PROCESSED / "jsonl").resolve()


@pytest.fixture(scope="module")
def real_scan():
    """The step with the CO-19 export scan on the 11 allowlisted trials (in memory, write=False), recording opens."""
    for t in ALLOWLIST:
        _db(t)
    before = {t: sha(PROCESSED / f"{t}.sqlite3") for t in ALLOWLIST}
    rec = _Recorder()
    with pytest.MonkeyPatch.context() as mp:
        _install_recorders(mp, rec)
        res = run.run(REPO, list(ALLOWLIST), write=False, scan=True)
    after = {t: sha(PROCESSED / f"{t}.sqlite3") for t in ALLOWLIST}
    return {"res": res, "paths": rec.paths, "before": before, "after": after}


@pytest.mark.slow
def test_coa07_scan_opens_only_allowlisted_trials(real_scan):
    """COA-07 guard: the scan opens only the 11 allowlisted trial DBs and, under data/processed/jsonl/, only those
    trials' folders; nothing under ground_truth/; DB hashes unchanged; no file is written (write=False)."""
    dbs = {Path(p).name for p in real_scan["paths"] if p.lower().endswith(".sqlite3")}
    assert dbs == {f"{t}.sqlite3" for t in ALLOWLIST}
    for p in real_scan["paths"]:
        if _under(p, JSONL_ROOT):
            trial = Path(p).resolve().relative_to(JSONL_ROOT).parts[0]
            assert trial in ALLOWLIST, f"scan opened an export of {trial}: {p}"
    assert not [p for p in real_scan["paths"] if _under(p, REPO / "ground_truth")]
    assert real_scan["before"] == real_scan["after"]
    assert any(_under(p, JSONL_ROOT) for p in real_scan["paths"]), "the scan read no export"


def _chg_rows(real_scan, trial: str) -> list[dict]:
    return real_scan["res"]["clock"][trial]["changes_rows"]


@pytest.mark.slow
def test_coa07_hits_listed_per_trial_and_flag_matches_d3_rule(real_scan):
    """COA-07: the hits per trial are listed, every export file passes the sha256 check, and the trial flag equals the
    D3 rule recomputed from the rows (a counted change classified between / after / no_pairs). Today it is false on all 11."""
    lines = []
    for t in ALLOWLIST:
        st = real_scan["res"]["stats"][t]
        scan = st["clock_change_scan"]
        rows = _chg_rows(real_scan, t)
        expect = any(r["counted"] and r["classification"] in ("between_pairs", "after_last_pair", "no_pairs")
                     for r in rows)
        lines.append(f"{t}: flag={st['clock_change_in_window']} hits={scan['export_hits']} "
                     f"{scan['by_classification']}")
        assert scan["export_scan_run"] is True and scan["files_skipped"] == 0 and scan["coverage_complete"] is True, t
        assert st["clock_change_in_window"] is expect, t
        assert real_scan["res"]["clock"][t]["flag"] is expect
        assert st["clock_change_in_window"] is False, f"{t}: owner expects false on all 11 today"
        assert {r["classification"] for r in rows} <= {"routine", "expected_before_first_pair"}, t
        assert all(r["source"] == "export" for r in rows), t          # the existing DBs hold no 4616 / System 1
    print("\nCOA-07 hits per trial\n" + "\n".join(lines))


@pytest.mark.slow
def test_coa07_counted_expected_steps_on_ep02_and_routine_ones(real_scan):
    """COA-07: counted `expected` steps are on ep-02 in s02_t00 (+8480 ms), s06_t00, s07_t00 and in every t01; routine ones
    are on s02_t00, s03_t00, s06_t00 and s07_t00; s04_t00 and s05_t00 have no clock change."""
    def pick(t, cls):
        return [r for r in _chg_rows(real_scan, t) if r["classification"] == cls]

    for t in ("s02_t00", "s06_t00", "s07_t00", "s02_t01", "s03_t01", "s06_t01", "s04_t01", "s07_t01"):
        exp = pick(t, "expected_before_first_pair")
        assert exp and {r["host"] for r in exp} == {"ep-02"}, t
        assert all(r["counted"] is True and abs(r["shift_ms"]) >= 1000 for r in exp), t
        assert {r["channel"] for r in exp} == {"Security", "System"}, t       # the 4616 and the System 1 of the same step
    assert {r["shift_ms"] for r in pick("s02_t00", "expected_before_first_pair")} == {8480}
    for t in ("s02_t00", "s03_t00", "s06_t00", "s07_t00"):
        rt = pick(t, "routine")
        assert rt and all(r["counted"] is False and abs(r["shift_ms"]) < 1000 for r in rt), t
    for t in ("s04_t00", "s05_t00"):
        assert _chg_rows(real_scan, t) == [], t
    for t in ("s03_t01", "s06_t01", "s02_t01", "s04_t01", "s07_t01"):
        assert pick(t, "routine") == [], t


@pytest.mark.slow
def test_coa07_offsets_unchanged_by_the_scan(real_scan, real):
    """COA-07: the scan changes no offset: rows equal those of the run without the scan, on all 11 trials."""
    for t in ALLOWLIST:
        assert [(r["host"], r["offset_status"], r["offset_ms"], r["n_pairs"]) for r in real_scan["res"]["rows"][t]] == [
            (r["host"], r["offset_status"], r["offset_ms"], r["n_pairs"]) for r in real["res"]["rows"][t]], t


@pytest.mark.slow
def test_coa07_changes_text_is_parseable_and_pre_steps_listed(real_scan):
    """COA-07 / D4 / D5: the clock_changes.csv text of every trial loads through the consumer's reader, and a counted
    step inside the agent window is listed in the pre-step report with its counts."""
    for t in ALLOWLIST:
        clock = real_scan["res"]["clock"][t]
        loaded = correct.parse_clock_changes_text(co_scan.changes_text(clock))
        assert len(loaded.changes) == len(clock["changes_rows"]), t
        for s in clock["pre_steps"]:
            assert s["a_real_time_in_window_count"] is not None and s["b_literal_in_window_before_step_count"] >= 0


def collect_refs(obj, path: tuple[str, ...] = ()) -> list[str]:
    """Every 64-hex string anywhere under `obj` (repeats kept), skipping fields whose key path contains 'sha256'
    (same rule as the GTA-06 test)."""
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            found += collect_refs(v, path + (str(k),))
    elif isinstance(obj, list):
        for v in obj:
            found += collect_refs(v, path)
    elif isinstance(obj, str) and re.match(r"^[0-9a-f]{64}$", obj):
        if not any("sha256" in q.lower() for q in path):
            found.append(obj)
    return found


KEY_TRIALS = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00"]


@pytest.mark.slow
@pytest.mark.parametrize("trial", KEY_TRIALS)
def test_coa08_no_key_hop_event_logged_before_a_counted_clock_change(real_scan, trial):
    """COA-08 (owner check): no key-hop event of a development trial (every 64-hex uid under `hops` of the approved
    key, `*sha256*` fields excluded; the key is read by this test only) was logged before a counted clock change on its
    host (correct.before_counted_change with the trial's clock_changes rows)."""
    key_path = REPO / "ground_truth" / "approved" / f"{trial}.yaml"
    if not key_path.exists():
        pytest.skip(f"no approved key {key_path}")
    key = json.loads(key_path.read_text(encoding="utf-8"))
    uids = sorted(set(collect_refs(key["hops"])))
    clock = real_scan["res"]["clock"][trial]
    changes = correct.parse_clock_changes_text(co_scan.changes_text(clock)).changes
    con = ak_db.open_ro(_db(trial))
    try:
        events = {r["event_uid"]: (r["host"], r["t_utc"]) for r in ak_db.query(con)}
    finally:
        con.close()
    bad, checked = [], 0
    for u in uids:
        if u not in events:
            continue                                                # GTA-06 asserts the keys against the DB
        host, t = events[u]
        checked += 1
        if correct.before_counted_change(host, to_us(t), changes):
            bad.append((u, host, t))
    for u, host, t in bad:
        print(f"{trial}: key-hop event {u} host {host} recorded {t} was logged before a counted clock change")
        for c in changes:
            if c.host == host and c.counted:
                print(f"    change {c.channel} {c.event_id} recorded {fmt_us(c.change_us)} previous {c.previous_time} "
                      f"shift {c.shift_ms} ms (last boot before: {c.last_boot_before_us})")
    assert checked > 0, f"{trial}: no key-hop event found in the DB"
    assert bad == [], f"{trial}: {len(bad)} of {checked} key-hop events logged before a counted clock change: {bad}"
    print(f"COA-08 {trial}: {checked} key-hop events checked, counted steps on "
          f"{sorted({c.host for c in changes if c.counted})}")


@pytest.mark.slow
def test_coa08_the_check_is_not_vacuous():
    """COA-08 sanity: the rule does flag an event that precedes a counted step on its host (ep-02 in s02_t00, +8480 ms)."""
    clock_changes = [ch.make_change(host="ep-02", channel="Security", event_id=4616,
                                    change_us=to_us("2026-09-24T05:37:57.551795Z"),
                                    previous_time="2026-09-24T05:37:49.071795Z", new_time="2026-09-24T05:37:57.551795Z",
                                    source="export", ref="1", source_sha256=None)]
    assert clock_changes[0].shift_ms == 8480 and clock_changes[0].counted
    assert correct.before_counted_change("ep-02", to_us("2026-09-24T05:37:50.000000Z"), clock_changes) is True
    assert correct.before_counted_change("ep-02", to_us("2026-09-24T05:37:58.000000Z"), clock_changes) is False


# ====================================================================================== real data: review SF-3 / SF-4

def _read_offsets_file(trial: str) -> tuple[list[str], list[dict]]:
    p = PROCESSED / f"{trial}.clock_offsets.csv"
    if not p.exists():
        pytest.skip(f"{p} missing")
    return read_csv(p)


@pytest.mark.slow
def test_sf4_real_clock_scan_is_complete_on_all_11_trials(real_scan):
    """SF-4: on the 11 allowlisted trials every manifest-listed security/system export is read and every clock-change record
    has a parseable time: clock_scan = complete in the fresh in-memory run (stats and rows), in the written offsets files
    under data/processed (read only), and in out/clock_offset/<trial>/clock_scan.json (read only)."""
    for t in ALLOWLIST:
        st = real_scan["res"]["stats"][t]
        assert st["clock_scan"] == "complete" and st["clock_change_in_window"] is False, t
        assert {r["clock_scan"] for r in real_scan["res"]["rows"][t]} == {"complete"}, t
        header, body = _read_offsets_file(t)
        assert header[-2:] == ["clock_changes_sha256", "clock_scan"], t
        assert len(body) == 4 and {r["clock_scan"] for r in body} == {"complete"}, t
        doc_path = REPO / "out" / "clock_offset" / t / "clock_scan.json"
        if doc_path.exists():
            doc = json.loads(doc_path.read_text(encoding="utf-8"))
            assert doc["clock_scan"] == "complete" and doc["manifest_files_skipped"] == 0, t
            assert doc["clock_change_records_without_time"] == 0 and doc["clock_change_in_window"] is False, t
            assert not [f for f in doc["files_skipped"] if f.get("manifest_listed")], t


@pytest.mark.slow
@pytest.mark.parametrize("trial", ALLOWLIST)
def test_sf3_real_offsets_file_hash_names_the_changes_file_and_equals_a_fresh_run(real_scan, trial):
    """SF-3: in data/processed (read only) the offsets file's clock_changes_sha256 equals the SHA-256 of the
    <trial>.clock_changes.csv beside it, on every row; the files equal what a fresh in-memory run (with the scan) writes, byte
    for byte, so they are in the new format and from this code."""
    header, body = _read_offsets_file(trial)
    changes_file = PROCESSED / f"{trial}.clock_changes.csv"
    assert changes_file.exists(), changes_file
    on_disk = sha(changes_file)
    assert {r["clock_changes_sha256"] for r in body} == {on_disk}
    fresh_changes = co_scan.changes_text(real_scan["res"]["clock"][trial])
    assert hashlib.sha256(fresh_changes.encode("utf-8")).hexdigest() == on_disk
    assert changes_file.read_bytes() == fresh_changes.encode("utf-8")
    from clock_offset import outputs, params
    fresh_offsets = outputs.csv_text(real_scan["res"]["rows"][trial], params.OFFSETS_COLUMNS)
    assert (PROCESSED / f"{trial}.clock_offsets.csv").read_bytes() == fresh_offsets.encode("utf-8")
    assert {r["db_sha256"] for r in body} == {sha(PROCESSED / f"{trial}.sqlite3")}


@pytest.mark.slow
def test_sf3_real_window_and_gate_outputs_name_the_current_clock_files():
    """SF-3: data/trial_windows.csv (read only) records, for every development trial it holds, the SHA-256 of that trial's
    offsets and clock-changes files now on disk, with time_basis corrected; out/gate/<trial>/stats.json (read only) names
    the same two hashes. A trial the window file does not hold is not checked here."""
    p = REPO / "data" / "trial_windows.csv"
    if not p.exists():
        pytest.skip("data/trial_windows.csv missing")
    _, rows = read_csv(p)
    seen = 0
    for r in rows:
        t = r["trial_id"]
        if t not in DEVELOPMENT or not (PROCESSED / f"{t}.clock_offsets.csv").exists():
            continue
        seen += 1
        assert r["time_basis"] == "corrected", t
        assert r["offsets_sha256"] == sha(PROCESSED / f"{t}.clock_offsets.csv"), t
        assert r["clock_changes_sha256"] == sha(PROCESSED / f"{t}.clock_changes.csv"), t
        gate_stats = REPO / "out" / "gate" / t / "stats.json"
        if gate_stats.exists():
            clk = json.loads(gate_stats.read_text(encoding="utf-8"))["clock"]
            assert clk["offsets_sha256"] == r["offsets_sha256"] and clk["clock_changes_sha256"] == r["clock_changes_sha256"], t
    assert seen >= 1


@pytest.mark.slow
def test_sf3_real_standalone_scan_equals_the_step_clock_events_and_scan_json(tmp_path, capsys):
    """CO-19 / SF-3: on s02_t00 (allowlist), in a tmp repo (DB, manifest and the security/system exports copied; the real
    data/processed, data/trial_windows.csv and out/ are never written), `python -m clock_offset` writes the offsets, the
    changes, clock_events.csv and clock_scan.json; then `python -m clock_offset.scan` rewrites clock_events.csv and
    clock_scan.json with exactly the same bytes. The tmp offsets and changes files equal the ones in data/processed, and
    the offsets file's clock_changes_sha256 is the hash of the changes file."""
    trial = "s02_t00"
    _db(trial)
    repo = tmp_path / "repo"
    (repo / "data" / "processed").mkdir(parents=True)
    shutil.copy(PROCESSED / f"{trial}.sqlite3", repo / "data" / "processed" / f"{trial}.sqlite3")
    shutil.copy(REPO / "data" / "manifest.csv", repo / "data" / "manifest.csv")
    src = PROCESSED / "jsonl" / trial / "per_file"
    for host_dir in sorted(p for p in src.iterdir() if p.is_dir()):
        for stem in ("security", "system"):
            f = host_dir / f"{stem}.jsonl"
            if f.is_file():
                dst = repo / "data" / "processed" / "jsonl" / trial / "per_file" / host_dir.name / f.name
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(f, dst)
    assert co_main.main(["--trials", trial, "--repo", str(repo)]) == 0
    capsys.readouterr()
    out = repo / "out" / "clock_offset" / trial
    step = {n: (out / n).read_bytes() for n in ("clock_events.csv", "clock_scan.json")}
    for n in step:
        (out / n).unlink()
    assert co_scan.main(["--trials", trial, "--repo", str(repo)]) == 0
    capsys.readouterr()
    assert {n: (out / n).read_bytes() for n in step} == step
    # the same files as the real run, and the binding
    for suffix in (".clock_offsets.csv", ".clock_changes.csv"):
        assert (repo / "data" / "processed" / f"{trial}{suffix}").read_bytes() == (PROCESSED / f"{trial}{suffix}").read_bytes()
    _, body = read_csv(repo / "data" / "processed" / f"{trial}.clock_offsets.csv")
    assert {r["clock_changes_sha256"] for r in body} == {sha(repo / "data" / "processed" / f"{trial}.clock_changes.csv")}
    assert {r["clock_scan"] for r in body} == {"complete"}
    real_out = REPO / "out" / "clock_offset" / trial
    for n in step:
        if (real_out / n).exists():
            assert (real_out / n).read_bytes() == step[n], n
