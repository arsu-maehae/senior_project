"""Tests for T7.4 task 3: the writer side of the stitcher (`stitch.outputs`, `stitch.__main__`, `STITCH_OUT_REL`).
Fast, synthetic: a temp repo built with `stitch_fixtures.make_repo`; nothing real is opened.

Written from docs/specs/03_stitch.md (section 2 refusals and DB hash; section 3 location, rebuild, sort order, byte
identity, the column lists of links.csv / hop_artefacts.csv / hop_identity.csv; ST-01, ST-49, STT-01, STT-12, STT-13 as
amended by 049) and decisions 046 and 049 (items 3, 4, 6, 7 and "Output conventions (task 3)"), not from the
implementation (the code was read only for public names, signatures and the JSON key names of run_info.json).

The column lists are PARSED FROM THE SPEC TEXT, not copied from the code.

World (event times are seconds after 10:30:00 via `stitch_fixtures.at`; the window is 10:00-11:00):
- target ep-02 (192.168.50.22), source ep-01 (192.168.50.21), ep-03 (192.168.50.23) has no logs at all.
- five remote logons on ep-02, each its own hop (gaps far above 2 s):
  M1 at 100 s  Acct_A  ep-01  -> candidate sessions by 4648 + command line (session 5000, account direct), a second
                                 session 5200 (another account, command line only), and a Sysmon 3 on the member port
                                 whose process has no Sysmon 1 (an unresolved row); a share copy and a service install
  M2 at 600 s  Acct_B  ep-01  -> target_only (no_evidence_in_range); a session of Acct_B opened BEFORE the window and
                                 still open at the LSASS read (the look-back)
  M3 at 800 s  Acct_C  ep-03  -> target_only (source_host_no_logs)
  M4 at 900 s  Acct_D  blank  -> target_only (source_host_unknown)
  M5 at 1000 s EP01$   ep-01  -> machine account, target_only (no_evidence_in_range)
- an LSASS read (Sysmon 10 + gate R1 row) on ep-01 at 50 s.
- events outside the window (PREW-* before, OUTW-* after) that must appear nowhere, plus a session opened and closed
  before the window.
Command text is placeholder text only; messages carry uids and ids, never command text.
"""
from __future__ import annotations

import csv
import hashlib
import importlib
import json
import re
import sqlite3
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stitch_fixtures as sf  # noqa: E402
from gate.classify import ip_kind  # noqa: E402
from gate.timeutil import fmt_us, to_us  # noqa: E402
from stitch import outputs as out  # noqa: E402
from stitch import params as stitch_params  # noqa: E402
from stitch.errors import StitchError  # noqa: E402

sm = importlib.import_module("stitch.__main__")

SPEC = REPO / "docs" / "specs" / "03_stitch.md"
TRIAL = sf.TRIAL
SRC, TGT, THIRD = "ep-01", "ep-02", "ep-03"
SRC_IP, TGT_IP, THIRD_IP = "192.168.50.21", "192.168.50.22", "192.168.50.23"
FILES = ["hop_artefacts.csv", "hop_identity.csv", "hops.csv", "links.csv", "path_edges.csv", "path_nodes.csv",
         "paths.csv", "report.md", "run_info.json", "stats.json"]
CSV_FILES = ["hop_artefacts.csv", "hop_identity.csv", "links.csv"]
NEW_CSV_FILES = ["hops.csv", "paths.csv", "path_edges.csv", "path_nodes.csv"]
ALL_CSV_FILES = CSV_FILES + NEW_CSV_FILES
NON_TABLE_FILES = ["stats.json", "report.md"]
CMD_A = sf.PLACEHOLDER_COMMAND + " ep-02 payloadxq.exe tail-alpha"
CMD_B = sf.PLACEHOLDER_COMMAND + " ep-02 tail-bravo-no-names"
CMD_OUT = sf.PLACEHOLDER_COMMAND + " ep-02 tail-outside-window"
IMAGE_DUMP = "C:\\Tools\\ProbeReader.exe"
DUMP_ACCOUNT = "Dumper_Acct"

# uids outside the window (never in any file) and the look-back uids (only in hop_identity.csv, open_session_uids)
OUT_UIDS = ["OUTW-PROC", "OUTW-DUMP", "OUTW-SHARE", "OUTW-LOGON", "PREW-PROC", "PREW-SHARE", "PREW-DUMP",
            "PREW-CLOSED-OPEN", "PREW-CLOSED-END"]
LOOKBACK_UID = "PREW-OPEN-LOOKBACK"

MEMBERS = [
    dict(uid="M1", off=100.0, lid=7000, account="Acct_A", ip=SRC_IP, port=50000, machine=0),
    dict(uid="M2", off=600.0, lid=7100, account="Acct_B", ip=SRC_IP, port=50100, machine=0),
    dict(uid="M3", off=800.0, lid=7200, account="Acct_C", ip=THIRD_IP, port=50200, machine=0),
    dict(uid="M4", off=900.0, lid=7300, account="Acct_D", ip=None, port=50300, machine=0),
    dict(uid="M5", off=1000.0, lid=7400, account="EP01$", ip=SRC_IP, port=50400, machine=1),
]
SESSION_ACCOUNTS = {"L5000": "ACCT_A", "L5200": "other_user"}


# ================================================================================================ the world
def world_rows() -> tuple[list[dict], list[dict], list[dict]]:
    """(DB rows, trigger rows, supporting rows)."""
    ev = sf.ev
    rows: list[dict] = []
    for m in MEMBERS:
        rows.append(ev(m["uid"], "Security", 4624, host=TGT, off=m["off"], logon_type=3, target_logon_id=m["lid"],
                       account_name=m["account"], source_ip=m["ip"], source_port=m["port"],
                       authentication_package="NTLM", machine_account=m["machine"]))
    # ep-01: source sessions
    rows += [
        ev("L5000", "Security", 4624, host=SRC, off=0.0, logon_type=3, target_logon_id=5000,
           account_name=SESSION_ACCOUNTS["L5000"]),
        ev("L5200", "Security", 4624, host=SRC, off=1.0, logon_type=3, target_logon_id=5200,
           account_name=SESSION_ACCOUNTS["L5200"]),
        # a session of Acct_B opened before the window and never closed (the ST-63 look-back)
        ev(LOOKBACK_UID, "Security", 4624, host=SRC, off=-1900.0, logon_type=3, target_logon_id=5100,
           account_name="Acct_B"),
        # a session of Acct_B opened and closed before the window: not open at the dump
        ev("PREW-CLOSED-OPEN", "Security", 4624, host=SRC, off=-1950.0, logon_type=3, target_logon_id=5300,
           account_name="Acct_B"),
        ev("PREW-CLOSED-END", "Security", 4634, host=SRC, off=-1940.0, target_logon_id=5300),
    ]
    # ep-01: the LSASS read, the processes, the 4648 and the Sysmon 3
    rows += [
        ev("DUMP1", "Sysmon", 10, host=SRC, off=50.0, source_image=IMAGE_DUMP, account_name=DUMP_ACCOUNT),
        ev("S1", "Sysmon", 1, host=SRC, off=95.0, process_guid="{G1}", process_id=4101, session_id=5000,
           image="C:\\Tools\\Runner.exe", command_line=CMD_A),
        ev("S2", "Sysmon", 1, host=SRC, off=97.0, process_guid="{G2}", process_id=4102, session_id=5200,
           image="C:\\Tools\\Runner.exe", command_line=CMD_B),
        ev("F1", "Security", 4648, host=SRC, off=96.0, subject_logon_id=5000, account_name="Acct_A",
           subject_account="ACCT_A", destination_host=TGT, field_values_json=json.dumps({"TargetServerName": TGT})),
        ev("N1", "Sysmon", 3, host=SRC, off=100.2, process_guid="{GX}", initiated=1, source_ip=SRC_IP,
           source_port=50000, destination_ip=TGT_IP, destination_port=445),
    ]
    # ep-02: a copy and an install of the same binary, under the member's logon
    rows += [
        ev("B5145", "Security", 5145, host=TGT, off=100.1, subject_logon_id=7000, share_name="\\\\*\\ADMIN$",
           relative_target_name="Windows\\payloadxq.exe"),
        ev("I4697", "Security", 4697, host=TGT, off=100.6, subject_logon_id=7000, service_name="SyncSvcQ",
           service_image_path="C:\\Windows\\payloadxq.exe"),
        ev("I7045", "System", 7045, host=TGT, off=100.6, service_name="SyncSvcQ",
           service_image_path="C:\\Windows\\payloadxq.exe"),
    ]
    # outside the window: nothing of these may appear in any output file
    rows += [
        ev("PREW-PROC", "Sysmon", 1, host=SRC, off=-2000.0, process_guid="{GP}", process_id=4201, session_id=5000,
           image="C:\\Tools\\Runner.exe", command_line=CMD_OUT),
        ev("OUTW-PROC", "Sysmon", 1, host=SRC, off=2000.0, process_guid="{GO}", process_id=4202, session_id=5000,
           image="C:\\Tools\\Runner.exe", command_line=CMD_OUT),
        ev("PREW-SHARE", "Security", 5145, host=TGT, off=-2000.0, subject_logon_id=7000, share_name="\\\\*\\ADMIN$",
           relative_target_name="Windows\\prewindow.exe"),
        ev("OUTW-SHARE", "Security", 5145, host=TGT, off=2000.0, subject_logon_id=7000, share_name="\\\\*\\ADMIN$",
           relative_target_name="Windows\\afterwindow.exe"),
        ev("PREW-DUMP", "Sysmon", 10, host=SRC, off=-1900.0, source_image=IMAGE_DUMP, account_name=DUMP_ACCOUNT),
        ev("OUTW-DUMP", "Sysmon", 10, host=SRC, off=2000.0, source_image=IMAGE_DUMP, account_name=DUMP_ACCOUNT),
        ev("OUTW-LOGON", "Security", 4624, host=TGT, off=2000.0, logon_type=3, target_logon_id=7900,
           account_name="Acct_Z", source_ip=SRC_IP, source_port=50900, authentication_package="NTLM"),
    ]
    trig = []
    for m in MEMBERS:
        trig.append({"trigger_id": f"t-{m['uid']}", "host": TGT, "anchor_logon_uid": m["uid"],
                     "trigger_event_uid": m["uid"], "target_logon_id": str(m["lid"]), "source_ip": m["ip"] or "",
                     "ip_kind": "blank" if m["ip"] is None else ip_kind(m["ip"]), "machine_account": str(m["machine"]),
                     "clock_unreliable": "0", "rule": "R4_smb", "gate_tier": "A", "supporting_event_uids": ""})
    dump_us = to_us(sf.at(50.0))
    sup = [{"event_uid": "DUMP1", "rule": "R1_lsass", "host": SRC, "event_utc_corrected": fmt_us(dump_us),
            "account_name": DUMP_ACCOUNT}]
    return rows, trig, sup


def write_gate_csv(path: Path, rows: list[dict], header: list[str]) -> None:
    fields = list(header)
    for r in rows:
        fields += [k for k in r if k not in fields]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def build_repo(tmp_path: Path, name: str = "repo", **kw):
    rows, trig, sup = world_rows()
    fake = sf.make_repo(tmp_path, rows, name=name, **kw)
    gdir = fake.paths.gate_dir
    if (gdir / "triggers.csv").exists():
        write_gate_csv(gdir / "triggers.csv", trig, ["event_uid"])
    if (gdir / "supporting.csv").exists():
        write_gate_csv(gdir / "supporting.csv", sup, ["event_uid"])
    return fake


def run_main(fake, trial: str | None = None) -> int:
    return sm.main(["--trial", trial or fake.trial, "--repo", str(fake.repo)])


def out_folder(fake) -> Path:
    return fake.repo / "out" / "stitch" / fake.trial


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def header_of(path: Path) -> list[str]:
    with open(path, newline="", encoding="utf-8") as fh:
        return next(csv.reader(fh))


def link_num(link_id: str) -> int:
    return int(link_id.rsplit("-l", 1)[1])


@pytest.fixture(scope="module")
def ran(tmp_path_factory):
    """One successful run on the synthetic repo, shared by the read-only tests."""
    root = tmp_path_factory.mktemp("stitch_outputs")
    fake = build_repo(root)
    db_before = sf.sha256_of(fake.paths.db)
    code = run_main(fake)
    folder = out_folder(fake)
    tables = {n: read_csv(folder / n) for n in ALL_CSV_FILES} if folder.exists() else {}
    return {"fake": fake, "code": code, "folder": folder, "db_before": db_before,
            "db_after": sf.sha256_of(fake.paths.db), "tables": tables}


def hop_order(tables) -> list[str]:
    """Hop ids in time order (hop ids are numbered in time order, spec 3) = M1..M5."""
    ids = sorted({r["hop_id"] for r in tables["links.csv"]})
    return ids


def db_command_lines(db: Path) -> list[str]:
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        return [r[0] for r in con.execute("SELECT command_line FROM events_dedup WHERE command_line IS NOT NULL")]
    finally:
        con.close()


def db_value(db: Path, uid: str, column: str):
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        rows = con.execute(f"SELECT {column} FROM events_dedup WHERE event_uid = ?", (uid,)).fetchall()
    finally:
        con.close()
    assert len(rows) == 1, f"{uid}: {len(rows)} DB rows"
    return rows[0][0]


# ================================================================================================ spec parsing
def spec_text() -> str:
    return SPEC.read_text(encoding="utf-8")


def spec_links_columns() -> list[str]:
    lines = spec_text().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("**`links.csv`**"))
    cols: list[str] = []
    started = False
    for line in lines[start + 1:]:
        if not line.startswith("|"):
            if started:
                break
            continue
        first = line.split("|")[1].strip()
        if first.startswith("Column") or set(first) <= set("-: "):
            continue
        started = True
        cols += [c.strip().strip("`") for c in first.split(",")]
    return cols


def spec_artefact_columns() -> list[str]:
    lines = spec_text().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("**`hop_artefacts.csv`**"))
    block: list[str] = []
    for line in lines[start:]:
        if not line.strip():
            break
        block.append(line)
    text = " ".join(block)
    text = re.sub(r"\([^()]*\)", " ", text)          # drop every parenthetical (value lists, notes)
    text = text[text.index("`hop_id"):]
    return re.findall(r"[a-z][a-z_0-9]*", text)


def spec_identity_columns() -> list[str]:
    m = re.search(r"`(hop_id, account,[^`]*)`", spec_text())
    assert m, "hop_identity.csv column list not found in the spec"
    return re.findall(r"[a-z][a-z_0-9]*", m.group(1))


# ================================================================================================ 1. contract: columns
def test_spec_parsing_found_plausible_lists():
    assert len(spec_links_columns()) == 30 and spec_links_columns()[0] == "link_id"
    assert spec_artefact_columns()[0] == "hop_id" and spec_artefact_columns()[-1] == "untied_same_name_bursts"
    assert spec_identity_columns()[-1] == "clock_unreliable"


def test_links_columns_equal_the_spec_list():
    assert list(out.LINKS_COLUMNS) == spec_links_columns()


def test_artefact_columns_equal_the_spec_list():
    assert list(out.ARTEFACT_COLUMNS) == spec_artefact_columns()


def test_identity_columns_equal_the_spec_list():
    assert list(out.IDENTITY_COLUMNS) == spec_identity_columns()


def test_column_tuples_have_no_duplicates():
    for cols in (out.LINKS_COLUMNS, out.ARTEFACT_COLUMNS, out.IDENTITY_COLUMNS):
        assert len(set(cols)) == len(cols)


def test_stitch_out_rel_is_out_stitch():
    assert stitch_params.STITCH_OUT_REL == "out/stitch"


# ================================================================================================ csv_text, link_id
def test_csv_text_header_rows_and_line_ends():
    text = out.csv_text(("a", "b"), [{"a": "1", "b": "x,y"}, {"b": "", "a": "2"}])
    assert text == 'a,b\n1,"x,y"\n2,\n'
    assert "\r" not in text


def test_csv_text_with_no_rows_is_the_header_only():
    assert out.csv_text(("a", "b"), []) == "a,b\n"


def test_csv_text_is_deterministic_and_follows_column_order_not_dict_order():
    rows = [{"b": "2", "a": "1"}]
    assert out.csv_text(("a", "b"), rows) == out.csv_text(("a", "b"), [{"a": "1", "b": "2"}]) == "a,b\n1,2\n"


@pytest.mark.parametrize("row", [{"a": "1"}, {"a": "1", "b": "2", "c": "3"}, {"a": "1", "c": "3"}])
def test_csv_text_refuses_a_key_mismatch(row):
    with pytest.raises(ValueError):
        out.csv_text(("a", "b"), [row])


@pytest.mark.parametrize("value", [1, None, 1.5, ["x"], True])
def test_csv_text_refuses_a_non_str_value(value):
    with pytest.raises(ValueError):
        out.csv_text(("a", "b"), [{"a": "1", "b": value}])


def test_link_id_format():
    assert out.link_id("s04_t00-h0001", 1) == "s04_t00-h0001-l01"
    assert out.link_id("s04_t00-h0001", 9) == "s04_t00-h0001-l09"
    assert out.link_id("s04_t00-h0001", 12) == "s04_t00-h0001-l12"
    assert out.link_id("h", 99) == "h-l99" and out.link_id("h", 100) == "h-l100"


# ================================================================================================ 2. end to end
def test_run_exits_zero_and_writes_exactly_the_ten_files(ran):
    assert ran["code"] == 0
    names = sorted(p.name for p in ran["folder"].iterdir())
    assert names == FILES, names
    assert not [p for p in ran["fake"].repo.rglob("*") if p.name.endswith((".tmp", ".old"))]
    parent = ran["folder"].parent
    assert sorted(p.name for p in parent.iterdir()) == [TRIAL]            # no leftover sibling folder


def test_all_ten_files_exist_and_run_info_lists_the_nine_others_with_sha256(ran):
    folder = ran["folder"]
    for n in FILES:
        assert (folder / n).is_file(), n
    info = json.loads((folder / "run_info.json").read_text(encoding="utf-8"))
    others = sorted(n for n in FILES if n != "run_info.json")
    assert len(others) == 9
    assert sorted(info["files"]) == others
    for n in others:
        raw = (folder / n).read_bytes()
        assert info["files"][n]["sha256"] == hashlib.sha256(raw).hexdigest(), n
        if n in NON_TABLE_FILES:
            assert info["files"][n]["rows"] is None, n                      # json / md are not tables
        else:
            assert info["files"][n]["rows"] == len(ran["tables"][n]), n


def test_csv_headers_equal_the_spec_lists(ran):
    f = ran["folder"]
    assert header_of(f / "links.csv") == spec_links_columns()
    assert header_of(f / "hop_artefacts.csv") == spec_artefact_columns()
    assert header_of(f / "hop_identity.csv") == spec_identity_columns()


def test_csv_files_use_unix_line_ends_and_end_with_a_newline(ran):
    for n in CSV_FILES + ["run_info.json"]:
        raw = (ran["folder"] / n).read_bytes()
        assert raw.endswith(b"\n") and b"\r" not in raw, n


def test_db_sha_unchanged_by_the_run(ran):
    assert ran["db_before"] == ran["db_after"]


def test_run_info_records_the_db_hash_and_every_file_hash(ran):
    info = json.loads((ran["folder"] / "run_info.json").read_text(encoding="utf-8"))
    assert info["db"]["sha256_before"] == info["db"]["sha256_after"] == ran["db_before"]
    assert info["trial_id"] == TRIAL
    for n in CSV_FILES:
        raw = (ran["folder"] / n).read_bytes()
        assert info["files"][n]["sha256"] == hashlib.sha256(raw).hexdigest(), n
        assert info["files"][n]["rows"] == len(ran["tables"][n]), n
    assert "run_info.json" not in info["files"] or info["files"]["run_info.json"] is not None


def test_two_runs_give_byte_identical_csv_files(tmp_path):
    fake = build_repo(tmp_path)
    assert run_main(fake) == 0
    first = {n: (out_folder(fake) / n).read_bytes() for n in CSV_FILES}
    assert run_main(fake) == 0
    second = {n: (out_folder(fake) / n).read_bytes() for n in CSV_FILES}
    assert first == second
    assert all(len(v) > 10 for v in first.values())
    assert sorted(p.name for p in out_folder(fake).iterdir()) == FILES


def test_folder_is_rebuilt_on_every_run_a_stale_file_does_not_survive(tmp_path):
    fake = build_repo(tmp_path)
    folder = out_folder(fake)
    folder.mkdir(parents=True)
    (folder / "stale_sentinel.txt").write_text("old", encoding="utf-8")
    (folder / "links.csv").write_text("junk\n", encoding="utf-8")
    assert run_main(fake) == 0
    assert sorted(p.name for p in folder.iterdir()) == FILES
    assert header_of(folder / "links.csv") == spec_links_columns()


def test_no_row_lost_every_hop_is_in_links_and_identity(ran):
    t = ran["tables"]
    hops = hop_order(t)
    assert len(hops) == len(MEMBERS) == 5
    assert all(re.fullmatch(rf"{TRIAL}-h\d{{4}}", h) for h in hops)
    assert {r["hop_id"] for r in t["hop_identity.csv"]} == set(hops)
    assert {r["hop_id"] for r in t["hop_artefacts.csv"]} <= set(hops)
    # no duplicated link rows
    ids = [r["link_id"] for r in t["links.csv"]]
    assert len(ids) == len(set(ids))


# ================================================================================================ links.csv
def hop_rows(ran, i: int) -> list[dict[str, str]]:
    h = hop_order(ran["tables"])[i]
    return sorted((r for r in ran["tables"]["links.csv"] if r["hop_id"] == h), key=lambda r: link_num(r["link_id"]))


def test_links_are_sorted_by_hop_then_link_number(ran):
    rows = ran["tables"]["links.csv"]
    keys = [(r["hop_id"], link_num(r["link_id"])) for r in rows]
    assert keys == sorted(keys)


def test_link_ids_are_hop_id_dash_l_number_from_one_without_gaps(ran):
    for i in range(len(MEMBERS)):
        rows = hop_rows(ran, i)
        hop = rows[0]["hop_id"]
        assert [r["link_id"] for r in rows] == [f"{hop}-l{n:02d}" for n in range(1, len(rows) + 1)]
        assert all(r["hop_id"] == hop for r in rows)


def test_hop_with_candidates_numbers_sessions_by_rank_then_unresolved_rows(ran):
    rows = hop_rows(ran, 0)
    got = [(r["source_session_id"], r["method"]) for r in rows]
    assert got == [("5000", "source_4648"), ("5000", "cmdline_target"), ("5200", "cmdline_target"),
                   ("", "sysmon3_port")], got
    assert [r["link_rank"] for r in rows] == ["1", "1", "2", ""]


def test_session_rows_repeat_one_value_per_session_and_carry_tier_and_account_match(ran):
    rows = hop_rows(ran, 0)
    s5000, s5200, unresolved = rows[:2], rows[2], rows[3]
    for r in s5000:
        assert (r["confidence_tier"], r["account_match"], r["name_check"], r["rank_basis"]) == (
            "B", "direct", "match", "tier"), r["link_id"]
        assert r["tie"] == "0" and r["source_host"] == SRC
        assert set(r["session_methods"].split(";")) == {"source_4648", "cmdline_target"}
        assert r["source_session_logon_uid"] == "L5000"
    assert (s5200["confidence_tier"], s5200["account_match"], s5200["name_check"]) == ("D", "none", "no_match")
    assert s5200["rank_basis"] == "tier" and s5200["tie"] == "0"
    assert s5200["session_methods"] == "cmdline_target"
    # the session facts of one session are the same on all its rows
    for col in ("account_match", "account_match_members", "account_match_member_count", "name_check", "link_rank",
                "tie", "rank_basis", "confidence_tier", "source_session_account", "candidate_count_all",
                "candidate_count_account"):
        assert s5000[0][col] == s5000[1][col], col
    assert s5000[0]["candidate_count_all"] == "2"
    assert s5000[0]["candidate_count_account"] == "1"
    assert unresolved["method"] == "sysmon3_port"


def test_name_check_names_are_target_side_names_with_their_command_events(ran):
    r = hop_rows(ran, 0)[0]
    assert r["name_check"] == "match"
    assert [n.lower() for n in r["name_check_names"].split(";") if n] and "payloadxq.exe" in r["name_check_names"].lower()
    assert set(r["name_check_event_uids"].split(";")) == {"S1"}


def test_unresolved_process_row_has_tier_d_no_session_and_a_reason(ran):
    r = hop_rows(ran, 0)[3]
    assert r["session_unresolved_reason"] in {"no_sysmon1_in_window", "system_process", "no_session_id"}
    assert r["source_session_id"] == "" and r["source_session_id_hex"] == ""
    assert (r["confidence_tier"], r["account_match"], r["account_match_member_count"]) == ("D", "none", "0")
    assert (r["link_rank"], r["tie"], r["rank_basis"]) == ("", "0", "no_session")
    assert r["target_only_reason"] == ""


def test_source_session_id_decimal_and_hex_are_the_same_value(ran):
    seen = 0
    for r in ran["tables"]["links.csv"]:
        if r["source_session_id"]:
            assert re.fullmatch(r"\d+", r["source_session_id"]), r["link_id"]
            assert re.fullmatch(r"0x[0-9a-fA-F]+", r["source_session_id_hex"]), r["link_id"]
            assert int(r["source_session_id_hex"], 16) == int(r["source_session_id"])
            seen += 1
        else:
            assert r["source_session_id_hex"] == "", r["link_id"]
    assert seen == 3
    assert {r["source_session_id_hex"] for r in hop_rows(ran, 0) if r["source_session_id"] == "5000"} == {"0x1388"}


@pytest.mark.parametrize("i,reason", [(1, "no_evidence_in_range"), (2, "source_host_no_logs"),
                                      (3, "source_host_unknown"), (4, "no_evidence_in_range")])
def test_target_only_row_st49(ran, i, reason):
    rows = hop_rows(ran, i)
    assert len(rows) == 1
    r = rows[0]
    assert r["link_id"] == f"{r['hop_id']}-l01"
    assert r["method"] == "target_only"
    assert r["confidence_tier"] == "D"
    assert r["account_match"] == "none"
    assert r["candidate_count"] == "0"
    assert r["link_rank"] == ""
    assert r["rank_basis"] == "target_only"
    assert r["target_only_reason"] == reason
    assert r["tie"] == "0"
    assert r["source_session_id"] == "" and r["source_session_id_hex"] == ""
    assert r["time_delta_ms"] == "" and r["time_delta_raw_ms"] == ""


def test_target_only_row_is_last_of_its_hop_and_only_target_only_rows_have_a_reason(ran):
    for i in range(len(MEMBERS)):
        rows = hop_rows(ran, i)
        kinds = [r["method"] == "target_only" for r in rows]
        assert kinds == sorted(kinds), rows[0]["hop_id"]                 # target_only never before another row
        for r in rows:
            assert (r["target_only_reason"] != "") == (r["method"] == "target_only"), r["link_id"]


def test_confidence_tier_is_only_a_b_c_d_and_method_vocabulary_is_the_spec_one(ran):
    for r in ran["tables"]["links.csv"]:
        assert r["confidence_tier"] in {"A", "B", "C", "D"}, r["link_id"]
        assert r["method"] in {"sysmon3_port", "source_4648", "cmdline_target", "target_only"}, r["link_id"]
        assert r["account_match"] in {"direct", "4648", "none"}
        assert r["name_check"] in {"match", "no_match", "no_names"}


def test_every_cell_is_text_free_of_python_artefacts(ran):
    for n in CSV_FILES:
        for r in ran["tables"][n]:
            for k, v in r.items():
                assert v is not None and "None" not in v.split(";"), (n, k)
                assert not re.search(r"\[|\]|\(|\)|Decimal|datetime", v) or k in {"names", "name_check_names"}, (n, k)


# ================================================================================================ hop_artefacts.csv
def test_artefact_rows_carry_the_copy_and_the_install_with_target_side_names(ran):
    rows = [r for r in ran["tables"]["hop_artefacts.csv"] if r["hop_id"] == hop_order(ran["tables"])[0]]
    kinds = {r["kind"] for r in rows}
    assert {"share_burst", "service_install"} <= kinds, kinds
    burst = next(r for r in rows if r["kind"] == "share_burst")
    install = next(r for r in rows if r["kind"] == "service_install")
    assert "payloadxq.exe" in burst["names"].lower()
    assert "syncsvcq" in install["names"].lower() and "payloadxq.exe" in install["names"].lower()
    for r in rows:
        assert r["method"] in {"logon_id", "file_name_time", "ip_time", "port_reuse"}
        assert r["confidence_tier"] in {"A", "B", "C", "D"}
        assert r["kind"] in {"share_burst", "service_install", "winrm_host", "winrm_91", "rdp_connection",
                             "followup_logon"}
    assert "I4697" in install["event_uids"].split(";") and "I7045" in install["event_uids"].split(";")
    assert "B5145" in burst["event_uids"].split(";")


# ================================================================================================ hop_identity.csv
def identity_rows(ran, i: int) -> list[dict[str, str]]:
    h = hop_order(ran["tables"])[i]
    return [r for r in ran["tables"]["hop_identity.csv"] if r["hop_id"] == h]


def test_target_only_hop_still_has_identity_rows(ran):
    r = identity_rows(ran, 1)                                   # M2: target_only, source ep-01 with a read
    assert len(r) == 1
    assert (r[0]["account"], r[0]["source_host"], r[0]["dump_event_uid"]) == ("Acct_B", SRC, "DUMP1")
    assert r[0]["not_applicable"] == ""
    assert hop_rows(ran, 1)[0]["method"] == "target_only"


def test_identity_row_of_a_candidate_hop(ran):
    (r,) = identity_rows(ran, 0)
    assert (r["account"], r["source_host"], r["dump_event_uid"]) == ("Acct_A", SRC, "DUMP1")
    assert r["dump_source_image"] == IMAGE_DUMP and r["dump_account"] == DUMP_ACCOUNT
    assert r["gap_ms"] == "50000"
    assert r["order_ok"] == "1" and r["order_within_tolerance"] == "0"
    assert r["open_session_uids"] == "L5000" and r["open_session_types"] == "3"
    assert r["session_open_before_window"] == "0" and r["end_unknown_session_uids"] == ""
    assert r["not_applicable"] == ""


def test_identity_times_are_formatted_like_the_gates_corrected_times(ran):
    gate_text = (ran["fake"].paths.gate_dir / "supporting.csv").read_text(encoding="utf-8")
    gate_time = read_csv(ran["fake"].paths.gate_dir / "supporting.csv")[0]["event_utc_corrected"]
    assert gate_time in gate_text
    shape = re.sub(r"\d", "9", gate_time)
    (r0,) = identity_rows(ran, 0)
    assert r0["dump_utc_corrected"] == gate_time
    assert r0["move_utc_corrected"] == fmt_us(to_us(sf.at(100.0)))
    assert re.sub(r"\d", "9", r0["move_utc_corrected"]) == shape
    (r1,) = identity_rows(ran, 1)
    assert r1["move_utc_corrected"] == fmt_us(to_us(sf.at(600.0)))


@pytest.mark.parametrize("i,na", [(2, "source_host_no_logs"), (3, "source_host_unknown"), (4, "machine_account")])
def test_not_applicable_rows_are_single_with_empty_dump_columns(ran, i, na):
    rows = identity_rows(ran, i)
    assert len(rows) == 1
    assert rows[0]["not_applicable"] == na
    assert rows[0]["dump_event_uid"] == "" and rows[0]["dump_utc_corrected"] == ""
    assert rows[0]["open_session_uids"] == ""


def test_not_applicable_values_come_only_from_the_spec_set(ran):
    allowed = {"", "source_host_unknown", "source_host_no_logs", "machine_account"}
    got = {r["not_applicable"] for r in ran["tables"]["hop_identity.csv"]}
    assert got <= allowed
    assert got == allowed                                        # the world exercises all four


def test_lookback_session_is_listed_and_flagged(ran):
    (r,) = identity_rows(ran, 1)
    assert r["open_session_uids"] == LOOKBACK_UID
    assert r["session_open_before_window"] == "1"
    assert r["gap_ms"] == "550000"


def test_session_opened_and_closed_before_the_window_is_not_open(ran):
    (r,) = identity_rows(ran, 1)
    assert "PREW-CLOSED-OPEN" not in r["open_session_uids"].split(";")


def test_flags_in_identity_rows_are_zero_one_or_empty(ran):
    for r in ran["tables"]["hop_identity.csv"]:
        for col in ("order_ok", "order_within_tolerance", "order_within_uncertainty", "session_open_before_window",
                    "clock_unreliable"):
            assert r[col] in {"0", "1", ""}, (r["hop_id"], col)


# ================================================================================================ STT-12
def all_text(ran) -> dict[str, str]:
    return {n: (ran["folder"] / n).read_text(encoding="utf-8") for n in FILES}


@pytest.mark.parametrize("uid", OUT_UIDS)
def test_outside_window_event_uid_is_in_no_file(ran, uid):
    for n, text in all_text(ran).items():
        assert uid not in text, f"{uid} found in {n}"


def test_lookback_uid_appears_only_in_identity_open_or_end_unknown_columns(ran):
    texts = all_text(ran)
    for n in FILES:
        if n != "hop_identity.csv":
            assert LOOKBACK_UID not in texts[n], n
    assert LOOKBACK_UID in texts["hop_identity.csv"]
    for r in ran["tables"]["hop_identity.csv"]:
        for col, v in r.items():
            if LOOKBACK_UID in v:
                assert col in {"open_session_uids", "end_unknown_session_uids"}, col


def test_outside_window_commands_and_names_do_not_appear(ran):
    for n, text in all_text(ran).items():
        assert "prewindow.exe" not in text.lower() and "afterwindow.exe" not in text.lower(), n
        assert "tail-outside-window" not in text, n


def test_outside_window_events_change_no_row_count(tmp_path, ran):
    """Removing every out-of-window event except the look-back session leaves links.csv and hop_artefacts.csv equal."""
    rows, trig, sup = world_rows()
    keep = [r for r in rows if r["event_uid"] not in OUT_UIDS]
    fake = sf.make_repo(tmp_path, keep, name="trimmed")
    write_gate_csv(fake.paths.gate_dir / "triggers.csv", trig, ["event_uid"])
    write_gate_csv(fake.paths.gate_dir / "supporting.csv", sup, ["event_uid"])
    assert run_main(fake) == 0
    for n in ("links.csv", "hop_artefacts.csv", "hop_identity.csv"):
        assert (out_folder(fake) / n).read_bytes() == (ran["folder"] / n).read_bytes(), n


# ================================================================================================ STT-13
BLANKED = ("dump_source_image", "dump_account", "account", "source_session_account")
NAME_COLUMNS = ("names", "name_check_names")


def target_side_names(db: Path) -> set[str]:
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        names: set[str] = set()
        for (rel,) in con.execute("SELECT relative_target_name FROM events_dedup WHERE event_id = 5145 "
                                  "AND relative_target_name IS NOT NULL"):
            names.add(re.split(r"[\\/]", rel)[-1].lower())
        for svc, img in con.execute("SELECT service_name, service_image_path FROM events_dedup "
                                    "WHERE event_id IN (4697, 7045)"):
            if svc:
                names.add(svc.lower())
            if img:
                names.add(re.split(r"[\\/]", img)[-1].lower())
        return names
    finally:
        con.close()


def scan_text(ran) -> str:
    """All CSV text with the four image / account columns and the target-side name cells blanked."""
    parts: list[str] = []
    names: list[str] = []
    for n in CSV_FILES:
        for r in ran["tables"][n]:
            for k, v in r.items():
                if k in BLANKED:
                    continue
                if k in NAME_COLUMNS:
                    names += [x for x in v.split(";") if x]
                    continue
                parts.append(v)
    parts.append((ran["folder"] / "run_info.json").read_text(encoding="utf-8"))
    text = "\n".join(parts)
    for nm in sorted(set(names), key=len, reverse=True):
        text = re.sub(re.escape(nm), "", text, flags=re.IGNORECASE)
    return text


def test_no_twelve_character_substring_of_any_command_line_in_any_file(ran):
    commands = db_command_lines(ran["fake"].paths.db)
    assert len(commands) >= 4
    text = scan_text(ran).casefold()
    hits = []
    for c in commands:
        c = c.casefold()
        for i in range(len(c) - 11):
            if c[i:i + 12] in text:
                hits.append(c[i:i + 12])
    assert hits == [], f"{len(hits)} command substring(s) of 12 characters in the output (count only)"


def test_the_scan_is_not_vacuous_a_command_name_is_in_the_output_cells(ran):
    cells = " ".join(r["names"] for r in ran["tables"]["hop_artefacts.csv"]).lower()
    assert "payloadxq.exe" in cells                          # the name allowance is really exercised
    assert "payloadxq.exe" in CMD_A


def test_name_cells_hold_only_target_side_names(ran):
    allowed = target_side_names(ran["fake"].paths.db)
    seen = set()
    for n in CSV_FILES:
        for r in ran["tables"][n]:
            for col in NAME_COLUMNS:
                for nm in (r.get(col) or "").split(";"):
                    if nm:
                        seen.add(nm.lower())
                        assert nm.lower() in allowed, f"{n}.{col}: {nm!r} is not a target-side name"
    assert seen


def test_image_and_account_columns_equal_the_db_fields_of_their_referenced_events(ran):
    db = ran["fake"].paths.db
    t = ran["tables"]
    sup = {r["event_uid"]: r for r in read_csv(ran["fake"].paths.gate_dir / "supporting.csv")}
    checked = {"dump": 0, "account": 0, "session": 0}
    hops = hop_order(t)
    first_member = {h: MEMBERS[i]["uid"] for i, h in enumerate(hops)}
    for r in t["hop_identity.csv"]:
        assert r["account"] == db_value(db, first_member[r["hop_id"]], "account_name"), r["hop_id"]
        checked["account"] += 1
        if r["dump_event_uid"]:
            assert r["dump_source_image"] == db_value(db, r["dump_event_uid"], "source_image")
            assert r["dump_account"] == sup[r["dump_event_uid"]]["account_name"]
            checked["dump"] += 1
        else:
            assert r["dump_source_image"] == "" and r["dump_account"] == ""
    for r in t["links.csv"]:
        if r["source_session_logon_uid"]:
            for uid in r["source_session_logon_uid"].split(";"):
                assert r["source_session_account"] == db_value(db, uid, "account_name"), r["link_id"]
            checked["session"] += 1
        else:
            assert r["source_session_account"] == "", r["link_id"]
    assert all(v > 0 for v in checked.values()), checked


def test_credential_account_of_a_4648_is_not_the_session_account(ran):
    """The 4648 credential account (Acct_A) differs in case from the session's own 4624 account (ACCT_A); the
    column must carry the 4624 field (STT-13, 049 item 7)."""
    rows = [r for r in hop_rows(ran, 0) if r["source_session_id"] == "5000"]
    assert {r["source_session_account"] for r in rows} == {"ACCT_A"}


def test_stitch_sources_contain_no_ground_truth_path():
    files = sorted((REPO / "src" / "stitch").glob("*.py"))
    assert files
    assert [f.name for f in files if "ground_truth" in f.read_text(encoding="utf-8")] == []


# ================================================================================================ refusals (STT-01)
@pytest.mark.parametrize("trial", ["s02_t02", "s01_t01", "s07_t05", "s04_t10"])
def test_trial_outside_the_allowlist_is_refused_before_any_file_access(tmp_path, capsys, trial):
    nowhere = tmp_path / "does_not_exist"
    assert sm.main(["--trial", trial, "--repo", str(nowhere)]) == 2
    assert not nowhere.exists()
    assert capsys.readouterr().err.startswith("refused:")


def test_trial_outside_the_allowlist_writes_nothing_in_a_real_looking_repo(tmp_path):
    fake = build_repo(tmp_path)
    before = sf.snapshot(fake.repo)
    assert sm.main(["--trial", "s02_t02", "--repo", str(fake.repo)]) == 2
    assert sf.snapshot(fake.repo) == before
    assert not (fake.repo / "out" / "stitch").exists()


def test_missing_gate_file_is_refused_with_nothing_written(tmp_path, capsys):
    fake = build_repo(tmp_path, skip_gate_file="supporting.csv")
    before = sf.snapshot(fake.repo)
    assert run_main(fake) == 2
    assert sf.snapshot(fake.repo) == before
    assert not (fake.repo / "out" / "stitch").exists()
    assert capsys.readouterr().err.startswith("refused:")


@pytest.mark.parametrize("kw", [
    {"skip_gate_file": "triggers.csv"},
    {"skip_gate_file": "unmatched_remote.csv"},
    {"skip_gate_file": "dispositions.csv"},
    {"skip_gate_file": "stats.json"},
    {"time_basis": "raw"},
    {"stats_db_sha_after": "0" * 64},
    {"stats_offsets_sha": "0" * 64},
    {"stats_changes_sha": "0" * 64},
    {"stats_window_changes": {"end_utc": "2026-09-24T11:30:00.000Z"}},
], ids=lambda kw: next(iter(kw)) + "=" + str(next(iter(kw.values())))[:12])
def test_each_section_2_refusal_exits_2_and_writes_nothing(tmp_path, kw):
    fake = build_repo(tmp_path, **kw)
    before = sf.snapshot(fake.repo)
    assert run_main(fake) == 2
    assert sf.snapshot(fake.repo) == before
    assert not (fake.repo / "out" / "stitch").exists()


def test_db_changed_after_the_gate_is_refused(tmp_path):
    fake = build_repo(tmp_path)
    con = sqlite3.connect(str(fake.paths.db))
    con.execute("DELETE FROM events_dedup WHERE event_uid = 'F1'")
    con.commit()
    con.close()
    before = sf.snapshot(fake.repo)
    assert run_main(fake) == 2
    assert sf.snapshot(fake.repo) == before
    assert not (fake.repo / "out" / "stitch").exists()


def test_refused_run_leaves_an_existing_output_folder_untouched(tmp_path):
    fake = build_repo(tmp_path, stats_db_sha_after="0" * 64)
    folder = out_folder(fake)
    folder.mkdir(parents=True)
    (folder / "sentinel.txt").write_text("keep me", encoding="utf-8")
    (folder / "links.csv").write_text("old,content\n", encoding="utf-8")
    before = sf.snapshot(folder)
    assert run_main(fake) == 2
    assert sf.snapshot(folder) == before
    assert sorted(p.name for p in folder.parent.iterdir()) == [TRIAL]


def test_allowlist_refusal_leaves_an_existing_output_folder_untouched(tmp_path):
    fake = build_repo(tmp_path)
    folder = fake.repo / "out" / "stitch" / "s02_t02"
    folder.mkdir(parents=True)
    (folder / "sentinel.txt").write_text("keep me", encoding="utf-8")
    before = sf.snapshot(fake.repo / "out")
    assert sm.main(["--trial", "s02_t02", "--repo", str(fake.repo)]) == 2
    assert sf.snapshot(fake.repo / "out") == before


def test_check_db_unchanged_raises_on_a_difference_and_not_on_equal():
    with pytest.raises(StitchError):
        sm.check_db_unchanged("a", "b")
    assert sm.check_db_unchanged("a", "a") is None
    assert sm.check_db_unchanged("0" * 64, "0" * 64) is None


def test_main_refuses_when_the_db_hash_differs_after_the_run(tmp_path, monkeypatch, capsys):
    fake = build_repo(tmp_path)
    real = sm.run_links_checked

    def fake_run(repo, trial, params=None, *a, **k):
        li, checked, paths, _b, _a = real(repo, trial, params) if params is not None else real(repo, trial)
        return li, checked, paths, "0" * 64, "1" * 64

    monkeypatch.setattr(sm, "run_links_checked", fake_run)
    before = sf.snapshot(fake.repo)
    assert run_main(fake) == 2
    assert sf.snapshot(fake.repo) == before
    assert not (fake.repo / "out" / "stitch").exists()
    assert capsys.readouterr().err.startswith("refused:")


def test_db_hash_mismatch_refusal_also_keeps_an_existing_folder(tmp_path, monkeypatch):
    fake = build_repo(tmp_path)
    assert run_main(fake) == 0
    folder = out_folder(fake)
    (folder / "extra_marker.txt").write_text("x", encoding="utf-8")
    real = sm.run_links_checked

    def fake_run(repo, trial, params=None, *a, **k):
        li, checked, paths, _b, _a = real(repo, trial, params) if params is not None else real(repo, trial)
        return li, checked, paths, "0" * 64, "1" * 64

    monkeypatch.setattr(sm, "run_links_checked", fake_run)
    before = sf.snapshot(folder)
    assert run_main(fake) == 2
    assert sf.snapshot(folder) == before
    assert (folder / "extra_marker.txt").exists()


def test_main_requires_a_trial_argument():
    with pytest.raises(SystemExit):
        sm.main([])


# ================================================================================================ T7.5 files (task 4)
def spec_table_columns(heading: str) -> list[str]:
    """Columns of the spec section 3 table that follows the line starting with `heading` (first cell of each row,
    split on commas). Parsed from the spec text, not copied from the code."""
    lines = spec_text().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith(heading))
    cols: list[str] = []
    started = False
    for line in lines[start + 1:]:
        if not line.startswith("|"):
            if started:
                break
            continue
        first = line.split("|")[1].strip()
        if first.startswith("Column") or set(first) <= set("-: "):
            continue
        started = True
        cols += [c.strip().strip("`") for c in first.split(",")]
    return cols


def _paths_nodes_edges_block() -> str:
    lines = spec_text().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("**`paths.csv`**, **`path_edges.csv`**"))
    block: list[str] = []
    for line in lines[start + 1:]:
        if not line.strip():
            break
        block.append(line)
    return " ".join(block)


def _backtick_columns(text: str) -> list[str]:
    text = re.sub(r"\([^()]*\)", " ", text)               # drop every parenthetical (value lists, notes)
    cols: list[str] = []
    for seg in re.findall(r"`([^`]*)`", text):
        cols += [c.strip() for c in seg.split(",") if c.strip()]
    return cols


def spec_paths_columns() -> list[str]:
    block = _paths_nodes_edges_block()
    part = block.split("`path_edges.csv`:")[0].split("`paths.csv`:")[1]
    return _backtick_columns(part)


def spec_edges_columns() -> list[str]:
    block = _paths_nodes_edges_block()
    part = block.split("`path_edges.csv`:")[1].split("`path_nodes.csv`:")[0]
    return _backtick_columns(part)


def spec_nodes_columns() -> list[str]:
    block = _paths_nodes_edges_block()
    return _backtick_columns(block.split("`path_nodes.csv`:")[1])


def test_spec_parsing_found_the_t75_lists():
    assert len(spec_table_columns("**`hops.csv`**")) == 43
    assert spec_table_columns("**`hops.csv`**")[:3] == ["hop_id", "target_host", "source_ip"]
    assert spec_table_columns("**`hops.csv`**")[-1] == "gate_clock_unreliable"
    assert spec_paths_columns()[0] == "path_id" and spec_paths_columns()[-1] == "shared_event_with"
    assert len(spec_paths_columns()) == 10
    assert spec_edges_columns() == ["path_id", "from_hop_id", "to_hop_id", "link_type", "time_delta_ms",
                                    "order_within_tolerance", "clock_unreliable"]
    assert spec_nodes_columns() == ["path_id", "hop_id", "role", "context", "host", "session_id", "event_uid",
                                    "link_id"]


def test_hops_columns_equal_the_spec_list_43_in_spec_order():
    assert len(out.HOPS_COLUMNS) == 43
    assert list(out.HOPS_COLUMNS) == spec_table_columns("**`hops.csv`**")


def test_paths_columns_equal_the_spec_list():
    assert list(out.PATHS_COLUMNS) == spec_paths_columns()


def test_edges_columns_equal_the_spec_list():
    assert list(out.EDGES_COLUMNS) == spec_edges_columns()


def test_nodes_columns_equal_the_spec_list():
    assert list(out.NODES_COLUMNS) == spec_nodes_columns()


def test_t75_column_tuples_have_no_duplicates():
    for cols in (out.HOPS_COLUMNS, out.PATHS_COLUMNS, out.EDGES_COLUMNS, out.NODES_COLUMNS):
        assert len(set(cols)) == len(cols)


def test_t75_file_names():
    assert (out.HOPS_FILE, out.PATHS_FILE, out.EDGES_FILE, out.NODES_FILE) == ("hops.csv", "paths.csv",
                                                                               "path_edges.csv", "path_nodes.csv")
    assert out.CHAIN_SEPARATOR == "|"


def test_written_headers_equal_the_spec_lists(ran):
    f = ran["folder"]
    assert header_of(f / "hops.csv") == spec_table_columns("**`hops.csv`**")
    assert header_of(f / "paths.csv") == spec_paths_columns()
    assert header_of(f / "path_edges.csv") == spec_edges_columns()
    assert header_of(f / "path_nodes.csv") == spec_nodes_columns()


# ---------------------------------------------------------------- the chain world
# Three user hops that chain, plus one hop with no trigger (a non-seed):
#   A  ep-01 -> ep-02 at 100 s (two members, 0.5 s apart, two accounts)  hop h0001
#   A2 ep-03 -> ep-02 at 150 s                                            hop h0002
#   B  ep-02 -> ep-01 at 300 s   (source IP is ep-02's)                   hop h0003   chains from A and from A2
#   N  ep-03 -> ep-02 at 400 s, no gate trigger (unmatched)               hop h0004   non-seed, no edge
CHAIN_ROWS = [
    dict(uid="CA", host=TGT, off=100.0, lid=8000, account="Chain_A1", ip=SRC_IP, port=50000, trig=True),
    dict(uid="CA-b", host=TGT, off=100.5, lid=8001, account="Chain_A2", ip=SRC_IP, port=50001, trig=True),
    dict(uid="CA2", host=TGT, off=150.0, lid=8002, account="Chain_C", ip=THIRD_IP, port=50100, trig=True),
    dict(uid="CB", host=SRC, off=300.0, lid=8003, account="Chain_B", ip=TGT_IP, port=50200, trig=True),
    dict(uid="CN", host=TGT, off=400.0, lid=8004, account="Chain_N", ip=THIRD_IP, port=50999, trig=False),
]


def chain_repo(tmp_path: Path, name: str = "chain"):
    rows = [sf.ev(m["uid"], "Security", 4624, host=m["host"], off=m["off"], logon_type=3, target_logon_id=m["lid"],
                  account_name=m["account"], source_ip=m["ip"], source_port=m["port"],
                  authentication_package="NTLM", machine_account=0) for m in CHAIN_ROWS]
    fake = sf.make_repo(tmp_path, rows, name=name)
    base = {"clock_unreliable": "0", "machine_account": "0"}
    trig, unmatched = [], []
    for m in CHAIN_ROWS:
        r = dict(base, trigger_id=("t-" if m["trig"] else "u-") + m["uid"], host=m["host"],
                 anchor_logon_uid=m["uid"], trigger_event_uid=m["uid"], target_logon_id=str(m["lid"]),
                 source_ip=m["ip"], ip_kind=ip_kind(m["ip"]))
        if m["trig"]:
            trig.append(dict(r, rule="R4_smb", gate_tier="A", supporting_event_uids=""))
        else:
            unmatched.append(r)
    write_gate_csv(fake.paths.gate_dir / "triggers.csv", trig, ["event_uid"])
    write_gate_csv(fake.paths.gate_dir / "unmatched_remote.csv", unmatched, ["event_uid"])
    return fake


@pytest.fixture(scope="module")
def chain(tmp_path_factory):
    fake = chain_repo(tmp_path_factory.mktemp("stitch_chain"))
    code = run_main(fake)
    folder = out_folder(fake)
    tables = {n: read_csv(folder / n) for n in ALL_CSV_FILES} if folder.exists() else {}
    stats = json.loads((folder / "stats.json").read_text(encoding="utf-8")) if folder.exists() else {}
    return {"fake": fake, "code": code, "folder": folder, "tables": tables, "stats": stats}


H = {i: f"{TRIAL}-h000{i}" for i in range(1, 5)}


def test_chain_world_runs_and_has_four_hops(chain):
    assert chain["code"] == 0
    assert [r["hop_id"] for r in chain["tables"]["hops.csv"]] == [H[1], H[2], H[3], H[4]]


def test_hops_csv_one_row_per_hop_nothing_lost_or_duplicated(chain, ran):
    assert len(chain["tables"]["hops.csv"]) == len({r["hop_id"] for r in chain["tables"]["links.csv"]}) == 4
    ids = [r["hop_id"] for r in ran["tables"]["hops.csv"]]
    assert ids == sorted(set(ids)) == hop_order(ran["tables"])


def test_in_path_equals_is_seed_per_hop_and_in_path_0_hops_equal_stats_list(chain, ran):
    for c in (chain, ran):
        rows = c["tables"]["hops.csv"]
        for r in rows:
            assert r["in_path"] == r["is_seed"], r["hop_id"]
            assert r["is_seed"] == ("1" if r["trigger_ids"] else "0"), r["hop_id"]
        stats = json.loads((c["folder"] / "stats.json").read_text(encoding="utf-8"))
        assert [r["hop_id"] for r in rows if r["in_path"] == "0"] == stats["hops_in_no_path"]
    assert [r["hop_id"] for r in chain["tables"]["hops.csv"] if r["in_path"] == "0"] == [H[4]]
    assert chain["stats"]["non_seed_hops"] == [H[4]]


def test_non_seed_hop_is_in_hops_csv_but_in_no_path_file(chain):
    t = chain["tables"]
    assert H[4] in {r["hop_id"] for r in t["hops.csv"]}
    assert H[4] in {r["hop_id"] for r in t["links.csv"]}                 # linked like any other hop (ST-23)
    assert H[4] not in {h for r in t["paths.csv"] for h in r["hop_ids"].split(";")}
    assert H[4] not in {r["hop_id"] for r in t["path_nodes.csv"]}
    assert H[4] not in {r[k] for r in t["path_edges.csv"] for k in ("from_hop_id", "to_hop_id")}
    row = next(r for r in t["hops.csv"] if r["hop_id"] == H[4])
    assert (row["is_seed"], row["in_path"], row["chain_parent_count"], row["trigger_ids"]) == ("0", "0", "0", "")


@pytest.mark.parametrize("which", ["ran", "chain"])
def test_member_columns_are_parallel_with_member_count_items(which, ran, chain):
    rows = (ran if which == "ran" else chain)["tables"]["hops.csv"]
    cols = ("member_logon_uids", "member_logon_ids", "member_logon_ids_hex", "member_accounts", "member_ports")
    for r in rows:
        n = int(r["member_count"])
        for c in cols:
            assert len(r[c].split(";")) == n, (r["hop_id"], c)
        for dec, hx in zip(r["member_logon_ids"].split(";"), r["member_logon_ids_hex"].split(";")):
            assert int(hx, 16) == int(dec), r["hop_id"]


def test_two_member_hop_lists_both_members_in_member_order(chain):
    r = next(x for x in chain["tables"]["hops.csv"] if x["hop_id"] == H[1])
    assert r["member_count"] == "2"
    assert r["member_logon_uids"] == "CA;CA-b"
    assert r["member_logon_ids"] == "8000;8001"
    assert r["member_logon_ids_hex"] == "0x1f40;0x1f41"
    assert r["member_accounts"] == "Chain_A1;Chain_A2"
    assert r["member_ports"] == "50000;50001"
    assert r["mixed_account"] == "1"
    assert r["is_seed"] == "1" and r["trigger_ids"] == "t-CA;t-CA-b"


def test_member_accounts_equal_the_db_account_of_each_member_uid(ran, chain):
    for c in (ran, chain):
        db = c["fake"].paths.db
        for r in c["tables"]["hops.csv"]:
            for uid, acct in zip(r["member_logon_uids"].split(";"), r["member_accounts"].split(";")):
                assert acct == db_value(db, uid, "account_name"), (r["hop_id"], uid)


def test_edges_are_the_two_host_time_edges_into_the_merged_hop(chain):
    rows = chain["tables"]["path_edges.csv"]
    assert [(r["from_hop_id"], r["to_hop_id"], r["link_type"]) for r in rows] == [
        (H[1], H[3], "host_time"), (H[2], H[3], "host_time")]
    assert [r["time_delta_ms"] for r in rows] == ["200000", "150000"]
    assert [r["order_within_tolerance"] for r in rows] == ["0", "0"]
    assert {r["path_id"] for r in rows} == {f"{TRIAL}-p0001"}


def test_multi_chain_parent_and_parent_list_in_hops_csv(chain):
    by = {r["hop_id"]: r for r in chain["tables"]["hops.csv"]}
    assert (by[H[3]]["chain_parent_count"], by[H[3]]["multi_chain_parent"]) == ("2", "1")
    assert by[H[3]]["chain_parent_hop_ids"] == f"{H[1]};{H[2]}"
    for h in (H[1], H[2]):
        assert (by[h]["chain_parent_count"], by[h]["multi_chain_parent"], by[h]["chain_parent_hop_ids"]) == (
            "0", "0", "")
    assert chain["stats"]["multi_chain_parent_hops"] == {H[3]: [H[1], H[2]]}


def test_paths_csv_edge_types_spelling_and_merged_from_chains(chain):
    rows = chain["tables"]["paths.csv"]
    assert len(rows) == 1
    r = rows[0]
    assert r["path_id"] == f"{TRIAL}-p0001"
    assert r["hop_ids"] == f"{H[1]};{H[2]};{H[3]}"
    assert r["n_hops"] == "3" and r["isolated"] == "0"
    assert r["edge_types"] == "host_time:2;session:0"
    assert r["merged_from"] == f"{H[1]}>{H[3]}|{H[2]}>{H[3]}"
    assert r["hosts"] == "ep-01>ep-02;ep-03>ep-02;ep-02>ep-01"
    assert r["seed_trigger_ids"] == "t-CA;t-CA-b;t-CA2;t-CB"
    assert (r["shared_source_session_with"], r["shared_event_with"]) == ("", "")


def test_edge_types_spelled_host_time_n_semicolon_session_m_everywhere(ran, chain):
    for c in (ran, chain):
        for r in c["tables"]["paths.csv"]:
            assert re.fullmatch(r"host_time:\d+;session:\d+", r["edge_types"]), r["edge_types"]
    assert all(r["edge_types"] == "host_time:0;session:0" for r in ran["tables"]["paths.csv"])


def test_merged_from_is_pipe_joined_chains_of_gt_joined_hop_ids(ran, chain):
    for c in (ran, chain):
        hop_ids = {r["hop_id"] for r in c["tables"]["hops.csv"]}
        for r in c["tables"]["paths.csv"]:
            chains = r["merged_from"].split("|")
            assert chains and all(chains)
            seen: set[str] = set()
            for ch in chains:
                ids = ch.split(">")
                assert set(ids) <= hop_ids and len(ids) == len(set(ids))
                seen |= set(ids)
            assert seen == set(r["hop_ids"].split(";"))
    for r in ran["tables"]["paths.csv"]:
        assert r["merged_from"] == r["hop_ids"] and r["isolated"] == "1"          # one hop, one chain of one


def test_every_seed_is_in_exactly_one_paths_row(ran, chain):
    for c in (ran, chain):
        in_paths = [h for r in c["tables"]["paths.csv"] for h in r["hop_ids"].split(";")]
        seeds = sorted(r["hop_id"] for r in c["tables"]["hops.csv"] if r["is_seed"] == "1")
        assert sorted(in_paths) == seeds
        assert len(in_paths) == len(set(in_paths))                                  # ST-04: none dropped, none twice
        for r in c["tables"]["paths.csv"]:
            assert int(r["n_hops"]) == len(r["hop_ids"].split(";"))


def test_path_nodes_belong_to_paths_and_hops_of_the_files(chain):
    t = chain["tables"]
    paths = {r["path_id"]: set(r["hop_ids"].split(";")) for r in t["paths.csv"]}
    assert t["path_nodes.csv"]
    for r in t["path_nodes.csv"]:
        assert r["hop_id"] in paths[r["path_id"]]
        assert r["role"] in {"target_logon", "artefact", "source_evidence", "source_session_event",
                             "target_session_event"}
        assert r["context"] in {"0", "1"}
    members = {u for r in t["hops.csv"] for u in r["member_logon_uids"].split(";")}
    assert {r["event_uid"] for r in t["path_nodes.csv"] if r["role"] == "target_logon"} == members - {"CN"}


def test_link_ids_in_path_nodes_are_links_csv_ids(ran):
    link_ids = {r["link_id"] for r in ran["tables"]["links.csv"]}
    nodes = ran["tables"]["path_nodes.csv"]
    with_link = [r for r in nodes if r["link_id"]]
    assert with_link
    assert {r["role"] for r in with_link} <= {"source_evidence", "source_session_event"}
    assert all(r["link_id"] in link_ids for r in with_link)
    assert all(r["link_id"] == "" for r in nodes if r["role"] in ("target_logon", "artefact", "target_session_event"))


def test_t74_files_are_the_same_bytes_on_a_second_build(ran, tmp_path):
    again = build_repo(tmp_path, name="again")
    assert run_main(again) == 0
    for n in CSV_FILES:
        assert (out_folder(again) / n).read_bytes() == (ran["folder"] / n).read_bytes(), n


# ---------------------------------------------------------------- byte identity of all files but run_info.json
def test_two_runs_byte_identical_for_every_file_except_run_info(tmp_path):
    fake = chain_repo(tmp_path)
    assert run_main(fake) == 0
    first = {n: (out_folder(fake) / n).read_bytes() for n in FILES}
    assert run_main(fake) == 0
    second = {n: (out_folder(fake) / n).read_bytes() for n in FILES}
    for n in FILES:
        if n != "run_info.json":
            assert first[n] == second[n], n
    assert all(len(first[n]) > 10 for n in FILES)


def test_two_runs_byte_identical_on_the_rich_world_too(tmp_path):
    fake = build_repo(tmp_path)
    assert run_main(fake) == 0
    first = {n: (out_folder(fake) / n).read_bytes() for n in FILES}
    assert run_main(fake) == 0
    for n in FILES:
        if n != "run_info.json":
            assert first[n] == (out_folder(fake) / n).read_bytes(), n


# ---------------------------------------------------------------- stats.json (spec section 3)
@pytest.fixture(scope="module")
def stats(ran):
    return json.loads((ran["folder"] / "stats.json").read_text(encoding="utf-8"))


def test_stats_json_has_no_timestamp(ran, stats):
    text = (ran["folder"] / "stats.json").read_text(encoding="utf-8")
    assert not re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", text)
    assert not [k for k in stats if "generated" in k or k.endswith("_utc") or k in ("timestamp", "time")]
    assert "generated_utc" not in text
    assert text.endswith("\n") and "\r" not in text


def test_stats_json_contains_the_spec_section_3_items(stats):
    for key in ("files", "hops_by_protocol_and_tier", "hops_by_methods_linked", "target_only_reasons",
                "hops_in_no_path", "followup_logons", "chain_edges_by_type", "gap_near_threshold",
                "gap_near_threshold_user_e2e", "system_session_evidence", "removed_by_window", "parameters", "db"):
        assert key in stats, key


def test_stats_files_are_the_row_counts_of_the_seven_csvs(ran, stats):
    assert sorted(stats["files"]) == sorted(ALL_CSV_FILES)
    for n in ALL_CSV_FILES:
        assert stats["files"][n] == len(ran["tables"][n]), n
    info = json.loads((ran["folder"] / "run_info.json").read_text(encoding="utf-8"))
    for n, rows in stats["files"].items():
        assert info["files"][n]["rows"] == rows, n


def test_stats_hops_by_protocol_and_tier_and_methods_linked(stats):
    assert stats["hops_by_protocol_and_tier"] == {"smb": {"A": 0, "B": 1, "C": 0, "D": 4}}
    assert stats["hops_by_methods_linked"] == {"smb": {"0": 4, "1": 0, "2": 1, "3": 0}}
    assert stats["hops"] == 5 and stats["seeds"] == 5


def test_stats_target_only_reasons_followups_hops_in_no_path(stats):
    assert stats["target_only_reasons"] == {"no_evidence_in_range": 2, "source_host_no_logs": 1,
                                            "source_host_unknown": 1}
    assert stats["hops_in_no_path"] == []
    assert stats["followup_logons"] == 0


def test_stats_chain_edges_by_type(stats, chain):
    assert stats["chain_edges_by_type"] == {"host_time": 0, "session": 0}
    assert chain["stats"]["chain_edges_by_type"] == {"host_time": 2, "session": 0}


def test_stats_gap_near_threshold_with_user_endpoint_count(stats):
    assert isinstance(stats["gap_near_threshold"], int) and isinstance(stats["gap_near_threshold_user_e2e"], int)
    assert 0 <= stats["gap_near_threshold_user_e2e"] <= stats["gap_near_threshold"]


def test_stats_system_session_evidence_per_method(stats):
    assert set(stats["system_session_evidence"]) == {"sysmon3_port", "source_4648", "cmdline_target"}
    assert all(isinstance(v, int) for v in stats["system_session_evidence"].values())


def test_stats_removed_by_window_counts_the_outside_events_and_lists_none(ran, stats):
    r = stats["removed_by_window"]
    total = sum(n for c in r.values() for n in c.values())
    assert total >= 6                                    # OUTW-PROC / SHARE / DUMP / LOGON, PREW-PROC / SHARE at least
    assert set(r) <= {SRC, TGT, THIRD}
    text = (ran["folder"] / "stats.json").read_text(encoding="utf-8")
    for uid in OUT_UIDS:
        assert uid not in text


def test_stats_parameters_and_db_hash(ran, stats):
    p = stats["parameters"]
    assert p["order_tol_s"] == 5.0 and p["group_gap_s"] == 2.0
    assert stats["db"]["sha256_before"] == stats["db"]["sha256_after"] == ran["db_before"]
    assert stats["trial_id"] == TRIAL


# ---------------------------------------------------------------- STT-13 over all ten files (decision 050 item 8)
def scan_text_all(ran) -> str:
    """Every file of the folder as text: the CSVs with the account / image columns (049 item 7, plus hops.csv
    member_accounts, 050 item 8) and the target-side name cells blanked; stats.json, report.md, run_info.json whole
    (report.md is never blanked)."""
    parts: list[str] = []
    names: list[str] = []
    blank = set(BLANKED) | {"member_accounts"}
    for n in ALL_CSV_FILES:
        for r in ran["tables"][n]:
            for k, v in r.items():
                if k in blank:
                    continue
                if k in NAME_COLUMNS:
                    names += [x for x in v.split(";") if x]
                    continue
                parts.append(v)
    for n in ("stats.json", "report.md", "run_info.json"):
        parts.append((ran["folder"] / n).read_text(encoding="utf-8"))
    text = "\n".join(parts)
    for nm in sorted(set(names), key=len, reverse=True):
        text = re.sub(re.escape(nm), "", text, flags=re.IGNORECASE)
    return text


def test_no_twelve_character_command_substring_in_any_of_the_ten_files(ran):
    commands = db_command_lines(ran["fake"].paths.db)
    text = scan_text_all(ran).casefold()
    hits = 0
    for c in commands:
        c = c.casefold()
        hits += sum(1 for i in range(len(c) - 11) if c[i:i + 12] in text)
    assert len(commands) >= 4
    assert hits == 0, f"{hits} command substring(s) of 12 characters in the output (count only)"


def test_report_md_has_no_blanking_no_account_no_image_no_command_substring(ran):
    report = (ran["folder"] / "report.md").read_text(encoding="utf-8").casefold()
    for c in db_command_lines(ran["fake"].paths.db):
        c = c.casefold()
        assert not [c[i:i + 12] for i in range(len(c) - 11) if c[i:i + 12] in report]
    accounts = {m["account"] for m in MEMBERS} | set(SESSION_ACCOUNTS.values()) | {DUMP_ACCOUNT}
    for a in accounts:
        assert a.casefold() not in report, "an account name is in report.md"
    for forbidden in (IMAGE_DUMP, "probereader", "runner.exe", "payloadxq", "syncsvcq"):
        assert forbidden.casefold() not in report, forbidden


def test_member_accounts_column_is_the_only_new_account_text_in_the_t75_csvs(ran):
    accounts = {m["account"].casefold() for m in MEMBERS} | {a.casefold() for a in SESSION_ACCOUNTS.values()}
    for n in ("paths.csv", "path_edges.csv", "path_nodes.csv"):
        text = (ran["folder"] / n).read_text(encoding="utf-8").casefold()
        for a in accounts:
            assert a not in text, (n, "holds an account name")
    hops_text = "\n".join(v for r in ran["tables"]["hops.csv"] for k, v in r.items() if k != "member_accounts")
    for a in accounts | {DUMP_ACCOUNT.casefold()}:
        assert a not in hops_text.casefold(), "hops.csv holds an account outside member_accounts"


# ---------------------------------------------------------------- the IPv4 exemption of the command scan (owner ruling)
# A command window is exempt only when, at every position where it occurs, it lies wholly inside a bare IPv4 literal
# (full dotted quad, each octet 0-255, bounded by the text ends or a character that is neither a digit nor '.').
def _hits(text: str, *commands: str) -> list[int]:
    return sf.non_exempt_hits(text, sf.command_grams(list(commands)))


SHARE_CMD = r"copy x \\192.168.50.22\ADMIN$\a.exe"


def test_bare_ip_cell_is_exempt():
    assert _hits("192.168.50.22", SHARE_CMD) == []
    assert _hits("10.0.0.1", "ping 10.0.0.1 now") == []                      # a shorter bare IP has no 12-char window


def test_the_helper_does_find_a_non_ip_command_window():
    assert _hits("xx payloadxq.exe yy", "run payloadxq.exe now") != []
    assert _hits("nothing in common here", SHARE_CMD) == []


def test_ip_followed_by_a_share_path_is_not_exempt():
    # the window "68.50.22\ADMI" crosses the end of the address
    assert _hits(r"192.168.50.22\ADMIN", SHARE_CMD) != []
    assert _hits(r"\\192.168.50.22\ADMIN$", SHARE_CMD) != []


def test_ip_preceded_by_backslashes_is_not_exempt():
    assert _hits(r"\\192.168.50.22", SHARE_CMD) != []


def test_ip_followed_by_a_port_is_not_exempt():
    # ':' is neither a digit nor a dot, so the token ends there, but the window with ":5985" crosses its end
    cmd = "Enter-PSSession 192.168.50.22:5985 -Credential"
    assert _hits("192.168.50.22:5985", cmd) != []
    assert _hits("192.168.50.22", cmd) == []                                 # the bare address alone is fine


def test_ip_inside_a_longer_token_is_not_exempt():
    assert _hits("x192.168.50.22", "run x192.168.50.22 now") != []
    assert _hits("host192.168.50.22", "ping host192.168.50.22") != []


def test_ip_with_extra_digits_is_not_a_bare_ip():
    assert _hits("192.168.50.2210", "ping 192.168.50.2210") != []            # fourth octet of four digits
    assert _hits("192.168.50.256", "ping 192.168.50.256") != []              # octet above 255
    assert _hits("192.168.50.22.1", "ping 192.168.50.22.1") != []            # five octets


def test_window_of_digits_and_dots_spanning_two_adjacent_addresses_is_not_exempt():
    cmd = "list 192.168.50.2.192.168.50.3 end"
    assert _hits("192.168.50.2.192.168.50.3", cmd) != []
    assert _hits("192.168.50.2 192.168.50.3", "list 192.168.50.2 192.168.50.3 end") != []   # window spans the space


def test_two_separate_bare_addresses_cells_are_each_exempt():
    assert _hits("192.168.50.21", "a 192.168.50.21 b") == []
    assert _hits("192.168.50.23", "a 192.168.50.23 b") == []


def test_exempt_at_one_occurrence_but_not_at_another_fails():
    text = r"192.168.50.22 and then 192.168.50.22\ADMIN"
    assert _hits(text, SHARE_CMD) != []
    only_bare = "192.168.50.22 and then 192.168.50.22"
    assert _hits(only_bare, SHARE_CMD) == []


def test_window_inside_the_address_but_bounded_by_quotes_of_a_json_line():
    # a JSON line holds the bare address between quotes: the quote is a non-digit, non-dot boundary character
    assert _hits('  "ep-01": "192.168.50.21",', "x 192.168.50.21 y") == []
    # but a command that has the quote next to the address makes the window with the quote a hit
    assert _hits('  "ep-01": "192.168.50.21",', 'x "192.168.50.21" y') != []


def test_matching_is_case_insensitive():
    assert _hits("RUN PAYLOADXQ.EXE", "run payloadxq.exe") != []


def test_command_grams_are_twelve_characters_and_casefolded():
    g = sf.command_grams(["ABCDEFGHIJKLMN"])
    assert g == {"abcdefghijkl", "bcdefghijklm", "cdefghijklmn"}
    assert sf.command_grams(["short"]) == set()
