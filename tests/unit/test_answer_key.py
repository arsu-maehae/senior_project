"""Tests for the T5 stage `src/answer_key` (spec docs/specs/07_answer_key.md).

Written from the spec (AK-01..AK-15, edge cases AKT-02..AKT-21, section 7) and CLAUDE.md. The code was
read only for callable names and the CLI entry. Expectations that need the "truth" (dumps, ancestry,
source hosts, service names) are recomputed here from the DB with independent code.

Real-data checks run on data/processed/s0N_t00.sqlite3 through hard links (or copies) in a temp repo, so
nothing under ground_truth/ or out/ of the real repo is touched. Synthetic cases edit temp copies of a DB.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from answer_key import targets, verify as verify_mod  # noqa: E402
from answer_key.__main__ import cmd_build, cmd_verify, main as cli_main, safe_draft_path  # noqa: E402

PROCESSED = REPO / "data" / "processed"
SRC_AK = REPO / "src" / "answer_key"
TRIALS = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00"]
PASSWORD = "Project123"
LAB_IP_HOST = {"192.168.50.21": "ep-01", "192.168.50.22": "ep-02", "192.168.50.23": "ep-03"}

HOP_FIELDS = ["hop_id", "protocol", "source_host", "target_host", "account", "move_time_utc", "basis", "status",
              "agent_event_uids", "target_event_uids", "identity_expected", "identity_basis", "time_delta_ms",
              "confidence_tier", "handoff_step", "handoff_account", "agent_account", "cmd_credential_account",
              "logon_account", "account_mismatch", "target_binding", "candidate_count", "needs_owner_approval",
              "flags"]
IDENTITY_BASIS_FIELDS = ["dump_event_uid", "open_session_ids", "dump_time_utc", "move_after_dump"]
TOP_FIELDS = ["trial_id", "scenario", "status", "provenance", "db_sha256", "window", "agent", "steps", "hops",
              "paths", "benign_paths", "unconfirmed", "open_points"]
STEP_FIELDS = ["step_id", "kind", "host", "time_utc", "account", "status", "source", "event_uids", "note"]
ALLOWED_FLAGS = {"clock_order_disagree", "run_day_spans_midnight", "source_host_conflict", "decision_conflict", "weak_exposure_only", "handoff_mismatch",
                 "attempt_no_target_evidence", "order_within_tolerance", "stray_agent_ep02", "decode_failed",
                 "end_unknown", "no_intended_step", "account_mismatch"}


def db_path(trial: str) -> Path:
    return PROCESSED / f"{trial}.sqlite3"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def need_db(trial: str) -> Path:
    p = db_path(trial)
    if not p.exists():
        pytest.skip(f"{p} missing (real-data check needs the processed trial DB)")
    return p


# ----------------------------------------------------------------------------------------- temp repos

def make_repo(root: Path, trial: str, link: bool) -> Path:
    """Temp repo with data/processed/<trial>.sqlite3 (hard link for real data, copy otherwise)."""
    src = need_db(trial)
    (root / "data" / "processed").mkdir(parents=True, exist_ok=True)
    (root / "ground_truth" / "drafts").mkdir(parents=True, exist_ok=True)
    (root / "ground_truth" / "approved").mkdir(parents=True, exist_ok=True)
    dst = root / "data" / "processed" / f"{trial}.sqlite3"
    if link:
        try:
            os.link(src, dst)
        except OSError:
            shutil.copy(src, dst)
    else:
        shutil.copy(src, dst)
    return root


def read_draft(repo: Path, trial: str) -> dict:
    return json.loads((repo / "ground_truth" / "drafts" / f"{trial}.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def real(tmp_path_factory):
    """trial -> (repo, draft, db hash before). Each real trial is built once into a temp repo."""
    out: dict = {}
    for trial in TRIALS:
        p = db_path(trial)
        if not p.exists():
            continue
        before = sha256(p)
        repo = make_repo(tmp_path_factory.mktemp(trial), trial, link=True)
        cmd_build(trial, repo)
        out[trial] = (repo, read_draft(repo, trial), before)
    return out


def draft_of(real, trial: str) -> dict:
    if trial not in real:
        pytest.skip(f"{db_path(trial)} missing")
    return real[trial][1]


def synth(tmp_path: Path, trial: str, edit=None) -> tuple[Path, dict]:
    """Copy of a real DB in a temp repo, optionally edited by edit(con); returns (repo, draft)."""
    repo = make_repo(tmp_path, trial, link=False)
    dbp = repo / "data" / "processed" / f"{trial}.sqlite3"
    if edit:
        con = sqlite3.connect(dbp)
        edit(con)
        con.commit()
        con.close()
    cmd_build(trial, repo)
    return repo, read_draft(repo, trial)


# ----------------------------------------------------------------------------------------- DB helpers

def rows(trial: str, sql: str, params=()) -> list[sqlite3.Row]:
    con = sqlite3.connect("file:" + db_path(trial).as_posix() + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        return con.execute(sql, params).fetchall()
    finally:
        con.close()


def by_uid(trial: str, uids) -> dict:
    uids = list(uids)
    out = {}
    for i in range(0, len(uids), 400):
        chunk = uids[i:i + 400]
        for r in rows(trial, f"SELECT * FROM events_dedup WHERE event_uid IN ({','.join('?' * len(chunk))})", chunk):
            out[r["event_uid"]] = r
    return out


def t_of(r) -> datetime:
    return parse(r["event_utc"] or r["timestamp_utc"])


def parse(text: str) -> datetime:
    return datetime.strptime(text.replace("Z", "")[:26].ljust(26, "0") if "." in text else text.replace("Z", "") + ".000000",
                             "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)


def fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


_counter = [0]


def insert_event(con: sqlite3.Connection, **kw) -> str:
    """Insert one synthetic row into `events` (so it shows in events_dedup)."""
    _counter[0] += 1
    n = _counter[0]
    uid = hashlib.sha256(f"synthetic-{n}".encode()).hexdigest()
    row = {"event_uid": uid, "field_values_json": "{}", "raw_event_sha256": uid,
           "duplicate_content_sha256": hashlib.sha256(f"dup-{n}".encode()).hexdigest(), "trial_id": "t00",
           "source_line": 900000 + n, "source_relative_path": "synthetic/test.evtx", "record_id": 9000000 + n,
           "scenario_id": "s02", "machine_account": 0, "predefined_session": 0}
    row.update(kw)
    if "event_utc" in row and "timestamp_utc" not in row:
        row["timestamp_utc"] = row["event_utc"]
    cols = ",".join(f'"{k}"' for k in row)
    con.execute(f"INSERT INTO events ({cols}) VALUES ({','.join('?' * len(row))})", list(row.values()))
    return uid


def sysmon1(con, host, t, guid, parent_guid, account, image, cmd, parent_image="C:\\Windows\\System32\\cmd.exe",
            pid=40000, ppid=1) -> str:
    return insert_event(con, host=host, channel="Sysmon", event_id=1, event_utc=fmt(t), process_guid=guid,
                        parent_process_guid=parent_guid, account_name=account, domain_short="lab", account=f"lab\\{account}",
                        image=image, parent_image=parent_image, command_line=cmd, process_id=pid, parent_process_id=ppid)


def find(node, key):
    """All values stored under `key` anywhere in a nested draft."""
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                out.append(v)
            out += find(v, key)
    elif isinstance(node, list):
        for v in node:
            out += find(v, key)
    return out


def hop_by_id(draft: dict, hop_id: str) -> dict:
    return next(h for h in draft["hops"] if h["hop_id"] == hop_id)


def confirmed(draft: dict) -> list[dict]:
    return [h for h in draft["hops"] if h["status"] == "confirmed"]


def run_cli(*args) -> int:
    return cli_main(list(args))


# =========================================================================================== contract

@pytest.mark.parametrize("trial", TRIALS)
def test_top_level_fields_and_constants(real, trial):
    d = draft_of(real, trial)
    for f in TOP_FIELDS:
        assert f in d, f"missing top-level field {f}"
    assert d["trial_id"] == trial and d["scenario"] == trial.split("_")[0]
    assert d["status"] == "draft"
    assert d["provenance"] == "log-based, agent process tree (decision 020)"
    assert d["db_sha256"] == real[trial][2]
    for f in ("start_utc", "end_utc", "source", "provisional", "outside_counts", "shrink_flag"):
        assert f in d["window"], f"window.{f}"
    assert d["window"]["source"] == "key"
    for f in ("image", "server_ip", "server_port", "accounts"):
        assert f in d["agent"], f"agent.{f}"
    assert d["agent"]["image"].lower().endswith("splunkd.exe")
    assert d["agent"]["server_port"] == 8888


@pytest.mark.parametrize("trial", TRIALS)
def test_hop_fields_and_enums(real, trial):
    d = draft_of(real, trial)
    ids = [h["hop_id"] for h in d["hops"]]
    assert len(ids) == len(set(ids)), "duplicate hop_id"
    for h in d["hops"]:
        for f in HOP_FIELDS:
            assert f in h, f"{h['hop_id']} missing {f}"
        for f in IDENTITY_BASIS_FIELDS:
            assert f in h["identity_basis"], f"{h['hop_id']} identity_basis.{f}"
        assert h["basis"] in {"command_names_target", "time_account_only"}            # test (1)
        assert h["status"] in {"confirmed", "unconfirmed"}
        assert h["identity_expected"] in (0, 1)
        assert h["confidence_tier"] in {"A", "B", "C", "D"}
        assert isinstance(h["move_time_utc"], str)
        assert isinstance(h["flags"], list) and set(h["flags"]) <= ALLOWED_FLAGS, h["flags"]
        assert isinstance(h["agent_event_uids"], list) and isinstance(h["target_event_uids"], list)
        assert len(h["target_event_uids"]) == len(set(h["target_event_uids"])), "duplicate target uid"
        assert h["target_binding"] in {"logon_id_artifact", "name_only", "time_account"}
        assert isinstance(h["account_mismatch"], bool)
        if h["status"] == "confirmed":
            assert h["protocol"] in {"SMB", "WinRM", "RDP"}


@pytest.mark.parametrize("trial", TRIALS)
def test_steps_fields_and_paths(real, trial):
    d = draft_of(real, trial)
    for s in d["steps"]:
        for f in STEP_FIELDS:
            assert f in s, f"step {s.get('step_id')} missing {f}"
        assert s["kind"] in {"agent_start", "lsass_dump", "move", "service_exec", "benign"}
        assert s["status"] in {"confirmed", "unconfirmed"}
        assert s["source"] in {"agent_tree", "target_side"}
    hop_ids = {h["hop_id"] for h in d["hops"]}
    for p in d["paths"]:
        assert p["role"] in {"attack", "attack_pair", "distractor"}
        assert set(p["hop_ids"]) <= hop_ids
    for p in d["benign_paths"]:
        assert p["role"] == "benign" and set(p["hop_ids"]) <= hop_ids
    in_paths = {x for p in d["paths"] for x in p["hop_ids"]}
    for h in d["hops"]:
        if h["basis"] == "time_account_only":
            assert h["hop_id"] not in in_paths, "time_account_only hop placed on an attack path"
    # every unconfirmed hop is listed in unconfirmed[] (AK-04, section 3)
    listed = {u["id"] for u in d["unconfirmed"]}
    for h in d["hops"]:
        if h["status"] == "unconfirmed":
            assert h["hop_id"] in listed, f"{h['hop_id']} unconfirmed but not in unconfirmed[]"


@pytest.mark.parametrize("trial", TRIALS)
def test_build_is_deterministic_no_rows_lost_or_duplicated(real, trial, tmp_path):
    repo, d1, _ = real[trial] if trial in real else pytest.skip("db missing")
    cmd_build(trial, repo)
    assert read_draft(repo, trial) == d1


# ====================================================================== (1) AK-02 / AK-04 basis rules

NAME_RE = {h: re.compile(rf"(?i)(?<![A-Za-z0-9_-])(?:{h}|endpoint-{h[-2:]})(?:\.lab\.local)?(?![A-Za-z0-9_-])")
           for h in ("ep-01", "ep-02", "ep-03")}


def ip_of(host: str) -> str:
    return next(i for i, h in LAB_IP_HOST.items() if h == host)


def names_target_independent(text: str, host: str) -> bool:
    return bool(NAME_RE[host].search(text)) or bool(re.search(r"(?<![\d.])" + re.escape(ip_of(host)) + r"(?!\d)(?!\.\d)", text))


def all_texts(text: str) -> list[str]:
    out = [text]
    for m in re.finditer(r"(?i)-(?:e|enc|ec|encodedcommand)\s+([A-Za-z0-9+/]{16,}={0,2})", text):
        try:
            out.append(base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode("utf-16-le"))
        except Exception:
            pass
    return out


@pytest.mark.parametrize("trial", TRIALS)
def test_time_account_only_never_confirmed_and_confirmed_names_target(real, trial):
    d = draft_of(real, trial)
    ev = by_uid(trial, [u for h in d["hops"] for u in h["agent_event_uids"]])
    for h in d["hops"]:
        if h["basis"] == "time_account_only":
            assert h["status"] != "confirmed", h["hop_id"]
        if h["status"] == "confirmed":
            assert h["basis"] == "command_names_target"
            assert h["agent_event_uids"], f"{h['hop_id']} confirmed without agent command"
            assert h["source_host"] != h["target_host"]
            texts = [t for u in h["agent_event_uids"] for t in all_texts(ev[u]["command_line"] or "")]
            assert any(names_target_independent(t, h["target_host"]) for t in texts), \
                f"{h['hop_id']}: no agent command names {h['target_host']}"
            assert h["agent_account"] not in ("system", None) and not h["agent_account"].endswith("$")


def agent_ancestor_reached(trial: str, uid: str) -> bool:
    """Independent walk by parent_process_guid (pid fallback) to splunkd.exe in Sysmon 1."""
    r0 = by_uid(trial, [uid])[uid]
    allr = rows(trial, "SELECT event_uid,host,process_guid,parent_process_guid,process_id,parent_process_id,image,"
                       "COALESCE(event_utc,timestamp_utc) t FROM events_dedup WHERE channel='Sysmon' AND event_id=1 AND host=?",
                (r0["host"],))
    g = {(r["process_guid"] or "").lower(): r for r in allr}
    cur = next(r for r in allr if r["event_uid"] == uid)
    for _ in range(30):
        if (cur["image"] or "").lower().endswith("splunkd.exe") and cur["event_uid"] != uid:
            return True
        par = g.get((cur["parent_process_guid"] or "").lower())
        if par is None:
            cands = [r for r in allr if r["process_id"] == cur["parent_process_id"] and r["t"] <= cur["t"]]
            par = max(cands, key=lambda r: r["t"]) if cands else None
        if par is None:
            return False
        cur = par
    return False


@pytest.mark.parametrize("trial", ["s02_t00", "s04_t00", "s05_t00", "s07_t00"])
def test_confirmed_hop_agent_commands_are_in_splunkd_tree(real, trial):
    d = draft_of(real, trial)
    for h in confirmed(d):
        for u in h["agent_event_uids"]:
            r = by_uid(trial, [u])[u]
            assert (r["channel"], r["event_id"]) == ("Sysmon", 1), "agent record must be Sysmon 1"
            assert agent_ancestor_reached(trial, u), f"{h['hop_id']}: {u} has no splunkd ancestor"


# ====================================================================== (2) AK-06 independence

def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods.add(("." * n.level) + (n.module or ""))
            if n.level:
                mods |= {("." * n.level) + (n.module or "") + "." + a.name for a in n.names}
    return mods


FORBIDDEN = ("log_check", "parsing_normalization", "stitch", "join")


def test_ak06_no_forbidden_imports_anywhere_in_package():
    for p in SRC_AK.glob("*.py"):
        for m in imported_modules(p):
            assert not any(f in m.lower() for f in FORBIDDEN), f"{p.name} imports {m}"


def test_ak06_import_whitelist_only_stdlib_or_package_local():
    stdlib = set(sys.stdlib_module_names)
    for p in SRC_AK.glob("*.py"):
        for m in imported_modules(p):
            if m.startswith("."):
                continue
            assert m.split(".")[0] in stdlib, f"{p.name} imports non-stdlib/non-local {m}"


def test_ak06_verify_shares_only_db_with_builder():
    mods = imported_modules(SRC_AK / "verify.py")
    local = {m for m in mods if m.startswith(".")}
    assert all(m.startswith(".db") for m in local), local
    for banned in ("build", "collect", "identity", "targets", "agent_tree", "finish", "timeutil"):
        assert not any(m.lstrip(".").split(".")[0] == banned for m in mods), f"verify imports {banned}"


def test_ak06_builder_imports_nothing_from_log_check_or_parser_even_transitively():
    sys_mods_before = set(sys.modules)
    import importlib
    importlib.import_module("answer_key.build")
    importlib.import_module("answer_key.verify")
    loaded = {m for m in sys.modules if m.startswith("answer_key")}
    # transitive: every imported answer_key module has been checked above; also check no log_check module
    # was pulled in *by answer_key* (log_check may be imported by other test modules, so check the imports).
    for m in loaded:
        mod = sys.modules[m]
        for v in vars(mod).values():
            name = getattr(v, "__module__", "") or ""
            assert "log_check" not in name and "parsing_normalization" not in name


def test_ak06_no_reads_of_out_log_check_in_source_strings():
    for p in SRC_AK.glob("*.py"):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) < 200:
                assert "out/log_check" not in n.value.replace("\\", "/") and n.value != "log_check", (p.name, n.value)
    # intended steps file and the CLI never point at the log-check output either
    for p in SRC_AK.glob("*"):
        if p.suffix in {".json", ".yaml"}:
            assert "out/log_check" not in p.read_text(encoding="utf-8").replace("\\", "/")


# ====================================================================== (3) AK-14 write rules

def test_ak14_refuses_approved_path(tmp_path):
    (tmp_path / "ground_truth" / "approved").mkdir(parents=True)
    (tmp_path / "ground_truth" / "drafts").mkdir(parents=True)
    for bad in ("../approved/s02_t00", "..\\approved\\s02_t00", "../../outside", "../approved/../approved/x"):
        with pytest.raises(SystemExit):
            safe_draft_path(tmp_path, bad)
    ok = safe_draft_path(tmp_path, "s02_t00")
    assert ok == (tmp_path / "ground_truth" / "drafts" / "s02_t00.yaml").resolve()


def test_ak14_cli_build_refuses_approved_and_writes_nothing(tmp_path):
    repo = make_repo(tmp_path, "s02_t00", link=True)
    shutil.copy(db_path("s02_t00"), repo / "data" / "processed" / "evil.sqlite3") if False else None
    with pytest.raises(SystemExit):
        run_cli("build", "--trial", "../approved/s02_t00", "--repo", str(repo))
    assert list((repo / "ground_truth" / "approved").rglob("*")) == []
    assert list((repo / "ground_truth" / "drafts").rglob("*")) == []


def snapshot(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}


def test_ak14_build_writes_only_the_draft_and_verify_only_out(tmp_path):
    repo = make_repo(tmp_path, "s02_t00", link=True)
    before = snapshot(repo)
    assert run_cli("build", "--trial", "s02_t00", "--repo", str(repo)) == 0
    new = snapshot(repo) - before
    assert new == {"ground_truth/drafts/s02_t00.yaml"}, new
    before = snapshot(repo)
    assert run_cli("verify", "--trial", "s02_t00", "--repo", str(repo)) == 0
    new = snapshot(repo) - before
    assert new and all(n.startswith("out/answer_key/s02_t00/") for n in new), new
    assert snapshot(repo / "ground_truth" / "approved") == set() if (repo / "ground_truth" / "approved").exists() else True


@pytest.mark.parametrize("trial", TRIALS)
def test_ak14_db_hash_unchanged_by_build_and_verify(tmp_path, trial):
    p = need_db(trial)
    h0 = sha256(p)
    st0 = p.stat().st_mtime_ns
    repo = make_repo(tmp_path, trial, link=True)
    cmd_build(trial, repo)
    rep = cmd_verify(trial, repo)
    assert sha256(p) == h0 and p.stat().st_mtime_ns == st0
    assert rep["db_sha256_draft"] == h0 == rep["db_sha256_now"]


def test_ak14_db_opened_read_only(tmp_path):
    from answer_key import db
    repo = make_repo(tmp_path, "s02_t00", link=False)
    con = db.open_ro(repo / "data" / "processed" / "s02_t00.sqlite3")
    with pytest.raises(sqlite3.OperationalError):
        con.execute("DELETE FROM events")
    con.close()


# ====================================================================== (4) S02

def stray_ep02_times() -> list[datetime]:
    rs = rows("s02_t00", "SELECT event_utc FROM events_dedup WHERE channel='Sysmon' AND event_id=1 AND host='ep-02' "
                         "AND parent_image LIKE '%splunkd.exe' AND account_name='system' ORDER BY event_utc")
    return [parse(r["event_utc"]) for r in rs]


def test_s02_exactly_one_confirmed_hop_svc_backup(real):
    d = draft_of(real, "s02_t00")
    c = confirmed(d)
    assert len(c) == 1
    h = c[0]
    assert (h["source_host"], h["target_host"], h["account"], h["protocol"]) == ("ep-01", "ep-02", "svc_backup", "SMB")
    assert h["basis"] == "command_names_target" and h["identity_expected"] == 1
    assert h["target_binding"] == "logon_id_artifact"
    assert [p["hop_ids"] for p in d["paths"]] == [[h["hop_id"]]] and d["paths"][0]["role"] == "attack"


def test_s02_stray_ep02_run_flagged_and_excluded(real):
    d = draft_of(real, "s02_t00")
    h = confirmed(d)[0]
    strays = [u for u in d["unconfirmed"] if u.get("role") == "stray"]
    assert strays, "stray ep-02 system run missing from unconfirmed[]"
    assert all("stray_agent_ep02" in u["flags"] for u in strays if u.get("kind") == "stray")
    stray_uids = {x for u in strays for x in u["event_uids"]}
    sys1 = [r["event_uid"] for r in rows("s02_t00", "SELECT event_uid FROM events_dedup WHERE channel='Sysmon' AND event_id=1 "
                                                    "AND host='ep-02' AND parent_image LIKE '%splunkd.exe' AND account_name='system'")]
    assert sys1 and set(sys1) <= stray_uids
    assert not (stray_uids & set(h["agent_event_uids"]))
    # stray 7045 / 4697 / 4624 / share events on ep-02 between the stray command and the real move
    move = parse(h["move_time_utc"])
    tgt = set(h["target_event_uids"])
    leaked = []
    for st in stray_ep02_times():
        for r in rows("s02_t00", "SELECT event_uid,event_id,event_utc FROM events_dedup WHERE host='ep-02' AND event_id IN "
                                 "(7045,4697,4624,5140,5145) AND event_utc >= ? AND event_utc < ?",
                      (fmt(st - timedelta(seconds=5)), fmt(move - timedelta(seconds=1)))):
            if r["event_uid"] in tgt:
                leaked.append((r["event_id"], r["event_uid"]))
    assert not leaked, f"stray events inside hop target_event_uids: {leaked}"
    tev = by_uid("s02_t00", tgt)
    assert not [u for u, r in tev.items() if r["event_id"] == 7045 and (r["service_name"] or "").lower() == "pktdropservice"
                and t_of(r) < move], "stray 7045 in hop"


def test_s02_stray_dump_not_used_for_identity(real):
    d = draft_of(real, "s02_t00")
    h = confirmed(d)[0]
    stray_dump = rows("s02_t00", "SELECT event_uid FROM events_dedup WHERE channel='Sysmon' AND event_id=10 AND host='ep-02' "
                                 "AND source_image LIKE '%rundll32.exe' AND target_image LIKE '%lsass.exe'")
    ib = h["identity_basis"]
    used = set(ib.get("dump_event_uids") or []) | ({ib["dump_event_uid"]} if ib["dump_event_uid"] else set())
    assert used, "no dump used"
    assert not ({r["event_uid"] for r in stray_dump} & used)
    ev = by_uid("s02_t00", used)
    assert {r["host"] for r in ev.values()} == {"ep-01"}
    assert all(r["event_id"] == 10 and r["target_image"].lower().endswith("lsass.exe") for r in ev.values())
    # the stray dump is in the key as stray / unconfirmed, never as a confirmed dump step
    conf_dump_uids = {u for s in d["steps"] if s["kind"] == "lsass_dump" and s["status"] == "confirmed" for u in s["event_uids"]}
    assert not ({r["event_uid"] for r in stray_dump} & conf_dump_uids)


# ====================================================================== (5) S04

def test_s04_track_b_confirmed_identity_1(real):
    d = draft_of(real, "s04_t00")
    c = confirmed(d)
    assert len(c) == 1
    b = c[0]
    assert b["account"] == "svc_backup" and b["identity_expected"] == 1 and b["basis"] == "command_names_target"
    assert any(b["hop_id"] in p["hop_ids"] for p in d["paths"])
    assert any(p["role"] == "attack_pair" for p in d["paths"] if b["hop_id"] in p["hop_ids"])


def track_a(d: dict) -> dict:
    cands = [h for h in d["hops"] if h["account"] == "admin_it" and h["source_host"] == "ep-01" and h["target_host"] == "ep-02"
             and any(h["hop_id"] in p["hop_ids"] for p in d["benign_paths"])]
    assert len(cands) == 1, [h["hop_id"] for h in cands]
    return cands[0]


def test_s04_track_a_unconfirmed_benign_identity_1_no_conflict(real):
    d = draft_of(real, "s04_t00")
    a = track_a(d)
    assert a["status"] == "unconfirmed"
    assert find(a, "proposed_role") and "benign" in find(a, "proposed_role")
    assert a["needs_owner_approval"] is True
    assert a["identity_expected"] == 1                       # decision 018
    assert a["identity_basis"]["move_after_dump"] is True and a["identity_basis"]["open_session_ids"]
    assert all("decision_conflict" not in h["flags"] for h in d["hops"])
    assert "decision_conflict" not in json.dumps(d["open_points"])
    assert not any(a["hop_id"] in p["hop_ids"] for p in d["paths"])


def test_s04_track_a_session_evidence_recorded_from_data(real):
    d = draft_of(real, "s04_t00")
    a = track_a(d)
    sid = find(a, "session_id")
    assert sid and sid[0] in {"0xd6398", "0xd663a", "0x17b18"}, sid
    assert find(a, "session_logon_type") and find(a, "splunkd_ancestor")
    assert find(a, "splunkd_ancestor")[0] is False            # no splunkd command naming ep-02 under admin_it (AK-08)


def test_s04_window_and_out_of_window_counted_not_failed(real):
    d = draft_of(real, "s04_t00")
    oc = d["window"]["outside_counts"]
    assert oc["target_side_events"] == sum(oc["per_hop"].values())
    rep = verify_mod.verify(d, db_path("s04_t00"))
    assert rep["ok"], rep["failures"][:3]
    assert rep["out_of_window"] >= 1                          # time_account_only hop events lie outside the key window


# ====================================================================== (6) S06 and tamper cases

def lsass_dump_rows(trial: str):
    return rows(trial, "SELECT * FROM events_dedup WHERE channel='Sysmon' AND event_id=10 AND source_image LIKE '%rundll32.exe' "
                       "AND target_image LIKE '%lsass.exe'")


def test_s06_no_dump_everywhere_all_identity_zero(real):
    assert lsass_dump_rows("s06_t00") == [], "data premise (decision 017) changed"
    d = draft_of(real, "s06_t00")
    assert [s for s in d["steps"] if s["kind"] == "lsass_dump" and s["event_uids"]] == []
    assert d["hops"]
    assert all(h["identity_expected"] == 0 for h in d["hops"])
    assert all("decision_conflict" not in h["flags"] for h in d["hops"])
    assert d["paths"] == []
    benign = {x for p in d["benign_paths"] for x in p["hop_ids"]}
    assert {h["hop_id"] for h in confirmed(d)} <= benign and benign


def test_s06_account_mismatch_recorded(real):
    d = draft_of(real, "s06_t00")
    # fixed expectations: (agent_account, cmd_credential_account, logon_account) per hop (decisions 023/024, AK-02)
    expect = {"s06-winrm-1": ("svc_backup", "admin_it", "admin_it"),
              "s06-winrm-2": ("svc_backup", "admin_it", "admin_it"),
              "s06-smb-1": ("svc_backup", "admin_it", "svc_backup")}
    for hid, (agent, cred, logon) in expect.items():
        h = hop_by_id(d, hid)
        assert (h["agent_account"], h["cmd_credential_account"], h["logon_account"]) == (agent, cred, logon), hid
        assert h["account_mismatch"] is True and "account_mismatch" in h["flags"], hid
        assert h["account"] == h["logon_account"], hid
        l4624 = [r for r in by_uid("s06_t00", h["target_event_uids"]).values() if r["event_id"] == 4624]
        assert {targets.normalise_account(r["account_name"]) for r in l4624} == {logon}, hid


def test_s06_inserted_dump_flips_identity_and_raises_decision_conflict(tmp_path):
    need_db("s06_t00")

    def edit(con):
        insert_event(con, host="ep-01", channel="Sysmon", event_id=10, event_utc="2026-10-12T09:02:30.000000Z",
                     process_guid="aaaaaaaa-0000-6ab4-0001-000000002200", process_id=7777, account_name="admin_it",
                     subject_account="lab\\admin_it", source_image="C:\\WINDOWS\\system32\\rundll32.exe",
                     target_image="C:\\WINDOWS\\system32\\lsass.exe", granted_access="0x1410")
        insert_event(con, host="ep-01", channel="Sysmon", event_id=10, event_utc="2026-10-12T09:02:30.400000Z",
                     process_guid="aaaaaaaa-0000-6ab4-0001-000000002200", process_id=7777, account_name="admin_it",
                     subject_account="lab\\admin_it", source_image="C:\\WINDOWS\\system32\\rundll32.exe",
                     target_image="C:\\WINDOWS\\system32\\lsass.exe", granted_access="0x1410")

    _, d = synth(tmp_path, "s06_t00", edit)
    flipped = [h for h in d["hops"] if h["identity_expected"] == 1]
    assert flipped, "identities did not flip"
    assert all("decision_conflict" in h["flags"] for h in flipped), [h["hop_id"] for h in flipped]
    assert len([s for s in d["steps"] if s["kind"] == "lsass_dump"]) == 1, "pair within 1 s must be one dump"


def test_ak18_deleting_track_a_ep01_logons_flips_to_zero_with_decision_conflict(tmp_path):
    need_db("s04_t00")

    def edit(con):
        con.execute("DELETE FROM events WHERE host='ep-01' AND event_id=4624 AND channel='Security' AND account_name='admin_it'")

    _, d = synth(tmp_path, "s04_t00", edit)
    a = track_a(d)
    assert a["identity_expected"] == 0
    assert "decision_conflict" in a["flags"]


# ====================================================================== (7) S07

def hop_service_and_logons(trial: str, h: dict):
    ev = by_uid(trial, h["target_event_uids"])
    svc = {(r["service_name"] or "").lower() for r in ev.values() if r["event_id"] in (7045, 4697)}
    logons = {r["target_logon_id"] for r in ev.values() if r["event_id"] == 4624}
    return svc, logons


def test_s07_two_hops_distinct_logons_and_services(real):
    d = draft_of(real, "s07_t00")
    c = confirmed(d)
    assert len(c) == 2
    x, y = c
    sx, lx = hop_service_and_logons("s07_t00", x)
    sy, ly = hop_service_and_logons("s07_t00", y)
    assert lx and ly and not (lx & ly), "hops share a 4624 logon id (merged)"
    ex = by_uid("s07_t00", x["target_event_uids"])
    ey = by_uid("s07_t00", y["target_event_uids"])
    l4624_x = {u for u, r in ex.items() if r["event_id"] == 4624}
    l4624_y = {u for u, r in ey.items() if r["event_id"] == 4624}
    assert l4624_x and l4624_y and not (l4624_x & l4624_y), "the two hops share a 4624 event"
    assert not ({u for u, r in ex.items() if r["event_id"] in (7045, 4697)} & {u for u, r in ey.items() if r["event_id"] in (7045, 4697)})
    assert {frozenset(sx), frozenset(sy)} == {frozenset({"xferservice"}), frozenset({"syncservice"})}, (sx, sy)
    assert x["hop_id"] != y["hop_id"]
    assert len({p["path_id"] for p in d["paths"]}) == 2


def test_s07_account_mismatch_and_handoff_account(real):
    d = draft_of(real, "s07_t00")
    assert any(h["account_mismatch"] and "account_mismatch" in h["flags"] for h in d["hops"])
    assert any(h["handoff_account"] == "svc_sql" for h in d["hops"])
    for h in confirmed(d):
        assert h["account"] == h["logon_account"]


def test_s07_records_which_ep01_dump_per_hop(real):
    d = draft_of(real, "s07_t00")
    for h in confirmed(d):
        u = h["identity_basis"]["dump_event_uid"]
        assert u
        r = by_uid("s07_t00", [u])[u]
        assert r["host"] == "ep-01" and r["event_id"] == 10
        assert parse(h["identity_basis"]["dump_time_utc"]) <= parse(h["move_time_utc"]) + timedelta(seconds=5)


# ====================================================================== (8) S05

def test_s05_hop2_uses_ep02_dump(real):
    d = draft_of(real, "s05_t00")
    c = confirmed(d)
    assert len(c) == 2
    h2 = next(h for h in c if h["protocol"] == "WinRM")
    assert (h2["source_host"], h2["target_host"], h2["account"]) == ("ep-02", "ep-03", "admin_it")
    ib = h2["identity_basis"]
    r = by_uid("s05_t00", [ib["dump_event_uid"]])[ib["dump_event_uid"]]
    assert r["host"] == "ep-02" and r["event_id"] == 10 and r["target_image"].lower().endswith("lsass.exe")
    assert h2["identity_expected"] == 1 and ib["move_after_dump"] is True and ib["open_session_ids"]
    h1 = next(h for h in c if h["protocol"] == "SMB")
    assert (h1["source_host"], h1["target_host"]) == ("ep-01", "ep-02")
    r1 = by_uid("s05_t00", [h1["identity_basis"]["dump_event_uid"]])[h1["identity_basis"]["dump_event_uid"]]
    assert r1["host"] == "ep-01"
    assert any([h1["hop_id"], h2["hop_id"]] == p["hop_ids"] for p in d["paths"]), "ordered two-hop attack path"


# ====================================================================== (9) target-name matching

IPMAP = dict(LAB_IP_HOST)


@pytest.mark.parametrize("text,expected", [
    (r"sc.exe \\192.168.50.22 create X", {"ep-02"}),
    (r"sc.exe \\192.168.50.2 create X", set()),
    (r"sc.exe \\192.168.50.220 create X", set()),
    (r"net use \\192.168.50.23\c$", {"ep-03"}),
    (r"dir \\ep-02.lab.local\admin$", {"ep-02"}),
    (r"dir \\EP-02\admin$", {"ep-02"}),
    (r"ping endpoint-03", {"ep-03"}),
    (r"ping ep-020", set()),
    (r"ping prep-02", set()),
    (r"ping ep-02x", set()),
    (r"ping 10.192.168.50.22", set()),
])
def test_find_targets_boundary_aware(text, expected):
    found, failed = targets.find_targets([text], IPMAP)
    assert found == expected and failed is False


def utf16b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()


def test_enc_payload_decoded_utf16le_for_matching():
    cmd = "powershell -NoP -enc " + utf16b64("Invoke-Command -ComputerName ep-03 -ScriptBlock { whoami }")
    dec, failed = targets.decode_encoded(cmd)
    assert failed is False and dec == ["Invoke-Command -ComputerName ep-03 -ScriptBlock { whoami }"]
    found, failed = targets.find_targets([cmd], IPMAP)
    assert found == {"ep-03"} and not failed
    cmd2 = "powershell -EncodedCommand " + utf16b64("Enter-PSSession 192.168.50.22")
    assert targets.find_targets([cmd2], IPMAP)[0] == {"ep-02"}


def test_enc_malformed_base64_sets_decode_failed():
    bad = "powershell -enc Zm9vZm9vZm9vZm9vZm9v"      # 15 bytes: odd length, not UTF-16LE
    dec, failed = targets.decode_encoded(bad)
    assert failed is True and dec == []
    found, failed = targets.find_targets([bad + " \\\\ep-02\\c$"], IPMAP)
    assert failed is True and found == {"ep-02"}


def test_account_normalisation_and_machine_accounts():
    assert targets.normalise_account("LAB\\Svc_Backup") == targets.normalise_account("svc_backup") == "svc_backup"
    assert targets.normalise_account("lab\\ADMIN_IT") == "admin_it"
    assert targets.is_user_account("LAB\\admin_it")
    for bad in ("SYSTEM", "ENDPOINT-02$", "-", "", None):
        assert not targets.is_user_account(bad)


def test_credential_account_parsed_before_masking():
    assert targets.credential_account([r"net use \\ep-02\c$ /user:LAB\admin_it Project123"]) == "admin_it"
    assert targets.credential_account(["New-Object PSCredential('LAB\\svc_backup', $pw)"]) == "svc_backup"


@pytest.mark.parametrize("cmd", [
    r"net use \\ep-02\c$ /user:LAB\admin_it Project123!",
    r"x.exe -Password Project123 y",
    r"x.exe /p:Project123 y",
    r"echo $env:LAB_PW and $env:SVCPWD",
])
def test_mask_command(cmd):
    out = targets.mask_command(cmd)
    assert PASSWORD not in out and "***" in out
    assert "$env:LAB_PW" not in out and "$env:SVCPWD" not in out


def synth_s02(tmp_path, edit):
    return synth(tmp_path, "s02_t00", edit)


AGENT_SPLUNKD_GUID = "c458e5dd-b6b8-6ab4-fa00-000000002200"      # svc_backup splunkd on ep-01 (S02 t00)


def agent_child(con, t: str, cmd: str, n: int, parent=AGENT_SPLUNKD_GUID, account="svc_backup", host="ep-01") -> str:
    return sysmon1(con, host, parse(t), f"deadbeef-{n:04x}-6ab4-0001-000000002200", parent, account,
                   "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmd,
                   parent_image="C:\\Users\\Public\\splunkd.exe", pid=50000 + n, ppid=7332)


def appears(draft: dict, uid: str) -> bool:
    return uid in json.dumps({k: v for k, v in draft.items() if k != "event_keys"})


def test_akt17_command_naming_target_without_4624_is_attempt(tmp_path):
    need_db("s02_t00")
    holder = {}

    def edit(con):
        holder["u"] = agent_child(con, "2026-09-24T05:44:00.000000Z", r"sc.exe \\ep-03 create Ghost binPath= C:\Windows\ghost.exe", 1)

    _, d = synth_s02(tmp_path, edit)
    u = holder["u"]
    assert not [h for h in d["hops"] if u in h["agent_event_uids"] and h["status"] == "confirmed"]
    att = [x for x in d["unconfirmed"] if x.get("reason") == "attempt_no_target_evidence" or "attempt_no_target_evidence" in x.get("flags", [])]
    assert att and any(u in x.get("agent_event_uids", x.get("event_uids", [])) for x in att)
    assert len(confirmed(d)) == 1, "real S02 hop must stay the only confirmed hop"


def test_akt17_source_own_name_is_not_a_target(tmp_path):
    need_db("s02_t00")
    holder = {}

    def edit(con):
        holder["u"] = agent_child(con, "2026-09-24T05:44:00.000000Z", "cmd.exe /c echo ep-01 192.168.50.21 endpoint-01.lab.local", 2)

    _, d = synth_s02(tmp_path, edit)
    u = holder["u"]
    assert not [h for h in d["hops"] if u in h["agent_event_uids"]], "self-named command became a hop"
    assert not [x for x in d["unconfirmed"] if x.get("target_host") == "ep-01" and u in json.dumps(x)]
    assert len(confirmed(d)) == 1


def test_akt17_two_targets_not_silently_first_picked(tmp_path):
    need_db("s02_t00")
    real_cmd_uid = {}

    def edit(con):
        r = con.execute("SELECT event_uid, command_line FROM events WHERE host='ep-01' AND event_id=1 AND channel='Sysmon' "
                        "AND command_line LIKE '%Copy-Item%PktDrop%' AND account_name='svc_backup'").fetchone()
        real_cmd_uid["u"] = r[0]
        con.execute("UPDATE events SET command_line=? WHERE event_uid=?", (r[1].rstrip('"') + '; ping ep-03"', r[0]))

    _, d = synth_s02(tmp_path, edit)
    u = real_cmd_uid["u"]
    assert appears(d, u), "command with two targets dropped from the key"
    assert not [h for h in confirmed(d) if u in h["agent_event_uids"]], "ambiguous two-target command was confirmed"


def test_akt17_decode_failure_makes_hop_unconfirmed(tmp_path):
    need_db("s02_t00")
    holder = {}

    def edit(con):
        r = con.execute("SELECT event_uid, command_line FROM events WHERE host='ep-01' AND event_id=1 AND channel='Sysmon' "
                        "AND command_line LIKE '%Copy-Item%PktDrop%' AND account_name='svc_backup'").fetchone()
        holder["u"] = r[0]
        con.execute("UPDATE events SET command_line=? WHERE event_uid=?", (r[1] + " -enc Zm9vZm9vZm9vZm9vZm9v", r[0]))

    _, d = synth_s02(tmp_path, edit)
    hs = [h for h in d["hops"] if holder["u"] in h["agent_event_uids"]]
    assert hs and all(h["status"] != "confirmed" for h in hs)
    assert any("decode_failed" in h["flags"] for h in hs)


# ====================================================================== (10) tolerance (AK-07, decision 014)

def s02_dump_uids():
    return [r["event_uid"] for r in rows("s02_t00", "SELECT event_uid FROM events_dedup WHERE channel='Sysmon' AND event_id=10 AND "
                                                    "host='ep-01' AND source_image LIKE '%rundll32.exe' AND target_image LIKE '%lsass.exe'")]


def s02_move_time() -> datetime:
    rs = rows("s02_t00", "SELECT event_utc FROM events_dedup WHERE host='ep-02' AND event_id=4624 AND source_ip='192.168.50.21' "
                         "AND account_name='svc_backup' ORDER BY event_utc LIMIT 1")
    return parse(rs[0]["event_utc"])


@pytest.mark.parametrize("dump_minus_move_s,identity,within", [(4, 1, True), (0, 1, True), (-4, 1, True), (-6, 1, False), (6, 0, False), (30, 0, False)])
def test_akt19_move_vs_dump_tolerance(tmp_path, dump_minus_move_s, identity, within):
    uids = s02_dump_uids()
    move = s02_move_time()

    def edit(con):
        for i, u in enumerate(sorted(uids)):
            t = move + timedelta(seconds=dump_minus_move_s, milliseconds=100 * i)
            con.execute("UPDATE events SET event_utc=?, timestamp_utc=? WHERE event_uid=?", (fmt(t), fmt(t), u))

    _, d = synth(tmp_path, "s02_t00", edit)
    hs = [h for h in d["hops"] if h["source_host"] == "ep-01" and h["target_host"] == "ep-02" and h["account"] == "svc_backup"
          and h["basis"] == "command_names_target"]
    assert len(hs) == 1
    h = hs[0]
    assert h["identity_expected"] == identity, (dump_minus_move_s, h["identity_basis"])
    assert ("order_within_tolerance" in h["flags"]) is within
    assert h["identity_basis"]["move_after_dump"] is bool(identity)


# ====================================================================== (11) verify.py

def test_verify_real_drafts_pass(real):
    for trial in real:
        rep = cmd_verify(trial, real[trial][0])
        assert rep["ok"], (trial, rep["failures"][:3])
        assert rep["checked"] > 0 and rep["per_kind"]
        assert isinstance(rep["out_of_window"], int)


def test_verify_negative_control_wrong_existing_uid(real, tmp_path):
    repo, d, _ = real["s02_t00"] if "s02_t00" in real else pytest.skip("db missing")
    d = json.loads(json.dumps(d))
    h = confirmed(d)[0]
    other = rows("s02_t00", "SELECT event_uid FROM events_dedup WHERE host='ep-02' AND event_id=4624 AND account_name!='svc_backup' LIMIT 1")
    other = other[0]["event_uid"] if other else rows("s02_t00", "SELECT event_uid FROM events_dedup WHERE host='ep-02' AND event_id=4634 LIMIT 1")[0]["event_uid"]
    victim = h["target_event_uids"][0]
    assert other not in h["target_event_uids"]
    h["target_event_uids"][0] = other                 # exists in DB, but is not the event the key meant
    rep = verify_mod.verify(d, db_path("s02_t00"))
    assert rep["ok"] is False and rep["failures"], "swapped uid not detected"
    # also swap together with the old key record: content key must disagree with the DB row
    d2 = json.loads(json.dumps(real["s02_t00"][1]))
    d2["event_keys"][victim] = dict(d2["event_keys"][victim], event_id=1)
    rep2 = verify_mod.verify(d2, db_path("s02_t00"))
    assert rep2["ok"] is False and any(f["type"] == "content_key_mismatch" for f in rep2["failures"])
    d3 = json.loads(json.dumps(real["s02_t00"][1]))
    d3["event_keys"][victim] = dict(d3["event_keys"][victim], host="ep-03")
    assert verify_mod.verify(d3, db_path("s02_t00"))["ok"] is False


def test_verify_missing_uid_detected(real):
    d = json.loads(json.dumps(draft_of(real, "s02_t00")))
    confirmed(d)[0]["target_event_uids"].append("0" * 64)
    rep = verify_mod.verify(d, db_path("s02_t00"))
    assert rep["ok"] is False and any(f["type"] == "missing_uid" for f in rep["failures"])


def test_verify_rejects_different_db_sha256(real):
    d = json.loads(json.dumps(draft_of(real, "s02_t00")))
    d["db_sha256"] = "0" * 64
    rep = verify_mod.verify(d, db_path("s02_t00"))
    assert rep["ok"] is False and any(f["type"] == "db_hash_mismatch" for f in rep["failures"])


def test_akt21_reordered_reingest_rejects_old_key(tmp_path):
    repo = make_repo(tmp_path, "s02_t00", link=False)
    cmd_build("s02_t00", repo)
    dbp = repo / "data" / "processed" / "s02_t00.sqlite3"
    con = sqlite3.connect(dbp)
    con.execute("UPDATE events SET source_line = source_line + 1 WHERE event_uid IN (SELECT event_uid FROM events LIMIT 5)")
    con.commit()
    con.close()
    assert run_cli("verify", "--trial", "s02_t00", "--repo", str(repo)) == 1
    rep = json.loads((repo / "out" / "answer_key" / "s02_t00" / "verify.json").read_text())
    assert rep["ok"] is False and rep["failures"][0]["type"] == "db_hash_mismatch"


def test_verify_out_of_window_counted_not_failed(real):
    d = json.loads(json.dumps(draft_of(real, "s02_t00")))
    base = verify_mod.verify(d, db_path("s02_t00"))
    d["window"]["start_utc"] = "2026-09-24T05:42:46.000Z"
    d["window"]["end_utc"] = "2026-09-24T05:42:47.000Z"
    rep = verify_mod.verify(d, db_path("s02_t00"))
    assert rep["ok"] is True and rep["out_of_window"] > base["out_of_window"]


def test_verify_counts_per_kind_match_db(real):
    d = draft_of(real, "s02_t00")
    rep = verify_mod.verify(d, db_path("s02_t00"))
    for kind, n in rep["per_kind"].items():
        ch, eid = kind.rsplit(" ", 1)
        assert n >= 1 and rows("s02_t00", "SELECT count(*) c FROM events_dedup WHERE channel=? AND event_id=?", (ch, int(eid)))[0]["c"] >= 1


def test_verify_every_uid_in_every_real_draft_exists(real):
    for trial, (repo, d, _) in real.items():
        refs = verify_mod.uids_with_context(d)
        assert refs
        ev = by_uid(trial, {u for u, _ in refs})
        missing = [(u, loc) for u, loc in refs if u not in ev]
        assert not missing, (trial, missing[:3])


# ====================================================================== (12) depth-3 chain, 4104

def test_akt16_depth3_agent_chain_found(tmp_path):
    need_db("s02_t00")
    guids = {"w1": "feedface-0001-6ab4-0001-000000002200", "w2": "feedface-0002-6ab4-0001-000000002200"}
    holder = {}

    def edit(con):
        r = con.execute("SELECT event_uid FROM events WHERE host='ep-01' AND event_id=1 AND channel='Sysmon' "
                        "AND command_line LIKE '%Copy-Item%PktDrop%' AND account_name='svc_backup'").fetchone()
        holder["u"] = r[0]
        cmd = "C:\\Windows\\System32\\cmd.exe"
        sysmon1(con, "ep-01", parse("2026-09-24T05:42:40.000000Z"), guids["w1"], AGENT_SPLUNKD_GUID, "svc_backup", cmd, "cmd.exe /c wrapper1",
                parent_image="C:\\Users\\Public\\splunkd.exe", pid=61001, ppid=7332)
        sysmon1(con, "ep-01", parse("2026-09-24T05:42:41.000000Z"), guids["w2"], guids["w1"], "svc_backup", cmd, "cmd.exe /c wrapper2",
                parent_image=cmd, pid=61002, ppid=61001)
        con.execute("UPDATE events SET parent_process_guid=?, parent_image=?, parent_process_id=61002 WHERE event_uid=?",
                    (guids["w2"], cmd, r[0]))

    _, d = synth_s02(tmp_path, edit)
    c = confirmed(d)
    assert len(c) == 1 and holder["u"] in c[0]["agent_event_uids"]
    assert c[0]["basis"] == "command_names_target" and (c[0]["source_host"], c[0]["target_host"]) == ("ep-01", "ep-02")


def test_akt16_4104_alone_never_confirms(tmp_path):
    need_db("s02_t00")

    def edit(con):
        cmd = r'Copy-Item C:\Users\Public\PktDrop.exe \\192.168.50.22\ADMIN$\PktDrop.exe; sc.exe \\192.168.50.22 create PktDropService binPath= C:\Windows\PktDrop.exe'
        con.execute("DELETE FROM events WHERE host='ep-01' AND event_id IN (1,4688) AND command_line LIKE '%PktDrop%'")
        insert_event(con, host="ep-01", channel="PowerShell", event_id=4104, event_utc="2026-09-24T05:42:46.700000Z",
                     command_line=cmd, field_values_json=json.dumps({"scriptblocktext": [cmd]}), account_name="svc_backup")

    _, d = synth_s02(tmp_path, edit)
    assert not confirmed(d), [h["hop_id"] for h in confirmed(d)]
    tao = [h for h in d["hops"] if h["basis"] == "time_account_only"]
    assert tao and all(h["status"] == "unconfirmed" for h in tao)
    # AK-05: the intended step is kept as unconfirmed with a reason, never dropped
    assert "s02-h1" in json.dumps({k: d[k] for k in ("steps", "unconfirmed", "hops")})
    assert not any(s["status"] == "confirmed" and s["kind"] in ("move", "service_exec") for s in d["steps"])


# ====================================================================== AK-10 dumps

def independent_dump_groups(trial: str) -> list[list[sqlite3.Row]]:
    rs = [r for r in lsass_dump_rows(trial) if (r["account_name"] or "").lower() not in ("system", "", "-") and not (r["account_name"] or "").endswith("$")]
    rs.sort(key=lambda r: (r["host"], r["process_guid"] or "", t_of(r)))
    groups: list[list] = []
    for r in rs:
        if groups and (groups[-1][-1]["host"], groups[-1][-1]["process_guid"]) == (r["host"], r["process_guid"]) \
                and (t_of(r) - t_of(groups[-1][-1])).total_seconds() <= 1.0:
            groups[-1].append(r)
        else:
            groups.append([r])
    return groups


@pytest.mark.parametrize("trial", ["s02_t00", "s04_t00", "s05_t00", "s07_t00"])
def test_ak10_one_dump_step_per_pair_and_only_rundll32(real, trial):
    d = draft_of(real, trial)
    groups = independent_dump_groups(trial)
    steps = [s for s in d["steps"] if s["kind"] == "lsass_dump" and s["event_uids"]]
    assert len(steps) == len(groups), (len(steps), len(groups))
    step_uids = {u for s in steps for u in s["event_uids"]}
    assert step_uids == {r["event_uid"] for g in groups for r in g}
    ev = by_uid(trial, step_uids)
    assert all(r["source_image"].lower().endswith("\\rundll32.exe") for r in ev.values()), "VBoxService/svchost used as dump"
    assert not [r for r in ev.values() if (r["account_name"] or "").lower() == "system"]
    for s in steps:
        assert s["host"] and s["time_utc"]


def test_akt10_single_surviving_record_still_counts(tmp_path):
    need_db("s02_t00")
    uids = s02_dump_uids()
    assert len(uids) == 2

    def edit(con):
        con.execute("DELETE FROM events WHERE event_uid=?", (sorted(uids)[0],))

    _, d = synth(tmp_path, "s02_t00", edit)
    steps = [s for s in d["steps"] if s["kind"] == "lsass_dump" and s["host"] == "ep-01" and s["event_uids"]]
    assert len(steps) == 1 and len(steps[0]["event_uids"]) == 1
    assert confirmed(d)[0]["identity_expected"] == 1


def test_akt10b_non_user_lsass_access_never_a_dump(real):
    for trial in ("s02_t00", "s06_t00"):
        d = draft_of(real, trial)
        sysacc = {r["event_uid"] for r in rows(trial, "SELECT event_uid FROM events_dedup WHERE channel='Sysmon' AND event_id=10 "
                                                      "AND target_image LIKE '%lsass.exe' AND (source_image LIKE '%VBoxService.exe' OR source_image LIKE '%svchost.exe')")}
        used = {u for s in d["steps"] if s["kind"] == "lsass_dump" for u in s["event_uids"]}
        used |= {u for h in d["hops"] for u in h["identity_basis"].get("dump_event_uids", [])}
        assert not (sysacc & used)


# ====================================================================== AK-07 source host, accounts

def independent_identity(trial: str, host: str, account: str, move: datetime) -> int:
    """Correction K from raw SQL only: latest domain-user rundll32->lsass dump on `host` at or before move+5 s,
    and a session of `account` on `host` with logon <= dump that no 4634 (logon < logoff <= dump) closed."""
    dumps = [min(t_of(r) for r in g) for g in independent_dump_groups(trial) if g[0]["host"] == host]
    dumps = [t for t in dumps if t <= move + timedelta(seconds=5)]
    if not dumps:
        return 0
    dump = max(dumps)
    logons = rows(trial, "SELECT target_logon_id, event_utc, logon_type, account_name FROM events_dedup WHERE host=? AND event_id=4624 "
                         "AND channel='Security'", (host,))
    for r in logons:
        if (r["account_name"] or "").lower() != account or r["target_logon_id"] in (0x3E4, 0x3E5, 0x3E7):
            continue
        if not r["logon_type"] or parse(r["event_utc"]) > dump:
            continue
        offs = rows(trial, "SELECT event_utc FROM events_dedup WHERE host=? AND event_id=4634 AND target_logon_id=?", (host, r["target_logon_id"]))
        if any(parse(r["event_utc"]) < parse(o["event_utc"]) <= dump for o in offs):
            continue
        return 1
    return 0


# fixed known identity values (decisions 017, 018, 022, 023, 024; Correction K)
KNOWN_IDENTITY = {"s02-h1": 1, "s03-h1": 1, "s04-A-h1": 1, "s04-B-h1": 1, "s04-t1": 0, "s05-h1": 1, "s05-h2": 1, "s05-t1": 0,
                  "s06-winrm-1": 0, "s06-winrm-2": 0, "s06-smb-1": 0, "s06-t1": 0, "s07-h-x": 1, "s07-h-y": 1, "s07-t1": 0}


@pytest.mark.parametrize("trial", TRIALS)
def test_ak07_hop_account_and_source_host_from_target_4624(real, trial):
    d = draft_of(real, trial)
    for h in d["hops"]:
        assert h["account"] == h["logon_account"]
        ev = by_uid(trial, h["target_event_uids"])
        l4624 = [r for r in ev.values() if r["event_id"] == 4624]
        assert l4624, f"{h['hop_id']} has no 4624 in target_event_uids"
        assert all(targets.normalise_account(r["account_name"]) == h["logon_account"] for r in l4624)
        assert {LAB_IP_HOST.get(r["source_ip"]) for r in l4624} == {h["source_host"]}, h["hop_id"]
        assert all(r["host"] == h["target_host"] and r["logon_type"] in (3, 10) for r in l4624)
        assert h["move_time_utc"] <= fmt(max(t_of(r) for r in l4624))
        # identity value: fixed known value AND an independent SQL computation (not the hop's own identity_basis)
        assert h["identity_expected"] == KNOWN_IDENTITY[h["hop_id"]], h["hop_id"]
        move = min(t_of(r) for r in l4624)
        assert h["identity_expected"] == independent_identity(trial, h["source_host"], h["logon_account"], move), h["hop_id"]


@pytest.mark.parametrize("trial", ["s02_t00", "s04_t00", "s05_t00", "s07_t00"])
def test_ak07_open_sessions_belong_to_moving_account_on_source_host(real, trial):
    d = draft_of(real, trial)
    for h in d["hops"]:
        sessions = h["identity_basis"].get("open_sessions", [])
        assert [s["logon_id_hex"] for s in sessions] == h["identity_basis"]["open_session_ids"]
        if not sessions:
            continue
        ev = by_uid(trial, [s["event_uid"] for s in sessions])
        for s in sessions:
            r = ev[s["event_uid"]]
            assert r["host"] == h["source_host"] and r["event_id"] == 4624
            assert targets.normalise_account(r["account_name"]) == h["account"]
            assert s["logon_type"] == r["logon_type"] and s["exposure_strength"] == (
                "strong" if r["logon_type"] in (2, 7, 10, 11, 4, 5) else "weak")
            assert hex(r["target_logon_id"]) == s["logon_id_hex"]
            assert r["target_logon_id"] not in (0x3E4, 0x3E5, 0x3E7)
            assert t_of(r) <= parse(h["identity_basis"]["dump_time_utc"])


# ====================================================================== AK-12 window

@pytest.mark.parametrize("trial", TRIALS)
def test_ak12_window_from_all_non_agent_start_steps(real, trial):
    d = draft_of(real, trial)
    # independent step times: a step time must equal the DB time of one of the step's own events
    times: list[datetime] = []
    for s in d["steps"]:
        if s["kind"] == "agent_start" or not s["time_utc"]:
            continue
        if s["event_uids"]:
            ev = by_uid(trial, s["event_uids"])
            assert ev, f"step {s['step_id']} has uids that are not in the DB"
            db_times = [t_of(r) for r in ev.values()]
            assert min(abs((parse(s["time_utc"]) - t).total_seconds()) for t in db_times) < 0.002, \
                f"step {s['step_id']} time {s['time_utc']} equals none of its events' times"
        times.append(parse(s["time_utc"]))
    assert times
    w = d["window"]
    assert abs((parse(w["start_utc"]) - (min(times) - timedelta(seconds=60))).total_seconds()) < 0.002
    assert abs((parse(w["end_utc"]) - (max(times) + timedelta(seconds=300))).total_seconds()) < 0.002
    assert w["source"] == "key"
    for h in confirmed(d):
        assert w["start_utc"] <= h["move_time_utc"] <= w["end_utc"]
    oc = w["outside_counts"]
    assert oc["target_side_events"] == sum(oc["per_hop"].values())
    assert set(oc["per_hop"]) <= {h["hop_id"] for h in d["hops"]}
    # outside events are counted, not moved to unconfirmed[] on position alone: confirmed hops stay confirmed
    for hid in oc["per_hop"]:
        assert hop_by_id(d, hid)["status"] in ("confirmed", "unconfirmed")


# ====================================================================== (13) fields, masking

@pytest.mark.parametrize("trial", TRIALS)
def test_drafts_never_contain_lab_password(real, trial):
    text = (real[trial][0] / "ground_truth" / "drafts" / f"{trial}.yaml").read_text(encoding="utf-8") if trial in real else pytest.skip("db missing")
    assert PASSWORD not in text
    for m in re.finditer(r"(?i)-(?:e|enc|ec|encodedcommand)\s+([A-Za-z0-9+/]{16,}={0,2})", text):
        try:
            dec = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode("utf-16-le")
        except Exception:
            continue
        assert PASSWORD not in dec, "password inside an -enc payload left in the draft"
    for m in re.finditer(r"(?i)/user:\S+\s+(\S+)", text):
        assert m.group(1).startswith("***"), f"unmasked /user: password {m.group(0)[:40]}"
    assert not re.search(r"(?i)-Password\s+(?!\*\*\*)\S", text)
    assert not re.search(r"(?i)/p:(?!\*\*\*)\S", text)
    assert not re.search(r"(?i)\$env:[A-Za-z0-9_]*PW", text)


def test_committed_drafts_in_repo_also_mask_password():
    for p in (REPO / "ground_truth" / "drafts").glob("s0[2-7]_t00.yaml"):
        assert PASSWORD not in p.read_text(encoding="utf-8"), p.name


def test_password_premise_exists_in_a_db(real):
    """Control: if no DB command line holds the password, the masking tests prove nothing."""
    hit = False
    for trial in real:
        if rows(trial, "SELECT 1 FROM events_dedup WHERE command_line LIKE ? LIMIT 1", (f"%{PASSWORD}%",)):
            hit = True
    if not hit:
        pytest.skip("no command line with the lab password in these DBs; masking checked on unit strings only")


@pytest.mark.parametrize("trial", ["s04_t00", "s06_t00"])
def test_agent_commands_masked_when_password_in_db(real, trial):
    d = draft_of(real, trial)
    pw_rows = rows(trial, "SELECT command_line FROM events_dedup WHERE command_line LIKE ?", (f"%{PASSWORD}%",))
    cmds = find(d, "agent_command")
    assert all(PASSWORD not in c for c in cmds)
    if pw_rows:
        assert any("***" in c for c in cmds) or not cmds


# ====================================================================== decisions 021-025: pinned expectations on the real drafts

def test_dec021_s04_track_a_source_session_is_desktop_0xd6398(real):
    d = draft_of(real, "s04_t00")
    a = hop_by_id(d, "s04-A-h1")
    assert (a["source_host"], a["target_host"], a["account"]) == ("ep-01", "ep-02", "admin_it")
    assert find(a, "session_id") == ["0xd6398"] and find(a, "session_logon_type") == [11]
    assert a["status"] == "unconfirmed" and a["identity_expected"] == 1 and a["needs_owner_approval"] is True
    assert a["proposed_role"] == "benign" and find(a, "splunkd_ancestor") == [False]
    assert "0xd6398" in a["identity_basis"]["open_session_ids"]
    # independent DB evidence for the session: a type 11 admin_it 4624 on ep-01 with logon id 0xd6398
    r = rows("s04_t00", "SELECT account_name, logon_type FROM events_dedup WHERE host='ep-01' AND event_id=4624 AND target_logon_id=?", (0xd6398,))
    assert r and all((x["account_name"], x["logon_type"]) == ("admin_it", 11) for x in r)
    assert [p["hop_ids"] for p in d["benign_paths"]] == [["s04-A-h1"]]


def test_dec022_s05_hop2_ep02_to_ep03_tier_a_uses_ep02_dump(real):
    d = draft_of(real, "s05_t00")
    h = hop_by_id(d, "s05-h2")
    assert (h["protocol"], h["source_host"], h["target_host"], h["account"]) == ("WinRM", "ep-02", "ep-03", "admin_it")
    assert h["confidence_tier"] == "A" and h["identity_expected"] == 1 and h["status"] == "confirmed"
    ib = h["identity_basis"]
    assert ib["dump_time_utc"].startswith("2026-10-12T07:11:49.7") and ib["dump_host"] == "ep-02"
    r = by_uid("s05_t00", [ib["dump_event_uid"]])[ib["dump_event_uid"]]
    assert (r["host"], r["event_id"]) == ("ep-02", 10) and fmt(t_of(r)).startswith("2026-10-12T07:11:49.7")
    assert [p["hop_ids"] for p in d["paths"]] == [["s05-h1", "s05-h2"]]


def test_dec023_s07_two_hops_fixed_values(real):
    d = draft_of(real, "s07_t00")
    x, y = hop_by_id(d, "s07-h-x"), hop_by_id(d, "s07-h-y")
    assert [c["hop_id"] for c in confirmed(d)] == ["s07-h-x", "s07-h-y"]
    assert (x["target_logon_id"], y["target_logon_id"]) == ("0x49cdfa", "0x4b5d51")
    sx, lx = hop_service_and_logons("s07_t00", x)
    sy, ly = hop_service_and_logons("s07_t00", y)
    assert sx == {"xferservice"} and sy == {"syncservice"}
    assert 0x49cdfa in lx and 0x4b5d51 in ly and not (lx & ly)     # a hop may hold a burst of logons; the anchor is its own
    assert x["candidate_count"] == 1
    assert x["account"] == y["account"] == "svc_backup"
    assert y["cmd_credential_account"] == "svc_sql" and y["handoff_account"] == "svc_sql"
    assert y["account_mismatch"] is True and "account_mismatch" in y["flags"]


def test_dec024_s06_all_hops_identity_zero_and_all_in_benign_paths(real):
    d = draft_of(real, "s06_t00")
    assert {h["hop_id"] for h in d["hops"]} == {"s06-winrm-1", "s06-winrm-2", "s06-smb-1", "s06-t1"}
    assert all(h["identity_expected"] == 0 for h in d["hops"])
    assert {x for p in d["benign_paths"] for x in p["hop_ids"]} == {h["hop_id"] for h in d["hops"]}
    assert all(p["role"] == "benign" for p in d["benign_paths"]) and d["paths"] == []
    smb = hop_by_id(d, "s06-smb-1")
    assert smb["candidate_count"] == 1 and len(smb["credential_logon_uids"]) == 1
    cl = by_uid("s06_t00", smb["credential_logon_uids"])
    assert all((r["event_id"], r["account_name"], r["host"], r["source_ip"]) == (4624, "admin_it", "ep-02", "192.168.50.21") for r in cl.values())
    w1 = hop_by_id(d, "s06-winrm-1")
    assert w1["candidate_count"] == 1 and w1["related_logon_uids"]
    rl = by_uid("s06_t00", w1["related_logon_uids"])
    assert all((r["event_id"], r["account_name"], r["host"]) == (4624, "admin_it", "ep-02") for r in rl.values())
    assert not (set(w1["related_logon_uids"]) & set(w1["target_event_uids"]))


def test_dec025_s03_dedicated_winrm_hop(real):
    d = draft_of(real, "s03_t00")
    h = hop_by_id(d, "s03-h1")
    assert [c["hop_id"] for c in confirmed(d)] == ["s03-h1"]
    assert (h["protocol"], h["source_host"], h["target_host"], h["account"]) == ("WinRM", "ep-01", "ep-03", "admin_it")
    assert h["identity_expected"] == 1 and h["confidence_tier"] == "A" and h["basis"] == "command_names_target"
    assert "handoff_mismatch" in h["flags"] and h["target_binding"] == "logon_id_artifact"
    ev = by_uid("s03_t00", h["target_event_uids"])
    wsm = [r for r in ev.values() if (r["image"] or "").lower().endswith("wsmprovhost.exe") or (r["channel"], r["event_id"]) == ("WinRM", 91)]
    assert wsm, "no wsmprovhost / WinRM 91 artefact in the hop"
    l4624 = [r for r in ev.values() if r["event_id"] == 4624]
    assert l4624 and {r["source_ip"] for r in l4624} == {"192.168.50.21"} and {r["host"] for r in l4624} == {"ep-03"}


def test_s02_stray_target_side_events_listed_and_not_in_hop(real):
    d = draft_of(real, "s02_t00")
    h = hop_by_id(d, "s02-h1")
    stray_ids = [u for e in d["unconfirmed"] if e.get("role") == "stray" for u in e.get("stray_target_side_event_uids", [])]
    assert stray_ids, "stray_target_side_event_uids empty"
    ev = by_uid("s02_t00", stray_ids)
    assert set(ev) == set(stray_ids)
    assert {r["event_id"] for r in ev.values()} <= {5140, 5145, 7045, 4697} and {r["host"] for r in ev.values()} == {"ep-02"}
    assert all(parse("2026-09-24T05:42:00Z") <= t_of(r) <= parse("2026-09-24T05:42:10Z") for r in ev.values())
    assert 7045 in {r["event_id"] for r in ev.values()}
    assert not (set(stray_ids) & set(h["target_event_uids"]))


def test_ak17_leftover_hops_only_inside_run_interval(real):
    for trial in real:
        d = draft_of(real, trial)
        ri = d["agent"]["run_interval"]
        lo, hi = parse(ri["start_utc"]), parse(ri["end_utc"])
        for h in d["hops"]:
            assert lo <= parse(h["move_time_utc"]) <= hi, (trial, h["hop_id"], h["move_time_utc"], ri)

    def at(trial, hhmmss):
        return [h["hop_id"] for h in draft_of(real, trial)["hops"] if h["move_time_utc"][11:19] == hhmmss]

    assert at("s06_t00", "07:05:15") == [] and at("s07_t00", "07:05:15") == []
    assert at("s05_t00", "07:05:15") == ["s05-t1"] and at("s07_t00", "09:11:08") == ["s07-t1"]
    for trial, hid in (("s05_t00", "s05-t1"), ("s07_t00", "s07-t1")):
        h = hop_by_id(draft_of(real, trial), hid)
        assert h["basis"] == "time_account_only" and h["status"] == "unconfirmed" and h["account"] == "admin_it"


def test_ak18_system_dumps_ignored_lists_s02_ep02_system_dump(real):
    d = draft_of(real, "s02_t00")
    db_sys = {r["event_uid"] for r in rows("s02_t00", "SELECT event_uid FROM events_dedup WHERE channel='Sysmon' AND event_id=10 AND host='ep-02' "
                                                      "AND source_image LIKE '%rundll32.exe' AND target_image LIKE '%lsass.exe' AND account_name='system'")}
    assert db_sys
    ent = [e for e in d["system_dumps_ignored"] if e["host"] == "ep-02"]
    assert len(ent) == 1 and set(ent[0]["event_uids"]) == db_sys and ent[0]["count"] >= 1 and "system" in ent[0]["accounts"]


# ====================================================================== AK-18 sessions (synthetic)

SESSION_ID = 2476739     # 0x25cac3: type 4 svc_backup logon on ep-01 at 05:35:51.41 (S02 t00), open at the 05:42 dump


def s02_hop(d: dict) -> dict:
    return hop_by_id(d, "s02-h1")


def test_ak18_logoff_with_reused_id_before_logon_does_not_close(tmp_path):
    need_db("s02_t00")
    assert rows("s02_t00", "SELECT 1 FROM events_dedup WHERE host='ep-01' AND event_id=4624 AND target_logon_id=? AND account_name='svc_backup'", (SESSION_ID,))

    def edit(con):
        insert_event(con, host="ep-01", channel="Security", event_id=4634, event_utc="2026-09-24T05:30:00.000000Z",
                     target_logon_id=SESSION_ID, logon_type=4)

    _, d = synth(tmp_path, "s02_t00", edit)
    h = s02_hop(d)
    assert h["identity_expected"] == 1 and "0x25cac3" in h["identity_basis"]["open_session_ids"]


def test_ak18_logoff_after_logon_before_dump_closes_session(tmp_path):
    need_db("s02_t00")

    def edit(con):
        insert_event(con, host="ep-01", channel="Security", event_id=4634, event_utc="2026-09-24T05:36:00.000000Z",
                     target_logon_id=SESSION_ID, logon_type=4)

    _, d = synth(tmp_path, "s02_t00", edit)
    h = s02_hop(d)
    assert "0x25cac3" not in h["identity_basis"]["open_session_ids"]
    assert h["identity_expected"] == 0 and h["identity_basis"]["identity_if_unknown_counted"] == 0


def test_ak18_dropping_the_4634_of_a_closed_session_counts_it_open(tmp_path):
    need_db("s02_t00")
    closed_id = 2475862     # svc_backup type 4 on ep-01, logon 05:35:51.23, 4634 at 05:35:51.26 (before the 05:42 dump)
    assert rows("s02_t00", "SELECT 1 FROM events_dedup WHERE host='ep-01' AND event_id=4634 AND target_logon_id=?", (closed_id,))
    _, d0 = synth(tmp_path / "a", "s02_t00")
    assert hex(closed_id) not in s02_hop(d0)["identity_basis"]["open_session_ids"]

    def edit(con):
        con.execute("DELETE FROM events WHERE host='ep-01' AND event_id=4634 AND target_logon_id=?", (closed_id,))

    _, d = synth(tmp_path / "b", "s02_t00", edit)
    ib = s02_hop(d)["identity_basis"]
    assert hex(closed_id) in ib["open_session_ids"], "session without a logoff must count as open (decision 004)"
    assert s02_hop(d)["identity_expected"] == 1 and ib["identity_if_unknown_counted"] == 1


def test_ak18_boot_marker_makes_session_end_unknown_not_counted(tmp_path):
    need_db("s02_t00")

    def edit(con):
        insert_event(con, host="ep-01", channel="System", event_id=6005, event_utc="2026-09-24T05:38:00.000000Z")

    _, d = synth(tmp_path, "s02_t00", edit)
    h = s02_hop(d)
    ib = h["identity_basis"]
    assert "0x25cac3" in ib["end_unknown_ids"] and "0x25cac3" not in ib["open_session_ids"]
    assert "end_unknown" in h["flags"]
    assert ib["identity_if_unknown_counted"] == 1
    assert h["identity_expected"] == (1 if ib["open_session_ids"] else 0)


# ====================================================================== source_host_conflict (synthetic)

def retarget_source_ip(con, new_ip: str):
    con.execute("UPDATE events SET source_ip=? WHERE host='ep-02' AND event_id=4624 AND source_ip='192.168.50.21' "
                "AND event_utc BETWEEN '2026-09-24T05:42:30' AND '2026-09-24T05:43:00'", (new_ip,))


def test_source_host_conflict_other_endpoint_ip(tmp_path):
    need_db("s02_t00")
    _, d = synth(tmp_path, "s02_t00", lambda con: retarget_source_ip(con, "192.168.50.23"))
    h = s02_hop(d)
    assert h["status"] == "confirmed" and h["source_host"] == "ep-03"
    assert "source_host_conflict" in h["flags"]
    assert h["identity_basis"]["dump_host"] == "ep-03"          # decision 013: the IP host, not the command host
    assert h["identity_expected"] == 0                           # ep-03 has no dump in S02


def test_source_host_conflict_unmapped_ip_gives_null_source(tmp_path):
    need_db("s02_t00")
    _, d = synth(tmp_path, "s02_t00", lambda con: retarget_source_ip(con, "192.168.50.199"))
    h = s02_hop(d)
    assert h["source_host"] is None and "source_host_conflict" in h["flags"]
    assert h["identity_expected"] == 0 and h["account"] == "svc_backup"


# ====================================================================== AKT-03 two services of one name (synthetic)

def test_akt03_two_services_same_name_never_silent_first_pick(tmp_path):
    need_db("s07_t00")
    holder = {}

    def edit(con):
        holder["u"] = insert_event(con, host="ep-02", channel="System", event_id=7045, event_utc="2026-10-12T09:17:59.000000Z",
                                   service_name="XferService", service_image_path="C:\\Windows\\Xpay.exe", account_name="svc_backup")

    repo, d = synth(tmp_path, "s07_t00", edit)
    x = hop_by_id(d, "s07-h-x")
    dbp = repo / "data" / "processed" / "s07_t00.sqlite3"
    con = sqlite3.connect(dbp)
    in_hop = [r[0] for r in con.execute(f"SELECT event_uid FROM events WHERE event_id=7045 AND event_uid IN ({','.join('?' * len(x['target_event_uids']))})",
                                        x["target_event_uids"])]
    con.close()
    both = holder["u"] in in_hop and len(in_hop) == 2
    neither = not in_hop
    assert both or neither or x["status"] != "confirmed", "exactly one of two same-name services silently taken"
    assert x["service_candidates_by_name"] == 2 or x["status"] != "confirmed"
    assert holder["u"] not in hop_by_id(d, "s07-h-y")["target_event_uids"]


# ====================================================================== PSCredential quote styles, splunkd exact path

@pytest.mark.parametrize("cmd", [
    "$c = New-Object System.Management.Automation.PSCredential('LAB\\admin_it', $pw)",
    '$c = New-Object System.Management.Automation.PSCredential("LAB\\admin_it", $pw)',
    '$c = New-Object System.Management.Automation.PSCredential(\\"LAB\\admin_it\\",$pw)',
])
def test_pscredential_account_three_quote_styles(cmd):
    assert targets.credential_account([cmd]) == "admin_it"


def test_is_splunkd_requires_exact_agent_path():
    from answer_key import agent_tree
    assert agent_tree.is_splunkd("C:\\Users\\Public\\splunkd.exe")
    assert agent_tree.is_splunkd("c:\\users\\public\\SPLUNKD.EXE")
    for bad in ("C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunkd.exe", "C:\\Users\\Public\\x\\splunkd.exe",
                "D:\\Users\\Public\\splunkd.exe", "splunkd.exe", "-", "", None):
        assert not agent_tree.is_splunkd(bad), bad


def test_child_of_other_splunkd_path_is_not_an_agent_command(tmp_path):
    need_db("s02_t00")
    holder = {}

    def edit(con):
        holder["u"] = sysmon1(con, "ep-01", parse("2026-09-24T05:44:00.000000Z"), "cafebabe-0001-6ab4-0001-000000002200",
                              "cafebabe-0000-6ab4-0001-000000002200", "svc_backup",
                              "C:\\Windows\\System32\\cmd.exe", r"sc.exe \\ep-03 create Foo binPath= C:\Windows\foo.exe",
                              parent_image="C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunkd.exe", pid=62000, ppid=7000)

    _, d = synth(tmp_path, "s02_t00", edit)
    u = holder["u"]
    # AK-04: a command not under the agent tree is at most listed as unconfirmed; never an agent-tree confirmation
    assert not [h for h in d["hops"] if u in h["agent_event_uids"] and (h["status"] == "confirmed" or h["basis"] == "command_names_target")]
    assert not any(u in p_uids for p_uids in [s["event_uids"] for s in d["steps"] if s["status"] == "confirmed"])
    assert all(x["kind"] in ("attempt", "hop", "step") and x.get("role") != "attack" for x in d["unconfirmed"] if appears(x, u))
    assert not appears({"paths": d["paths"]}, u)
    assert len(confirmed(d)) == 1


# ====================================================================== flags: clock_order_disagree, midnight

def test_clock_order_disagree_is_an_allowed_flag_and_is_raised(tmp_path):
    assert "clock_order_disagree" in ALLOWED_FLAGS
    need_db("s02_t00")
    uids = sorted(s02_dump_uids())
    _, d0 = synth(tmp_path / "base", "s02_t00")
    h0 = s02_hop(d0)
    t0 = parse(h0["agent_command_time_utc"])
    move = parse(h0["move_time_utc"])
    assert abs((move - t0).total_seconds()) < 4, "premise: command and 4624 within the 5 s tolerance"
    dump_t = t0 + timedelta(seconds=1)     # dump after the agent command on ep-01's clock; the 4624 (ep-02 clock) is still >= dump - 5 s

    def edit(con):
        for i, u in enumerate(uids):
            t = dump_t + timedelta(milliseconds=50 * i)
            con.execute("UPDATE events SET event_utc=?, timestamp_utc=? WHERE event_uid=?", (fmt(t), fmt(t), u))

    _, d = synth(tmp_path / "x", "s02_t00", edit)
    h = s02_hop(d)
    assert h["identity_basis"]["move_after_dump"] is True
    assert h["identity_basis"]["dump_before_agent_command_source_clock"] is False
    assert "clock_order_disagree" in h["flags"] and set(h["flags"]) <= ALLOWED_FLAGS


def test_run_day_spans_midnight_flag(tmp_path):
    need_db("s02_t00")

    def edit(con):
        agent_child(con, "2026-09-23T23:55:00.000000Z", "cmd.exe /c echo early", 70, parent="feedbeef-0000-6ab4-0001-000000002200")

    _, d = synth(tmp_path / "x", "s02_t00", edit)
    assert "run_day_spans_midnight" in d["flags"]
    assert d["agent"]["run_days"] == ["2026-09-23", "2026-09-24"]
    _, d0 = synth(tmp_path / "plain", "s02_t00")
    assert "run_day_spans_midnight" not in d0["flags"] and d0["agent"]["run_days"] == ["2026-09-24"]


# ====================================================================== verify: wrong_event_type, logon_uids

def test_verify_rejects_uid_of_wrong_event_type(real):
    d = json.loads(json.dumps(draft_of(real, "s02_t00")))
    h = hop_by_id(d, "s02-h1")
    ev = by_uid("s02_t00", h["target_event_uids"])
    u4624 = next(u for u, r in ev.items() if r["event_id"] == 4624)
    assert u4624 in d["event_keys"]
    h["agent_event_uids"].append(u4624)                # a 4624 is not a process-creation record
    rep = verify_mod.verify(d, db_path("s02_t00"))
    bad = [f for f in rep["failures"] if f["type"] == "wrong_event_type"]
    assert rep["ok"] is False and bad and bad[0]["uid"] == u4624 and bad[0]["at"].endswith("/agent_event_uids")
    assert bad[0]["found"] == "Security 4624"
    assert not [f for f in rep["failures"] if f["type"] != "wrong_event_type"]


def test_verify_checks_logon_uid_lists(real):
    d = json.loads(json.dumps(draft_of(real, "s06_t00")))
    smb = hop_by_id(d, "s06-smb-1")
    ev = by_uid("s06_t00", smb["target_event_uids"])
    u5145 = next(u for u, r in ev.items() if r["event_id"] != 4624)      # any non-logon target-side event
    smb["credential_logon_uids"] = [u5145]
    w1 = hop_by_id(d, "s06-winrm-1")
    w1["related_logon_uids"] = ["0" * 64]
    rep = verify_mod.verify(d, db_path("s06_t00"))
    types = {(f["type"], f["uid"]) for f in rep["failures"]}
    assert ("wrong_event_type", u5145) in types and ("missing_uid", "0" * 64) in types
    assert rep["ok"] is False
