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
PASSWORD = "FakePw-0001"
LAB_IP_HOST = {"192.168.50.21": "ep-01", "192.168.50.22": "ep-02", "192.168.50.23": "ep-03"}

HOP_FIELDS = ["hop_id", "protocol", "source_host", "target_host", "account", "move_time_utc", "basis", "status",
              "agent_event_uids", "target_event_uids", "identity_expected", "identity_basis", "time_delta_ms",
              "confidence_tier", "handoff_step", "handoff_account", "agent_account", "cmd_credential_account",
              "logon_account", "account_mismatch", "target_binding", "candidate_count", "needs_owner_approval",
              "flags", "role"]
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

@pytest.mark.slow
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


@pytest.mark.slow
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
        assert h["basis"] in {"command_names_target", "manual_command_names_target", "time_account_only"}   # AK-20
        assert h["role"] in {"attack", "benign", "background"}                          # AK-19
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


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_steps_fields_and_paths(real, trial):
    d = draft_of(real, trial)
    for s in d["steps"]:
        for f in STEP_FIELDS:
            assert f in s, f"step {s.get('step_id')} missing {f}"
        assert s["kind"] in {"agent_start", "lsass_dump", "move", "service_exec", "benign"}
        assert s["status"] in {"confirmed", "unconfirmed"}
        # spec 3 lists agent_tree|target_side; the manual basis (AK-20) needs a third source value (spec gap, reported)
        assert s["source"] in {"agent_tree", "target_side", "manual_session"}
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


@pytest.mark.slow
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


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_time_account_only_never_confirmed_and_confirmed_names_target(real, trial):
    d = draft_of(real, trial)
    ev = by_uid(trial, [u for h in d["hops"] for u in h["agent_event_uids"]])
    for h in d["hops"]:
        if h["basis"] == "time_account_only":
            assert h["status"] != "confirmed", h["hop_id"]
        if h["status"] == "confirmed":
            assert h["basis"] in {"command_names_target", "manual_command_names_target"}   # AK-02 / AK-20
            assert h["agent_event_uids"], f"{h['hop_id']} confirmed without agent command"
            assert h["source_host"] != h["target_host"]
            texts = [t for u in h["agent_event_uids"] for t in all_texts(ev[u]["command_line"] or "")]
            assert any(names_target_independent(t, h["target_host"]) for t in texts), \
                f"{h['hop_id']}: no agent command names {h['target_host']}"
            assert h["agent_account"] not in ("system", None) and not h["agent_account"].endswith("$")
            if h["basis"] == "manual_command_names_target":
                assert h["handoff_step"], f"{h['hop_id']}: manual basis needs an intended step (AK-20)"


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


@pytest.mark.slow
@pytest.mark.parametrize("trial", ["s02_t00", "s04_t00", "s05_t00", "s07_t00"])
def test_confirmed_hop_agent_commands_are_in_splunkd_tree(real, trial):
    d = draft_of(real, trial)
    for h in confirmed(d):
        if h["basis"] == "manual_command_names_target":
            continue                      # AK-20: manual hops are the opposite case, tested separately (NOT in the splunkd tree)
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


# Spec 07 line 13 (amended 2026-11-12, decision 041): the only top-level package outside the stdlib and
# the package's own relative imports that the key code may import is `lab_common`.
ALLOWED_NON_STDLIB_TOPLEVEL = {"lab_common"}


def test_ak06_import_whitelist_only_stdlib_or_package_local():
    stdlib = set(sys.stdlib_module_names)
    for p in SRC_AK.glob("*.py"):
        for m in imported_modules(p):
            if m.startswith("."):
                continue
            top = m.split(".")[0]
            assert top in stdlib or top in ALLOWED_NON_STDLIB_TOPLEVEL, f"{p.name} imports non-stdlib/non-local {m}"


def test_ak06_lab_common_is_the_only_allowance_and_is_really_used():
    """Spec 07 line 13: exactly one extra top-level package is allowed; it is `lab_common` and nothing else."""
    assert ALLOWED_NON_STDLIB_TOPLEVEL == {"lab_common"}
    stdlib = set(sys.stdlib_module_names)
    extra = {m.split(".")[0] for p in SRC_AK.glob("*.py") for m in imported_modules(p)
             if not m.startswith(".") and m.split(".")[0] not in stdlib}
    assert extra <= {"lab_common"}, extra


def test_ak06_lab_common_imports_only_stdlib():
    """The lab_common allowance cannot become a back door: src/lab_common/*.py imports only the stdlib (and its own
    relative imports), never answer_key, log_check, parser, gate or trial_window."""
    lab = SRC_AK.parent / "lab_common"
    files = sorted(lab.glob("*.py"))
    assert files, "src/lab_common has no python files"
    stdlib = set(sys.stdlib_module_names)
    banned = ("answer_key", "log_check", "parsing_normalization", "parser", "gate", "trial_window", "stitch")
    for p in files:
        for m in imported_modules(p):
            if m.startswith("."):
                continue
            top = m.split(".")[0]
            assert top in stdlib, f"{p.name} imports non-stdlib {m}"
            assert not any(b in m.lower() for b in banned), f"{p.name} imports {m}"


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


@pytest.mark.slow
def test_ak14_cli_build_refuses_approved_and_writes_nothing(tmp_path):
    repo = make_repo(tmp_path, "s02_t00", link=True)
    shutil.copy(db_path("s02_t00"), repo / "data" / "processed" / "evil.sqlite3") if False else None
    with pytest.raises(SystemExit):
        run_cli("build", "--trial", "../approved/s02_t00", "--repo", str(repo))
    assert list((repo / "ground_truth" / "approved").rglob("*")) == []
    assert list((repo / "ground_truth" / "drafts").rglob("*")) == []


def snapshot(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
def test_s02_exactly_one_confirmed_hop_svc_backup(real):
    d = draft_of(real, "s02_t00")
    c = confirmed(d)
    assert len(c) == 1
    h = c[0]
    assert (h["source_host"], h["target_host"], h["account"], h["protocol"]) == ("ep-01", "ep-02", "svc_backup", "SMB")
    assert h["basis"] == "command_names_target" and h["identity_expected"] == 1
    assert h["target_binding"] == "logon_id_artifact"
    assert [p["hop_ids"] for p in d["paths"]] == [[h["hop_id"]]] and d["paths"][0]["role"] == "attack"


@pytest.mark.slow
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


@pytest.mark.slow
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

@pytest.mark.slow
def test_s04_track_b_confirmed_identity_1(real):
    d = draft_of(real, "s04_t00")
    c = [h for h in confirmed(d) if h["basis"] == "command_names_target"]   # Track A is confirmed too, by manual basis (AK-20)
    assert len(c) == 1 and c[0]["hop_id"] == "s04-B-h1"
    b = c[0]
    assert b["role"] == "attack" and b["account"] == "svc_backup" and b["identity_expected"] == 1
    assert any(b["hop_id"] in p["hop_ids"] for p in d["paths"])
    assert any(p["role"] == "attack_pair" for p in d["paths"] if b["hop_id"] in p["hop_ids"])


def track_a(d: dict) -> dict:
    cands = [h for h in d["hops"] if h["account"] == "admin_it" and h["source_host"] == "ep-01" and h["target_host"] == "ep-02"
             and any(h["hop_id"] in p["hop_ids"] for p in d["benign_paths"])]
    assert len(cands) == 1, [h["hop_id"] for h in cands]
    return cands[0]


@pytest.mark.slow
def test_s04_track_a_confirmed_manual_benign_identity_1_no_conflict(real):
    d = draft_of(real, "s04_t00")
    a = track_a(d)
    assert a["status"] == "confirmed" and a["basis"] == "manual_command_names_target"   # AK-20, decision 021
    assert a["role"] == "benign"                                                         # AK-19
    assert a["needs_owner_approval"] is False
    assert a["identity_expected"] == 1                       # decision 018
    assert a["identity_basis"]["move_after_dump"] is True and a["identity_basis"]["open_session_ids"]
    assert all("decision_conflict" not in h["flags"] for h in d["hops"])
    assert "decision_conflict" not in json.dumps(d["open_points"])
    assert not any(a["hop_id"] in p["hop_ids"] for p in d["paths"])


@pytest.mark.slow
def test_s04_track_a_session_evidence_recorded_from_data(real):
    d = draft_of(real, "s04_t00")
    a = track_a(d)
    sid = find(a, "session_id")
    assert sid and sid[0] in {"0xd6398", "0xd663a", "0x17b18"}, sid
    assert find(a, "session_logon_type") and find(a, "splunkd_ancestor")
    assert find(a, "splunkd_ancestor")[0] is False            # manual session, not in the splunkd tree (AK-20)


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
def test_s07_account_mismatch_and_handoff_account(real):
    d = draft_of(real, "s07_t00")
    assert any(h["account_mismatch"] and "account_mismatch" in h["flags"] for h in d["hops"])
    assert any(h["handoff_account"] == "svc_sql" for h in d["hops"])
    for h in confirmed(d):
        assert h["account"] == h["logon_account"]


@pytest.mark.slow
def test_s07_records_which_ep01_dump_per_hop(real):
    d = draft_of(real, "s07_t00")
    for h in confirmed(d):
        u = h["identity_basis"]["dump_event_uid"]
        assert u
        r = by_uid("s07_t00", [u])[u]
        assert r["host"] == "ep-01" and r["event_id"] == 10
        assert parse(h["identity_basis"]["dump_time_utc"]) <= parse(h["move_time_utc"]) + timedelta(seconds=5)


# ====================================================================== (8) S05

@pytest.mark.slow
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
    assert targets.credential_account([r"net use \\ep-02\c$ /user:LAB\admin_it FakePw-0001"]) == "admin_it"
    assert targets.credential_account(["New-Object PSCredential('LAB\\svc_backup', $pw)"]) == "svc_backup"


@pytest.mark.parametrize("cmd", [
    r"net use \\ep-02\c$ /user:LAB\admin_it FakePw-0001!",
    r"x.exe -Password FakePw-0001 y",
    r"x.exe /p:FakePw-0001 y",
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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

@pytest.mark.slow
def test_verify_real_drafts_pass(real):
    for trial in real:
        rep = cmd_verify(trial, real[trial][0])
        assert rep["ok"], (trial, rep["failures"][:3])
        assert rep["checked"] > 0 and rep["per_kind"]
        assert isinstance(rep["out_of_window"], int)


@pytest.mark.slow
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


@pytest.mark.slow
def test_verify_missing_uid_detected(real):
    d = json.loads(json.dumps(draft_of(real, "s02_t00")))
    confirmed(d)[0]["target_event_uids"].append("0" * 64)
    rep = verify_mod.verify(d, db_path("s02_t00"))
    assert rep["ok"] is False and any(f["type"] == "missing_uid" for f in rep["failures"])


@pytest.mark.slow
def test_verify_rejects_different_db_sha256(real):
    d = json.loads(json.dumps(draft_of(real, "s02_t00")))
    d["db_sha256"] = "0" * 64
    rep = verify_mod.verify(d, db_path("s02_t00"))
    assert rep["ok"] is False and any(f["type"] == "db_hash_mismatch" for f in rep["failures"])


@pytest.mark.slow
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


@pytest.mark.slow
def test_verify_out_of_window_counted_not_failed(real):
    d = json.loads(json.dumps(draft_of(real, "s02_t00")))
    base = verify_mod.verify(d, db_path("s02_t00"))
    d["window"]["start_utc"] = "2026-09-24T05:42:46.000Z"
    d["window"]["end_utc"] = "2026-09-24T05:42:47.000Z"
    rep = verify_mod.verify(d, db_path("s02_t00"))
    assert rep["ok"] is True and rep["out_of_window"] > base["out_of_window"]


@pytest.mark.slow
def test_verify_counts_per_kind_match_db(real):
    d = draft_of(real, "s02_t00")
    rep = verify_mod.verify(d, db_path("s02_t00"))
    for kind, n in rep["per_kind"].items():
        ch, eid = kind.rsplit(" ", 1)
        assert n >= 1 and rows("s02_t00", "SELECT count(*) c FROM events_dedup WHERE channel=? AND event_id=?", (ch, int(eid)))[0]["c"] >= 1


@pytest.mark.slow
def test_verify_every_uid_in_every_real_draft_exists(real):
    for trial, (repo, d, _) in real.items():
        refs = verify_mod.uids_with_context(d)
        assert refs
        ev = by_uid(trial, {u for u, _ in refs})
        missing = [(u, loc) for u, loc in refs if u not in ev]
        assert not missing, (trial, missing[:3])


# ====================================================================== (12) depth-3 chain, 4104

@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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

@pytest.mark.slow
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

# The real lab password is never stored in the repo. Value-independent checks below look at the
# STRUCTURE (the token after /user:<account>, -Password, /p: must be ***). If the owner exports the real
# value as LAB_PASSWORD, the same tests also search for that value; otherwise that extra check is skipped.
REAL_PASSWORD = os.environ.get("LAB_PASSWORD") or None


def _assert_structurally_masked(text: str) -> None:
    for m in re.finditer(r"(?i)/user:\S+\s+(\S+)", text):
        assert m.group(1).startswith("***"), f"unmasked /user: password {m.group(0)[:40]}"
    assert not re.search(r"(?i)-Password\s+(?!\*\*\*)\S", text)
    assert not re.search(r"(?i)/p:(?!\*\*\*)\S", text)
    assert not re.search(r"(?i)\$env:[A-Za-z0-9_]*PW", text)


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_drafts_never_contain_lab_password(real, trial):
    text = (real[trial][0] / "ground_truth" / "drafts" / f"{trial}.yaml").read_text(encoding="utf-8") if trial in real else pytest.skip("db missing")
    _assert_structurally_masked(text)
    for m in re.finditer(r"(?i)-(?:e|enc|ec|encodedcommand)\s+([A-Za-z0-9+/]{16,}={0,2})", text):
        try:
            dec = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)).decode("utf-16-le")
        except Exception:
            continue
        _assert_structurally_masked(dec)
        if REAL_PASSWORD:
            assert REAL_PASSWORD not in dec, "password inside an -enc payload left in the draft"
    if REAL_PASSWORD:
        assert REAL_PASSWORD not in text


def test_committed_drafts_in_repo_also_mask_password():
    for p in (REPO / "ground_truth" / "drafts").glob("s0[2-7]_t00.yaml"):
        text = p.read_text(encoding="utf-8")
        _assert_structurally_masked(text)
        if REAL_PASSWORD:
            assert REAL_PASSWORD not in text, p.name


@pytest.mark.slow
def test_password_premise_exists_in_a_db(real):
    """Control: if no DB command line carries a /user: credential, the masking tests prove nothing."""
    hit = False
    for trial in real:
        if rows(trial, "SELECT 1 FROM events_dedup WHERE command_line LIKE '%/user:%' LIMIT 1"):
            hit = True
    if not hit:
        pytest.skip("no command line with /user: credentials in these DBs; masking checked on unit strings only")


@pytest.mark.slow
@pytest.mark.parametrize("trial", ["s04_t00", "s06_t00"])
def test_agent_commands_masked_when_password_in_db(real, trial):
    d = draft_of(real, trial)
    cred_rows = rows(trial, "SELECT command_line FROM events_dedup WHERE command_line LIKE '%/user:%'")
    cmds = find(d, "agent_command")
    for c in cmds:
        _assert_structurally_masked(c)
        if REAL_PASSWORD:
            assert REAL_PASSWORD not in c
    if cred_rows:
        assert any("***" in c for c in cmds) or not cmds


# ====================================================================== decisions 021-025: pinned expectations on the real drafts

@pytest.mark.slow
def test_dec021_s04_track_a_source_session_is_desktop_0xd6398(real):
    d = draft_of(real, "s04_t00")
    a = hop_by_id(d, "s04-A-h1")
    assert (a["source_host"], a["target_host"], a["account"]) == ("ep-01", "ep-02", "admin_it")
    assert find(a, "session_id") == ["0xd6398"] and find(a, "session_logon_type") == [11]
    assert a["status"] == "confirmed" and a["basis"] == "manual_command_names_target" and a["role"] == "benign"
    assert a["identity_expected"] == 1 and a["needs_owner_approval"] is False
    assert a["source_session_logon_id"] == "0xd6398"
    assert "decision 021" in a["owner_note"]
    assert find(a, "splunkd_ancestor") == [False]
    assert "0xd6398" in a["identity_basis"]["open_session_ids"]
    # independent DB evidence for the session: a type 11 admin_it 4624 on ep-01 with logon id 0xd6398
    r = rows("s04_t00", "SELECT account_name, logon_type FROM events_dedup WHERE host='ep-01' AND event_id=4624 AND target_logon_id=?", (0xd6398,))
    assert r and all((x["account_name"], x["logon_type"]) == ("admin_it", 11) for x in r)
    assert [p["hop_ids"] for p in d["benign_paths"]] == [["s04-A-h1"]]


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
def test_ak18_logoff_with_reused_id_before_logon_does_not_close(tmp_path):
    need_db("s02_t00")
    assert rows("s02_t00", "SELECT 1 FROM events_dedup WHERE host='ep-01' AND event_id=4624 AND target_logon_id=? AND account_name='svc_backup'", (SESSION_ID,))

    def edit(con):
        insert_event(con, host="ep-01", channel="Security", event_id=4634, event_utc="2026-09-24T05:30:00.000000Z",
                     target_logon_id=SESSION_ID, logon_type=4)

    _, d = synth(tmp_path, "s02_t00", edit)
    h = s02_hop(d)
    assert h["identity_expected"] == 1 and "0x25cac3" in h["identity_basis"]["open_session_ids"]


@pytest.mark.slow
def test_ak18_logoff_after_logon_before_dump_closes_session(tmp_path):
    need_db("s02_t00")

    def edit(con):
        insert_event(con, host="ep-01", channel="Security", event_id=4634, event_utc="2026-09-24T05:36:00.000000Z",
                     target_logon_id=SESSION_ID, logon_type=4)

    _, d = synth(tmp_path, "s02_t00", edit)
    h = s02_hop(d)
    assert "0x25cac3" not in h["identity_basis"]["open_session_ids"]
    assert h["identity_expected"] == 0 and h["identity_basis"]["identity_if_unknown_counted"] == 0


@pytest.mark.slow
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


@pytest.mark.slow
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


@pytest.mark.slow
def test_source_host_conflict_other_endpoint_ip(tmp_path):
    need_db("s02_t00")
    _, d = synth(tmp_path, "s02_t00", lambda con: retarget_source_ip(con, "192.168.50.23"))
    h = s02_hop(d)
    assert h["status"] == "confirmed" and h["source_host"] == "ep-03"
    assert "source_host_conflict" in h["flags"]
    assert h["identity_basis"]["dump_host"] == "ep-03"          # decision 013: the IP host, not the command host
    assert h["identity_expected"] == 0                           # ep-03 has no dump in S02


@pytest.mark.slow
def test_source_host_conflict_unmapped_ip_gives_null_source(tmp_path):
    need_db("s02_t00")
    _, d = synth(tmp_path, "s02_t00", lambda con: retarget_source_ip(con, "192.168.50.199"))
    h = s02_hop(d)
    assert h["source_host"] is None and "source_host_conflict" in h["flags"]
    assert h["identity_expected"] == 0 and h["account"] == "svc_backup"


# ====================================================================== AKT-03 two services of one name (synthetic)

@pytest.mark.slow
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


@pytest.mark.slow
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

@pytest.mark.slow
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


@pytest.mark.slow
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

@pytest.mark.slow
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


@pytest.mark.slow
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


# ====================================================================== 2026-11-10 rules: AK-19 .. AK-22
# Written from spec 07 (AK-19..AK-22) and decisions 021 / 026, not from the code.

DRAFTS = REPO / "ground_truth" / "drafts"
MANIFEST = REPO / "data" / "manifest.csv"
BACKGROUND_HOPS = {"s04_t00": "s04-t1", "s05_t00": "s05-t1", "s06_t00": "s06-t1", "s07_t00": "s07-t1"}


def committed(trial: str) -> dict:
    p = DRAFTS / f"{trial}.yaml"
    if not p.exists():
        pytest.skip(f"{p} missing")
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def full(tmp_path_factory):
    """One temp repo holding all six DBs + manifest + provisional windows, every draft built in it."""
    root = tmp_path_factory.mktemp("full")
    built = []
    for trial in TRIALS:
        if db_path(trial).exists():
            make_repo(root, trial, link=True)
            built.append(trial)
    (root / "docs" / "research").mkdir(parents=True, exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    if MANIFEST.exists():
        shutil.copy(MANIFEST, root / "data" / "manifest.csv")
    prov = REPO / "docs" / "research" / "provisional_windows.csv"
    if prov.exists():
        shutil.copy(prov, root / "docs" / "research" / "provisional_windows.csv")
    for trial in built:
        cmd_build(trial, root)
    return root, built


# ---- AK-19 role

@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_ak19_every_hop_has_role_in_vocabulary(real, trial):
    d = draft_of(real, trial)
    assert d["hops"]
    for h in d["hops"]:
        assert h.get("role") in {"attack", "benign", "background"}, (trial, h["hop_id"], h.get("role"))


@pytest.mark.slow
def test_ak19_role_is_separate_from_status(real):
    d = draft_of(real, "s04_t00")
    pairs = {(h["role"], h["status"]) for h in d["hops"]}
    assert ("benign", "confirmed") in pairs and ("background", "unconfirmed") in pairs     # not the same axis


@pytest.mark.slow
@pytest.mark.parametrize("trial,hid", sorted(BACKGROUND_HOPS.items()))
def test_ak19_leftover_hops_are_background_unconfirmed_time_account_only(real, trial, hid):
    h = hop_by_id(draft_of(real, trial), hid)
    assert (h["role"], h["status"], h["basis"]) == ("background", "unconfirmed", "time_account_only")
    assert h["agent_event_uids"] == []


@pytest.mark.slow
def test_ak19_s06_named_hops_benign_leftover_background(real):
    d = draft_of(real, "s06_t00")
    for h in d["hops"]:
        assert h["role"] == ("background" if h["hop_id"] == "s06-t1" else "benign"), h["hop_id"]
    assert {h["hop_id"] for h in d["hops"] if h["role"] == "benign"} == {"s06-winrm-1", "s06-winrm-2", "s06-smb-1"}


@pytest.mark.slow
@pytest.mark.parametrize("trial,ids", [("s02_t00", ["s02-h1"]), ("s03_t00", ["s03-h1"]), ("s05_t00", ["s05-h1", "s05-h2"]),
                                       ("s07_t00", ["s07-h-x", "s07-h-y"])])
def test_ak19_attack_hops_role_attack(real, trial, ids):
    d = draft_of(real, trial)
    for hid in ids:
        assert hop_by_id(d, hid)["role"] == "attack", hid


@pytest.mark.slow
def test_ak19_s04_roles(real):
    d = draft_of(real, "s04_t00")
    assert hop_by_id(d, "s04-A-h1")["role"] == "benign"
    assert hop_by_id(d, "s04-B-h1")["role"] == "attack"        # paths[] role stays attack_pair, hop role is attack
    assert any(p["role"] == "attack_pair" and p["hop_ids"] == ["s04-B-h1"] for p in d["paths"])


@pytest.mark.slow
def test_ak19_no_negative_hop_sits_on_an_attack_path(real):
    """Evaluation counts benign + background as negatives: none may be on paths[]."""
    for trial in real:
        d = draft_of(real, trial)
        on_attack = {x for p in d["paths"] for x in p["hop_ids"]}
        for h in d["hops"]:
            if h["role"] in ("benign", "background"):
                assert h["hop_id"] not in on_attack, (trial, h["hop_id"])


def _intended_with(tmp_path, monkeypatch, edit) -> None:
    import answer_key.__main__ as m
    intended = json.loads(m.INTENDED.read_text(encoding="utf-8"))
    edit(intended)
    alt = tmp_path / "intended_edit.json"
    alt.write_text(json.dumps(intended), encoding="utf-8")
    monkeypatch.setattr(m, "INTENDED", alt)


@pytest.mark.slow
def test_ak19_build_fails_when_a_hop_has_no_valid_role(tmp_path, monkeypatch):
    """Synthetic: an intended step whose role is outside the vocabulary must make the build fail, not write a draft."""
    need_db("s02_t00")

    def edit(intended):
        for st in intended["scenarios"]["s02"]["steps"]:
            if st["kind"] == "move":
                st["role"] = "bogus"
    _intended_with(tmp_path, monkeypatch, edit)
    import answer_key.__main__ as m
    repo = make_repo(tmp_path / "r", "s02_t00", link=False)
    with pytest.raises((ValueError, KeyError)):
        m.cmd_build("s02_t00", repo)
    assert not (repo / "ground_truth" / "drafts" / "s02_t00.yaml").exists(), "a draft was written despite the invalid role"


# ---- AK-20 manual basis (decision 021)

def track_a_command_uids() -> set[str]:
    """Independent: Sysmon 1 commands in the approved session 877464 on ep-01 that name ep-02 (by IP)."""
    return {r["event_uid"] for r in rows("s04_t00", "SELECT event_uid FROM events_dedup WHERE channel='Sysmon' AND event_id=1 AND "
                                                    "host='ep-01' AND session_id=877464 AND command_line LIKE '%192.168.50.22%'")}


@pytest.mark.slow
def test_ak20_s04_track_a_pinned(real):
    d = draft_of(real, "s04_t00")
    a = hop_by_id(d, "s04-A-h1")
    assert a["basis"] == "manual_command_names_target" and a["status"] == "confirmed" and a["role"] == "benign"
    assert a["identity_expected"] == 1
    assert a["source_session_logon_id"] == "0xd6398" and int(a["source_session_logon_id"], 16) == 877464
    assert a["needs_owner_approval"] is False
    assert "decision 021" in a["owner_note"]
    assert a["handoff_step"] == "s04-A-h1"
    assert "no_intended_step" not in a["flags"] and "decision_conflict" not in a["flags"]
    assert [s for s in d["steps"] if s["step_id"] == "s04-A-h1-move"][0]["status"] == "confirmed"


@pytest.mark.slow
def test_ak20_s04_track_a_commands_matched_by_logon_id_and_not_in_splunkd_tree(real):
    d = draft_of(real, "s04_t00")
    a = hop_by_id(d, "s04-A-h1")
    ev = by_uid("s04_t00", a["agent_event_uids"])
    assert set(ev) == set(a["agent_event_uids"]) and ev
    for u, r in ev.items():
        assert (r["channel"], r["event_id"]) == ("Sysmon", 1)
        assert r["session_id"] == 877464, f"{u}: Sysmon 1 session_id is not the approved session"      # logon-id match
        assert r["account_name"] == "admin_it"
        assert names_target_independent(r["command_line"] or "", "ep-02")
        assert not agent_ancestor_reached("s04_t00", u), f"{u} has a splunkd ancestor"
    cmds = " ".join((r["command_line"] or "").lower() for r in ev.values())
    for word in ("net", "use", "create", "start", "healthagentsvc"):
        assert word in cmds, word
    assert track_a_command_uids() == set(ev)                  # nothing from the session is lost
    assert find(a, "splunkd_ancestor") == [False] and find(a, "session_id") == ["0xd6398"]


@pytest.mark.slow
def test_ak20_s04_track_b_stays_agent_command_basis(real):
    b = hop_by_id(draft_of(real, "s04_t00"), "s04-B-h1")
    assert (b["basis"], b["role"], b["status"]) == ("command_names_target", "attack", "confirmed")
    assert b["agent_account"] == "svc_backup"


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_ak20_manual_basis_only_with_step_match_and_confirmed(real, trial):
    d = draft_of(real, trial)
    manual = []
    for h in d["hops"]:
        if h["basis"] == "manual_command_names_target":
            manual.append(h["hop_id"])
            assert h["handoff_step"] and h["status"] == "confirmed" and "no_intended_step" not in h["flags"], h["hop_id"]
        if h["status"] == "unconfirmed":
            assert h["basis"] != "manual_command_names_target", f"{h['hop_id']}: unconfirmed with manual basis"
    assert manual == (["s04-A-h1"] if trial == "s04_t00" else [])


@pytest.mark.slow
def test_ak20_manual_command_matching_no_intended_step_is_downgraded(tmp_path, monkeypatch):
    """Synthetic: the Track A step now targets ep-03, so the manual command naming ep-02 matches no step."""
    need_db("s04_t00")

    def edit(intended):
        for st in intended["scenarios"]["s04"]["steps"]:
            if st["id"] == "s04-A-h1":
                st["target_host"] = "ep-03"
    _intended_with(tmp_path, monkeypatch, edit)
    import answer_key.__main__ as m
    repo = make_repo(tmp_path / "r", "s04_t00", link=False)
    m.cmd_build("s04_t00", repo)
    d = read_draft(repo, "s04_t00")
    orig = track_a_command_uids()
    hit = [h for h in d["hops"] if set(h["agent_event_uids"]) & orig]
    assert hit, "the manual commands vanished from the key instead of being downgraded"
    for h in hit:
        assert (h["basis"], h["status"], h["role"]) == ("time_account_only", "unconfirmed", "background"), h["hop_id"]
        assert h["confidence_tier"] == "D"
    assert not [h for h in d["hops"] if h["basis"] == "manual_command_names_target"]
    assert {h["hop_id"] for h in hit} <= {u["id"] for u in d["unconfirmed"]}               # kept for review, never dropped
    assert not ({h["hop_id"] for h in hit} & {x for p in d["paths"] for x in p["hop_ids"]})
    assert hop_by_id(d, "s04-B-h1")["status"] == "confirmed"                                 # Track B unaffected


@pytest.mark.slow
def test_ak20_manual_command_in_agent_tree_session_is_not_manual_basis(tmp_path):
    """Synthetic: re-parent the Track A session's powershell.exe under admin_it's splunkd; its commands are agent-tree now."""
    need_db("s04_t00")
    ps = rows("s04_t00", "SELECT process_guid FROM events_dedup WHERE event_uid LIKE '61646f10%'")
    spl = rows("s04_t00", "SELECT process_guid FROM events_dedup WHERE channel='Sysmon' AND event_id=1 AND host='ep-01' AND "
                          "account_name='admin_it' AND image LIKE '%splunkd.exe'")
    assert ps and spl, "data premise changed (powershell.exe parent of the Track A commands / admin_it splunkd)"
    guid, sp = ps[0]["process_guid"], spl[0]["process_guid"]

    def edit(con):
        con.execute("UPDATE events SET parent_process_guid=?, parent_image='C:\\Users\\Public\\splunkd.exe' "
                    "WHERE channel='Sysmon' AND event_id=1 AND process_guid=?", (sp, guid))

    _, d = synth(tmp_path, "s04_t00", edit)
    uids = track_a_command_uids()
    for h in d["hops"]:
        if set(h["agent_event_uids"]) & uids:
            assert h["basis"] != "manual_command_names_target", f"{h['hop_id']}: agent-tree command labelled manual"
    assert not [h for h in d["hops"] if h["basis"] == "manual_command_names_target"]


# ---- AK-21 lock gate (decisions 027, 028)

OWNER_FILE = SRC_AK / "owner_reviews.json"


def owner_entries() -> dict:
    """Independent read of the owner file: {trial: {hop_id: entry}}."""
    data = json.loads(OWNER_FILE.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _verify_copy(real, trial, mutate):
    d = json.loads(json.dumps(read_draft(real[trial][0], trial)))
    mutate(d)
    return verify_mod.verify(d, db_path(trial))


def _blockers(rep) -> list[str]:
    return sorted(b["hop_id"] for b in rep["lock_blockers"])


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_ak21_verify_json_lock_fields_on_real_drafts(real, trial):
    repo = real[trial][0] if trial in real else pytest.skip("db missing")
    cmd_verify(trial, repo)
    on_disk = json.loads((repo / "out" / "answer_key" / trial / "verify.json").read_text(encoding="utf-8"))
    assert on_disk["lock_ready"] is True and on_disk["lock_blockers"] == []
    d = read_draft(repo, trial)
    owner = owner_entries().get(trial, {})
    for h in d["hops"]:
        e = owner.get(h["hop_id"], {})
        assert h["excluded"] is bool(e.get("excluded", False)) and h["excluded"] is False
        assert h["reviewed"] is bool(e.get("reviewed", False)), (trial, h["hop_id"])
        if h["role"] == "background":
            assert h["reviewed"] is True and h["excluded"] is False, (trial, h["hop_id"])
        else:
            assert h["reviewed"] is False, (trial, h["hop_id"])
            assert h["status"] == "confirmed"


def test_ak21_owner_file_covers_exactly_the_four_background_hops():
    own = owner_entries()
    assert {t: sorted(v) for t, v in own.items()} == {t: [h] for t, h in BACKGROUND_HOPS.items()}
    for v in own.values():
        for e in v.values():
            assert e["reviewed"] is True and e["excluded"] is False and e["excluded_reason"] is None


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_ak21_exclusion_fields_present_with_defaults_on_every_hop(real, trial):
    for h in draft_of(real, trial)["hops"]:
        for k in ("reviewed", "reviewed_note", "excluded", "excluded_reason"):
            assert k in h, (trial, h["hop_id"], k)
        assert h["excluded"] is False and h["excluded_reason"] is None
        assert isinstance(h["reviewed"], bool)
        if h["role"] != "background":
            assert h["reviewed_note"] is None


@pytest.mark.slow
def test_ak21_clearing_reviewed_on_background_hop_blocks(real):
    assert _verify_copy(real, "s04_t00", lambda d: None)["lock_ready"] is True
    rep = _verify_copy(real, "s04_t00", lambda d: hop_by_id(d, "s04-t1").update(reviewed=False))
    assert rep["lock_ready"] is False and _blockers(rep) == ["s04-t1"] and rep["lock_blockers"][0]["reason"]


@pytest.mark.slow
def test_ak21_confirmed_attack_hop_changed_to_unconfirmed_blocks(real):
    rep = _verify_copy(real, "s02_t00", lambda d: d["hops"][0].update(status="unconfirmed"))
    assert d_role(real, "s02_t00", "s02-h1") == "attack"
    assert rep["lock_ready"] is False and _blockers(rep) == ["s02-h1"]


def d_role(real, trial, hid):
    return hop_by_id(draft_of(real, trial), hid)["role"]


@pytest.mark.slow
def test_ak21_unconfirmed_benign_hop_blocks(real):
    assert d_role(real, "s06_t00", "s06-winrm-1") == "benign"
    rep = _verify_copy(real, "s06_t00", lambda d: hop_by_id(d, "s06-winrm-1").update(status="unconfirmed"))
    assert rep["lock_ready"] is False and _blockers(rep) == ["s06-winrm-1"]


@pytest.mark.slow
def test_ak21_excluded_without_reason_blocks_and_with_reason_stops_blocking(real):
    for reason in (None, "", "   "):
        rep = _verify_copy(real, "s02_t00", lambda d: d["hops"][0].update(excluded=True, excluded_reason=reason))
        assert rep["lock_ready"] is False and _blockers(rep) == ["s02-h1"], repr(reason)
    rep = _verify_copy(real, "s02_t00", lambda d: d["hops"][0].update(excluded=True, excluded_reason="owner: out of scope"))
    assert rep["lock_ready"] is True and rep["lock_blockers"] == []


@pytest.mark.slow
def test_ak21_excluded_hop_skips_status_and_review_rules(real):
    def mut(d):
        hop_by_id(d, "s02-h1").update(status="unconfirmed", excluded=True, excluded_reason="owner")
    assert _verify_copy(real, "s02_t00", mut)["lock_ready"] is True

    def mut_bg(d):
        hop_by_id(d, "s04-t1").update(reviewed=False, excluded=True, excluded_reason="owner")
    assert _verify_copy(real, "s04_t00", mut_bg)["lock_ready"] is True


@pytest.mark.slow
@pytest.mark.parametrize("excluded", [False, True])
def test_ak21_hop_without_valid_role_blocks_lock_even_if_excluded(real, excluded):
    def mut(d):
        d["hops"][0].pop("role")
        d["hops"][0].update(excluded=excluded, excluded_reason="owner" if excluded else None)
    rep = _verify_copy(real, "s02_t00", mut)
    assert rep["lock_ready"] is False and _blockers(rep) == ["s02-h1"]


@pytest.mark.slow
def test_ak21_invalid_role_value_blocks(real):
    rep = _verify_copy(real, "s02_t00", lambda d: d["hops"][0].update(role="bogus"))
    assert rep["lock_ready"] is False and _blockers(rep) == ["s02-h1"]


@pytest.mark.slow
def test_ak21_lock_gate_is_informational_verify_still_ok(real):
    d = json.loads(json.dumps(draft_of(real, "s04_t00")))
    hop_by_id(d, "s04-t1")["reviewed"] = False
    rep = verify_mod.verify(d, db_path("s04_t00"))
    assert rep["ok"] is True and rep["lock_ready"] is False
    assert cmd_verify("s04_t00", real["s04_t00"][0])["ok"] is True


@pytest.mark.slow
def test_ak21_owner_entry_for_missing_hop_raises(tmp_path, monkeypatch):
    need_db("s04_t00")
    import answer_key.__main__ as m
    alt = tmp_path / "owner_bad.json"
    alt.write_text(json.dumps({"s04_t00": {"s04-t1": {"reviewed": True}, "s04-nope": {"reviewed": True}}}), encoding="utf-8")
    monkeypatch.setattr(m, "OWNER_REVIEWS", alt)
    repo = make_repo(tmp_path / "r", "s04_t00", link=True)
    with pytest.raises(ValueError, match="s04-nope"):
        m.cmd_build("s04_t00", repo)
    assert not (repo / "ground_truth" / "drafts" / "s04_t00.yaml").exists()


@pytest.mark.slow
def test_ak21_build_deterministic_apart_from_owner_file(tmp_path, monkeypatch):
    need_db("s04_t00")
    import answer_key.__main__ as m
    base = make_repo(tmp_path / "a", "s04_t00", link=True)
    m.cmd_build("s04_t00", base)
    d1 = read_draft(base, "s04_t00")
    alt = tmp_path / "owner_empty.json"
    alt.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(m, "OWNER_REVIEWS", alt)
    other = make_repo(tmp_path / "b", "s04_t00", link=True)
    m.cmd_build("s04_t00", other)
    d2 = read_draft(other, "s04_t00")
    assert hop_by_id(d1, "s04-t1")["reviewed"] is True and hop_by_id(d2, "s04-t1")["reviewed"] is False
    for d in (d1, d2):
        hop_by_id(d, "s04-t1").update(reviewed=None, reviewed_note=None)
    assert d1 == d2
    assert verify_mod.lock_status(read_draft(other, "s04_t00"))["lock_ready"] is False
    m.cmd_build("s04_t00", base)
    assert read_draft(base, "s04_t00") == read_draft(base, "s04_t00")


# ---- AK-22 run interval, manifest span, overlap

def manifest_span_independent(trial: str) -> tuple[datetime, datetime, int]:
    import csv
    scenario, tr = trial.split("_")
    with open(MANIFEST, newline="", encoding="utf-8") as fh:
        rs = [r for r in csv.DictReader(fh) if r["scenario"] == scenario and r["trial"] == tr
              and r["first_event_utc"] and r["last_event_utc"]]
    assert rs, f"no manifest rows for {trial}"
    return (min(parse(r["first_event_utc"]) for r in rs), max(parse(r["last_event_utc"]) for r in rs), len(rs))


@pytest.mark.parametrize("trial", TRIALS)
def test_ak22_manifest_span_matches_manifest_csv_committed_draft(trial):
    if not MANIFEST.exists():
        pytest.skip("manifest missing")
    d = committed(trial)
    lo, hi, n = manifest_span_independent(trial)
    ms = d["agent"]["manifest_span"]
    assert parse(ms["start_utc"]) == lo and parse(ms["end_utc"]) == hi, (ms, lo, hi)
    ri = d["agent"]["run_interval"]
    assert lo <= parse(ri["start_utc"]) <= parse(ri["end_utc"]) <= hi, (ri, ms)
    assert ms.get("files") == n


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_ak22_manifest_span_matches_manifest_csv_fresh_build(full, trial):
    root, built = full
    if trial not in built or not MANIFEST.exists():
        pytest.skip("db or manifest missing")
    d = read_draft(root, trial)
    lo, hi, _ = manifest_span_independent(trial)
    ms = d["agent"]["manifest_span"]
    assert parse(ms["start_utc"]) == lo and parse(ms["end_utc"]) == hi
    ri = d["agent"]["run_interval"]
    assert lo <= parse(ri["start_utc"]) and parse(ri["end_utc"]) <= hi
    for h in d["hops"]:
        assert parse(ri["start_utc"]) <= parse(h["move_time_utc"]) <= parse(ri["end_utc"]), h["hop_id"]


def _copy_drafts(dst: Path, trials=TRIALS) -> Path:
    (dst / "ground_truth" / "drafts").mkdir(parents=True, exist_ok=True)
    (dst / "ground_truth" / "approved").mkdir(parents=True, exist_ok=True)
    for t in trials:
        if (DRAFTS / f"{t}.yaml").exists():
            shutil.copy(DRAFTS / f"{t}.yaml", dst / "ground_truth" / "drafts" / f"{t}.yaml")
    return dst


def test_ak22_check_overlap_writes_files_and_reports_no_overlap_for_six_drafts(tmp_path):
    repo = _copy_drafts(tmp_path)
    assert run_cli("check-overlap", "--repo", str(repo)) == 0
    oj, om = repo / "out" / "answer_key" / "overlap.json", repo / "out" / "answer_key" / "overlap.md"
    assert oj.exists() and om.exists() and om.read_text(encoding="utf-8").strip()
    rep = json.loads(oj.read_text(encoding="utf-8"))
    assert rep["overlapping_pairs"] == []
    iv = {}
    for t in TRIALS:                                          # independent recomputation of the six intervals
        d = committed(t)
        iv[t] = (parse(d["agent"]["run_interval"]["start_utc"]), parse(d["agent"]["run_interval"]["end_utc"]))
    for a in TRIALS:
        for b in TRIALS:
            if a < b:
                assert not (iv[a][0] < iv[b][1] and iv[b][0] < iv[a][1]), (a, b)
    assert set(rep["run_intervals"]) == set(TRIALS)


def test_ak22_check_overlap_reports_a_pair_when_intervals_overlap(tmp_path):
    repo = _copy_drafts(tmp_path)
    p5 = repo / "ground_truth" / "drafts" / "s05_t00.yaml"
    d5 = json.loads(p5.read_text(encoding="utf-8"))
    d6 = json.loads((repo / "ground_truth" / "drafts" / "s06_t00.yaml").read_text(encoding="utf-8"))
    d5["agent"]["run_interval"] = dict(d6["agent"]["run_interval"])          # synthetic: s05 now runs when s06 runs
    p5.write_text(json.dumps(d5), encoding="utf-8")
    assert run_cli("check-overlap", "--repo", str(repo)) == 0
    rep = json.loads((repo / "out" / "answer_key" / "overlap.json").read_text(encoding="utf-8"))
    assert [sorted(p["trials"]) for p in rep["overlapping_pairs"]] == [["s05_t00", "s06_t00"]]
    assert "s05_t00" in (repo / "out" / "answer_key" / "overlap.md").read_text(encoding="utf-8")


def test_ak22_partial_overlap_of_30_seconds_is_reported(tmp_path):
    repo = _copy_drafts(tmp_path, ["s05_t00", "s06_t00"])
    p5 = repo / "ground_truth" / "drafts" / "s05_t00.yaml"
    d5 = json.loads(p5.read_text(encoding="utf-8"))
    d6 = json.loads((repo / "ground_truth" / "drafts" / "s06_t00.yaml").read_text(encoding="utf-8"))
    s6 = parse(d6["agent"]["run_interval"]["start_utc"])
    d5["agent"]["run_interval"] = {"start_utc": fmt(s6 - timedelta(minutes=5)), "end_utc": fmt(s6 + timedelta(seconds=30))}
    p5.write_text(json.dumps(d5), encoding="utf-8")
    run_cli("check-overlap", "--repo", str(repo))
    rep = json.loads((repo / "out" / "answer_key" / "overlap.json").read_text(encoding="utf-8"))
    assert len(rep["overlapping_pairs"]) == 1


def test_ak22_s05_t1_shared_with_s06_and_s07_committed_draft():
    h = hop_by_id(committed("s05_t00"), "s05-t1")
    assert h["shared_with_trials"] == ["s06_t00", "s07_t00"] and "shared_with_trial" in h["flags"]


@pytest.mark.slow
def test_ak22_s05_t1_shared_fresh_build_and_independent_content_check(full):
    root, built = full
    if not {"s05_t00", "s06_t00", "s07_t00"} <= set(built):
        pytest.skip("need s05, s06, s07 DBs")
    h = hop_by_id(read_draft(root, "s05_t00"), "s05-t1")
    assert h["shared_with_trials"] == ["s06_t00", "s07_t00"] and "shared_with_trial" in h["flags"]
    sha = h["target_4624_content_sha256"]                    # independent: its 4624 content exists in the other two DBs
    for other in ("s06_t00", "s07_t00"):
        assert rows(other, "SELECT 1 FROM events_dedup WHERE duplicate_content_sha256=? AND event_id=4624", (sha,)), other
    for trial in built:
        for hh in read_draft(root, trial)["hops"]:
            assert trial not in hh.get("shared_with_trials", [])
            assert bool(hh.get("shared_with_trials")) == ("shared_with_trial" in hh["flags"]), hh["hop_id"]
            if hh.get("shared_with_trials"):
                assert hh["role"] == "background", "only background hops are flagged as shared"


@pytest.mark.slow
def test_ak22_overlap_json_lists_shared_background_hop(full):
    root, built = full
    if not {"s05_t00", "s06_t00", "s07_t00"} <= set(built):
        pytest.skip("need s05, s06, s07 DBs")
    run_cli("check-overlap", "--repo", str(root))
    rep = json.loads((root / "out" / "answer_key" / "overlap.json").read_text(encoding="utf-8"))
    assert rep["overlapping_pairs"] == []
    assert [(s["trial"], s["hop_id"], s["shared_with_trials"]) for s in rep["shared_background_hops"]
            if s["hop_id"] == "s05-t1"] == [("s05_t00", "s05-t1", ["s06_t00", "s07_t00"])]


# ---- AK-14 re-check after the new CLI action

def _tree(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): sha256(p) for p in sorted(root.rglob("*")) if p.is_file()}


def test_ak14_check_overlap_writes_nothing_under_approved(tmp_path):
    repo = _copy_drafts(tmp_path)
    (repo / "ground_truth" / "approved" / "keep.txt").write_text("owner file", encoding="utf-8")
    before = _tree(repo / "ground_truth" / "approved")
    run_cli("check-overlap", "--repo", str(repo))
    assert _tree(repo / "ground_truth" / "approved") == before
    written = {p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_file()}
    assert {w for w in written if w.startswith("out/")} == {"out/answer_key/overlap.json", "out/answer_key/overlap.md"}
    assert {w for w in written if w.startswith("ground_truth/")} == \
        {"ground_truth/approved/keep.txt"} | {f"ground_truth/drafts/{t}.yaml" for t in TRIALS if (DRAFTS / f"{t}.yaml").exists()}


@pytest.mark.slow
def test_ak14_safe_draft_path_refuses_approved_and_verify_leaves_approved_empty(real, tmp_path):
    (tmp_path / "ground_truth" / "approved").mkdir(parents=True)
    (tmp_path / "ground_truth" / "drafts").mkdir(parents=True)
    with pytest.raises(SystemExit):
        safe_draft_path(tmp_path, "../approved/s02_t00")
    for trial in real:
        repo = real[trial][0]
        cmd_verify(trial, repo)
        assert list((repo / "ground_truth" / "approved").iterdir()) == []
