"""Tests for evtx_pipeline.trial_normalize (T3 pass A), written from
docs/specs/01_normalise_fixes.md (NF-01..NF-20, sections 6 and 7) and decisions 004-008.

Real-data tests read data/processed/jsonl (physical lines split on "\\n" only, 1-based) and
skip with a reason when the file is missing.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "parsing_normalization"))

from evtx_pipeline.trial_normalize import (  # noqa: E402
    HOSTS,
    TRIAL_RELEVANT_EVENT_IDS,
    bare_account_name,
    domain_short,
    host_from_relative_path,
    host_lower,
    is_relevant,
    logon_id_or_none,
    normalize_trial_event,
    split_domain_user,
)

JSONL = REPO / "data" / "processed" / "jsonl"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
LOGON_ID_COLUMNS = ("session_id", "subject_logon_id", "target_logon_id", "target_linked_logon_id")


# ---------------------------------------------------------------- helpers
def read_line(rel: str, line_no: int) -> dict:
    path = JSONL / rel
    if not path.exists():
        pytest.skip(f"missing development JSONL: {path}")
    with open(path, encoding="utf-8", newline="") as fh:
        lines = fh.read().split("\n")
    return json.loads(lines[line_no - 1])


def norm(event: dict, trial: str = "t00", scenario: str = "s02", line: int = 1) -> dict:
    return normalize_trial_event(event, scenario_id=scenario, trial_id=trial, line_number=line)


def real(rel: str, line_no: int, **kw) -> dict:
    return norm(read_line(rel, line_no), line=line_no, **kw)


def make_event(channel: str, event_id: int, data: dict, *, rel: str = "ep-02/security.evtx",
               computer: str = "Endpoint-02.lab.local", ts: str | None = "2026-09-24T05:00:00.1234567Z") -> dict:
    return {
        "schema_version": "1.0",
        "source": {"relative_path": rel, "filename": rel.split("/")[-1], "sha256": "ab" * 32,
                   "size_bytes": 1, "record_index": 1},
        "hints": {"claimed_scenario": None, "host_from_path": None},
        "system": {"provider": "p", "event_id": str(event_id), "event_record_id": "42",
                   "channel": channel, "computer": computer, "timestamp_raw": ts},
        "event_data": [{"name": k, "value": v} for k, v in data.items()],
        "user_data": None,
        "raw_xml": ("<Event><System><Execution ProcessID=\"772\" ThreadID=\"1\"/></System></Event>"),
    }


def logon4624(user="svc_backup", domain="LAB", target_id="0x11a5b15", **extra) -> dict:
    data = {"SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-",
            "SubjectLogonId": "0x0", "TargetUserName": user, "TargetDomainName": domain,
            "TargetLogonId": target_id, "LogonType": "3", "TargetLinkedLogonId": "0x0",
            "IpAddress": "192.168.50.22", "IpPort": "49761"}
    data.update(extra)
    return make_event("Security", 4624, data)


# ---------------------------------------------------------------- helper functions
def test_hosts_constant_is_lowercase_set():
    assert tuple(HOSTS) == ("dc01", "ep-01", "ep-02", "ep-03")  # NF-10


@pytest.mark.parametrize("ch,ids", [
    ("Security", {1102, 4634, 4647, 4688}), ("System", {104, 6005, 6006, 6008, 41, 1074}),
])
def test_trial_relevant_ids_include_added(ch, ids):  # NF-09 / decision 004
    assert ids <= TRIAL_RELEVANT_EVENT_IDS[ch]


@pytest.mark.parametrize("ch,eid", [
    ("Security", 1102), ("System", 104), ("System", 6005), ("System", 6006), ("System", 6008),
    ("System", 41), ("System", 1074), ("Security", 4634), ("Security", 4647), ("Security", 4688),
    ("Security", 4624), ("Security", 4769), ("Security", 4768), ("Sysmon", 1), ("Sysmon", 3),
    ("Sysmon", 10), ("Sysmon", 11), ("System", 7045), ("Security", 5145),
])
def test_is_relevant_true(ch, eid):
    assert is_relevant(ch, eid) is True


@pytest.mark.parametrize("ch,eid", [("Security", 4799), ("System", 12345), ("Sysmon", 22),
                                    ("NoSuchChannel", 4624), (None, None)])
def test_is_relevant_false(ch, eid):
    assert is_relevant(ch, eid) is False


@pytest.mark.parametrize("raw,exp", [
    ("DC-01.lab.local", "dc01"), ("DC01", "dc01"), ("ep-01", "ep-01"), ("EP-02", "ep-02"),
    ("Endpoint-03.lab.local", "ep-03"), (None, None), ("", None), ("-", None),
])
def test_host_lower(raw, exp):  # NF-10 / NF-15
    got = host_lower(raw)
    assert got == exp
    assert got is None or got == got.lower()


@pytest.mark.parametrize("rel,exp", [("dc01/security.evtx", "dc01"), ("EP-01/sysmon.evtx", "ep-01"),
                                     ("ep-03\\winrm.evtx", "ep-03")])
def test_host_from_relative_path(rel, exp):
    assert host_from_relative_path(rel) == exp


@pytest.mark.parametrize("rel", ["win-abc/security.evtx", "security.evtx", "", "ep-09/system.evtx"])
def test_host_from_relative_path_unknown_raises(rel):  # NF-15
    with pytest.raises(ValueError):
        host_from_relative_path(rel)


def test_split_domain_user():
    assert split_domain_user("LAB\\svc_backup") == ("LAB", "svc_backup")
    assert split_domain_user("svc_backup") == (None, "svc_backup")
    assert split_domain_user(None) == (None, None)
    assert split_domain_user("NT AUTHORITY\\SYSTEM") == ("NT AUTHORITY", "SYSTEM")


@pytest.mark.parametrize("raw,exp", [
    ("svc_backup@LAB.LOCAL", "svc_backup"), ("LAB\\svc_backup", "svc_backup"), ("SVC_Backup", "svc_backup"),
    ("ep-02$", "ep-02$"), ("ep-02$@LAB.LOCAL", "ep-02$"), ("EP-02\\Administrator", "administrator"),
    ("NT AUTHORITY\\SYSTEM", "system"), (None, None), ("", None), ("-", None),
])
def test_bare_account_name(raw, exp):  # NF-04
    assert bare_account_name(raw) == exp


@pytest.mark.parametrize("raw,exp", [("LAB.LOCAL", "lab"), ("LAB", "lab"), ("lab.local", "lab"),
                                     ("NT AUTHORITY", "nt authority"), (None, None), ("", None)])
def test_domain_short(raw, exp):  # NF-18
    assert domain_short(raw) == exp


@pytest.mark.parametrize("raw,exp", [("0x0", None), (0, None), ("0", None), (None, None), ("-", None),
                                     ("0x5f3f3", 390131), ("0x3e7", 999), ("18504469", 18504469)])
def test_logon_id_or_none(raw, exp):  # NF-11
    assert logon_id_or_none(raw) == exp


# ---------------------------------------------------------------- real examples
def test_real_kerberos_4624():
    r = real("s02_t00/per_file/dc01/security.jsonl", 33)
    assert r["event_id"] == 4624 and r["channel"] == "Security"
    assert r["account_name"] == "svc_backup" and r["domain_short"] == "lab"
    assert r["session_id"] == r["target_logon_id"] == 18504469
    assert r["subject_logon_id"] is None  # 0x0 -> NULL
    assert r["source_ip"] == "192.168.50.22" and r["source_port"] == 49761
    assert r["logon_guid"] == "5221cbe0-fe14-d6d5-b68c-09fdfdfd0b9b"
    assert r["machine_account"] == 0 and r["predefined_session"] == 0
    assert r["host"] == "dc01" and r["export_host"] == "DC-01.lab.local"
    assert r["target_linked_logon_id"] is None


def test_real_4769():
    r = real("s02_t00/per_file/dc01/security.jsonl", 29)
    assert r["event_id"] == 4769
    assert r["account_name"] == "svc_backup" and r["domain_short"] == "lab"
    assert r["source_port"] == 49762  # from IpPort
    assert r["session_id"] is None
    assert r["service_name"] == "DC-01$"
    assert r["machine_account"] == 0  # flag follows the requesting account


def test_kerberos_4624_and_4769_same_account_key():  # NF-T04
    a = real("s02_t00/per_file/dc01/security.jsonl", 33)
    b = real("s02_t00/per_file/dc01/security.jsonl", 29)
    assert (a["account_name"], a["domain_short"]) == (b["account_name"], b["domain_short"])
    assert a["logon_guid"] == b["logon_guid"]  # LogonGuid confirms Kerberos hops


def test_real_ntlm_4624():
    r = real("s02_t00/per_file/ep-02/security.jsonl", 6560)
    assert r["logon_guid"] is None
    assert r["source_port"] == 49782 and r["source_host"] == "ep-01"
    assert r["host"] == "ep-02" and r["export_host"] == "Endpoint-02.lab.local"
    assert r["authentication_package"] == "NTLM"


def test_real_4688_nf11():
    r = real("s01_t00/per_file/dc01/security.jsonl", 2)
    assert r["event_id"] == 4688
    assert r["session_id"] == 390131 == int("0x5f3f3", 16)
    assert r["subject_logon_id"] == 390131
    assert r["target_logon_id"] is None


def test_real_sysmon3_smb_nf13_nf14():
    r = real("s01_t00/per_file/ep-03/sysmon.jsonl", 33754)
    assert r["channel"] == "Sysmon" and r["event_id"] == 3
    assert r["initiated"] == 1 and r["destination_port"] == 445
    assert r["predefined_session"] == 0
    assert r["logon_guid"] is None
    assert r["account_name"] == "system" and r["domain_short"] == "nt authority"
    assert r["subject_account"] is not None
    assert r["image"] == "System"
    assert r["source_host"] == "ep-03"


def test_real_sysmon10():
    r = real("s02_t00/per_file/ep-01/sysmon.jsonl", 4)
    assert r["event_id"] == 10
    assert r["source_image"].lower().endswith("vboxservice.exe")
    assert r["granted_access"] == "0x1400"
    assert r["target_process_guid"] == "c458e5dd-a815-6ab4-0c00-000000002100"
    assert r["subject_account"] is not None  # NF-05 SourceUser
    assert r["account_name"] == "system"


def test_real_sysmon1_logonid():
    r = real("s01_t00/per_file/dc01/sysmon.jsonl", 21)
    assert r["event_id"] == 1
    assert r["session_id"] == 999  # LogonId 0x3e7
    assert r["predefined_session"] == 0  # NF-13: never from Sysmon process owner
    assert r["sysmon_logon_guid"] == "6f88cc0a-ad69-6ab4-e703-000000000000"
    assert r["logon_guid"] is None
    assert r["account_name"] == "system"


def test_real_sysmon11():
    r = real("s01_t00/per_file/dc01/sysmon.jsonl", 22)
    assert r["event_id"] == 11 and r["account_name"] == "system"
    assert r["subject_account"] is not None
    assert r["session_id"] is None
    assert r["target_filename"].endswith(".etl")


def test_real_4648():
    r = real("s01_t00/per_file/dc01/security.jsonl", 152)
    assert r["event_id"] == 4648
    assert r["session_id"] == r["subject_logon_id"] == 999
    assert r["predefined_session"] == 1


def test_real_4672():
    r = real("s01_t00/per_file/dc01/security.jsonl", 32)
    assert r["event_id"] == 4672
    assert r["session_id"] == r["subject_logon_id"] == 18504469
    assert r["account_name"] == "svc_backup"


def test_real_4634():
    r = real("s01_t00/per_file/dc01/security.jsonl", 2337)
    assert r["event_id"] == 4634
    assert r["session_id"] == r["target_logon_id"] == 201037
    assert r["machine_account"] == 1 and r["account_name"] == "dc-01$"


def test_real_4647_session_id():
    """NF-11 lists SubjectLogonId for 4647, but the real 4647 (ep-01 line 121) carries only
    TargetLogonId 0x62f43. Expectation: a session-end row must still know its session."""
    r = real("s01_t00/per_file/ep-01/security.jsonl", 121)
    assert r["event_id"] == 4647
    assert r["session_id"] == 405315, "4647 session_id is NULL although the log has a logon id"


def test_4647_with_subject_logon_id_synthetic():  # NF-11 as written
    ev = make_event("Security", 4647, {"SubjectUserName": "admin_it", "SubjectDomainName": "LAB",
                                       "SubjectLogonId": "0x62f43"})
    r = norm(ev)
    assert r["session_id"] == 0x62F43 and r["subject_logon_id"] == 0x62F43


def test_real_1102_log_cleared():
    r = real("s01_t00/per_file/dc01/security.jsonl", 1)
    assert r["event_id"] == 1102 and r["session_id"] is None
    assert is_relevant(r["channel"], r["event_id"])


def test_real_6005_system():
    r = real("s01_t00/per_file/dc01/system.jsonl", 3)
    assert r["event_id"] == 6005 and r["channel"] == "System" and r["host"] == "dc01"
    assert r["session_id"] is None and r["predefined_session"] == 0


def test_real_1074_system():
    r = real("s01_t00/per_file/ep-01/system.jsonl", 3)
    assert r["event_id"] == 1074 and r["host"] == "ep-01"


def test_real_7045():
    r = real("s01_t00/per_file/ep-03/system.jsonl", 87)
    assert r["event_id"] == 7045 and r["service_name"] == "Microsoft Kernel Debug Network Miniport"
    assert r["service_image_path"].lower().endswith("kdnic.sys")
    # NF-15 / NF-T10: default WIN-... computer name stays in export_host, host = folder
    assert r["host"] == "ep-03" and r["export_host"] == "WIN-V4KV8HLJS0B"


def test_real_5145():
    r = real("s01_t00/per_file/dc01/security.jsonl", 36)
    assert r["event_id"] == 5145
    assert r["session_id"] == r["subject_logon_id"] == 18504469
    assert r["source_port"] == 49761 and r["share_name"].endswith("IPC$")


def test_real_winrm_91():
    r = real("s01_t00/per_file/ep-03/winrm.jsonl", 1889)
    assert r["channel"] == "WinRM" and r["event_id"] == 91 and r["host"] == "ep-03"
    assert r["winrm_activity_id"]
    assert r["process_id"] is None  # NF-06: no XML Execution ProcessID fallback


def test_real_powershell_4104():
    r = real("s01_t00/per_file/ep-03/powershell.jsonl", 1)
    assert r["channel"] == "PowerShell" and r["event_id"] == 4104
    assert r["host"] == "ep-03"


def test_real_4768_machine_account():
    r = real("s01_t00/per_file/dc01/security.jsonl", 2329)
    assert r["event_id"] == 4768
    assert r["machine_account"] == 1 and r["account_name"] == "dc-01$"
    assert r["domain_short"] == "lab"  # realm lab.local


# ---------------------------------------------------------------- NF-01, NF-16 contract
def test_scenario_trial_carried_and_uid_differs_by_trial():
    ev = logon4624()
    a, b = norm(ev, trial="t00"), norm(ev, trial="t01")
    assert a["scenario_id"] == "s02" and a["trial_id"] == "t00" and b["trial_id"] == "t01"
    assert a["event_uid"] != b["event_uid"]
    assert norm(ev, scenario="s03")["event_uid"] != a["event_uid"]
    assert a["event_uid"] == norm(ev, trial="t00")["event_uid"]  # deterministic


def test_event_uid_differs_by_line():
    ev = logon4624()
    assert norm(ev, line=1)["event_uid"] != norm(ev, line=2)["event_uid"]


def test_raw_event_none_and_source_line():  # NF-09/NF-16
    r = norm(logon4624(), line=77)
    assert "raw_event" in r and r["raw_event"] is None
    assert r["source_line"] == 77
    assert r["source_relative_path"] == "ep-02/security.evtx"


def test_raw_event_sha256_canonical_and_stable():
    ev = logon4624()
    r1, r2 = norm(ev), norm(copy.deepcopy(ev))
    assert r1["raw_event_sha256"] == r2["raw_event_sha256"]
    compact = hashlib.sha256(json.dumps(ev, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=False).encode("utf-8")).hexdigest()
    compact_ascii = hashlib.sha256(json.dumps(ev, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert r1["raw_event_sha256"] in (compact, compact_ascii)
    reordered = dict(reversed(list(ev.items())))
    assert norm(reordered)["raw_event_sha256"] == r1["raw_event_sha256"]
    other = copy.deepcopy(ev)
    other["system"]["event_record_id"] = "43"
    assert norm(other)["raw_event_sha256"] != r1["raw_event_sha256"]


def test_does_not_mutate_input():
    ev = logon4624()
    snap = copy.deepcopy(ev)
    norm(ev)
    assert ev == snap


def test_output_has_new_columns():
    r = norm(logon4624())
    for col in ("trial_id", "account_name", "domain_short", "machine_account", "target_linked_logon_id",
                "source_image", "granted_access", "target_process_guid", "initiated",
                "sysmon_logon_guid", "export_host", "source_line", "raw_event_sha256", "predefined_session"):
        assert col in r, col


# ---------------------------------------------------------------- NF-03 ports
def test_port_zero_stays_zero():
    r = norm(logon4624(IpPort="0"))
    assert r["source_port"] == 0


def test_ipport_alias_for_4648_and_4625():
    for eid in (4625, 4648):
        ev = make_event("Security", eid, {"SubjectLogonId": "0x1234", "IpAddress": "10.0.0.1", "IpPort": "5555"})
        assert norm(ev)["source_port"] == 5555


# ---------------------------------------------------------------- NF-04 / NF-18 accounts
def test_user_at_realm_form():
    ev = make_event("Security", 4769, {"TargetUserName": "svc_backup@LAB.LOCAL", "TargetDomainName": "LAB.LOCAL",
                                       "ServiceName": "DC-01$", "IpAddress": "::ffff:192.168.50.22", "IpPort": "49762"})
    r = norm(ev)
    assert r["account_name"] == "svc_backup" and r["domain_short"] == "lab" and r["machine_account"] == 0


def test_domain_backslash_user_form_in_username_field():
    ev = logon4624(user="LAB\\svc_backup", domain="LAB")
    assert norm(ev)["account_name"] == "svc_backup"


def test_machine_account_plain_and_realm():
    plain = norm(logon4624(user="ep-02$", domain="LAB"))
    assert plain["machine_account"] == 1 and plain["account_name"] == "ep-02$"
    ev = make_event("Security", 4769, {"TargetUserName": "ep-02$@LAB.LOCAL", "TargetDomainName": "LAB.LOCAL",
                                       "ServiceName": "krbtgt"})
    realm = norm(ev)
    assert realm["machine_account"] == 1 and realm["account_name"] == "ep-02$"
    assert realm["service_name"] == "krbtgt"


def test_local_vs_domain_administrator():  # decision 008
    local = norm(logon4624(user="Administrator", domain="EP-02"))
    dom = norm(logon4624(user="Administrator", domain="LAB"))
    assert local["account_name"] == dom["account_name"] == "administrator"
    assert local["domain_short"] == "ep-02" and dom["domain_short"] == "lab"
    assert local["domain_short"] != dom["domain_short"]


def test_original_account_kept():
    r = norm(logon4624(user="SVC_Backup", domain="LAB"))
    assert "svc_backup" in r["account"].lower()  # NF-04 original kept in `account`


def test_sysmon_user_prefix_fills_domain():  # NF-14 / NF-18
    ev = make_event("Microsoft-Windows-Sysmon/Operational", 1,
                    {"User": "LAB\\svc_backup", "LogonId": "0x1a2b3", "LogonGuid": "{6f88cc0a-ad69-6ab4-e703-000000000000}",
                     "Image": "C:\\x.exe", "ProcessGuid": "{6f88cc0a-ad68-6ab4-0400-000000001400}"},
                    rel="ep-01/sysmon.evtx")
    r = norm(ev)
    assert r["domain"] == "LAB" and r["domain_short"] == "lab"
    assert r["account_name"] == "svc_backup" and r["subject_account"] is not None
    assert r["session_id"] == 0x1A2B3
    assert r["logon_guid"] is None and r["sysmon_logon_guid"] == "6f88cc0a-ad69-6ab4-e703-000000000000"
    assert r["predefined_session"] == 0


def test_sysmon10_source_target_user():  # NF-05
    ev = make_event("Microsoft-Windows-Sysmon/Operational", 10,
                    {"SourceUser": "LAB\\svc_backup", "TargetUser": "NT AUTHORITY\\SYSTEM",
                     "SourceImage": "C:\\a.exe", "TargetImage": "C:\\Windows\\system32\\lsass.exe",
                     "GrantedAccess": "0x1010", "SourceProcessGUID": "{aaaaaaaa-0000-0000-0000-000000000001}",
                     "TargetProcessGUID": "{bbbbbbbb-0000-0000-0000-000000000002}"}, rel="ep-01/sysmon.evtx")
    r = norm(ev)
    assert r["subject_account"] and "svc_backup" in r["subject_account"].lower()
    assert r["target_account"] and "system" in r["target_account"].lower()
    assert r["account_name"] == "svc_backup" and r["domain_short"] == "lab"
    assert r["granted_access"] == "0x1010"
    assert r["target_process_guid"] == "bbbbbbbb-0000-0000-0000-000000000002"


def test_sysmon3_initiated_false():
    ev = make_event("Microsoft-Windows-Sysmon/Operational", 3,
                    {"User": "NT AUTHORITY\\SYSTEM", "Initiated": "false", "SourceIp": "10.0.0.1",
                     "SourcePort": "445", "DestinationIp": "10.0.0.2", "DestinationPort": "50000"},
                    rel="ep-01/sysmon.evtx")
    r = norm(ev)
    assert r["initiated"] == 0 and r["predefined_session"] == 0


# ---------------------------------------------------------------- NF-11 / NF-12 / NF-13
def test_4624_logon_id_3e7_predefined():
    r = norm(logon4624(user="SYSTEM", domain="NT AUTHORITY", target_id="0x3e7"))
    assert r["session_id"] == 999 and r["predefined_session"] == 1


@pytest.mark.parametrize("hexid,pre", [("0x3e4", 1), ("0x3e5", 1), ("0x3e6", 1), ("0x3e7", 1), ("0x3e3", 0), ("0x3e8", 0)])
def test_predefined_logon_id_range(hexid, pre):
    assert norm(logon4624(user="u", domain="LAB", target_id=hexid))["predefined_session"] == pre


def test_anonymous_logon_predefined():
    r = norm(logon4624(user="ANONYMOUS LOGON", domain="NT AUTHORITY", target_id="0x12345"))
    assert r["predefined_session"] == 1 and r["account_name"] == "anonymous logon"


def test_predefined_not_set_for_other_events():
    ev = make_event("Security", 4688, {"SubjectUserName": "SYSTEM", "SubjectDomainName": "NT AUTHORITY",
                                       "SubjectLogonId": "0x3e7", "NewProcessId": "0x10"})
    assert norm(ev)["predefined_session"] == 0  # not in 4624/4634/4647/4648/4672


def test_sysmon3_system_user_predefined_zero():
    ev = make_event("Microsoft-Windows-Sysmon/Operational", 3,
                    {"User": "NT AUTHORITY\\SYSTEM", "Initiated": "true", "SourceIp": "10.0.0.1",
                     "SourcePort": "4000", "DestinationIp": "10.0.0.2", "DestinationPort": "445"},
                    rel="ep-03/sysmon.evtx")
    assert norm(ev)["predefined_session"] == 0


def test_zero_logon_ids_become_null_synthetic():
    ev = make_event("Security", 4688, {"SubjectLogonId": "0x5f3f3", "TargetLogonId": "0x0"})
    r = norm(ev)
    assert r["session_id"] == 390131 and r["target_logon_id"] is None
    r2 = norm(make_event("Security", 4625, {"SubjectLogonId": "0x0", "TargetLogonId": "0x0"}))
    for col in LOGON_ID_COLUMNS:
        assert r2[col] is None


def test_target_linked_logon_id():  # NF-12
    r = norm(logon4624(TargetLinkedLogonId="0x1a2b4"))
    assert r["target_linked_logon_id"] == 0x1A2B4
    assert norm(logon4624(TargetLinkedLogonId="0x0"))["target_linked_logon_id"] is None


def test_session_id_by_event_id():
    cases = {4624: "TargetLogonId", 4634: "TargetLogonId", 4648: "SubjectLogonId", 4672: "SubjectLogonId",
             4688: "SubjectLogonId", 5140: "SubjectLogonId", 5145: "SubjectLogonId"}
    for eid, col in cases.items():
        other = "SubjectLogonId" if col == "TargetLogonId" else "TargetLogonId"
        ev = make_event("Security", eid, {col: "0x1111", other: "0x2222"})
        assert norm(ev)["session_id"] == 0x1111, eid


def test_session_id_null_for_sessionless_events():
    ev = make_event("Security", 4769, {"TargetUserName": "a", "SubjectLogonId": "0x1", "TargetLogonId": "0x2"})
    assert norm(ev)["session_id"] is None


# ---------------------------------------------------------------- NF-15 hosts
def test_computer_ep01_in_folder_ep02():
    ev = make_event("Security", 4624, {"TargetLogonId": "0x1234"}, rel="ep-02/security.evtx", computer="EP-01")
    r = norm(ev)
    assert r["host"] == "ep-02" and r["export_host"] == "EP-01"


def test_relative_path_unknown_folder_raises():
    ev = make_event("Security", 4624, {"TargetLogonId": "0x1234"}, rel="win-xyz/security.evtx")
    with pytest.raises(ValueError):
        norm(ev)


def test_source_destination_host_lowercase():
    ev = make_event("Security", 4648, {"SubjectLogonId": "0x1234", "TargetServerName": "DC-01.lab.local",
                                       "WorkstationName": "ENDPOINT-01"})
    r = norm(ev)
    for k in ("source_host", "destination_host"):
        if r.get(k) is not None:
            assert r[k] == r[k].lower(), (k, r[k])
    assert r["destination_host"] == "dc01"
    assert r["source_host"] == "ep-01"


# ---------------------------------------------------------------- NF-06 / NF-17
def test_security_process_id_no_xml_fallback():
    ev = make_event("Security", 4672, {"SubjectLogonId": "0x1234"})  # raw_xml has Execution ProcessID 772
    assert norm(ev)["process_id"] is None
    ev_sys = make_event("System", 7045, {"ServiceName": "x"}, rel="ep-03/system.evtx")
    assert norm(ev_sys)["process_id"] is None
    ev_w = make_event("Microsoft-Windows-WinRM/Operational", 91, {}, rel="ep-03/winrm.evtx")
    assert norm(ev_w)["process_id"] is None


def test_real_event_xml_fallback_removed():
    """Same, built by modifying a real event: drop ProcessId from a real 4624."""
    ev = read_line("s02_t00/per_file/dc01/security.jsonl", 33)
    ev["event_data"] = [d for d in ev["event_data"] if d["name"] != "ProcessId"]
    assert "Execution ProcessID" in (ev.get("raw_xml") or "")
    assert norm(ev)["process_id"] is None


def test_kept_row_null_timestamp_raises():
    with pytest.raises(ValueError):
        norm(make_event("Security", 4624, {"TargetLogonId": "0x1"}, ts=None))


# ---------------------------------------------------------------- no zero in logon-id columns
@pytest.mark.parametrize("rel", [
    "s01_t00/per_file/dc01/security.jsonl",
    "s02_t00/per_file/ep-02/security.jsonl",
    "s01_t00/per_file/ep-01/sysmon.jsonl",
    "s03_t00/per_file/ep-01/security.jsonl",
])
def test_no_zero_logon_ids_first_2000(rel):
    path = JSONL / rel
    if not path.exists():
        pytest.skip(f"missing {path}")
    n = 0
    with open(path, encoding="utf-8", newline="") as fh:
        for i, line in enumerate(fh.read().split("\n"), 1):
            if not line.strip():
                continue
            r = norm(json.loads(line), line=i)
            for col in LOGON_ID_COLUMNS:
                assert r[col] != 0, (rel, i, col)
            assert r["host"] in HOSTS and r["raw_event"] is None and r["source_line"] == i
            assert r["trial_id"] == "t00"
            n += 1
            if n >= 2000:
                break
    assert n > 0
