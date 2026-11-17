"""T8.2d: the 14 locked rules and their manifest (spec 04_label LBT-02, LBT-08, LB-04, LB-07, LB-10, LB-12, LB-13,
section 3.3 licence, section 3.5 locked list, decisions 056 / 057 / 058).

Written from the spec's rule tables, not from the implementation or from the rule files' own text (the rule YAML was
read only to learn which keys a rule's filter uses). Synthetic events only; the rules folder is copied into a pytest
`tmp_path` for every refusal test, so the committed folder is never touched.
"""
from __future__ import annotations

import csv
import io
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from label import params as lp  # noqa: E402
from label import rules as lr  # noqa: E402
from label.errors import LabelError  # noqa: E402
from label.events import Event  # noqa: E402
from label.labels import match_event  # noqa: E402

RULES_DIR = Path(lp.RULES_DIR)
RULESET = lr.load_rules(RULES_DIR)
RULES = RULESET.rules
BY_ID = {r.rule_id: r for r in RULES}

# Spec 3.5 (literal copy): rule -> (technique, source, level)
LOCKED = {
    "SR-01": ("T1003.001", "sigmahq", "high"), "SR-02": ("T1003.001", "sigmahq", "medium"),
    "SR-03": ("T1003.001", "sigmahq", "high"), "SR-10": ("T1021.002", "sigmahq", "low"),
    "SR-11": ("T1021.002", "sigmahq", "high"), "SR-12": ("T1021.002", "sigmahq", "medium"),
    "SR-20": ("T1570", "own", "low"), "SR-30": ("T1569.002", "own", "low"), "SR-31": ("T1569.002", "own", "low"),
    "SR-40": ("T1021.006", "sigmahq", "medium"), "SR-41": ("T1021.006", "sigmahq", "high"),
    "SR-50": ("T1021.001", "own", "low"), "SR-60": ("T1078", "sigmahq", "medium"),
    "SR-61": ("T1550.002", "sigmahq", "medium"),
}
SIGMA_IDS = {"SR-01": "a49fa4d5-11db-418c-8473-1e014a8dd462", "SR-02": "5ef9853e-4d0e-4a70-846f-a9ca37d876da",
             "SR-03": "aa35a627-33fb-4d04-a165-d33b4afca3e8", "SR-10": "098d7118-55bc-4912-a836-dc6483a8d150",
             "SR-11": "b210394c-ba12-4f89-9117-44a2464b9511", "SR-12": "586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3",
             "SR-40": "734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8", "SR-41": "c539afac-c12a-46ed-b1bd-5a5567c9f045",
             "SR-60": "941e5c45-cda7-4864-8cea-bbb7458d194a", "SR-61": "8eef149c-bd26-49f2-9e5a-9b00e3af499b"}
LEVEL_VALUE = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SIGMA_COMMIT = "54967d64e6dda2b4daa81f47f7a8bf1f591b68a0"


def ids_matching(channel: str, event_id: int, fields: dict) -> set[str]:
    """Rule ids that match one synthetic event. `eventid` is always present, as in the real `field_values_json`."""
    f = {"eventid": [str(event_id)]}
    f.update({k.lower(): v if isinstance(v, list) else [v] for k, v in fields.items()})
    e = Event(uid="u1", host="ep-01", channel=channel, event_id=event_id, record_id=1, us_raw=0, us=0,
              clock_unreliable=0, fields_json=json.dumps(f))
    return {m.rule.rule_id for m in match_event(e, RULES)}


# ================================================================================================ the locked list
def test_the_manifest_lists_exactly_the_14_locked_rules_with_locked_technique_source_level():
    rows = {r["rule_id"]: r for r in RULESET.manifest_rows}
    assert set(rows) == set(LOCKED)
    for rid, (tech, source, level) in LOCKED.items():
        assert (rows[rid]["technique"], rows[rid]["source"], rows[rid]["level"]) == (tech, source, level), rid


def test_sr_42_is_dropped():
    assert "SR-42" not in BY_ID


def test_level_value_map_of_every_loaded_rule():
    for r in RULES:
        assert r.level_value == LEVEL_VALUE[r.level], r.rule_id
    assert lp.LEVEL_VALUE == LEVEL_VALUE


def test_own_rules_are_low_lb07():
    assert {r.rule_id for r in RULES if r.source == "own"} == {"SR-20", "SR-30", "SR-31", "SR-50"}
    assert all(r.level == "low" for r in RULES if r.source == "own")


def test_the_sigma_commit_parameter():
    assert lp.SIGMA_COMMIT == SIGMA_COMMIT


def test_secondary_technique_and_tactic_tags_are_kept_on_the_rule():
    """Spec 3.1: T1059.001 is a second tag of SR-03 / SR-40 / SR-41; T1078 stays primary of SR-60."""
    assert BY_ID["SR-40"].technique == "T1021.006" and "T1059.001" in BY_ID["SR-40"].techniques
    assert "T1059.001" in BY_ID["SR-41"].techniques
    assert "T1059.001" in BY_ID["SR-03"].techniques
    assert BY_ID["SR-60"].technique == "T1078"
    assert all(r.technique in r.techniques for r in RULES)
    assert all(r.tactics for r in RULES)


# ================================================================================================ LBT-02 per rule
LSASS = r"C:\Windows\system32\lsass.exe"
NTDLL = r"C:\Windows\SYSTEM32\ntdll.dll+a"
# rule -> (channel, event id, minimal matching fields, {variant: overrides that must NOT match}, {variant: overrides
# that must STILL match}). A None override removes the field.
CASES: dict[str, tuple[str, int, dict, dict, dict]] = {
    "SR-01": ("Sysmon", 10,
              {"targetimage": LSASS, "sourceimage": r"C:\Windows\System32\rundll32.exe",
               "calltrace": r"C:\Windows\SYSTEM32\ntdll.dll+a|C:\Windows\system32\COMSVCS.dll+b"},
              {"sel_targetimage": {"targetimage": r"C:\Windows\explorer.exe"},
               "sel_sourceimage": {"sourceimage": r"C:\Windows\System32\cmd.exe"},
               "sel_calltrace": {"calltrace": NTDLL},
               "absent_targetimage": {"targetimage": None}, "absent_calltrace": {"calltrace": None}},
              {"upper_case": {"targetimage": LSASS.upper(), "sourceimage": r"C:\X\RUNDLL32.EXE"}}),
    "SR-02": ("Sysmon", 10,
              {"targetimage": LSASS, "grantedaccess": "0x1438", "calltrace": NTDLL, "sourceuser": r"LAB\alice",
               "sourceimage": r"C:\Tools\x.exe"},
              {"sel_targetimage": {"targetimage": r"C:\Windows\explorer.exe"},
               "sel_grantedaccess": {"grantedaccess": "0x0010"},
               "sel_calltrace": {"calltrace": r"C:\x\foo.sys+a"},
               "filter_system_user": {"sourceuser": r"NT AUTHORITY\SYSTEM"},
               "filter_system_user_other_language": {"sourceuser": r"NT AUTORITE\SYSTEM"},
               "filter_sysmon": {"sourceimage": r"C:\Windows\Sysmon64.exe"},
               "filter_thor": {"calltrace": NTDLL + r"|C:\Windows\Temp\asgard2-agent\x\thor\thor64.exe+1|UNKNOWN(0)",
                               "grantedaccess": "0x103800"}},
              {"access_0x1fffff": {"grantedaccess": "0x1fffff"},
               "filter_field_absent": {"sourceuser": None, "sourceimage": None},
               "thor_calltrace_but_other_access": {"calltrace": NTDLL + r"|C:\Windows\Temp\asgard2-agent\x\thor"
                                                                      r"\thor64.exe+1|UNKNOWN(0)"}}),
    "SR-03": ("Sysmon", 10,
              {"targetimage": LSASS, "sourceimage": r"C:\Windows\system32\wsmprovhost.exe", "grantedaccess": "0x1410"},
              {"sel_targetimage": {"targetimage": r"C:\Windows\explorer.exe"},
               "sel_sourceimage": {"sourceimage": r"C:\Windows\system32\rundll32.exe"},
               "filter_access": {"grantedaccess": "0x80000000"}},
              {"filter_field_absent": {"grantedaccess": None}}),
    "SR-10": ("Security", 5140,
              {"sharename": r"\\*\ADMIN$", "subjectusername": "alice"},
              {"sel_sharename_ipc": {"sharename": r"\\*\IPC$"},
               "sel_sharename_as_written_upstream": {"sharename": "Admin$"},      # no backslash: not the stored form
               "sel_eventid": {"eventid": "5145"},
               "filter_machine_account": {"subjectusername": "WS01$"}},
              {"filter_field_absent": {"subjectusername": None}, "lower_case": {"sharename": r"\\*\admin$"}}),
    "SR-11": ("Security", 5145,
              {"sharename": r"\\*\C$", "accessmask": "0x2", "subjectusername": "alice", "ipaddress": "192.168.50.21"},
              {"sel_sharename": {"sharename": r"\\*\ADMIN$"}, "sel_accessmask": {"accessmask": "0x1"},
               "sel_eventid": {"eventid": "5140"},
               "filter_machine_account": {"subjectusername": "WS01$"}, "filter_ipv6_loopback": {"ipaddress": "::1"}},
              {"filter_fields_absent": {"subjectusername": None, "ipaddress": None}}),
    "SR-12": ("Security", 5145,
              {"sharename": r"\\*\IPC$", "relativetargetname": "svcctl", "accesslist": "WriteData (or AddFile)"},
              {"sel_sharename": {"sharename": r"\\*\ADMIN$"}, "sel_relativetarget": {"relativetargetname": "foo"},
               "sel_accesslist": {"accesslist": "ReadData"},
               "stored_code_form_is_not_the_word": {"accesslist": "%%4417 "},
               "absent_relativetarget": {"relativetargetname": None}},
              {}),
    "SR-20": ("Security", 5145,
              {"sharename": r"\\*\ADMIN$", "relativetargetname": "x.exe", "accesslist": "%%4417 "},
              {"sel_sharename_ipc_decision_059": {"sharename": r"\\*\IPC$"},
               "sel_sharename": {"sharename": r"\\*\LabShare"}, "sel_extension": {"relativetargetname": "x.txt"},
               "sel_accesslist": {"accesslist": "%%4416"}, "sel_eventid": {"eventid": "5140"},
               "absent_accesslist": {"accesslist": None}},
              {"c_share": {"sharename": r"\\*\C$"}, "ps1": {"relativetargetname": "dir\\X.PS1"},
               "machine_account_not_filtered": {"subjectusername": "WS01$"},
               "dll": {"relativetargetname": "a.dll"}, "bat": {"relativetargetname": "a.bat"},
               "cmd": {"relativetargetname": "a.cmd"}, "vbs": {"relativetargetname": "a.vbs"}}),
    "SR-30": ("System", 7045,
              {"provider": "Service Control Manager", "servicename": "svc"},
              {"sel_provider": {"provider": "Microsoft-Windows-Kernel-General"}, "sel_eventid": {"eventid": "7036"},
               "absent_provider": {"provider": None}},
              {}),
    "SR-31": ("Security", 4697,
              {"servicename": "svc", "servicetype": "0x10"},
              {"sel_eventid": {"eventid": "4698"},
               "filter_per_user_service_0xd0": {"servicetype": "0xd0"},
               "filter_per_user_service_0xe0": {"servicetype": "0xe0"}},
              {"filter_field_absent": {"servicetype": None},
               "machine_account_not_filtered_atk_l05": {"subjectusername": "WS01$"}}),
    "SR-41": ("Sysmon", 3,
              {"destinationport": "5985", "initiated": "true", "sourceisipv6": "false",
               "user": r"LAB\alice", "sourceip": "192.168.50.21", "destinationip": "192.168.50.22",
               "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
              {"sel_port": {"destinationport": "80"}, "sel_initiated": {"initiated": "false"},
               "sel_ipv6": {"sourceisipv6": "true"},
               "filter_network_service": {"user": r"NT AUTHORITY\NETWORK SERVICE"},
               "filter_network_service_french": {"user": r"NT AUTORITE\SERVICE RÉSEAU"},
               "filter_loopback": {"sourceip": "127.0.0.1", "destinationip": "127.0.0.1"},
               "filter_loopback_v6": {"sourceip": "::1", "destinationip": "::1"},
               "filter_avast": {"image": r"C:\Program Files\Avast Software\Avast\AvastSvc.exe"}},
              {"port_5986": {"destinationport": "5986"},
               "only_source_is_loopback": {"sourceip": "127.0.0.1"},
               "filter_fields_absent": {"user": None, "sourceip": None, "destinationip": None, "image": None}}),
    "SR-50": ("Security", 4624, {"logontype": "10"},
              {"sel_type3_by_ip_atk_l06": {"logontype": "3"}, "sel_type2": {"logontype": "2"},
               "sel_eventid": {"eventid": "4625"}, "absent_type": {"logontype": None}},
              {}),
    "SR-60": ("Security", 4648,
              {"processname": r"C:\Windows\System32\winrs.exe", "targetservername": "ep-02",
               "subjectusername": "alice", "targetusername": "bob"},
              {"sel_dash_processname": {"processname": "-"},
               "sel_other_process": {"processname": r"C:\Windows\explorer.exe"},
               "sel_eventid": {"eventid": "4624"},
               "filter_localhost": {"targetservername": "localhost"},
               "filter_both_machine_accounts": {"subjectusername": "A$", "targetusername": "B$"},
               "absent_processname": {"processname": None}},
              {"only_subject_is_machine": {"subjectusername": "A$"},
               "only_target_is_machine": {"targetusername": "B$"},
               "powershell": {"processname": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
               "net1": {"processname": r"C:\Windows\System32\net1.exe"},
               "filter_fields_absent": {"targetservername": None, "subjectusername": None, "targetusername": None}}),
}


def merged(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


def case_params(index: int):
    return [pytest.param(rid, name, id=f"{rid}-{name}") for rid, c in CASES.items() for name in c[index]]


@pytest.mark.parametrize("rid", sorted(CASES))
def test_lbt02_minimal_matching_event_matches_its_rule(rid):
    ch, eid, base, _no, _yes = CASES[rid]
    assert rid in ids_matching(ch, eid, base)


@pytest.mark.parametrize("rid,variant", case_params(3))
def test_lbt02_each_broken_selection_or_triggered_filter_does_not_match(rid, variant):
    ch, eid, base, no, _yes = CASES[rid]
    over = dict(no[variant])
    eid2 = int(over.pop("eventid")) if "eventid" in over else eid
    assert rid not in ids_matching(ch, eid2, merged(base, over))


@pytest.mark.parametrize("rid,variant", case_params(4))
def test_lbt02_alternatives_and_missing_filter_fields_still_match(rid, variant):
    ch, eid, base, _no, yes = CASES[rid]
    assert rid in ids_matching(ch, eid, merged(base, yes[variant]))


@pytest.mark.parametrize("rid", sorted(CASES))
def test_lbt02_the_logsource_restricts_the_channel(rid):
    """The same fields on a channel / event no rule covers match nothing; a wrong channel never matches."""
    _ch, eid, base, _no, _yes = CASES[rid]
    assert ids_matching("Application", eid, base) == set()


def test_lbt02_sr20_is_anchored_on_the_backslash_and_does_not_match_ipc_dollar_decision_059():
    """Decision 059: SR-20's share literals are `\\ADMIN$` / `\\C$`, so the stored IPC$ name (which ends in `C$`) does
    not match; ADMIN$ and C$ still do."""
    exe = {"relativetargetname": "x.exe", "accesslist": "%%4417 "}
    assert "SR-20" not in ids_matching("Security", 5145, dict(exe, sharename=r"\\*\IPC$"))
    assert "SR-20" in ids_matching("Security", 5145, dict(exe, sharename=r"\\*\ADMIN$"))
    assert "SR-20" in ids_matching("Security", 5145, dict(exe, sharename=r"\\*\C$"))


def test_lbt02_sr11_endswith_c_dollar_also_covers_ipc_dollar_as_written_upstream():
    """Characterisation (a note, not a defect): SR-11 is an unchanged SigmaHQ copy, `ShareName endswith C$` as written
    upstream, so a 0x2 access on the stored IPC$ name is labelled."""
    assert "SR-11" in ids_matching("Security", 5145, {"sharename": r"\\*\IPC$", "accessmask": "0x2"})


def test_lbt02_sr_40_sysmon_1_image_or_parent_image():
    img = r"C:\Windows\System32\wsmprovhost.exe"
    assert "SR-40" in ids_matching("Sysmon", 1, {"image": img})
    assert "SR-40" in ids_matching("Sysmon", 1, {"parentimage": img, "image": r"C:\Windows\System32\cmd.exe"})
    assert "SR-40" not in ids_matching("Sysmon", 1, {"image": r"C:\Windows\System32\cmd.exe"})
    assert "SR-40" not in ids_matching("Sysmon", 1, {"image": None or r"C:\x\notwsmprovhost.exe.txt"})
    assert "SR-40" not in ids_matching("Sysmon", 1, {})


def test_lbt02_sr_40_security_4688_uses_the_renamed_fields():
    img = r"C:\Windows\System32\wsmprovhost.exe"
    assert "SR-40" in ids_matching("Security", 4688, {"newprocessname": img})
    assert "SR-40" in ids_matching("Security", 4688, {"parentprocessname": img, "newprocessname": r"C:\x\cmd.exe"})
    assert "SR-40" not in ids_matching("Security", 4688, {"image": img})             # the Sysmon name: no 4688 field
    assert "SR-40" not in ids_matching("Security", 4688, {"parentimage": img})
    assert "SR-40" not in ids_matching("Security", 4688, {"newprocessname": r"C:\Windows\System32\cmd.exe"})


def test_lbt02_sr_61_both_selections_and_the_filter():
    m3 = {"subjectusersid": "S-1-0-0", "logontype": "3", "logonprocessname": "NtLmSsp", "keylength": "0",
          "targetusername": "bob"}
    m9 = {"logontype": "9", "logonprocessname": "seclogo", "targetusername": "bob"}
    assert "SR-61" in ids_matching("Security", 4624, m3)
    assert "SR-61" in ids_matching("Security", 4624, m9)
    for name, over in {"sid": {"subjectusersid": "S-1-5-21-1"}, "type": {"logontype": "2"},
                       "process": {"logonprocessname": "Kerberos"}, "keylength": {"keylength": "128"},
                       "filter_anonymous": {"targetusername": "ANONYMOUS LOGON"}}.items():
        assert "SR-61" not in ids_matching("Security", 4624, merged(m3, over)), name
    assert "SR-61" not in ids_matching("Security", 4624, merged(m9, {"logonprocessname": "NtLmSsp"}))
    assert "SR-61" not in ids_matching("Security", 4624, merged(m9, {"targetusername": "ANONYMOUS LOGON"}))
    assert "SR-61" not in ids_matching("Security", 4625, {}) and "SR-61" not in ids_matching("Security", 4624, {})


def test_lbt02_stored_value_formats_apply_as_written_no_trimming():
    """Spec 6: a value-format mismatch is not fixed by trimming. `NtLmSsp ` (padded) does not match SR-61's literal."""
    m3 = {"subjectusersid": "S-1-0-0", "logontype": "3", "logonprocessname": "NtLmSsp ", "keylength": "0"}
    assert "SR-61" not in ids_matching("Security", 4624, m3)


def test_lbt02_an_event_may_match_several_rules_lb06():
    got = ids_matching("Sysmon", 10, {"targetimage": LSASS, "sourceimage": r"C:\Windows\System32\rundll32.exe",
                                      "calltrace": r"C:\Windows\SYSTEM32\ntdll.dll+a|C:\Windows\system32\comsvcs.dll+b",
                                      "grantedaccess": "0x1038", "sourceuser": r"LAB\alice"})
    assert {"SR-01", "SR-02"} <= got


def test_lbt02_a_plain_network_logon_is_labelled_by_no_rule():
    """Spec 10.1 / L-LB3: nothing labels a plain type 3 logon."""
    assert ids_matching("Security", 4624, {"logontype": "3", "targetusername": "alice"}) == set()


def test_lbt02_atk_l01_unlisted_dump_tools_stay_unlabelled():
    """A dump by another tool (mask / call trace outside SR-01 / SR-02) is not labelled; identity is unaffected."""
    got = ids_matching("Sysmon", 10, {"targetimage": LSASS, "sourceimage": r"C:\Tools\procdump64.exe",
                                      "grantedaccess": "0x1410", "calltrace": r"C:\x\foo.sys+a",
                                      "sourceuser": r"LAB\alice"})
    assert got == set()


# ================================================================================================ LBT-08 manifest
@pytest.fixture()
def rules_copy(tmp_path):
    dst = tmp_path / "rules"
    shutil.copytree(RULES_DIR, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def test_the_committed_manifest_loads_and_matches_the_files():
    rs = lr.load_rules(RULES_DIR)
    assert len(rs.rules) == 14
    for row in rs.manifest_rows:
        assert lr.lf_sha256((RULES_DIR / row["file"]).read_bytes()) == row["sha256"]


def test_manifest_columns_are_the_spec_columns():
    with open(RULES_DIR / "manifest.csv", newline="", encoding="utf-8") as fh:
        assert next(csv.reader(fh)) == [
            "rule_id", "file", "sha256", "source", "sigma_id", "sigma_commit", "title", "author", "license",
            "references", "technique", "techniques", "tactics", "level"]


def test_a_changed_rule_file_refuses_the_run(rules_copy):
    p = rules_copy / "SR-30_service_installed_system.yml"
    p.write_text(p.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8", newline="\n")
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


def test_a_changed_level_in_a_rule_file_refuses_the_run(rules_copy):
    p = rules_copy / "SR-01_lsass_dump_comsvcs_dll.yml"
    p.write_bytes(p.read_bytes().replace(b"level: high", b"level: low"))
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


def test_a_missing_rule_file_refuses_the_run(rules_copy):
    (rules_copy / "SR-61_pass_the_hash_2.yml").unlink()
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


def test_an_extra_rule_file_not_in_the_manifest_refuses_the_run(rules_copy):
    shutil.copy(rules_copy / "SR-30_service_installed_system.yml", rules_copy / "SR-99_extra.yml")
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


@pytest.mark.parametrize("name", ["notes.txt", "SR-01_backup.yml.bak", "README.md", "extra.csv"])
def test_any_other_file_in_the_rules_folder_refuses_the_run_decision_058(rules_copy, name):
    (rules_copy / name).write_text("x", encoding="utf-8")
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


def test_a_manifest_row_without_a_file_refuses_the_run(rules_copy):
    text = (rules_copy / "manifest.csv").read_text(encoding="utf-8")
    rows = list(csv.DictReader(io.StringIO(text)))
    rows.append(dict(rows[0], rule_id="SR-98", file="SR-98_none.yml"))
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    (rules_copy / "manifest.csv").write_text(out.getvalue(), encoding="utf-8", newline="\n")
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


def test_a_rule_file_without_a_manifest_row_refuses_the_run(rules_copy):
    text = (rules_copy / "manifest.csv").read_text(encoding="utf-8").splitlines(keepends=True)
    kept = [ln for ln in text if not ln.startswith("SR-61,")]
    assert len(kept) == len(text) - 1
    (rules_copy / "manifest.csv").write_text("".join(kept), encoding="utf-8", newline="\n")
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


def test_a_missing_manifest_refuses_the_run(rules_copy):
    (rules_copy / "manifest.csv").unlink()
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


def test_a_manifest_changed_to_match_a_changed_file_is_refused_by_the_pins(rules_copy):
    """LB-10 / ATK-S01: re-pinning a changed rule in the manifest copy does not help; the pins are in the code."""
    p = rules_copy / "SR-50_rdp_logon.yml"
    p.write_bytes(p.read_bytes().replace(b"LogonType: 10", b"LogonType: 3"))
    (rules_copy / "manifest.csv").write_text(lr.manifest_text(lr.build_manifest_rows(rules_copy)), encoding="utf-8",
                                             newline="\n")
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


def test_crlf_line_endings_give_the_same_hash_lb13(rules_copy):
    for p in rules_copy.iterdir():
        p.write_bytes(p.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert b"\r\n" in (rules_copy / "SR-30_service_installed_system.yml").read_bytes()
    rs = lr.load_rules(rules_copy)                              # manifest and files all CRLF: still accepted
    assert rs.manifest_sha256 == RULESET.manifest_sha256
    assert [r["sha256"] for r in rs.manifest_rows] == [r["sha256"] for r in RULESET.manifest_rows]
    for r in RULES:
        assert lr.lf_sha256((rules_copy / r.file).read_bytes()) == lr.lf_sha256((RULES_DIR / r.file).read_bytes())


def test_lf_sha256_ignores_crlf_and_lone_cr():
    base = b"a\nb\nc\n"
    assert lr.lf_sha256(base) == lr.lf_sha256(base.replace(b"\n", b"\r\n")) == lr.lf_sha256(base.replace(b"\n", b"\r"))
    assert lr.lf_sha256(base) != lr.lf_sha256(b"a\nb\nd\n")


def test_each_rule_file_declares_one_manifest_row():
    rows = RULESET.manifest_rows
    assert len({r["rule_id"] for r in rows}) == len(rows) == 14
    assert len({r["file"] for r in rows}) == 14
    on_disk = {p.name for p in RULES_DIR.glob("*.yml")}
    assert on_disk == {r["file"] for r in rows}


def test_licence_columns_for_every_sigmahq_rule_section_3_3():
    for r in RULESET.manifest_rows:
        if r["source"] == "sigmahq":
            assert r["license"] == "DRL-1.1", r["rule_id"]
            assert r["sigma_commit"] == SIGMA_COMMIT, r["rule_id"]
            assert r["sigma_id"] == SIGMA_IDS[r["rule_id"]], r["rule_id"]
            assert r["author"].strip() and r["title"].strip(), r["rule_id"]
        else:
            assert r["license"] == "own" and r["sigma_id"] == "" and r["sigma_commit"] == "", r["rule_id"]


def test_sigmahq_rule_files_carry_the_drl_attribution_and_the_commit():
    for r in RULESET.manifest_rows:
        if r["source"] != "sigmahq":
            continue
        text = (RULES_DIR / r["file"]).read_text(encoding="utf-8")
        assert "Detection Rule License" in text, r["rule_id"]
        assert SIGMA_COMMIT in text, r["rule_id"]


def test_an_unchanged_sigmahq_rule_keeps_its_id_and_the_adapted_sr10_has_a_new_id_and_a_derived_related():
    import yaml
    for r in RULESET.manifest_rows:
        if r["source"] != "sigmahq":
            continue
        doc = yaml.safe_load((RULES_DIR / r["file"]).read_text(encoding="utf-8"))
        if r["rule_id"] == "SR-10":
            assert doc["id"] != SIGMA_IDS["SR-10"]
            rel = doc.get("related") or []
            assert any(x.get("id") == SIGMA_IDS["SR-10"] and x.get("type") == "derived" for x in rel)
        else:
            assert doc["id"] == SIGMA_IDS[r["rule_id"]], r["rule_id"]
        assert doc["title"] == r["title"]


def test_the_manifest_is_the_locked_one_the_run_info_pins_it():
    """LB-10: the run pins the manifest hash (checked end to end in test_label_stage); here it is a stable value."""
    assert len(RULESET.manifest_sha256) == 64
    assert RULESET.manifest_sha256 == lr.lf_sha256((RULES_DIR / "manifest.csv").read_bytes())


# ================================================================================================ ATK-S01 pins (decision 061)
# Literal copy of the pinned LF SHA-256 values of src/label/params.py (RULE_SHA256, MANIFEST_SHA256), 14 + 1. A
# legitimate rule change must update the rule file, the manifest, params.py, THIS table and a new decision record.
PINNED = {
    "SR-01": "e21fdafd9ae62edb6a1e56626098962446db0116b7d74c65390e2004f9b6eea1",
    "SR-02": "685d4e6de0d8644006aea0a333d155f8053e8fd545a211003c608cc2a633a952",
    "SR-03": "aa5a9efa0c5fe4e3b65d26433eb163293706c08bd14579161ca4eaf41dcd8729",
    "SR-10": "ea4c7616dc2668960a7f90be68bd14bac6f8918146bf3caa3c1f03989f027cb4",
    "SR-11": "48965a503ddb84bd0f98b9215467e1ac5b83caaf40cda976b154e108efdec368",
    "SR-12": "8b0320e5467b94d464f5212a363a72cebfdfb6ce3bfa36d2c43c8bc9b6ed3171",
    "SR-20": "570444935014e6040f59809e0ccd5932e149240dade4cca2fcabe3d36dca1532",
    "SR-30": "bb8fdfdf290358e91a0268f5a1df2b4d81c5189395df5c7a65a612edd5b87c04",
    "SR-31": "1358bda73b3fa08a6738afa1d44abb1d2dcbd52c1142b9c3ae693f4948dd348f",
    "SR-40": "fc874778dd8be01110ead523c56b7892206daf981152fa40371f3a2b9741f1a1",
    "SR-41": "d6e78042bab06777df640416fa2d62e6906f28fa155e09b115de1674cbcadc59",
    "SR-50": "5a05e9aacee626c8a139c30bccb1ebba710c7514590e0874dc601ac8f2d9eb32",
    "SR-60": "abc7123f2e21d4bf6fc90711885f68478d253993b360897fa00d6a27c3a903bb",
    "SR-61": "a60b80c34a90e086dc1a394b8bc2c252684d17fec99c37939f8a9f43a958f1b7",
}
PINNED_MANIFEST = "3508a065dad556d0aad214470270dc4868759c4b023b3454febfb1d45288ee5e"


def test_atk_s01_the_code_pins_equal_the_literals_held_here():
    assert dict(lp.RULE_SHA256) == PINNED
    assert lp.MANIFEST_SHA256 == PINNED_MANIFEST
    assert len(PINNED) + 1 == 15


def test_atk_s01_the_files_on_disk_hash_to_the_pins_lf_normalised():
    for row in RULESET.manifest_rows:
        data = (RULES_DIR / row["file"]).read_bytes()
        assert lr.lf_sha256(data) == PINNED[row["rule_id"]], row["rule_id"]
    assert lr.lf_sha256((RULES_DIR / "manifest.csv").read_bytes()) == PINNED_MANIFEST
    assert RULESET.manifest_sha256 == PINNED_MANIFEST


@pytest.mark.parametrize("rid", sorted(PINNED))
def test_atk_s01_a_changed_rule_byte_with_a_rebuilt_manifest_is_refused(rules_copy, rid):
    row = next(r for r in RULESET.manifest_rows if r["rule_id"] == rid)
    p = rules_copy / row["file"]
    p.write_bytes(p.read_bytes() + b"\n# one more comment line\n")                     # a harmless-looking change
    (rules_copy / "manifest.csv").write_text(lr.manifest_text(lr.build_manifest_rows(rules_copy)), encoding="utf-8",
                                             newline="\n")
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


def test_atk_s01_a_changed_manifest_byte_is_refused(rules_copy):
    p = rules_copy / "manifest.csv"
    data = bytearray(p.read_bytes())
    i = data.index(b"Pass the Hash") + 5                                                 # inside a title cell
    data[i] = ord("X")
    p.write_bytes(bytes(data))
    with pytest.raises(LabelError):
        lr.load_rules(rules_copy)


def test_atk_s01_the_refusal_says_a_new_decision_record_is_needed(rules_copy):
    p = rules_copy / "SR-30_service_installed_system.yml"
    p.write_bytes(p.read_bytes() + b"# x\n")
    (rules_copy / "manifest.csv").write_text(lr.manifest_text(lr.build_manifest_rows(rules_copy)), encoding="utf-8",
                                             newline="\n")
    with pytest.raises(LabelError) as exc:
        lr.load_rules(rules_copy)
    assert "decision" in str(exc.value).lower()
