"""Tests for T7.3 task 1: `stitch.cmdtext` (command text and 4648 target fields reduced to match facts) and the
stitcher hygiene rules around it (decision 048 item 1; spec 03_stitch ST-42, ST-43, ST-46, STT-05, STT-07, STT-13).
Fast: pure strings and tiny SQLite files under `tmp_path`. The real data is never opened.

Written from docs/specs/03_stitch.md, decision 048 and the T7.3 plan, not from the implementation. The code was read
only for public names and signatures. Every command text below is a neutral invented string; assertions carry
counts and uids only.
"""
from __future__ import annotations

import ast
import base64
import dataclasses
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from stitch import cmdtext as ct  # noqa: E402
from stitch import params as sp  # noqa: E402

SRC_STITCH = REPO / "src" / "stitch"

EP2 = ct.target_name_forms("ep-02", "192.168.50.2")
EP3 = ct.target_name_forms("ep-03", "192.168.50.3")
DC = ct.target_name_forms("dc01", "192.168.50.10")


def b64(text: str) -> str:
    """A PowerShell -EncodedCommand payload: base64 of UTF-16LE."""
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


def blob(result: ct.CmdResult) -> str:
    """Every field value of a CmdResult as one string."""
    return " ".join(repr(getattr(result, f.name)) for f in dataclasses.fields(result))


def shares_long_substring(text: str, haystack: str, n: int = 12) -> bool:
    return any(text[i:i + n] in haystack for i in range(max(0, len(text) - n + 1)))


# ================================================================================================ 0. target forms
def test_forms_endpoint_names_have_host_and_windows_name_and_ip():
    assert ct.target_name_forms("ep-02", "192.168.50.2") == (("ep-02", "host_name"), ("endpoint-02", "windows_name"),
                                                             ("192.168.50.2", "ip"))


def test_forms_dc01_has_dc_dash_01_as_windows_name():
    forms = dict(ct.target_name_forms("dc01", "192.168.50.10"))
    assert forms["dc01"] == "host_name" and forms["dc-01"] == "windows_name" and forms["192.168.50.10"] == "ip"


def test_forms_without_ip_has_no_ip_kind():
    assert all(kind != "ip" for _, kind in ct.target_name_forms("ep-01", None))
    assert all(kind != "ip" for _, kind in ct.target_name_forms("ep-01", ""))


# ================================================================================================ 1. host-name boundaries
@pytest.mark.parametrize("text", ["\\\\192.168.50.22\\c$", "net use 192.168.50.22", "192.168.50.22", "x 192.168.50.200",
                                  "10.192.168.50.2", "a.192.168.50.2", "1192.168.50.2", "192.168.50.2.5",
                                  "-192.168.50.2", "192.168.50.2x"])
def test_ip_does_not_match_inside_a_longer_address_or_name(text):
    assert ct.match_text(text, ct.target_name_forms("ep-02", "192.168.50.2")[2:]) is None


@pytest.mark.parametrize("text", ["\\\\192.168.50.2\\c$", "192.168.50.2:445", "connect 192.168.50.2 now",
                                  "\"192.168.50.2\"", "http://192.168.50.2/x", "192.168.50.2", "x=192.168.50.2,y",
                                  "to 192.168.50.2."])
def test_ip_matches_with_normal_delimiters(text):
    assert ct.match_text(text, (("192.168.50.2", "ip"),)) == "ip"


def test_prefix_host_name_does_not_match_a_longer_host_name():
    forms = ct.target_name_forms("ep-0", None)
    assert ct.match_text("ping ep-02", forms) is None
    assert ct.match_text("ping ep-0", forms) == "host_name"


@pytest.mark.parametrize("text", ["ep-021", "xep-02", "ep-02x", "ep-02-b", "ep-0", "pre.ep-02", "ep-020.lab.local"])
def test_ep02_does_not_match_a_longer_or_prefixed_name(text):
    assert ct.match_text(text, EP2) is None


@pytest.mark.parametrize("text,kind", [
    ("EP-02", "host_name"), ("ep-02", "host_name"), ("ep-02.lab.local", "host_name"),
    ("\\\\Endpoint-02.lab.local\\ADMIN$", "windows_name"), ("\\\\endpoint-02\\c$", "windows_name"),
    ("ENDPOINT-02", "windows_name"), ("Enter-PSSession -ComputerName ep-02", "host_name"),
    ("ep-02.", "host_name"), ("(ep-02)", "host_name"),
    ("\\\\192.168.50.2\\c$", "ip"), ("192.168.50.2:445", "ip"),
])
def test_ep02_names_match_and_return_the_right_kind(text, kind):
    assert ct.match_text(text, EP2) == kind


def test_dc01_matches_dc_dash_01_as_windows_name_and_dc01_as_host_name():
    assert ct.match_text("dc-01", DC) == "windows_name"
    assert ct.match_text("DC-01.lab.local", DC) == "windows_name"
    assert ct.match_text("dc01", DC) == "host_name"
    assert ct.match_text("dc011", DC) is None


@pytest.mark.parametrize("text", [None, "", "   "])
def test_empty_or_null_text_never_matches(text):
    assert ct.match_text(text, EP2) is None


def test_no_forms_never_match():
    assert ct.match_text("ep-02", ()) is None


def test_match_is_independent_of_the_order_of_forms():
    forms = ct.target_name_forms("ep-02", "192.168.50.2")
    text = "\\\\192.168.50.2\\c$ and ep-02"
    assert ct.match_text(text, forms) == ct.match_text(text, tuple(reversed(forms)))


def test_one_target_does_not_match_the_text_of_another():
    assert ct.match_text("\\\\ep-03\\c$", EP2) is None
    assert ct.match_text("\\\\ep-03\\c$", EP3) == "host_name"


# ================================================================================================ 2. name boundaries (STT-07)
@pytest.mark.parametrize("name,text", [
    ("Xpay", "Xpay.exe"), ("Xpay", "c:\\x\\Xpay.exe"), ("Xpay.exe", "Xpay.exe.config"), ("pay.exe", "Xpay.exe"),
    ("Xpay.exe", "Xpay.exe2"), ("Xpay.exe", "Xpay.exe-old"), ("Xpay.exe", "OldXpay.exe"), ("Xpay.exe", "_Xpay.exe"),
    ("Xpay.exe", "my-Xpay.exe"),
])
def test_name_inside_a_longer_name_is_not_found(name, text):
    assert ct.names_in_text(text, [name]) == ()


@pytest.mark.parametrize("text", ["run Xpay.exe.", "\"C:\\Windows\\Xpay.exe\"", "C:\\Windows\\Xpay.exe", "Xpay.exe",
                                  "start xpay.exe now", "XPAY.EXE", "x Xpay.exe, y", "'Xpay.exe'", "Xpay.exe\\x",
                                  "cmd /c Xpay.exe & dir"])
def test_name_is_found_at_normal_boundaries_and_case_insensitively(text):
    assert ct.names_in_text(text, ["Xpay.exe"]) == ("Xpay.exe",)


def test_names_in_text_returns_the_given_spelling_not_the_texts():
    assert ct.names_in_text("run XPAY.EXE", ["Xpay.exe"]) == ("Xpay.exe",)
    assert ct.names_in_text("run xpay.exe", ["XpAy.ExE"]) == ("XpAy.ExE",)


def test_names_in_text_is_sorted_and_tests_each_name_on_its_own():
    got = ct.names_in_text("copy b.exe a.exe svc.exe", ["svc.exe", "b.exe", "a.exe", "zz.exe"])
    assert got == ("a.exe", "b.exe", "svc.exe")
    assert ct.names_in_text("run Xpay.exe.config", ["Xpay.exe", "Xpay.exe.config"]) == ("Xpay.exe.config",)


@pytest.mark.parametrize("text", [None, ""])
def test_names_in_text_empty_text_gives_nothing(text):
    assert ct.names_in_text(text, ["a.exe"]) == ()


def test_names_in_text_ignores_empty_names():
    assert ct.names_in_text("anything", ["", None]) == ()   # type: ignore[list-item]


# ================================================================================================ 3. -EncodedCommand
PS_NAMING_EP2 = "Invoke-Command -ComputerName ep-02 -ScriptBlock { whoami }"


@pytest.mark.parametrize("switch", ["-enc", "-EncodedCommand", "-ec", "/e", "-e", "-ENC", "-EncodedC", "/enc"])
def test_encoded_command_naming_the_target_is_matched_via_decoded(switch):
    cmd = f"powershell.exe -NoProfile {switch} {b64(PS_NAMING_EP2)}"
    assert ct.match_text(cmd, EP2) is None, "the plain text must not name the target (payload is base64)"
    res = ct.command_result("U1", cmd, [("ep-02", EP2)], {})
    assert res.targets == (("ep-02", "host_name", "decoded"),)
    assert res.undecodable is False and res.has_command is True


def test_pwsh_and_full_path_powershell_are_decoded_too():
    for exe in ("pwsh -enc", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ec"):
        res = ct.command_result("U1", f"{exe} {b64(PS_NAMING_EP2)}", [("ep-02", EP2)], {})
        assert res.targets == (("ep-02", "host_name", "decoded"),), exe


def test_decoded_ip_and_windows_name_kinds():
    res = ct.command_result("U1", f"powershell -enc {b64('copy x \\\\192.168.50.2\\c$')}", [("ep-02", EP2)], {})
    assert res.targets == (("ep-02", "ip", "decoded"),)
    res = ct.command_result("U1", f"powershell -enc {b64('dir \\\\Endpoint-02.lab.local\\c$')}", [("ep-02", EP2)], {})
    assert res.targets == (("ep-02", "windows_name", "decoded"),)


def test_payload_quoted_is_decoded():
    cmd = f"powershell -enc \"{b64(PS_NAMING_EP2)}\""
    assert ct.command_result("U1", cmd, [("ep-02", EP2)], {}).targets == (("ep-02", "host_name", "decoded"),)


def test_plain_match_is_via_plain():
    res = ct.command_result("U1", "psexec \\\\ep-02 -s cmd", [("ep-02", EP2)], {})
    assert res.targets == (("ep-02", "host_name", "plain"),)
    assert res.undecodable is False and res.has_command is True


def test_plain_match_wins_over_decoded_when_both_name_the_target():
    cmd = f"powershell -nop ep-02 -enc {b64(PS_NAMING_EP2)}"
    assert ct.command_result("U1", cmd, [("ep-02", EP2)], {}).targets == (("ep-02", "host_name", "plain"),)


def test_encoded_command_naming_another_target_does_not_match_this_one():
    cmd = f"powershell -enc {b64('Enter-PSSession ep-03')}"
    res = ct.command_result("U1", cmd, [("ep-02", EP2), ("ep-03", EP3)], {})
    assert res.targets == (("ep-03", "host_name", "decoded"),)


def test_two_targets_in_one_command_are_both_listed_sorted():
    res = ct.command_result("U1", "copy a \\\\ep-03\\c$ and \\\\ep-02\\c$", [("ep-03", EP3), ("ep-02", EP2)], {})
    assert res.targets == (("ep-02", "host_name", "plain"), ("ep-03", "host_name", "plain"))


@pytest.mark.parametrize("payload", ["!!!not-base64!!!", "QUJD", "A", "////////", "deadbeefzz"])
def test_bad_payload_is_flagged_undecodable_and_matches_nothing(payload):
    res = ct.command_result("U1", f"powershell -enc {payload}", [("ep-02", EP2)], {})
    assert res.undecodable is True
    assert res.targets == ()
    assert res.has_command is True


def test_valid_base64_of_random_bytes_is_undecodable():
    random_bytes = bytes(range(1, 64)) + bytes([0xFF, 0xFE])         # not printable UTF-16 text
    cmd = "powershell -enc " + base64.b64encode(random_bytes).decode()
    assert ct.command_result("U1", cmd, [("ep-02", EP2)], {}).undecodable is True


def test_one_good_and_one_bad_payload_still_matches_and_flags_undecodable():
    cmd = f"powershell -enc {b64(PS_NAMING_EP2)} -ec !!bad!!"
    res = ct.command_result("U1", cmd, [("ep-02", EP2)], {})
    assert res.targets == (("ep-02", "host_name", "decoded"),)
    assert res.undecodable is True


def test_a_good_payload_is_not_undecodable():
    res = ct.command_result("U1", f"powershell -enc {b64('Get-Date')}", [("ep-02", EP2)], {})
    assert res.undecodable is False and res.targets == ()


def test_non_powershell_command_with_dash_e_is_not_decoded():
    cmd = f"tool.exe -e {b64(PS_NAMING_EP2)}"
    assert ct.is_powershell(cmd) is False
    res = ct.command_result("U1", cmd, [("ep-02", EP2)], {})
    assert res.targets == () and res.undecodable is False


def test_non_powershell_bad_dash_e_payload_is_not_flagged():
    res = ct.command_result("U1", "other.exe -e !!!bad!!!", [("ep-02", EP2)], {})
    assert res.undecodable is False and res.targets == ()


def test_dash_ex_is_not_an_encoded_command_switch():
    """-ExecutionPolicy is not -e: its argument is not a payload."""
    cmd = f"powershell -ExecutionPolicy Bypass -File x.ps1"
    assert ct.encoded_payloads(cmd) == []
    assert ct.command_result("U1", cmd, [("ep-02", EP2)], {}).undecodable is False


def test_is_powershell_and_encoded_payloads_basic():
    assert ct.is_powershell("PowerShell.exe -nop")
    assert ct.is_powershell("pwsh -c x")
    assert not ct.is_powershell("cmd.exe /c dir") and not ct.is_powershell(None) and not ct.is_powershell("")
    assert ct.encoded_payloads("powershell -enc AAAA -ec BBBB") == ["AAAA", "BBBB"]
    assert ct.encoded_payloads("cmd /c dir") == []
    assert ct.encoded_payloads(None) == []


def test_decode_payload_roundtrip_and_failures():
    assert ct.decode_payload(b64("Get-Process")) == "Get-Process"
    assert ct.decode_payload("!!!") is None
    assert ct.decode_payload("QUJD") is None           # three bytes: not whole UTF-16 characters


def test_decoded_texts_returns_texts_and_flag():
    texts, bad = ct.decoded_texts(f"powershell -enc {b64('one')} -enc !!x")
    assert texts == ("one",) and bad is True
    assert ct.decoded_texts("cmd /c dir") == ((), False)


def test_encoded_target_side_names_are_found_in_decoded_text():
    cmd = f"powershell -enc {b64('copy-item C:\\x\\Xpay.exe')}"
    res = ct.command_result("U1", cmd, [("ep-02", EP2)], {"ep-02": ["Xpay.exe", "Other.exe"]})
    assert res.names_found == (("ep-02", "Xpay.exe"),)


# ================================================================================================ 3b. names_found
def test_names_found_are_per_probed_target_and_sorted_even_without_a_target_match():
    names = {"ep-02": ["b.exe", "a.exe"], "ep-03": ["c.exe"]}
    res = ct.command_result("U1", "run a.exe b.exe c.exe", [("ep-02", EP2), ("ep-03", EP3)], names)
    assert res.names_found == (("ep-02", "a.exe"), ("ep-02", "b.exe"), ("ep-03", "c.exe"))
    assert res.targets == ()           # no host named: names_found does not imply a target match


def test_names_of_an_unprobed_target_are_not_reported():
    res = ct.command_result("U1", "run a.exe", [("ep-02", EP2)], {"ep-03": ["a.exe"]})
    assert res.names_found == ()


def test_name_inside_a_longer_name_is_not_in_names_found():
    res = ct.command_result("U1", "run Xpay.exe.config", [("ep-02", EP2)], {"ep-02": ["Xpay.exe"]})
    assert res.names_found == ()


# ================================================================================================ 4. no text in CmdResult
def test_cmdresult_fields_are_exactly_the_documented_facts():
    assert [f.name for f in dataclasses.fields(ct.CmdResult)] == ["event_uid", "targets", "undecodable",
                                                                  "names_found", "has_command"]


def test_cmdresult_is_frozen():
    res = ct.command_result("U1", "x", [], {})
    with pytest.raises(dataclasses.FrozenInstanceError):
        res.undecodable = True  # type: ignore[misc]


COMMANDS = [
    "psexec.exe \\\\ep-02 -u LabDomain\\someone -p Passw0rd-Invented-9 cmd.exe /c whoami > C:\\Temp\\out-file.txt",
    f"powershell.exe -NoProfile -enc {b64('Invoke-Command -ComputerName ep-02 -ScriptBlock { Get-ChildItem C:\\Users }')}",
    "net use \\\\192.168.50.2\\c$ /user:LabDomain\\someone Another-Invented-Pw-1 && copy Xpay.exe \\\\192.168.50.2\\c$\\",
    f"powershell -enc !!undecodable-payload-with-some-length-0123456789!!",
]


@pytest.mark.parametrize("command", COMMANDS)
def test_cmdresult_holds_no_text_of_the_command_or_the_decoded_payload(command):
    res = ct.command_result("U-1", command, [("ep-02", EP2)], {"ep-02": ["Xpay.exe"]})
    text = blob(res)
    assert command not in text
    assert not shares_long_substring(command, text), "a 12-character piece of the command is in the result"
    texts, _ = ct.decoded_texts(command)
    for d in texts:
        assert d not in text
        assert not shares_long_substring(d, text), "a 12-character piece of the decoded payload is in the result"
    for f in dataclasses.fields(res):
        value = getattr(res, f.name)
        assert isinstance(value, (str, bool, tuple)), f.name
    assert res.event_uid == "U-1"


def test_result_for_a_null_or_blank_command_has_no_command_flag():
    for cmd in (None, "", "   "):
        res = ct.command_result("U2", cmd, [("ep-02", EP2)], {"ep-02": ["a.exe"]})
        assert res.has_command is False and res.targets == () and res.names_found == () and res.undecodable is False


# ================================================================================================ 5. DB readers
CMD_COLUMNS = ["event_uid", "host", "channel", "event_id", "command_line", "field_values_json", "destination_host",
               "destination_ip", "source_ip", "subject_account"]


def make_db(path: Path, rows: list[dict], table: str = "events_dedup") -> Path:
    con = sqlite3.connect(str(path))
    try:
        con.execute(f"CREATE TABLE {table} ({', '.join(CMD_COLUMNS)})")
        con.executemany(f"INSERT INTO {table} VALUES ({', '.join('?' * len(CMD_COLUMNS))})",
                        [tuple(r.get(c) for c in CMD_COLUMNS) for r in rows])
        con.commit()
    finally:
        con.close()
    return path


def row(uid: str, host: str, channel: str, event_id: int, **kw) -> dict:
    return dict(event_uid=uid, host=host, channel=channel, event_id=event_id, **kw)


@pytest.fixture
def con(tmp_path):
    rows = [
        row("S1-NAMED", "ep-01", "Sysmon", 1, command_line="psexec \\\\ep-02 -s cmd"),
        row("S1-OTHER", "ep-01", "Sysmon", 1, command_line="notepad.exe C:\\x\\Xpay.exe"),
        row("S1-ENC", "ep-01", "Sysmon", 1, command_line=f"powershell -enc {b64('Enter-PSSession ep-03')}"),
        row("S1-BAD", "ep-01", "Sysmon", 1, command_line="powershell -enc !!bad!!"),
        row("S1-NULL", "ep-01", "Sysmon", 1, command_line=None),
        row("B4688-NULL", "ep-01", "Security", 4688, command_line=None),
        row("B4688-NAMED", "ep-01", "Security", 4688, command_line="net use \\\\192.168.50.2\\c$"),
        row("B4688-EMPTY", "ep-01", "Security", 4688, command_line=""),
        row("S3-NOT-A-COMMAND", "ep-01", "Sysmon", 3, command_line="would name ep-02"),
        row("SYS1-NOT-SYSMON", "ep-01", "System", 1, command_line="would name ep-02"),
        row("S1-ON-EP03", "ep-03", "Sysmon", 1, command_line="psexec \\\\ep-02 -s cmd"),
    ]
    db = make_db(tmp_path / "t.sqlite3", rows)
    c = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    yield c
    c.close()


PROBES = {"ep-01": [("ep-02", EP2), ("ep-03", EP3)], "ep-03": [("ep-02", EP2)]}


def test_read_command_results_gives_a_result_for_every_requested_command_uid(con):
    uids = ["S1-NAMED", "S1-OTHER", "S1-ENC", "S1-BAD", "S1-NULL", "B4688-NULL", "B4688-NAMED", "B4688-EMPTY"]
    out = ct.read_command_results(con, {"ep-01": uids}, PROBES, {"ep-02": ["Xpay.exe"]})
    assert sorted(out) == sorted(uids)
    assert all(isinstance(r, ct.CmdResult) and r.event_uid == u for u, r in out.items())
    assert out["S1-NAMED"].targets == (("ep-02", "host_name", "plain"),)
    assert out["S1-OTHER"].targets == () and out["S1-OTHER"].has_command is True
    assert out["S1-OTHER"].names_found == (("ep-02", "Xpay.exe"),)
    assert out["S1-ENC"].targets == (("ep-03", "host_name", "decoded"),)
    assert out["S1-BAD"].undecodable is True and out["S1-BAD"].targets == ()
    assert out["B4688-NAMED"].targets == (("ep-02", "ip", "plain"),)


def test_null_or_empty_command_gives_has_command_false_not_a_missing_result(con):
    out = ct.read_command_results(con, {"ep-01": ["S1-NULL", "B4688-NULL", "B4688-EMPTY"]}, PROBES)
    assert sorted(out) == ["B4688-EMPTY", "B4688-NULL", "S1-NULL"]
    assert all(r.has_command is False and r.targets == () for r in out.values())


def test_uid_requested_under_another_host_gets_no_result(con):
    out = ct.read_command_results(con, {"ep-03": ["S1-NAMED"], "ep-01": ["S1-ON-EP03"]}, PROBES)
    assert out == {}


def test_uid_requested_under_two_hosts_is_read_for_the_right_one(con):
    out = ct.read_command_results(con, {"ep-03": ["S1-NAMED"], "ep-01": ["S1-NAMED"]}, PROBES)
    assert list(out) == ["S1-NAMED"]


def test_probes_of_the_events_own_host_are_used(con):
    out = ct.read_command_results(con, {"ep-03": ["S1-ON-EP03"]}, PROBES)
    assert out["S1-ON-EP03"].targets == (("ep-02", "host_name", "plain"),)


def test_host_without_probes_gives_results_with_no_targets(con):
    out = ct.read_command_results(con, {"ep-01": ["S1-NAMED"]}, {})
    assert out["S1-NAMED"].targets == () and out["S1-NAMED"].has_command is True


def test_non_command_events_and_unknown_uids_get_no_result(con):
    out = ct.read_command_results(con, {"ep-01": ["S3-NOT-A-COMMAND", "SYS1-NOT-SYSMON", "NO-SUCH-UID"]}, PROBES)
    assert out == {}


def test_results_are_sorted_by_uid_and_independent_of_request_order(con):
    uids = ["S1-OTHER", "S1-NAMED", "B4688-NAMED", "S1-ENC"]
    a = ct.read_command_results(con, {"ep-01": uids}, PROBES)
    b = ct.read_command_results(con, {"ep-01": list(reversed(uids)) + uids}, PROBES)
    assert a == b and list(a) == sorted(a)


def test_read_command_results_carries_no_command_text(con):
    out = ct.read_command_results(con, {"ep-01": ["S1-NAMED", "S1-ENC", "B4688-NAMED", "S1-BAD"]}, PROBES)
    text = " ".join(blob(r) for r in out.values())
    for cmd in ("psexec \\\\ep-02 -s cmd", "net use \\\\192.168.50.2\\c$", "Enter-PSSession ep-03"):
        assert not shares_long_substring(cmd, text)


def test_database_is_not_modified_by_the_readers(tmp_path):
    db = make_db(tmp_path / "ro.sqlite3", [row("S1", "ep-01", "Sysmon", 1, command_line="x ep-02")])
    before = db.read_bytes()
    c = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        ct.read_command_results(c, {"ep-01": ["S1"]}, PROBES)
        ct.read_4648_targets(c, ["S1"])
    finally:
        c.close()
    assert db.read_bytes() == before


@pytest.mark.parametrize("n", [899, 900, 901, 1800, 1801, 2500])
def test_more_than_900_uids_are_chunked_and_every_one_is_answered(tmp_path, n):
    rows = [row(f"U{i:05d}", "ep-01", "Sysmon", 1, command_line="psexec \\\\ep-02 x" if i % 2 else "dir")
            for i in range(n)]
    db = make_db(tmp_path / "many.sqlite3", rows)
    c = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        if hasattr(c, "setlimit"):         # make the statement limit as small as on an old SQLite build
            c.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
        out = ct.read_command_results(c, {"ep-01": [r["event_uid"] for r in rows]}, PROBES)
        assert len(out) == n
        assert sum(1 for r in out.values() if r.targets) == n // 2
        r4648 = [row(f"U{i:05d}", "ep-01", "Security", 4648, destination_host="ep-02") for i in range(n)]
        db2 = make_db(tmp_path / "many4648.sqlite3", r4648)
        c2 = sqlite3.connect(f"file:{db2.as_posix()}?mode=ro", uri=True)
        try:
            if hasattr(c2, "setlimit"):
                c2.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
            assert len(ct.read_4648_targets(c2, [r["event_uid"] for r in r4648])) == n
        finally:
            c2.close()
    finally:
        c.close()


def test_events_dedup_name_is_the_view_that_is_read(tmp_path):
    """A table called `events` with the same uid must not be read: the stitcher reads `events_dedup` only."""
    db = tmp_path / "two.sqlite3"
    make_db(db, [row("S1", "ep-01", "Sysmon", 1, command_line="clean ep-03")], table="events_dedup")
    c = sqlite3.connect(str(db))
    try:
        c.execute(f"CREATE TABLE events ({', '.join(CMD_COLUMNS)})")
        c.execute(f"INSERT INTO events VALUES ({', '.join('?' * len(CMD_COLUMNS))})",
                  ("S1", "ep-01", "Sysmon", 1, "dup ep-02", None, None, None, None, None))
        c.commit()
        out = ct.read_command_results(c, {"ep-01": ["S1"]}, PROBES)
    finally:
        c.close()
    assert out["S1"].targets == (("ep-03", "host_name", "plain"),)


# ================================================================================================ 5b. 4648 targets
SECRET = "hunter2-Invented-Secret-Value"


def test_texts_of_4648_only_target_fields_in_columns_and_json():
    js = json.dumps({"TargetServerName": "ep-02.lab.local", "TargetInfo": "cifs/ep-02", "IpAddress": "192.168.50.2",
                     "SubjectUserName": "someone", "Password": SECRET, "ProcessName": "C:\\x\\a.exe",
                     "TargetUserName": "acct_a"})
    got = ct.texts_of_4648(("ep-02", "192.168.50.2", "192.168.50.21"), js)
    assert set(got) == {"ep-02", "ep-02.lab.local", "cifs/ep-02", "192.168.50.2", "192.168.50.21"}
    assert len(got) == len(set(got)), "texts are not repeated"
    text = " ".join(got)
    for bad in ("someone", SECRET, "a.exe", "acct_a"):
        assert bad not in text


@pytest.mark.parametrize("key", ["targetservername", "TARGETSERVERNAME", "TargetServerName", "tArGeTsErVeRnAmE"])
def test_json_keys_are_case_insensitive(key):
    assert ct.texts_of_4648((None, None, None), json.dumps({key: "ep-02"})) == ("ep-02",)
    assert ct.texts_of_4648((None, None, None), json.dumps({key.replace("servername", "info").replace(
        "SERVERNAME", "INFO").replace("ServerName", "Info").replace("sErVeRnAmE", "InFo"): "cifs/ep-02"})) \
        == ("cifs/ep-02",)


def test_ipaddress_json_key_is_read_case_insensitively():
    assert ct.texts_of_4648((None, None, None), json.dumps({"IPADDRESS": "192.168.50.2"})) == ("192.168.50.2",)
    assert ct.texts_of_4648((None, None, None), json.dumps({"ipaddress": "192.168.50.2"})) == ("192.168.50.2",)


@pytest.mark.parametrize("empty", ["-", "", None, "  -  ", "   "])
def test_dash_and_empty_values_are_dropped(empty):
    js = json.dumps({"TargetServerName": empty, "TargetInfo": empty, "IpAddress": empty})
    assert ct.texts_of_4648((empty, empty, empty), js) == ()


@pytest.mark.parametrize("js", [None, "", "not json {", "[1, 2]", "null", "12"])
def test_missing_or_unparseable_json_gives_the_columns_alone(js):
    assert ct.texts_of_4648(("ep-02", None, "-"), js) == ("ep-02",)


def test_other_json_keys_alone_give_nothing():
    js = json.dumps({"SubjectUserName": "SECRET-USER", "Password": SECRET, "TargetUserName": "ep-02"})
    assert ct.texts_of_4648((None, None, None), js) == ()


def test_match_4648_uses_the_target_texts_and_boundaries():
    assert ct.match_4648(("ep-02.lab.local",), EP2) == "host_name"
    assert ct.match_4648(("cifs/endpoint-02",), EP2) == "windows_name"
    assert ct.match_4648(("-", "192.168.50.2"), EP2) == "ip"
    assert ct.match_4648(("192.168.50.22",), EP2) is None
    assert ct.match_4648(("ep-021",), EP2) is None
    assert ct.match_4648((), EP2) is None


def test_read_4648_targets_reads_only_target_fields_and_only_4648(tmp_path):
    js = json.dumps({"targetservername": "ep-02", "TargetInfo": "cifs/ep-02", "IpAddress": "192.168.50.2",
                     "SubjectUserName": "FAKE-SUBJECT", "Secret": SECRET})
    rows = [
        row("A", "ep-01", "Security", 4648, destination_host="ep-02", destination_ip="-", source_ip="",
            field_values_json=js, subject_account="FAKE-SUBJECT"),
        row("B", "ep-01", "Security", 4648, destination_host=None, destination_ip="192.168.50.3",
            source_ip="192.168.50.4", field_values_json=None),
        row("C", "ep-01", "Security", 4648, field_values_json=json.dumps({"SubjectUserName": "FAKE-SUBJECT"})),
        row("D", "ep-01", "Security", 4624, destination_host="ep-02", field_values_json=js),
        row("E", "ep-01", "Sysmon", 1, command_line="ep-02", field_values_json=js),
        row("F", "ep-01", "Security", 4648, destination_host="ep-03", field_values_json="{bad json"),
    ]
    db = make_db(tmp_path / "e.sqlite3", rows)
    c = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        out = ct.read_4648_targets(c, ["A", "B", "C", "D", "E", "F", "MISSING"])
    finally:
        c.close()
    assert sorted(out) == ["A", "B", "C", "F"]
    assert set(out["A"]) == {"ep-02", "cifs/ep-02", "192.168.50.2"}
    assert set(out["B"]) == {"192.168.50.3", "192.168.50.4"}
    assert out["C"] == ()
    assert out["F"] == ("ep-03",)
    flat = " ".join(t for v in out.values() for t in v)
    for bad in ("FAKE-SUBJECT", SECRET, "Secret"):
        assert bad not in flat
    assert all(isinstance(v, tuple) for v in out.values())
    assert list(out) == sorted(out)


# ================================================================================================ 6. hygiene
def stitch_sources() -> list[Path]:
    files = sorted(SRC_STITCH.glob("*.py"))
    assert len(files) >= 8, "src/stitch has too few source files"
    return files


def test_hygiene_only_cmdtext_and_params_name_the_command_text_columns():
    offenders = {}
    for f in stitch_sources():
        text = f.read_text(encoding="utf-8")
        hits = [w for w in ("command_line", "field_values_json") if w in text]
        if hits:
            offenders[f.name] = hits
    assert set(offenders) <= {"cmdtext.py", "params.py"}, f"command text columns named in {sorted(offenders)}"
    assert "cmdtext.py" in offenders, "cmdtext.py must be the module that selects them"


def test_hygiene_scan_columns_contain_neither_command_text_column():
    assert "command_line" not in sp.SCAN_COLUMNS and "field_values_json" not in sp.SCAN_COLUMNS


def test_hygiene_no_other_module_selects_the_view_with_command_text():
    """Only cmdtext may build a SELECT over the view for these columns; other modules do not mention them at all
    (covered above), and none may use `SELECT *`."""
    for f in stitch_sources():
        text = f.read_text(encoding="utf-8")
        assert not re.search(r"select\s+\*", text, re.IGNORECASE), f"{f.name}: SELECT * would read command text"


def test_hygiene_new_scan_columns_are_the_seven_non_command_fields():
    new = ("logon_guid", "share_name", "relative_target_name", "service_name", "service_image_path",
           "destination_host", "subject_account")
    assert all(c in sp.SCAN_COLUMNS for c in new)
    assert set(sp.SCAN_COLUMNS) <= set(sp.SPEC_DB_COLUMNS)
    assert len(set(sp.SCAN_COLUMNS)) == len(sp.SCAN_COLUMNS)


def test_hygiene_vocabularies():
    assert tuple(sp.METHODS) == ("sysmon3_port", "source_4648", "cmdline_target", "target_only")
    assert set(sp.ARTEFACT_KINDS) >= {"share_burst", "service_install", "winrm_host", "winrm_91", "rdp_connection",
                                      "followup_logon"}
    assert set(sp.TARGET_ONLY_REASONS) == {"source_host_unknown", "source_host_no_logs", "no_evidence_in_range"}
    for vocab in (sp.METHODS, sp.ARTEFACT_KINDS, sp.TARGET_ONLY_REASONS):
        assert len(set(vocab)) == len(vocab)


BANNED_KEY_MODULES = ["answer_key.build", "answer_key.finish", "answer_key.verify", "answer_key.overlap",
                      "answer_key.targets"]


def _fresh_interpreter(code: str) -> dict:
    proc = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=180,
                          cwd=str(REPO / "tests"))
    assert proc.returncode == 0, f"fresh interpreter failed:\n{proc.stderr[-2000:]}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_hygiene_fresh_interpreter_importing_every_stitch_module_loads_no_log_check_or_key_builder():
    names = sorted(f.stem for f in stitch_sources())
    code = f"""
import sys, json, importlib
sys.path.insert(0, {str(REPO / "src")!r})
loaded = []
for stem in {names!r}:
    name = "stitch" if stem == "__init__" else "stitch." + stem
    importlib.import_module(name)
    loaded.append(name)
banned = {BANNED_KEY_MODULES!r}
print(json.dumps({{"banned": [b for b in banned if b in sys.modules],
                   "log_check": sorted(m for m in sys.modules if m == "log_check" or m.startswith("log_check.")),
                   "loaded": loaded}}))
"""
    res = _fresh_interpreter(code)
    assert "stitch.cmdtext" in res["loaded"] and "stitch.scan" in res["loaded"] and "stitch.inputs" in res["loaded"]
    assert res["log_check"] == [], f"log_check modules loaded by src/stitch: {res['log_check']}"
    assert res["banned"] == [], f"key-builder modules loaded by src/stitch: {res['banned']}"


def test_hygiene_import_probe_self_check_sees_log_check_and_key_builder():
    """The probe above is meaningful: importing log_check and answer_key.build in the same style shows up."""
    code = f"""
import sys, json, importlib
sys.path.insert(0, {str(REPO / "src")!r})
importlib.import_module("log_check.matching")
importlib.import_module("answer_key.build")
print(json.dumps({{"banned": [b for b in {BANNED_KEY_MODULES!r} if b in sys.modules],
                   "log_check": sorted(m for m in sys.modules if m == "log_check" or m.startswith("log_check."))}}))
"""
    res = _fresh_interpreter(code)
    assert "answer_key.build" in res["banned"] and "log_check.matching" in res["log_check"]


def test_hygiene_cmdtext_imports_nothing_outside_the_stdlib_and_the_stitch_params():
    tree = ast.parse((SRC_STITCH / "cmdtext.py").read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imports.add("." * node.level + (node.module or ""))
    allowed = {"__future__", "base64", "binascii", "json", "re", "sqlite3", "dataclasses", "functools", "typing",
               ".params"}
    assert imports <= allowed, sorted(imports - allowed)
