"""T7.5 task 4 tests for ``stitch.report``: ``report_md`` and ``stats_dict`` on a synthetic trial (fast).

Written from spec 03_stitch section 3 (``stats.json``, ``report.md``), ST-73, L-ST2 and decisions 013 and 050 item 8
(``report.md`` holds event-level facts only: no account, image, command text or target-side name), not from the
implementation (the code was read only for public names and signatures).

World: the rich world of `test_stitch_outputs` (accounts, a credential account in a 4648, a dump with an image and an
account, command lines, a copied and installed binary, a look-back session) plus one more hop MB that leaves ep-02 and
enters ep-01 at 1100 s. MB chains from the four user hops that entered ep-02 (M1..M4; M5 is a machine account and takes
no part), so MB has four chain parents (limitation L-ST2).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stitch_fixtures as sf  # noqa: E402
import test_stitch_outputs as tso  # noqa: E402
from gate.classify import ip_kind  # noqa: E402
from stitch import report as rp  # noqa: E402
from stitch.links import run_links_checked  # noqa: E402
from stitch.nodes import build_path_outputs  # noqa: E402
from stitch.params import StitchParams  # noqa: E402

TRIAL = sf.TRIAL
PARAMS = StitchParams()
MB_UID, MB_ACCOUNT = "MB", "Acct_E_Report"


def multi_parent_repo(tmp_path: Path, name: str = "report_repo"):
    rows, trig, sup = tso.world_rows()
    rows.append(sf.ev(MB_UID, "Security", 4624, host=tso.SRC, off=1100.0, logon_type=3, target_logon_id=7500,
                      account_name=MB_ACCOUNT, source_ip=tso.TGT_IP, source_port=50500,
                      authentication_package="NTLM", machine_account=0))
    trig.append({"trigger_id": f"t-{MB_UID}", "host": tso.SRC, "anchor_logon_uid": MB_UID, "trigger_event_uid": MB_UID,
                 "target_logon_id": "7500", "source_ip": tso.TGT_IP, "ip_kind": ip_kind(tso.TGT_IP),
                 "machine_account": "0", "clock_unreliable": "0", "rule": "R4_smb", "gate_tier": "A",
                 "supporting_event_uids": ""})
    fake = sf.make_repo(tmp_path, rows, name=name)
    tso.write_gate_csv(fake.paths.gate_dir / "triggers.csv", trig, ["event_uid"])
    tso.write_gate_csv(fake.paths.gate_dir / "supporting.csv", sup, ["event_uid"])
    return fake


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    """In-process objects and the written files of one run of the multi-parent world."""
    fake = multi_parent_repo(tmp_path_factory.mktemp("stitch_report"))
    assert tso.run_main(fake) == 0
    folder = tso.out_folder(fake)
    tables = {n: tso.read_csv(folder / n) for n in tso.ALL_CSV_FILES}
    li, _checked, _paths, before, after = run_links_checked(fake.repo, fake.trial, PARAMS)
    pathset, nodes = build_path_outputs(li, PARAMS)
    stats = rp.stats_dict(li, pathset, nodes, {n: len(t) for n, t in tables.items()}, PARAMS, before, after)
    return {"fake": fake, "li": li, "pathset": pathset, "nodes": nodes, "stats": stats, "folder": folder,
            "report": rp.report_md(stats, li, pathset), "file": (folder / "report.md").read_text(encoding="utf-8"),
            "tables": tables}


# ------------------------------------------------------------------ the world has what the tests need

def test_world_has_a_multi_parent_hop(world):
    mp = world["stats"]["multi_chain_parent_hops"]
    assert len(mp) == 1
    ((hop, parents),) = mp.items()
    assert len(parents) == 4
    assert world["stats"]["chain_edges_by_type"] == {"host_time": 4, "session": 0}
    assert len(world["pathset"].paths) == 2          # one merged path {M1..M4, MB} and the machine-account M5


# ------------------------------------------------------------------ determinism and form

def test_report_md_is_deterministic(world):
    again = rp.report_md(world["stats"], world["li"], world["pathset"])
    assert again == world["report"]


def test_written_report_equals_report_md_of_the_same_inputs(world):
    assert world["file"] == world["report"]


def test_two_runs_write_the_same_report_bytes(world):
    before = (world["folder"] / "report.md").read_bytes()
    assert tso.run_main(world["fake"]) == 0                 # same repo, same DB: the report must not change
    assert (world["folder"] / "report.md").read_bytes() == before


def test_report_is_text_with_unix_line_ends_and_one_trailing_newline(world):
    r = world["report"]
    assert isinstance(r, str) and r.endswith("\n") and not r.endswith("\n\n") and "\r" not in r
    assert r.startswith("#")


def test_report_has_no_timestamp_of_the_run(world):
    r = world["report"]
    assert "generated" not in r.lower()
    # corrected event times (2026-09-24 of the fixture) may appear; a wall-clock time of the run may not
    assert not re.search(r"\b2026-1[0-2]-\d\d\b", r) and "2027-" not in r


# ------------------------------------------------------------------ the two fixed sentences

def test_identity_sentence_is_in_the_report(world):
    assert rp.IDENTITY_SENTENCE and rp.IDENTITY_SENTENCE in world["report"]
    assert "013" in rp.IDENTITY_SENTENCE or "linked source session" in rp.IDENTITY_SENTENCE


def test_l_st2_sentence_is_in_the_report_when_a_hop_has_several_parents(world):
    assert world["stats"]["multi_chain_parent_hops"]
    assert rp.L_ST2_SENTENCE and rp.L_ST2_SENTENCE in world["report"]
    assert "L-ST2" in rp.L_ST2_SENTENCE


def test_multi_parent_hop_and_its_parents_are_listed(world):
    ((hop, parents),) = world["stats"]["multi_chain_parent_hops"].items()
    lines = [l for l in world["report"].splitlines() if hop in l and all(p in l for p in parents)]
    assert lines, "no report line names the multi-parent hop with all its parents"


def test_identity_sentence_present_without_a_multi_parent_hop_too(tmp_path):
    fake = tso.build_repo(tmp_path)                     # the plain world: no chain edge
    li, _c, _p, before, after = run_links_checked(fake.repo, fake.trial, PARAMS)
    pathset, nodes = build_path_outputs(li, PARAMS)
    stats = rp.stats_dict(li, pathset, nodes, {"hops.csv": 5}, PARAMS, before, after)
    assert not stats["multi_chain_parent_hops"]
    assert rp.IDENTITY_SENTENCE in rp.report_md(stats, li, pathset)


# ------------------------------------------------------------------ paths and edges listed

def test_every_path_id_appears(world):
    for p in world["pathset"].paths:
        assert p.path_id in world["report"]
    for r in world["tables"]["paths.csv"]:
        assert r["path_id"] in world["report"]


def test_every_edge_appears_with_path_hops_and_type(world):
    assert world["tables"]["path_edges.csv"]
    lines = world["report"].splitlines()
    for r in world["tables"]["path_edges.csv"]:
        assert any(r["path_id"] in l and r["from_hop_id"] in l and r["to_hop_id"] in l and r["link_type"] in l
                   and r["time_delta_ms"] in l for l in lines), (r["from_hop_id"], r["to_hop_id"])


def test_every_hop_of_every_path_appears(world):
    for r in world["tables"]["paths.csv"]:
        for h in r["hop_ids"].split(";"):
            assert h in world["report"]


def test_report_counts_agree_with_stats(world):
    s, r = world["stats"], world["report"]
    assert f"hops: {s['hops']}" in r and f"seeds: {s['seeds']}" in r
    assert f"paths: {s['paths']}" in r


# ------------------------------------------------------------------ decision 050 item 8: nothing sensitive

def forbidden_strings() -> dict[str, list[str]]:
    members = [m["account"] for m in tso.MEMBERS] + [MB_ACCOUNT]
    return {
        "member account": members,
        "source_session_account": list(tso.SESSION_ACCOUNTS.values()),
        "credential account (4648)": ["Acct_A", "ACCT_A"],
        "artefact name": ["payloadxq.exe", "payloadxq", "SyncSvcQ", "ADMIN$"],
        "dump image": [tso.IMAGE_DUMP, "ProbeReader.exe", "ProbeReader", "Runner.exe"],
        "dump account": [tso.DUMP_ACCOUNT],
        "command text": [sf.PLACEHOLDER_COMMAND, "tail-alpha", "tail-bravo-no-names", "tail-outside-window",
                         "0123456789"],
    }


@pytest.mark.parametrize("kind", list(forbidden_strings()))
def test_report_contains_no_sensitive_text(world, kind):
    report = world["report"].casefold()
    for s in forbidden_strings()[kind]:
        assert s.casefold() not in report, f"{kind} text is in report.md"


def test_no_twelve_character_substring_of_any_command_line_in_the_report(world):
    report = world["report"].casefold()
    commands = tso.db_command_lines(world["fake"].paths.db)
    assert len(commands) >= 4
    hits = 0
    for c in commands:
        c = c.casefold()
        hits += sum(1 for i in range(len(c) - 11) if c[i:i + 12] in report)
    assert hits == 0, f"{hits} command substring(s) of 12 characters in report.md (count only)"


def test_report_holds_no_account_value_of_any_csv_cell(world):
    """Every value of the account / image columns of the CSVs (the cells that carry such text) is absent."""
    report = world["report"].casefold()
    cells: set[str] = set()
    for r in world["tables"]["hops.csv"]:
        cells |= {a for a in r["member_accounts"].split(";") if a}
    for r in world["tables"]["hop_identity.csv"]:
        cells |= {r["account"], r["dump_account"], r["dump_source_image"]} - {""}
    for r in world["tables"]["links.csv"]:
        cells |= {r["source_session_account"]} - {""}
        cells |= {n for n in r["name_check_names"].split(";") if n}
    for r in world["tables"]["hop_artefacts.csv"]:
        cells |= {n for n in r["names"].split(";") if n}
    assert len(cells) >= 8
    for c in cells:
        assert c.casefold() not in report, "a CSV text cell value is in report.md"


def test_stats_json_dict_has_no_account_image_or_command_text(world):
    import json
    text = json.dumps(world["stats"]).casefold()
    for kind, items in forbidden_strings().items():
        for s in items:
            assert s.casefold().replace("\\", "\\\\") not in text and s.casefold() not in text, kind
