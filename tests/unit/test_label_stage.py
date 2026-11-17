"""T8.2d: the label stage end to end on a synthetic repo (spec 04_label LBT-01, LBT-05, LBT-06, LBT-07, LBT-08, LBT-09,
LB-00, LB-01, LB-03, LB-06, LB-08, LB-09, LB-11, LB-13, section 2 refusals, section 3.4 output contract; decision 058).

Written from the spec and decisions 056 / 057 / 058, not from the implementation (the code was read only for its public
entry points: `label.__main__.main`, `label.run.label_trial`, `label.rules.load_rules`, `label.params`). A fake repo
from `stitch_fixtures.make_repo` plus hand-written stitch outputs lives in a pytest `tmp_path`; the CLI writes into
`tmp_path` through `--out` (or into the fake repo's own `out/`). Nothing under the real `out/`, `data/` or
`ground_truth/` is opened. Command cells are neutral placeholders.
"""
from __future__ import annotations

import ast
import builtins
import io
import json
import re
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_fixtures as cf  # noqa: E402
import label_fixtures as lf  # noqa: E402
import stitch_fixtures as sf  # noqa: E402
from label import params as lp  # noqa: E402
from label import rules as lr  # noqa: E402
from label.errors import LabelError  # noqa: E402
from label.run import label_trial  # noqa: E402

T = sf.at
TIME_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")


# ------------------------------------------------------------------------------------------------ the synthetic world
def world_rows() -> list[dict]:
    cmd = {"command_line": sf.PLACEHOLDER_COMMAND}
    return [
        lf.sysmon10("d1_dump", off=10),                                                       # SR-01 + SR-02
        lf.sysmon10("d2_unlabelled", off=11, source=r"C:\Windows\System32\wmiprvse.exe",
                    calltrace=r"C:\x\foo.sys+a", access="0x1410"),                            # no rule
        lf.wsman_proc("p1_s1", "Sysmon", off=20, pid=4242, **cmd),                            # SR-40
        lf.wsman_proc("p1_4688", "Security", off=20.5, pid=4242, **cmd),                      # SR-40, same process
        lf.wsman_proc("p3_4688", "Security", off=40, pid=4242, **cmd),                        # SR-40, 20 s later
        lf.svc4697("s1_4697", "SvcA", off=30),                                                # SR-31
        lf.svc7045("s1_7045", "SvcA", off=31),                                                # SR-30, same install
        lf.svc7045("s2_7045", "SvcB", off=60),                                                # SR-30, alone
        lf.plain4624("l1_4624", off=5),                                                       # no rule
        lf.sysmon10("dup_aaa", off=70, record_id=777),                                        # SR-01 + SR-02
        lf.sysmon10("dup_bbb", off=70, record_id=777),                                        # near duplicate of dup_aaa
        lf.sysmon10("z_out", off=3600),                                                       # raw 11:30, outside
        lf.sysmon10("dup_out", off=3600, record_id=777),                                      # copy outside the window
    ]


NODES = [
    lf.node("p1", "h1", "d1_dump", role="source_session_event", context="1", host="ep-01"),
    lf.node("p1", "h1", "p1_s1"),
    lf.node("p1", "h1", "s1_copy"),                      # an ST-05 copy of s1_4697 (hops.csv member_logon_uids)
    lf.node("p1", "h1", "l1_4624", role="target_logon"),
    lf.node("p1", "h1", "ghost"),                        # not in the DB at all
    lf.node("p2", "h1", "p1_s1"),                        # the same event in a second path
    lf.node("p1", "h1", "dup_bbb"),                      # the LB-03 copy of dup_aaa
]
HOPS = [lf.hop("h1", members="s1_4697|s1_copy;l1_4624"), lf.hop("h2", in_path="0")]
IDENTITY = [
    {"hop_id": "h1", "account": "alice", "dump_event_uid": "d1_dump", "dump_utc_corrected": T(10)},
    {"hop_id": "h1", "account": "bob", "dump_event_uid": "d1_dump", "dump_utc_corrected": T(10)},
    {"hop_id": "h1", "account": "alice", "dump_event_uid": "d2_unlabelled", "dump_utc_corrected": T(11)},
    {"hop_id": "h1", "account": "alice", "dump_event_uid": "lookback_uid", "dump_utc_corrected": T(-100)},
    {"hop_id": "h1", "account": "alice", "dump_event_uid": "", "dump_utc_corrected": ""},
]


@pytest.fixture(scope="module")
def ran(tmp_path_factory):
    root = tmp_path_factory.mktemp("label_stage")
    w = lf.run_world(root, world_rows(), NODES, HOPS, IDENTITY)
    db_before = sf.sha256_of(w.fake.paths.db)
    w2out = root / "second_out"
    code2 = lf.cli(w.fake, w2out)
    return {"w": w, "tables": lf.tables(w.out) if w.out.exists() else {}, "second": w2out, "code2": code2,
            "db_before": db_before, "db_after": sf.sha256_of(w.fake.paths.db)}


def ev_rows(ran, uid=None, rule=None):
    rows = ran["tables"]["event_labels.csv"]
    return [r for r in rows if (uid is None or r["event_uid"] == uid) and (rule is None or r["rule_id"] == rule)]


# ================================================================================================ contract
def test_the_run_succeeds_and_writes_exactly_the_seven_spec_files(ran):
    assert ran["w"].code == 0 and ran["code2"] == 0
    assert sorted(p.name for p in ran["w"].out.iterdir()) == lf.OUTPUT_FILES


def test_the_default_folder_is_not_created_when_out_is_given(ran):
    assert not (ran["w"].fake.repo / "out" / "label").exists()


def test_columns_of_every_table_are_the_spec_columns_in_order(ran):
    out = ran["w"].out
    assert lf.header_of(out / "event_labels.csv") == lf.EVENT_COLUMNS
    assert lf.header_of(out / "node_labels.csv") == lf.NODE_COLUMNS
    assert lf.header_of(out / "hop_labels.csv") == lf.HOP_COLUMNS
    assert lf.header_of(out / "rules_manifest.csv") == lf.MANIFEST_COLUMNS


def test_the_code_column_lists_equal_the_spec_lists():
    from label import outputs as lo
    assert list(lo.EVENT_COLUMNS) == lf.EVENT_COLUMNS
    assert list(lo.NODE_COLUMNS) == lf.NODE_COLUMNS
    assert list(lo.HOP_COLUMNS) == lf.HOP_COLUMNS
    assert list(lp.MANIFEST_COLUMNS) == lf.MANIFEST_COLUMNS
    assert sorted(lo.OUTPUT_FILES) == lf.OUTPUT_FILES
    assert list(lp.STITCH_FILES) == lf.STITCH_FILES


def test_no_tier_column_and_method_is_sigma_rule_spec_3_4_q8(ran):
    assert not any("tier" in c for c in lf.EVENT_COLUMNS + lf.NODE_COLUMNS + lf.HOP_COLUMNS)
    assert not any("tier" in c for c in lf.header_of(ran["w"].out / "event_labels.csv"))
    assert {r["method"] for r in ev_rows(ran)} == {"sigma_rule"}


def test_event_label_cells_have_the_spec_types(ran):
    rows = ev_rows(ran)
    assert rows
    for r in rows:
        assert r["trial_id"] == lf.TRIAL
        assert TIME_RE.match(r["event_utc"]) and TIME_RE.match(r["event_utc_corrected"]), r["event_uid"]
        assert int(r["event_id"]) > 0 and int(r["record_id"]) >= 0
        assert r["level_value"] in {"0", "1", "2", "3", "4"}
        assert r["clock_unreliable"] in {"0", "1"}
        assert r["rule_source"] in {"sigmahq", "own"}
        assert (r["sigma_id"] == "") == (r["rule_source"] == "own")
        assert re.fullmatch(r"SR-\d\d", r["rule_id"])
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", r["technique"])


def test_level_and_level_value_agree_with_the_locked_map(ran):
    for r in ev_rows(ran):
        assert lp.LEVEL_VALUE[r["level"]] == int(r["level_value"])


def test_every_match_of_every_rule_is_a_row_lb06(ran):
    got = {(r["event_uid"], r["rule_id"]) for r in ev_rows(ran)}
    expected = {("d1_dump", "SR-01"), ("d1_dump", "SR-02"), ("p1_s1", "SR-40"), ("p1_4688", "SR-40"),
                ("p3_4688", "SR-40"), ("s1_4697", "SR-31"), ("s1_7045", "SR-30"), ("s2_7045", "SR-30"),
                ("dup_aaa", "SR-01"), ("dup_aaa", "SR-02")}
    assert got == expected
    assert len(ev_rows(ran)) == len(expected)                       # one row per (event, rule), no duplicates


def test_unmatched_events_have_no_label_row(ran):
    seen = {r["event_uid"] for r in ev_rows(ran)}
    assert not seen & {"d2_unlabelled", "l1_4624"}


def test_event_rows_are_sorted_by_corrected_time_then_uid_then_rule_lb13(ran):
    keys = [(r["event_utc_corrected"], r["event_uid"], r["rule_id"]) for r in ev_rows(ran)]
    assert keys == sorted(keys)


def test_multi_tag_columns_are_semicolon_joined_and_node_columns_are_primary_only_decision_058(ran):
    r = ev_rows(ran, "p1_s1", "SR-40")[0]
    assert r["technique"] == "T1021.006"
    assert set(r["techniques"].split(";")) == {"T1021.006", "T1059.001"}
    assert r["tactics"] and all(t == t.lower() for t in r["tactics"].split(";"))
    nodes = [n for n in ran["tables"]["node_labels.csv"] if n["event_uid"] == "p1_s1"]
    assert nodes and all(n["techniques"] == "T1021.006" for n in nodes)


def test_rule_titles_sources_and_levels_come_from_the_manifest(ran):
    man = {r["rule_id"]: r for r in ran["tables"]["rules_manifest.csv"]}
    for r in ev_rows(ran):
        assert r["rule_title"] == man[r["rule_id"]]["title"]
        assert r["rule_source"] == man[r["rule_id"]]["source"]
        assert r["level"] == man[r["rule_id"]]["level"]
        assert r["sigma_id"] == man[r["rule_id"]]["sigma_id"]


def test_rules_manifest_is_a_copy_of_the_input_manifest(ran):
    assert (ran["w"].out / "rules_manifest.csv").read_bytes().replace(b"\r\n", b"\n") == \
        (Path(lp.RULES_DIR) / "manifest.csv").read_bytes().replace(b"\r\n", b"\n")


# ================================================================================================ LBT-05 window / duplicates
def test_an_event_outside_the_window_has_no_row_and_no_mention_in_any_file(ran):
    for p in ran["w"].out.iterdir():
        text = p.read_text(encoding="utf-8")
        assert "z_out" not in text and "dup_out" not in text, p.name


def test_outside_window_rows_are_counted_in_stats(ran):
    stats = json.loads((ran["w"].out / "stats.json").read_text(encoding="utf-8"))
    flat = json.dumps(stats)
    assert '"outside_window_rows": 2' in flat.replace(":2", ": 2")


def test_near_duplicate_rows_collapse_to_the_smallest_uid_lb03(ran):
    rows = ev_rows(ran, "dup_aaa")
    assert sorted(r["rule_id"] for r in rows) == ["SR-01", "SR-02"]               # one row per rule
    assert {r["dup_uids"] for r in rows} == {"dup_bbb"}                           # the copy, and no out-of-window uid
    assert not ev_rows(ran, "dup_bbb")                                            # the copy has no row of its own


def test_events_without_duplicates_have_an_empty_dup_uids(ran):
    assert {r["dup_uids"] for r in ev_rows(ran) if r["event_uid"] != "dup_aaa"} == {""}


def test_duplicates_need_the_same_host_channel_and_record_id_lb03(tmp_path):
    rows = [lf.sysmon10("a1", off=10, record_id=5), lf.sysmon10("a2", off=10, record_id=5, host="ep-02"),   # host
            lf.sysmon10("b1", off=20, record_id=6), lf.plain4624("b2", off=20, host="ep-01", record_id=6),     # channel
            lf.sysmon10("c1", off=30, record_id=None), lf.sysmon10("c2", off=30, record_id=None)]           # no record
    w = lf.run_world(tmp_path, rows)
    assert w.code == 0
    labelled = [r for r in lf.read_csv(w.out / "event_labels.csv") if r["rule_id"] == "SR-01"]
    assert sorted(r["event_uid"] for r in labelled) == ["a1", "a2", "b1", "c1", "c2"]
    assert {r["dup_uids"] for r in labelled} == {""}


def test_three_copies_are_joined_with_a_pipe_sorted(tmp_path):
    rows = [lf.sysmon10(u, off=10, record_id=9) for u in ("m_c", "m_a", "m_b")]
    w = lf.run_world(tmp_path, rows)
    got = [r for r in lf.read_csv(w.out / "event_labels.csv") if r["rule_id"] == "SR-01"]
    assert len(got) == 1 and got[0]["event_uid"] == "m_a" and got[0]["dup_uids"] == "m_b|m_c"


def test_the_window_uses_corrected_time_and_event_times_are_written_corrected_co09(tmp_path):
    rows = [lf.sysmon10("ep01_late", off=10, host="ep-01"),          # raw 10:30:10, offset +40 min -> corrected 09:50
            lf.sysmon10("ep02_in", off=10, host="ep-02")]            # offset +5 s -> corrected 10:30:05
    w = lf.run_world(tmp_path, rows, offsets=cf.offsets_spec(ep_01=(2_400_000, "ok", True),
                                                             ep_02=(5000, "ok", True)))
    assert w.code == 0
    got = {r["event_uid"]: r for r in lf.read_csv(w.out / "event_labels.csv") if r["rule_id"] == "SR-01"}
    assert set(got) == {"ep02_in"}                                   # the corrected 09:50 event is outside the window
    assert got["ep02_in"]["event_utc"] == T(10, ) .replace("10:30:10", "10:30:10")
    assert got["ep02_in"]["event_utc_corrected"] == T(5)
    assert "ep01_late" not in json.dumps({p.name: p.read_text(encoding="utf-8") for p in w.out.iterdir()})


def test_clock_unreliable_follows_the_event_host_status(tmp_path):
    rows = [lf.sysmon10("h1_ok", off=10, host="ep-01"), lf.sysmon10("h2_none", off=10, host="ep-02")]
    w = lf.run_world(tmp_path, rows, offsets=cf.offsets_spec(ep_02=(None, "none", True)))
    got = {r["event_uid"]: r["clock_unreliable"] for r in lf.read_csv(w.out / "event_labels.csv")
           if r["rule_id"] == "SR-01"}
    assert got == {"h1_ok": "0", "h2_none": "1"}


# ================================================================================================ LBT-06 node join
def test_one_node_row_per_stitch_node_row_in_the_same_order_labelled_or_not(ran):
    nodes_out = ran["tables"]["node_labels.csv"]
    assert len(nodes_out) == len(NODES)
    for got, src in zip(nodes_out, NODES):
        assert (got["path_id"], got["hop_id"], got["role"], got["context"], got["host"], got["event_uid"]) == \
            (src["path_id"], src["hop_id"], src["role"], src["context"], src["host"], src["event_uid"])


def test_a_labelled_node_carries_rule_ids_primary_techniques_and_max_level(ran):
    by = {(n["path_id"], n["event_uid"]): n for n in ran["tables"]["node_labels.csv"]}
    d = by[("p1", "d1_dump")]
    assert d["labelled"] == "1" and d["rule_ids"] == "SR-01;SR-02" and d["techniques"] == "T1003.001"
    assert d["max_level_value"] == "3" and d["context"] == "1"
    p = by[("p1", "p1_s1")]
    assert p["labelled"] == "1" and p["rule_ids"] == "SR-40" and p["max_level_value"] == "2"
    assert by[("p2", "p1_s1")]["labelled"] == "1"                    # the same event in a second path


def test_a_node_that_is_an_st05_copy_of_a_labelled_event_is_labelled_lb08(ran):
    by = {n["event_uid"]: n for n in ran["tables"]["node_labels.csv"]}
    c = by["s1_copy"]                                                # member_logon_uids "s1_4697|s1_copy"
    assert c["labelled"] == "1" and c["rule_ids"] == "SR-31" and c["techniques"] == "T1569.002"
    assert c["max_level_value"] == "1"


def test_a_node_that_is_an_lb03_copy_of_a_labelled_event_is_labelled(ran):
    by = {n["event_uid"]: n for n in ran["tables"]["node_labels.csv"]}
    assert by["dup_bbb"]["labelled"] == "1" and by["dup_bbb"]["rule_ids"] == "SR-01;SR-02"


def test_unlabelled_nodes_are_written_with_labelled_zero_and_empty_cells(ran):
    by = {n["event_uid"]: n for n in ran["tables"]["node_labels.csv"]}
    for uid in ("l1_4624", "ghost"):
        n = by[uid]
        assert (n["labelled"], n["rule_ids"], n["techniques"], n["max_level_value"]) == ("0", "", "", "")


def test_a_labelled_context_one_node_is_labelled_like_any_node_q6(ran):
    by = {n["event_uid"]: n for n in ran["tables"]["node_labels.csv"]}
    assert by["d1_dump"]["context"] == "1" and by["d1_dump"]["labelled"] == "1"


# ================================================================================================ hop labels
def test_one_hop_row_per_hop_in_order_and_counts_distinct_node_events(ran):
    hops = ran["tables"]["hop_labels.csv"]
    assert [h["hop_id"] for h in hops] == ["h1", "h2"]
    h1, h2 = hops
    assert h1["in_path"] == "1" and h2["in_path"] == "0"
    assert h1["n_node_events"] == "6"                  # d1_dump, p1_s1, s1_copy, l1_4624, ghost, dup_bbb (p1_s1 once)
    assert h1["n_labelled_node_events"] == "4"         # d1_dump, p1_s1, s1_copy, dup_bbb
    assert h1["techniques"].split(";") == sorted({"T1003.001", "T1021.006", "T1569.002"})


def test_a_hop_with_no_labelled_node_has_zero_and_empty_techniques_atk_l08(ran):
    h2 = ran["tables"]["hop_labels.csv"][1]
    assert (h2["n_node_events"], h2["n_labelled_node_events"], h2["techniques"]) == ("0", "0", "")
    assert (h2["dump_event_uids"], h2["dump_labelled"], h2["dump_rule_ids"], h2["dump_max_level_value"]) == \
        ("", "", "", "")


def test_dump_columns_are_one_value_per_distinct_uid_in_time_order_decision_058(ran):
    h1 = ran["tables"]["hop_labels.csv"][0]
    assert h1["dump_event_uids"] == "lookback_uid;d1_dump;d2_unlabelled"        # distinct, non-empty, time then uid
    assert h1["dump_labelled"] == "outside_window;1;0"                         # same order, one value per uid
    assert h1["dump_rule_ids"] == "SR-01;SR-02"
    assert h1["dump_max_level_value"] == "3"


def test_dump_columns_are_facts_and_do_not_change_the_node_rows(tmp_path):
    """Q1 / Q2 / ATK-L02: the same run without any identity rows gives identical node_labels."""
    rows = world_rows()
    a = lf.run_world(tmp_path, rows, NODES, HOPS, IDENTITY, name="with")
    b = lf.run_world(tmp_path, rows, NODES, HOPS, [], name="without")
    assert (a.out / "node_labels.csv").read_bytes() == (b.out / "node_labels.csv").read_bytes()
    assert (a.out / "event_labels.csv").read_bytes() == (b.out / "event_labels.csv").read_bytes()
    hb = lf.read_csv(b.out / "hop_labels.csv")[0]
    assert hb["dump_event_uids"] == "" and hb["n_labelled_node_events"] == "4"


# ================================================================================================ LBT-09 count_key
def test_a_sysmon_1_and_a_4688_of_one_process_share_the_sysmon_1_uid(ran):
    assert ev_rows(ran, "p1_s1", "SR-40")[0]["count_key"] == "p1_s1"
    assert ev_rows(ran, "p1_4688", "SR-40")[0]["count_key"] == "p1_s1"


def test_a_4697_and_a_7045_of_one_install_share_the_4697_uid(ran):
    assert ev_rows(ran, "s1_4697", "SR-31")[0]["count_key"] == "s1_4697"
    assert ev_rows(ran, "s1_7045", "SR-30")[0]["count_key"] == "s1_4697"


def test_a_third_event_outside_the_collapse_window_gets_its_own_key(ran):
    assert ev_rows(ran, "p3_4688", "SR-40")[0]["count_key"] == "p3_4688"        # same pid, 20 s later
    assert ev_rows(ran, "s2_7045", "SR-30")[0]["count_key"] == "s2_7045"        # no 4697 of that name


def test_other_events_key_on_their_own_uid_and_both_paired_events_stay_labelled(ran):
    for r in ev_rows(ran, "d1_dump"):
        assert r["count_key"] == "d1_dump"
    assert ev_rows(ran, "p1_4688") and ev_rows(ran, "s1_7045")


def test_the_collapse_window_boundaries_use_the_stitch_value_of_two_seconds(tmp_path):
    from stitch.params import StitchParams
    assert lp.LabelParams().process_collapse_s == StitchParams().process_collapse_s == 2
    rows = [lf.wsman_proc("q_s1", "Sysmon", off=20, pid=7, host="ep-02"),
            lf.wsman_proc("q_in", "Security", off=21.9, pid=7, host="ep-02"),
            lf.wsman_proc("r_s1", "Sysmon", off=100, pid=8, host="ep-02"),
            lf.wsman_proc("r_out", "Security", off=102.5, pid=8, host="ep-02")]
    w = lf.run_world(tmp_path, rows)
    key = {r["event_uid"]: r["count_key"] for r in lf.read_csv(w.out / "event_labels.csv")}
    assert key == {"q_s1": "q_s1", "q_in": "q_s1", "r_s1": "r_s1", "r_out": "r_out"}


# ================================================================================================ LBT-07 leakage etc.
def leaks(out_dir: Path, values) -> int:
    """Number of 12-character windows of `values` found in any output file, except windows that also occur in the
    public rule files or that are the level word 'informational' (JSON quoting included)."""
    exempt = lf.public_rule_grams()
    wanted = {g for v in values for g in lf.text_grams(str(v))}
    bad: set[str] = set()
    for p in sorted(Path(out_dir).iterdir()):
        bad |= lf.output_windows(p.read_text(encoding="utf-8"), exempt) & wanted
    return len(bad)


def test_no_command_script_or_path_text_reaches_any_output_lbt07(ran):
    values = [sf.PLACEHOLDER_COMMAND, *lf.PLACEHOLDERS.values()]
    assert leaks(ran["w"].out, values) == 0


def test_the_leak_scan_would_notice_a_leak_negative_control(tmp_path):
    folder = tmp_path / "o"
    folder.mkdir()
    (folder / "report.md").write_text("x " + lf.PLACEHOLDERS["scriptblocktext"] + " y", encoding="utf-8")
    assert leaks(folder, [lf.PLACEHOLDERS["scriptblocktext"]]) > 0


def test_the_db_hash_is_unchanged_and_recorded_before_and_after(ran):
    assert ran["db_before"] == ran["db_after"]
    stats = json.loads((ran["w"].out / "stats.json").read_text(encoding="utf-8"))
    assert stats["db"]["sha256_before"] == stats["db"]["sha256_after"] == ran["db_before"]
    info = json.loads((ran["w"].out / "run_info.json").read_text(encoding="utf-8"))
    assert info["db"]["sha256_before"] == info["db"]["sha256_after"] == ran["db_before"]


def test_two_runs_are_byte_identical_except_run_info_lb13(ran):
    a, b = lf.blobs(ran["w"].out), lf.blobs(ran["second"])
    assert sorted(a) == sorted(b) == lf.OUTPUT_FILES
    for name in lf.OUTPUT_FILES:
        if name != "run_info.json":
            assert a[name] == b[name], name
    ia, ib = json.loads(a["run_info.json"]), json.loads(b["run_info.json"])
    ia.pop("generated_utc"), ib.pop("generated_utc")
    assert ia == ib


def test_outputs_use_lf_line_endings(ran):
    for name, data in lf.blobs(ran["w"].out).items():
        assert b"\r" not in data, name


def test_run_info_pins_the_manifest_the_rule_files_and_every_input_lb10(ran):
    info = json.loads((ran["w"].out / "run_info.json").read_text(encoding="utf-8"))
    rs = lr.load_rules(Path(lp.RULES_DIR))
    assert info["rules_manifest_sha256"] == rs.manifest_sha256
    assert info["rules_sha256"] == {r["rule_id"]: r["sha256"] for r in rs.manifest_rows}
    text = json.dumps(info)
    stitch_dir = ran["w"].fake.repo / "out" / "stitch" / lf.TRIAL
    for name in lf.STITCH_FILES:                                      # 058 point 10: stitch file hashes recorded
        assert lf.sha256_file(stitch_dir / name) in text, name
    assert lf.sha256_file(ran["w"].fake.stats_path) in text           # the gate stats hash


def test_stats_json_counts_per_rule_equal_the_label_rows_lba01_shape(ran):
    stats = json.loads((ran["w"].out / "stats.json").read_text(encoding="utf-8"))
    per_rule = stats["labels"]["matches_per_rule"]
    from collections import Counter
    rows = Counter(r["rule_id"] for r in ev_rows(ran))
    assert set(per_rule) == set(lr.load_rules(Path(lp.RULES_DIR)).rules and {r.rule_id for r in
                                                                            lr.load_rules(Path(lp.RULES_DIR)).rules})
    for rid, n in per_rule.items():
        assert n == rows.get(rid, 0), rid
    assert {"SR-03", "SR-11", "SR-12", "SR-50", "SR-61", "SR-10", "SR-20"} <= set(stats["labels"]["rules_with_no_match"])


def test_report_md_states_counts_and_makes_no_forbidden_claim(ran):
    text = (ran["w"].out / "report.md").read_text(encoding="utf-8").lower()
    assert "sr-01" in text and "sr-10" in text
    for phrase in ("reduces false positive", "detects stolen", "identifies the attacker", "probability of"):
        assert phrase not in text


def test_src_label_never_names_a_ground_truth_path_in_code_spec_2():
    """Static check: no non-docstring string literal in src/label mentions `ground_truth`."""
    offenders = []
    for p in sorted((REPO / "src" / "label").glob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        docstrings = {id(n.body[0].value) for n in ast.walk(tree)
                      if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef))
                      and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings \
                    and "ground_truth" in n.value:
                offenders.append(f"{p.name}:{n.lineno}")
        for n in ast.walk(tree):
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                mod = getattr(n, "module", "") or ""
                names = [a.name for a in n.names]
                # answer_key.db is only the read-only DB opener / file hasher (no key is read through it)
                full = [f"{mod}.{x}" if mod else x for x in names]
                for q in full:
                    if ("evaluate" in q or "answer_key" in q) and q != "answer_key.db.open_ro" \
                            and q != "answer_key.db.sha256_file":
                        offenders.append(f"{p.name}:{n.lineno} imports {q}")
    assert offenders == []


def test_a_run_opens_nothing_under_ground_truth_dynamic(tmp_path, monkeypatch):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, IDENTITY)
    seen: list[str] = []
    real_open, real_connect = builtins.open, sqlite3.connect

    def spy_open(file, *a, **k):
        seen.append(str(file))
        return real_open(file, *a, **k)

    def spy_connect(database, *a, **k):
        seen.append(str(database))
        return real_connect(database, *a, **k)

    monkeypatch.setattr(builtins, "open", spy_open)
    monkeypatch.setattr(io, "open", spy_open)
    monkeypatch.setattr(sqlite3, "connect", spy_connect)
    assert lf.cli(fake, tmp_path / "o") == 0
    monkeypatch.undo()
    assert seen, "the spy saw no file open"
    assert [s for s in seen if "ground_truth" in s.replace("\\", "/")] == []


# ================================================================================================ LBT-01 refusals
def untouched(fake) -> dict:
    return sf.snapshot(fake.repo)


def assert_refused_and_nothing_written(fake, code: int, before: dict, tmp_path: Path | None = None) -> None:
    assert code == 2
    assert not (fake.repo / "out" / "label").exists()
    assert untouched(fake) == before


@pytest.mark.parametrize("trial", ["s02_t02", "s02_t10", "s07_t05", "s01_t00", "s01_t01", "not_a_trial"])
def test_lbt01_a_test_trial_or_s01_is_refused_before_any_path_is_opened(tmp_path, monkeypatch, trial, capsys):
    """Allowlist first (LB-00, 046, 053). The repo does not exist, so nothing may be touched under it."""
    import os
    ghost = tmp_path / "no_such_repo"
    touched: list[str] = []
    real_open, real_stat = builtins.open, os.stat

    def spy_open(file, *a, **k):
        touched.append(str(file))
        return real_open(file, *a, **k)

    def spy_stat(path, *a, **k):
        touched.append(str(path))
        return real_stat(path, *a, **k)

    import label.__main__ as lm
    monkeypatch.setattr(builtins, "open", spy_open)
    monkeypatch.setattr(os, "stat", spy_stat)
    code = lm.main(["--trial", trial, "--repo", str(ghost), "--out", str(tmp_path / "out_x")])
    monkeypatch.undo()
    assert code == 2
    assert [t for t in touched if str(ghost) in t or "out_x" in t] == []
    assert not ghost.exists() and not (tmp_path / "out_x").exists()
    err = capsys.readouterr().err
    assert err.startswith("refused") and "not found" not in err.lower()


def test_lbt01_a_test_trial_is_refused_even_when_a_fake_repo_has_the_files(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, IDENTITY)
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake, trial="s02_t02"), before)


def test_lbt01_the_library_raises_label_error_for_a_test_trial(tmp_path):
    fake = lf.build(tmp_path, world_rows())
    for trial in ("s02_t02", "s01_t00"):
        with pytest.raises(LabelError):
            label_trial(fake.repo, trial)


@pytest.mark.parametrize("missing", lf.STITCH_FILES)
def test_lbt01_a_missing_stitch_file_refuses_and_writes_nothing(tmp_path, missing):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, IDENTITY, skip_stitch=[missing])
    before = untouched(fake)
    out = tmp_path / "o"
    assert lf.cli(fake, out) == 2
    assert not out.exists()
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


@pytest.mark.parametrize("gate_file", ["stats.json", "triggers.csv", "supporting.csv", "unmatched_remote.csv"])
def test_lbt01_a_missing_gate_file_refuses(tmp_path, gate_file):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, skip_gate_file=gate_file)
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


def test_lbt01_gate_time_basis_not_corrected_refuses(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, time_basis="raw")
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


def test_lbt01_db_hash_differing_from_the_gate_stats_refuses(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, stats_db_sha_after="0" * 64)
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


def test_lbt01_db_hash_differing_from_the_stitch_run_info_refuses(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, run_db_sha="1" * 64)
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


def test_lbt01_stitch_run_info_without_a_db_hash_refuses(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    (fake.repo / "out" / "stitch" / fake.trial / "run_info.json").write_text("{}", encoding="utf-8")
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


def test_lbt01_a_db_changed_after_the_run_refuses(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    with open(fake.paths.db, "ab") as fh:
        fh.write(b"\0")
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


def test_lbt01_window_row_in_the_gate_stats_differing_from_the_window_file_refuses(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, stats_window_changes={"end_utc": "2026-09-24T11:30:00.000Z"})
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


@pytest.mark.parametrize("kw", [{"stats_offsets_sha": "2" * 64}, {"stats_changes_sha": "3" * 64}])
def test_lbt01_clock_file_hash_differing_from_the_gate_stats_refuses(tmp_path, kw):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, **kw)
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


def test_lbt01_co17_an_uncorrected_host_with_events_after_the_cutoff_refuses(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, start="2026-10-26T10:00:00.000Z",
                    end="2026-10-26T11:00:00.000Z", offsets=cf.offsets_spec(ep_01=(None, "none", True)))
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


def test_lbt01_events_view_lacking_a_column_refuses(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, drop_columns=["field_values_json"])
    before = untouched(fake)
    assert_refused_and_nothing_written(fake, lf.cli(fake), before)


def test_lbt01_rule_file_problems_refuse_through_the_library_and_write_nothing(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    rules = tmp_path / "rules"
    shutil.copytree(lp.RULES_DIR, rules, ignore=shutil.ignore_patterns("__pycache__"))
    (rules / "SR-30_service_installed_system.yml").write_text("changed\n", encoding="utf-8")
    before = untouched(fake)
    with pytest.raises(LabelError):
        label_trial(fake.repo, fake.trial, rules_dir=rules)
    assert untouched(fake) == before
    shutil.copytree(lp.RULES_DIR, tmp_path / "rules2", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp_path / "rules2" / "stray.txt").write_text("x", encoding="utf-8")
    with pytest.raises(LabelError):
        label_trial(fake.repo, fake.trial, rules_dir=tmp_path / "rules2")


def test_lbt01_label_trial_with_the_committed_rules_succeeds_on_the_fake_repo(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, IDENTITY)
    res = label_trial(fake.repo, fake.trial)
    assert sorted(res.files) == lf.OUTPUT_FILES
    assert not (fake.repo / "out" / "label").exists()                 # label_trial itself writes nothing


# ---------------------------------------------------------------- --out
@pytest.mark.parametrize("rel", ["", "out", "data", "docs", "src", "tests", "data/inside", ".git"])
def test_out_inside_the_repo_but_not_below_out_is_refused_and_nothing_is_written(tmp_path, rel):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    before = untouched(fake)
    target = fake.repo / rel if rel else fake.repo
    code = lf.cli(fake, target)
    assert code == 2
    assert untouched(fake) == before


def test_out_below_the_repos_out_folder_is_accepted(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    target = fake.repo / "out" / "label_elsewhere" / "run1"
    assert lf.cli(fake, target) == 0
    assert sorted(p.name for p in target.iterdir()) == lf.OUTPUT_FILES


def test_out_outside_the_repo_writes_the_seven_files_and_no_default_folder(tmp_path, capsys):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    target = tmp_path / "elsewhere" / "run1"
    assert lf.cli(fake, target) == 0
    assert sorted(p.name for p in target.iterdir()) == lf.OUTPUT_FILES
    assert not (fake.repo / "out" / "label").exists()
    assert sorted(p.name for p in target.parent.iterdir()) == ["run1"]           # no temporary sibling left
    assert capsys.readouterr().out.strip()


def test_out_existing_folder_with_a_foreign_file_is_refused_and_left_as_it_was(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    target = tmp_path / "precious"
    target.mkdir()
    (target / "keep_me.txt").write_text("mine", encoding="utf-8")
    before = sf.snapshot(target)
    assert lf.cli(fake, target) == 2
    assert sf.snapshot(target) == before


def test_out_existing_folder_with_a_subfolder_is_refused(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    target = tmp_path / "t"
    (target / "sub").mkdir(parents=True)
    assert lf.cli(fake, target) == 2
    assert (target / "sub").is_dir()


def test_out_existing_file_is_refused(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    target = tmp_path / "afile"
    target.write_text("x", encoding="utf-8")
    assert lf.cli(fake, target) == 2
    assert target.read_text(encoding="utf-8") == "x"


def test_out_existing_folder_holding_only_output_names_is_rebuilt(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, )
    target = tmp_path / "again"
    assert lf.cli(fake, target) == 0
    (target / "event_labels.csv").write_text("stale\n", encoding="utf-8")
    assert lf.cli(fake, target) == 0
    assert lf.header_of(target / "event_labels.csv") == lf.EVENT_COLUMNS
    assert sorted(p.name for p in target.iterdir()) == lf.OUTPUT_FILES


def test_development_mode_refuses_out(tmp_path):
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    out = tmp_path / "devout"
    import label.__main__ as lm
    assert lm.main(["--development", "--repo", str(fake.repo), "--out", str(out)]) == 2
    assert not out.exists()


def test_a_refusal_in_the_default_folder_leaves_an_earlier_good_run_untouched(tmp_path):
    """Rebuilt on every run only on success: a later refused run (DB changed) must not delete the earlier folder."""
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS)
    assert lf.cli(fake) == 0
    good = lf.blobs(lf.label_dir(fake))
    with open(fake.paths.db, "ab") as fh:
        fh.write(b"\0")
    assert lf.cli(fake) == 2
    assert lf.blobs(lf.label_dir(fake)) == good


# ================================================================================================ stage review 061
# ---------------------------------------------------------------- ATK-S03 context-0 hop counts
def test_atk_s03_hop_columns_count_context_zero_labelled_nodes(ran):
    h1 = ran["tables"]["hop_labels.csv"][0]
    # labelled: d1_dump (context 1), p1_s1, s1_copy, dup_bbb (context 0)
    assert h1["n_labelled_node_events"] == "4" and h1["n_labelled_context0_node_events"] == "3"
    assert lf.header_of(ran["w"].out / "hop_labels.csv")[3:5] == ["n_labelled_node_events",
                                                                  "n_labelled_context0_node_events"]


def test_atk_s03_a_hop_whose_only_labelled_node_is_a_context_one_dump(tmp_path):
    rows = [lf.sysmon10("only_dump", off=10)]                                     # SR-01 + SR-02, nothing else
    nodes = [lf.node("p1", "hx", "only_dump", role="source_session_event", context="1", host="ep-01"),
             lf.node("p1", "hx", "l1_plain", role="target_logon")]
    rows.append(lf.plain4624("l1_plain", off=5))
    w = lf.run_world(tmp_path, rows, nodes, [lf.hop("hx")])
    assert w.code == 0
    (h,) = lf.read_csv(w.out / "hop_labels.csv")
    assert h["n_node_events"] == "2" and h["n_labelled_node_events"] == "1"
    assert h["n_labelled_context0_node_events"] == "0"
    assert h["techniques"] == "" and "T1003.001" not in h["techniques"]
    node = {n["event_uid"]: n for n in lf.read_csv(w.out / "node_labels.csv")}
    assert node["only_dump"]["labelled"] == "1" and node["only_dump"]["techniques"] == "T1003.001"   # node row unchanged
    stats = json.loads((w.out / "stats.json").read_text(encoding="utf-8"))
    assert stats["hops"]["in_path_without_labelled_node"] == 1
    assert stats["hops"]["with_labelled_node"] == 1                 # any context
    assert stats["hops"]["with_labelled_context0_node"] == 0        # decision 061 stats key
    assert stats["hops"]["labelled_context0_node_events"] == 0


def test_atk_s03_a_context_zero_label_still_counts_the_hop(tmp_path):
    rows = [lf.sysmon10("a_dump", off=10), lf.svc7045("a_svc", "SvcZ", off=20)]
    nodes = [lf.node("p1", "hy", "a_dump", role="source_session_event", context="1", host="ep-01"),
             lf.node("p1", "hy", "a_svc")]
    w = lf.run_world(tmp_path, rows, nodes, [lf.hop("hy")])
    (h,) = lf.read_csv(w.out / "hop_labels.csv")
    assert (h["n_labelled_node_events"], h["n_labelled_context0_node_events"], h["techniques"]) == \
        ("2", "1", "T1569.002")
    stats = json.loads((w.out / "stats.json").read_text(encoding="utf-8"))
    assert stats["hops"]["in_path_without_labelled_node"] == 0


# ---------------------------------------------------------------- ATK-S05 stale or malformed stitch / gate / clock inputs
def refused_world(tmp_path, mutate=None, **build_kw):
    """Build the standard fake repo, apply `mutate(fake)`, run the CLI into a tmp folder; return (code, fake, out,
    snapshot-before)."""
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, IDENTITY, **build_kw)
    if mutate:
        mutate(fake)
    before = sf.snapshot(fake.repo)
    out = tmp_path / "o"
    return lf.cli(fake, out), fake, out, before


def assert_nothing_written(code, fake, out, before):
    assert code == 2
    assert not out.exists() and not (fake.repo / "out" / "label").exists()
    assert sf.snapshot(fake.repo) == before


def test_atk_s05_the_unmutated_world_is_accepted(tmp_path):
    code, fake, out, _ = refused_world(tmp_path)
    assert code == 0 and out.exists()


@pytest.mark.parametrize("what", ["gate", "offsets", "changes"])
def test_atk_s05_a_changed_gate_stats_or_clock_hash_in_the_stitch_run_info_refuses(tmp_path, what):
    def mutate(fake):
        def edit(d):
            if what == "gate":
                d["gate_stats_sha256"] = "f" * 64
            elif what == "offsets":
                d["window"]["offsets_sha256"] = "e" * 64
            else:
                d["window"]["clock_changes_sha256"] = "d" * 64
        lf.edit_run_info(fake, edit)
    assert_nothing_written(*refused_world(tmp_path, mutate))


def test_atk_s05_a_gate_stats_file_changed_after_the_stitch_run_refuses(tmp_path):
    def mutate(fake):
        d = json.loads(fake.stats_path.read_text(encoding="utf-8"))
        d["note"] = "regenerated"
        fake.stats_path.write_text(json.dumps(d, sort_keys=True), encoding="utf-8")
    assert_nothing_written(*refused_world(tmp_path, mutate))


@pytest.mark.parametrize("name", ["path_nodes.csv", "hops.csv", "hop_identity.csv", "hop_artefacts.csv"])
def test_atk_s05_a_stitch_csv_whose_hash_differs_from_the_run_info_refuses(tmp_path, name):
    def mutate(fake):
        p = fake.repo / "out" / "stitch" / fake.trial / name
        p.write_bytes(p.read_bytes() + b"\n")                                       # a changed byte after the run
    assert_nothing_written(*refused_world(tmp_path, mutate))


def test_atk_s05_a_stitch_csv_with_no_recorded_hash_refuses(tmp_path):
    def mutate(fake):
        lf.edit_run_info(fake, lambda d: d["files"].pop("hops.csv"))
    assert_nothing_written(*refused_world(tmp_path, mutate))


@pytest.mark.parametrize("drop,where", [("context", "node"), ("event_uid", "node"), ("hop_id", "node"),
                                        ("dump_utc_corrected", "identity"), ("dump_event_uid", "identity")])
def test_atk_s05_a_missing_required_column_refuses(tmp_path, drop, where):
    kw = ({"node_columns": [c for c in lf.NODE_IN_COLUMNS if c != drop]} if where == "node"
          else {"identity_columns": [c for c in lf.IDENTITY_IN_COLUMNS if c != drop]})
    assert_nothing_written(*refused_world(tmp_path, **kw))


def test_atk_s05_a_missing_required_column_of_hops_csv_refuses(tmp_path):
    def mutate(fake):
        p = fake.repo / "out" / "stitch" / fake.trial / "hops.csv"
        p.write_text("hop_id,in_path\nh1,1\nh2,0\n", encoding="utf-8")            # no member_logon_uids
        lf.edit_run_info(fake, lambda d: d["files"]["hops.csv"].update(sha256=lf.sha256_file(p)))
    assert_nothing_written(*refused_world(tmp_path, mutate))


def test_atk_s05_a_ragged_stitch_row_refuses(tmp_path):
    def mutate(fake):
        p = fake.repo / "out" / "stitch" / fake.trial / "hops.csv"
        p.write_text("hop_id,in_path,member_logon_uids\nh1,1,a,EXTRA\n", encoding="utf-8")
        lf.edit_run_info(fake, lambda d: d["files"]["hops.csv"].update(sha256=lf.sha256_file(p)))
    assert_nothing_written(*refused_world(tmp_path, mutate))


@pytest.mark.parametrize("bad", ["not-a-time", "2026-13-45T99:00:00Z", ""])
def test_atk_s05_an_unparsable_or_empty_dump_utc_corrected_refuses(tmp_path, bad):
    ident = [{"hop_id": "h1", "account": "alice", "dump_event_uid": "d1_dump", "dump_utc_corrected": bad}]
    fake = lf.build(tmp_path, world_rows(), NODES, HOPS, ident)
    before = sf.snapshot(fake.repo)
    out = tmp_path / "o"
    assert_nothing_written(lf.cli(fake, out), fake, out, before)


def test_atk_s05_a_row_without_a_dump_uid_needs_no_time(tmp_path):
    """No dump uid, no time needed: the row is skipped, not refused."""
    ident = [{"hop_id": "h1", "account": "alice", "dump_event_uid": "", "dump_utc_corrected": ""}]
    w = lf.run_world(tmp_path, world_rows(), NODES, HOPS, ident)
    assert w.code == 0


# ---------------------------------------------------------------- ATK-S02 characterisation (limitation L-LB5)
def test_atk_s02_characterisation_a_near_duplicate_is_labelled_through_the_smallest_uid_only(tmp_path):
    """Spec LB-03 / L-LB5, kept as written (not a failure): two rows with one (host, channel, record_id) are one event;
    the representative is the smallest uid, so only ITS payload is matched, and the copy inherits its labels."""
    tool = r"C:\Tools\other.exe"
    rows = [
        # case 1: the smallest uid carries the matching payload -> labelled, the copy is listed
        lf.sysmon10("c1_a", off=10, record_id=501),
        lf.sysmon10("c1_b", off=10, record_id=501, source=tool, calltrace=r"C:\x\foo.sys+a", access="0x1410"),
        # case 2: the smallest uid carries the NON-matching payload -> no label at all, though the copy would match
        lf.sysmon10("c2_a", off=20, record_id=502, source=tool, calltrace=r"C:\x\foo.sys+a", access="0x1410"),
        lf.sysmon10("c2_b", off=20, record_id=502),
    ]
    w = lf.run_world(tmp_path, rows)
    got = [r for r in lf.read_csv(w.out / "event_labels.csv") if r["event_uid"].startswith(("c1", "c2"))]
    assert {r["event_uid"] for r in got} == {"c1_a"}
    assert {r["dup_uids"] for r in got} == {"c1_b"}
    assert {r["rule_id"] for r in got} == {"SR-01", "SR-02"}
