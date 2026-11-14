"""Fast synthetic tests of the T7.6 link accuracy module `src/evaluate` (decision 051 items 1-10 and the
"Implementation readings" 1-11; spec 03_stitch ST-25, STA-05..STA-08 and the section 3 column lists; decision 047
item 3 for the boot epochs).

Written from the design, not from the implementation (the code was read only for the public names: `evaluate.evaluate_trial`,
`evaluate.EvalError`, the CLI `python -m evaluate --trial/--development/--repo/--stitch-dir/--out`, and the output file
names). Every fixture lives in a `tmp_path` (`evaluate_fixtures`): a fake repo with a small events DB, the ten stitch
files with SHA-256s in the stitch `run_info.json`, and an approved key. The real `data/`, `out/` and `ground_truth/`
are never opened; no `key_lock.csv` is ever created outside a `tmp_path`.

Messages carry ids, hosts and counts only, never command text.
"""
from __future__ import annotations

import ast
import csv
import io
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import evaluate  # noqa: E402
from evaluate import EvalError, evaluate_trial  # noqa: E402
from evaluate import __main__ as em  # noqa: E402
import evaluate_fixtures as fx  # noqa: E402
import stitch_fixtures as sf  # noqa: E402
from evaluate_fixtures import (SRC, DST, TARGET_LID, SESSION_KEY, SESSION_OTHER, ek, hop_row, ident_row, key_hop,  # noqa: E402
                               link_row, logon, ev, only_keyed, std_world)

KEYED = "link_accuracy_hops.csv"
FACTS = "link_facts_hops.csv"
TOTALS = "link_accuracy_totals.csv"
MD = "link_accuracy.md"
RUN_INFO = "run_info.json"

CMD = lambda: link_row("H1", 1, "cmdline_target", 1280, "U500")  # noqa: E731  key session, rank 1
OTHER = lambda rank=1, tie=0, tier="C": link_row("H1", 2, "source_4648", 1536, "U600", rank=rank, tie=tie, tier=tier)  # noqa: E731


def read_csv(path: Path) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8"), newline="")))


def run_dev(w: fx.World, **kw):
    return evaluate_trial(w.repo, w.trial, "development", w.stitch_dir, **kw)


def cli(w: fx.World, out: Path, *extra: str, trial: str | None = None) -> int:
    return em.main(["--trial", trial or w.trial, "--repo", str(w.repo), "--stitch-dir", str(w.stitch_dir),
                    "--out", str(out), *extra])


def key_info(run_info: dict) -> dict:
    """The key block of a run_info.json: top level or under `inputs` (decision 051 item 9 says `key.path/sha256/lock`)."""
    if isinstance(run_info.get("key"), dict):
        return run_info["key"]
    return run_info["inputs"]["key"]


def one(w: fx.World, **kw) -> dict[str, str]:
    return only_keyed(run_dev(w, **kw))


# ================================================================================================ contract
def test_keyed_trial_contract_columns_rows_and_order(tmp_path):
    """One keyed row per key hop in key order, one fact row per stitch hop in hops.csv order; nothing lost, nothing
    duplicated; the output folder holds the files the design names."""
    uids = ["T1", "T2", "T3"]
    w = fx.build_world(
        tmp_path, db_rows=fx.std_db(),
        event_keys=fx.std_event_keys({"T2": ek("T2", DST, "Security", 4624, 205.0)}),
        key_hops=[key_hop("k1", target_uids=["T1"], target_lid=TARGET_LID, session_hex="0x500", agent_uids=["C1"]),
                  key_hop("k2", target_uids=["T2"], target_lid=0x101, session_hex="0x600", agent_uids=["C1"])],
        hops=[hop_row("H1", ["T1"], [TARGET_LID]), hop_row("H2", ["T2"], [0x101]),
              hop_row("H3", ["T3"], [0x102], tier="D", cand=0)],
        links=[link_row("H1", 1, "cmdline_target", 1280, "U500"), link_row("H2", 1, "cmdline_target", 1536, "U600"),
               link_row("H3", 1, "target_only")],
        identity=[ident_row("H1"), ident_row("H2"), ident_row("H3")])
    res = run_dev(w)
    assert [r["key_hop_id"] for r in res.keyed_rows] == ["k1", "k2"]
    assert [r["hop_id"] for r in res.fact_rows] == ["H1", "H2", "H3"]
    assert len({r["hop_id"] for r in res.fact_rows}) == len(res.fact_rows)
    cols = set(res.keyed_rows[0])
    for c in ("split", "trial_id", "key_hop_id", "key_account", "match", "hop_id", "key_logons_in_hop",
              "best_tier", "candidate_count", "session_compare", "among_candidates", "rank1", "only_candidate",
              "expected_target_only", "target_only_ok", "target_only_reason", "evidence_before_range",
              "port_cmd_agree", "identity_value", "identity_match"):
        assert c in cols, c
    assert all(isinstance(v, str) for r in res.keyed_rows for v in r.values())
    tcols = set(res.total_rows[0])
    for c in ("split", "trial_id", "scope", "protocol_group", "tier", "compare_ambiguous_boot"):
        assert c in tcols, c
    out = tmp_path / "out"
    assert cli(w, out) == 0
    names = {p.name for p in out.iterdir()}
    assert {KEYED, FACTS, TOTALS, MD, RUN_INFO} <= names
    assert len(read_csv(out / KEYED)) == 2 and len(read_csv(out / FACTS)) == 3
    # the CSV on disk equals the in-memory rows
    assert [r["key_hop_id"] for r in read_csv(out / KEYED)] == ["k1", "k2"]
    # the keyed totals add up: the sum of the per-(group, tier) rows equals the all/all row
    keyed_tot = [r for r in read_csv(out / TOTALS) if r["scope"] == "keyed"]
    allrow = [r for r in keyed_tot if r["protocol_group"] == "all"]
    assert len(allrow) == 1
    for c in ("key_hops", "matched", "with_key_session", "among", "rank1_correct"):
        assert sum(int(r[c]) for r in keyed_tot if r["protocol_group"] != "all") == int(allrow[0][c]), c
    assert int(allrow[0]["key_hops"]) == 2 and int(allrow[0]["matched"]) == 2
    assert int(allrow[0]["among"]) == 2 and int(allrow[0]["rank1_correct"]) == 2


# ================================================================================================ ST-25 match
def _multi(tmp_path, hops, key_lid=TARGET_LID, key_uids=("T1", "T2", "T3")):
    ekeys = fx.std_event_keys({"T2": ek("T2", DST, "Security", 4624, 106.0),
                               "T3": ek("T3", DST, "Security", 5145, 107.0)})
    links = [link_row(h["hop_id"], 1, "target_only") for h in hops]
    return fx.build_world(
        tmp_path, db_rows=fx.std_db(), event_keys=ekeys,
        key_hops=[key_hop("k1", target_uids=list(key_uids), target_lid=key_lid, session_hex="0x500",
                          agent_uids=["C1"])],
        hops=hops, links=links, identity=[ident_row(h["hop_id"]) for h in hops])


def test_st25_matched_with_both_key_logons_in_the_hop(tmp_path):
    w = _multi(tmp_path, [hop_row("H1", ["T1", "T2"], [0x100, 0x101])])
    r = one(w)
    assert (r["match"], r["hop_id"], r["key_logons_in_hop"]) == ("matched", "H1", "2/2")


def test_st25_key_4624_chosen_by_logon_id_among_several_key_4624s(tmp_path):
    hops = [hop_row("H1", ["T1"], [0x100]), hop_row("H2", ["T2"], [0x101])]
    r1 = one(_multi(tmp_path, hops, key_lid=0x100))
    assert (r1["match"], r1["hop_id"], r1["key_logons_in_hop"]) == ("matched", "H1", "1/2")
    r2 = one(_multi(tmp_path, hops, key_lid=0x101))
    assert (r2["match"], r2["hop_id"], r2["key_logons_in_hop"]) == ("matched", "H2", "1/2")


def test_st25_logon_id_must_equal_even_when_the_uid_is_a_key_target_event(tmp_path):
    # the hop holds the key uid T1 but under another logon ID, and the key's own 4624 (0x100) is in no hop
    r = one(_multi(tmp_path, [hop_row("H1", ["T1"], [0x999]), hop_row("H2", ["T2"], [0x101])]))
    assert r["match"] == "unmatched" and r["hop_id"] == ""


def test_st25_unmatched_row_and_totals_tier(tmp_path):
    w = _multi(tmp_path, [hop_row("H1", ["T2"], [0x101]), hop_row("H2", ["T9"], [0x100])])
    res = run_dev(w)
    r = only_keyed(res)
    assert r["match"] == "unmatched" and r["hop_id"] == ""
    # reading 1: empty hop and verdict columns, identity missing / 0, tier unmatched, protocol group from the key
    for c in ("among_candidates", "rank1", "only_candidate", "session_compare", "best_tier", "key_logons_in_hop"):
        assert r[c] == "", c
    assert (r["identity_value"], r["identity_match"]) == ("missing", "0")
    tot = [t for t in res.total_rows if t["scope"] == "keyed" and t["tier"] == "unmatched"]
    assert len(tot) == 1 and tot[0]["protocol_group"] == "smb"
    assert (tot[0]["key_hops"], tot[0]["matched"]) == ("1", "0")


def test_st25_multiple_match_lists_the_hops(tmp_path):
    w = _multi(tmp_path, [hop_row("H1", ["T1"], [0x100]), hop_row("H2", ["T1", "T2"], [0x100, 0x101])])
    res = run_dev(w)
    r = only_keyed(res)
    assert r["match"] == "multiple"
    assert set(r["hop_id"].split(";")) == {"H1", "H2"}
    assert (r["identity_value"], r["identity_match"]) == ("missing", "0")
    assert r["rank1"] == "" and r["among_candidates"] == ""
    assert res.headline["match_multiple"] == 1


# ================================================================================================ rank-1 verdicts
def test_rank1_correct_and_only(tmp_path):
    r = one(std_world(tmp_path, links=[CMD()]))
    assert (r["match"], r["among_candidates"], r["rank1"], r["only_candidate"]) == ("matched", "1", "correct", "1")
    assert r["session_compare"] == "logon_uid" and r["key_sessions_hex"] == "0x500"


def test_rank1_correct_but_not_only(tmp_path):
    r = one(std_world(tmp_path, links=[CMD(), OTHER(rank=2)], hop_kw={"cand": 2}))
    assert (r["among_candidates"], r["rank1"], r["only_candidate"]) == ("1", "correct", "0")
    assert r["candidate_count"] == "2"


def test_rank1_tied_correct(tmp_path):
    r = one(std_world(tmp_path, links=[link_row("H1", 1, "cmdline_target", 1280, "U500", tie=1, tier="C"),
                                       OTHER(rank=1, tie=1, tier="C")], hop_kw={"cand": 2, "tier": "C"}))
    assert (r["among_candidates"], r["rank1"], r["only_candidate"], r["tie"]) == ("1", "tied_correct", "0", "1")


def test_rank1_wrong_when_the_key_session_is_ranked_second(tmp_path):
    r = one(std_world(tmp_path, links=[link_row("H1", 1, "cmdline_target", 1280, "U500", rank=2), OTHER(rank=1)],
                      hop_kw={"cand": 2}))
    assert (r["among_candidates"], r["rank1"], r["only_candidate"]) == ("1", "wrong", "0")


def test_rank1_wrong_and_not_among_when_the_key_session_is_absent(tmp_path):
    r = one(std_world(tmp_path, links=[OTHER()]))
    assert (r["among_candidates"], r["rank1"], r["only_candidate"]) == ("0", "wrong", "0")


def test_rank1_no_candidate_for_a_target_only_hop(tmp_path):
    r = one(std_world(tmp_path, links=[link_row("H1", 1, "target_only")], hop_kw={"cand": 0, "tier": "D"}))
    assert (r["among_candidates"], r["rank1"], r["only_candidate"]) == ("0", "no_candidate", "0")
    assert r["best_tier"] == "D" and r["target_only_reason"] == "no_evidence_in_range"
    assert r["expected_target_only"] == "0"


def test_a_target_only_row_is_never_a_candidate_session(tmp_path):
    res = run_dev(std_world(tmp_path, links=[link_row("H1", 1, "target_only")], hop_kw={"cand": 0, "tier": "D"}))
    assert res.headline["rank1_no_candidate"] == 1 and res.headline["rank1_correct"] == 0


def test_two_key_sessions_must_all_be_among_the_candidates(tmp_path):
    # no explicit session id: the key sessions are those of the Sysmon 1 agent events, session_id read from the DB
    db = [ev("C2", "Sysmon", 1, host=SRC, off=101.0, session_id=0x600, command_line=sf.PLACEHOLDER_COMMAND)]
    ekeys = {"C2": ek("C2", SRC, "Sysmon", 1, 101.0)}
    kk = {"session_hex": None, "session_evidence": None, "agent_uids": ["C1", "C2"]}
    only_one = one(std_world(tmp_path, key_kw=kk, extra_db=db, event_keys=ekeys, links=[CMD()]))
    assert only_one["key_sessions_hex"] == "0x500;0x600"
    assert (only_one["among_candidates"], only_one["rank1"]) == ("0", "wrong")
    both = one(std_world(tmp_path, key_kw=kk, extra_db=db, event_keys=ekeys, name="r2",
                         links=[CMD(), OTHER(rank=1, tie=1)]))
    assert (both["among_candidates"], both["rank1"], both["only_candidate"]) == ("1", "correct", "1")
    bigger = one(std_world(tmp_path, key_kw=kk, extra_db=db, event_keys=ekeys, name="r3",
                           links=[CMD(), OTHER(rank=1, tie=1), link_row("H1", 3, "source_4648", 1700, "U700", rank=1, tie=1)]))
    assert (bigger["among_candidates"], bigger["rank1"], bigger["only_candidate"]) == ("1", "tied_correct", "0")


def test_key_session_tier_methods_and_rank_are_reported(tmp_path):
    r = one(std_world(tmp_path, links=[link_row("H1", 1, "sysmon3_port", 1280, "U500", tier="A",
                                                methods="sysmon3_port;cmdline_target"),
                                       link_row("H1", 2, "cmdline_target", 1280, "U500", tier="A",
                                                methods="sysmon3_port;cmdline_target")],
                      hop_kw={"tier": "A", "protocol": "winrm"}))
    assert r["key_session_tier"] == "A" and r["key_session_rank"] == "1"
    assert set(r["key_session_methods"].split(";")) == {"sysmon3_port", "cmdline_target"}
    assert r["protocol_group"] == "winrm" and r["candidate_count_port"] == "1" and r["candidate_count_cmd"] == "1"


# ================================================================================================ background key hop
BG = {"session_hex": None, "session_evidence": None, "agent_uids": []}


def test_background_key_hop_target_only_ok(tmp_path):
    res = run_dev(std_world(tmp_path, key_kw=BG, links=[link_row("H1", 1, "target_only")],
                            hop_kw={"cand": 0, "tier": "D"}))
    r = only_keyed(res)
    assert r["expected_target_only"] == "1" and r["target_only_ok"] == "1"
    assert r["among_candidates"] == r["rank1"] == r["only_candidate"] == ""
    assert r["key_sessions_hex"] == "" and r["key_session_uid_source"] == ""
    assert res.headline["background"] == 1 and res.headline["background_target_only_ok"] == 1
    assert res.headline["with_key_session"] == 0


def test_background_key_hop_with_a_session_row_is_not_ok(tmp_path):
    r = one(std_world(tmp_path, key_kw=BG, links=[OTHER()]))
    assert r["expected_target_only"] == "1" and r["target_only_ok"] == "0"


# ================================================================================================ session_compare
def test_compare_logon_uid_same_uid(tmp_path):
    r = one(std_world(tmp_path, links=[CMD()]))
    assert (r["session_compare"], r["rank1"], r["key_session_uid_source"]) == ("logon_uid", "correct", "direct")


def test_compare_logon_uid_same_logon_id_different_uid_is_wrong(tmp_path):
    """The same logon ID reused after a boot: (host, logon ID) would call it correct, the 4624 uid says wrong."""
    r = one(std_world(tmp_path, links=[link_row("H1", 1, "cmdline_target", 1280, "U500_EARLIER_BOOT")]))
    assert r["session_compare"] == "logon_uid"
    assert (r["among_candidates"], r["rank1"], r["only_candidate"]) == ("0", "wrong", "0")


def test_compare_host_logon_id_when_the_stitch_row_has_no_uid(tmp_path):
    r = one(std_world(tmp_path, links=[link_row("H1", 1, "cmdline_target", 1280, "")]))
    assert r["session_compare"] == "host_logon_id"
    assert (r["among_candidates"], r["rank1"], r["only_candidate"]) == ("1", "correct", "1")


def test_compare_host_logon_id_compares_the_host_too(tmp_path):
    r = one(std_world(tmp_path, links=[link_row("H1", 1, "cmdline_target", 1280, "", host="ep-03")]))
    assert r["session_compare"] == "host_logon_id"
    assert (r["among_candidates"], r["rank1"]) == ("0", "wrong")


BOOT_AFTER_COMMAND = [ev("B1", "System", 6005, host=SRC, off=300.0), logon("U500_AGAIN", 500.0, 0x500, host=SRC)]


def test_compare_ambiguous_boot_gives_no_verdict_and_is_counted(tmp_path):
    res = run_dev(std_world(tmp_path, extra_db=BOOT_AFTER_COMMAND,
                            links=[link_row("H1", 1, "cmdline_target", 1280, "")]))
    r = only_keyed(res)
    assert r["session_compare"] == "ambiguous_boot"
    assert (r["among_candidates"], r["rank1"], r["only_candidate"]) == ("", "", "")
    assert res.headline["compare_ambiguous_boot"] == 1 and res.headline["rank1_correct"] == 0
    tot = [t for t in res.total_rows if t["scope"] == "keyed" and t["protocol_group"] == "all"]
    assert tot[0]["compare_ambiguous_boot"] == "1" and tot[0]["compare_logon_uid"] == "0"


def test_two_epochs_are_not_ambiguous_when_both_sides_have_a_uid(tmp_path):
    r = one(std_world(tmp_path, extra_db=BOOT_AFTER_COMMAND, links=[link_row("H1", 1, "cmdline_target", 1280, "U500")]))
    assert (r["session_compare"], r["rank1"]) == ("logon_uid", "correct")


def test_one_epoch_is_enough_for_host_logon_id_even_with_a_second_boot_elsewhere(tmp_path):
    # a boot on ANOTHER host does not make the key host's logon ID ambiguous
    db = [ev("B1", "System", 6005, host="ep-03", off=300.0), logon("X", 500.0, 0x500, host="ep-03")]
    r = one(std_world(tmp_path, extra_db=db, links=[link_row("H1", 1, "cmdline_target", 1280, "")]))
    assert r["session_compare"] == "host_logon_id"


def test_ambiguous_boot_can_come_from_a_hop_without_candidates_only_if_the_key_has_no_uid(tmp_path):
    """Reading 5: a target_only hop is compared by the general rule. Key uid present -> logon_uid -> no_candidate."""
    r = one(std_world(tmp_path, extra_db=BOOT_AFTER_COMMAND, links=[link_row("H1", 1, "target_only")],
                      hop_kw={"cand": 0, "tier": "D"}))
    assert (r["session_compare"], r["rank1"], r["among_candidates"], r["only_candidate"]) == (
        "logon_uid", "no_candidate", "0", "0")


# key session given by its Sysmon 1 agent events (no explicit id) so that the uid comes from the DB lookup
VIA_SYSMON = {"session_hex": None, "session_evidence": None, "agent_uids": ["C1"]}
RESTART = [ev("S1", "System", 6006, host=SRC, off=50.0), ev("S2", "System", 6005, host=SRC, off=60.0)]


def test_key_side_lookup_picks_the_4624_of_the_command_boot_epoch(tmp_path):
    """4624 U500 (10 s) is of the boot before the restart at 50 s; UNEW (70 s) opens the same logon ID after it; the
    key command (100 s) is in the new epoch, so the key uid is UNEW."""
    db = RESTART + [logon("UNEW", 70.0, 0x500, host=SRC)]
    good = one(std_world(tmp_path, key_kw=VIA_SYSMON, extra_db=db, links=[link_row("H1", 1, "cmdline_target", 1280, "UNEW")]))
    assert (good["key_session_uid_source"], good["session_compare"], good["rank1"]) == ("lookup", "logon_uid", "correct")
    bad = one(std_world(tmp_path, key_kw=VIA_SYSMON, extra_db=db, name="r2",
                        links=[link_row("H1", 1, "cmdline_target", 1280, "U500")]))
    assert (bad["session_compare"], bad["among_candidates"], bad["rank1"]) == ("logon_uid", "0", "wrong")


def test_key_side_lookup_never_takes_an_earlier_boot_4624(tmp_path):
    """No 4624 of the logon ID in the command's epoch: the key uid is NOT the earlier boot's 4624."""
    r = one(std_world(tmp_path, key_kw=VIA_SYSMON, extra_db=RESTART, links=[link_row("H1", 1, "cmdline_target", 1280, "U500")]))
    assert r["key_session_uid_source"] == "none"
    assert r["session_compare"] == "host_logon_id"        # one epoch only (the earlier boot)
    assert r["rank1"] == "correct"


def test_key_side_lookup_takes_the_latest_4624_at_or_before_the_command_in_the_epoch(tmp_path):
    db = [logon("U500_B", 60.0, 0x500, host=SRC), logon("U500_LATE", 150.0, 0x500, host=SRC)]   # 150 s is after C1
    r = one(std_world(tmp_path, key_kw=VIA_SYSMON, extra_db=db, links=[link_row("H1", 1, "cmdline_target", 1280, "U500_B")]))
    assert (r["key_session_uid_source"], r["session_compare"], r["rank1"]) == ("lookup", "logon_uid", "correct")


def test_reading3_session_logon_uid_used_only_for_the_same_session_id(tmp_path):
    """session_evidence.session_logon_uid counts when session_evidence.session_id is absent or equals the key session;
    with a different session_id it is not used and the uid comes from the DB lookup."""
    # absent session_id: direct
    r = one(std_world(tmp_path, links=[CMD()], name="a",
                      key_kw={"session_evidence": {"session_logon_uid": "U500"}}))
    assert r["key_session_uid_source"] == "direct"
    # equal session_id: direct (hex spelling may differ in case / padding)
    r = one(std_world(tmp_path, links=[CMD()], name="b",
                      key_kw={"session_evidence": {"session_id": "0x500", "session_logon_uid": "U500"}}))
    assert r["key_session_uid_source"] == "direct"
    # different session_id: the uid belongs to another session -> not used; lookup finds U500 in the DB
    r = one(std_world(tmp_path, links=[CMD()], name="c",
                      key_kw={"session_evidence": {"session_id": "0x600", "session_logon_uid": "U600"}}))
    assert r["key_session_uid_source"] == "lookup" and r["key_sessions_hex"] == "0x500"
    assert (r["session_compare"], r["rank1"]) == ("logon_uid", "correct")      # U500 from the DB, not U600
    # and the wrong uid would have produced a wrong verdict
    r = one(std_world(tmp_path, links=[link_row("H1", 1, "cmdline_target", 1280, "U600")], name="d",
                      key_kw={"session_evidence": {"session_id": "0x600", "session_logon_uid": "U600"}}))
    assert r["rank1"] == "wrong"


def test_reading4_command_event_uids_preferred_over_agent_event_uids(tmp_path):
    """For an explicit key session the command events are session_evidence.command_event_uids when present, else
    agent_event_uids. The reference time (and boot epoch) of the uid lookup follows them."""
    # restart at 50/60 s; 4624 U500 (10 s, old boot); UNEW (70 s, new boot). C1 (agent) at 100 s is in the new boot;
    # CE (command) at 30 s is in the old boot.
    db = RESTART + [logon("UNEW", 70.0, 0x500, host=SRC),
                    ev("CE", "Sysmon", 1, host=SRC, off=30.0, session_id=0x500, command_line=sf.PLACEHOLDER_COMMAND)]
    ekeys = {"CE": ek("CE", SRC, "Sysmon", 1, 30.0)}
    explicit = {"session_hex": "0x500", "session_evidence": None, "agent_uids": ["C1"]}
    # agent_event_uids only: reference 100 s, new epoch -> UNEW
    a = one(std_world(tmp_path, key_kw=explicit, extra_db=db, event_keys=ekeys, name="a",
                      links=[link_row("H1", 1, "cmdline_target", 1280, "UNEW")]))
    assert (a["key_session_uid_source"], a["rank1"]) == ("lookup", "correct")
    # command_event_uids present: reference 30 s, old epoch -> U500 (UNEW would be wrong)
    kw = {**explicit, "session_evidence": {"command_event_uids": ["CE"]}}
    b = one(std_world(tmp_path, key_kw=kw, extra_db=db, event_keys=ekeys, name="b",
                      links=[link_row("H1", 1, "cmdline_target", 1280, "U500")]))
    assert (b["key_session_uid_source"], b["session_compare"], b["rank1"]) == ("lookup", "logon_uid", "correct")
    c = one(std_world(tmp_path, key_kw=kw, extra_db=db, event_keys=ekeys, name="c",
                      links=[link_row("H1", 1, "cmdline_target", 1280, "UNEW")]))
    assert (c["among_candidates"], c["rank1"]) == ("0", "wrong")


def test_reading4_only_command_events_on_the_source_host_count(tmp_path):
    """A command event that event_keys places on another host is ignored; the next one is used."""
    db = RESTART + [logon("UNEW", 70.0, 0x500, host=SRC),
                    ev("CX", "Sysmon", 1, host=DST, off=30.0, session_id=0x500, command_line=sf.PLACEHOLDER_COMMAND)]
    ekeys = {"CX": ek("CX", DST, "Sysmon", 1, 30.0)}
    kw = {"session_hex": "0x500", "session_evidence": {"command_event_uids": ["CX", "C1"]}, "agent_uids": []}
    r = one(std_world(tmp_path, key_kw=kw, extra_db=db, event_keys=ekeys,
                      links=[link_row("H1", 1, "cmdline_target", 1280, "UNEW")]))
    assert (r["key_session_uid_source"], r["rank1"]) == ("lookup", "correct")      # reference = C1 at 100 s


def _boot_world(tmp_path, bgs, name):
    """Two startup events 100 s apart (6005 at 1000 s, 41 at 1100 s); a 4624 of logon ID 0x500 between them (1050 s);
    the key command at 1200 s; the candidate carries the between-startups uid."""
    db = [ev("B1", "System", 6005, host=SRC, off=1000.0), ev("B2", "System", 41, host=SRC, off=1100.0),
          logon("UB", 1050.0, 0x500, host=SRC),
          ev("C2", "Sysmon", 1, host=SRC, off=1200.0, session_id=0x500, command_line=sf.PLACEHOLDER_COMMAND)]
    return std_world(tmp_path, name=name, boot_group_s=bgs, extra_db=db,
                     key_kw={"session_hex": None, "session_evidence": None, "agent_uids": ["C2"]},
                     event_keys={"C2": ek("C2", SRC, "Sysmon", 1, 1200.0)},
                     links=[link_row("H1", 1, "cmdline_target", 1280, "UB")])


def test_boot_grouping_follows_run_info_boot_group_s_one_restart_at_120(tmp_path):
    r = one(_boot_world(tmp_path, 120.0, "w120"))
    assert (r["key_session_uid_source"], r["session_compare"], r["rank1"]) == ("lookup", "logon_uid", "correct")


def test_boot_grouping_follows_run_info_boot_group_s_two_restarts_at_60(tmp_path):
    r = one(_boot_world(tmp_path, 60.0, "w60"))
    # two boundaries (1000 s and 1100 s): the command at 1200 s is in a third epoch with no 4624 of the logon ID
    assert r["key_session_uid_source"] == "none"
    assert r["session_compare"] == "ambiguous_boot"
    assert r["rank1"] == "" and r["among_candidates"] == ""


@pytest.mark.parametrize("t, expected", [
    (1005.0, "host_logon_id"),    # before the shutdown group's last event: still the old boot (one epoch)
    (1010.0, "ambiguous_boot"),   # at the boundary instant: the new boot
    (1050.0, "ambiguous_boot"),   # after the last shutdown event, before the startup group: the new boot
    (1105.0, "ambiguous_boot"),
])
def test_clean_restart_has_one_boundary_at_the_shutdown_groups_last_event(tmp_path, t, expected):
    db = [ev("D1x", "System", 6006, host=SRC, off=1000.0), ev("D2x", "System", 1074, host=SRC, off=1010.0),
          ev("D3x", "System", 41, host=SRC, off=1100.0), ev("D4x", "System", 6005, host=SRC, off=1130.0),
          logon("U500_NEWBOOT", t, 0x500, host=SRC)]
    r = one(std_world(tmp_path, extra_db=db, links=[link_row("H1", 1, "cmdline_target", 1280, "")]))
    assert r["session_compare"] == expected


@pytest.mark.parametrize("t, expected", [(999.0, "host_logon_id"), (1000.0, "ambiguous_boot"), (1100.0, "ambiguous_boot")])
def test_startup_group_without_shutdown_starts_its_epoch_at_its_first_event(tmp_path, t, expected):
    db = [ev("S1x", "System", 41, host=SRC, off=1000.0), ev("S2x", "System", 6005, host=SRC, off=1030.0),
          logon("U500_NEWBOOT", t, 0x500, host=SRC)]
    r = one(std_world(tmp_path, extra_db=db, links=[link_row("H1", 1, "cmdline_target", 1280, "")]))
    assert r["session_compare"] == expected


def test_a_shutdown_and_startup_far_apart_make_two_boundaries(tmp_path):
    # shutdown at 1000 s, startup at 1500 s (500 s > 120 s is still a different kind, so the startup group is its own
    # group right after a shutdown group: no extra boundary). A 4624 at 1200 s (between them) is in the new epoch.
    db = [ev("D1x", "System", 6006, host=SRC, off=1000.0), ev("D3x", "System", 41, host=SRC, off=1500.0),
          logon("U500_NEWBOOT", 1200.0, 0x500, host=SRC)]
    r = one(std_world(tmp_path, extra_db=db, links=[link_row("H1", 1, "cmdline_target", 1280, "")]))
    assert r["session_compare"] == "ambiguous_boot"


# ================================================================================================ identity
OPEN = dict(dump="D1", open_uids="X1")


def idv(tmp_path, rows, name="r", expected=1, **kw):
    return one(std_world(tmp_path, name=name, links=[CMD()], identity=rows, key_kw={"expected": expected, **kw}))


@pytest.mark.parametrize("rows, value", [
    ([ident_row("H1", **OPEN)], "1"),                                                     # one decider, all variants
    ([ident_row("H1")], "0"),                                                             # no LSASS read on the host
    ([ident_row("H1", dump="D1", open_uids="X1", order_ok=0, gap_ms=-9000)], "0"),        # dump after the move
    ([ident_row("H1", dump="D1", open_uids="")], "0"),                                    # read, but no open session
    ([ident_row("H1", dump="D1", dump_account="LAB\\other_user", open_uids="X1"),
      ident_row("H1", dump="D2", open_uids="X2", gap_ms=5000)], "1"),                    # two non-system deciders
])
def test_identity_value_all_six_variants_agree(tmp_path, rows, value):
    r = idv(tmp_path, rows)
    assert r["identity_value"] == value
    assert r["identity_match"] == ("1" if value == "1" else "0")


@pytest.mark.parametrize("rows", [
    # SYSTEM read decides under 'all' only
    [ident_row("H1", dump="D1", dump_account="SYSTEM", open_uids="X1")],
    # machine account read
    [ident_row("H1", dump="D1", dump_account="DC01$", open_uids="X1")],
    # end_unknown session decides only when counted
    [ident_row("H1", dump="D1", open_uids="", end_unknown="E1")],
    # key_rule takes the nearest read (no open session); 'all' and 'nonsystem' find the far one that has one
    [ident_row("H1", dump="D1", open_uids="X1", gap_ms=600000), ident_row("H1", dump="D2", open_uids="", gap_ms=10000)],
])
def test_identity_variants_that_differ_are_q9_dependent(tmp_path, rows):
    res = run_dev(std_world(tmp_path, links=[CMD()], identity=rows))
    r = only_keyed(res)
    assert r["identity_value"] == "q9_dependent" and r["identity_match"] == "q9_dependent"
    assert res.headline["identity_q9_dependent"] == 1 and res.headline["identity_match"] == 0


def test_identity_key_rule_nearest_read_with_open_session_decides_in_every_variant(tmp_path):
    rows = [ident_row("H1", dump="D1", open_uids="", gap_ms=600000), ident_row("H1", dump="D2", open_uids="X2", gap_ms=10000)]
    assert idv(tmp_path, rows)["identity_value"] == "1"


def test_identity_match_compares_with_the_key_expected_value(tmp_path):
    assert idv(tmp_path, [ident_row("H1", **OPEN)], "a", expected=1)["identity_match"] == "1"
    assert idv(tmp_path, [ident_row("H1", **OPEN)], "b", expected=0)["identity_match"] == "0"
    assert idv(tmp_path, [ident_row("H1")], "c", expected=0)["identity_match"] == "1"
    assert idv(tmp_path, [ident_row("H1")], "d", expected=1)["identity_match"] == "0"
    r = idv(tmp_path, [ident_row("H1")], "e", expected=0)
    assert r["identity_expected"] == "0"


def test_identity_mixed_account_hop_uses_the_key_accounts_rows(tmp_path):
    rows = [ident_row("H1", "acct_a", **OPEN), ident_row("H1", "acct_b")]
    hop_kw = {"member_accounts": "acct_a;acct_b", "mixed_account": 1}
    a = one(std_world(tmp_path, links=[CMD()], identity=rows, hop_kw=hop_kw, key_kw={"account": "Acct_A"}, name="ra"))
    b = one(std_world(tmp_path, links=[CMD()], identity=rows, hop_kw=hop_kw, key_kw={"account": "ACCT_B"}, name="rb"))
    assert (a["identity_value"], b["identity_value"]) == ("1", "0")
    assert (a["key_account"], b["key_account"]) == ("acct_a", "acct_b")        # lower-cased (reading 8)


def test_identity_not_applicable_row(tmp_path):
    r = idv(tmp_path, [ident_row("H1", na="source_host_unknown")])
    assert r["identity_value"] == "" and r["identity_not_applicable"] == "source_host_unknown"
    assert r["identity_match"] == "0"                                         # reading 7


def test_identity_missing_rows(tmp_path):
    for i, rows in enumerate(([], [ident_row("H1", "someone_else", **OPEN)])):
        r = idv(tmp_path, rows, f"m{i}")
        assert r["identity_value"] == "missing" and r["identity_match"] == "0"


def test_identity_order_flags_and_deciding_dumps(tmp_path):
    r = idv(tmp_path, [ident_row("H1", dump="D1", open_uids="X1", tol=1, unc=0),
                       ident_row("H1", dump="D2", open_uids="X2", tol=0, unc=1, gap_ms=9000)])
    assert (r["identity_order_within_tolerance"], r["identity_order_within_uncertainty"]) == ("1", "1")
    assert r["identity_deciding_dump_uids"] == "D1;D2"
    none = idv(tmp_path, [ident_row("H1")], "n")
    assert (none["identity_order_within_tolerance"], none["identity_order_within_uncertainty"]) == ("", "")
    assert none["identity_deciding_dump_uids"] == ""


# ================================================================================================ port_cmd_agree
def pc(tmp_path, links, name="r", **hop):
    res = run_dev(std_world(tmp_path, name=name, links=links, hop_kw={"protocol": "winrm", **hop}))
    return res, only_keyed(res)


def test_port_cmd_agree_yes(tmp_path):
    both = "sysmon3_port;cmdline_target"
    res, r = pc(tmp_path, [link_row("H1", 1, "sysmon3_port", 1280, "U500", tier="A", methods=both),
                           link_row("H1", 2, "cmdline_target", 1280, "U500", tier="A", methods=both)])
    assert r["port_cmd_agree"] == "yes" and res.fact_rows[0]["port_cmd_agree"] == "yes"
    tot = [t for t in res.total_rows if t["scope"] == "all_hops" and t["protocol_group"] == "all"][0]
    assert (tot["port_cmd_both"], tot["port_cmd_agree"]) == ("1", "1")


def test_port_cmd_agree_no(tmp_path):
    res, r = pc(tmp_path, [link_row("H1", 1, "sysmon3_port", 1280, "U500", tier="C", methods="sysmon3_port"),
                           link_row("H1", 2, "cmdline_target", 1536, "U600", tier="C", methods="cmdline_target")],
                cand=2)
    assert r["port_cmd_agree"] == "no"
    tot = [t for t in res.total_rows if t["scope"] == "all_hops" and t["protocol_group"] == "all"][0]
    assert (tot["port_cmd_both"], tot["port_cmd_agree"]) == ("1", "0")


def test_port_cmd_agree_n_a_when_one_method_is_missing(tmp_path):
    _, a = pc(tmp_path, [link_row("H1", 1, "sysmon3_port", 1280, "U500", tier="A")], name="a")
    _, b = pc(tmp_path, [link_row("H1", 1, "source_4648", 1280, "U500"), link_row("H1", 2, "cmdline_target", 1280, "U500")], name="b")
    _, c = pc(tmp_path, [link_row("H1", 1, "target_only")], name="c", cand=0, tier="D")
    assert (a["port_cmd_agree"], b["port_cmd_agree"], c["port_cmd_agree"]) == ("n_a", "n_a", "n_a")


# ================================================================================================ totals and groups
@pytest.mark.parametrize("protocol, group", [("smb", "smb"), ("smb_service", "smb"), ("winrm", "winrm"),
                                              ("rdp", "rdp"), ("none", "none")])
def test_protocol_group_smb_service_is_smb(tmp_path, protocol, group):
    res = run_dev(std_world(tmp_path, links=[CMD()], hop_kw={"protocol": protocol}))
    r = only_keyed(res)
    assert r["protocol_group"] == group and r["protocol"] == protocol
    tot = [t for t in res.total_rows if t["scope"] == "keyed" and t["protocol_group"] == group]
    assert len(tot) == 1 and tot[0]["tier"] == "B" and tot[0]["key_hops"] == "1"


def test_totals_have_an_all_row_per_scope(tmp_path):
    res = run_dev(std_world(tmp_path, links=[CMD()]))
    for scope in ("keyed", "all_hops", "user_e2e_hops"):
        assert [t for t in res.total_rows if t["scope"] == scope and t["protocol_group"] == "all" and t["tier"] == "all"]


# ================================================================================================ unkeyed trial
def _unkeyed_world(tmp_path):
    hops = [hop_row("H1", ["T1"], [TARGET_LID]), hop_row("H2", ["T2"], [0x101], tier="D", cand=0)]
    links = [link_row("H1", 1, "cmdline_target", 1280, "U500"), link_row("H2", 1, "target_only")]
    w = fx.build_world(tmp_path, trial="s02_t01", db_rows=fx.std_db(), hops=hops, links=links,
                       identity=[ident_row("H1", **OPEN), ident_row("H2")], write_key=False)
    # a DRAFT key that would match both hops: it must never be read
    draft = w.repo / "ground_truth" / "drafts" / "s02_t01.yaml"
    draft.parent.mkdir(parents=True, exist_ok=True)
    draft.write_text(json.dumps({"trial_id": "s02_t01", "db_sha256": "0" * 64, "event_keys": fx.std_event_keys(),
                                 "hops": [key_hop("k1", target_uids=["T1"], target_lid=TARGET_LID, session_hex="0x500",
                                                  agent_uids=["C1"])]}), encoding="utf-8")
    return w


def test_unkeyed_trial_writes_facts_and_totals_without_verdicts(tmp_path):
    w = _unkeyed_world(tmp_path)
    out = tmp_path / "out"
    assert cli(w, out) == 0
    names = {p.name for p in out.iterdir()}
    assert KEYED not in names and FACTS in names and TOTALS in names
    facts = read_csv(out / FACTS)
    assert [r["hop_id"] for r in facts] == ["H1", "H2"]
    for c in ("among_candidates", "rank1", "only_candidate", "target_only_ok", "identity_match", "match",
              "expected_target_only"):
        assert c not in facts[0], c
    totals = read_csv(out / TOTALS)
    assert {t["scope"] for t in totals} == {"all_hops", "user_e2e_hops"}
    assert next(t for t in totals if t["scope"] == "all_hops" and t["protocol_group"] == "all")["hops"] == "2"
    assert all(r["split"] == "development" for r in facts + totals)
    assert json.loads((out / RUN_INFO).read_text(encoding="utf-8")).get("inputs", {}).get("key") in (None, {})
    assert "no approved key" in (out / MD).read_text(encoding="utf-8").lower()


def test_unkeyed_trial_result_has_no_keyed_rows(tmp_path):
    res = run_dev(_unkeyed_world(tmp_path))
    assert res.keyed_rows is None and len(res.fact_rows) == 2
    assert KEYED not in res.files and fx.sf is sf


def test_a_draft_key_is_never_read_even_when_it_is_the_only_key(tmp_path):
    w = _unkeyed_world(tmp_path)
    # a corrupt draft would raise if read
    (w.repo / "ground_truth" / "drafts" / "s02_t01.yaml").write_text("NOT JSON {{{", encoding="utf-8")
    assert run_dev(w).keyed_rows is None


def test_a_key_outside_approved_is_not_read(tmp_path):
    w = std_world(tmp_path, links=[CMD()], trial="s02_t01", key_dir="drafts")
    assert run_dev(w).keyed_rows is None


# ================================================================================================ labels
def test_labels_header_sentences_and_wording(tmp_path):
    w = std_world(tmp_path, links=[CMD()])
    out = tmp_path / "out"
    assert cli(w, out) == 0
    for p in out.glob("*.csv"):
        rows = read_csv(p)
        assert rows and all(r["split"] == "development" for r in rows), p.name
    md = out / MD
    text = md.read_text(encoding="utf-8")
    assert text.splitlines()[0] == "# DEVELOPMENT — not a result (decision 019)"
    low = " ".join(text.lower().split())
    assert "winrm tier a" in low and "apart" in low                     # tier A reported apart from tier B
    assert "tier b on smb is agreement" in low and "not accuracy" in low
    for bad in ("detects", "reduces false positives", "identifies the attacker", "detect stolen"):
        assert bad not in low, bad
    summary = json.loads((out / "link_accuracy.json").read_text(encoding="utf-8"))
    assert summary["split"] == "development"


def test_test_split_is_labelled_test_not_development(tmp_path):
    w = std_world(tmp_path, links=[CMD()], trial="s02_t05")
    _write_lock(w)
    res = evaluate_trial(w.repo, w.trial, "test", w.stitch_dir)
    assert all(r["split"] == "test" for r in res.keyed_rows + res.fact_rows + res.total_rows)
    first = res.files["link_accuracy.md"].splitlines()[0]
    assert "DEVELOPMENT" not in first


def test_account_text_is_in_the_csv_only_never_in_the_md(tmp_path):
    w = std_world(tmp_path, links=[CMD()], key_kw={"account": "acct_zq_distinct"},
                  identity=[ident_row("H1", "acct_zq_distinct", **OPEN)])
    out = tmp_path / "out"
    assert cli(w, out) == 0
    assert "acct_zq_distinct" in (out / KEYED).read_text(encoding="utf-8")
    assert "acct_zq_distinct" not in (out / MD).read_text(encoding="utf-8").lower()


# ================================================================================================ refusals
def _snap(root: Path) -> dict:
    return sf.snapshot(root)


def _refused(w, tmp_path, capsys, match=None, trial=None):
    before = _snap(tmp_path)
    out = tmp_path / "outdir" / "ev"
    capsys.readouterr()
    code = cli(w, out, trial=trial)
    err = capsys.readouterr().err
    assert code == 2, err
    assert "refused" in err.lower()
    if match:
        assert re.search(match, err, re.I), err
    assert not out.exists() and not (out.parent / f".{out.name}.tmp").exists()
    assert not (tmp_path / "outdir").exists()
    assert _snap(tmp_path) == before                     # nothing created, removed or changed anywhere


def test_refuses_a_missing_stitch_file_and_writes_nothing(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()])
    (w.stitch_dir / "links.csv").unlink()
    _refused(w, tmp_path, capsys, "links.csv")


def test_refuses_an_edited_stitch_file(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()])
    with open(w.stitch_dir / "hops.csv", "a", encoding="utf-8") as fh:
        fh.write("\n")
    _refused(w, tmp_path, capsys, "hops.csv")


def test_refuses_when_run_info_is_missing(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()])
    (w.stitch_dir / "run_info.json").unlink()
    _refused(w, tmp_path, capsys, "run_info")


def test_refuses_db_sha_different_from_run_info(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()], run_info_db_sha="0" * 64)
    _refused(w, tmp_path, capsys, "sha")


def test_refuses_a_db_changed_after_the_stitch_run(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()])
    sf.write_events_db(w.db, fx.std_db() + [logon("LATER", 900.0, 0x777, host=SRC)])
    _refused(w, tmp_path, capsys, "sha")


def test_refuses_key_db_sha_mismatch(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()], key_db_sha="1" * 64)
    _refused(w, tmp_path, capsys, "db_sha256|sha")


def test_refuses_key_of_another_trial(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()], key_trial="s03_t00")
    _refused(w, tmp_path, capsys, "trial")


def test_refuses_stitch_run_info_of_another_trial(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()], run_info_trial="s03_t00")
    _refused(w, tmp_path, capsys, "trial")


def test_refuses_run_info_without_boot_group_s(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()], boot_group_s=None)
    _refused(w, tmp_path, capsys, "boot_group_s")


def test_refuses_a_protocol_outside_the_st22_vocabulary(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()], hop_kw={"protocol": "kerberos"})
    _refused(w, tmp_path, capsys, "protocol")


def test_refusal_leaves_an_existing_output_folder_untouched(tmp_path, capsys):
    w = std_world(tmp_path, links=[CMD()])
    out = tmp_path / "outdir" / "ev"
    out.mkdir(parents=True)
    (out / "old.txt").write_text("old", encoding="utf-8")
    (w.stitch_dir / "links.csv").unlink()
    before = _snap(tmp_path)
    assert cli(w, out) == 2
    assert _snap(tmp_path) == before


def test_evaluate_trial_raises_eval_error_and_the_error_is_public(tmp_path):
    w = std_world(tmp_path, links=[CMD()], key_trial="s03_t00")
    with pytest.raises(EvalError):
        run_dev(w)
    assert evaluate.EvalError is EvalError


@pytest.mark.parametrize("trial, reason", [("s02_t02", "not a development trial"), ("s07_t10", "not a development trial"),
                                           ("s01_t00", "not a development trial"),
                                           ("s2_t0", "malformed"), ("S02_T00", "malformed"), ("../../etc", "malformed"),
                                           ("s02_t00x", "malformed"), ("s02_t00;ls", "malformed")])
def test_cli_allowlist_refuses_before_any_file_access(tmp_path, capsys, trial, reason):
    ghost = tmp_path / "does_not_exist"
    out = tmp_path / "ghost_out"
    code = em.main(["--trial", trial, "--repo", str(ghost), "--stitch-dir", str(ghost / "s"), "--out", str(out)])
    err = capsys.readouterr().err
    assert code == 2 and reason in err
    assert not ghost.exists() and not out.exists()
    assert list(tmp_path.iterdir()) == []


def test_cli_development_refuses_stitch_dir_and_out(tmp_path, capsys):
    code = em.main(["--development", "--repo", str(tmp_path), "--out", str(tmp_path / "o")])
    assert code == 2 and not (tmp_path / "o").exists()


# ================================================================================================ key lock
def _manifest(w, rows, header="trial_id,key_path,sha256", bom=False):
    p = w.repo / "ground_truth" / "key_lock.csv"
    p.parent.mkdir(parents=True, exist_ok=True)
    text = header + "\n" + "".join(",".join(r) + "\n" for r in rows)
    p.write_bytes((b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8"))
    return p


def _write_lock(w, sha=None):
    return _manifest(w, [[w.trial, f"ground_truth/approved/{w.trial}.yaml", sha or w.key_sha]])


def _test_world(tmp_path):
    return std_world(tmp_path, links=[CMD()], trial="s02_t05")


def run_test_split(w):
    return evaluate_trial(w.repo, w.trial, "test", w.stitch_dir)


def test_key_lock_accepts_a_listed_matching_key(tmp_path):
    w = _test_world(tmp_path)
    _write_lock(w)
    res = run_test_split(w)
    assert key_info(res.run_info)["lock"] == "locked"
    assert key_info(res.run_info)["sha256"] == w.key_sha
    assert only_keyed(res)["rank1"] == "correct"


def test_key_lock_refuses_a_missing_manifest(tmp_path):
    w = _test_world(tmp_path)
    with pytest.raises(EvalError):
        run_test_split(w)
    assert not (w.repo / "ground_truth" / "key_lock.csv").exists()          # code never creates the manifest


def test_key_lock_refuses_a_wrong_header(tmp_path):
    w = _test_world(tmp_path)
    _manifest(w, [[w.trial, "k", w.key_sha]], header="trial,path,hash")
    with pytest.raises(EvalError):
        run_test_split(w)


def test_key_lock_refuses_a_bom_header(tmp_path):
    w = _test_world(tmp_path)
    _manifest(w, [[w.trial, "k", w.key_sha]], bom=True)
    with pytest.raises(EvalError):
        run_test_split(w)


def test_key_lock_refuses_a_trial_that_is_not_listed(tmp_path):
    w = _test_world(tmp_path)
    _manifest(w, [["s02_t06", "k", w.key_sha]])
    with pytest.raises(EvalError):
        run_test_split(w)


def test_key_lock_refuses_two_rows_for_the_trial(tmp_path):
    w = _test_world(tmp_path)
    _manifest(w, [[w.trial, "k", w.key_sha], [w.trial, "k", w.key_sha]])
    with pytest.raises(EvalError):
        run_test_split(w)


def test_key_lock_refuses_a_sha_that_differs(tmp_path):
    w = _test_world(tmp_path)
    _write_lock(w, sha="a" * 64)
    with pytest.raises(EvalError):
        run_test_split(w)


def test_key_lock_refuses_a_key_edited_after_locking(tmp_path):
    w = _test_world(tmp_path)
    _write_lock(w)
    with open(w.key_path, "a", encoding="utf-8") as fh:
        fh.write("\n")
    with pytest.raises(EvalError):
        run_test_split(w)


def test_key_lock_refuses_a_missing_test_key(tmp_path):
    w = std_world(tmp_path, links=[CMD()], trial="s02_t05", write_key=False)
    _manifest(w, [[w.trial, "k", "b" * 64]])
    with pytest.raises(EvalError):
        run_test_split(w)


def test_key_lock_not_required_for_development_and_a_wrong_manifest_is_ignored(tmp_path):
    w = std_world(tmp_path, links=[CMD()])
    res = run_dev(w)
    info = key_info(res.run_info)
    assert info["lock"] == "not_required" and info["sha256"] == w.key_sha
    assert info["path"].endswith(f"ground_truth/approved/{w.trial}.yaml")
    assert not (w.repo / "ground_truth" / "key_lock.csv").exists()
    _manifest(w, [["s99_t99", "k", "c" * 64]], header="garbage,header")
    assert key_info(run_dev(w).run_info)["lock"] == "not_required"


def test_key_lock_wrong_sha_in_manifest_does_not_matter_for_development(tmp_path):
    w = std_world(tmp_path, links=[CMD()])
    _write_lock(w, sha="d" * 64)
    assert only_keyed(run_dev(w))["rank1"] == "correct"


def test_test_split_refusal_writes_nothing_through_the_core(tmp_path):
    w = _test_world(tmp_path)
    before = _snap(tmp_path)
    with pytest.raises(EvalError):
        run_test_split(w)
    assert _snap(tmp_path) == before


# ================================================================================================ determinism
def test_two_runs_are_byte_identical_except_run_info(tmp_path):
    w = std_world(tmp_path, links=[CMD(), OTHER(rank=2)], hop_kw={"cand": 2})
    a, b = tmp_path / "a", tmp_path / "b"
    assert cli(w, a) == 0 and cli(w, b) == 0
    names = sorted(p.name for p in a.iterdir())
    assert names == sorted(p.name for p in b.iterdir()) and RUN_INFO in names
    for n in names:
        if n != RUN_INFO:
            assert (a / n).read_bytes() == (b / n).read_bytes(), n
    ia, ib = (json.loads((d / RUN_INFO).read_text(encoding="utf-8")) for d in (a, b))
    ia.pop("generated_utc", None), ib.pop("generated_utc", None)
    assert ia == ib


def test_run_info_records_the_hashes_of_the_other_files(tmp_path):
    import hashlib
    w = std_world(tmp_path, links=[CMD()])
    out = tmp_path / "o"
    assert cli(w, out) == 0
    info = json.loads((out / RUN_INFO).read_text(encoding="utf-8"))
    files = info["files"]
    assert set(files) == {p.name for p in out.iterdir()} - {RUN_INFO}
    for n, f in files.items():
        assert hashlib.sha256((out / n).read_bytes()).hexdigest() == f["sha256"], n


def test_the_db_and_the_inputs_are_unchanged_by_a_run(tmp_path):
    w = std_world(tmp_path, links=[CMD()])
    before = {k: v for k, v in _snap(w.repo).items()}
    run_dev(w)
    assert _snap(w.repo) == before


# ================================================================================================ isolation
def _py_files(pkg: str) -> list[Path]:
    return sorted((REPO / "src" / pkg).rglob("*.py"))


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_src_evaluate_has_files_and_imports_nothing_from_stitch():
    files = _py_files("evaluate")
    assert len(files) >= 5
    for f in files:
        assert "stitch" not in _imported_roots(f), f.name
        text = f.read_text(encoding="utf-8")
        assert not re.search(r"^\s*(from|import)\s+stitch\b", text, re.M), f.name


def test_src_stitch_imports_nothing_from_evaluate():
    files = _py_files("stitch")
    assert len(files) >= 10
    for f in files:
        assert "evaluate" not in _imported_roots(f), f.name
        assert not re.search(r"^\s*(from|import)\s+evaluate\b", f.read_text(encoding="utf-8"), re.M), f.name


def test_src_stitch_never_mentions_ground_truth():
    for f in _py_files("stitch"):
        assert "ground_truth" not in f.read_text(encoding="utf-8"), f.name


def test_src_evaluate_never_selects_command_text_or_field_json():
    """No SQL string of src/evaluate names `command_line` or `field_values_json`."""
    seen_sql = 0
    for f in _py_files("evaluate"):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            strings: list[str] = []
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                strings = [node.value]
            elif isinstance(node, ast.JoinedStr):
                strings = ["".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))]
            for s in strings:
                if re.search(r"\bselect\b", s, re.I) and re.search(r"\bfrom\b", s, re.I):
                    seen_sql += 1
                    assert "command_line" not in s and "field_values_json" not in s, f.name
                    assert not re.search(r"select\s+\*", s, re.I), f.name
    assert seen_sql >= 1


def test_src_evaluate_opens_the_db_read_only():
    text = "\n".join(f.read_text(encoding="utf-8") for f in _py_files("evaluate"))
    assert "mode=ro" in text


# ================================================================================================ no command text in outputs
def test_outputs_hold_no_twelve_character_piece_of_any_command_line(tmp_path):
    cmds = ["XQZ-DISTINCT-cmd --secret-flag value-9876543210 //zzz-top-unique.example",
            "powershell -NoProfile -Command Invoke-UniqueMarkerCommandQQQ 'abcdefghijklmnopqrstuvwxyz'"]
    extra = [ev("C4688", "Security", 4688, host=SRC, off=101.0, command_line=cmds[1], subject_logon_id=0x500)]
    w = fx.build_world(
        tmp_path, db_rows=fx.std_db(extra, command=cmds[0]), event_keys=fx.std_event_keys(),
        key_hops=[key_hop("k1", target_uids=["T1"], target_lid=TARGET_LID, session_hex="0x500", agent_uids=["C1"],
                          agent_command=cmds[0], agent_commands=cmds)],
        hops=[hop_row("H1", ["T1"], [TARGET_LID])], links=[CMD()], identity=[ident_row("H1", **OPEN)])
    out = tmp_path / "out"
    assert cli(w, out) == 0
    grams = sf.command_grams(cmds)
    assert grams
    for p in sorted(out.iterdir()):
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
            assert sf.non_exempt_hits(line, grams) == [], f"{p.name}:{i + 1}"


# ================================================================================================ --development
def _dev_repo(tmp_path, break_last=False):
    """All nine development trials in one fake repo: six keyed t00 trials, three t01 trials without a key."""
    trials = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00", "s02_t01", "s03_t01", "s06_t01"]
    worlds = []
    for t in trials:
        keyed = t.endswith("_t00")
        worlds.append(std_world(tmp_path, trial=t, links=[CMD()], write_key=keyed))
        if keyed:
            kp = worlds[-1].key_path
            data = json.loads(kp.read_text(encoding="utf-8"))
            assert data["trial_id"] == t
    if break_last:
        (worlds[-1].stitch_dir / "links.csv").unlink()
    return worlds[0].repo


def test_development_mode_writes_every_trial_and_a_summary(tmp_path):
    repo = _dev_repo(tmp_path)
    assert em.main(["--development", "--repo", str(repo)]) == 0
    root = repo / "out" / "evaluate"
    folders = {p.name for p in root.iterdir()}
    assert {"s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00", "s02_t01", "s03_t01", "s06_t01",
            "development"} <= folders
    assert (root / "s02_t00" / KEYED).is_file() and not (root / "s02_t01" / KEYED).exists()
    summ = root / "development"
    rows = read_csv(summ / "link_accuracy_summary.csv")
    kinds = {r["row_kind"] for r in rows}
    assert kinds == {"hop", "total"}
    hop_rows = [r for r in rows if r["row_kind"] == "hop"]
    assert len(hop_rows) == 6 and all(r["split"] == "development" for r in rows)
    assert all(r["trial_id"] == "all" for r in rows if r["row_kind"] == "total")
    top = (summ / "link_accuracy_summary.md").read_text(encoding="utf-8").splitlines()[0]
    assert top == "# DEVELOPMENT — not a result (decision 019)"
    assert (summ / RUN_INFO).is_file()


def test_development_mode_one_refused_trial_writes_nothing(tmp_path, capsys):
    repo = _dev_repo(tmp_path, break_last=True)
    before = _snap(tmp_path)
    assert em.main(["--development", "--repo", str(repo)]) == 2
    assert "refused" in capsys.readouterr().err.lower()
    assert not (repo / "out" / "evaluate").exists()
    assert _snap(tmp_path) == before
