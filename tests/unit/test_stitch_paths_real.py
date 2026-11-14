"""Real-data acceptance for T7.5 (spec 03_stitch ST-04, ST-23, ST-70..ST-74, STA-01, STA-09, STT-14 and sections 10.7;
decision 050) on the nine development trials. Slow; parametrised over `clock_offset.params.DEVELOPMENT_TRIALS` only,
never t02-t10.

Written from the spec, decision 050 and the approved t00 keys, not from the implementation. The keys are read by the
tests only (`src/stitch` never opens them). A key hop is matched to the stitch hop whose member 4624 uid is one of the
key hop's `target_event_uids` (ST-25), through the `member_logon_uids` column of `hops.csv`.

Writes: only through `stitch.__main__.main`, into `out/stitch/<development trial>/` (pipeline output, allowed). Nothing
under `out/stitch_check/` is ever written; it is read as the T7.4 baseline. Assertion messages carry counts, hop ids
and uids only, never command text.
"""
from __future__ import annotations

import csv
import functools
import hashlib
import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from answer_key.db import sha256_file  # noqa: E402
from clock_offset import params as co_params  # noqa: E402
from stitch import __main__ as stitch_main  # noqa: E402
from stitch import check_index as ci  # noqa: E402
from stitch import check_links as cl  # noqa: E402
from stitch.inputs import trial_paths  # noqa: E402
from stitch.links import run_links  # noqa: E402

pytestmark = pytest.mark.slow

DEV = list(co_params.DEVELOPMENT_TRIALS)
DEV_T00 = [t for t in DEV if t.endswith("_t00")]
APPROVED = REPO / "ground_truth" / "approved"
CHECK_REL = Path("out") / "stitch_check"
TEN_FILES = ["hop_artefacts.csv", "hop_identity.csv", "hops.csv", "links.csv", "path_edges.csv", "path_nodes.csv",
             "paths.csv", "report.md", "run_info.json", "stats.json"]
CSV_TABLES = ["hop_artefacts.csv", "hop_identity.csv", "hops.csv", "links.csv", "path_edges.csv", "path_nodes.csv",
              "paths.csv"]
T74_FILES = ["links.csv", "hop_artefacts.csv", "hop_identity.csv"]


# ================================================================================================ helpers
def _read(blob: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(blob.decode("utf-8"))))


@functools.lru_cache(maxsize=None)
def _written(trial: str) -> dict | None:
    """Run `python -m stitch` in process once; the ten files' bytes, parsed tables, stats and the exit code."""
    assert trial in DEV, trial                      # belt and braces: only development trials, ever
    paths = trial_paths(REPO, trial)
    if not paths.db.is_file() or not (paths.gate_dir / "stats.json").is_file():
        return None
    code = stitch_main.main(["--trial", trial, "--repo", str(REPO)])
    folder = REPO / "out" / "stitch" / trial
    blobs = {p.name: p.read_bytes() for p in sorted(folder.iterdir())}
    tables = {n: _read(blobs[n]) for n in CSV_TABLES if n in blobs}
    return {"code": code, "blobs": blobs, "tables": tables, "folder": folder,
            "stats": json.loads(blobs["stats.json"].decode("utf-8")) if "stats.json" in blobs else {},
            "info": json.loads(blobs["run_info.json"].decode("utf-8")) if "run_info.json" in blobs else {}}


def written(trial: str) -> dict:
    got = _written(trial)
    if got is None:
        pytest.skip(f"{trial}: trial DB or gate output missing")
    assert got["code"] == 0, f"{trial}: exit code {got['code']}"
    return got


def load_key(trial: str) -> dict:
    path = APPROVED / f"{trial}.yaml"
    if not path.is_file():
        pytest.skip(f"no approved key for {trial}")
    return json.loads(path.read_text(encoding="utf-8"))


def stitch_hop_id(w: dict, kh: dict) -> str:
    """The hop id of the stitch hop whose member 4624 is one of the key hop's `target_event_uids` (ST-25); several
    hits are narrowed by the key's target logon ID."""
    uids = set(kh["target_event_uids"])
    rows = w["tables"]["hops.csv"]
    hits = [r for r in rows if set(r["member_logon_uids"].split(";")) & uids]
    if len(hits) > 1:
        want = str(int(kh["target_logon_id"], 16))
        hits = [r for r in hits if want in r["member_logon_ids"].split(";")]
    assert len(hits) == 1, f"{kh['hop_id']}: {len(hits)} stitch hops hold its target 4624 uid(s)"
    return hits[0]["hop_id"]


@functools.lru_cache(maxsize=None)
def key_map(trial: str) -> dict[str, str]:
    """key hop id -> stitch hop id, for every hop of the t00 key."""
    w, key = written(trial), load_key(trial)
    return {kh["hop_id"]: stitch_hop_id(w, kh) for kh in key["hops"]}


def hop_row(w: dict, hop_id: str) -> dict[str, str]:
    (row,) = [r for r in w["tables"]["hops.csv"] if r["hop_id"] == hop_id]
    return row


def path_of(w: dict, hop_id: str) -> dict[str, str]:
    rows = [r for r in w["tables"]["paths.csv"] if hop_id in r["hop_ids"].split(";")]
    assert len(rows) == 1, f"{hop_id}: in {len(rows)} paths.csv rows"
    return rows[0]


# ================================================================================================ the ten files
@pytest.mark.parametrize("trial", DEV)
def test_the_run_writes_the_ten_files_with_the_expected_exit_code(trial):
    w = written(trial)
    assert sorted(w["blobs"]) == sorted(TEN_FILES), f"{trial}: files {sorted(w['blobs'])}"


@pytest.mark.parametrize("trial", DEV)
def test_two_runs_give_the_same_bytes_for_every_file_but_run_info(trial):
    first = written(trial)["blobs"]
    assert stitch_main.main(["--trial", trial, "--repo", str(REPO)]) == 0
    folder = REPO / "out" / "stitch" / trial
    for n in TEN_FILES:
        if n != "run_info.json":
            assert (folder / n).read_bytes() == first[n], f"{trial}: {n} differs between two runs"


# ================================================================================================ chain edges (ST-72, STA-09)
def all_edges() -> list[tuple[str, dict[str, str]]]:
    return [(t, r) for t in DEV for r in written(t)["tables"]["path_edges.csv"]]


def test_exactly_two_chain_edges_over_all_development_trials_both_in_s05_t00_both_host_time():
    edges = all_edges()
    got = [(t, r["from_hop_id"], r["to_hop_id"], r["link_type"]) for t, r in edges]
    assert len(edges) == 2, f"{len(edges)} chain edges over the nine trials: {got}"
    assert {t for t, _ in edges} == {"s05_t00"}, got
    assert {r["link_type"] for _, r in edges} == {"host_time"}, got


def test_the_two_s05_edges_are_key_h1_to_key_h2_and_background_t1_to_key_h2_with_the_expected_deltas():
    m = key_map("s05_t00")
    h1, h2, t1 = m["s05-h1"], m["s05-h2"], m["s05-t1"]
    by_from = {r["from_hop_id"]: r for t, r in all_edges() if t == "s05_t00"}
    assert set(by_from) == {h1, t1}, f"edge sources {sorted(by_from)}, expected {sorted([h1, t1])}"
    assert all(r["to_hop_id"] == h2 for r in by_from.values())
    assert 118_000 <= int(by_from[h1]["time_delta_ms"]) <= 119_999, by_from[h1]["time_delta_ms"]
    assert 450_000 <= int(by_from[t1]["time_delta_ms"]) <= 451_999, by_from[t1]["time_delta_ms"]
    assert all(r["order_within_tolerance"] == "0" for r in by_from.values())          # both far outside 5 s
    path_ids = {r["path_id"] for r in by_from.values()}
    assert len(path_ids) == 1


def test_no_session_edge_anywhere_and_stats_agree():
    for t in DEV:
        w = written(t)
        assert all(r["link_type"] == "host_time" for r in w["tables"]["path_edges.csv"]), t
        assert w["stats"]["chain_edges_by_type"]["session"] == 0, t
        assert w["stats"]["chain_edges_by_type"]["host_time"] == len(w["tables"]["path_edges.csv"]), t


def test_every_edge_end_is_a_seed_and_no_machine_account_only_hop_has_an_edge():
    for t in DEV:
        w = written(t)
        rows = {r["hop_id"]: r for r in w["tables"]["hops.csv"]}
        for e in w["tables"]["path_edges.csv"]:
            for end in (e["from_hop_id"], e["to_hop_id"]):
                assert rows[end]["is_seed"] == "1", f"{t}: edge end {end} is not a seed"
                accts = rows[end]["member_accounts"].split(";")
                assert not all(a.endswith("$") for a in accts), f"{t}: edge end {end} is machine-account only"


# ================================================================================================ the s05 path (L-ST2)
def test_s05_path_is_exactly_the_background_hop_and_the_two_attack_hops():
    w = written("s05_t00")
    m = key_map("s05_t00")
    want = {m["s05-t1"], m["s05-h1"], m["s05-h2"]}
    p = path_of(w, m["s05-h2"])
    assert set(p["hop_ids"].split(";")) == want, p["hop_ids"]
    assert p["n_hops"] == "3" and p["isolated"] == "0"
    assert p["edge_types"] == "host_time:2;session:0"
    assert set(p["merged_from"].split("|")) == {f"{m['s05-t1']}>{m['s05-h2']}", f"{m['s05-h1']}>{m['s05-h2']}"}
    ids = p["hop_ids"].split(";")
    assert ids == sorted(ids), "hop ids of the path are in time order (= id order)"
    for hid in want:
        assert path_of(w, hid)["path_id"] == p["path_id"]
    assert [r["path_id"] for r in w["tables"]["paths.csv"] if r["n_hops"] != "1"] == [p["path_id"]]


def test_s05_h2_is_flagged_multi_chain_parent_with_both_parents_listed_in_hop_order():
    w = written("s05_t00")
    m = key_map("s05_t00")
    r = hop_row(w, m["s05-h2"])
    assert (r["multi_chain_parent"], r["chain_parent_count"]) == ("1", "2")
    parents = r["chain_parent_hop_ids"].split(";")
    assert set(parents) == {m["s05-h1"], m["s05-t1"]}
    assert parents == sorted(parents)
    assert w["stats"]["multi_chain_parent_hops"] == {m["s05-h2"]: parents}
    for k in ("s05-h1", "s05-t1"):
        rr = hop_row(w, m[k])
        assert (rr["multi_chain_parent"], rr["chain_parent_count"], rr["chain_parent_hop_ids"]) == ("0", "0", "")


def test_the_l_st2_sentence_is_in_the_s05_report():
    from stitch.report import L_ST2_SENTENCE
    assert L_ST2_SENTENCE in written("s05_t00")["blobs"]["report.md"].decode("utf-8")


@pytest.mark.parametrize("trial", [t for t in DEV if t != "s05_t00"])
def test_no_multi_hop_path_and_no_multi_parent_hop_in_any_other_trial(trial):
    w = written(trial)
    assert [r["path_id"] for r in w["tables"]["paths.csv"] if r["n_hops"] != "1"] == [], trial
    assert all(r["multi_chain_parent"] == "0" for r in w["tables"]["hops.csv"]), trial
    assert w["stats"]["multi_hop_paths"] == [] and w["stats"]["multi_chain_parent_hops"] == {}, trial


# ================================================================================================ s07 X and Y (ST-73)
def test_s07_x_and_y_are_two_paths_each_naming_the_other_as_sharing_a_source_session():
    w = written("s07_t00")
    key = load_key("s07_t00")
    m = key_map("s07_t00")
    key_paths = {p["path_id"]: p["hop_ids"] for p in key["paths"]}
    assert len(key_paths) == 2, key_paths
    (xp, xh), (yp, yh) = sorted(key_paths.items())
    assert len(xh) == len(yh) == 1
    x_hop, y_hop = m[xh[0]], m[yh[0]]
    px, py = path_of(w, x_hop), path_of(w, y_hop)
    assert px["path_id"] != py["path_id"], "X and Y are in one path"
    assert px["hop_ids"] == x_hop and py["hop_ids"] == y_hop                       # nothing else merged in
    assert py["path_id"] in px["shared_source_session_with"].split(";")
    assert px["path_id"] in py["shared_source_session_with"].split(";")


def test_the_s06_hops_sharing_one_agent_session_stay_separate_paths_with_the_note_set():
    for t in ("s06_t00", "s06_t01"):
        w = written(t)
        assert all(r["n_hops"] == "1" for r in w["tables"]["paths.csv"]), t
    w = written("s06_t00")
    noted = [r for r in w["tables"]["paths.csv"] if r["shared_source_session_with"]]
    assert noted, "s06_t00: no path carries a shared_source_session_with note"
    ids = {r["path_id"] for r in w["tables"]["paths.csv"]}
    for r in noted:
        for other in r["shared_source_session_with"].split(";"):
            assert other in ids and other != r["path_id"]
            back = next(x for x in w["tables"]["paths.csv"] if x["path_id"] == other)
            assert r["path_id"] in back["shared_source_session_with"].split(";"), "note is not symmetric"


@pytest.mark.parametrize("trial", DEV)
def test_notes_name_existing_paths_only_and_never_merge(trial):
    w = written(trial)
    ids = {r["path_id"] for r in w["tables"]["paths.csv"]}
    for r in w["tables"]["paths.csv"]:
        for col in ("shared_source_session_with", "shared_event_with"):
            for other in filter(None, r[col].split(";")):
                assert other in ids and other != r["path_id"], f"{trial}: {col} names {other}"


# ================================================================================================ STA-09 attack hops in paths.csv
@pytest.mark.parametrize("trial", DEV_T00)
def test_every_attack_hop_of_the_key_is_a_seed_in_exactly_one_paths_row(trial):
    w, key = written(trial), load_key(trial)
    m = key_map(trial)
    attack = [kh["hop_id"] for kh in key["hops"] if kh.get("role") == "attack"]
    key_path_hops = {h for p in key["paths"] for h in p["hop_ids"]}
    if trial == "s06_t00":
        assert attack == [], "S06 has no attack path (AK-09)"           # its benign hops are checked below
    else:
        assert attack, f"{trial}: no attack hop in the key"
    assert set(attack) <= key_path_hops
    for k in attack:
        r = hop_row(w, m[k])
        assert (r["is_seed"], r["in_path"]) == ("1", "1"), f"{trial}: key hop {k} is stitch hop {m[k]} with is_seed={r['is_seed']}"
        path_of(w, m[k])                                   # exactly one row


@pytest.mark.parametrize("trial", DEV_T00)
def test_every_keyed_seed_hop_of_any_role_is_in_a_path_and_a_key_hop_maps_to_one_stitch_hop(trial):
    w = written(trial)
    m = key_map(trial)
    assert len(set(m.values())) == len(m), f"{trial}: two key hops map to one stitch hop"
    for k, hid in m.items():
        r = hop_row(w, hid)
        assert r["in_path"] == r["is_seed"], (trial, k)


def test_the_isolated_target_only_seed_style_paths_exist_and_are_kept():
    """ST-74: a path of one hop with no edge is a row of paths.csv (isolated = 1); there are many in the data."""
    n = 0
    for t in DEV:
        w = written(t)
        for r in w["tables"]["paths.csv"]:
            if r["isolated"] == "1":
                n += 1
                assert r["n_hops"] == "1" and r["edge_types"] == "host_time:0;session:0"
                assert r["merged_from"] == r["hop_ids"]
        assert w["stats"]["isolated_paths"] == sum(1 for r in w["tables"]["paths.csv"] if r["isolated"] == "1")
    assert n > 20


# ================================================================================================ STA-01 / ST-04
@functools.lru_cache(maxsize=None)
def _hopset(trial: str):
    li, _before, _after = run_links(REPO, trial)
    return li.hopset


def gate_remote_uids(trial: str) -> list[str]:
    """Every remote logon of the gate files: the non-empty anchors of triggers.csv plus every unmatched_remote row's
    logon uid (spec ST-03)."""
    gdir = trial_paths(REPO, trial).gate_dir
    out: list[str] = []
    for r in csv.DictReader(open(gdir / "triggers.csv", newline="", encoding="utf-8")):
        if (r.get("anchor_logon_uid") or "").strip():
            out.append(r["anchor_logon_uid"].strip())
    for r in csv.DictReader(open(gdir / "unmatched_remote.csv", newline="", encoding="utf-8")):
        uid = (r.get("anchor_logon_uid") or "").strip() or (r.get("trigger_event_uid") or "").strip()
        assert uid, f"{trial}: an unmatched row names no logon uid"
        out.append(uid)
    return out


@pytest.mark.parametrize("trial", DEV)
def test_sta01_every_remote_logon_is_a_member_of_exactly_one_hops_row_or_a_followup_of_exactly_one(trial):
    w, hs = written(trial), _hopset(trial)
    rows = {r["hop_id"]: r for r in w["tables"]["hops.csv"]}
    member_hop: dict[str, set[str]] = {}
    for h in hs.hops:
        for mem in h.members:
            for u in mem.event_uids:
                member_hop.setdefault(u, set()).add(h.hop_id)
    follow_hop: dict[str, set[str]] = {}
    for h in hs.hops:
        for f in h.followups:
            for u in f.event_uids:
                follow_hop.setdefault(u, set()).add(h.hop_id)
    bad: list[str] = []
    gate = gate_remote_uids(trial)
    for uid in gate:
        homes = member_hop.get(uid, set()) | follow_hop.get(uid, set())
        if len(homes) != 1:
            bad.append(f"{uid}: in {len(homes)} hops")
    assert bad == [], f"{trial}: {len(bad)} remote logon(s) not in exactly one hop: " + "; ".join(bad[:8])
    # the file side: every gate logon's hop is a hops.csv row, and its representative uid is listed in that row
    listed_members = {u for r in rows.values() for u in r["member_logon_uids"].split(";") if u}
    listed_followups = {u for r in rows.values() for u in r["followup_logon_uids"].split(";") if u}
    for h in hs.hops:
        assert h.hop_id in rows
        for mem in h.members:
            assert mem.uid in listed_members, f"{trial}: member {mem.uid} not in hops.csv"
    assert len(listed_members & listed_followups) == 0
    # distinct remote logons in the files = distinct logons of the gate files (ST-05 copies collapsed)
    reps = len(listed_members) + len(listed_followups)
    assert reps == w["stats"]["remote_logons"], f"{trial}: {reps} logons in hops.csv vs stats {w['stats']['remote_logons']}"
    assert len(set(gate)) >= reps                              # a logon may be named by two gate uids (ST-05), never fewer


@pytest.mark.parametrize("trial", DEV)
def test_hops_csv_rows_equal_stats_hops_and_every_hop_of_every_file_is_in_it(trial):
    w = written(trial)
    t = w["tables"]
    ids = [r["hop_id"] for r in t["hops.csv"]]
    assert len(ids) == len(set(ids)) == w["stats"]["hops"] == w["stats"]["files"]["hops.csv"], trial
    assert ids == sorted(ids)
    assert {r["hop_id"] for r in t["links.csv"]} == set(ids), trial               # every hop has link rows (ST-49)
    assert {r["hop_id"] for r in t["hop_identity.csv"]} == set(ids), trial
    assert {r["hop_id"] for r in t["hop_artefacts.csv"]} <= set(ids), trial
    assert sum(int(r["member_count"]) for r in t["hops.csv"]) + sum(
        int(r["followup_logon_count"]) for r in t["hops.csv"]) == w["stats"]["remote_logons"], trial


@pytest.mark.parametrize("trial", DEV)
def test_st04_in_path_0_hops_are_exactly_the_non_seed_hops_listed_in_stats(trial):
    w = written(trial)
    rows = w["tables"]["hops.csv"]
    no_path = [r["hop_id"] for r in rows if r["in_path"] == "0"]
    non_seed = [r["hop_id"] for r in rows if r["is_seed"] == "0"]
    assert no_path == non_seed == w["stats"]["hops_in_no_path"] == w["stats"]["non_seed_hops"], trial
    assert all(r["trigger_ids"] == "" for r in rows if r["is_seed"] == "0")
    assert all(r["trigger_ids"] != "" for r in rows if r["is_seed"] == "1")
    assert all(r["in_path"] == r["is_seed"] for r in rows)
    in_paths = [h for r in w["tables"]["paths.csv"] for h in r["hop_ids"].split(";")]
    seeds = sorted(r["hop_id"] for r in rows if r["is_seed"] == "1")
    assert sorted(in_paths) == seeds and len(in_paths) == len(set(in_paths)), f"{trial}: seeds vs path members"
    assert w["stats"]["seeds"] == len(seeds) and w["stats"]["paths"] == len(w["tables"]["paths.csv"])
    non_seed_in_nodes = {r["hop_id"] for r in w["tables"]["path_nodes.csv"]} & set(non_seed)
    assert non_seed_in_nodes == set(), f"{trial}: non-seed hops with path nodes: {sorted(non_seed_in_nodes)}"


@pytest.mark.parametrize("trial", DEV)
def test_every_path_node_row_is_in_a_path_and_a_hop_of_that_path(trial):
    w = written(trial)
    paths = {r["path_id"]: set(r["hop_ids"].split(";")) for r in w["tables"]["paths.csv"]}
    link_ids = {r["link_id"] for r in w["tables"]["links.csv"]}
    for r in w["tables"]["path_nodes.csv"]:
        assert r["hop_id"] in paths[r["path_id"]]
        if r["link_id"]:
            assert r["link_id"] in link_ids and r["link_id"].startswith(r["hop_id"] + "-l")
    ident = [(r["path_id"], r["hop_id"], r["role"], r["event_uid"], r["link_id"]) for r in w["tables"]["path_nodes.csv"]]
    assert len(ident) == len(set(ident)), f"{trial}: duplicated path_nodes rows"
    # every seed has at least its own target_logon node
    have = {r["hop_id"] for r in w["tables"]["path_nodes.csv"] if r["role"] == "target_logon"}
    assert have == {h for hs_ in paths.values() for h in hs_}


# ================================================================================================ T7.2-T7.4 results unchanged
@pytest.mark.parametrize("trial", DEV)
def test_the_three_t74_files_have_the_baseline_sha256_of_t74_run_info(trial):
    base = REPO / CHECK_REL / trial / "t74_run_info.json"
    if not base.is_file():
        pytest.skip(f"{trial}: no t74_run_info.json baseline")
    want = json.loads(base.read_text(encoding="utf-8"))["files"]
    w = written(trial)
    for n in T74_FILES:
        got = hashlib.sha256(w["blobs"][n]).hexdigest()
        assert got == want[n]["sha256"], f"{trial}: {n} sha256 differs from the T7.4 baseline"
        assert w["info"]["files"][n]["sha256"] == want[n]["sha256"]
        assert len(w["tables"][n]) == want[n]["rows"], f"{trial}: {n} row count differs from the baseline"


@pytest.mark.parametrize("trial", DEV)
def test_t73_links_and_t72_index_files_are_byte_identical_to_fresh_check_data(trial):
    paths = trial_paths(REPO, trial)
    for name, runner in (("t73_links.json", cl.run_check), ("t72_index.json", ci.run_check)):
        committed = REPO / CHECK_REL / trial / name
        if not paths.db.is_file() or not committed.is_file():
            pytest.skip(f"{trial}: DB or committed {name} missing")
        data = runner(REPO, trial)
        fresh = ci.check_text(data).encode("utf-8")
        assert fresh == committed.read_bytes(), f"{trial}: {name} differs from the committed file"
        assert data["db"]["sha256_before"] == data["db"]["sha256_after"] == sha256_file(paths.db)


# ================================================================================================ DB hash, refusal
@pytest.mark.parametrize("trial", DEV)
def test_db_sha_unchanged_run_info_before_equals_after_equals_gate_stats(trial):
    w = written(trial)
    paths = trial_paths(REPO, trial)
    gate = json.loads((paths.gate_dir / "stats.json").read_text(encoding="utf-8"))
    sha = sha256_file(paths.db)
    assert w["info"]["db"]["sha256_before"] == w["info"]["db"]["sha256_after"] == sha, trial
    assert w["info"]["db"]["sha256_after"] == gate["db"]["sha256_after"], trial
    assert w["stats"]["db"] == {"sha256_before": sha, "sha256_after": sha}, trial
    assert sha in w["blobs"]["report.md"].decode("utf-8")


def test_a_non_development_trial_is_refused_with_exit_2_and_no_folder(capsys):
    target = REPO / "out" / "stitch" / "s02_t02"
    assert not target.exists(), "out/stitch/s02_t02 exists before the test"
    code = stitch_main.main(["--trial", "s02_t02", "--repo", str(REPO)])
    err = capsys.readouterr().err
    assert code == 2, f"exit code {code}"
    assert "refused" in err
    assert not target.exists(), "out/stitch/s02_t02 was created"
    leftovers = sorted(p.name for p in (REPO / "out" / "stitch").iterdir() if p.name.startswith(".") or "s02_t02" in p.name)
    assert leftovers == [], f"leftover entries {leftovers}"
