"""T9 score stage end to end on a synthetic repo (spec 05_score section 2 inputs, section 3 outputs, SC-01..04, SC-21b, SC-40,
SC-41, SC-60, SC-61; SCT-21b, SCT-32, SCT-34, SCT-41, SCT-42, SCT-60; decisions 054, 067).

Written from the spec and decisions, not from the implementation (the code was read only for its public entry points:
`score.run.run_trial`, `score.__main__.main`). The world and its hand computation live in `score_fixtures.base_world`.
Nothing under the real `out/`, `data/` or `ground_truth/` is opened; the CLI writes into pytest tmp folders.
"""
from __future__ import annotations

import builtins
import hashlib
import io
import json
import pathlib
import random
import re
import sqlite3
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import score.__main__ as sm  # noqa: E402
import score_fixtures as fx  # noqa: E402
from score import params as sp  # noqa: E402
from score.run import run_trial  # noqa: E402

RANKED_COLS = ["trial_id", "variant", "rank", "tie_size", "path_id", "score", "length_score", "edge_score", "seq_len",
               "node_score", "n_node_units", "node_score_ctx1", "identity_coherence", "identity_low", "identity_high",
               "n_crossings", "n_crossings_coherent", "n_crossings_flagged", "n_hops", "hop_ids", "hosts", "isolated",
               "merged_from", "multi_chain_parent", "technique_sequence", "best_tier_min", "clock_unreliable"]
STEPS_COLS = ["path_id", "step", "from_technique", "to_technique", "from_tactic", "to_tactic", "tactic_score",
              "technique_score", "score_e", "basis", "method", "candidate_count", "time_delta_ms", "from_event_uids",
              "to_event_uids"]
UNITS_COLS = ["path_id", "count_key", "event_uids", "hop_id", "techniques", "level_value"]
IDENT_VALUES_COLS = ["hop_id", "account", "value", "identity_status", "applicable", "not_applicable", "method",
                     "candidate_count", "deciding_dump_event_uids", "open_session_uids", "time_delta_ms",
                     "order_within_uncertainty", "session_open_before_window", "hop_best_tier", "clock_unreliable"]
B0_COLS = ["trial_id", "variant", "rank", "tie_size", "unit_id", "event_uids", "host", "techniques", "level_value",
           "score"]
EIGHT = {"ranked_paths.csv", "path_steps.csv", "path_node_units.csv", "hop_identity_values.csv", "b0_ranked.csv",
         "stats.json", "report.md", "run_info.json"}
FORBIDDEN = ("stolen", "detects", "probability", "reduces false positives", "identifies the attacker")
NOW = "2026-11-18T00:00:00Z"


def header(text: str) -> list[str]:
    return next(__import__("csv").reader(io.StringIO(text)))


@pytest.fixture()
def repo(tmp_path):
    return fx.build_repo(tmp_path / "repo", fx.base_world())


@pytest.fixture()
def result(repo):
    return run_trial(repo, fx.TRIAL, generated_utc=NOW)


def rows_of(result, name):
    return fx.parse_text(result.files[name])


def by_path(rows, variant):
    return {r["path_id"]: r for r in rows if r["variant"] == variant}


# ------------------------------------------------------------------------------------------------ contract
def test_the_eight_spec_files_with_the_spec_columns_in_order(result):
    assert set(result.files) == EIGHT
    assert header(result.files["ranked_paths.csv"]) == RANKED_COLS
    assert header(result.files["path_steps.csv"]) == STEPS_COLS
    assert header(result.files["path_node_units.csv"]) == UNITS_COLS
    assert header(result.files["hop_identity_values.csv"]) == IDENT_VALUES_COLS
    assert header(result.files["b0_ranked.csv"]) == B0_COLS


def test_every_path_is_ranked_exactly_once_per_variant_nothing_dropped_or_added(result):
    rows = rows_of(result, "ranked_paths.csv")
    ids = {f"p000{i}" for i in range(1, 7)}
    assert len(rows) == 18
    for v in ("full", "b1", "b2"):
        got = [r["path_id"] for r in rows if r["variant"] == v]
        assert sorted(got) == sorted(ids)
    assert {r["variant"] for r in rows} == {"full", "b1", "b2"}
    assert {r["trial_id"] for r in rows} == {fx.TRIAL}


def test_copied_stitch_columns_are_unchanged(result):
    full = by_path(rows_of(result, "ranked_paths.csv"), "full")
    assert full["p0005"]["isolated"] == "1" and full["p0001"]["isolated"] == "0"     # an isolated path is never dropped
    assert full["p0004"]["hop_ids"] == "h3;h4" and full["p0004"]["n_hops"] == "2"
    assert full["p0002"]["hosts"] == "ep-02>ep-03"
    assert full["p0006"]["merged_from"] == "h7;h6"


def test_type_of_every_ranked_cell(result):
    for r in rows_of(result, "ranked_paths.csv"):
        int(r["rank"]), int(r["tie_size"]), int(r["seq_len"]), int(r["n_node_units"]), int(r["n_crossings"])
        for c in ("score", "length_score", "edge_score", "node_score", "node_score_ctx1", "identity_coherence",
                  "identity_low", "identity_high"):
            assert re.fullmatch(r"\d\.\d{6}", r[c]), (c, r[c])
            assert 0.0 <= float(r[c]) <= 1.0
        assert r["clock_unreliable"] in ("0", "1") and r["multi_chain_parent"] in ("0", "1")


# ------------------------------------------------------------------------------------------------ hand-computed numbers
def test_components_on_the_hand_computed_world(result):
    full = by_path(rows_of(result, "ranked_paths.csv"), "full")
    exp = {  # L, N, N_ctx1, I, units, seq_len
        "p0001": (0.75, 0.25, 0.375, 1.0, 3, 2),
        "p0002": (0.25, 0.625, 0.625, 0.0, 2, 1),
        "p0003": (0.0, 0.0, 0.0, 0.0, 0, 0),
        "p0004": (0.0, 0.0, 0.0, 0.0, 0, 0),
        "p0005": (0.0, 0.0, 0.0, 1.0, 0, 0),
        "p0006": (0.8203125, 0.4, 0.4, 0.5, 5, 4),
    }
    for pid, (L, N, N1, I, units, n) in exp.items():
        r = full[pid]
        assert float(r["length_score"]) == pytest.approx(L, abs=1e-6), pid
        assert float(r["node_score"]) == pytest.approx(N, abs=1e-6), pid
        assert float(r["node_score_ctx1"]) == pytest.approx(N1, abs=1e-6), pid
        assert float(r["identity_coherence"]) == pytest.approx(I, abs=1e-6), pid
        assert (int(r["n_node_units"]), int(r["seq_len"])) == (units, n), pid
        assert float(r["score"]) == pytest.approx((L + N + I) / 3, abs=1.5e-6), pid


def test_variant_scores_and_ranks_on_the_hand_computed_world(result):
    rows = rows_of(result, "ranked_paths.csv")
    full, b1, b2 = (by_path(rows, v) for v in ("full", "b1", "b2"))
    assert {p: (r["rank"], r["tie_size"]) for p, r in full.items()} == {
        "p0001": ("1", "1"), "p0006": ("2", "1"), "p0005": ("3", "1"), "p0002": ("4", "1"),
        "p0003": ("5", "2"), "p0004": ("5", "2")}
    assert {p: (r["rank"], r["tie_size"]) for p, r in b1.items()} == {
        "p0006": ("1", "1"), "p0001": ("2", "1"), "p0002": ("3", "1"),
        "p0003": ("4", "3"), "p0004": ("4", "3"), "p0005": ("4", "3")}
    assert {p: (r["rank"], r["tie_size"]) for p, r in b2.items()} == {
        "p0002": ("1", "1"), "p0006": ("2", "1"), "p0001": ("3", "1"),
        "p0003": ("4", "3"), "p0004": ("4", "3"), "p0005": ("4", "3")}
    assert float(b1["p0001"]["score"]) == pytest.approx(0.5, abs=1e-6)
    assert float(b1["p0006"]["score"]) == pytest.approx((0.8203125 + 0.4) / 2, abs=1e-6)
    assert float(b2["p0002"]["score"]) == pytest.approx(0.625, abs=1e-6)
    assert float(full["p0005"]["score"]) == pytest.approx(1 / 3, abs=1e-6)         # exposed, nothing labelled (ATK-SC-09)


def test_rows_are_listed_by_variant_in_rank_order(result):
    rows = rows_of(result, "ranked_paths.csv")
    for v in ("full", "b1", "b2"):
        ranks = [int(r["rank"]) for r in rows if r["variant"] == v]
        assert ranks == sorted(ranks)


def test_node_score_ctx1_is_reported_but_never_in_the_score(result):
    full = by_path(rows_of(result, "ranked_paths.csv"), "full")["p0001"]
    assert float(full["node_score_ctx1"]) > float(full["node_score"])
    assert float(full["score"]) == pytest.approx((0.75 + 0.25 + 1.0) / 3, abs=1e-6)       # not (.75 + .375 + 1) / 3


def test_technique_sequences_and_hop_boundary_steps(result):
    full = by_path(rows_of(result, "ranked_paths.csv"), "full")
    assert full["p0001"]["technique_sequence"] == "T1021.002>T1570>T1569.002"
    assert full["p0002"]["technique_sequence"] == "T1078>T1021.006"
    assert full["p0003"]["technique_sequence"] == ""
    assert full["p0006"]["technique_sequence"] == "T1021.002>T1570>T1569.002>T1078>T1021.006"   # chain edge beats time
    steps = [r for r in rows_of(result, "path_steps.csv") if r["path_id"] == "p0006"]
    assert [r["basis"] for r in steps] == ["direct", "direct", "hop_chain", "indirect"]
    assert steps[2]["time_delta_ms"] == "5250" and steps[0]["time_delta_ms"] == ""
    assert steps[2]["from_event_uids"] == "w_svc" and steps[2]["to_event_uids"] == "w_4648;w_4648b"


def test_steps_rows_carry_method_candidate_count_and_uids(result):
    steps = rows_of(result, "path_steps.csv")
    assert len(steps) == 2 + 1 + 4
    for r in steps:
        assert r["method"] == "technique_sequence" and r["candidate_count"] == "1"
        assert r["from_event_uids"] and r["to_event_uids"]
    p1 = [r for r in steps if r["path_id"] == "p0001"]
    assert [(r["from_technique"], r["to_technique"], r["score_e"]) for r in p1] == [
        ("T1021.002", "T1570", "1.000000"), ("T1570", "T1569.002", "1.000000")]
    assert p1[0]["from_tactic"] == p1[0]["to_tactic"] == "lateral-movement" and p1[1]["to_tactic"] == "execution"


def test_node_units_rows(result):
    units = rows_of(result, "path_node_units.csv")
    p1 = [r for r in units if r["path_id"] == "p0001"]
    assert [r["count_key"] for r in p1] == ["k_cp", "k_smb", "k_svc"]               # the dump (context 1) is not a unit
    assert next(r for r in p1 if r["count_key"] == "k_svc")["event_uids"] == "u_s4697;u_s7045"
    assert len(units) == 3 + 2 + 5 and {r["level_value"] for r in p1} == {"1"}


def test_identity_values_cover_every_hop_account_with_status_and_method(result):
    rows = {(r["hop_id"], r["account"]): r for r in rows_of(result, "hop_identity_values.csv")}
    assert len(rows) == 7
    assert (rows["h1", "svc"]["value"], rows["h1", "svc"]["identity_status"]) == ("1", "exposed")
    assert rows["h1", "svc"]["time_delta_ms"] == "10000" and rows["h1", "svc"]["deciding_dump_event_uids"] == "d1"
    # excluded OS/AV read: value 0, not counted
    assert (rows["h2", "admin_it"]["value"], rows["h2", "admin_it"]["candidate_count"]) == ("0", "0")
    assert rows["h3", "dc-01$"]["value"] == "" and rows["h3", "dc-01$"]["applicable"] == "0"
    assert rows["h3", "dc-01$"]["identity_status"] == "unknown:machine_account"
    assert rows["h4", "usr"]["identity_status"] == "unknown:source_host_unknown"
    assert rows["h5", "svc2"]["value"] == "1" and rows["h5", "svc2"]["hop_best_tier"] == "D"    # target_only hop gets a value
    assert rows["h7", "u7"]["value"] == "0" and rows["h7", "u7"]["order_within_uncertainty"] == "1"
    assert all(r["method"] == "correction_k" for r in rows.values())


def test_identity_low_high_crossings_and_flags_on_the_multi_hop_path(result):
    r = by_path(rows_of(result, "ranked_paths.csv"), "full")["p0006"]
    assert (r["n_crossings"], r["n_crossings_coherent"], r["n_crossings_flagged"]) == ("2", "1", "1")
    assert (float(r["identity_coherence"]), float(r["identity_low"]), float(r["identity_high"])) == (0.5, 0.5, 1.0)
    assert r["clock_unreliable"] == "1" and r["multi_chain_parent"] == "1" and r["best_tier_min"] == "C"
    p4 = by_path(rows_of(result, "ranked_paths.csv"), "full")["p0004"]
    assert p4["n_crossings"] == "0" and p4["best_tier_min"] == "D"


def test_b0_has_one_row_per_labelled_unit_any_host_any_context(result):
    b0 = rows_of(result, "b0_ranked.csv")
    keys = {e["count_key"] for e in fx.base_world().events}
    assert sorted(r["unit_id"] for r in b0) == sorted(keys)
    assert {r["variant"] for r in b0} == {"b0"}
    top = b0[0]
    assert (top["unit_id"], top["rank"], top["score"], top["host"]) == ("k_orphan", "1", "1.000000", "ep-09")
    dump = next(r for r in b0 if r["unit_id"] == "k_dump")
    assert dump["level_value"] == "3" and dump["score"] == "0.750000"              # context 1 is in b0 (owner Q12)
    ranks = [int(r["rank"]) for r in b0]
    assert ranks == sorted(ranks)


def test_stats_and_run_info(result):
    stats = json.loads(result.files["stats.json"])
    info = json.loads(result.files["run_info.json"])
    assert stats["candidates_per_variant"]["full"] == stats["candidates_per_variant"]["b1"] == 6
    assert stats["paths_without_labelled_unit"] == 3
    p = info["parameters"]
    assert p["alpha"] == 0.5 and p["beta"] == 0.5 and p["a"] == 1.0 and p["b"] == 1.0 and p["eps"] == 0.01
    assert info["order_table_sha256"] == sp.ORDER_TABLE_SHA256
    assert info["generated_utc"] == NOW
    for name, rec in info["files"].items():
        assert rec["sha256"] == hashlib.sha256(result.files[name].encode("utf-8")).hexdigest(), name
    assert info["files"]["ranked_paths.csv"]["rows"] == 18
    assert set(info["inputs"]) == {"stitch", "label"}
    assert stats["parameters"] == p


def test_report_wording(result):
    text = result.files["report.md"].lower()
    for w in FORBIDDEN:
        assert w not in text, w
    assert not re.search(r"confidence\s*%", text)
    assert "exposed" in text and "not a likelihood" in text


def test_outputs_are_deterministic_except_generated_utc(repo):
    a = run_trial(repo, fx.TRIAL, generated_utc="2026-01-01T00:00:00Z")
    b = run_trial(repo, fx.TRIAL, generated_utc="2027-01-01T00:00:00Z")
    assert {k: v for k, v in a.files.items() if k != "run_info.json"} == {k: v for k, v in b.files.items() if k != "run_info.json"}
    ia, ib = json.loads(a.files["run_info.json"]), json.loads(b.files["run_info.json"])
    ia.pop("generated_utc"), ib.pop("generated_utc")
    assert ia == ib


# ------------------------------------------------------------------------------------------------ SCT-21b / 41 / 42
def shuffled_world(seed: int, *, reverse_hop_lists: bool) -> fx.World:
    rnd = random.Random(seed)
    w = fx.base_world()
    for name in ("paths", "edges", "hops", "identity", "nodes", "events"):
        rnd.shuffle(getattr(w, name))
    if reverse_hop_lists:
        for p in w.paths:
            hs = p["hop_ids"].split(";")
            p["hop_ids"] = ";".join(reversed(hs))
    return w


def strip_hop_ids(text: str) -> list[dict]:
    rows = fx.parse_text(text)
    for r in rows:
        r.pop("hop_ids")
        r.pop("merged_from")
    return rows


@pytest.mark.parametrize("seed,rev", [(1, False), (2, True), (3, True), (4, False)])
def test_row_order_of_every_input_and_hop_list_order_change_no_score(tmp_path, result, seed, rev):
    repo2 = fx.build_repo(tmp_path / "shuf", shuffled_world(seed, reverse_hop_lists=rev))
    other = run_trial(repo2, fx.TRIAL, generated_utc=NOW)
    assert strip_hop_ids(other.files["ranked_paths.csv"]) == strip_hop_ids(result.files["ranked_paths.csv"])
    for name in ("path_steps.csv", "path_node_units.csv", "hop_identity_values.csv", "b0_ranked.csv", "stats.json"):
        assert other.files[name] == result.files[name], name


def test_hop_list_permutations_of_a_three_hop_merged_path_change_no_score(tmp_path):
    import itertools
    seen = set()
    for perm in itertools.permutations(["h6", "h7", "h1"]):             # h1 is a sibling with no chain edge
        w = fx.base_world()
        w.paths = [fx.path("p0009", list(perm))]
        w.edges = [fx.edge("p0009", "h6", "h7")]
        w.nodes = [dict(n, path_id="p0009") for n in w.nodes if n["path_id"] in ("p0006", "p0001")]
        w.identity = [r for r in w.identity if r["hop_id"] in ("h1", "h6", "h7")]
        w.hops = [h for h in w.hops if h["hop_id"] in ("h1", "h6", "h7")]
        res = run_trial(fx.build_repo(tmp_path / f"r{len(seen)}_{'_'.join(perm)}", w), fx.TRIAL, generated_utc=NOW)
        rows = [r for r in fx.parse_text(res.files["ranked_paths.csv"]) if r["variant"] == "full"]
        assert len(rows) == 1
        seen.add((rows[0]["score"], rows[0]["length_score"], rows[0]["technique_sequence"],
                  rows[0]["identity_coherence"], rows[0]["node_score"]))
        assert fx.parse_text(res.files["path_steps.csv"])[0]["path_id"] == "p0009"
    assert len(seen) == 1, seen


def tied_world(rename: dict[str, str] | None = None) -> fx.World:
    """Two identical SMB paths (attack / benign with equal components, s04 A/B, ATK-SC-01) and one lower path."""
    w = fx.base_world()
    ren = rename or {}
    keep = {"p0001", "p0002"}
    w.paths = [dict(p) for p in w.paths if p["path_id"] in keep]
    w.edges, w.nodes = [], [dict(n) for n in w.nodes if n["path_id"] == "p0001"]
    twin = [dict(n, path_id="p0007") for n in w.nodes]
    w.nodes += twin + [dict(n) for n in fx.base_world().nodes if n["path_id"] == "p0002"]
    w.paths.append(fx.path("p0007", "h1"))
    for p in w.paths:
        p["path_id"] = ren.get(p["path_id"], p["path_id"])
    for n in w.nodes:
        n["path_id"] = ren.get(n["path_id"], n["path_id"])
    return w


def test_equal_components_tie_at_rank_one_and_swapping_path_ids_changes_nothing_but_display_order(tmp_path):
    a = run_trial(fx.build_repo(tmp_path / "a", tied_world()), fx.TRIAL, generated_utc=NOW)
    b = run_trial(fx.build_repo(tmp_path / "b", tied_world({"p0001": "p0007", "p0007": "p0001"})), fx.TRIAL,
                  generated_utc=NOW)
    ra = {r["path_id"]: r for r in fx.parse_text(a.files["ranked_paths.csv"]) if r["variant"] == "full"}
    rb = {r["path_id"]: r for r in fx.parse_text(b.files["ranked_paths.csv"]) if r["variant"] == "full"}
    assert (ra["p0001"]["rank"], ra["p0001"]["tie_size"]) == ("1", "2") == (ra["p0007"]["rank"], ra["p0007"]["tie_size"])
    assert ra["p0001"]["score"] == ra["p0007"]["score"]
    for pid in ra:                                  # the swap exchanges ids of identical paths: every cell stays
        other = {"p0001": "p0007", "p0007": "p0001"}.get(pid, pid)
        cells = lambda r: {k: v for k, v in r.items() if k not in ("path_id",)}
        assert cells(ra[pid]) == cells(rb[other])
    listed = [r["path_id"] for r in fx.parse_text(a.files["ranked_paths.csv"]) if r["variant"] == "full"][:2]
    assert listed == sorted(listed)                 # inside a tie: path_id, display only


# ------------------------------------------------------------------------------------------------ SC-02 refusals
def refuse(args, capsys, tmp_path=None):
    code = sm.main(args)
    err = capsys.readouterr().err
    return code, err


def edit(path: Path, fn):
    data = path.read_bytes()
    path.write_bytes(fn(data))


def cli(repo, out=None, trial=fx.TRIAL):
    args = ["--trial", trial, "--repo", str(repo)]
    if out is not None:
        args += ["--out", str(out)]
    return args


def test_cli_writes_the_eight_files_into_a_tmp_out_and_prints_the_folder(repo, capsys):
    out = repo / "out" / "score_tmp"
    assert sm.main(cli(repo, out)) == 0
    assert {p.name for p in out.iterdir()} == EIGHT
    assert not (repo / "out" / "score").exists()
    assert capsys.readouterr().err == ""
    info = json.loads((out / "run_info.json").read_text(encoding="utf-8"))
    for name, rec in info["files"].items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == rec["sha256"]


def test_cli_default_folder_is_out_score_trial_inside_the_repo(repo):
    assert sm.main(cli(repo)) == 0
    assert {p.name for p in (repo / "out" / "score" / fx.TRIAL).iterdir()} == EIGHT


def test_cli_may_write_to_a_folder_outside_the_repo(repo, tmp_path):
    out = tmp_path / "elsewhere" / "x"
    assert sm.main(cli(repo, out)) == 0 and (out / "ranked_paths.csv").is_file()


def test_cli_rerun_replaces_the_folder_and_outputs_are_identical(repo):
    out = repo / "out" / "score_tmp"
    assert sm.main(cli(repo, out)) == 0
    first = {p.name: p.read_bytes() for p in out.iterdir() if p.name != "run_info.json"}
    assert sm.main(cli(repo, out)) == 0
    assert first == {p.name: p.read_bytes() for p in out.iterdir() if p.name != "run_info.json"}


@pytest.mark.parametrize("trial", ["s02_t05", "s02_t10", "s05_t02", "s01_t00", "s01_t01", "x", "../s02_t00"])
def test_a_test_trial_or_a_non_allowlisted_id_is_refused_before_any_file_is_opened(tmp_path, capsys, trial):
    empty = tmp_path / "empty_repo"
    empty.mkdir()
    out = empty / "out" / "score_x"
    code, err = refuse(cli(empty, out, trial), capsys)
    assert code == 2 and err.startswith("refused:")
    assert list(empty.rglob("*")) == []                                    # nothing created


def test_allowlist_check_happens_before_opening_files_even_when_the_inputs_exist(repo, capsys, monkeypatch):
    opened = []
    real_open = builtins.open
    monkeypatch.setattr(builtins, "open", lambda f, *a, **k: (opened.append(str(f)), real_open(f, *a, **k))[1])
    real_read = pathlib.Path.read_bytes
    monkeypatch.setattr(pathlib.Path, "read_bytes", lambda self: (opened.append(str(self)), real_read(self))[1])
    code, err = refuse(cli(repo, trial="s02_t05"), capsys)
    assert code == 2 and not [p for p in opened if "s02_t05" in p]


def test_development_with_out_is_refused(repo, capsys):
    code, err = refuse(["--development", "--repo", str(repo), "--out", str(repo / "out" / "x")], capsys)
    assert code == 2 and err.startswith("refused:")


def test_out_inside_the_repo_but_not_below_out_is_refused_and_nothing_is_written(repo, capsys):
    for bad in (repo / "elsewhere", repo / "out", repo):
        before = sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*"))
        code, err = refuse(cli(repo, bad), capsys)
        assert code == 2 and err.startswith("refused:"), bad
        assert sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*")) == before


def test_out_folder_holding_foreign_files_is_refused_and_kept(repo, capsys):
    out = repo / "out" / "score_tmp"
    out.mkdir(parents=True)
    (out / "notes.txt").write_text("keep me", encoding="utf-8")
    code, err = refuse(cli(repo, out), capsys)
    assert code == 2 and err.startswith("refused:")
    assert (out / "notes.txt").read_text(encoding="utf-8") == "keep me" and len(list(out.iterdir())) == 1


def assert_refused_and_nothing_written(repo, capsys):
    out = repo / "out" / "score_tmp"
    code, err = refuse(cli(repo, out), capsys)
    assert code == 2 and err.startswith("refused:"), err
    assert not out.exists() and not (repo / "out" / "score").exists()
    assert not [p for p in (repo / "out").iterdir() if p.name.startswith(".")]          # no .tmp / .old leftovers
    return err


@pytest.mark.parametrize("rel", ["stitch/{t}/paths.csv", "stitch/{t}/path_edges.csv", "stitch/{t}/hops.csv",
                                 "stitch/{t}/hop_identity.csv", "stitch/{t}/run_info.json", "label/{t}/node_labels.csv",
                                 "label/{t}/event_labels.csv", "label/{t}/run_info.json", "stitch/{t}/path_nodes.csv"])
def test_a_missing_input_file_is_refused(repo, capsys, rel):
    (repo / "out" / rel.format(t=fx.TRIAL)).unlink()
    assert_refused_and_nothing_written(repo, capsys)


@pytest.mark.parametrize("rel,column", [("stitch/{t}/paths.csv", "hop_ids"), ("stitch/{t}/hops.csv", "best_tier"),
                                        ("stitch/{t}/hop_identity.csv", "order_ok"),
                                        ("label/{t}/node_labels.csv", "max_level_value"),
                                        ("label/{t}/event_labels.csv", "count_key")])
def test_a_missing_required_column_is_refused(tmp_path, capsys, rel, column):
    w = fx.base_world()
    repo = fx.build_repo(tmp_path / "r", w)
    # rewrite the file without the column and re-hash everything so only the column check can refuse it
    p = repo / "out" / rel.format(t=fx.TRIAL)
    rows = fx.read_rows(p)
    cols = [c for c in rows[0].keys() if c != column]
    p.write_bytes(fx.csv_bytes(cols, rows))
    _rehash(repo)
    assert_refused_and_nothing_written(repo, capsys)


def _rehash(repo: Path, trial: str = fx.TRIAL) -> None:
    """Make both run_info files describe the CSVs as they now are (so only a content check can refuse)."""
    sdir, ldir = repo / "out" / "stitch" / trial, repo / "out" / "label" / trial
    s_info = json.loads((sdir / "run_info.json").read_text(encoding="utf-8"))
    for n in s_info["files"]:
        s_info["files"][n]["sha256"] = fx.sha((sdir / n).read_bytes())
    (sdir / "run_info.json").write_text(json.dumps(s_info, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    l_info = json.loads((ldir / "run_info.json").read_text(encoding="utf-8"))
    for n in l_info["files"]:
        l_info["files"][n]["sha256"] = fx.sha((ldir / n).read_bytes())
    for n in l_info["stitch_files_sha256"]:
        l_info["stitch_files_sha256"][n] = fx.sha((sdir / n).read_bytes())
    (ldir / "run_info.json").write_text(json.dumps(l_info, indent=1, sort_keys=True) + "\n", encoding="utf-8")


@pytest.mark.parametrize("rel", ["stitch/{t}/paths.csv", "stitch/{t}/path_edges.csv", "stitch/{t}/hops.csv",
                                 "stitch/{t}/hop_identity.csv", "label/{t}/node_labels.csv",
                                 "label/{t}/event_labels.csv"])
def test_an_input_edited_after_its_run_info_was_written_is_refused(repo, capsys, rel):
    edit(repo / "out" / rel.format(t=fx.TRIAL), lambda b: b + b"\n")
    assert_refused_and_nothing_written(repo, capsys)


def test_a_stitch_rerun_after_labelling_is_refused_label_stitch_hashes_differ(repo, capsys):
    """Stitch files and the stitch run_info are consistent with each other, but the label run was made on other bytes."""
    sdir = repo / "out" / "stitch" / fx.TRIAL
    edit(sdir / "hops.csv", lambda b: b.replace(b"ep-02", b"ep-07"))
    s_info = json.loads((sdir / "run_info.json").read_text(encoding="utf-8"))
    s_info["files"]["hops.csv"]["sha256"] = fx.sha((sdir / "hops.csv").read_bytes())
    (sdir / "run_info.json").write_text(json.dumps(s_info), encoding="utf-8")
    assert_refused_and_nothing_written(repo, capsys)


def test_label_run_info_without_the_stitch_hash_list_is_refused(repo, capsys):
    p = repo / "out" / "label" / fx.TRIAL / "run_info.json"
    info = json.loads(p.read_text(encoding="utf-8"))
    info.pop("stitch_files_sha256")
    p.write_text(json.dumps(info), encoding="utf-8")
    assert_refused_and_nothing_written(repo, capsys)


def test_a_run_info_that_records_no_hash_for_a_file_is_refused(repo, capsys):
    p = repo / "out" / "stitch" / fx.TRIAL / "run_info.json"
    info = json.loads(p.read_text(encoding="utf-8"))
    info["files"].pop("hops.csv")
    p.write_text(json.dumps(info), encoding="utf-8")
    assert_refused_and_nothing_written(repo, capsys)


def test_label_files_that_disagree_are_refused(tmp_path, capsys):
    w = fx.base_world()
    w.events.append(fx.event("u_smb", "OTHER_KEY", 1))                  # one uid with two count_keys
    repo = fx.build_repo(tmp_path / "r1", w)
    assert_refused_and_nothing_written(repo, capsys)
    w = fx.base_world()
    w.events = [e for e in w.events if e["event_uid"] != "u_cp"]        # a labelled node with no event_labels row
    repo = fx.build_repo(tmp_path / "r2", w)
    assert_refused_and_nothing_written(repo, capsys)


def test_a_path_hop_missing_from_hops_or_identity_is_refused(tmp_path, capsys):
    w = fx.base_world()
    w.hops = [h for h in w.hops if h["hop_id"] != "h2"]
    assert_refused_and_nothing_written(fx.build_repo(tmp_path / "r1", w), capsys)
    w = fx.base_world()
    w.identity = [r for r in w.identity if r["hop_id"] != "h5"]
    assert_refused_and_nothing_written(fx.build_repo(tmp_path / "r2", w), capsys)


def test_a_repeated_path_id_is_refused(tmp_path, capsys):
    w = fx.base_world()
    w.paths.append(fx.path("p0001", "h2"))
    assert_refused_and_nothing_written(fx.build_repo(tmp_path / "r", w), capsys)


def test_a_changed_order_table_is_refused_by_the_pin(repo, capsys, monkeypatch, tmp_path):
    changed = tmp_path / "order_table.json"
    obj = json.loads(sp.ORDER_TABLE_FILE.read_text(encoding="utf-8"))
    obj["tactic_of"]["T1078"] = "persistence"
    changed.write_text(json.dumps(obj), encoding="utf-8")
    import score.order as od
    monkeypatch.setattr(od, "ORDER_TABLE_FILE", changed, raising=True)
    monkeypatch.setattr(od.load_order_table, "__defaults__", (changed, sp.ORDER_TABLE_SHA256))
    assert "order table" in assert_refused_and_nothing_written(repo, capsys)


# ------------------------------------------------------------------------------------------------ SC-03 runtime
def test_the_scorer_opens_no_database_and_no_ground_truth_or_data_path(repo, monkeypatch):
    def no_db(*a, **k):
        raise AssertionError("score opened a database")
    monkeypatch.setattr(sqlite3, "connect", no_db)
    opened: list[str] = []
    real_open, real_pio = builtins.open, pathlib.Path.open
    monkeypatch.setattr(builtins, "open", lambda f, *a, **k: (opened.append(str(f)), real_open(f, *a, **k))[1])
    monkeypatch.setattr(pathlib.Path, "open", lambda self, *a, **k: (opened.append(str(self)), real_pio(self, *a, **k))[1])
    real_rb = pathlib.Path.read_bytes
    monkeypatch.setattr(pathlib.Path, "read_bytes", lambda self: (opened.append(str(self)), real_rb(self))[1])
    run_trial(repo, fx.TRIAL, generated_utc=NOW)
    assert opened, "the spy saw no file at all"
    bad = [p for p in opened if re.search(r"ground_truth|[\\/]data[\\/]|\.sqlite", p.replace("\\", "/"))]
    assert not bad


# ------------------------------------------------------------------------------------------------ folder swap (SC-60), empty trial
def test_cli_leaves_no_tmp_or_old_sibling_folder_behind(repo):
    out = repo / "out" / "score_tmp"
    assert sm.main(cli(repo, out)) == 0
    assert sm.main(cli(repo, out)) == 0                              # a rerun replaces the folder (the .old swap)
    assert sorted(p.name for p in (repo / "out").iterdir() if p.name.startswith(("score", "."))) == ["score_tmp"]


def test_a_trial_with_no_path_writes_header_only_path_tables_and_does_not_crash(tmp_path):
    w = fx.base_world()
    w.paths, w.edges, w.nodes = [], [], []
    res = run_trial(fx.build_repo(tmp_path / "r", w), fx.TRIAL, generated_utc=NOW)
    assert rows_of(res, "ranked_paths.csv") == [] and rows_of(res, "path_steps.csv") == []
    assert header(res.files["ranked_paths.csv"]) == RANKED_COLS
    assert len(rows_of(res, "hop_identity_values.csv")) == 7            # every hop of hop_identity.csv (decision 067 item 9)
    assert {r["unit_id"] for r in rows_of(res, "b0_ranked.csv")} == {e["count_key"] for e in w.events}
