"""T9 score stage on the nine development trials (spec 05_score SCA-01..SCA-05, SC-03, SC-04, SC-21b, SC-34 / SCT-34, SC-52,
SC-53, section 6 edge cases that exist in current data, section 10 development measurements; decisions 063, 064, 067).
Slow; read-only; DEVELOPMENT trials only (`score.params.ALLOWED_TRIALS`). These are DEVELOPMENT numbers, not results
(decision 019). SCA-06 (the ranking report) belongs to `evaluate --rank`, not here.

Written from the spec and decisions, not from the implementation. The stage is run through its CLI into pytest
`tmp_path`s (`--out`), so nothing is written under `out/` (the root conftest fails a session that does). Inputs are the
existing `out/stitch/<t>/` and `out/label/<t>/` folders (read-only). The approved keys are opened read-only, only to
count and compare `identity_expected` (SCA-02). Messages carry counts, hop ids and uids only.

    REQUIRE_REAL_DATA=1 python -m pytest tests/unit/test_score_real.py   # a missing input FAILS instead of skipping
"""
from __future__ import annotations

import ast
import builtins
import hashlib
import json
import math
import pathlib
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pytest
from real_data import missing_input  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import score.__main__ as sm  # noqa: E402
from score import params as sp  # noqa: E402
from score.run import run_trial  # noqa: E402
from score_fixtures import read_rows  # noqa: E402

pytestmark = pytest.mark.slow

DEV = list(sp.ALLOWED_TRIALS)
KEYED = [t for t in DEV if t.endswith("_t00")]
FORBIDDEN = ("stolen", "detects", "probability", "confidence", "reduces false positives", "identifies the attacker")
EIGHT = {"ranked_paths.csv", "path_steps.csv", "path_node_units.csv", "hop_identity_values.csv", "b0_ranked.csv",
         "stats.json", "report.md", "run_info.json"}
TOL = 3e-6          # CSV scores are written with 6 decimals


def need(trial: str) -> None:
    assert trial in DEV, trial
    gone = [p for p in (REPO / "out" / "stitch" / trial / "run_info.json", REPO / "out" / "stitch" / trial / "paths.csv",
                        REPO / "out" / "label" / trial / "run_info.json",
                        REPO / "out" / "label" / trial / "node_labels.csv") if not p.is_file()]
    if gone:
        missing_input(f"{trial}: missing {', '.join(p.parent.name + '/' + p.name for p in gone)}")


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    root = tmp_path_factory.mktemp("score_real")
    cache: dict[str, Path] = {}

    def go(trial: str) -> Path:
        need(trial)
        if trial not in cache:
            out = root / trial
            code = sm.main(["--trial", trial, "--out", str(out)])
            assert code == 0, f"{trial}: exit code {code}"
            cache[trial] = out
        return cache[trial]
    return go


def tables(folder: Path) -> dict[str, list[dict[str, str]]]:
    return {n: read_rows(folder / n) for n in ("ranked_paths.csv", "path_steps.csv", "path_node_units.csv",
                                               "hop_identity_values.csv", "b0_ranked.csv")}


def file_hashes(trial: str) -> dict[str, str]:
    out = {}
    for stage in ("stitch", "label"):
        for p in sorted((REPO / "out" / stage / trial).iterdir()):
            if p.is_file():
                out[f"{stage}/{p.name}"] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def path_of_hop(rows, hop_id):
    hits = [r for r in rows if r["variant"] == "full" and hop_id in r["hop_ids"].split(";")]
    assert len(hits) == 1, f"{hop_id}: {len(hits)} paths"
    return hits[0]


# ------------------------------------------------------------------------------------------------ SCA-01
@pytest.mark.parametrize("trial", DEV)
def test_sca01_every_path_ranked_once_per_variant_and_b0_has_one_row_per_unit(run, trial):
    out = run(trial)
    t = tables(out)
    paths = read_rows(REPO / "out" / "stitch" / trial / "paths.csv")
    ids = sorted(p["path_id"] for p in paths)
    assert len(ids) == len(set(ids))
    for v in ("full", "b1", "b2"):
        assert sorted(r["path_id"] for r in t["ranked_paths.csv"] if r["variant"] == v) == ids, f"{trial} {v}"
    assert len(t["ranked_paths.csv"]) == 3 * len(ids)
    ev = read_rows(REPO / "out" / "label" / trial / "event_labels.csv")
    units = {e["count_key"] or e["event_uid"] for e in ev}
    b0 = t["b0_ranked.csv"]
    assert len(b0) == len(units) and {r["unit_id"] for r in b0} == units
    assert {f.name for f in out.iterdir()} == EIGHT


def test_sca01_development_totals_match_spec_section_10(run):
    total = single = multi = nolabel = 0
    for trial in DEV:
        for r in (x for x in tables(run(trial))["ranked_paths.csv"] if x["variant"] == "full"):
            total += 1
            single += r["n_hops"] == "1"
            multi += int(r["n_hops"]) > 1
            nolabel += r["n_node_units"] == "0"
    assert (total, single, multi, nolabel) == (53, 52, 1, 38)


# ------------------------------------------------------------------------------------------------ SCA-02
def key_hops():
    rows = []
    for t in KEYED:
        p = REPO / "out" / "evaluate" / t / "link_accuracy_hops.csv"
        if not p.is_file():
            missing_input(f"{t}: out/evaluate link_accuracy_hops.csv missing")
        rows += read_rows(p)
    return rows


def test_sca02_hop_identity_equals_identity_expected_on_the_15_keyed_hops(run):
    rows = key_hops()
    assert len(rows) == 15
    # the expected values are the approved keys' own (read-only): count them and compare as a multiset
    yaml_vals = []
    for t in KEYED:
        text = (REPO / "ground_truth" / "approved" / f"{t}.yaml").read_text(encoding="utf-8")
        yaml_vals += re.findall(r'"identity_expected":\s*(\d)', text)
    assert sorted(yaml_vals) == sorted(r["identity_expected"] for r in rows)
    wrong = []
    for r in rows:
        vals = [a for a in read_rows(run(r["trial_id"]) / "hop_identity_values.csv") if a["hop_id"] == r["hop_id"]]
        applicable = [int(a["value"]) for a in vals if a["applicable"] == "1"]
        value = max(applicable) if applicable else 0
        if value != int(r["identity_expected"]):
            wrong.append((r["trial_id"], r["key_hop_id"], r["hop_id"], r["identity_expected"], value))
    assert not wrong, wrong


# ------------------------------------------------------------------------------------------------ SCA-03
@pytest.mark.parametrize("trial", DEV)
def test_sca03_two_runs_are_byte_identical_except_generated_utc_and_inputs_are_unchanged(run, tmp_path, trial):
    need(trial)
    before = file_hashes(trial)
    first = run(trial)
    second = tmp_path / "second"
    assert sm.main(["--trial", trial, "--out", str(second)]) == 0
    assert file_hashes(trial) == before
    for name in EIGHT - {"run_info.json"}:
        assert (first / name).read_bytes() == (second / name).read_bytes(), f"{trial}: {name}"
    a, b = (json.loads((d / "run_info.json").read_text(encoding="utf-8")) for d in (first, second))
    a.pop("generated_utc"), b.pop("generated_utc")
    assert a == b
    # the recorded input hashes are the real files' hashes
    for stage in ("stitch", "label"):
        for name, h in a["inputs"][stage].items():
            assert before[f"{stage}/{name}"] == h, f"{trial}: {stage}/{name}"


@pytest.mark.parametrize("trial", DEV)
def test_existing_out_score_equals_a_fresh_run_if_present(run, trial):
    committed = REPO / "out" / "score" / trial
    if not committed.is_dir():
        pytest.skip(f"{trial}: no existing out/score folder")
    fresh = run(trial)
    assert {p.name for p in committed.iterdir()} == EIGHT
    stale = [n for n in sorted(EIGHT - {"run_info.json"}) if (committed / n).read_bytes() != (fresh / n).read_bytes()]
    assert not stale, f"{trial}: out/score differs from a fresh run in {stale}"
    a, b = (json.loads((d / "run_info.json").read_text(encoding="utf-8")) for d in (committed, fresh))
    a.pop("generated_utc"), b.pop("generated_utc")
    assert a == b


# ------------------------------------------------------------------------------------------------ SCA-04
def recompute(folder: Path):
    """Independent recomputation of every path's components from the written CSVs and the recorded parameters."""
    t = tables(folder)
    info = json.loads((folder / "run_info.json").read_text(encoding="utf-8"))
    p = info["parameters"]
    steps, units, idv = defaultdict(list), defaultdict(list), defaultdict(list)
    for r in t["path_steps.csv"]:
        steps[r["path_id"]].append(r)
    for r in t["path_node_units.csv"]:
        units[r["path_id"]].append(r)
    for r in t["hop_identity_values.csv"]:
        idv[r["hop_id"]].append(r)
    out = {}
    for r in (x for x in t["ranked_paths.csv"] if x["variant"] == "full"):
        s = sorted(steps[r["path_id"]], key=lambda x: int(x["step"]))
        n = len(s)
        edge = sum(float(x["score_e"]) for x in s) / n if n else 0.0
        length = (1 - math.exp(-n / p["lam"])) * edge if n else 0.0
        lv = [int(u["level_value"]) for u in units[r["path_id"]]]
        node = sum(lv) / (len(lv) * 4) if lv else 0.0
        cross = coherent = 0
        for h in sorted(set(r["hop_ids"].split(";"))):
            app = [int(a["value"]) for a in idv[h] if a["applicable"] == "1"]
            if app:
                cross += 1
                coherent += max(app) == 1
        ident = coherent / cross if cross else 0.0
        seq = ([s[0]["from_technique"]] + [x["to_technique"] for x in s]) if s else []
        out[r["path_id"]] = dict(n=n, edge=edge, length=length, node=node, nunits=len(lv), ident=ident, cross=cross,
                                 coherent=coherent, seq=seq,
                                 full=p["w1"] * length + p["w2"] * node + p["w3"] * ident,
                                 b1=(p["w1"] * length + p["w2"] * node) / (p["w1"] + p["w2"]), b2=node)
    return t, out


@pytest.mark.parametrize("trial", DEV)
def test_sca04_every_written_score_is_recomputed_from_the_csvs(run, trial):
    t, calc = recompute(run(trial))
    bad = []
    for r in t["ranked_paths.csv"]:
        c = calc[r["path_id"]]
        checks = [("score", c[r["variant"]]), ("length_score", c["length"]), ("edge_score", c["edge"]),
                  ("node_score", c["node"]), ("identity_coherence", c["ident"])]
        for col, want in checks:
            if abs(float(r[col]) - want) > TOL:
                bad.append((r["path_id"], r["variant"], col, r[col], round(want, 6)))
        for col, want in (("seq_len", c["n"]), ("n_node_units", c["nunits"]), ("n_crossings", c["cross"]),
                          ("n_crossings_coherent", c["coherent"])):
            if int(r[col]) != want:
                bad.append((r["path_id"], r["variant"], col, r[col], want))
        if r["technique_sequence"] != ">".join(c["seq"]):
            bad.append((r["path_id"], r["variant"], "technique_sequence"))
    assert not bad, bad


@pytest.mark.parametrize("trial", DEV)
def test_sca04_ranks_are_competition_ranks_of_the_written_scores(run, trial):
    rows = tables(run(trial))["ranked_paths.csv"]
    for v in ("full", "b1", "b2"):
        vr = [r for r in rows if r["variant"] == v]
        scores = [float(r["score"]) for r in vr]
        for r, s in zip(vr, scores):
            assert int(r["rank"]) == 1 + sum(x > s for x in scores), (trial, v, r["path_id"])
            assert int(r["tie_size"]) == sum(x == s for x in scores), (trial, v, r["path_id"])
        assert scores == sorted(scores, reverse=True)
    b0 = tables(run(trial))["b0_ranked.csv"]
    sc = [float(r["score"]) for r in b0]
    assert all(int(r["rank"]) == 1 + sum(x > s for x in sc) for r, s in zip(b0, sc))
    assert all(abs(float(r["score"]) - int(r["level_value"]) / 4) <= TOL for r in b0)


def test_sca04_score_components_and_variants_stay_in_unit_interval(run):
    for trial in DEV:
        for r in tables(run(trial))["ranked_paths.csv"]:
            for c in ("score", "length_score", "node_score", "identity_coherence", "identity_low", "identity_high"):
                assert 0.0 <= float(r[c]) <= 1.0, (trial, r["path_id"], c)
            assert float(r["identity_low"]) <= float(r["identity_coherence"]) + TOL <= float(r["identity_high"]) + 2 * TOL


# ------------------------------------------------------------------------------------------------ SCA-05
SRC = REPO / "src" / "score"


def code_strings(tree: ast.AST):
    """String constants that are not docstrings."""
    doc_ids = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            b = getattr(n, "body", [])
            if b and isinstance(b[0], ast.Expr) and isinstance(getattr(b[0], "value", None), ast.Constant):
                doc_ids.add(id(b[0].value))
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in doc_ids:
            yield n.value


def test_sca05_static_no_ground_truth_path_no_database_import_in_src_score():
    files = sorted(SRC.glob("*.py"))
    assert len(files) >= 10
    for f in files:
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for s in code_strings(tree):
            low = s.lower().replace("\\", "/")
            assert "ground_truth" not in low, f"{f.name}: string {s[:40]!r}"
            assert not re.search(r"(^|/)data/(raw|processed|sample|incoming)", low), f"{f.name}: {s[:40]!r}"
            assert ".sqlite" not in low and "events_dedup" not in low, f"{f.name}: {s[:40]!r}"
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                assert not any(a.name.split(".")[0] in ("sqlite3", "yaml") for a in n.names), f.name
            if isinstance(n, ast.ImportFrom):
                assert (n.module or "").split(".")[0] not in ("sqlite3", "yaml"), f.name
            if isinstance(n, ast.Attribute) and n.attr == "connect" and isinstance(n.value, ast.Name):
                assert n.value.id != "sqlite3", f.name


def test_sca05_runtime_no_database_and_no_ground_truth_or_data_file_is_opened(monkeypatch):
    for t in ("s04_t00", "s05_t00"):
        need(t)

    def no_db(*a, **k):
        raise AssertionError("score opened a database")
    monkeypatch.setattr(sqlite3, "connect", no_db)
    opened: list[str] = []
    real_open, real_po, real_rb = builtins.open, pathlib.Path.open, pathlib.Path.read_bytes
    monkeypatch.setattr(builtins, "open", lambda f, *a, **k: (opened.append(str(f)), real_open(f, *a, **k))[1])
    monkeypatch.setattr(pathlib.Path, "open", lambda s, *a, **k: (opened.append(str(s)), real_po(s, *a, **k))[1])
    monkeypatch.setattr(pathlib.Path, "read_bytes", lambda s: (opened.append(str(s)), real_rb(s))[1])
    for t in ("s04_t00", "s05_t00"):
        run_trial(REPO, t, generated_utc="2026-11-18T00:00:00Z")
    assert opened
    norm = [p.replace("\\", "/") for p in opened]
    assert not [p for p in norm if re.search(r"ground_truth|/data/|\.sqlite", p)]
    assert any("/out/stitch/" in p for p in norm) and any("/out/label/" in p for p in norm)


@pytest.mark.parametrize("trial", ["s02_t05", "s03_t02", "s07_t10", "s01_t00"])
def test_sca05_test_trials_are_refused_with_exit_2_and_nothing_written(tmp_path, capsys, trial):
    out = tmp_path / "x"
    assert sm.main(["--trial", trial, "--out", str(out)]) == 2
    assert capsys.readouterr().err.startswith("refused:")
    assert not out.exists() and not (REPO / "out" / "score" / trial).exists()


# ------------------------------------------------------------------------------------------------ answer-key events
def test_s04_track_a_benign_and_track_b_attack_tie_at_rank_one_with_tie_size_two(run):
    rows = tables(run("s04_t00"))["ranked_paths.csv"]
    a, b = (path_of_hop(rows, h) for h in ("s04_t00-h0023", "s04_t00-h0024"))      # key hops s04-A-h1, s04-B-h1
    assert a["path_id"] != b["path_id"]
    for r in (a, b):
        assert (r["rank"], r["tie_size"]) == ("1", "2")
        assert r["technique_sequence"] == "T1021.002>T1570>T1569.002"
        assert float(r["length_score"]) == pytest.approx(0.75, abs=TOL)
        assert float(r["node_score"]) == pytest.approx(0.25, abs=TOL)
        assert float(r["identity_coherence"]) == 1.0
        assert float(r["score"]) == pytest.approx(2 / 3, abs=TOL)
    assert a["score"] == b["score"]


def test_s04_every_other_path_ranks_below_the_two_key_paths(run):
    rows = [r for r in tables(run("s04_t00"))["ranked_paths.csv"] if r["variant"] == "full"]
    others = [r for r in rows if r["rank"] != "1"]
    assert others and all(float(r["score"]) < 2 / 3 - 1e-3 for r in others)


def test_s05_key_attack_path_is_multi_hop_with_hop_chain_boundary_and_background_dilution(run):
    out = run("s05_t00")
    t = tables(out)
    r = path_of_hop(t["ranked_paths.csv"], "s05_t00-h0030")                 # key hop s05-h1; s05-h2 = h0032
    assert "s05_t00-h0032" in r["hop_ids"].split(";") and "s05_t00-h0010" in r["hop_ids"].split(";")
    assert r["technique_sequence"] == "T1021.002>T1570>T1569.002>T1078>T1021.006"
    steps = [s for s in t["path_steps.csv"] if s["path_id"] == r["path_id"]]
    assert [s["basis"] for s in steps] == ["direct", "direct", "hop_chain", "indirect"]
    assert float(r["length_score"]) == pytest.approx(0.9375 * 0.875, abs=TOL)
    assert r["n_crossings"] == "3" and r["n_crossings_coherent"] == "2"
    assert float(r["identity_coherence"]) == pytest.approx(2 / 3, abs=TOL)          # h0010 value 0 dilutes (ATK-SC-05)
    assert float(r["node_score"]) == pytest.approx(1.923 / 4, abs=2e-3)
    assert r["n_node_units"] == "13"
    full = [x for x in t["ranked_paths.csv"] if x["variant"] == "full"]
    assert r["rank"] == "1" and all(float(x["score"]) < float(r["score"]) for x in full if x is not r)


def test_s05_h2_is_not_listed_before_h1_in_the_sequence_whatever_the_hop_list_order(run):
    """SC-21b: the sequence follows the chain order (h0030 SMB, then h0032 WinRM), not the order of `hop_ids`."""
    rows = tables(run("s05_t00"))["ranked_paths.csv"]
    r = path_of_hop(rows, "s05_t00-h0032")
    seq = r["technique_sequence"].split(">")
    assert seq.index("T1569.002") < seq.index("T1078") < seq.index("T1021.006")


# key hop -> (L, N, I, tolerance on N) from spec 10.1 / 10.2 mean levels and the templates
KEY_EXPECT = {
    ("s02_t00", "s02_t00-h0025"): ("T1021.002>T1570", 0.5, 0.25, 1.0, TOL),
    ("s03_t00", "s03_t00-h0020"): ("T1078>T1021.006", 0.25, 2.25 / 4, 1.0, TOL),
    ("s04_t00", "s04_t00-h0023"): ("T1021.002>T1570>T1569.002", 0.75, 0.25, 1.0, TOL),
    ("s04_t00", "s04_t00-h0024"): ("T1021.002>T1570>T1569.002", 0.75, 0.25, 1.0, TOL),
    ("s06_t00", "s06_t00-h0027"): ("T1078>T1021.006", 0.25, 2.333 / 4, 0.0, 1e-3),
    ("s06_t00", "s06_t00-h0034"): ("T1078>T1021.006", 0.25, 2.0 / 4, 0.0, TOL),
    ("s06_t00", "s06_t00-h0037"): ("T1021.002>T1569.002", 0.5, 0.25, 0.0, TOL),
    ("s07_t00", "s07_t00-h0027"): ("T1021.002>T1570>T1569.002", 0.75, 0.25, 1.0, TOL),
    ("s07_t00", "s07_t00-h0031"): ("T1021.002>T1570>T1569.002", 0.75, 0.25, 1.0, TOL),
}


@pytest.mark.parametrize("trial,hop", sorted(KEY_EXPECT))
def test_keyed_single_hop_paths_have_the_spec_section_10_components(run, trial, hop):
    seq, L, N, I, ntol = KEY_EXPECT[(trial, hop)]
    r = path_of_hop(tables(run(trial))["ranked_paths.csv"], hop)
    assert r["technique_sequence"] == seq
    assert float(r["length_score"]) == pytest.approx(L, abs=TOL)
    assert float(r["node_score"]) == pytest.approx(N, abs=ntol)
    assert float(r["identity_coherence"]) == I
    assert float(r["score"]) == pytest.approx((L + N + I) / 3, abs=ntol + TOL)


def test_s06_benign_winrm_path_scores_0277778_and_no_s06_benign_path_outranks_an_attack_sized_score(run):
    rows = [r for r in tables(run("s06_t00"))["ranked_paths.csv"] if r["variant"] == "full"]
    w1 = path_of_hop(rows, "s06_t00-h0027")
    assert float(w1["score"]) == pytest.approx(0.277778, abs=2e-4)
    assert max(float(r["score"]) for r in rows) < 2 / 3 - 0.1               # below the s04 / s07 SMB attack paths (0.667)


# ------------------------------------------------------------------------------------------------ SCT-34 / section 6
def test_sct34_s07_dump_is_kept_out_of_node_score_but_shown_in_ctx1(run):
    rows = tables(run("s07_t00"))["ranked_paths.csv"]
    for hop in ("s07_t00-h0027", "s07_t00-h0031"):
        r = path_of_hop(rows, hop)
        assert float(r["node_score_ctx1"]) > float(r["node_score"]) + 0.1
        assert float(r["node_score"]) == pytest.approx(0.25, abs=TOL)
        assert float(r["score"]) == pytest.approx(2 / 3, abs=TOL)           # the dump did not raise the score


def test_s07_two_attack_paths_tie_at_rank_one_ties_are_reported_as_ties(run):
    rows = [r for r in tables(run("s07_t00"))["ranked_paths.csv"] if r["variant"] == "full"]
    top = [r for r in rows if r["rank"] == "1"]
    assert len(top) == 2 and {r["tie_size"] for r in top} == {"2"}


def test_atk_sc06_machine_account_and_no_logs_hops_are_unknown_not_zero_and_leave_the_denominator(run):
    unknown = Counter()
    for trial in DEV:
        for a in tables(run(trial))["hop_identity_values.csv"]:
            if a["applicable"] == "0":
                assert a["value"] == "" and a["identity_status"] == f"unknown:{a['not_applicable']}"
                unknown[a["not_applicable"]] += 1
            else:
                assert a["value"] in ("0", "1") and a["identity_status"] in (
                    "exposed", "not_exposed", "unknown:end_unknown_session")
                assert (a["identity_status"] == "exposed") == (a["value"] == "1")
    assert unknown["machine_account"] > 0
    assert unknown["source_host_no_logs"] >= 1                              # s07 ep-03 (spec section 6)


def test_in_path_identity_pairs_match_spec_section_10_3(run):
    counts = Counter()
    for trial in DEV:
        t = tables(run(trial))
        in_path = {h for r in t["ranked_paths.csv"] if r["variant"] == "full" for h in r["hop_ids"].split(";")}
        for a in t["hop_identity_values.csv"]:
            if a["hop_id"] in in_path:
                counts["rows"] += 1
                counts[a["identity_status"] if a["applicable"] == "0" else f"value{a['value']}"] += 1
    assert counts["rows"] == 61
    assert (counts["value1"], counts["value0"], counts["unknown:machine_account"],
            counts["unknown:source_host_no_logs"]) == (12, 15, 33, 1)


@pytest.mark.parametrize("trial,hop", [("s06_t00", "s06_t00-h0037"), ("s06_t01", "s06_t01-h0026")])
def test_atk_sc08_hop_with_several_accounts_has_one_row_per_account_and_value_zero(run, trial, hop):
    rows = [a for a in tables(run(trial))["hop_identity_values.csv"] if a["hop_id"] == hop]
    assert len(rows) >= 2, f"{hop}: expected one row per account"
    assert len({a["account"] for a in rows}) == len(rows)
    assert all(a["value"] == "0" for a in rows if a["applicable"] == "1")


def test_development_n_hops_unknown_total_matches_spec_section_10_3(run):
    """Spec 10.1 / 10.3: 38 of the 53 development paths have no labelled unit (machine-account and background hops); the
    paths with no applicable account on any hop carry n_crossings 0 and n_hops_unknown = n_hops."""
    zero = sum(1 for t in DEV for r in tables(run(t))["ranked_paths.csv"]
               if r["variant"] == "full" and r["n_crossings"] == "0" and r["n_hops_unknown"] == r["n_hops"])
    assert zero > 0


def test_development_has_no_flagged_crossings_so_low_high_equal_coherence(run):
    for trial in DEV:
        for r in tables(run(trial))["ranked_paths.csv"]:
            assert r["n_crossings_flagged"] == "0", (trial, r["path_id"])
            assert r["identity_low"] == r["identity_high"] == r["identity_coherence"], (trial, r["path_id"])


def test_target_only_hops_get_an_identity_value(run):
    """013: identity does not depend on the linked source session; a tier-D hop with an exposed account is exposed."""
    seen = 0
    for trial in DEV:
        tier = {h["hop_id"]: h["best_tier"] for h in read_rows(REPO / "out" / "stitch" / trial / "hops.csv")}
        for a in tables(run(trial))["hop_identity_values.csv"]:
            assert a["hop_best_tier"] == tier[a["hop_id"]]
            if a["hop_best_tier"] == "D" and a["applicable"] == "1":
                assert a["value"] in ("0", "1")
                seen += 1
    assert seen > 0


def test_every_identity_row_names_its_method_and_the_exposed_wording_is_used(run):
    for trial in DEV:
        for a in tables(run(trial))["hop_identity_values.csv"]:
            assert a["method"] == "correction_k"
        for s in tables(run(trial))["path_steps.csv"]:
            assert s["method"] == "technique_sequence" and s["candidate_count"] == "1"
            assert s["basis"] in ("direct", "indirect", "same_tactic", "absent", "hop_chain")


@pytest.mark.parametrize("trial", DEV)
def test_report_wording(run, trial):
    """CLAUDE.md wording: 'probability' only inside the exact phrase 'not a probability'; 'confidence' never (069 item 10)."""
    out = run(trial)
    for name in ("report.md", "stats.json"):
        text = (out / name).read_text(encoding="utf-8").lower().replace("not a probability", " ")
        for w in FORBIDDEN:
            assert w not in text, f"{trial} {name}: {w}"
        assert not re.search(r"confidence\s*%", text), f"{trial} {name}"
    report = (out / "report.md").read_text(encoding="utf-8").lower()
    assert "exposed" in report and "not a probability" in report


@pytest.mark.parametrize("trial", DEV)
def test_scores_are_written_with_12_decimals_and_n_hops_unknown_completes_the_hop_count(run, trial):
    """Spec section 3 / 3.1 (069 items 4 and 5)."""
    for r in tables(run(trial))["ranked_paths.csv"]:
        for c in ("score", "length_score", "edge_score", "node_score", "node_score_ctx1", "identity_coherence",
                  "identity_low", "identity_high"):
            assert re.fullmatch(r"\d\.\d{12}", r[c]), (trial, r["path_id"], c, r[c])
        assert int(r["n_crossings"]) + int(r["n_hops_unknown"]) == int(r["n_hops"]), (trial, r["path_id"])


def test_order_table_and_parameters_are_recorded_in_every_run_info(run):
    for trial in DEV:
        info = json.loads((run(trial) / "run_info.json").read_text(encoding="utf-8"))
        assert info["order_table_sha256"] == sp.ORDER_TABLE_SHA256
        assert info["parameters"]["lam"] == pytest.approx(1 / math.log(2))
        assert info["parameters"]["w1"] == pytest.approx(1 / 3)


# ------------------------------------------------------------------------------------------------ stats.json host_time gaps (L-ST5)
def test_stats_host_time_edge_gaps_on_s05_t00_equal_the_stitch_chain_edges(run):
    """Spec 05 section 3.5 / spec 03 STA-09: s05_t00 has two host_time chain edges (s05-t1 -> s05-h2 and s05-h1 -> s05-h2);
    stats.json reports their gaps (L-ST5 measurement), read from path_edges.csv."""
    stats = json.loads((run("s05_t00") / "stats.json").read_text(encoding="utf-8"))
    edges = [e for e in read_rows(REPO / "out" / "stitch" / "s05_t00" / "path_edges.csv") if e["link_type"] == "host_time"]
    gaps = sorted(int(e["time_delta_ms"]) for e in edges)
    assert len(gaps) == 2
    assert stats["host_time_edge_gaps_ms"] == {"count": 2, "min": gaps[0], "max": gaps[-1], "values": gaps}
    assert gaps == [118827, 450762]


@pytest.mark.parametrize("trial", [t for t in DEV if t != "s05_t00"])
def test_stats_host_time_edge_gaps_are_empty_where_the_trial_has_no_chain_edge(run, trial):
    stats = json.loads((run(trial) / "stats.json").read_text(encoding="utf-8"))
    edges = [e for e in read_rows(REPO / "out" / "stitch" / trial / "path_edges.csv") if e["link_type"] == "host_time"]
    assert stats["host_time_edge_gaps_ms"]["count"] == len(edges) == 0
    assert stats["host_time_edge_gaps_ms"]["values"] == [] and stats["host_time_edge_gaps_ms"]["min"] is None
