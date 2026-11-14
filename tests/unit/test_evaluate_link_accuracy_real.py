"""Real-data acceptance for T7.6 (spec 03_stitch STA-05..STA-08, decision 051 prototype numbers, decision 044 kill
criteria, decision 014) on the nine development trials. Slow; read-only; parametrised over
`clock_offset.params.DEVELOPMENT_TRIALS` only, never t02-t10. These are DEVELOPMENT numbers, not results (decision 019).

Written from the spec and decision 051, not from the implementation (the code was read only for its public entry points:
`evaluate.evaluate_trial`, `evaluate.__main__.main` and, for STA-07, the stitcher's `run_links_checked`, `build_files`,
`replace_folder`, `StitchParams`).

Writes: only into pytest `tmp_path`s (the STA-07 harness runs the stitcher into a temp folder and the accuracy module on
it). Nothing is written under `out/`, `ground_truth/` or `data/`. The keys are read by the module under test; the tests
only read the baseline `out/evaluate_check/t76_baseline.json` and the existing `out/stitch/<trial>/` folders.
Messages carry counts, hop ids and uids only, never command text.
"""
from __future__ import annotations

import csv
import dataclasses
import functools
import hashlib
import io
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

import evaluate  # noqa: E402
from evaluate import __main__ as em  # noqa: E402
from clock_offset import params as co_params  # noqa: E402
from stitch.__main__ import build_files, replace_folder  # noqa: E402
from stitch.links import run_links_checked  # noqa: E402
from stitch.params import StitchParams  # noqa: E402

pytestmark = pytest.mark.slow

DEV = list(co_params.DEVELOPMENT_TRIALS)
DEV_T00 = [t for t in DEV if t.endswith("_t00")]
DEV_T01 = [t for t in DEV if t.endswith("_t01")]
KEYED = "link_accuracy_hops.csv"
BASELINE = REPO / "out" / "evaluate_check" / "t76_baseline.json"
VERDICT_COLUMNS = ("among_candidates", "rank1", "only_candidate", "target_only_ok", "identity_match", "match",
                   "expected_target_only")


def sha256_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _missing(trial: str) -> str | None:
    assert trial in DEV, trial                         # belt and braces: development trials only
    if not (REPO / "out" / "stitch" / trial / "run_info.json").is_file():
        return f"{trial}: out/stitch folder missing"
    if not (REPO / "data" / "processed" / f"{trial}.sqlite3").is_file():
        return f"{trial}: trial DB missing"
    return None


@functools.lru_cache(maxsize=None)
def _evaluated(trial: str):
    if _missing(trial):
        return None
    return evaluate.evaluate_trial(REPO, trial, "development", REPO / "out" / "stitch" / trial)


def result(trial: str):
    got = _evaluated(trial)
    if got is None:
        pytest.skip(_missing(trial))
    return got


def keyed_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for t in DEV_T00:
        rows += list(result(t).keyed_rows)
    return rows


def by_key(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    return {r["key_hop_id"]: r for r in rows}


# ================================================================================================ STA-05
def test_sta05_all_15_key_hops_match_exactly_one_stitch_hop():
    rows = keyed_rows()
    assert len(rows) == 15
    assert [r["key_hop_id"] for r in rows if r["match"] != "matched"] == []
    assert all(r["hop_id"] and ";" not in r["hop_id"] for r in rows)
    # key_logons_in_hop is `n/m` with n >= 1 (the matched logon itself is a member)
    for r in rows:
        n, m = (int(x) for x in r["key_logons_in_hop"].split("/"))
        assert 1 <= n <= m, (r["key_hop_id"], r["key_logons_in_hop"])
    print("\nkey_logons_in_hop:", {r["key_hop_id"]: r["key_logons_in_hop"] for r in rows})


def test_sta05_eleven_key_hops_with_a_key_session_all_correct():
    rows = keyed_rows()
    withs = [r for r in rows if r["expected_target_only"] == "0"]
    assert len(withs) == 11
    assert sum(r["among_candidates"] == "1" for r in withs) == 11
    assert Counter(r["rank1"] for r in withs) == {"correct": 11}
    assert all(r["rank1_sessions_hex"] == r["key_sessions_hex"] and r["key_sessions_hex"] for r in withs)


def test_sta05_only_candidate_9_of_11_the_two_exceptions_are_the_s04_pair():
    withs = [r for r in keyed_rows() if r["expected_target_only"] == "0"]
    only = [r for r in withs if r["only_candidate"] == "1"]
    notonly = [r for r in withs if r["only_candidate"] != "1"]
    assert len(only) == 9
    assert sorted(r["key_hop_id"] for r in notonly) == ["s04-A-h1", "s04-B-h1"]
    assert all(r["candidate_count"] == "2" for r in notonly)
    a, b = (next(r for r in notonly if r["key_hop_id"] == k) for k in ("s04-A-h1", "s04-B-h1"))
    # S04: track A's first-ranked session is not track B's, and the reverse
    assert a["rank1_sessions_hex"] != b["rank1_sessions_hex"]
    assert a["rank1_sessions_hex"] == a["key_sessions_hex"] and b["rank1_sessions_hex"] == b["key_sessions_hex"]
    assert a["key_sessions_hex"] not in b["rank1_sessions_hex"] and b["key_sessions_hex"] not in a["rank1_sessions_hex"]


def test_sta05_session_compare_is_by_4624_uid_on_all_11_and_the_key_uid_source():
    withs = [r for r in keyed_rows() if r["expected_target_only"] == "0"]
    assert Counter(r["session_compare"] for r in withs) == {"logon_uid": 11}          # 051 kill criteria
    src = Counter(r["key_session_uid_source"] for r in withs)
    assert src == {"direct": 1, "lookup": 10}
    assert [r["key_hop_id"] for r in withs if r["key_session_uid_source"] == "direct"] == ["s04-A-h1"]


def test_sta05_tiers_winrm_a_apart_from_b_and_smb_b():
    withs = [r for r in keyed_rows() if r["expected_target_only"] == "0"]
    winrm = [r for r in withs if r["protocol_group"] == "winrm"]
    smb = [r for r in withs if r["protocol_group"] == "smb"]
    assert len(winrm) == 4 and len(smb) == 7
    assert sorted(r["key_hop_id"] for r in winrm if r["key_session_tier"] == "A") == ["s03-h1", "s05-h2", "s06-winrm-1"]
    assert [r["key_hop_id"] for r in winrm if r["key_session_tier"] == "B"] == ["s06-winrm-2"]
    assert Counter(r["key_session_tier"] for r in smb) == {"B": 7}
    # tier A rows were found by the port join; tier B on SMB by the command-line rule
    assert all("sysmon3_port" in r["key_session_methods"] for r in winrm if r["key_session_tier"] == "A")
    assert all("cmdline_target" in r["key_session_methods"] for r in smb)


def test_sta05_port_and_command_line_agree_on_every_user_endpoint_hop_that_has_both():
    facts = [f for t in DEV for f in result(t).fact_rows if f["user_e2e"] == "1"]
    both = [f for f in facts if f["port_cmd_agree"] in ("yes", "no")]
    assert len(both) == 6, Counter(f["port_cmd_agree"] for f in facts)
    assert [f["hop_id"] for f in both if f["port_cmd_agree"] != "yes"] == []
    # of those, the keyed WinRM hops with a Sysmon 3 are among them
    keyed = by_key(keyed_rows())
    assert {k for k, r in keyed.items() if r["port_cmd_agree"] == "yes"} == {"s03-h1", "s05-h2", "s06-winrm-1"}
    assert keyed["s06-winrm-2"]["port_cmd_agree"] == "n_a"                    # no Sysmon 3 for that hop


# ================================================================================================ STA-06
def test_sta06_four_background_key_hops_are_target_only_tier_d():
    bg = [r for r in keyed_rows() if r["expected_target_only"] == "1"]
    assert sorted(r["key_hop_id"] for r in bg) == ["s04-t1", "s05-t1", "s06-t1", "s07-t1"]
    for r in bg:
        assert r["match"] == "matched" and r["target_only_ok"] == "1", r["key_hop_id"]
        assert r["best_tier"] == "D" and r["target_only_reason"] == "no_evidence_in_range", r["key_hop_id"]
        assert r["candidate_count"] == "0"
        assert r["among_candidates"] == r["rank1"] == r["only_candidate"] == ""


def test_sta06_evidence_before_range_on_the_two_key_hops():
    keyed = by_key(keyed_rows())
    assert int(keyed["s06-smb-1"]["evidence_before_range"]) == 6
    assert int(keyed["s07-h-y"]["evidence_before_range"]) == 4
    assert int(keyed["s06-smb-1"]["evidence_before_range"]) > 0
    # the rest of the keyed hops have none
    others = {k: r["evidence_before_range"] for k, r in keyed.items() if k not in ("s06-smb-1", "s07-h-y")}
    print("\nevidence_before_range of the other key hops:", {k: v for k, v in others.items() if v not in ("", "0")})


@pytest.mark.parametrize("trial", DEV_T01)
def test_sta06_t01_trials_have_facts_and_totals_but_no_verdicts(trial):
    res = result(trial)
    assert res.keyed_rows is None and KEYED not in res.files
    assert res.fact_rows and "link_accuracy_totals.csv" in res.files
    assert all(c not in res.fact_rows[0] for c in VERDICT_COLUMNS)
    assert {t["scope"] for t in res.total_rows} == {"all_hops", "user_e2e_hops"}
    assert all(f["key_hop_id"] == "" and f["split"] == "development" for f in res.fact_rows)
    assert res.headline["keyed"] is False


def test_sta06_s02_t01_05_34_09_group_is_reported_in_facts_target_only_with_its_identity_value():
    res = result("s02_t01")
    with open(REPO / "out" / "stitch" / "s02_t01" / "hops.csv", encoding="utf-8", newline="") as fh:
        hops = list(csv.DictReader(fh))
    found = [h for h in hops if "T05:34:09" in h["first_utc"] and h["member_accounts"] == "admin_it"
             and h["source_host"] == "ep-01" and h["target_host"] == "ep-02"]
    assert len(found) == 1, [h["hop_id"] for h in found]
    f = next(r for r in res.fact_rows if r["hop_id"] == found[0]["hop_id"])
    assert f["best_tier"] == "D" and f["target_only_reason"] == "no_evidence_in_range"
    assert int(f["evidence_before_range"]) > 0
    assert f["identity_values"] == "admin_it=1"                                  # identity does not use the link (013)
    assert f["user_e2e"] == "1"
    assert all(c not in f for c in VERDICT_COLUMNS)


# ================================================================================================ STA-08
def test_sta08_identity_matches_the_key_on_all_15_and_no_q9_dependence():
    rows = keyed_rows()
    assert Counter(r["identity_match"] for r in rows) == {"1": 15}
    assert not [r for r in rows if r["identity_value"] == "q9_dependent"]
    assert not [r for r in rows if r["identity_not_applicable"]]
    for r in rows:
        assert r["identity_expected"] in ("0", "1") and r["identity_value"] == r["identity_expected"], r["key_hop_id"]
    # no keyed hop is within the tolerance of a dump or inside the uncertainty band
    assert [r["key_hop_id"] for r in rows if r["identity_order_within_tolerance"] not in ("", "0")] == []
    assert [r["key_hop_id"] for r in rows if r["identity_order_within_uncertainty"] not in ("", "0")] == []


def test_the_t00_headlines_agree_with_the_rows():
    h = {t: result(t).headline for t in DEV_T00}
    assert sum(x["key_hops"] for x in h.values()) == 15
    assert sum(x["matched"] for x in h.values()) == 15
    assert sum(x["with_key_session"] for x in h.values()) == 11
    assert sum(x["among"] for x in h.values()) == 11
    assert sum(x["rank1_correct"] for x in h.values()) == 11
    assert sum(x["only_candidate"] for x in h.values()) == 9
    assert sum(x["background_target_only_ok"] for x in h.values()) == 4
    assert sum(x["compare_ambiguous_boot"] + x["compare_host_logon_id"] for x in h.values()) == 0
    assert sum(x["identity_match"] for x in h.values()) == 15


# ================================================================================================ inputs unchanged
def test_stitch_files_keys_and_dbs_are_unchanged_since_the_baseline():
    """The nine non-run_info stitch files and the approved keys equal the baseline SHA-256s exactly. run_info.json is
    rewritten by every stitch run (only `generated_utc` changes), so its own SHA is NOT compared: instead its `files`
    map and `db` block must equal the current SHA-256s of the nine files and of the DB."""
    if not BASELINE.is_file():
        pytest.skip("out/evaluate_check/t76_baseline.json absent")
    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    bad: list[str] = []
    for trial, entry in base.items():
        if trial == "_keys":
            continue
        folder = REPO / "out" / "stitch" / trial
        for name, sha in entry["files"].items():
            if name == "run_info.json":
                continue
            if not (folder / name).is_file() or sha256_of(folder / name) != sha:
                bad.append(f"{trial}/{name}")
        info_path = folder / "run_info.json"
        if not info_path.is_file():
            bad.append(f"{trial}/run_info.json missing")
            continue
        info = json.loads(info_path.read_text(encoding="utf-8"))
        for name, fact in info["files"].items():
            if not (folder / name).is_file() or sha256_of(folder / name) != fact["sha256"]:
                bad.append(f"{trial}/run_info.files/{name}")
        if set(info["files"]) != set(entry["files"]) - {"run_info.json"}:
            bad.append(f"{trial}/run_info.files names")
        db = REPO / "data" / "processed" / f"{trial}.sqlite3"
        if not db.is_file() or {info["db"]["sha256_before"], info["db"]["sha256_after"]} != {sha256_of(db)}:
            bad.append(f"{trial}/db")
    for name, sha in base["_keys"].items():
        p = REPO / "ground_truth" / "approved" / name
        if not p.is_file() or sha256_of(p) != sha:
            bad.append(f"approved/{name}")
    assert bad == []


@pytest.mark.parametrize("trial", DEV)
def test_db_unchanged_by_an_evaluation_and_equal_to_the_stitch_run(trial):
    if _missing(trial):
        pytest.skip(_missing(trial))
    db = REPO / "data" / "processed" / f"{trial}.sqlite3"
    before = sha256_of(db)
    evaluate.evaluate_trial(REPO, trial, "development", REPO / "out" / "stitch" / trial)
    assert sha256_of(db) == before
    info = json.loads((REPO / "out" / "stitch" / trial / "run_info.json").read_text(encoding="utf-8"))
    assert info["db"]["sha256_after"] == before
    key = REPO / "ground_truth" / "approved" / f"{trial}.yaml"
    if key.is_file():
        assert json.loads(key.read_text(encoding="utf-8"))["db_sha256"] == before


def test_every_development_trial_writes_labelled_outputs_through_the_cli(tmp_path):
    """The CLI on real data, into tmp: development label on every CSV row and every .md; nothing under out/."""
    out_root = REPO / "out" / "evaluate"
    existed = {p.name: p.stat().st_mtime_ns for p in out_root.iterdir()} if out_root.is_dir() else None
    for trial in DEV:
        if _missing(trial):
            pytest.skip(_missing(trial))
        target = tmp_path / trial
        assert em.main(["--trial", trial, "--repo", str(REPO), "--out", str(target)]) == 0
        for p in sorted(target.glob("*.csv")):
            rows = list(csv.DictReader(io.StringIO(p.read_text(encoding="utf-8"), newline="")))
            assert rows and all(r["split"] == "development" for r in rows), (trial, p.name)
        for p in sorted(target.glob("*.md")):
            assert p.read_text(encoding="utf-8").splitlines()[0] == "# DEVELOPMENT — not a result (decision 019)"
        assert (target / KEYED).is_file() == trial.endswith("_t00")
    after = {p.name: p.stat().st_mtime_ns for p in out_root.iterdir()} if out_root.is_dir() else None
    assert after == existed


# ================================================================================================ STA-07 sensitivity
# One parameter changed at a time (spec 03 section 5 alternatives; the frozen values are 30 / 15 / 5 / 2).
VARIANTS: dict[str, dict[str, float]] = {
    "frozen (30/15/5/2)": {},
    "look-back 120 s": {"link_lookback_s": 120.0},
    "after 5 s": {"link_after_s": 5.0},
    "after 10 s": {"link_after_s": 10.0},
    "after 15 s": {"link_after_s": 15.0},
    "after 30 s": {"link_after_s": 30.0},
    "port join 2 s": {"port_join_s": 2.0},
    "port join 5 s": {"port_join_s": 5.0},
    "port join 10 s": {"port_join_s": 10.0},
    "group gap 1 s": {"group_gap_s": 1.0},
    "group gap 2 s": {"group_gap_s": 2.0},
    "group gap 3 s": {"group_gap_s": 3.0},
    "group gap 5 s": {"group_gap_s": 5.0},
}
FROZEN = "frozen (30/15/5/2)"
# Columns whose definition depends on the parameters being varied (evidence counted outside the range)
RANGE_COLUMNS = ("evidence_before_range", "evidence_after_range")


@functools.lru_cache(maxsize=None)
def _variant_results(variant: str) -> dict[str, Any]:
    """Run the stitcher on the six keyed t00 trials with the variant's parameters into a temp folder (never out/),
    then the accuracy module on each result (`stitch_dir`). The test harness does this, never src/evaluate."""
    import tempfile
    for t in DEV_T00:
        if _missing(t):
            return {}
    params = dataclasses.replace(StitchParams(), **VARIANTS[variant])
    root = Path(tempfile.mkdtemp(prefix="sta07_"))
    out: dict[str, Any] = {}
    for trial in DEV_T00:
        li, checked, paths, before, after = run_links_checked(REPO, trial, params)
        assert before == after
        files = build_files(REPO, li, checked, paths, before, after, params, "2026-01-01T00:00:00Z")
        folder = root / "stitch" / trial
        replace_folder(folder, files)
        out[trial] = evaluate.evaluate_trial(REPO, trial, "development", folder)
    return out


def variant(name: str) -> dict[str, Any]:
    got = _variant_results(name)
    if not got:
        pytest.skip("development trial data missing")
    return got


def v_rows(name: str) -> list[dict[str, str]]:
    return [r for t in DEV_T00 for r in variant(name)[t].keyed_rows]


def accuracy_view(rows: list[dict[str, str]], drop: tuple[str, ...] = RANGE_COLUMNS) -> list[dict[str, str]]:
    return [{k: v for k, v in r.items() if k not in drop} for r in rows]


def summarise(name: str) -> dict[str, Any]:
    rows = v_rows(name)
    withs = [r for r in rows if r["expected_target_only"] == "0"]
    bg = [r for r in rows if r["expected_target_only"] == "1"]
    return {
        "matched": sum(r["match"] == "matched" for r in rows), "multiple": sum(r["match"] == "multiple" for r in rows),
        "among": sum(r["among_candidates"] == "1" for r in withs),
        "rank1_ok": sum(r["rank1"] == "correct" for r in withs), "tied": sum(r["rank1"] == "tied_correct" for r in withs),
        "wrong": sum(r["rank1"] == "wrong" for r in withs), "no_cand": sum(r["rank1"] == "no_candidate" for r in withs),
        "only": sum(r["only_candidate"] == "1" for r in withs),
        "tiers(A/B/C/D)": "/".join(str(sum(r["key_session_tier"] == t for r in withs)) for t in "ABCD"),
        "target_only_ok": f"{sum(r['target_only_ok'] == '1' for r in bg)}/{len(bg)}",
        "identity_ok": sum(r["identity_match"] == "1" for r in rows),
        "q9_dep": sum(r["identity_match"] == "q9_dependent" for r in rows),
    }


def changed_hops(name: str) -> list[str]:
    base = {r["key_hop_id"]: r for r in v_rows(FROZEN)}
    cols = ("match", "hop_id", "best_tier", "candidate_count", "among_candidates", "rank1", "only_candidate",
            "target_only_ok", "key_session_tier", "identity_match", "target_only_reason")
    out = []
    for r in v_rows(name):
        b = base[r["key_hop_id"]]
        diff = {c: f"{b[c]}->{r[c]}" for c in cols if b[c] != r[c]}
        if diff:
            out.append(f"{r['key_hop_id']}: {diff}")
    return out


def test_sta07_table_is_printed():
    header = ["variant", "matched", "multiple", "among", "rank1_ok", "tied", "wrong", "no_cand", "only", "tiers(A/B/C/D)",
              "target_only_ok", "identity_ok", "q9_dep"]
    lines = ["", "STA-07 sensitivity (six keyed t00 trials, 15 key hops, 11 with a key session; DEVELOPMENT, not results)",
             " | ".join(f"{h:>14}" if i else f"{h:<20}" for i, h in enumerate(header))]
    for name in VARIANTS:
        s = summarise(name)
        lines.append(" | ".join(f"{str(s[h]):>14}" if i else f"{name:<20}" for i, h in enumerate(header)))
    lines.append("")
    for name in ("after 5 s", "look-back 120 s", "group gap 5 s", "group gap 1 s", "group gap 3 s", "port join 2 s"):
        d = changed_hops(name)
        lines.append(f"{name}: {len(d)} key hop(s) differ from frozen")
        lines += [f"    {x}" for x in d]
    print("\n".join(lines))


def test_sta07_frozen_values_equal_the_baseline():
    """The harness at the frozen values reproduces the accuracy rows read from the existing out/stitch folders."""
    for t in DEV_T00:
        base = result(t)
        got = variant(FROZEN)[t]
        assert [dict(r) for r in got.keyed_rows] == [dict(r) for r in base.keyed_rows], t
        assert [dict(r) for r in got.total_rows] == [dict(r) for r in base.total_rows], t
        assert [dict(r) for r in got.fact_rows] == [dict(r) for r in base.fact_rows], t
    s = summarise(FROZEN)
    assert (s["matched"], s["among"], s["rank1_ok"], s["only"]) == (15, 11, 11, 9)


def test_sta07_group_gap_2_equals_frozen_and_port_join_5_equals_frozen():
    base = v_rows(FROZEN)
    assert v_rows("group gap 2 s") == base
    assert v_rows("port join 5 s") == base
    assert v_rows("after 15 s") == base


def test_sta07_kill_criterion_after_15_and_30_give_identical_accuracy_rows():
    assert accuracy_view(v_rows("after 15 s")) == accuracy_view(v_rows("after 30 s"))
    assert accuracy_view(v_rows("after 15 s")) == accuracy_view(v_rows("after 10 s"))     # 044: 10 s and 30 s equal too


def test_sta07_decision_014_port_join_5_and_10_give_identical_keyed_accuracy_rows():
    assert accuracy_view(v_rows("port join 5 s")) == accuracy_view(v_rows("port join 10 s"))


def test_sta07_no_keyed_hop_needs_evidence_outside_the_frozen_range():
    """044 kill criterion: every key hop's verdict at the frozen range already equals the verdict with the widest
    after-window tried (30 s) on the columns that name the key session. (The 120 s look-back is printed, not asserted.)"""
    cols = ("match", "among_candidates", "rank1", "only_candidate")
    frozen = [{c: r[c] for c in cols} for r in v_rows(FROZEN) if r["expected_target_only"] == "0"]
    wide = [{c: r[c] for c in cols} for r in v_rows("after 30 s") if r["expected_target_only"] == "0"]
    assert frozen == wide
    s = summarise(FROZEN)
    assert s["among"] == 11 and s["rank1_ok"] == 11


def test_sta07_recorded_changes_are_only_printed_not_asserted():
    """Spec 10.4 / 044 / 014 expectations, recorded for the report: after 5 s, look-back 120 s, group gap 5 s, 1 s."""
    for name in ("after 5 s", "look-back 120 s", "group gap 5 s", "group gap 1 s", "group gap 3 s", "port join 2 s"):
        d = changed_hops(name)
        print(f"{name}: {summarise(name)}")
        for x in d:
            print("   ", x)
    assert True


def test_sta07_cli_with_stitch_dir_and_out_into_tmp(tmp_path):
    """The CLI on a harness-built stitch folder (group gap 5 s) writes only to --out."""
    if any(_missing(t) for t in DEV_T00):
        pytest.skip("development trial data missing")
    params = dataclasses.replace(StitchParams(), group_gap_s=5.0)
    trial = "s04_t00"
    li, checked, paths, before, after = run_links_checked(REPO, trial, params)
    folder = tmp_path / "stitch" / trial
    replace_folder(folder, build_files(REPO, li, checked, paths, before, after, params, "2026-01-01T00:00:00Z"))
    out = tmp_path / "ev"
    assert em.main(["--trial", trial, "--repo", str(REPO), "--stitch-dir", str(folder), "--out", str(out)]) == 0
    rows = list(csv.DictReader(io.StringIO((out / KEYED).read_text(encoding="utf-8"), newline="")))
    assert [r["key_hop_id"] for r in rows] == ["s04-A-h1", "s04-B-h1", "s04-t1"]
    print("\ngroup gap 5 s, s04_t00 (A and B merge?):",
          [(r["key_hop_id"], r["match"], r["hop_id"], r["rank1"], r["only_candidate"]) for r in rows])
