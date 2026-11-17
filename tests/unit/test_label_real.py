"""T8.2d: the label stage on the nine development trials (spec 04_label LBA-01, LBA-02, LBA-03, LBA-05, LBA-06, LBT-07
on real DBs, LBT-10; decisions 056 / 058). Slow; read-only; DEVELOPMENT trials only (`stitch.params.ALLOWED_TRIALS`,
equal to `clock_offset.params.DEVELOPMENT_TRIALS`); a test trial id is only ever passed to the CLI to see it refused.
These are DEVELOPMENT numbers, not results (decision 019). LBA-04 (the recall table) belongs to PLAN 8.3, not here.

Written from the spec and decisions 056 / 058, not from the implementation. The stage is run through its CLI into pytest
`tmp_path`s (`--out`), so nothing is written under `out/`. The approved keys are opened read-only, only for the six keyed
t00 trials, only for step / hop uids and roles. Messages carry counts, hop ids and uids only: never a command line,
script text, ContextInfo, Payload or UserData value (the DBs hold lab passwords).
"""
from __future__ import annotations

import csv
import functools
import json
import re
import shutil
import sqlite3
import sys
from collections import Counter
from pathlib import Path

import pytest
import yaml
from real_data import missing_input  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import label_fixtures as lf  # noqa: E402
from clock_offset import params as co_params  # noqa: E402
from label import matcher as mt  # noqa: E402
from label import params as lp  # noqa: E402
from label import rules as lr  # noqa: E402
from label.errors import LabelError  # noqa: E402
from label.events import Event  # noqa: E402
from label.labels import match_event  # noqa: E402
from label.run import label_trial  # noqa: E402
from stitch.params import ALLOWED_TRIALS  # noqa: E402

pytestmark = pytest.mark.slow

DEV = list(ALLOWED_TRIALS)
assert DEV == list(co_params.DEVELOPMENT_TRIALS)
KEYED = [t for t in DEV if t.endswith("_t00")]                     # s02..s07 t00: the six approved keys
MOVEMENT = {"T1021.002", "T1021.006", "T1021.001", "T1569.002", "T1570"}
SENSITIVE_KEYS = ("commandline", "parentcommandline", "scriptblocktext", "contextinfo", "payload", "userdata")
LEAK_KEYS = SENSITIVE_KEYS + ("servicefilename", "imagepath")
GRAM = 12

# Spec 10.4 (and decision 058 for SR-31 after P3'): matches per rule in the window, in the order of this list.
TRIAL_ORDER = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00", "s02_t01", "s03_t01", "s06_t01"]
EXPECTED = {
    "SR-01": [4, 2, 2, 4, 0, 4, 2, 2, 0], "SR-02": [1, 1, 1, 2, 0, 2, 1, 1, 0],
    "SR-20": [4, 0, 4, 2, 0, 4, 2, 0, 0], "SR-30": [1, 0, 2, 1, 1, 2, 1, 0, 1],
    "SR-31": [1, 0, 2, 1, 1, 2, 1, 0, 1], "SR-40": [0, 2, 0, 2, 6, 0, 0, 13, 16],
    "SR-41": [0, 3, 0, 3, 3, 0, 0, 3, 7], "SR-60": [0, 5, 0, 5, 10, 0, 0, 5, 10],
    "SR-03": [0] * 9, "SR-11": [0] * 9, "SR-12": [0] * 9, "SR-50": [0] * 9, "SR-61": [0] * 9,
}


# ------------------------------------------------------------------------------------------------ inputs
def db_path(trial: str) -> Path:
    return REPO / "data" / "processed" / f"{trial}.sqlite3"


def missing(trial: str) -> str | None:
    assert trial in DEV, trial                                      # development trials only, belt and braces
    need = [db_path(trial), REPO / "data" / "processed" / f"{trial}.clock_offsets.csv",
            REPO / "data" / "processed" / f"{trial}.clock_changes.csv", REPO / "out" / "gate" / trial / "stats.json",
            REPO / "out" / "stitch" / trial / "run_info.json", REPO / "data" / "trial_windows.csv"]
    gone = [p.name for p in need if not p.is_file()]
    return f"{trial}: missing {', '.join(gone)}" if gone else None


def need_inputs(trial: str) -> None:
    reason = missing(trial)
    if reason:
        missing_input(reason)


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@pytest.fixture(scope="module")
def run_trial(tmp_path_factory):
    """`run_trial(trial)` runs the stage CLI into a temp folder once per trial and returns the folder."""
    import label.__main__ as lm
    root = tmp_path_factory.mktemp("label_real")
    cache: dict[str, Path] = {}

    def run(trial: str) -> Path:
        need_inputs(trial)
        if trial not in cache:
            out = root / trial
            code = lm.main(["--trial", trial, "--out", str(out)])
            assert code == 0, f"{trial}: exit code {code}"
            cache[trial] = out
        return cache[trial]

    return run


def tables(folder: Path) -> dict[str, list[dict[str, str]]]:
    return {n: read_csv(folder / n) for n in ("event_labels.csv", "node_labels.csv", "hop_labels.csv")}


def stats_of(folder: Path) -> dict:
    return json.loads((folder / "stats.json").read_text(encoding="utf-8"))


def load_key(trial: str) -> dict:
    path = REPO / "ground_truth" / "approved" / f"{trial}.yaml"
    if not path.is_file():
        missing_input(f"approved key missing: {trial}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def stitch_hops_of_key_hop(trial: str, key: dict, key_hop: dict) -> set[str]:
    """Stitch hop ids whose `member_logon_uids` hold a target 4624 of the key hop (spec 10.6)."""
    t4624 = {u for u in key_hop["target_event_uids"] if key["event_keys"].get(u, {}).get("event_id") == 4624}
    out = set()
    for h in read_csv(REPO / "out" / "stitch" / trial / "hops.csv"):
        members = {u for item in h["member_logon_uids"].split(";") for u in item.split("|") if u}
        if members & t4624:
            out.add(h["hop_id"])
    return out


# ================================================================================================ run + LBA-01
@pytest.mark.parametrize("trial", DEV)
def test_the_stage_runs_on_every_development_trial_and_leaves_the_db_unchanged(run_trial, trial):
    folder = run_trial(trial)
    assert sorted(p.name for p in folder.iterdir()) == sorted(
        ["event_labels.csv", "node_labels.csv", "hop_labels.csv", "rules_manifest.csv", "stats.json", "report.md",
         "run_info.json"])
    st = stats_of(folder)
    gate = json.loads((REPO / "out" / "gate" / trial / "stats.json").read_text(encoding="utf-8"))
    assert st["db"]["sha256_before"] == st["db"]["sha256_after"] == gate["db"]["sha256_after"]


@pytest.mark.parametrize("trial", DEV)
def test_lba01_label_rows_per_rule_equal_stats_json(run_trial, trial):
    folder = run_trial(trial)
    per_rule = stats_of(folder)["labels"]["matches_per_rule"]
    rows = Counter(r["rule_id"] for r in tables(folder)["event_labels.csv"])
    assert set(per_rule) == set(EXPECTED) | {"SR-10"}
    assert {rid: n for rid, n in per_rule.items()} == {rid: rows.get(rid, 0) for rid in per_rule}


@pytest.mark.parametrize("trial", DEV)
def test_lba01_every_path_node_row_is_in_node_labels_and_every_hop_in_hop_labels(run_trial, trial):
    folder = run_trial(trial)
    nodes_in = read_csv(REPO / "out" / "stitch" / trial / "path_nodes.csv")
    hops_in = read_csv(REPO / "out" / "stitch" / trial / "hops.csv")
    t = tables(folder)
    assert len(t["node_labels.csv"]) == len(nodes_in) > 0
    for got, src in zip(t["node_labels.csv"], nodes_in):
        assert (got["path_id"], got["hop_id"], got["role"], got["context"], got["host"], got["event_uid"]) == \
            (src["path_id"], src["hop_id"], src["role"], src["context"], src["host"], src["event_uid"])
    assert [h["hop_id"] for h in t["hop_labels.csv"]] == [h["hop_id"] for h in hops_in]
    assert [h["in_path"] for h in t["hop_labels.csv"]] == [h["in_path"] for h in hops_in]


@pytest.mark.parametrize("trial", DEV)
def test_lba01_node_and_hop_counts_are_consistent(run_trial, trial):
    t = tables(run_trial(trial))
    by_hop: dict[str, dict[str, str]] = {}
    for n in t["node_labels.csv"]:
        by_hop.setdefault(n["hop_id"], {})[n["event_uid"]] = n["labelled"]
    for h in t["hop_labels.csv"]:
        nodes = by_hop.get(h["hop_id"], {})
        assert int(h["n_node_events"]) == len(nodes), h["hop_id"]
        assert int(h["n_labelled_node_events"]) == sum(1 for v in nodes.values() if v == "1"), h["hop_id"]
        states = [s for s in h["dump_labelled"].split(";") if s]
        assert len(states) == len([u for u in h["dump_event_uids"].split(";") if u]), h["hop_id"]
        assert set(states) <= {"0", "1", "outside_window"}


def test_development_numbers_labels_per_rule_per_trial_match_the_spec_measurements(run_trial):
    """Spec 10.4 (SR-31 after P3', decision 058): a development number, not a result."""
    got: dict[str, list[int]] = {rid: [] for rid in EXPECTED}
    sr10: list[int] = []
    for trial in TRIAL_ORDER:
        per_rule = stats_of(run_trial(trial))["labels"]["matches_per_rule"]
        for rid in EXPECTED:
            got[rid].append(per_rule[rid])
        sr10.append(per_rule["SR-10"])
    assert got == EXPECTED
    assert sum(sr10) == 9 and all(0 <= n <= 2 for n in sr10)        # spec 3.2 P1: 9 rows over the 9 trials


def test_sr31_matches_nine_events_and_eight_of_them_are_path_nodes_decision_058(run_trial):
    events = 0
    node_events: set[tuple[str, str]] = set()
    for trial in TRIAL_ORDER:
        t = tables(run_trial(trial))
        events += sum(1 for r in t["event_labels.csv"] if r["rule_id"] == "SR-31")
        node_events |= {(trial, n["event_uid"]) for n in t["node_labels.csv"] if "SR-31" in n["rule_ids"].split(";")}
    assert events == 9 and len(node_events) == 8


@pytest.mark.parametrize("trial", DEV)
def test_no_label_row_lies_outside_the_window_and_rows_are_ordered(run_trial, trial):
    folder = run_trial(trial)
    rows = tables(folder)["event_labels.csv"]
    win = stats_of(folder)["window"]
    start, end = win.get("start_utc") or win["row"]["start_utc"], win.get("end_utc") or win["row"]["end_utc"]
    keys = [(r["event_utc_corrected"], r["event_uid"], r["rule_id"]) for r in rows]
    assert keys == sorted(keys)
    assert all(start <= r["event_utc_corrected"] <= end[:-1] + "9999Z" for r in rows)
    assert len({(r["event_uid"], r["rule_id"]) for r in rows}) == len(rows)


# ================================================================================================ LBA-02 dumps
def key_dump_uids(key: dict) -> list[str]:
    out = []
    for s in key["steps"]:
        if s["kind"] != "lsass_dump":
            continue
        for u in s["event_uids"]:
            k = key["event_keys"].get(u, {})
            if k.get("channel") == "Sysmon" and k.get("event_id") == 10:
                out.append(u)
    return out


def labelled_uids(rows: list[dict[str, str]], technique: str) -> set[str]:
    out = set()
    for r in rows:
        if technique in r["technique"].split(";") or technique in r["techniques"].split(";"):
            out.add(r["event_uid"])
            out |= {u for u in r["dup_uids"].split("|") if u}
    return out


def test_lba02_every_key_lsass_dump_event_is_labelled_t1003_001(run_trial):
    total = 0
    unlabelled: list[tuple[str, str]] = []
    for trial in KEYED:
        key = load_key(trial)
        t = tables(run_trial(trial))
        lab = labelled_uids(t["event_labels.csv"], "T1003.001")
        for u in key_dump_uids(key):
            total += 1
            if u not in lab:
                unlabelled.append((trial, u))
    assert unlabelled == []
    assert total == 14                                              # spec 10.1: 14 key dump events in six keys


def test_lba02_t1003_001_is_on_context_one_nodes_only_q1(run_trial):
    for trial in KEYED:
        for n in tables(run_trial(trial))["node_labels.csv"]:
            if "T1003.001" in n["techniques"].split(";"):
                assert n["context"] == "1", (trial, n["event_uid"])


def test_lba02_system_and_av_lsass_reads_are_not_labelled_t1003_001(run_trial):
    """Spec 6 / 10.5: of 70 R1_lsass rows, 20 are labelled and these are all in the window; labelled T1003.001 events
    never exceed the SR-01 + SR-02 distinct events (no other rule carries the technique)."""
    total = 0
    for trial in TRIAL_ORDER:
        rows = tables(run_trial(trial))["event_labels.csv"]
        total += len(labelled_uids(rows, "T1003.001"))
        assert {r["rule_id"] for r in rows if r["technique"] == "T1003.001"} <= {"SR-01", "SR-02", "SR-03"}
    assert total == 20


# ================================================================================================ LBA-03 attack hops
def key_hops(key: dict, role: str) -> list[dict]:
    return [h for h in key["hops"] if h["role"] == role]


def test_lba03_every_attack_hop_has_a_context_zero_node_labelled_with_a_movement_technique(run_trial):
    n_hops = 0
    bad: list[tuple[str, str]] = []
    for trial in KEYED:
        key = load_key(trial)
        t = tables(run_trial(trial))
        for kh in key_hops(key, "attack"):
            n_hops += 1
            shops = stitch_hops_of_key_hop(trial, key, kh)
            techs = {x for n in t["node_labels.csv"] if n["hop_id"] in shops and n["context"] == "0"
                     and n["labelled"] == "1" for x in n["techniques"].split(";") if x}
            if not shops or not techs & MOVEMENT:
                bad.append((trial, kh["hop_id"]))
    assert n_hops == 7                                              # spec 10.6: 7 key attack hops
    assert bad == []


def test_lba03_negative_control_a_background_hop_has_no_movement_label(run_trial):
    """Spec 10.6: background hops get no label (the control for the positive test above)."""
    checked = 0
    for trial in KEYED:
        key = load_key(trial)
        t = tables(run_trial(trial))
        for kh in key_hops(key, "background"):
            checked += 1
            for sh in stitch_hops_of_key_hop(trial, key, kh):
                assert all(n["labelled"] == "0" for n in t["node_labels.csv"] if n["hop_id"] == sh), (trial, sh)
    assert checked >= 1


def test_lba03_the_attack_hop_labels_include_the_hop_rows(run_trial):
    for trial in KEYED:
        key = load_key(trial)
        t = tables(run_trial(trial))
        hl = {h["hop_id"]: h for h in t["hop_labels.csv"]}
        for kh in key_hops(key, "attack"):
            for sh in stitch_hops_of_key_hop(trial, key, kh):
                assert int(hl[sh]["n_labelled_node_events"]) > 0, (trial, kh["hop_id"])
                assert set(hl[sh]["techniques"].split(";")) & MOVEMENT, (trial, kh["hop_id"])


# ================================================================================================ LBA-05 benign hops
def test_lba05_no_t1003_001_label_on_any_node_or_hop_of_a_benign_key_hop(run_trial):
    checked = 0
    for trial in KEYED:
        key = load_key(trial)
        t = tables(run_trial(trial))
        hl = {h["hop_id"]: h for h in t["hop_labels.csv"]}
        for kh in key_hops(key, "benign"):
            for sh in stitch_hops_of_key_hop(trial, key, kh):
                checked += 1
                nodes = [n for n in t["node_labels.csv"] if n["hop_id"] == sh]
                assert nodes
                for n in nodes:
                    assert "T1003.001" not in n["techniques"].split(";"), (trial, sh, n["event_uid"])
                    assert not {"SR-01", "SR-02", "SR-03"} & set(n["rule_ids"].split(";")), (trial, sh)
                assert "T1003.001" not in hl[sh]["techniques"].split(";"), (trial, sh)
    assert checked >= 4                                             # s04 A and the three s06 benign hops


def test_lba05_s04_a_hop_dump_columns_are_facts_and_do_not_enter_the_node_counts(run_trial):
    key = load_key("s04_t00")
    t = tables(run_trial("s04_t00"))
    hl = {h["hop_id"]: h for h in t["hop_labels.csv"]}
    (a,) = [h for h in key["hops"] if h["hop_id"] == "s04-A-h1"]
    (sh,) = stitch_hops_of_key_hop("s04_t00", key, a)
    row = hl[sh]
    # the dump reads are reported (facts) ...
    assert row["dump_event_uids"] != "" and set(row["dump_labelled"].split(";")) <= {"0", "1", "outside_window"}
    # ... but the node counts come from node rows alone
    labelled = {n["event_uid"] for n in t["node_labels.csv"] if n["hop_id"] == sh and n["labelled"] == "1"}
    assert int(row["n_labelled_node_events"]) == len(labelled)
    assert not {u for u in row["dump_event_uids"].split(";") if u} & {
        n["event_uid"] for n in t["node_labels.csv"] if n["hop_id"] == sh and n["context"] == "0"}


# ================================================================================================ LBA-06 report
def test_lba06_level_profile_per_key_hop_is_reported_not_scored(run_trial):
    """Review ATK-L03: print per key hop the mean `max_level_value` of labelled context 0 nodes and of all labelled
    nodes, and flag a benign hop at or above an attack hop of the same trial. Counts and hop ids only."""
    lines: list[str] = []
    flags: list[str] = []
    n_hops = 0
    for trial in KEYED:
        key = load_key(trial)
        t = tables(run_trial(trial))
        prof: dict[str, tuple[str, float | None, float | None]] = {}
        for kh in key["hops"]:
            if kh["role"] not in ("attack", "benign"):
                continue
            shops = stitch_hops_of_key_hop(trial, key, kh)
            lab = {(n["hop_id"], n["event_uid"]): n for n in t["node_labels.csv"] if n["hop_id"] in shops
                   and n["labelled"] == "1"}
            zero = [int(n["max_level_value"]) for n in lab.values() if n["context"] == "0"]
            allv = [int(n["max_level_value"]) for n in lab.values()]
            m0 = sum(zero) / len(zero) if zero else None
            ma = sum(allv) / len(allv) if allv else None
            prof[kh["hop_id"]] = (kh["role"], m0, ma)
            n_hops += 1
            lines.append(f"{trial} {kh['hop_id']} {kh['role']}: context0 mean "
                         f"{'-' if m0 is None else f'{m0:.2f}'} (n={len(zero)}), all "
                         f"{'-' if ma is None else f'{ma:.2f}'} (n={len(allv)})")
        attack = [v for v in prof.values() if v[0] == "attack" and v[1] is not None]
        for hid, (role, m0, _ma) in prof.items():
            if role == "benign" and m0 is not None and attack and any(m0 >= a[1] for a in attack):
                flags.append(f"{trial} {hid}")
    print("\nLBA-06 level profile (development numbers, reported only)")
    print("\n".join(lines))
    print("benign hop at or above an attack hop of its trial:", flags if flags else "none")
    assert n_hops == 11                                             # 7 attack + 4 benign key hops (s04 A, s06 x3)
    assert lines                                                    # something was reported (run with -s to see it)


# ================================================================================================ refusals on real data
@pytest.mark.parametrize("trial", ["s02_t02", "s05_t07", "s07_t10", "s01_t00"])
def test_a_test_trial_and_s01_t00_are_refused_with_nothing_written(tmp_path, trial):
    import label.__main__ as lm
    out = tmp_path / "must_not_exist"
    assert lm.main(["--trial", trial, "--out", str(out)]) == 2
    assert not out.exists()
    with pytest.raises(LabelError):
        label_trial(REPO, trial)


def test_out_inside_the_repo_outside_out_is_refused_after_a_real_run_and_nothing_is_written():
    import label.__main__ as lm
    need_inputs("s02_t00")
    target = REPO / "docs" / "label_test_must_not_exist"
    assert lm.main(["--trial", "s02_t00", "--out", str(target)]) == 2
    assert not target.exists()


def test_a_rule_manifest_hash_mismatch_refuses_a_real_trial(tmp_path):
    need_inputs("s02_t00")
    rules = tmp_path / "rules"
    shutil.copytree(lp.RULES_DIR, rules, ignore=shutil.ignore_patterns("__pycache__"))
    p = rules / "SR-20_executable_written_admin_share.yml"
    p.write_bytes(p.read_bytes() + b"\n# changed\n")
    with pytest.raises(LabelError):
        label_trial(REPO, "s02_t00", rules_dir=rules)


def test_an_extra_file_in_the_rules_folder_refuses_a_real_trial(tmp_path):
    need_inputs("s02_t00")
    rules = tmp_path / "rules"
    shutil.copytree(lp.RULES_DIR, rules, ignore=shutil.ignore_patterns("__pycache__"))
    (rules / "extra.yml").write_text("title: x\n", encoding="utf-8")
    with pytest.raises(LabelError):
        label_trial(REPO, "s02_t00", rules_dir=rules)


# ================================================================================================ LBT-07 on real DBs
def db_values(trial: str):
    """Every command / script value of the DB (`command_line`, and the LEAK_KEYS of `field_values_json`)."""
    con = sqlite3.connect(f"file:{db_path(trial).as_posix()}?mode=ro", uri=True)
    try:
        for cl, fv in con.execute("SELECT command_line, field_values_json FROM events_dedup "
                                  "WHERE command_line IS NOT NULL OR field_values_json IS NOT NULL"):
            if cl:
                yield cl
            if fv and any(k in fv for k in LEAK_KEYS):
                d = json.loads(fv)
                for k in LEAK_KEYS:
                    for v in d.get(k) or []:
                        if v:
                            yield str(v)
    finally:
        con.close()


def test_lbt07_no_12_character_command_or_script_substring_in_any_output(run_trial):
    """Streams every DB command / script value and counts the 12-character windows that occur in an output file and
    not in the public rule files. Counts and file names only; the windows are never printed."""
    outputs: dict[str, set[str]] = {}
    exempt = lf.public_rule_grams()
    for trial in DEV:
        folder = run_trial(trial)
        for p in sorted(folder.iterdir()):
            for g in lf.output_windows(p.read_text(encoding="utf-8"), exempt):
                outputs.setdefault(g, set()).add(f"{trial}/{p.name}")
    hit_files: Counter[str] = Counter()
    for trial in DEV:
        seen: set[str] = set()
        for value in db_values(trial):
            v = value.casefold()
            for i in range(len(v) - GRAM + 1):
                g = v[i:i + GRAM]
                if g in outputs and g not in seen:
                    seen.add(g)
                    for f in outputs[g]:
                        hit_files[f] += 1
    assert dict(hit_files) == {}, f"{sum(hit_files.values())} leaking 12-character windows in {sorted(hit_files)}"


def test_lbt07_the_db_hash_is_unchanged_by_a_run(run_trial):
    from answer_key.db import sha256_file
    trial = "s02_t00"
    need_inputs(trial)
    before = sha256_file(db_path(trial))
    run_trial(trial)
    assert sha256_file(db_path(trial)) == before


# ================================================================================================ LBT-10 format contract
SENS = set(SENSITIVE_KEYS)


def logsource_targets() -> dict[tuple[str, int], list[lr.Rule]]:
    """(channel, event id) -> the rules that can apply; a service logsource covers the channel, so it is keyed by the
    pairs the development rules actually need (listed explicitly)."""
    pairs = {("Sysmon", 10), ("Sysmon", 1), ("Sysmon", 3), ("Security", 4688), ("Security", 5140), ("Security", 5145),
             ("Security", 4697), ("Security", 4624), ("Security", 4648), ("System", 7045)}
    out: dict[tuple[str, int], list[lr.Rule]] = {}
    rules = lr.load_rules(Path(lp.RULES_DIR)).rules
    for ch, eid in pairs:
        out[(ch, eid)] = [r for r in rules if r.logsource.applies(ch, eid)]
    return out


def applies_to_pair(rule: lr.Rule, eid: int) -> bool:
    """A service-logsource rule covers a whole channel, but its own `EventID` literals say which events it is about;
    the format report only pairs a rule with the events it names."""
    ids = {str(v) for sel in rule.detection.selections.values() for alt in sel.alternatives for item in alt
           if item.field == "EventID" for v in item.values}
    return not ids or str(eid) in ids


def rule_items(rule: lr.Rule):
    for sel in rule.detection.selections.values():
        for alt in sel.alternatives:
            for item in alt:
                yield sel.name, item


def scan_db(trial: str, pairs: set[tuple[str, int]]):
    """Yield (channel, event id, uid, parsed JSON object) for the rows of `pairs`; read-only."""
    con = sqlite3.connect(f"file:{db_path(trial).as_posix()}?mode=ro", uri=True)
    try:
        for uid, ch, eid, fv in con.execute("SELECT event_uid, channel, event_id, field_values_json FROM events_dedup "
                                            "WHERE field_values_json IS NOT NULL"):
            if (ch, eid) in pairs:
                yield ch, eid, uid, json.loads(fv)
    finally:
        con.close()


def test_lbt10_real_row_fixtures_still_match_with_sensitive_fields_blanked_and_literals_report():
    """One real DB row per rule that has a development match (picked by the rule itself, then the sensitive fields are
    blanked and the row must still match). Then, for every literal of every rule, the stored values of its field in the
    development DBs are checked: a literal no stored value could match is REPORTED (rule id, field, literal: all public
    rule text), never failed (spec 7 LBT-10)."""
    for t in DEV:
        need_inputs(t)
    targets = logsource_targets()
    pairs = set(targets)
    rules = lr.load_rules(Path(lp.RULES_DIR)).rules
    by_id = {r.rule_id: r for r in rules}
    fixture: dict[str, tuple[str, int, dict]] = {}
    stored: dict[tuple[str, int, str], set[str]] = {}
    needed: dict[tuple[str, int], set[str]] = {}
    for (ch, eid), rs in targets.items():
        for r in rs:
            if not applies_to_pair(r, eid):
                continue
            for _name, item in rule_items(r):
                key = mt.field_key(item.field, r.logsource.process_creation_4688(ch, eid))
                if key:
                    needed.setdefault((ch, eid), set()).add(key)
    for trial in DEV:
        for ch, eid, _uid, obj in scan_db(trial, pairs):
            fields = mt.event_fields(obj)
            for key in needed.get((ch, eid), ()):
                for v in fields.get(key, ()):
                    stored.setdefault((ch, eid, key), set()).add(v.lower())
            for r in targets[(ch, eid)]:
                if r.rule_id in fixture:
                    continue
                if mt.match_detection(r.detection, fields, r.logsource.process_creation_4688(ch, eid)):
                    blank = {k: v for k, v in obj.items() if k.lower() not in SENS}
                    fixture[r.rule_id] = (ch, eid, blank)
    # fixtures exist for every rule that matched in development, and still match after blanking
    assert {"SR-01", "SR-02", "SR-10", "SR-20", "SR-30", "SR-31", "SR-40", "SR-41", "SR-60"} <= set(fixture)
    for rid, (ch, eid, blank) in fixture.items():
        e = Event(uid="fx", host="ep-01", channel=ch, event_id=eid, record_id=1, us_raw=0, us=0, clock_unreliable=0,
                  fields_json=json.dumps(blank))
        assert rid in {m.rule.rule_id for m in match_event(e, [by_id[rid]])}, rid
    # the format-contract report
    unmatchable: list[str] = []
    for (ch, eid), rs in targets.items():
        for r in rs:
            if not applies_to_pair(r, eid):
                continue
            for name, item in rule_items(r):
                key = mt.field_key(item.field, r.logsource.process_creation_4688(ch, eid))
                if key is None:
                    continue
                values = stored.get((ch, eid, key), set())
                for lit, pat in zip(item.values, item.patterns):
                    if not any(pat.fullmatch(v) for v in values):
                        unmatchable.append(f"{r.rule_id} {ch}/{eid} {item.field}|{item.modifier or '='} {lit!r}")
    unmatchable = sorted(set(unmatchable))
    print(f"\nLBT-10 format contract: {len(unmatchable)} rule literals with no stored value that could match "
          f"(reported, not failed)")
    for line in unmatchable:
        print("  ", line)
    assert isinstance(unmatchable, list)                            # reported, never failed (run with -s to see it)
