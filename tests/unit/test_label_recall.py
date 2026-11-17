"""T8.2d / T8.3: the labelling recall, spec 04_label LBA-04 and decision 060 (`python -m evaluate --label-recall`).

Written from spec 04 section 7 (LBA-04 and its expected-technique table) and decision 060, not from the implementation
(the code was read only for its public entry points: `evaluate.label_recall`, `evaluate.label_run.label_trial`,
`evaluate.__main__.main`, `evaluate.writers`). Two parts:

- fast unit tests of the pure functions on a synthetic key and synthetic label rows;
- slow real-data tests on the six keyed t00 development trials. The recall counts are derived here independently from
  the approved keys, `out/label/<trial>/event_labels.csv` and two read-only DB columns (`share_name`,
  `relative_target_name`), then compared with what the stage reports; the numbers in decision 060 are only the second
  check. Every write goes to a pytest `tmp_path` through `--out`; nothing is written under `out/`.

Messages carry counts, hop ids and uids only. A test trial id is only ever passed to the CLI to see it refused.
"""
from __future__ import annotations

import csv
import json
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

from clock_offset import params as co_params  # noqa: E402
from evaluate import __main__ as em  # noqa: E402
from evaluate import label_recall as lrc  # noqa: E402
from evaluate import label_run  # noqa: E402
from evaluate import writers  # noqa: E402

DEV = list(co_params.DEVELOPMENT_TRIALS)
KEYED = [t for t in DEV if t.endswith("_t00")]
T01 = [t for t in DEV if t.endswith("_t01")]

# Spec 04 section 7, LBA-04: the columns (decision 060 renames "hop_id or step_id" to hop_or_step_id and appends four).
SPEC_COLUMNS = ["trial_id", "hop_or_step_id", "kind", "event_uid", "expected_technique", "labelled",
                "labelled_expected", "rule_ids"]
EXTRA_COLUMNS = ["role", "scored", "match_method", "label_techniques", "label_run_sha256"]  # 061 S06
RUN_SHA = "ab" * 32
# Spec 04 section 7: the expected-technique table (kind of key event -> technique).
SPEC_EXPECTED = {"T1003.001": {"lsass_dump"}, "T1021.002": {"smb_share"}, "T1570": {"smb_copy"},
                 "T1569.002": {"service_install"}, "T1021.006": {"winrm_process", "winrm_source_conn"},
                 "none": {"target_4624"}}
LINK_FILES = ["link_accuracy.json", "link_accuracy.md", "link_accuracy_hops.csv", "link_accuracy_totals.csv",
              "link_facts_hops.csv", "run_info.json"]


# ================================================================================================ synthetic unit tests
def ek(channel: str, eid: int, host: str) -> dict:
    return {"channel": channel, "event_id": eid, "host": host, "record_id": 1, "time_utc": "2026-01-01T00:00:00Z"}


def synthetic_key() -> tuple[dict, dict]:
    keys = {
        "t4624": ek("Security", 4624, "ep-02"), "t5140a": ek("Security", 5140, "ep-02"),
        "t5145x": ek("Security", 5145, "ep-02"), "t5145ipc": ek("Security", 5145, "ep-02"),
        "t5145lab": ek("Security", 5145, "ep-02"), "t7045": ek("System", 7045, "ep-02"),
        "t4697": ek("Security", 4697, "ep-02"),
        "w4624": ek("Security", 4624, "ep-02"), "w1": ek("Sysmon", 1, "ep-02"), "w4688": ek("Security", 4688, "ep-02"),
        "w91": ek("WinRM", 91, "ep-02"), "w3": ek("Sysmon", 3, "ep-01"),
        "b7045": ek("System", 7045, "ep-03"), "b4624": ek("Security", 4624, "ep-03"),
        "g5140": ek("Security", 5140, "ep-03"),
        "e7045": ek("System", 7045, "ep-03"),
        "d1": ek("Sysmon", 10, "ep-01"), "d2": ek("Sysmon", 10, "ep-01"), "d3": ek("Sysmon", 10, "ep-01"),
        "s7045": ek("System", 7045, "ep-04"),
    }
    hops = [
        {"hop_id": "H-smb", "role": "attack", "protocol": "SMB", "source_host": "ep-01", "target_host": "ep-02",
         "target_event_uids": ["t4624", "t5140a", "t5145x", "t5145ipc", "t5145lab", "t7045", "t4697"]},
        {"hop_id": "H-winrm", "role": "attack", "protocol": "WinRM", "source_host": "ep-01", "target_host": "ep-02",
         "target_event_uids": ["w4624", "w1", "w4688", "w91"], "port_join_event_uids": ["w3"]},
        {"hop_id": "H-benign", "role": "benign", "protocol": "SMB", "source_host": "ep-01", "target_host": "ep-03",
         "target_event_uids": ["b7045", "b4624"]},
        {"hop_id": "H-bg", "role": "background", "protocol": "SMB", "source_host": "ep-01", "target_host": "ep-03",
         "target_event_uids": ["g5140"]},
        {"hop_id": "H-excl", "role": "attack", "excluded": True, "protocol": "SMB", "source_host": "ep-01",
         "target_host": "ep-03", "target_event_uids": ["e7045"]},
    ]
    steps = [
        {"step_id": "S-dump", "kind": "lsass_dump", "status": "confirmed", "event_uids": ["d1", "d2"]},
        {"step_id": "S-dump-unc", "kind": "lsass_dump", "status": "unconfirmed", "event_uids": ["d3"]},
        {"step_id": "S-svc", "kind": "service_exec", "status": "confirmed", "event_uids": ["t7045", "s7045"]},
        {"step_id": "S-move", "kind": "move", "status": "confirmed", "event_uids": ["w1"]},
    ]
    shares = {"t5140a": lrc.ShareFacts(r"\\*\ADMIN$", ""), "t5145x": lrc.ShareFacts(r"\\*\ADMIN$", "run.EXE"),
              "t5145ipc": lrc.ShareFacts(r"\\*\IPC$", "svcctl"), "t5145lab": lrc.ShareFacts(r"\\*\LabShare", "a.exe"),
              "g5140": lrc.ShareFacts(r"\\*\IPC$", "")}
    return {"event_keys": keys, "hops": hops, "steps": steps}, shares


def label_row(uid: str, rule: str, tech: str, dup: str = "", techs: str | None = None) -> dict:
    return {"trial_id": "t", "event_uid": uid, "dup_uids": dup, "rule_id": rule, "technique": tech,
            "techniques": techs or tech}


def synthetic_rows():
    key, shares = synthetic_key()
    labels = [label_row("d1", "SR-01", "T1003.001"), label_row("t5140a", "SR-10", "T1021.002"),
              label_row("t5145x", "SR-31", "T1569.002"),                      # labelled, but not the expected T1570
              label_row("t7045", "SR-30", "T1569.002"),
              label_row("w1", "SR-40", "T1021.006", techs="T1021.006;T1059.001"),
              label_row("w4688rep", "SR-40", "T1021.006", dup="w4688"),       # a copy listed in dup_uids
              label_row("b7045", "SR-30", "T1569.002")]
    return lrc.recall_rows("t", key, shares, labels, label_run_sha256=RUN_SHA), key


def by_uid(rows):
    return {r["event_uid"]: r for r in rows}


def test_columns_are_the_spec_columns_then_the_decision_060_extras():
    assert list(lrc.COLUMNS) == SPEC_COLUMNS + EXTRA_COLUMNS


def test_the_expected_technique_table_is_the_spec_table():
    got: dict[str, set[str]] = {}
    for kind, tech in lrc.EXPECTED.items():
        got.setdefault(tech, set()).add(kind)
    assert got == SPEC_EXPECTED


def test_kinds_and_expected_techniques_of_a_synthetic_key():
    rows, _key = synthetic_rows()
    r = by_uid(rows)
    assert {u: (x["kind"], x["expected_technique"]) for u, x in r.items()} == {
        "t4624": ("target_4624", "none"), "t5140a": ("smb_share", "T1021.002"), "t5145x": ("smb_copy", "T1570"),
        "t5145ipc": ("smb_share", "T1021.002"), "t7045": ("service_install", "T1569.002"),
        "t4697": ("service_install", "T1569.002"), "w4624": ("target_4624", "none"),
        "w1": ("winrm_process", "T1021.006"), "w4688": ("winrm_process", "T1021.006"),
        "w3": ("winrm_source_conn", "T1021.006"), "b7045": ("service_install", "T1569.002"),
        "b4624": ("target_4624", "none"), "g5140": ("smb_share", "T1021.002"), "e7045": ("service_install", "T1569.002"),
        "d1": ("lsass_dump", "T1003.001"), "d2": ("lsass_dump", "T1003.001"), "d3": ("lsass_dump", "T1003.001"),
        "s7045": ("service_install", "T1569.002")}


def test_events_of_no_table_kind_get_no_row_but_are_counted():
    rows, key = synthetic_rows()
    uids = {r["event_uid"] for r in rows}
    assert not uids & {"t5145lab", "w91"}                          # lab share, WinRM 91
    counts = lrc.unkinded_counts(key, uids)
    assert counts.get("Security 5145") == 1 and counts.get("WinRM 91") == 1


def test_target_4624_rows_are_reported_and_never_scored():
    rows, _ = synthetic_rows()
    t = [r for r in rows if r["kind"] == "target_4624"]
    assert {r["event_uid"] for r in t} == {"t4624", "w4624", "b4624"}
    assert all(r["scored"] == "0" and r["expected_technique"] == "none" and r["labelled_expected"] == "" for r in t)
    assert "none" not in lrc.recall_counts(rows)


def test_benign_background_excluded_and_unconfirmed_rows_are_reported_never_scored():
    rows, _ = synthetic_rows()
    r = by_uid(rows)
    for uid in ("b7045", "g5140", "e7045", "d3"):
        assert r[uid]["scored"] == "0", uid
    for uid in ("t5140a", "t5145x", "t7045", "t4697", "w1", "w4688", "w3", "d1", "d2", "s7045"):
        assert r[uid]["scored"] == "1", uid
    assert r["b7045"]["role"] == "benign" and r["g5140"]["role"] == "background"
    assert r["e7045"]["role"] == "excluded" and r["d3"]["role"] == "step_unconfirmed"


def test_labelled_and_labelled_expected_and_the_match_method():
    rows, _ = synthetic_rows()
    r = by_uid(rows)
    assert (r["d1"]["labelled"], r["d1"]["labelled_expected"], r["d1"]["rule_ids"]) == ("1", "1", "SR-01")
    assert (r["d2"]["labelled"], r["d2"]["labelled_expected"], r["d2"]["rule_ids"]) == ("0", "0", "")
    assert (r["t5145x"]["labelled"], r["t5145x"]["labelled_expected"]) == ("1", "0")     # labelled, wrong technique
    assert r["w1"]["labelled_expected"] == "1"                                           # primary
    assert r["w1"]["match_method"] == "uid" and r["d2"]["match_method"] == "none"
    assert r["w4688"]["match_method"] == "dup_uid" and r["w4688"]["labelled_expected"] == "1"


def test_a_secondary_tag_counts_as_the_expected_technique():
    key, shares = synthetic_key()
    got = lrc.recall_rows("t", key, shares, [label_row("t4697", "SR-X", "T1078", techs="T1078;T1569.002")],
                          label_run_sha256=RUN_SHA)
    assert by_uid(got)["t4697"]["labelled_expected"] == "1"


def test_a_uid_listed_by_a_hop_and_a_step_is_one_row_and_the_hop_wins():
    rows, _ = synthetic_rows()
    assert [r["event_uid"] for r in rows].count("t7045") == 1
    assert by_uid(rows)["t7045"]["hop_or_step_id"] == "H-smb" and by_uid(rows)["t7045"]["role"] == "attack"
    assert by_uid(rows)["s7045"]["hop_or_step_id"] == "S-svc"                           # a step-only install


def test_recall_counts_per_technique_and_overall():
    rows, _ = synthetic_rows()
    c = lrc.recall_counts(rows)
    assert c == {"T1003.001": (1, 2), "T1021.002": (1, 2), "T1570": (0, 1), "T1569.002": (1, 3),
                 "T1021.006": (2, 3), "overall": (5, 11)}


def test_rows_are_unique_per_uid_and_sorted():
    rows, _ = synthetic_rows()
    assert len({r["event_uid"] for r in rows}) == len(rows)
    keys = [(r["hop_or_step_id"], lrc.KIND_ORDER.index(r["kind"]), r["event_uid"]) for r in rows]
    assert keys == sorted(keys)


def test_csv_text_has_the_columns_and_one_line_per_row():
    rows, _ = synthetic_rows()
    text = lrc.trial_csv(rows)
    lines = text.splitlines()
    assert lines[0].split(",") == SPEC_COLUMNS + EXTRA_COLUMNS
    assert len(lines) == len(rows) + 1 and "\r" not in text


def test_label_counts_are_key_free():
    c = lrc.label_counts([label_row("a", "SR-01", "T1003.001"), label_row("a", "SR-02", "T1003.001"),
                          label_row("b", "SR-40", "T1021.006", techs="T1021.006;T1059.001")])
    assert c["label_rows"] == 3 and c["labelled_events"] == 2
    assert c["events_per_technique"] == {"T1003.001": 1, "T1021.006": 1, "T1059.001": 1}
    assert c["rows_per_rule"] == {"SR-01": 1, "SR-02": 1, "SR-40": 1}


def test_a_trial_without_a_key_has_no_rows_only_counts():
    rec = lrc.TrialRecall("s02_t01", "development", None, lrc.label_counts([label_row("a", "SR-01", "T1003.001")]),
                          {}, {})
    md = lrc.summary_md("development", [rec])
    assert "s02_t01" in md and "1 trials without a key" in md and "never scored" in md
    assert "Never run on t02" in md


# ================================================================================================ real data
pytestmark_slow = pytest.mark.slow


def db_path(t: str) -> Path:
    return REPO / "data" / "processed" / f"{t}.sqlite3"


def need(t: str) -> None:
    for p in (db_path(t), REPO / "out" / "label" / t / "event_labels.csv", REPO / "out" / "label" / t / "run_info.json",
              REPO / "ground_truth" / "approved" / f"{t}.yaml"):
        if not p.is_file():
            missing_input(f"{t}: missing {p.relative_to(REPO).as_posix()}")


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def key_of(t: str) -> dict:
    return yaml.safe_load((REPO / "ground_truth" / "approved" / f"{t}.yaml").read_text(encoding="utf-8"))


def share_facts(t: str, uids: list[str]) -> dict[str, tuple[str, str]]:
    """uid -> (share_name, relative_target_name): the two non-command columns, read-only."""
    con = sqlite3.connect(f"file:{db_path(t).as_posix()}?mode=ro", uri=True)
    try:
        out = {}
        for i in range(0, len(uids), 500):
            chunk = uids[i:i + 500]
            q = ",".join("?" for _ in chunk)
            for uid, sn, rt in con.execute(
                    f"SELECT event_uid, share_name, relative_target_name FROM events_dedup WHERE event_uid IN ({q})",
                    chunk):
                out[uid] = (sn or "", rt or "")
        return out
    finally:
        con.close()


def leaf(share: str) -> str:
    return share.strip().rstrip("\\").split("\\")[-1].lower()


def derive(t: str) -> dict[str, tuple[str, str, bool]]:
    """Independent derivation of the scored key events of one keyed trial: uid -> (expected technique, kind, labelled
    with it). Only attack hops and confirmed steps are scored; kinds come from the key (and the share name), never
    from a label."""
    key = key_of(t)
    ek_ = key["event_keys"]
    labels = read_csv(REPO / "out" / "label" / t / "event_labels.csv")
    have: dict[str, set[str]] = {}
    for r in labels:
        techs = {r["technique"]} | {x for x in r["techniques"].split(";") if x}
        for u in [r["event_uid"]] + [d for d in r["dup_uids"].split("|") if d]:
            have.setdefault(u, set()).update(techs)

    def info(u):
        e = ek_.get(u, {})
        return e.get("channel"), e.get("event_id"), e.get("host")

    smb_uids = [u for h in key["hops"] if (h["protocol"] or "").lower() == "smb" for u in h["target_event_uids"]
                if info(u)[0] == "Security" and info(u)[1] in (5140, 5145)]
    shares = share_facts(t, sorted(set(smb_uids)))
    out: dict[str, tuple[str, str]] = {}
    hop_uids: set[str] = set()
    for h in key["hops"]:
        proto = (h["protocol"] or "").lower()
        for u in h["target_event_uids"] + h.get("port_join_event_uids", []):
            hop_uids.add(u)
        if h["role"] != "attack" or h.get("excluded"):
            continue
        for u in h["target_event_uids"]:
            ch, eid, host = info(u)
            if host != h["target_host"]:
                continue
            if (ch, eid) in (("System", 7045), ("Security", 4697)):
                out[u] = ("T1569.002", "service_install")
            elif proto == "smb" and ch == "Security" and eid in (5140, 5145):
                name, target = shares[u]
                lf = leaf(name)
                admin_file = lf == "admin$" or (len(lf) == 2 and lf[0].isalpha() and lf[1] == "$")
                if not (admin_file or lf == "ipc$"):
                    continue
                if eid == 5145 and admin_file and target.strip().lower().endswith(
                        (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs")):
                    out[u] = ("T1570", "smb_copy")
                else:
                    out[u] = ("T1021.002", "smb_share")
            elif proto == "winrm" and (ch, eid) in (("Sysmon", 1), ("Security", 4688)):
                out[u] = ("T1021.006", "winrm_process")
        if proto == "winrm":
            for u in h.get("port_join_event_uids", []):
                ch, eid, host = info(u)
                if (ch, eid) == ("Sysmon", 3) and host == h["source_host"]:
                    out[u] = ("T1021.006", "winrm_source_conn")
    for s in key["steps"]:
        if s["status"] != "confirmed" or s["kind"] not in ("lsass_dump", "service_exec"):
            continue
        for u in s["event_uids"]:
            ch, eid, _host = info(u)
            if u in hop_uids:
                continue
            if s["kind"] == "lsass_dump" and (ch, eid) == ("Sysmon", 10):
                out[u] = ("T1003.001", "lsass_dump")
            elif s["kind"] == "service_exec" and (ch, eid) in (("System", 7045), ("Security", 4697)):
                out[u] = ("T1569.002", "service_install")
    return {u: (tech, kind, tech in have.get(u, set())) for u, (tech, kind) in out.items()}


@pytest.fixture(scope="module")
def recall_runs(tmp_path_factory):
    """Run `python -m evaluate --label-recall --trial T --out DIR` for every keyed trial once."""
    root = tmp_path_factory.mktemp("recall")
    out: dict[str, Path] = {}
    for t in KEYED:
        need(t)
        folder = root / t
        assert em.main(["--label-recall", "--trial", t, "--out", str(folder)]) == 0, t
        out[t] = folder
    return out


def rows_of(runs, t):
    return read_csv(runs[t] / "label_recall.csv")


@pytest.mark.slow
def test_lba04_each_keyed_trial_writes_only_label_recall_csv_with_the_columns(recall_runs):
    for t in KEYED:
        assert sorted(p.name for p in recall_runs[t].iterdir()) == ["label_recall.csv"], t
        with open(recall_runs[t] / "label_recall.csv", newline="", encoding="utf-8") as fh:
            assert next(csv.reader(fh)) == SPEC_COLUMNS + EXTRA_COLUMNS, t
        assert all(r["trial_id"] == t for r in rows_of(recall_runs, t))


@pytest.mark.slow
def test_lba04_one_row_per_uid_and_cells_are_in_the_spec_vocabulary(recall_runs):
    for t in KEYED:
        rows = rows_of(recall_runs, t)
        assert rows and len({r["event_uid"] for r in rows}) == len(rows), t
        for r in rows:
            assert r["kind"] in lrc.EXPECTED and r["labelled"] in {"0", "1"} and r["scored"] in {"0", "1"}
            tech = next(k for k, kinds in SPEC_EXPECTED.items() if r["kind"] in kinds)
            assert r["expected_technique"] == tech
            assert (r["labelled_expected"] == "") == (tech == "none")
            assert r["match_method"] in {"uid", "dup_uid", "none"}
            assert (r["match_method"] == "none") == (r["labelled"] == "0")
            if r["labelled_expected"] == "1":
                assert r["labelled"] == "1" and tech in r["label_techniques"].split(";")


@pytest.mark.slow
def test_lba04_target_4624_rows_are_never_scored(recall_runs):
    n = 0
    for t in KEYED:
        for r in rows_of(recall_runs, t):
            if r["kind"] == "target_4624":
                n += 1
                assert r["scored"] == "0" and r["expected_technique"] == "none" and r["labelled_expected"] == ""
    assert n == 41                                                  # decision 060


@pytest.mark.slow
def test_lba04_benign_and_background_key_rows_are_never_scored(recall_runs):
    seen = Counter()
    for t in KEYED:
        for r in rows_of(recall_runs, t):
            if r["role"] in ("benign", "background"):
                seen[r["role"]] += 1
                assert r["scored"] == "0", (t, r["event_uid"])
            if r["scored"] == "1":
                assert set(r["role"].split(";")) & {"attack", "step"}, (t, r["event_uid"])
    assert seen["benign"] > 0 and seen["background"] > 0


@pytest.mark.slow
def test_lba04_recall_per_technique_equals_an_independent_derivation(recall_runs):
    derived: dict[str, list[int]] = {}
    for t in KEYED:
        need(t)
        d = derive(t)
        # the scored rows of the stage are exactly the independently derived ones, uid by uid
        got = {r["event_uid"]: (r["expected_technique"], r["kind"], r["labelled_expected"] == "1")
               for r in rows_of(recall_runs, t) if r["scored"] == "1"}
        assert got == d, f"{t}: {len(set(got) ^ set(d))} uids differ, {sum(got.get(u) != d.get(u) for u in set(got) & set(d))} cells differ"
        for tech, _kind, ok in d.values():
            for name in (tech, "overall"):
                slot = derived.setdefault(name, [0, 0])
                slot[0] += ok
                slot[1] += 1
    assert derived == {"T1003.001": [14, 14], "T1021.002": [5, 23], "T1570": [10, 15], "T1569.002": [8, 8],
                       "T1021.006": [9, 9], "overall": [46, 69]}        # decision 060 development numbers


@pytest.mark.slow
def test_lba04_recall_counts_function_on_the_real_rows_equals_the_stated_numbers(recall_runs):
    rows = [r for t in KEYED for r in rows_of(recall_runs, t)]
    assert lrc.recall_counts(rows) == {"T1003.001": (14, 14), "T1021.002": (5, 23), "T1570": (10, 15),
                                       "T1569.002": (8, 8), "T1021.006": (9, 9), "overall": (46, 69)}


@pytest.mark.slow
def test_lba04_every_key_dump_is_in_the_recall_rows_and_labelled(recall_runs):
    """LBA-02 through the recall: the 14 lsass_dump rows are scored and all carry T1003.001."""
    rows = [r for t in KEYED for r in rows_of(recall_runs, t) if r["kind"] == "lsass_dump"]
    assert len(rows) == 14 and all(r["scored"] == "1" and r["labelled_expected"] == "1" for r in rows)


@pytest.mark.slow
def test_lba04_fresh_rows_equal_the_committed_out_evaluate_files(recall_runs):
    for t in KEYED:
        committed = REPO / "out" / "evaluate" / t / "label_recall.csv"
        if not committed.is_file():
            missing_input(f"{t}: out/evaluate/{t}/label_recall.csv missing")
        assert committed.read_bytes() == (recall_runs[t] / "label_recall.csv").read_bytes(), t


@pytest.mark.slow
def test_lba04_t01_trials_give_counts_only():
    for t in T01:
        for p in (db_path(t), REPO / "out" / "label" / t / "event_labels.csv"):
            if not p.is_file():
                missing_input(f"{t}: missing {p.name}")
        rec = label_run.label_trial(REPO, t, "development")
        assert rec.rows is None and rec.counts["label_rows"] > 0 and rec.unkinded == {}
        assert not (REPO / "out" / "evaluate" / t / "label_recall.csv").exists()


@pytest.mark.slow
def test_lba04_t01_cli_writes_nothing_and_the_summary_has_counts_for_t01_only(tmp_path, capsys):
    t = T01[0]
    need_db = db_path(t)
    if not need_db.is_file():
        missing_input(f"{t}: DB missing")
    out = tmp_path / "t01_out"
    assert em.main(["--label-recall", "--trial", t, "--out", str(out)]) == 0
    assert not out.exists()
    assert "no approved key" in capsys.readouterr().out
    md = REPO / "out" / "evaluate" / "development" / "label_recall.md"
    if not md.is_file():
        missing_input("out/evaluate/development/label_recall.md missing")
    text = md.read_text(encoding="utf-8")
    per_trial = text.split("## Recall per trial")[1].split("##")[0]
    assert all(t in per_trial for t in KEYED) and not any(t in per_trial for t in T01)
    counts = text.split("## Label counts per trial")[1].split("##")[0]
    assert all(t in counts for t in T01)
    assert "| 46/69" not in text or "46/69 (66.7 %)" in text


@pytest.mark.slow
def test_lba04_fresh_summary_equals_the_committed_markdown():
    """The summary built in memory from the nine trials equals out/evaluate/development/label_recall.md (read-only)."""
    for t in DEV:
        need_one = [db_path(t), REPO / "out" / "label" / t / "event_labels.csv"]
        if not all(p.is_file() for p in need_one):
            missing_input(f"{t}: inputs missing")
    md = REPO / "out" / "evaluate" / "development" / "label_recall.md"
    if not md.is_file():
        missing_input("label_recall.md missing")
    res = [label_run.label_trial(REPO, t, "development") for t in DEV]
    fresh, committed = lrc.summary_md("development", res), md.read_text(encoding="utf-8")
    marker = "## Inputs (SHA-256)"
    # everything the report says about the recall (numbers, misses, counts) is current ...
    assert fresh.split(marker)[0] == committed.split(marker)[0]


@pytest.mark.slow
def test_lba04_committed_summary_records_the_current_label_and_key_files():
    """T7.7 style: the input hashes in out/evaluate/development/label_recall.md equal the files now in out/label (a
    label re-run after the summary was written makes the summary stale; rerun `python -m evaluate --label-recall
    --development`)."""
    import hashlib
    md = REPO / "out" / "evaluate" / "development" / "label_recall.md"
    if not md.is_file():
        missing_input("label_recall.md missing")
    sec = md.read_text(encoding="utf-8").split("## Inputs (SHA-256)")[1].strip().splitlines()
    head = [c.strip() for c in sec[0].strip("|").split("|")]
    table = {}
    for line in sec[2:]:
        cells = [c.strip() for c in line.strip("|").split("|")]
        table[cells[0]] = dict(zip(head, cells))
    stale = []
    for t in DEV:
        lab = REPO / "out" / "label" / t
        if not (lab / "event_labels.csv").is_file():
            missing_input(f"{t}: out/label missing")
        rec = table[t]
        for col, name in (("event_labels_sha256", "event_labels.csv"), ("label_run_info_sha256", "run_info.json")):
            if rec[col] != hashlib.sha256((lab / name).read_bytes()).hexdigest():
                stale.append(f"{t}:{name}")
    assert stale == [], f"stale recall summary for {stale}"


@pytest.mark.slow
def test_lba04_link_accuracy_then_recall_then_link_accuracy_keep_both_outputs(tmp_path):
    t = "s04_t00"
    need(t)
    if not (REPO / "out" / "stitch" / t / "run_info.json").is_file():
        missing_input(f"{t}: out/stitch missing")
    out = tmp_path / "both"
    assert em.main(["--trial", t, "--out", str(out)]) == 0
    link_first = {p.name: p.read_bytes() for p in out.iterdir()}
    assert sorted(link_first) == sorted(LINK_FILES)
    assert em.main(["--label-recall", "--trial", t, "--out", str(out)]) == 0
    after_recall = {p.name: p.read_bytes() for p in out.iterdir()}
    assert sorted(after_recall) == sorted(LINK_FILES + ["label_recall.csv"])
    assert {n: b for n, b in after_recall.items() if n != "label_recall.csv"} == link_first
    assert em.main(["--trial", t, "--out", str(out)]) == 0
    after_link = {p.name: p.read_bytes() for p in out.iterdir()}
    assert sorted(after_link) == sorted(LINK_FILES + ["label_recall.csv"])
    assert after_link["label_recall.csv"] == after_recall["label_recall.csv"]
    for n in LINK_FILES:
        if n != "run_info.json":
            assert after_link[n] == link_first[n], n
    # run_info.json differs only in the timestamp
    a, b = json.loads(after_link["run_info.json"]), json.loads(link_first["run_info.json"])
    a.pop("generated_utc"), b.pop("generated_utc")
    assert a == b


@pytest.mark.slow
def test_lba04_recall_twice_is_byte_identical_and_keeps_the_link_files(tmp_path):
    t = "s05_t00"
    need(t)
    out = tmp_path / "r"
    assert em.main(["--label-recall", "--trial", t, "--out", str(out)]) == 0
    first = (out / "label_recall.csv").read_bytes()
    assert em.main(["--label-recall", "--trial", t, "--out", str(out)]) == 0
    assert (out / "label_recall.csv").read_bytes() == first


# ---------------------------------------------------------------- refusals
@pytest.mark.parametrize("trial", ["s02_t02", "s05_t07", "s07_t10", "s01_t00", "bogus"])
def test_lba04_a_test_trial_is_refused_and_nothing_is_written(tmp_path, trial):
    out = tmp_path / "must_not_exist"
    assert em.main(["--label-recall", "--trial", trial, "--repo", str(tmp_path / "no_repo"), "--out", str(out)]) == 2
    assert not out.exists() and not (tmp_path / "no_repo").exists()


def test_lba04_option_combinations_that_do_not_apply_are_refused(tmp_path):
    out = tmp_path / "x"
    assert em.main(["--label-recall", "--development", "--out", str(out), "--repo", str(tmp_path / "r")]) == 2
    assert em.main(["--label-recall", "--trial", "s04_t00", "--stitch-dir", str(tmp_path / "s"),
                    "--repo", str(tmp_path / "r")]) == 2
    assert not out.exists()


def test_lba04_out_inside_the_repo_but_outside_out_is_refused_and_nothing_is_created():
    """A keyed trial (the --out check comes after the inputs); only non-existing targets are used, so a broken refusal
    could never replace an existing folder."""
    t = "s04_t00"
    if not (REPO / "out" / "label" / t / "event_labels.csv").is_file() or not db_path(t).is_file():
        missing_input("inputs missing")
    for rel in ("docs/label_recall_must_not_exist", "data/label_recall_must_not_exist", "label_recall_must_not_exist"):
        target = REPO / rel
        assert em.main(["--label-recall", "--trial", t, "--out", str(target)]) == 2
        assert not target.exists(), rel


def test_lba04_a_foreign_file_in_an_existing_out_folder_is_refused(tmp_path):
    t = "s04_t00"
    folder = tmp_path / "precious"
    folder.mkdir()
    (folder / "keep_me.txt").write_text("mine", encoding="utf-8")
    if not (REPO / "out" / "label" / t / "event_labels.csv").is_file() or not db_path(t).is_file():
        missing_input("inputs missing")
    assert em.main(["--label-recall", "--trial", t, "--out", str(folder)]) == 2
    assert sorted(p.name for p in folder.iterdir()) == ["keep_me.txt"]


def test_lba04_the_writer_file_names_and_trial_files():
    assert writers.LABEL_RECALL_FILE == "label_recall.csv" and writers.LABEL_RECALL_MD == "label_recall.md"
    assert "label_recall.csv" in em.TRIAL_FILES


# ================================================================================================ stage review 061 (S06 etc.)
def test_every_synthetic_row_carries_the_label_run_hash_atk_s06():
    rows, _ = synthetic_rows()
    assert rows and {r["label_run_sha256"] for r in rows} == {RUN_SHA}


def test_recall_rows_require_the_label_run_hash_keyword():
    key, shares = synthetic_key()
    with pytest.raises(TypeError):
        lrc.recall_rows("t", key, shares, [])                       # no label_run_sha256


@pytest.mark.slow
def test_lba04_rows_carry_the_sha256_of_the_label_run_info_they_were_built_from(recall_runs):
    import hashlib
    for t in KEYED:
        want = hashlib.sha256((REPO / "out" / "label" / t / "run_info.json").read_bytes()).hexdigest()
        assert {r["label_run_sha256"] for r in rows_of(recall_runs, t)} == {want}, t


@pytest.mark.slow
def test_atk_s06_a_kept_link_file_of_another_trial_refuses_the_recall_and_leaves_the_folder(tmp_path):
    """`--trial s03_t00 --out <folder holding s02 files>`: exit 2, the folder is untouched."""
    for t in ("s02_t00", "s03_t00"):
        need(t)
    if not (REPO / "out" / "stitch" / "s02_t00" / "run_info.json").is_file():
        missing_input("out/stitch/s02_t00 missing")
    folder = tmp_path / "s02_files"
    assert em.main(["--trial", "s02_t00", "--out", str(folder)]) == 0
    assert em.main(["--label-recall", "--trial", "s02_t00", "--out", str(folder)]) == 0
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    assert em.main(["--label-recall", "--trial", "s03_t00", "--out", str(folder)]) == 2
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]          # no temporary sibling left


@pytest.mark.slow
def test_atk_s06_a_kept_recall_file_of_another_trial_refuses_the_link_evaluation(tmp_path):
    for t in ("s02_t00", "s03_t00"):
        need(t)
    if not (REPO / "out" / "stitch" / "s03_t00" / "run_info.json").is_file():
        missing_input("out/stitch/s03_t00 missing")
    folder = tmp_path / "s02_recall"
    assert em.main(["--label-recall", "--trial", "s02_t00", "--out", str(folder)]) == 0
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    assert em.main(["--trial", "s03_t00", "--out", str(folder)]) == 2
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before


@pytest.mark.slow
def test_atk_s06_a_t01_trial_with_out_inside_the_repo_outside_out_is_refused_and_nothing_is_created():
    """The --out check now comes before the no-key return (061)."""
    t = "s02_t01"
    for p in (db_path(t), REPO / "out" / "label" / t / "event_labels.csv"):
        if not p.is_file():
            missing_input(f"{t}: missing {p.name}")
    for rel in ("docs/label_recall_t01_must_not_exist", "data/label_recall_t01_must_not_exist",
                "label_recall_t01_must_not_exist"):
        target = REPO / rel
        assert em.main(["--label-recall", "--trial", t, "--out", str(target)]) == 2
        assert not target.exists(), rel
