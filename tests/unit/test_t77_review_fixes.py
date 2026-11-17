"""Regression tests for the code bugs of the T7.7 stage review (docs/reviews/03_stitch-2026-11-17.md), fast and
synthetic. Each test fails on the code before the fix.

- ATK-17: `python -m evaluate --trial ... --out DIR` replaced ANY folder (the folder swap deletes the old one). Now the
  shared `lab_common.outdir` check refuses, before anything is written, a DIR inside the repository that is not strictly
  below `out/`, an existing file, and an existing folder holding anything but the trial file names (decision 054).
- ATK-23: evaluate compared the key's session uid with the whole `source_session_logon_uid` cell, which may hold several
  `;`-joined uids of one session (ST-05 copies / a second 4624 while open): a correct session scored as wrong.
- ATK-24: a Sysmon 1 agent uid of the key that is absent from `events_dedup` was skipped, which silently turned a keyed
  hop into a background hop. It is now a refusal (nothing written; the message names the key hop, not the uid).
- ATK-27: a service image path with an unterminated quote gave a "file name" cut from the argument text; it is now read
  like an unquoted path (first token), so `names` in hop_artefacts.csv holds a bare file name.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import evaluate_fixtures as fx  # noqa: E402
import stitch_fixtures as sf  # noqa: E402
from evaluate import EvalError, evaluate_trial  # noqa: E402
from evaluate import __main__ as em  # noqa: E402
from evaluate.keys import session_lookup_requests  # noqa: E402
from evaluate_fixtures import SESSION_KEY, ek, link_row, only_keyed, std_world  # noqa: E402
from lab_common import outdir as lab_outdir  # noqa: E402
from stitch import outdir as stitch_outdir  # noqa: E402
from stitch.artefacts import binary_file_name  # noqa: E402


# ================================================================================================ ATK-17
def cli(w: fx.World, out: Path) -> int:
    return em.main(["--trial", w.trial, "--repo", str(w.repo), "--stitch-dir", str(w.stitch_dir), "--out", str(out)])


def good_world(tmp_path: Path) -> fx.World:
    return std_world(tmp_path, links=[link_row("H1", 1, "cmdline_target", 1280, SESSION_KEY)])


@pytest.mark.parametrize("rel", ["ground_truth/approved", "src", "docs", "data/raw", "data", ".", "out", "tests/x"])
def test_atk17_evaluate_out_inside_the_repo_but_not_below_out_is_refused_and_the_tree_is_unchanged(tmp_path, capsys,
                                                                                                    rel):
    w = good_world(tmp_path)
    (w.repo / "src").mkdir(exist_ok=True)
    (w.repo / "src" / "keep.py").write_text("x = 1\n", encoding="utf-8")
    (w.repo / "docs").mkdir(exist_ok=True)
    before = sf.snapshot(w.repo)
    assert cli(w, w.repo / rel) == 2
    assert capsys.readouterr().err.startswith("refused:")
    assert sf.snapshot(w.repo) == before
    assert w.key_path.is_file()


def test_atk17_evaluate_out_folder_with_a_foreign_file_is_refused_and_left_untouched(tmp_path, capsys):
    w = good_world(tmp_path)
    target = tmp_path / "mine"
    target.mkdir()
    (target / "notes.txt").write_text("keep", encoding="utf-8")
    before = sf.snapshot(tmp_path)
    assert cli(w, target) == 2
    assert "notes.txt" in capsys.readouterr().err
    assert sf.snapshot(tmp_path) == before


def test_atk17_evaluate_out_naming_a_file_is_refused(tmp_path):
    w = good_world(tmp_path)
    target = tmp_path / "f.txt"
    target.write_text("x", encoding="utf-8")
    assert cli(w, target) == 2
    assert target.read_text(encoding="utf-8") == "x"


def test_atk17_evaluate_out_outside_the_repo_or_below_out_still_works_and_rebuilds_its_own_folder(tmp_path):
    w = good_world(tmp_path)
    outside = tmp_path / "elsewhere"
    assert cli(w, outside) == 0
    names = sorted(p.name for p in outside.iterdir())
    assert set(names) <= set(em.TRIAL_FILES) and "run_info.json" in names
    assert cli(w, outside) == 0                                   # its own files only: rebuilt
    below = w.repo / "out" / "evaluate_alt" / w.trial
    assert cli(w, below) == 0 and below.is_dir()


def test_atk17_evaluate_default_folder_unchanged_behaviour(tmp_path):
    w = good_world(tmp_path)
    folder = w.repo / "out" / "evaluate" / w.trial
    folder.mkdir(parents=True)
    (folder / "stale.txt").write_text("old", encoding="utf-8")
    assert em.main(["--trial", w.trial, "--repo", str(w.repo), "--stitch-dir", str(w.stitch_dir)]) == 0
    assert not (folder / "stale.txt").exists()


def test_atk17_evaluate_trial_files_are_the_writer_names():
    from evaluate import writers
    assert set(em.TRIAL_FILES) == {writers.KEYED_FILE, writers.FACTS_FILE, writers.TOTALS_FILE, writers.JSON_FILE,
                                   writers.MD_FILE, writers.RUN_INFO_FILE}


def test_atk17_stitch_and_evaluate_share_one_rule():
    assert stitch_outdir.protected_reason is lab_outdir.protected_reason
    assert stitch_outdir.foreign_entries is lab_outdir.foreign_entries


def test_atk17_out_target_refusal_returns_none_for_a_free_target(tmp_path):
    assert lab_outdir.out_target_refusal(tmp_path / "new", tmp_path / "repo", ["a"]) is None


# ================================================================================================ ATK-23
@pytest.mark.parametrize("cell", [f"{SESSION_KEY};U500copy", f"U500copy;{SESSION_KEY}"])
def test_atk23_a_joined_uid_cell_holding_the_key_uid_is_the_key_session(tmp_path, cell):
    w = std_world(tmp_path, links=[link_row("H1", 1, "cmdline_target", 0x500, cell)])
    row = only_keyed(evaluate_trial(w.repo, w.trial, "development", w.stitch_dir))
    assert row["session_compare"] == "logon_uid"
    assert (row["among_candidates"], row["rank1"], row["only_candidate"]) == ("1", "correct", "1")
    assert row["key_session_tier"] == "B"


def test_atk23_a_joined_cell_without_the_key_uid_is_still_another_session(tmp_path):
    w = std_world(tmp_path, links=[link_row("H1", 1, "cmdline_target", 0x600, "U600;U600copy")])
    row = only_keyed(evaluate_trial(w.repo, w.trial, "development", w.stitch_dir))
    assert (row["among_candidates"], row["rank1"]) == ("0", "wrong")


def test_atk23_joined_key_session_and_another_session_tied_at_rank1_is_tied_correct(tmp_path):
    links = [link_row("H1", 1, "cmdline_target", 0x500, f"{SESSION_KEY};U500copy", tie=1, tier="C"),
             link_row("H1", 2, "source_4648", 0x600, "U600", tie=1, tier="C")]
    w = std_world(tmp_path, links=links)
    row = only_keyed(evaluate_trial(w.repo, w.trial, "development", w.stitch_dir))
    assert row["rank1"] == "tied_correct" and row["only_candidate"] == "0"


# ================================================================================================ ATK-24
def test_atk24_a_key_agent_uid_absent_from_the_db_is_refused_not_turned_into_background():
    key_hop = {"hop_id": "k9", "agent_event_uids": ["GONE1", "C1"]}
    event_keys = {"GONE1": ek("GONE1", "ep-01", "Sysmon", 1, 100.0), "C1": ek("C1", "ep-01", "Sysmon", 1, 101.0)}
    from evaluate.inputs import EventRow
    events = {"C1": EventRow("C1", "ep-01", "Sysmon", 1, 0, 0x500)}
    with pytest.raises(EvalError) as exc:
        session_lookup_requests(key_hop, event_keys, events)
    msg = str(exc.value)
    assert msg.startswith("refused:") and "k9" in msg and "1 Sysmon 1" in msg and "GONE1" not in msg


def test_atk24_a_present_agent_uid_with_a_null_session_is_still_skipped_as_051_reads():
    from evaluate.inputs import EventRow
    key_hop = {"hop_id": "k9", "agent_event_uids": ["C1"]}
    event_keys = {"C1": ek("C1", "ep-01", "Sysmon", 1, 100.0)}
    assert session_lookup_requests(key_hop, event_keys, {"C1": EventRow("C1", "ep-01", "Sysmon", 1, 0, None)}) == []


def test_atk24_end_to_end_the_cli_refuses_and_writes_nothing(tmp_path, capsys):
    w = std_world(tmp_path, links=[link_row("H1", 1, "target_only")],
                  key_kw={"session_hex": None, "session_evidence": None, "agent_uids": ["C9"]},
                  event_keys={"C9": ek("C9", "ep-01", "Sysmon", 1, 100.0)})
    out = tmp_path / "out_eval"
    assert cli(w, out) == 2
    assert "refused:" in capsys.readouterr().err
    assert not out.exists()


# ================================================================================================ ATK-27
@pytest.mark.parametrize("image,want", [
    ('"C:\\Windows\\Ypay.exe -arg \\\\host\\share\\secretish part', "Ypay.exe"),
    ("'C:\\Windows\\Ypay.exe /x a\\b c", "Ypay.exe"),
    ('"C:\\Program Files\\app dir\\Ypay.exe" -k grp', "Ypay.exe"),     # terminated: unchanged
    ('"', ""),
    ('"   ', ""),
])
def test_atk27_binary_file_name_never_returns_argument_text(image, want):
    got = binary_file_name(image)
    assert got == want
    assert " " not in got


# ================================================================================================ OQ-1 (decision 055)
def _hops_with_a_copied_member(tmp_path: Path) -> list[dict[str, str]]:
    """The T7.4 writer world plus an ST-05 near-duplicate copy of member M1 (same host, channel, record ID)."""
    import csv
    import importlib
    import io
    from test_stitch_outputs import world_rows, write_gate_csv
    rows, trig, sup = world_rows()
    m1 = next(r for r in rows if r["event_uid"] == "M1")
    rows.append(dict(m1, event_uid="M1-copy"))
    fake = sf.make_repo(tmp_path, rows, name="copy")
    write_gate_csv(fake.paths.gate_dir / "triggers.csv", trig, ["event_uid"])
    write_gate_csv(fake.paths.gate_dir / "supporting.csv", sup, ["event_uid"])
    out = tmp_path / "copy_out"
    sm = importlib.import_module("stitch.__main__")
    assert sm.main(["--trial", fake.trial, "--repo", str(fake.repo), "--out", str(out)]) == 0
    return list(csv.DictReader(io.StringIO((out / "hops.csv").read_text(encoding="utf-8"))))


def test_oq1_hops_csv_keeps_a_members_st05_copies_joined_by_bar_and_stays_parallel(tmp_path):
    rows = _hops_with_a_copied_member(tmp_path)
    (row,) = [r for r in rows if r["member_logon_uids"].split("|")[0] == "M1"]
    assert row["member_logon_uids"] == "M1|M1-copy"
    assert row["member_count"] == "1" and row["member_logon_ids"] == "7000"
    assert all(len(r["member_logon_uids"].split(";")) == int(r["member_count"]) for r in rows)


def test_oq1_member_uids_cell_without_copies_is_the_uid_alone():
    from stitch.outputs import member_uids_cell
    assert member_uids_cell("A", ["A"]) == "A"
    assert member_uids_cell("A", ["A", "B", "C"]) == "A|B|C"
    assert member_uids_cell("B", ["A", "B"]) == "B|A"


def test_oq1_evaluate_matches_a_key_that_names_the_copy_uid():
    from evaluate.keys import key_logons_in_hop, match_key_hop
    hop = {"hop_id": "H1", "member_logon_uids": "T0;T1|T1copy", "member_logon_ids": "255;256"}
    kh = {"target_event_uids": ["T1copy"], "target_logon_id": hex(256), "target_host": "ep-02"}
    res = match_key_hop(kh, [hop])
    assert res.outcome == "matched" and res.hop_ids == ("H1",) and res.member_uids == ("T1copy",)
    ekeys = {"T1copy": {"host": "ep-02", "channel": "Security", "event_id": 4624}}
    assert key_logons_in_hop(kh, ekeys, hop) == "1/1"


# ================================================================================================ OQ-2 (decision 055)
def test_oq2_target_only_ok_allows_unresolved_rows_but_not_a_candidate_session():
    from evaluate.link_accuracy import has_only_target_only
    to = link_row("H1", 1, "target_only")
    unresolved = dict(link_row("H1", 2, "sysmon3_port", 0, ""), source_session_id="", source_session_id_hex="",
                      session_unresolved_reason="no_sysmon1_in_window")
    assert has_only_target_only([to]) is True
    assert has_only_target_only([unresolved, to]) is True
    assert has_only_target_only([to, link_row("H1", 2, "cmdline_target", 0x600, "U600")]) is False
    assert has_only_target_only([unresolved]) is False                 # no target_only row at all
