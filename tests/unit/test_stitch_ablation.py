"""Spec 06_evaluate section 10, stitch half of the ablation switch: AB-01, AB-05, AB-06, AB-07 (fast, synthetic).

Written from the spec, not from the code (the code was read for names and signatures only). Rules tested:
- AB-01: only `cmdline_target` may be disabled; `StitchParams(disabled_methods=...)` and the CLI refuse any other name;
  the disabled set is recorded in `run_info.json` / `stats.json` (and in `parameters`).
- AB-05: a default run writes no `disabled_methods` key anywhere (`params_dict`, `disabled_block`, run_info, stats,
  report), so its bytes are those of the pre-change code.
- AB-06: `--disable-method` is refused when `--repo` (or `--out`) is, or lies in, the real repository; exit 2 and nothing
  is written (the stage entry points are replaced by functions that fail the test if called).
- AB-07: with the method disabled, `by_cmdline` returns an empty result, `link_subject` has no command-line row or
  session, the tier falls back to what the other evidence gives, `data_limits` counts 0 command-line evidence after the
  last event, `read_commands` reads nothing, and the report carries the ABLATION line only then.

World helpers come from `test_stitch_source` (one member 4624 on ep-02, source session 5000 on ep-01), from
`test_stitch_check_links` (data limits) and from `test_stitch_outputs` (a complete synthetic repo with command lines).
Nothing real is opened; nothing is written under the real `out/`.
"""
from __future__ import annotations

import dataclasses
import importlib
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stitch_fixtures as sf  # noqa: E402
import test_stitch_check_links as tcl  # noqa: E402
import test_stitch_outputs as tso  # noqa: E402
import test_stitch_source as tss  # noqa: E402
from stitch import links as links_mod  # noqa: E402
from stitch import report as rp  # noqa: E402
from stitch import source as src  # noqa: E402
from stitch import tiers  # noqa: E402
from stitch.index import params_dict  # noqa: E402
from stitch.params import DISABLEABLE_METHODS, METHODS, StitchParams  # noqa: E402

sm = importlib.import_module("stitch.__main__")

CMD = "cmdline_target"
OFF = StitchParams(disabled_methods=frozenset({CMD}))
ON = StitchParams()


# ================================================================================================ AB-01 parameters
def test_ab01_only_cmdline_target_may_be_disabled():
    assert tuple(DISABLEABLE_METHODS) == (CMD,)
    assert CMD in METHODS


def test_ab01_default_params_have_no_disabled_methods_and_the_key_is_absent_from_params_dict():
    assert StitchParams().disabled_methods == frozenset()
    assert "disabled_methods" not in params_dict(StitchParams())


def test_ab01_params_dict_lists_the_disabled_set_when_set():
    assert params_dict(OFF)["disabled_methods"] == [CMD]
    rest = {k: v for k, v in params_dict(OFF).items() if k != "disabled_methods"}
    assert rest == params_dict(StitchParams())                       # nothing else moves


@pytest.mark.parametrize("name", ["source_4648", "sysmon3_port", "target_only", "nonsense", ""])
def test_ab01_any_other_method_name_raises(name):
    with pytest.raises(ValueError):
        StitchParams(disabled_methods={name})


def test_ab01_a_mix_of_a_good_and_a_bad_name_raises():
    with pytest.raises(ValueError):
        StitchParams(disabled_methods={CMD, "source_4648"})


def test_ab01_method_enabled_follows_the_set():
    assert ON.method_enabled(CMD) and OFF.method_enabled("sysmon3_port") and OFF.method_enabled("source_4648")
    assert not OFF.method_enabled(CMD)


def test_ab01_dataclass_replace_keeps_the_refusal():
    with pytest.raises(ValueError):
        dataclasses.replace(ON, disabled_methods=frozenset({"source_4648"}))


# ================================================================================================ AB-05 disabled_block
def test_ab05_disabled_block_is_empty_by_default_and_names_the_method_when_set():
    assert rp.disabled_block(ON) == {}
    assert rp.disabled_block(OFF) == {"disabled_methods": [CMD]}


# ================================================================================================ AB-07 by_cmdline
def cmd_world(*, with_pre: bool = False) -> tss.World:
    """One hop M1 (ep-01 -> ep-02) at 100 s whose source session 5000 (account acct_a, the member's account) ran one
    command naming ep-02 at 90 s; optionally a second command 200 s before the first member (before the look-back)."""
    w = tss.World()
    w.member("M1")
    w.src_logon("L5000", 0.0, tss.S5000, account="acct_a")
    w.s1("S1", 90.0, "{G1}", tss.S5000)
    if with_pre:
        w.s1("S0", 0.0, "{G0}", tss.S5000)                            # 100 s before M1: in the 120 s band before range
    return w


def test_ab07_by_cmdline_finds_the_session_when_enabled():
    res = tss.run(cmd_world(), ON).cmdline()
    assert res.sessions == [tss.skey(tss.S5000)]


def test_ab07_by_cmdline_counts_the_out_of_range_command_when_enabled_so_the_disabled_zero_is_real():
    assert tss.run(cmd_world(with_pre=True), ON).cmdline().before_range == 1


def test_ab07_by_cmdline_returns_an_empty_result_when_disabled():
    res = tss.run(cmd_world(with_pre=True), OFF).cmdline()
    assert res.method == CMD
    assert res.evidence == [] and res.sessions == []
    assert (res.system_evidence, res.before_range, res.after_range) == (0, 0, 0)


def test_ab07_by_cmdline_ignores_command_facts_a_caller_still_holds():
    """The method itself honours the switch: facts passed in are not reintroduced."""
    r = tss.run(cmd_world(), OFF)
    assert r.w.cmd, "the world does hold command facts"
    assert src.by_cmdline(r.subject, r.index.processes, r.w.cmd, OFF).evidence == []


def test_ab07_link_subject_has_no_command_line_row_session_or_count_when_disabled():
    r_on, r_off = tss.run(cmd_world(), ON), tss.run(cmd_world(), OFF)
    on, off = r_on.links(), r_off.links()
    assert [row.method for row in on.rows] == [CMD]
    assert [row.method for row in off.rows] == [src.METHOD_TARGET_ONLY]
    assert off.candidate_counts[CMD] == 0 and off.candidate_count_all == 0
    assert off.sessions == {} and all(CMD not in v for v in off.session_methods.values())
    assert on.candidate_count_all == 1 and on.candidate_counts[CMD] == 1


def test_ab07_a_command_line_only_hop_falls_from_tier_b_to_d_and_is_kept_as_target_only():
    """Effect in the stated direction: the key hop's only evidence was the command line (spec 06 AB-07: effects are
    reported, not hidden)."""
    on, off = tss.run(cmd_world(), ON), tss.run(cmd_world(), OFF)
    assert tiers.hop_verdicts(on.hop, on.links(), []).best_tier == "B"
    hv = tiers.hop_verdicts(off.hop, off.links(), [])
    assert hv.best_tier == "D" and hv.sessions == {}


def test_ab07_name_check_cannot_match_without_command_line_evidence():
    """tiers.name_check_of reads only cmdline_target evidence, so with it empty no session matches (names from command
    lines no longer break a tie or move a link_rank)."""
    r = tss.run(cmd_world(), OFF)
    sl = r.links()
    assert sl.methods[CMD].evidence == []
    got, names, uids = tiers.name_check_of(tss.skey(tss.S5000), sl, ["payloadxq.exe"])
    assert got == tiers.NAME_NO_MATCH and names == [] and uids == []


def test_ab07_name_check_is_not_run_not_no_match_when_the_caller_says_the_method_is_disabled():
    """Attacker reading (ATK-EV-41, stated by the coordinator): a check that did not run must not read as `no_match`;
    a hop without names stays `no_names` (that fact comes from artefacts, not from command lines)."""
    r = tss.run(cmd_world(), OFF)
    sl = r.links()
    key = tss.skey(tss.S5000)
    assert tiers.name_check_of(key, sl, ["payloadxq.exe"], run=False) == ("not_run", [], [])
    assert tiers.name_check_of(key, sl, [], run=False) == (tiers.NAME_NO_NAMES, [], [])
    assert tiers.name_check_of(key, tss.run(cmd_world(), ON).links(), ["payloadxq.exe"], run=True)[0] == "no_match"


# ================================================================================================ AB-07 data_limits
def limits_with_cmd_after():
    w = tcl.limits_world()
    w.s1("S1", 120.0, "{G1}", 5000)                                   # names ep-02 after its last Security event
    return w


def test_ab07_data_limits_counts_the_command_after_the_last_event_when_enabled():
    lm = tcl.Built(limits_with_cmd_after()).limits(ON)[tcl.TGT]
    assert lm.evidence_after[CMD] == 1 and lm.data_limitation == 1


def test_ab07_data_limits_cmdline_count_is_zero_when_disabled():
    lm = tcl.Built(limits_with_cmd_after()).limits(OFF)[tcl.TGT]
    assert lm.evidence_after[CMD] == 0 and lm.evidence_after_uids[CMD] == []
    assert lm.data_limitation == 0 and lm.hops_near_end == []


def test_ab07_data_limits_other_methods_still_count_when_cmdline_is_disabled():
    w = limits_with_cmd_after()
    w.s3("N1", 121.0)
    lm = tcl.Built(w).limits(OFF)[tcl.TGT]
    assert lm.evidence_after == {tcl.PORT: 1, tcl.E4648: 0, tcl.CMD: 0}
    assert lm.data_limitation == 1


# ================================================================================================ AB-07 read_commands
class _NoUse:
    """A connection that fails the test on any use: a disabled run must not read command text at all."""

    def __getattr__(self, name):
        raise AssertionError(f"the database was used ({name}) although cmdline_target is disabled")


def test_ab07_read_commands_returns_empty_without_touching_the_database_when_disabled(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("read_command_results must not be called when disabled")
    monkeypatch.setattr(links_mod, "read_command_results", boom)
    assert links_mod.read_commands(_NoUse(), None, None, None, OFF) == {}


def test_ab07_read_commands_reads_when_enabled(monkeypatch):
    seen = []
    monkeypatch.setattr(links_mod, "read_command_results", lambda *a, **k: seen.append(1) or {"X": "fact"})
    monkeypatch.setattr(links_mod, "process_uids_by_host", lambda *_: {})
    monkeypatch.setattr(links_mod, "command_probes", lambda *_: ())
    monkeypatch.setattr(links_mod, "names_by_target", lambda *_: {})

    class _Index:
        processes = None
    assert links_mod.read_commands(object(), _Index(), None, None, ON) == {"X": "fact"}
    assert seen == [1]


# ================================================================================================ AB-06 CLI refusals
@pytest.fixture
def guarded(monkeypatch):
    """Any call that would run or write a stitch run fails the test: a refusal must come before all of them."""
    def boom(*a, **k):
        raise AssertionError("the stitch run started although the ablation flag must have been refused")
    monkeypatch.setattr(sm, "run_links_checked", boom)
    monkeypatch.setattr(sm, "replace_folder", boom)
    monkeypatch.setattr(sm, "build_files", boom)


def real_out_snapshot() -> dict[str, int]:
    root = REPO / "out" / "stitch"
    if not root.is_dir():
        return {}
    return {f.relative_to(root).as_posix(): f.stat().st_mtime_ns for f in root.rglob("*") if f.is_file()}


def test_ab06_disable_method_with_the_real_repo_is_refused_with_exit_2_and_nothing_written(guarded, capsys):
    before = real_out_snapshot()
    code = sm.main(["--trial", "s04_t00", "--disable-method", CMD, "--repo", str(REPO)])
    err = capsys.readouterr().err
    assert code == 2 and err.startswith("refused:") and "scratch" in err
    assert real_out_snapshot() == before
    assert not (REPO / "out" / "stitch" / ".s04_t00.tmp").exists()


def test_ab06_disable_method_without_repo_defaults_to_the_real_repo_and_is_refused(guarded, capsys):
    assert sm.main(["--trial", "s04_t00", "--disable-method", CMD]) == 2
    assert "refused:" in capsys.readouterr().err


def test_ab06_a_subfolder_of_the_real_repo_is_refused_too(guarded, capsys):
    assert sm.main(["--trial", "s04_t00", "--disable-method", CMD, "--repo", str(REPO / "docs")]) == 2
    assert "refused:" in capsys.readouterr().err


def test_ab06_out_inside_the_real_repo_is_refused_even_with_a_scratch_repo(guarded, tmp_path, capsys):
    out = REPO / "out" / "ablation" / "must_not_exist_x"
    code = sm.main(["--trial", "s04_t00", "--disable-method", CMD, "--repo", str(tmp_path), "--out", str(out)])
    assert code == 2 and "refused:" in capsys.readouterr().err
    assert not out.exists()


@pytest.mark.parametrize("name", ["source_4648", "sysmon3_port", "bogus"])
def test_ab01_unknown_method_is_refused_with_a_scratch_repo(guarded, tmp_path, capsys, name):
    code = sm.main(["--trial", "s04_t00", "--disable-method", name, "--repo", str(tmp_path)])
    err = capsys.readouterr().err
    assert code == 2 and err.startswith("refused:") and name in err
    assert list(tmp_path.iterdir()) == []                             # nothing written


def test_ab01_unknown_method_is_refused_with_the_real_repo_too(guarded, capsys):
    assert sm.main(["--trial", "s04_t00", "--disable-method", "source_4648", "--repo", str(REPO)]) == 2
    assert "refused:" in capsys.readouterr().err


def test_ab06_no_flag_is_not_refused_for_the_real_repo_by_the_flag_check():
    assert sm.disable_refusal([], REPO, None) is None


# ================================================================================================ end to end (synthetic repo)
def run_in(fake, *extra: str) -> int:
    return sm.main(["--trial", fake.trial, "--repo", str(fake.repo), *extra])


def read_links(fake) -> list[dict[str, str]]:
    return tso.read_csv(tso.out_folder(fake) / "links.csv")


@pytest.fixture(scope="module")
def pair(tmp_path_factory):
    """The same synthetic trial stitched by default and with cmdline_target disabled, in two scratch repos."""
    d = tso.build_repo(tmp_path_factory.mktemp("abl_default"), "repo")
    a = tso.build_repo(tmp_path_factory.mktemp("abl_off"), "repo")
    assert run_in(d) == 0
    assert run_in(a, "--disable-method", CMD) == 0
    return d, a


def files_text(fake) -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in tso.out_folder(fake).iterdir()}


def test_ab01_default_run_has_cmdline_rows_in_this_world(pair):
    d, _a = pair
    assert any(r["method"] == CMD for r in read_links(d)), "the world must contain command-line evidence"


def test_ab07_ablated_run_has_no_cmdline_row_and_no_session_naming_it(pair):
    _d, a = pair
    rows = read_links(a)
    assert rows
    assert not [r for r in rows if r["method"] == CMD]
    assert not [r for r in rows if CMD in (r["session_methods"] or "").split(";")]


def test_ab07_ablated_name_check_never_matches_and_names_no_events(pair):
    _d, a = pair
    for r in read_links(a):
        assert r["name_check"] != "match" and r["name_check_event_uids"] == "" and r["name_check_names"] == ""


def test_ab07_ablated_name_check_is_not_run_or_no_names_never_no_match(pair):
    _d, a = pair
    assert {r["name_check"] for r in read_links(a)} <= {"not_run", "no_names"}


def test_ab07_default_run_name_check_does_match_somewhere_so_the_previous_test_is_not_vacuous(pair):
    d, _a = pair
    assert any(r["name_check"] == "match" for r in read_links(d))


def test_ab01_hops_are_the_same_hops_in_both_runs(pair):
    d, a = pair
    hd = tso.read_csv(tso.out_folder(d) / "hops.csv")
    ha = tso.read_csv(tso.out_folder(a) / "hops.csv")
    assert [h["hop_id"] for h in hd] == [h["hop_id"] for h in ha]       # no row lost or added; hops ignore the method
    assert list(hd[0]) == list(ha[0])


def test_ab05_default_run_carries_no_disabled_methods_anywhere(pair):
    d, _a = pair
    for name, text in files_text(d).items():
        assert "disabled_methods" not in text, name
        assert "ABLATION" not in text, name
    info = json.loads(files_text(d)["run_info.json"])
    assert "disabled_methods" not in info and "disabled_methods" not in info["parameters"]
    assert "disabled_methods" not in json.loads(files_text(d)["stats.json"])


def test_ab01_ablated_run_records_the_set_in_run_info_stats_and_parameters(pair):
    _d, a = pair
    t = files_text(a)
    info, stats = json.loads(t["run_info.json"]), json.loads(t["stats.json"])
    assert info["disabled_methods"] == [CMD] and info["parameters"]["disabled_methods"] == [CMD]
    assert stats["disabled_methods"] == [CMD]


def test_ab07_report_has_the_ablation_line_only_in_the_ablated_run(pair):
    d, a = pair
    assert "ABLATION" in files_text(a)["report.md"] and CMD in files_text(a)["report.md"]
    assert "ABLATION" not in files_text(d)["report.md"]


def test_ab05_parameters_of_both_runs_differ_only_by_the_disabled_set(pair):
    d, a = pair
    pd = json.loads(files_text(d)["run_info.json"])["parameters"]
    pa = json.loads(files_text(a)["run_info.json"])["parameters"]
    pa.pop("disabled_methods")
    assert pd == pa


def test_ab07_ablated_counts_in_stats_name_no_cmdline_hops(pair):
    """`hops_by_methods_linked` and the per-method counts must not list the disabled method as having linked a hop."""
    _d, a = pair
    stats = json.loads(files_text(a)["stats.json"])
    text = json.dumps({k: v for k, v in stats.items() if k in ("hops_by_methods_linked", "link_rows_by_method",
                                                                "candidate_count_all", "methods")})
    assert CMD not in text.replace("disabled_methods", "")
    linked = stats.get("hops_by_methods_linked")
    if isinstance(linked, dict):
        assert not [k for k in linked if CMD in str(k).split("+") + str(k).split(";") + str(k).split(",")]


def test_ab01_repeat_flag_and_order_do_not_matter(tmp_path):
    fake = tso.build_repo(tmp_path)
    assert run_in(fake, "--disable-method", CMD, "--disable-method", CMD) == 0
    assert json.loads(files_text(fake)["run_info.json"])["disabled_methods"] == [CMD]
