"""T7.7 audit gap: STT-12 second clause on synthetic data ("`clock_unreliable` and `gate_clock_unreliable` as ST-02"),
until now checked only on the real s06_t01 trial (test_stitch_links_real).

ST-02: `clock_unreliable` = 1 on a row when a host of the row is `none`, `wide` or `stale` (or an event of the row was
logged before a counted clock change); `gate_clock_unreliable` carries the gate's value, inherited from the members'
gate rows. The two are kept apart, so a gate flag never sets the stitcher's own flag and the reverse.

World: the T7.4 writer world of `test_stitch_outputs.py` (hops M1, M2, M5 from ep-01, M3 from ep-03, M4 blank IP; all
to ep-02). Fast, synthetic, through `python -m stitch --out`.
"""
from __future__ import annotations

import csv
import importlib
import io
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_fixtures as cf  # noqa: E402
import stitch_fixtures as sf  # noqa: E402
from test_stitch_outputs import MEMBERS, world_rows, write_gate_csv  # noqa: E402

sm = importlib.import_module("stitch.__main__")


def run(tmp_path: Path, name: str, gate_flag_uids: set[str] = frozenset(), offsets: dict | None = None) -> dict:
    rows, trig, sup = world_rows()
    for t in trig:
        if t["anchor_logon_uid"] in gate_flag_uids:
            t["clock_unreliable"] = "1"
    fake = sf.make_repo(tmp_path, rows, name=name, offsets=offsets)
    write_gate_csv(fake.paths.gate_dir / "triggers.csv", trig, ["event_uid"])
    write_gate_csv(fake.paths.gate_dir / "supporting.csv", sup, ["event_uid"])
    out = tmp_path / f"{name}_out"
    assert sm.main(["--trial", fake.trial, "--repo", str(fake.repo), "--out", str(out)]) == 0
    tables = {}
    for n in ("hops.csv", "links.csv"):
        tables[n] = list(csv.DictReader(io.StringIO((out / n).read_text(encoding="utf-8"))))
    return tables


def by_member(tables: dict) -> dict[str, dict[str, str]]:
    """member uid -> its hops.csv row (every world hop has one member)."""
    return {r["member_logon_uids"]: r for r in tables["hops.csv"]}


def test_baseline_all_flags_zero(tmp_path):
    hops = by_member(run(tmp_path, "base"))
    assert set(hops) == {m["uid"] for m in MEMBERS}
    assert {(r["clock_unreliable"], r["gate_clock_unreliable"]) for r in hops.values()} == {("0", "0")}


def test_a_gate_flag_is_carried_to_its_hop_only_and_does_not_set_the_stitchers_flag(tmp_path):
    tables = run(tmp_path, "gate_flag", gate_flag_uids={"M1"})
    hops = by_member(tables)
    assert hops["M1"]["gate_clock_unreliable"] == "1" and hops["M1"]["clock_unreliable"] == "0"
    assert all(r["gate_clock_unreliable"] == "0" for u, r in hops.items() if u != "M1")
    m1 = hops["M1"]["hop_id"]
    assert all(r["clock_unreliable"] == "0" for r in tables["links.csv"] if r["hop_id"] == m1)


def test_a_wide_source_host_flags_the_hops_and_links_that_touch_it_and_not_the_gate_column(tmp_path):
    tables = run(tmp_path, "wide", offsets=cf.offsets_spec(ep_01=(0, "wide", True)))
    hops = by_member(tables)
    for uid in ("M1", "M2", "M5"):                                   # source ep-01
        assert hops[uid]["clock_unreliable"] == "1", uid
        assert hops[uid]["gate_clock_unreliable"] == "0", uid
    for uid in ("M3", "M4"):                                         # source ep-03 / unknown: ep-01 not involved
        assert hops[uid]["clock_unreliable"] == "0", uid
    ep01_hops = {hops[u]["hop_id"] for u in ("M1", "M2", "M5")}
    assert all(r["clock_unreliable"] == "1" for r in tables["links.csv"] if r["hop_id"] in ep01_hops)


def test_a_wide_target_host_flags_every_hop(tmp_path):
    hops = by_member(run(tmp_path, "wide_tgt", offsets=cf.offsets_spec(ep_02=(0, "wide", True))))
    assert {r["clock_unreliable"] for r in hops.values()} == {"1"}
    assert {r["gate_clock_unreliable"] for r in hops.values()} == {"0"}
