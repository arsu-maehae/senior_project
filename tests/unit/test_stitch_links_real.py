"""Real-data checks for T7.3 task 1 (plan sections 3 and 4, task 1): the scan extension that keeps the link kinds apart
must leave the committed T7.2 check files byte-identical, keep every link row inside the window and leave the DBs
unchanged. Slow; parametrised over `clock_offset.params.DEVELOPMENT_TRIALS` only, never t02-t10.

Written from the plan and decision 048, not from the implementation. Assertions and messages carry counts and uids
only, never command text. Nothing is written under the repo.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from answer_key.db import sha256_file  # noqa: E402
from clock_offset import params as co_params  # noqa: E402
from gate.timeutil import US_PER_MS  # noqa: E402
from stitch.check_index import check_text, run_check  # noqa: E402
from stitch.cmdtext import read_4648_targets, read_command_results, target_name_forms  # noqa: E402
from stitch.inputs import check_allowed, load_link_inputs, load_scan, trial_paths  # noqa: E402
from stitch.params import StitchParams  # noqa: E402

pytestmark = pytest.mark.slow

DEV = list(co_params.DEVELOPMENT_TRIALS)
PARAMS = StitchParams()
LINK_KINDS = {("Security", 5140), ("Security", 5145), ("Security", 4697), ("Security", 4648), ("Security", 4769),
              ("System", 7045), ("WinRM", 91)}
CHECK_REL = Path("out") / "stitch_check"


def _paths_or_skip(trial: str):
    assert trial in DEV, trial                 # belt and braces: only development trials, ever
    paths = trial_paths(REPO, trial)
    if not paths.db.is_file() or not (paths.gate_dir / "stats.json").is_file():
        pytest.skip(f"{trial}: trial DB or gate output missing")
    return paths


def _gate_sha_after(paths) -> str:
    return json.loads((paths.gate_dir / "stats.json").read_text(encoding="utf-8"))["db"]["sha256_after"]


def _probe_everything(con, scan):
    """What T7.3 will do inside the bracket: every in-window process start and 4648 of the scan, against every lab
    host. Returns counts and the requested / answered uid sets only."""
    probes_all = [(h, target_name_forms(h, ip)) for h, ip in sorted(PARAMS.lab_host_ips.items())]
    hosts = sorted({r["host"] for r in scan.in_window})
    want: dict[str, list[str]] = {h: [] for h in hosts}
    for r in scan.in_window:
        if (r["channel"], r["event_id"]) in {("Sysmon", 1), ("Security", 4688)}:
            want[r["host"]].extend(r["event_uids"])
    results = read_command_results(con, want, {h: probes_all for h in hosts})
    uids_4648 = [u for r in scan.link_rows if (r["channel"], r["event_id"]) == ("Security", 4648)
                 for u in r["event_uids"]]
    targets = read_4648_targets(con, uids_4648)
    return {"want": sorted({u for v in want.values() for u in v}), "got": sorted(results),
            "want_4648": sorted(uids_4648), "got_4648": sorted(targets),
            "with_target": sum(1 for r in results.values() if r.targets),
            "undecodable": sum(1 for r in results.values() if r.undecodable)}


@pytest.mark.parametrize("trial", DEV)
def test_t72_index_file_is_byte_identical_after_the_scan_extension(trial):
    paths = _paths_or_skip(trial)
    committed = REPO / CHECK_REL / trial / "t72_index.json"
    if not committed.is_file():
        pytest.skip(f"{trial}: no committed t72_index.json")
    data = run_check(REPO, trial)
    fresh = check_text(data).encode("utf-8")
    old = committed.read_bytes()
    assert fresh == old, f"{trial}: t72_index.json differs ({len(fresh)} bytes now, {len(old)} committed)"
    assert data["db"]["sha256_before"] == data["db"]["sha256_after"] == _gate_sha_after(paths)


@pytest.mark.parametrize("trial", DEV)
def test_link_rows_are_all_in_the_window_and_every_db_sha_is_unchanged(trial):
    paths = _paths_or_skip(trial)
    gate_sha = _gate_sha_after(paths)
    sha_pre = sha256_file(paths.db)
    checked = check_allowed(paths)
    scan, probe, before, after = load_link_inputs(checked, paths, _probe_everything, PARAMS)
    assert sha_pre == before == after == gate_sha == sha256_file(paths.db)

    rows = scan.link_rows
    assert rows, f"{trial}: no link row in the window"
    outside = sorted(u for r in rows for u in r["event_uids"]
                     if not (checked.start_us <= r["us"] < checked.end_us + US_PER_MS) or r["in_window"] not in (True, 1))
    assert outside == [], f"{trial}: {len(outside)} link row(s) outside the window, e.g. {outside[:5]}"
    kinds = {(r["channel"], r["event_id"]) for r in rows}
    assert kinds <= LINK_KINDS, f"{trial}: unexpected kind(s) {sorted(kinds - LINK_KINDS)}"
    assert [(r["us"], r["event_uid"]) for r in rows] == sorted((r["us"], r["event_uid"]) for r in rows)

    in_window = {u for r in scan.in_window for u in r["event_uids"]}
    lookback = {u for r in scan.lookback for u in r["event_uids"]}
    link = [u for r in rows for u in r["event_uids"]]
    assert len(link) == len(set(link)), f"{trial}: a uid is in two link rows"
    assert set(link).isdisjoint(in_window) and set(link).isdisjoint(lookback), f"{trial}: link uid in another list"
    print(f"{trial}: link rows {len(rows)} (uids {len(link)}), near-dup groups {scan.link_near_duplicate_groups}, "
          f"split {scan.link_near_duplicate_split_by_window}; "
          f"by kind { {f'{c}/{e}': sum(1 for r in rows if (r['channel'], r['event_id']) == (c, e)) for c, e in sorted(kinds)} }")
    # ST-01 for a dedup'd view: a link group is placed by its earliest copy, never by a pre-window one.
    assert scan.link_near_duplicate_split_by_window <= scan.link_near_duplicate_groups
    assert probe["got"] == probe["want"], f"{trial}: {len(set(probe['want']) ^ set(probe['got']))} process uid(s) unanswered"
    assert probe["got_4648"] == probe["want_4648"], f"{trial}: 4648 uid(s) unanswered"
    print(f"{trial}: commands read {len(probe['got'])}, naming a lab host {probe['with_target']}, "
          f"undecodable {probe['undecodable']}, 4648 read {len(probe['got_4648'])}")


@pytest.mark.parametrize("trial", DEV)
def test_adding_the_link_kinds_leaves_every_t72_scan_field_as_load_scan_gives_it(trial):
    paths = _paths_or_skip(trial)
    checked = check_allowed(paths)
    a, _, _ = load_scan(checked, paths, PARAMS)
    b, _, _, _ = load_link_inputs(checked, paths, lambda con, s: None, PARAMS)
    assert a.in_window == b.in_window and a.lookback == b.lookback
    assert a.kept_lookback_by_type == b.kept_lookback_by_type and a.removed_by_window == b.removed_by_window
    assert a.near_duplicate_groups == b.near_duplicate_groups
    assert a.near_duplicate_split_by_window == b.near_duplicate_split_by_window
    assert a.loaded_total == b.loaded_total
    assert a.link_rows == b.link_rows
