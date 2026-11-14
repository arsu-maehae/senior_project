"""Real-data checks for T7.3 task 1 (plan sections 3 and 4, task 1): the scan extension that keeps the link kinds apart
must leave the committed T7.2 check files byte-identical, keep every link row inside the window and leave the DBs
unchanged. Task 2 (hops, plan section 5 C2-C5, spec 03_stitch STA-01..03, 10.1, 10.2, 10.7) is at the end of the
module. Slow; parametrised over `clock_offset.params.DEVELOPMENT_TRIALS` only, never t02-t10.

Written from the plan and decision 048, not from the implementation. Assertions and messages carry counts and uids
only, never command text. Nothing is written under the repo.
"""
from __future__ import annotations

import functools
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from answer_key.db import sha256_file  # noqa: E402
from clock_offset import params as co_params  # noqa: E402
from gate.timeutil import US_PER_MS  # noqa: E402
from stitch.artefacts import build_artefacts  # noqa: E402
from stitch.check_index import check_text, run_check  # noqa: E402
from stitch.cmdtext import read_4648_targets, read_command_results, target_name_forms  # noqa: E402
from stitch.hops import build_hops  # noqa: E402
from stitch.index import build_index  # noqa: E402
from stitch.inputs import check_allowed, load_link_inputs, load_scan, read_gate_rows, trial_paths  # noqa: E402
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


# ================================================================================================ T7.3 task 2: hops
# Plan section 5 C2-C5 and spec 03_stitch STA-01..STA-03, 10.1, 10.2, 10.7 on the nine development trials. Hops are built
# with check_allowed + load_scan + build_index + read_gate_rows + build_hops, once per trial. The tests read the approved
# t00 keys; `src/stitch` never does. The expected numbers are literal copies of the spec / plan tables.
DEV_T00 = [t for t in DEV if t.endswith("_t00")]
APPROVED = REPO / "ground_truth" / "approved"
ENDPOINTS = {h for h in PARAMS.lab_host_ips if h.startswith("ep-")}
ENDPOINT_IPS = {ip for h, ip in PARAMS.lab_host_ips.items() if h.startswith("ep-")}

# spec 10.1 (table order s02_t00, s02_t01, s03_t00, s03_t01, s04_t00, s05_t00, s06_t00, s06_t01, s07_t00)
TABLE_ORDER = ["s02_t00", "s02_t01", "s03_t00", "s03_t01", "s04_t00", "s05_t00", "s06_t00", "s06_t01", "s07_t00"]


def _by_trial(values: list[int]) -> dict[str, int]:
    return dict(zip(TABLE_ORDER, values))


REMOTE_LOGONS = _by_trial([90, 70, 77, 83, 81, 129, 115, 74, 92])
IP_GROUPS = _by_trial([25, 26, 19, 21, 21, 41, 36, 26, 26])
BLANK_IP = _by_trial([2, 4, 4, 7, 4, 4, 7, 7, 7])
SEEDS = _by_trial([4, 10, 3, 4, 5, 10, 7, 6, 6])
USER_E2E = _by_trial([1, 2, 1, 1, 3, 3, 5, 4, 3])
FOLLOWUP_GROUPS = {t: int(t in ("s05_t00", "s06_t00", "s06_t01")) for t in TABLE_ORDER}
# spec input notes IN-01 / STA-02, in the input-notes order
KEY_ORDER = ["s02-h1", "s03-h1", "s04-A-h1", "s04-B-h1", "s04-t1", "s05-h1", "s05-h2", "s05-t1", "s06-winrm-1",
             "s06-winrm-2", "s06-smb-1", "s06-t1", "s07-h-x", "s07-h-y", "s07-t1"]
KEY_MEMBER_COUNTS = dict(zip(KEY_ORDER, [3, 5, 3, 3, 1, 3, 5, 1, 3, 5, 3, 1, 3, 2, 1]))


@dataclass
class Hopped:
    trial: str
    paths: Any
    checked: Any
    scan: Any
    gate: Any
    hs: Any
    by_uid: dict[str, dict]               # every uid of every in-window row -> its row


@functools.lru_cache(maxsize=None)
def _hopped(trial: str):
    assert trial in DEV, trial            # belt and braces: only development trials, ever
    paths = trial_paths(REPO, trial)
    if not paths.db.is_file() or not (paths.gate_dir / "stats.json").is_file():
        return None
    checked = check_allowed(paths)
    scan, _, _ = load_scan(checked, paths, PARAMS)
    index = build_index(trial, scan, PARAMS)
    gate = read_gate_rows(paths.gate_dir)
    hs = build_hops(trial, gate, scan, index.sessions, PARAMS)
    by_uid = {u: r for r in scan.in_window for u in r["event_uids"]}
    return Hopped(trial, paths, checked, scan, gate, hs, by_uid)


def hopped(trial: str) -> Hopped:
    got = _hopped(trial)
    if got is None:
        pytest.skip(f"{trial}: trial DB or gate output missing")
    return got


def load_key(trial: str) -> dict:
    path = APPROVED / f"{trial}.yaml"
    if not path.is_file():
        pytest.skip(f"no approved key for {trial}")
    return json.loads(path.read_text(encoding="utf-8"))


def gate_logon_uids(ld: Hopped) -> list[str]:
    """Every remote logon of the gate files: trigger anchors plus unmatched rows (a trigger row with no anchor is no logon)."""
    out = [r["anchor_logon_uid"].strip() for r in ld.gate.triggers if (r.get("anchor_logon_uid") or "").strip()]
    out += [(r.get("anchor_logon_uid") or r.get("trigger_event_uid") or "").strip() for r in ld.gate.unmatched]
    return out


def hop_by_id(ld: Hopped, hop_id: str):
    return next(h for h in ld.hs.hops if h.hop_id == hop_id)


def groups_before_followups(ld: Hopped) -> list[tuple[str, str | None, list, bool, str | None]]:
    """(target host, source IP, member logons, has trigger, hop id it is attached to) for every group, follow-up groups
    included (the groups of spec 10.1 "hop groups at 2 s")."""
    out = [(h.target_host, h.source_ip, h.members, any(m.trigger_ids for m in h.members), None) for h in ld.hs.hops]
    for f in ld.hs.followups:
        h = hop_by_id(ld, f.hop_id)
        out.append((h.target_host, h.source_ip, f.logons, any(m.trigger_ids for m in f.logons), f.hop_id))
    return out


def is_user_e2e(target: str, ip: str | None, members: list) -> bool:
    """User endpoint -> endpoint (spec 10.1): source IP of a lab endpoint, target an endpoint, not all machine accounts."""
    return ip in ENDPOINT_IPS and target in ENDPOINTS and not all(m.machine_account == 1 for m in members)


def key_logon_uids(ld: Hopped, key: dict, hop: dict) -> list[str]:
    """The key hop's target 4624 uids: the key's `target_event_uids` that are Security 4624s of the target host carrying
    the key's target logon ID (spec ST-25: the hop is matched by this logon)."""
    want = int(hop["target_logon_id"], 16)
    ek = key["event_keys"]
    out = []
    for u in hop["target_event_uids"]:
        e = ek.get(u)
        row = ld.by_uid.get(u)
        if e and e["channel"] == "Security" and e["event_id"] == 4624 and row is not None \
                and row["host"] == hop["target_host"] and row["target_logon_id"] == want:
            out.append(u)
    return out


def hop_with_uid(ld: Hopped, uid: str):
    """(hop, is_member) of the hop that holds `uid` as a member or as a follow-up logon; exactly one."""
    found = []
    for h in ld.hs.hops:
        if any(uid in m.event_uids for m in h.members):
            found.append((h, True))
        if any(uid in m.event_uids for m in h.followups):
            found.append((h, False))
    assert len(found) == 1, f"{uid} found in {len(found)} places"
    return found[0]


# ------------------------------------------------------------------------------------------------ C2 / STA-01
@pytest.mark.parametrize("trial", DEV)
def test_c2_every_gate_remote_logon_is_a_member_of_one_hop_or_a_follow_up_of_one_hop(trial):
    ld = hopped(trial)
    want = gate_logon_uids(ld)
    assert len(want) == len(set(want))
    seen: list[str] = []
    for h in ld.hs.hops:
        for m in h.members + h.followups:
            seen.extend(m.event_uids)
    assert len(seen) == len(set(seen)), f"{trial}: {len(seen) - len(set(seen))} uid(s) in more than one place"
    assert set(seen) == set(want), f"{trial}: {len(set(seen) ^ set(want))} uid(s) differ from the gate files"
    members = {u for h in ld.hs.hops for m in h.members for u in m.event_uids}
    follow = {u for h in ld.hs.hops for m in h.followups for u in m.event_uids}
    assert members.isdisjoint(follow)
    n = len(want)
    assert n == REMOTE_LOGONS[trial] == ld.hs.counts["remote_logons"]
    print(f"C2 {trial}: remote logons {n}, members {len(members)}, follow-up logons {len(follow)}")


@pytest.mark.parametrize("trial", DEV)
def test_c2_group_hop_seed_and_follow_up_counts_equal_spec_10_1(trial):
    ld = hopped(trial)
    groups = groups_before_followups(ld)
    ip_groups = [g for g in groups if g[1] is not None]
    blank = [g for g in groups if g[1] is None]
    assert len(ip_groups) == IP_GROUPS[trial], f"{trial}: {len(ip_groups)} groups with a source IP"
    assert len(blank) == BLANK_IP[trial], f"{trial}: {len(blank)} blank-IP groups"
    assert all(len(g[2]) == 1 for g in blank), f"{trial}: a blank-IP group with more than one logon"
    assert len(groups) == IP_GROUPS[trial] + BLANK_IP[trial]
    assert sum(1 for g in groups if g[3]) == SEEDS[trial], f"{trial}: seeds before follow-ups"
    assert sum(h.is_seed for h in ld.hs.hops) == SEEDS[trial]
    assert len(ld.hs.followups) == FOLLOWUP_GROUPS[trial], f"{trial}: {len(ld.hs.followups)} follow-up groups"
    assert len(ld.hs.hops) == IP_GROUPS[trial] + BLANK_IP[trial] - FOLLOWUP_GROUPS[trial]
    assert all(not g[3] for g in groups if g[4] is not None), f"{trial}: a triggered follow-up group"
    assert [h.hop_id for h in ld.hs.hops] == [f"{trial}-h{n:04d}" for n in range(1, len(ld.hs.hops) + 1)]
    order = [(h.first_us, h.members[0].uid) for h in ld.hs.hops]
    assert order == sorted(order), f"{trial}: hop ids are not in corrected first-member time order"
    print(f"C2 {trial}: groups {len(groups)} (with IP {len(ip_groups)}, blank {len(blank)}), hops {len(ld.hs.hops)}, "
          f"seeds {SEEDS[trial]}, follow-up groups {len(ld.hs.followups)}")


def test_c2_the_three_follow_up_groups_are_in_s05_t00_s06_t00_and_s06_t01():
    per = {t: len(hopped(t).hs.followups) for t in DEV}
    assert {t: n for t, n in per.items() if n} == {"s05_t00": 1, "s06_t00": 1, "s06_t01": 1}
    assert sum(per.values()) == 3


def test_c2_the_s05_t00_follow_up_is_a_machine_account_dc01_group_9_6_s_after_its_seed():
    ld = hopped("s05_t00")
    (f,) = ld.hs.followups
    hop = hop_by_id(ld, f.hop_id)
    assert hop.target_host == "dc01" and hop.is_seed == 1
    assert all(m.machine_account == 1 for m in f.logons)
    assert 9550 <= f.time_delta_ms < 9650                                # spec 10.7: 9.6 s (9.598 s measured)
    assert set(f.ports) <= {m.source_port for m in hop.members}
    assert (f.kind, f.method, f.confidence_tier, f.candidate_count) == ("followup_logon", "port_reuse", "C", 1)


@pytest.mark.parametrize("trial", DEV)
def test_c2_follow_up_groups_are_untriggered_on_their_hops_ip_target_and_ports_within_30_s(trial):
    ld = hopped(trial)
    for f in ld.hs.followups:
        h = hop_by_id(ld, f.hop_id)
        assert h.is_seed == 1
        assert not ({m.uid for m in f.logons} & {m.uid for m in h.members})
        assert f.time_delta_ms == round((f.logons[0].us_raw - h.members[-1].us_raw) / 1000)
        assert 0 < f.time_delta_ms <= 30000
        assert all(m.source_ip == h.source_ip and m.host == h.target_host for m in f.logons)
        assert all(m.source_port in {x.source_port for x in h.members} for m in f.logons)
        assert not any(m.trigger_ids for m in f.logons)
        assert {m.uid for m in f.logons} <= {m.uid for m in h.followups}


# ------------------------------------------------------------------------------------------------ C3
def test_c3_user_endpoint_to_endpoint_groups_are_23_of_which_21_are_seeds_and_21_hops_remain():
    per_group, per_seed, per_hop, per_hop_seed = {}, {}, {}, {}
    attached = []
    for t in TABLE_ORDER:
        ld = hopped(t)
        e2e = [g for g in groups_before_followups(ld) if is_user_e2e(g[0], g[1], g[2])]
        per_group[t] = len(e2e)
        per_seed[t] = sum(1 for g in e2e if g[3])
        attached += [t for g in e2e if g[4] is not None]
        hops = [h for h in ld.hs.hops if is_user_e2e(h.target_host, h.source_ip, h.members)]
        per_hop[t] = len(hops)
        per_hop_seed[t] = sum(h.is_seed for h in hops)
    print(f"C3 groups {per_group}, seeds {per_seed}, hops {per_hop}")
    assert per_group == USER_E2E
    assert sum(per_group.values()) == 23 and sum(per_seed.values()) == 21
    assert sum(per_hop.values()) == 21 and sum(per_hop_seed.values()) == 21, "after follow-ups: 21 hops, all seeds"
    assert sorted(attached) == ["s06_t00", "s06_t01"]                   # the two attached user groups


@pytest.mark.parametrize("trial,low,high", [("s06_t00", 10950, 11100), ("s06_t01", 11850, 12000)])
def test_c3_the_attached_user_group_is_11_0_s_or_11_9_s_after_a_winrm_hop_on_its_ports(trial, low, high):
    ld = hopped(trial)
    user = [f for f in ld.hs.followups
            if is_user_e2e(hop_by_id(ld, f.hop_id).target_host, hop_by_id(ld, f.hop_id).source_ip, f.logons)]
    assert len(user) == 1, f"{trial}: {len(user)} attached user group(s)"
    f = user[0]
    hop = hop_by_id(ld, f.hop_id)
    assert hop.protocol == "winrm" and hop.is_seed == 1 and len(f.logons) == 2
    assert low <= f.time_delta_ms < high, f"{trial}: {f.time_delta_ms} ms after the hop's last member"
    assert set(f.ports) <= {m.source_port for m in hop.members} and len(f.ports) >= 1
    print(f"C3 {trial}: follow-up of {hop.hop_id}, {f.time_delta_ms} ms, ports {f.ports}")


# ------------------------------------------------------------------------------------------------ C4 / STA-02
@pytest.mark.parametrize("trial", DEV_T00)
def test_c4_key_hops_have_the_input_notes_member_counts_and_never_share_a_hop(trial):
    ld = hopped(trial)
    key = load_key(trial)
    seen: dict[str, str] = {}
    for kh in key["hops"]:
        kid = kh["hop_id"]
        assert kid in KEY_MEMBER_COUNTS, f"{trial}: unexpected key hop id {kid}"
        uids = key_logon_uids(ld, key, kh)
        assert uids, f"{trial} {kid}: no 4624 of the key's logon ID among its target events"
        found = [hop_with_uid(ld, u) for u in uids]
        assert all(is_member for _, is_member in found), f"{trial} {kid}: the key's 4624 is a follow-up logon"
        ids = {h.hop_id for h, _ in found}
        assert len(ids) == 1, f"{trial} {kid}: its 4624s are in {len(ids)} hops {sorted(ids)}"
        (hid,) = ids
        assert hid not in seen, f"{trial}: key hops {seen[hid]} and {kid} share hop {hid}"
        seen[hid] = kid
        hop = found[0][0]
        assert hop.member_count == KEY_MEMBER_COUNTS[kid], f"{trial} {kid}: {hop.member_count} members in {hid}"
        assert hop.target_host == kh["target_host"]
        print(f"C4 {trial} {kid}: {hid} members {hop.member_count} protocol {hop.protocol} seed {hop.is_seed} "
              f"followups {len(hop.followups)}")


def test_c4_the_member_counts_of_the_15_key_hops_in_input_notes_order():
    got = {}
    for t in DEV_T00:
        ld, key = hopped(t), load_key(t)
        for kh in key["hops"]:
            hop, _ = hop_with_uid(ld, key_logon_uids(ld, key, kh)[0])
            got[kh["hop_id"]] = hop.member_count
    assert list(got) == KEY_ORDER, "key hop ids are not the 15 of the input notes in order"
    assert [got[k] for k in KEY_ORDER] == [3, 5, 3, 3, 1, 3, 5, 1, 3, 5, 3, 1, 3, 2, 1]


# ------------------------------------------------------------------------------------------------ C5 / STA-03
def test_c5_s06_smb_1_is_one_hop_with_both_accounts_and_the_key_4624_is_a_member():
    ld, key = hopped("s06_t00"), load_key("s06_t00")
    kh = next(h for h in key["hops"] if h["hop_id"] == "s06-smb-1")
    uids = key_logon_uids(ld, key, kh)
    assert uids
    hops = {hop_with_uid(ld, u)[0].hop_id for u in uids}
    assert len(hops) == 1
    hop = hop_by_id(ld, next(iter(hops)))
    assert all(any(u in m.event_uids for m in hop.members) for u in uids)
    assert hop.mixed_account == 1 and len({m.account_key for m in hop.members}) == 2
    assert hop.member_count == 3 and hop.protocol == "smb_service" and hop.is_seed == 1
    assert hop.followups == []


def test_c5_s06_t01_has_a_mixed_account_smb_service_hop_at_06_23_59_corrected():
    ld = hopped("s06_t01")
    mixed = [h for h in ld.hs.hops if h.mixed_account and is_user_e2e(h.target_host, h.source_ip, h.members)]
    assert len(mixed) == 1, f"s06_t01: {len(mixed)} mixed user endpoint hops"
    h = mixed[0]
    assert h.protocol == "smb_service" and h.is_seed == 1 and h.member_count == 3
    assert "T06:23:59" in h.first_utc_corrected, f"{h.hop_id}: corrected first member {h.first_utc_corrected}"


@pytest.mark.parametrize("trial", TABLE_ORDER)
def test_c5_mixed_account_user_endpoint_hops_exist_only_in_s06_t00_and_s06_t01(trial):
    ld = hopped(trial)
    mixed = [h for h in ld.hs.hops if h.mixed_account and is_user_e2e(h.target_host, h.source_ip, h.members)]
    assert len(mixed) == (1 if trial in ("s06_t00", "s06_t01") else 0), f"{trial}: {[h.hop_id for h in mixed]}"


@pytest.mark.parametrize("trial", DEV)
def test_c5_mixed_account_is_exactly_a_difference_of_member_accounts(trial):
    ld = hopped(trial)
    for h in ld.hs.hops:
        assert h.mixed_account == int(len({m.account_key for m in h.members}) > 1), f"{trial} {h.hop_id}"


# ------------------------------------------------------------------------------------------------ spec 6 spot checks
def test_s04_a_and_b_are_two_hops_with_gap_near_threshold_and_merges_at_3s_on_both():
    ld, key = hopped("s04_t00"), load_key("s04_t00")
    hops = {}
    for kh in key["hops"]:
        if kh["hop_id"] in ("s04-A-h1", "s04-B-h1"):
            hops[kh["hop_id"]] = hop_with_uid(ld, key_logon_uids(ld, key, kh)[0])[0]
    a, b = hops["s04-A-h1"], hops["s04-B-h1"]
    assert a.hop_id != b.hop_id
    for h in (a, b):
        assert (h.gap_near_threshold, h.merges_at_3s) == (1, 1), f"{h.hop_id}"
    assert a.next_gap_ms == b.prev_gap_ms and 2460 <= a.next_gap_ms < 2480, f"gap {a.next_gap_ms} ms (spec 2.47 s)"
    assert a.hop_id in b.shares_port_with_hops and b.hop_id in a.shares_port_with_hops   # port 49734 (input notes)


def test_s03_t01_has_a_winrm_hop_of_five_members_with_its_largest_inside_gap_1_33_s():
    ld = hopped("s03_t01")
    cand = [h for h in ld.hs.hops if h.protocol == "winrm" and h.member_count == 5 and h.inside_gap_max_ms is not None
            and 1300 <= h.inside_gap_max_ms < 1340]
    assert len(cand) == 1, f"s03_t01: {len(cand)} such hops"
    h = cand[0]
    assert h.splits_at_1s == 1 and h.gap_near_threshold == 1 and h.is_seed == 1
    assert is_user_e2e(h.target_host, h.source_ip, h.members)


@pytest.mark.parametrize("trial", DEV_T00)
def test_largest_inside_gap_of_a_user_endpoint_hop_on_t00_is_below_one_second(trial):
    ld = hopped(trial)
    hops = [h for h in ld.hs.hops if is_user_e2e(h.target_host, h.source_ip, h.members)]
    gaps = [h.inside_gap_max_ms for h in hops if h.inside_gap_max_ms is not None]
    assert gaps and max(gaps) < 1000, f"{trial}: {max(gaps)} ms"           # spec 10.2: 0.837 s (s05-h2) on t00
    assert all(h.splits_at_1s == 0 for h in hops)


# ------------------------------------------------------------------------------------------------ ST-01
@pytest.mark.parametrize("trial", DEV)
def test_no_hop_or_follow_up_holds_an_out_of_window_uid(trial):
    ld = hopped(trial)
    in_window = {u for r in ld.scan.in_window for u in r["event_uids"]}
    lookback = {u for r in ld.scan.lookback for u in r["event_uids"]}
    uids = [u for h in ld.hs.hops for m in h.members + h.followups for u in m.event_uids]
    assert uids and set(uids) <= in_window, f"{trial}: {len(set(uids) - in_window)} uid(s) not in the window"
    assert set(uids).isdisjoint(lookback)
    lo, hi = ld.checked.start_us, ld.checked.end_us + US_PER_MS
    bad = sorted(m.uid for h in ld.hs.hops for m in h.members + h.followups if not lo <= m.us < hi)
    assert bad == [], f"{trial}: {len(bad)} logon(s) outside the window, e.g. {bad[:5]}"
    for f in ld.hs.followups:
        assert all(lo <= m.us < hi for m in f.logons)
    assert all(ld.by_uid[m.uid]["channel"] == "Security" and ld.by_uid[m.uid]["event_id"] == 4624
               for h in ld.hs.hops for m in h.members + h.followups)


@pytest.mark.parametrize("trial", DEV)
def test_hops_are_identical_across_two_builds_and_the_db_is_unchanged(trial):
    ld = hopped(trial)
    again = build_hops(trial, ld.gate, ld.scan, build_index(trial, ld.scan, PARAMS).sessions, PARAMS)

    def view(hops):
        return [(h.hop_id, h.member_uids, h.protocol, h.inside_gap_max_ms, h.prev_gap_ms, h.next_gap_ms,
                 h.shares_port_with_hops, [m.uid for m in h.followups]) for h in hops]
    assert view(ld.hs.hops) == view(again.hops)
    gate_sha = json.loads((ld.paths.gate_dir / "stats.json").read_text(encoding="utf-8"))["db"]["sha256_after"]
    assert sha256_file(ld.paths.db) == gate_sha


# ================================================================================================ T7.3 task 3: artefacts
# Plan section 5 C6, spec 03_stitch STA-04 and 10.3 on the nine development trials. Artefacts are built once per trial from
# the cached hops (`_hopped`) and a fresh session index. Messages carry counts, ids, uids and target-side names only.
REMOTE_INSTALLS = {"s02_t00": 0, "s02_t01": 1, "s03_t00": 0, "s03_t01": 0, "s04_t00": 2, "s05_t00": 1, "s06_t00": 1,
                   "s06_t01": 1, "s07_t00": 2}
# Ties: the spec says the nearest copy is 50-182 ms before the install, measured to the 4697. The code measures to the
# EARLIEST event of the install (decision 048 reading), which gives 50-181 ms on the development trials, so the test accepts
# 40-200 ms. Task 0 values: s04_t00 87 and 50, s05_t00 130, s07_t00 122 and 118, s02_t01 181.
TIE_DELTA_MS = (40, 200)


@functools.lru_cache(maxsize=None)
def _artefacted(trial: str):
    ld = _hopped(trial)
    if ld is None:
        return None
    sessions = build_index(trial, ld.scan, PARAMS).sessions
    return build_artefacts(ld.hs, ld.scan, sessions, ld.gate, PARAMS)


def artefacts(trial: str):
    got = _artefacted(trial)
    if got is None:
        pytest.skip(f"{trial}: trial DB or gate output missing")
    return got


def remote_installs(art) -> list:
    """Installs that are a hop artefact: by a member's 4697, or a 7045 alone attached through a tie."""
    return [i for i in art.installs if i.hop_id is not None or i.tie_hop_ids]


@pytest.mark.parametrize("trial", DEV)
def test_c6_remote_installs_per_trial_each_with_a_4697_and_a_7045(trial):
    art = artefacts(trial)
    remote = remote_installs(art)
    assert len(remote) == REMOTE_INSTALLS[trial], f"{trial}: {len(remote)} remote installs"
    assert all(i.uids_4697 and i.uids_7045 for i in remote), f"{trial}: a remote install lacks its 4697 or its 7045"
    rows = [r for r in art.rows if r.kind == "service_install"]
    assert sorted(r.ref_id for r in rows) == sorted(i.install_id for i in remote)
    assert all(r.method == "logon_id" and r.confidence_tier == "A" for r in rows)
    print(f"C6 {trial}: remote installs {len(remote)} of {len(art.installs)}, "
          f"names {sorted(i.service_name for i in remote)}")


def test_c6_eight_remote_installs_over_the_nine_trials():
    assert sum(len(remote_installs(artefacts(t))) for t in DEV) == sum(REMOTE_INSTALLS.values()) == 8


def test_c6_exactly_six_installs_have_a_tied_burst_each_exactly_one_just_before_the_install():
    tied = []
    for t in DEV:
        art = artefacts(t)
        per_install: dict[str, list] = {}
        for tie in art.ties:
            per_install.setdefault(tie.install_id, []).append(tie)
        for iid, ties in per_install.items():
            assert len(ties) == 1 and ties[0].candidate_count == 1, f"{t} {iid}: {len(ties)} tied bursts"
            lo, hi = TIE_DELTA_MS
            assert lo <= ties[0].delta_ms <= hi, f"{t} {iid}: copy {ties[0].delta_ms} ms before the install"
            assert ties[0].method == "file_name_time"
            tied.append((t, iid, ties[0].delta_ms))
        assert {i.install_id for i in remote_installs(art)} >= set(per_install), f"{t}: a tie of a non-remote install"
    print(f"C6 ties (trial, install, ms): {tied}")
    assert len(tied) == 6, f"{len(tied)} installs with a tie"
    assert sorted(t for t, _, _ in tied) == ["s02_t01", "s04_t00", "s04_t00", "s05_t00", "s07_t00", "s07_t00"]


@pytest.mark.parametrize("trial", ["s06_t00", "s06_t01"])
def test_c6_the_benignmon_install_has_no_tie_and_no_same_name_burst(trial):
    art = artefacts(trial)
    benign = [i for i in art.installs if "benignmon" in i.service_name.lower()]
    assert len(benign) == 1, f"{trial}: {len(benign)} BenignMon installs"
    inst = benign[0]
    assert inst.hop_id is not None and inst.binary_key
    assert not [t for t in art.ties if t.install_id == inst.install_id]
    assert inst.untied_same_name_bursts == []
    same = [b.burst_id for b in art.bursts if any(name == inst.binary_key for name, _ in b.file_writes)]
    assert same == [], f"{trial}: {len(same)} burst(s) write {inst.binary_name}"
    row = next(r for r in art.rows if r.ref_id == inst.install_id)
    assert row.untied_same_name_bursts == []


def _user_share_sessions(art) -> dict[str, list]:
    out: dict[str, list] = {}
    for b in art.bursts:
        if not b.member_machine_account:
            out.setdefault(b.member_uid, []).append(b)
    return out


def test_c6_13_user_share_sessions_and_exactly_one_with_more_than_one_burst():
    per_trial, multi = {}, []
    for t in DEV:
        art = artefacts(t)
        sessions = _user_share_sessions(art)
        per_trial[t] = len(sessions)
        assert art.counts["user_share_sessions"] == len(sessions)
        multi += [(t, uid, len(bs)) for uid, bs in sessions.items() if len(bs) > 1]
    print(f"C6 user share sessions per trial {per_trial}; with several bursts {multi}")
    assert sum(per_trial.values()) == 13
    assert len(multi) == 1 and multi[0][0] == "s07_t00" and multi[0][2] == 2


def test_c6_the_multi_burst_session_is_s07_t00_logon_0x49cdfa_with_bursts_at_about_0_and_95_3_s():
    ld, art = hopped("s07_t00"), artefacts("s07_t00")
    bursts = sorted((b for b in art.bursts if b.logon_id_hex == "0x49cdfa"), key=lambda b: b.first_us_raw)
    assert len(bursts) == 2
    member = next(m for h in ld.hs.hops for m in h.members if m.uid == bursts[0].member_uid)
    assert bursts[1].member_uid == bursts[0].member_uid == member.uid
    starts = [(b.first_us_raw - member.us_raw) / 1e6 for b in bursts]
    assert 0 <= starts[0] < 2.0, f"first burst {starts[0]} s after the 4624"
    assert 94.5 <= starts[1] <= 96.0, f"second burst {starts[1]} s after the 4624"
    assert not member.machine_account


def _s07_key_hops():
    ld, key = hopped("s07_t00"), load_key("s07_t00")
    out = {}
    for kh in key["hops"]:
        if kh["hop_id"] in ("s07-h-x", "s07-h-y"):
            out[kh["hop_id"]] = hop_with_uid(ld, key_logon_uids(ld, key, kh)[0])[0]
    assert set(out) == {"s07-h-x", "s07-h-y"}
    return out


def _burst_rows(art, hop) -> list:
    return [r for r in art.rows if r.hop_id == hop.hop_id and r.kind == "share_burst"]


def test_c6_sta04_y_holds_the_ypay_copy_logged_under_x_and_x_holds_only_its_own_copy():
    art = artefacts("s07_t00")
    hops = _s07_key_hops()
    x, y = hops["s07-h-x"], hops["s07-h-y"]
    assert x.hop_id != y.hop_id
    yr = [r for r in _burst_rows(art, y) if "ypay.exe" in [n.lower() for n in r.names]]
    assert len(yr) == 1, f"{len(yr)} Ypay.exe burst rows on Y's hop"
    r = yr[0]
    assert (r.method, r.confidence_tier) == ("file_name_time", "B")
    assert r.logged_under_hop_id == x.hop_id and r.hop_id == y.hop_id and r.candidate_count == 1
    xr = _burst_rows(art, x)
    assert len(xr) == 1, f"{len(xr)} burst rows on X's hop"
    assert [n.lower() for n in xr[0].names] == ["xpay.exe"]
    assert (xr[0].method, xr[0].confidence_tier) == ("logon_id", "A")
    assert not any("ypay.exe" in [n.lower() for n in rr.names] for rr in xr)
    assert not any(u in rr.event_uids for rr in art.rows if rr.hop_id == x.hop_id for u in r.event_uids)


def test_c6_sta04_x_and_y_each_have_exactly_one_install_and_they_differ():
    art = artefacts("s07_t00")
    hops = _s07_key_hops()
    installs = {}
    for name, h in hops.items():
        rows = [r for r in art.rows if r.hop_id == h.hop_id and r.kind == "service_install"]
        assert len(rows) == 1, f"{name}: {len(rows)} install rows"
        assert art.service_install_count[h.hop_id] == 1
        installs[name] = rows[0]
    assert installs["s07-h-x"].ref_id != installs["s07-h-y"].ref_id
    assert installs["s07-h-x"].event_uids != installs["s07-h-y"].event_uids
    names = {n.lower() for n in installs["s07-h-x"].names} | {n.lower() for n in installs["s07-h-y"].names}
    assert {"xpay.exe", "ypay.exe"} <= names
    # each install is tied to a copy; the Y install's tied burst is the one logged under X's logon
    ties = {t.install_id: t for t in art.ties}
    assert set(ties) >= {installs["s07-h-x"].ref_id, installs["s07-h-y"].ref_id}
    assert ties[installs["s07-h-y"].ref_id].logged_under_hop_id == hops["s07-h-x"].hop_id
    assert ties[installs["s07-h-x"].ref_id].logged_under_hop_id == hops["s07-h-x"].hop_id


@pytest.mark.parametrize("trial", DEV)
def test_every_gate_supporting_uid_of_a_hop_is_held_by_an_artefact_row_or_was_moved(trial):
    art = artefacts(trial)
    left = {h: v for h, v in art.gate_support_not_attached.items() if v}
    assert left == {}, f"{trial}: {sum(len(v) for v in left.values())} supporting uid(s) unattached on {sorted(left)}"
    assert art.counts["hops_with_gate_support_not_attached"] == 0


@pytest.mark.parametrize("trial", DEV)
def test_no_hop_has_more_than_one_install_and_counts_agree_with_the_rows(trial):
    art, ld = artefacts(trial), hopped(trial)
    assert set(art.service_install_count) == {h.hop_id for h in ld.hs.hops}
    assert max(art.service_install_count.values()) <= 1, f"{trial}: a hop with more than one install"
    for h in ld.hs.hops:
        assert art.service_install_count[h.hop_id] == sum(1 for r in art.rows
                                                          if r.hop_id == h.hop_id and r.kind == "service_install")
    assert art.counts["hops_with_more_than_one_install"] == 0


@pytest.mark.parametrize("trial", DEV)
def test_every_artefact_uid_is_in_the_window_and_every_row_is_well_formed(trial):
    art, ld = artefacts(trial), hopped(trial)
    in_window = {u for r in ld.scan.in_window + ld.scan.link_rows for u in r["event_uids"]}
    lookback = {u for r in ld.scan.lookback for u in r["event_uids"]}
    uids = [u for r in art.rows for u in r.event_uids]
    assert set(uids) <= in_window, f"{trial}: {len(set(uids) - in_window)} artefact uid(s) not in the window"
    assert set(uids).isdisjoint(lookback)
    hop_ids = {h.hop_id for h in ld.hs.hops}
    assert {r.hop_id for r in art.rows} <= hop_ids
    keys = [(r.hop_id, r.kind, tuple(r.event_uids), r.ref_id) for r in art.rows]
    assert len(keys) == len(set(keys)), f"{trial}: a duplicated artefact row"
    assert [(r.hop_id, r.first_us_raw, r.kind, r.event_uids[0]) for r in art.rows] == sorted(
        (r.hop_id, r.first_us_raw, r.kind, r.event_uids[0]) for r in art.rows)
    for r in art.rows:
        assert r.supporting_span_ms >= 0 and r.candidate_count >= 1 and r.confidence_tier in ("A", "B", "C")
    assert all(art.supporting_span_ms[h] is None or art.supporting_span_ms[h] >= 0 for h in hop_ids)
    held = {r.hop_id for r in art.rows}
    assert {h for h, v in art.supporting_span_ms.items() if v is None} == hop_ids - held
    # every follow-up group is exactly one row
    assert sum(1 for r in art.rows if r.kind == "followup_logon") == len(ld.hs.followups)


@pytest.mark.parametrize("trial", DEV)
def test_artefacts_are_identical_across_two_builds(trial):
    ld, art = hopped(trial), artefacts(trial)
    again = build_artefacts(ld.hs, ld.scan, build_index(trial, ld.scan, PARAMS).sessions, ld.gate, PARAMS)
    view = lambda a: ([(r.hop_id, r.kind, r.method, r.confidence_tier, r.candidate_count, r.time_delta_ms,  # noqa: E731
                        r.supporting_span_ms, r.event_uids, r.ref_id) for r in a.rows],
                      [(t.install_id, t.burst_id, t.hop_id, t.delta_ms) for t in a.ties], a.counts)
    assert view(art) == view(again)
