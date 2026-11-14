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


# ================================================================================================ T7.3 task 4: source linking
# Plan section 5 C7-C12, C15 and spec 03_stitch 10.4, 10.5, 10.8, STA-05 (the link check that does not use the key), STA-06,
# ST-01, ST-02 on the nine development trials. The whole pipeline (index, hops, artefacts, command results, links) is built
# once per trial inside the read-only bracket of `load_link_inputs`. The key is read by the tests only. Messages carry counts,
# hop ids, hex session IDs and uids only, never command text.
from stitch import source as src  # noqa: E402
from stitch.confirm import confirm_of, kerberos_confirm, norm_logon_guid  # noqa: E402
from stitch.sessions import hex_id, logon_id_int  # noqa: E402

PORT, E4648, CMD = src.METHOD_PORT, src.METHOD_4648, src.METHOD_CMD
EP_IP = dict(PARAMS.lab_host_ips)


@dataclass
class Linked:
    trial: str
    paths: Any
    checked: Any
    scan: Any
    hs: Any
    index: Any
    arts: Any
    links: dict
    cmd: dict
    t4648: dict
    hosts: set
    by_uid: dict[str, dict]
    sha: tuple


@functools.lru_cache(maxsize=None)
def _linked(trial: str):
    assert trial in DEV, trial            # belt and braces: only development trials, ever
    paths = trial_paths(REPO, trial)
    if not paths.db.is_file() or not (paths.gate_dir / "stats.json").is_file():
        return None
    checked = check_allowed(paths)

    def extra(con, scan):
        index = build_index(trial, scan, PARAMS)
        gate = read_gate_rows(paths.gate_dir)
        hopset = build_hops(trial, gate, scan, index.sessions, PARAMS)
        arts = build_artefacts(hopset, scan, index.sessions, gate, PARAMS)
        hosts = sorted(PARAMS.lab_host_ips)
        probes = {h: [(t, target_name_forms(t, PARAMS.lab_host_ips[t])) for t in hosts if t != h] for h in hosts}
        hop_target = {h.hop_id: h.target_host for h in hopset.hops}
        names: dict[str, set[str]] = {}
        for r in arts.rows:
            if r.kind in ("share_burst", "service_install"):
                names.setdefault(hop_target[r.hop_id], set()).update(r.names)
        uids_by_host: dict[str, list[str]] = {}
        for p in index.processes.processes.values():
            uids_by_host.setdefault(p.host, []).extend(p.sysmon1_uids + p.sec4688_uids)
        cmd = read_command_results(con, uids_by_host, probes, {k: sorted(v) for k, v in names.items()})
        u4648 = [u for r in scan.link_rows if (r["channel"], r["event_id"]) == ("Security", 4648)
                 for u in (r.get("event_uids") or [r["event_uid"]])]
        t4648 = read_4648_targets(con, u4648)
        links = src.build_links(hopset, scan, index, cmd, t4648, PARAMS, offsets=checked.clock.offsets)
        return hopset, index, arts, links, cmd, t4648

    gate_sha = _gate_sha_after(paths)
    sha_pre = sha256_file(paths.db)
    scan, (hopset, index, arts, links, cmd, t4648), before, after = load_link_inputs(checked, paths, extra, PARAMS)
    by_uid = {u: r for r in scan.in_window for u in r["event_uids"]}
    return Linked(trial, paths, checked, scan, hopset, index, arts, links, cmd, t4648, src.hosts_with_rows(scan), by_uid,
                  (sha_pre, before, after, gate_sha))


def linked(trial: str) -> Linked:
    got = _linked(trial)
    if got is None:
        pytest.skip(f"{trial}: trial DB or gate output missing")
    return got


def user_e2e_hops(ld: Linked) -> list:
    return [h for h in ld.hs.hops if is_user_e2e(h.target_host, h.source_ip, h.members)]


def proto_group(h) -> str:
    return "smb" if h.protocol in ("smb", "smb_service") else h.protocol


def krb(ld: Linked, hop_or_members) -> bool:
    members = hop_or_members.members if hasattr(hop_or_members, "members") else hop_or_members
    return bool(kerberos_confirm(members, ld.scan.link_rows))


def hop_of_followup(ld: Linked, f):
    return next(h for h in ld.hs.hops if h.hop_id == f.hop_id)


def describe(ld: Linked, h) -> str:
    """Per-hop summary for failure messages and -s output: ids and counts only."""
    L = ld.links[h.hop_id]
    sess = {hex_id(k[1]): "+".join(m[:4] for m in ms) for k, ms in L.session_methods.items()}
    td = sorted({(r.method[:4], r.time_delta_ms) for r in L.rows if r.session_key is not None})
    return (f"{h.hop_id} {h.protocol} {h.source_ip}->{h.target_host} sessions={sess} all={L.candidate_count_all} "
            f"counts={L.candidate_counts} td={td} to={L.target_only_reason or '-'} "
            f"before={L.evidence_before_range} after={L.evidence_after_range}")


def key_hop_of(ld: Linked, key: dict, kh: dict):
    uids = key_logon_uids(ld, key, kh)
    assert uids, f"{ld.trial} {kh['hop_id']}: no 4624 of the key's logon ID among its target events"
    hop, is_member = hop_with_uid(ld, uids[0])
    assert is_member
    return hop


def key_source_lids(ld: Linked, key: dict, kh: dict) -> set[int]:
    """The key's source session (owner reading): `source_session_logon_id` / `session_evidence.session_id` where present,
    otherwise the logon ID of the key command's Sysmon 1 events among `agent_event_uids`."""
    if kh.get("source_session_logon_id"):
        return {int(kh["source_session_logon_id"], 16)}
    se = kh.get("session_evidence") or {}
    if se.get("session_id"):
        return {int(se["session_id"], 16)}
    out = set()
    for u in kh.get("agent_event_uids") or []:
        e, row = key["event_keys"].get(u), ld.by_uid.get(u)
        if e and (e["channel"], e["event_id"]) == ("Sysmon", 1) and row is not None:
            lid = logon_id_int(row.get("session_id"))
            if lid is not None:
                out.add(lid)
    return out


def candidate_lids(ld: Linked, hop) -> set[int]:
    return {k[1] for k in ld.links[hop.hop_id].candidate_sessions}


@functools.lru_cache(maxsize=None)
def keyed_hops() -> tuple:
    """(trial, key, linked, stitch hop, key hop) for the keyed hops of the six t00 trials that are not background."""
    out = []
    for t in DEV_T00:
        ld, key = linked(t), load_key(t)
        for kh in key["hops"]:
            if kh["role"] != "background":
                out.append((t, key, ld, key_hop_of(ld, key, kh), kh))
    return tuple(out)


# ------------------------------------------------------------------------------------------------ C7 / spec 10.4
def _tally() -> dict[str, dict[str, int]]:
    tot = {g: dict(hops=0, sysmon3_port=0, source_4648=0, cmdline_target=0, multi=0, target_only=0, kerberos=0)
           for g in ("smb", "winrm")}
    for t in DEV:
        ld = linked(t)
        for h in user_e2e_hops(ld):
            L = ld.links[h.hop_id]
            c = tot[proto_group(h)]
            c["hops"] += 1
            for m in (PORT, E4648, CMD):
                c[m] += L.candidate_counts[m] > 0
            c["multi"] += L.candidate_count_all > 1
            c["target_only"] += bool(L.target_only_reason)
            c["kerberos"] += krb(ld, h)
    return tot


def test_c7_the_21_user_endpoint_hops_are_14_smb_and_7_winrm():
    tot = _tally()
    print(f"C7 {tot}")
    assert (tot["smb"]["hops"], tot["winrm"]["hops"]) == (14, 7)


def test_c7_smb_hops_spec_10_4_at_30_s_look_back_and_15_s_after():
    c = _tally()["smb"]
    print(f"C7 smb {c}")
    assert c["sysmon3_port"] == 0, "the port join links no SMB hop (Sysmon does not log SMB)"
    assert c["source_4648"] == 2
    assert c["cmdline_target"] == 9
    assert c["multi"] == 2                                               # s04 A and B
    assert c["target_only"] == 5
    assert c["kerberos"] == 0                                            # NTLM has no LogonGuid


def test_c7_winrm_hops_spec_10_4():
    c = _tally()["winrm"]
    print(f"C7 winrm {c}")
    assert c["sysmon3_port"] == 6
    assert c["source_4648"] == 7
    assert c["cmdline_target"] == 7
    assert c["multi"] == 0 and c["target_only"] == 0
    assert c["kerberos"] == 7


def test_c7_the_two_hops_with_more_than_one_candidate_session_are_the_s04_pair():
    ld, key = linked("s04_t00"), load_key("s04_t00")
    multi = [(t, h) for t in DEV for h in user_e2e_hops(linked(t)) if linked(t).links[h.hop_id].candidate_count_all > 1]
    a = key_hop_of(ld, key, next(k for k in key["hops"] if k["hop_id"] == "s04-A-h1"))
    b = key_hop_of(ld, key, next(k for k in key["hops"] if k["hop_id"] == "s04-B-h1"))
    assert {h.hop_id for _, h in multi} == {a.hop_id, b.hop_id}


def test_c7_the_five_smb_target_only_hops_are_the_four_t00_background_logons_and_the_s02_t01_logon():
    got = []
    for t in DEV:
        ld = linked(t)
        for h in user_e2e_hops(ld):
            if proto_group(h) == "smb" and ld.links[h.hop_id].target_only_reason:
                got.append((t, ld.links[h.hop_id].target_only_reason))
    print(f"C7 SMB target_only: {got}")
    assert sorted(t for t, _ in got) == ["s02_t01", "s04_t00", "s05_t00", "s06_t00", "s07_t00"]
    assert {r for _, r in got} == {"no_evidence_in_range"}


def _user_followups(ld: Linked) -> list:
    out = []
    for f in ld.hs.followups:
        hop = hop_of_followup(ld, f)
        if is_user_e2e(hop.target_host, hop.source_ip, f.logons):
            out.append((f, hop))
    return out


def _link_followup(ld: Linked, f, hop) -> src.SubjectLinks:
    subj = src.subject_of(hop.target_host, hop.source_ip, f.logons, PARAMS)
    return src.link_subject(subj, ld.scan, ld.index.processes, ld.index.sessions, ld.cmd, ld.t4648, ld.hosts, PARAMS,
                            offsets=ld.checked.clock.offsets)


@pytest.mark.parametrize("trial", ["s06_t00", "s06_t01"])
def test_c7_the_no_artefact_row_follow_up_group_has_4648_command_and_kerberos_but_no_link_row(trial):
    ld = linked(trial)
    user = _user_followups(ld)
    assert len(user) == 1, f"{trial}: {len(user)} user follow-up group(s)"
    f, hop = user[0]
    sl = _link_followup(ld, f, hop)
    print(f"C7 {trial} follow-up of {hop.hop_id}: counts {sl.candidate_counts} "
          f"sessions {[hex_id(k[1]) for k in sl.candidate_sessions]}")
    assert sl.candidate_counts[E4648] > 0, f"{trial}: no 4648 for the follow-up group"
    assert sl.candidate_counts[CMD] > 0, f"{trial}: no command for the follow-up group"
    assert kerberos_confirm(f.logons, ld.scan.link_rows), f"{trial}: follow-up group not Kerberos-confirmed"
    # ST-26: build_links has no entry for it and no hop's rows carry its logons
    fol_uids = {u for lg in f.logons for u in lg.event_uids}
    assert set(ld.links) == {h.hop_id for h in ld.hs.hops}
    for L in ld.links.values():
        assert fol_uids.isdisjoint(L.member_uids)
        assert fol_uids.isdisjoint(u for r in L.rows for u in r.supporting_event_uids)


def test_c7_the_no_artefact_row_is_2_of_2_for_4648_command_and_kerberos():
    n = n4648 = ncmd = nkrb = 0
    for trial in ("s06_t00", "s06_t01"):
        ld = linked(trial)
        for f, hop in _user_followups(ld):
            sl = _link_followup(ld, f, hop)
            n += 1
            n4648 += sl.candidate_counts[E4648] > 0
            ncmd += sl.candidate_counts[CMD] > 0
            nkrb += bool(kerberos_confirm(f.logons, ld.scan.link_rows))
    assert (n, n4648, ncmd, nkrb) == (2, 2, 2, 2)


# ------------------------------------------------------------------------------------------------ C8 / STA-05 (no key)
def test_c8_where_the_port_join_and_the_command_line_both_find_a_session_they_find_the_same_one_6_of_6():
    both = same = 0
    detail = []
    for t in DEV:
        ld = linked(t)
        for h in user_e2e_hops(ld):
            L = ld.links[h.hop_id]
            if L.candidate_counts[PORT] and L.candidate_counts[CMD]:
                both += 1
                ok = L.methods[PORT].sessions == L.methods[CMD].sessions
                same += ok
                detail.append((h.hop_id, ok, [hex_id(k[1]) for k in L.methods[PORT].sessions],
                               [hex_id(k[1]) for k in L.methods[CMD].sessions]))
    print(f"C8 both={both} same={same} {detail}")
    assert (both, same) == (6, 6), f"{[d for d in detail if not d[1]]}"


# ------------------------------------------------------------------------------------------------ C9 key source session
def test_c9_the_key_source_session_is_among_the_candidates_for_11_of_11_keyed_hops_and_the_only_one_for_9():
    rows, problems = [], []
    port_hops = []
    for t, key, ld, hop, kh in keyed_hops():
        lids = key_source_lids(ld, key, kh)
        if not lids:
            problems.append(f"{t} {kh['hop_id']}: the key has no source session")
            continue
        cand = candidate_lids(ld, hop)
        in_ = lids <= cand
        only_ = in_ and cand == lids
        rows.append((kh["hop_id"], sorted(hex_id(x) for x in lids), sorted(hex_id(x) for x in cand), in_, only_))
        if ld.links[hop.hop_id].candidate_counts[PORT]:
            port_hops.append(kh["hop_id"])
        print(f"C9 {kh['hop_id']:12s} {describe(ld, hop)}  key={rows[-1][1]} among={in_} only={only_}")
    among, only = sum(r[3] for r in rows), sum(r[4] for r in rows)
    print(f"C9 keyed hops with a source session {len(rows)}, among {among}, only {only}; "
          f"WinRM port joins (reported apart): {port_hops}")
    assert not problems, problems
    assert len(rows) == 11
    assert among == 11, f"key session not among the candidates for {[r[0] for r in rows if not r[3]]}"
    assert only == 9, f"only candidate for {only} (not 9); not only: {[(r[0], r[2]) for r in rows if not r[4]]}"


def test_c9_the_two_exceptions_are_s04_a_and_s04_b_each_with_sessions_0xd6398_and_0x17c46():
    ld, key = linked("s04_t00"), load_key("s04_t00")
    for name in ("s04-A-h1", "s04-B-h1"):
        kh = next(k for k in key["hops"] if k["hop_id"] == name)
        hop = key_hop_of(ld, key, kh)
        cand = candidate_lids(ld, hop)
        assert cand == {0xD6398, 0x17C46}, f"{name}: candidates {sorted(hex_id(x) for x in cand)}"
    others = [kh["hop_id"] for _, _, ld_, hop, kh in keyed_hops()
              if kh["hop_id"] not in ("s04-A-h1", "s04-B-h1") and ld_.links[hop.hop_id].candidate_count_all != 1]
    assert others == [], f"keyed hops with other than one candidate session: {others}"


def test_c9_s04_a_sees_bs_command_after_its_logon_and_b_sees_as_before_its_logon():
    ld, key = linked("s04_t00"), load_key("s04_t00")
    out = {}
    for name in ("s04-A-h1", "s04-B-h1"):
        kh = next(k for k in key["hops"] if k["hop_id"] == name)
        hop = key_hop_of(ld, key, kh)
        mine = key_source_lids(ld, key, kh)
        rows = [r for r in ld.links[hop.hop_id].rows if r.method == CMD and r.session_key is not None]
        other = [r for r in rows if r.source_session_id not in mine]
        assert len(other) == 1, f"{name}: {len(other)} command rows of the other session"
        out[name] = other[0].time_delta_ms
    print(f"C9 other session's nearest command: {out}")
    assert 3000 <= out["s04-A-h1"] < 3100, out                       # spec 10.4: A lists B's at +3.05 s
    assert -1900 < out["s04-B-h1"] <= -1800, out                     # B lists A's at -1.87 s


# ------------------------------------------------------------------------------------------------ C10 / STA-06
def test_c10_the_four_background_key_hops_are_target_only_no_evidence_in_range():
    seen = []
    for t in DEV_T00:
        ld, key = linked(t), load_key(t)
        for kh in key["hops"]:
            if kh["role"] != "background":
                continue
            hop = key_hop_of(ld, key, kh)
            L = ld.links[hop.hop_id]
            seen.append(kh["hop_id"])
            assert L.target_only_reason == "no_evidence_in_range", f"{kh['hop_id']}: {describe(ld, hop)}"
            assert L.candidate_count_all == 0 and [r.method for r in L.rows] == ["target_only"]
    assert sorted(seen) == ["s04-t1", "s05-t1", "s06-t1", "s07-t1"]


def test_c10_s06_smb_1_has_evidence_before_range_and_is_linked_only_by_evidence_6_to_7_5_s_after_its_logon():
    ld, key = linked("s06_t00"), load_key("s06_t00")
    hop = key_hop_of(ld, key, next(k for k in key["hops"] if k["hop_id"] == "s06-smb-1"))
    L = ld.links[hop.hop_id]
    print(f"C10 {describe(ld, hop)}")
    assert L.evidence_before_range > 0, f"s06-smb-1: before-range evidence {L.evidence_before_range}"
    cand_rows = [r for r in L.rows if r.session_key is not None]
    assert cand_rows, "s06-smb-1 has no candidate row"
    deltas = sorted(r.time_delta_ms for r in cand_rows)
    assert all(6000 <= d <= 7500 for d in deltas), f"s06-smb-1 deltas {deltas}"
    assert L.candidate_count_all >= 1 and not L.target_only_reason


def test_c10_the_s02_t01_05_34_09_hop_has_no_candidate_and_evidence_before_range():
    ld = linked("s02_t01")
    day_us = 86_400_000_000
    target = 5 * 3600 + 34 * 60 + 9
    hops = [h for h in user_e2e_hops(ld) if abs((h.first_us % day_us) / 1e6 - target) <= 1.0]
    assert len(hops) == 1, f"{len(hops)} s02_t01 user hops within 1 s of 05:34:09"
    L = ld.links[hops[0].hop_id]
    print(f"C10 {describe(ld, hops[0])}")
    assert L.candidate_count_all == 0 and L.target_only_reason == "no_evidence_in_range"
    assert L.evidence_before_range > 0, f"{hops[0].hop_id}: before-range evidence {L.evidence_before_range}"


# ------------------------------------------------------------------------------------------------ C11
def _dc_hops(ld: Linked) -> list:
    return [h for h in ld.hs.hops if h.target_host == "dc01" and h.source_ip in ENDPOINT_IPS]


def test_c11_endpoint_to_dc01_hops_have_no_candidate_session_by_any_method_in_any_trial():
    n, bad = 0, []
    for t in DEV:
        ld = linked(t)
        for h in _dc_hops(ld):
            n += 1
            L = ld.links[h.hop_id]
            if L.candidate_count_all or any(L.candidate_counts.values()):
                bad.append((h.hop_id, dict(L.candidate_counts)))
    print(f"C11 endpoint->dc01 hops {n}")
    assert n > 100
    assert bad == [], f"{len(bad)} endpoint->dc01 hop(s) with a candidate session: {bad[:5]}"


def test_c11_endpoint_to_dc01_hops_are_kerberos_confirmed_except_exactly_one_s03_t01_machine_account_hop():
    n, unconfirmed = 0, []
    for t in DEV:
        ld = linked(t)
        for h in _dc_hops(ld):
            n += 1
            if not krb(ld, h):
                unconfirmed.append((t, h.hop_id, h.source_ip, h.machine_account_only, h.member_count))
    print(f"C11 endpoint->dc01 hops {n}, not Kerberos-confirmed {len(unconfirmed)}: {unconfirmed}")
    assert len(unconfirmed) == 1, f"{len(unconfirmed)} unconfirmed endpoint->dc01 hops: {unconfirmed}"
    t, hid, ip, machine_only, _ = unconfirmed[0]
    assert t == "s03_t01" and ip == EP_IP["ep-02"] and machine_only == 1, f"{t} {hid} {ip} machine_only={machine_only}"


def test_c11_the_unconfirmed_hop_has_no_in_window_4769_with_its_guid():
    ld = linked("s03_t01")
    hops = [h for h in _dc_hops(ld) if not krb(ld, h)]
    assert len(hops) == 1
    guids = {norm_logon_guid(m.logon_guid) for m in hops[0].members} - {None}
    assert guids, "the unconfirmed hop has no usable LogonGuid"
    in_window = {norm_logon_guid(r.get("logon_guid")) for r in ld.scan.link_rows
                 if (r["channel"], r["event_id"], r["host"]) == ("Security", 4769, "dc01")}
    assert guids.isdisjoint(in_window)


def test_c11_s07_t00_has_exactly_5_target_only_source_host_no_logs_hops_all_from_ep_03():
    ld = linked("s07_t00")
    nl = [h for h in ld.hs.hops if ld.links[h.hop_id].target_only_reason == "source_host_no_logs"]
    print(f"C11 s07_t00 source_host_no_logs hops: {len(nl)}")
    assert len(nl) == 5
    assert {h.source_ip for h in nl} == {EP_IP["ep-03"]}
    for h in nl:
        L = ld.links[h.hop_id]
        assert [r.method for r in L.rows] == ["target_only"] and L.source_host == "ep-03"
    others = {t: sum(1 for h in linked(t).hs.hops if linked(t).links[h.hop_id].target_only_reason == "source_host_no_logs")
              for t in DEV if t != "s07_t00"}
    print(f"C11 source_host_no_logs hops in the other trials (reported): {others}")


# ------------------------------------------------------------------------------------------------ C12 / spec 10.5
def test_c12_port_join_match_deltas_over_the_winrm_hops_25_matches_corrected_and_raw_ranges():
    corr, raw = [], []
    for t in DEV:
        ld = linked(t)
        for h in user_e2e_hops(ld):
            if h.protocol == "winrm":
                for c, r in ld.links[h.hop_id].methods[PORT].match_deltas_us:
                    corr.append(c / 1e6)
                    raw.append(r / 1e6)
    print(f"C12 port matches {len(corr)}: corrected {min(corr):+.3f}..{max(corr):+.3f}, raw {min(raw):+.3f}..{max(raw):+.3f}")
    tol = 0.010 + 1e-6                                                   # 10 ms (the spec values are truncated)
    assert len(corr) == 25, f"{len(corr)} port matches"
    assert abs(min(corr) - (-2.09)) <= tol and abs(max(corr) - 1.57) <= tol, f"{min(corr):+.3f} {max(corr):+.3f}"
    assert abs(min(raw) - (-18.87)) <= tol and abs(max(raw) - (-1.21)) <= tol, f"{min(raw):+.3f} {max(raw):+.3f}"


def test_c12_the_nearest_command_delta_on_the_keyed_hops_lies_in_minus_6_5_to_plus_6_8_s():
    deltas = []
    for t, key, ld, hop, kh in keyed_hops():
        for r in ld.links[hop.hop_id].rows:
            if r.method == CMD and r.session_key is not None:
                deltas.append((r.time_delta_ms, kh["hop_id"]))
    assert deltas, "no command row on any keyed hop"
    lo, hi = min(deltas), max(deltas)
    print(f"C12 nearest command on keyed hops: {lo[0] / 1000:+.2f} s ({lo[1]}) .. {hi[0] / 1000:+.2f} s ({hi[1]})")
    out = [d for d in deltas if not -6500 <= d[0] <= 6800]
    assert out == [], f"command deltas outside [-6.5, +6.8] s: {out}"


# ------------------------------------------------------------------------------------------------ C15 / ST-01
@pytest.mark.parametrize("trial", DEV)
def test_c15_no_evidence_supporting_or_confirm_uid_is_outside_the_window_or_in_the_look_back(trial):
    ld = linked(trial)
    in_window = {u for r in ld.scan.in_window + ld.scan.link_rows for u in r["event_uids"]}
    lookback = {u for r in ld.scan.lookback for u in r["event_uids"]}
    uids: set[str] = set()
    for h in ld.hs.hops:
        L = ld.links[h.hop_id]
        for r in L.rows:
            uids.update(r.evidence_uids)
            uids.update(r.supporting_event_uids)
            uids.update(r.source_session_logon_uids)
            uids.update(r.names_event_uids)
        uids.update(confirm_of(h, ld.scan.link_rows, ld.arts)[1])
    assert uids and uids <= in_window, f"{trial}: {len(uids - in_window)} uid(s) not in the window"
    assert uids.isdisjoint(lookback), f"{trial}: {len(uids & lookback)} uid(s) from the look-back"
    lo, hi = ld.checked.start_us, ld.checked.end_us + US_PER_MS
    rows = {u: r for r in ld.scan.in_window + ld.scan.link_rows for u in r["event_uids"]}
    bad = sorted(u for u in uids if not lo <= rows[u]["us"] < hi)
    assert bad == [], f"{trial}: {len(bad)} uid(s) outside the window by corrected time, e.g. {bad[:5]}"


@pytest.mark.parametrize("trial", DEV)
def test_every_db_sha_is_unchanged_and_one_entry_with_well_formed_rows_exists_per_hop(trial):
    ld = linked(trial)
    sha_pre, before, after, gate_sha = ld.sha
    assert sha_pre == before == after == gate_sha == sha256_file(ld.paths.db)
    assert set(ld.links) == {h.hop_id for h in ld.hs.hops}
    for h in ld.hs.hops:
        L = ld.links[h.hop_id]
        assert L.rows, f"{h.hop_id}: no link row at all"
        assert bool(L.target_only_reason) == (L.candidate_count_all == 0)
        assert (L.rows[-1].method == "target_only") == bool(L.target_only_reason)
        assert sum(1 for r in L.rows if r.method == "target_only") == int(bool(L.target_only_reason))


# ------------------------------------------------------------------------------------------------ ST-02
def test_st02_s06_t01_ep_01_to_ep_03_winrm_rows_are_clock_unreliable_and_ep_01_to_ep_02_rows_are_not():
    ld = linked("s06_t01")
    to3 = [h for h in user_e2e_hops(ld) if h.protocol == "winrm" and h.target_host == "ep-03"
           and h.source_ip == EP_IP["ep-01"]]
    to2 = [h for h in user_e2e_hops(ld) if h.protocol == "winrm" and h.target_host == "ep-02"
           and h.source_ip == EP_IP["ep-01"]]
    assert to3 and to2, f"s06_t01: {len(to3)} ep-01->ep-03 and {len(to2)} ep-01->ep-02 WinRM hops"
    for h in to3:
        flags = [r.clock_unreliable for r in ld.links[h.hop_id].rows]
        assert flags and set(flags) == {1}, f"{h.hop_id}: {flags}"
        assert ld.links[h.hop_id].host_clock_unreliable == 1
    for h in to2:
        flags = [r.clock_unreliable for r in ld.links[h.hop_id].rows]
        assert flags and set(flags) == {0}, f"{h.hop_id}: {flags}"
        assert ld.links[h.hop_id].host_clock_unreliable == 0


def test_st02_the_gate_value_is_kept_apart_from_the_stitchers_on_the_ep_01_to_ep_02_hop():
    ld = linked("s06_t01")
    to2 = [h for h in user_e2e_hops(ld) if h.target_host == "ep-02" and h.source_ip == EP_IP["ep-01"]]
    assert to2 and all(h.gate_clock_unreliable == 1 for h in to2)       # the gate marks every row of the trial


@pytest.mark.parametrize("trial", [t for t in DEV if t != "s06_t01"])
def test_st02_report_clock_unreliable_link_rows_of_the_other_trials(trial):
    """Reported, not asserted: spec 6 names only s06_t01 (`wide` ep-03); other trials are reported for review."""
    ld = linked(trial)
    flagged = [(h.hop_id, r.method) for h in user_e2e_hops(ld) for r in ld.links[h.hop_id].rows if r.clock_unreliable]
    print(f"ST-02 {trial}: clock_unreliable user endpoint link rows {len(flagged)}")


# ================================================================================================ T7.3 task 5: links, check file
# Plan section 5 C1, C13-C16 and spec 03_stitch STT-12, STT-13, STA-07 and 10.4 on the nine development trials. Written from
# the plan, decision 048 (items 1, 6, 11, 13 as amended) and the spec, not from the implementation. The sensitivity runs call
# `links.run_links` with a `dataclasses.replace` copy of `StitchParams` and are cached per (trial, parameter). Messages carry
# counts, hop ids, hex session IDs and uids only, never command text or account names.
import builtins  # noqa: E402
import contextlib  # noqa: E402
import dataclasses  # noqa: E402
import os  # noqa: E402
import pathlib  # noqa: E402
import sqlite3  # noqa: E402
import subprocess  # noqa: E402

from stitch import check_links as cl  # noqa: E402
from stitch.links import run_links  # noqa: E402

SRC_DIR = REPO / "src"
OUT_ROOT = REPO / "out" / "stitch_check"


@contextlib.contextmanager
def _watch_fs(needle: str, monkeypatch):
    """Record every filesystem or sqlite call whose first argument contains `needle`, then delegate."""
    seen: list[str] = []

    def wrap(obj, name):
        orig = getattr(obj, name)

        def inner(*args, **kw):
            try:
                text = str(args[0]) if args else ""
            except Exception:  # noqa: BLE001
                text = ""
            if needle in text:
                seen.append(f"{name}({text})")
            return orig(*args, **kw)
        monkeypatch.setattr(obj, name, inner)

    with monkeypatch.context():
        wrap(builtins, "open")
        for n in ("stat", "lstat", "scandir", "listdir"):
            wrap(os, n)
        for n in ("exists", "isfile", "isdir"):
            wrap(os.path, n)
        for n in ("stat", "exists", "is_file", "is_dir", "open", "read_bytes", "read_text", "mkdir", "iterdir"):
            wrap(pathlib.Path, n)
        wrap(sqlite3, "connect")
        yield seen


def _listing() -> list[str] | None:
    return sorted(p.name for p in OUT_ROOT.iterdir()) if OUT_ROOT.is_dir() else None


@functools.lru_cache(maxsize=None)
def _check_data(trial: str) -> dict:
    """The check-file dict of one development trial (built once; nothing written)."""
    assert trial in DEV, trial
    _paths_or_skip(trial)
    return cl.run_check(REPO, trial)


def _all_strings(value: Any) -> list[str]:
    """Every scalar of a parsed JSON value as text, keys left out (a key name is the schema's, not data)."""
    out: list[str] = []
    if isinstance(value, dict):
        for v in value.values():
            out.extend(_all_strings(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(_all_strings(v))
    elif value is not None and not isinstance(value, bool):
        out.append(str(value))
    return out


def _all_keys(value: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(str(k))
            out |= _all_keys(v)
    elif isinstance(value, list):
        for v in value:
            out |= _all_keys(v)
    return out


# ------------------------------------------------------------------------------------------------ C1
def test_c1_s02_t02_is_refused_by_the_cli_with_exit_2_and_no_folder_is_created():
    assert "s02_t02" not in DEV
    listing = _listing()
    proc = subprocess.run([sys.executable, "-m", "stitch.check_links", "--trial", "s02_t02"], cwd=str(SRC_DIR),
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 2, f"exit {proc.returncode}"
    assert proc.stderr.startswith("refused:") and proc.stdout == ""
    assert not (OUT_ROOT / "s02_t02").exists()
    assert _listing() == listing


@pytest.mark.parametrize("trial", ["s03_t05", "s07_t10", "s06_t02"])
def test_c1_other_test_trials_are_refused_before_any_file_of_them_is_opened(trial, monkeypatch):
    assert trial not in DEV
    listing = _listing()
    with _watch_fs(trial, monkeypatch) as seen:
        code = cl.main(["--trial", trial, "--repo", str(REPO)])
    assert code == 2
    assert seen == [], f"{trial}: {len(seen)} filesystem call(s) on a path of the refused trial"
    assert not (OUT_ROOT / trial).exists()
    assert _listing() == listing


@pytest.mark.parametrize("trial", DEV)
def test_c1_check_links_twice_gives_byte_identical_files_and_leaves_db_and_t72_index_unchanged(trial):
    paths = _paths_or_skip(trial)
    t72 = REPO / CHECK_REL / trial / "t72_index.json"
    t72_before = t72.read_bytes() if t72.is_file() else None
    sha_pre = sha256_file(paths.db)
    out = REPO / CHECK_REL / trial / "t73_links.json"
    assert cl.main(["--trial", trial, "--repo", str(REPO)]) == 0
    first = out.read_bytes()
    assert cl.main(["--trial", trial, "--repo", str(REPO)]) == 0
    second = out.read_bytes()
    assert first == second, f"{trial}: two runs differ ({len(first)} / {len(second)} bytes)"
    assert first == check_text(_check_data(trial)).encode("utf-8")
    assert first.endswith(b"\n") and b"\r" not in first
    data = json.loads(first)
    assert data["trial_id"] == trial
    assert data["db"]["sha256_before"] == data["db"]["sha256_after"] == _gate_sha_after(paths) == sha_pre
    assert sha256_file(paths.db) == sha_pre
    assert [p.name for p in out.parent.iterdir() if p.suffix == ".tmp"] == []
    if t72_before is not None:
        assert t72.read_bytes() == t72_before, f"{trial}: t72_index.json changed"


# ------------------------------------------------------------------------------------------------ STT-13
MIN_SUB = 12


def _db_values(db: pathlib.Path, sql: str) -> list[tuple]:
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        return [tuple(r) for r in con.execute(sql)]
    finally:
        con.close()


def _allowed_strings(data: dict) -> set[str]:
    """Not command text: target-side names listed in the file, lab IPs (parameters and `source_ip` values)."""
    allowed: set[str] = set()
    for a in data["artefacts"]:
        allowed.update(n for n in a["names"] if n)
    for h in data["hops"]:
        if h["source_ip"]:
            allowed.add(h["source_ip"])
        for r in h["links"]:
            allowed.update(n for n in r["names_found"] if n)
    allowed.update(str(v) for v in data["parameters"]["lab_host_ips"].values())
    return {a.lower() for a in allowed if len(a) >= 3}


def _strip(text: str, allowed: set[str]) -> list[str]:
    """Lower-case `text`, replace every allowed string (longest first) by a separator, return the pieces of length >= 12."""
    s = text.lower()
    for a in sorted(allowed, key=len, reverse=True):
        s = s.replace(a, "\x00")
    return [p for p in s.split("\x00") if len(p) >= MIN_SUB]


def _grams(pieces: list[str]) -> set[str]:
    return {p[i:i + MIN_SUB] for p in pieces for i in range(len(p) - MIN_SUB + 1)}


def _stt13_hits(trial: str) -> tuple[list[str], int, int]:
    """(uids of commands sharing a 12-character substring with the file, commands read, 12-grams of the file)."""
    data = _check_data(trial)
    allowed = _allowed_strings(data)
    grams = _grams(_strip("\x00".join(_all_strings(data)), allowed))     # string and number values, no keys
    db = trial_paths(REPO, trial).db
    rows = _db_values(db, "SELECT event_uid, command_line FROM events_dedup "
                          "WHERE command_line IS NOT NULL AND command_line != ''")
    hit_uids, seen = [], {}
    for uid, cmd in rows:
        if cmd not in seen:
            seen[cmd] = any(g in grams for g in _grams(_strip(cmd, allowed)))
        if seen[cmd]:
            hit_uids.append(uid)
    return sorted(hit_uids), len(rows), len(grams)


@pytest.mark.parametrize("trial", DEV)
def test_stt13_no_command_line_substring_of_12_or_more_characters_is_in_the_check_file(trial):
    """Method: take every string / number VALUE of the parsed t73_links.json (keys are the schema's, left out); lower-case
    it; cut out the allowed strings (target-side names listed in the file, lab IPs of the parameters, `source_ip` values);
    apply the same cut to every `command_line` of the trial DB (read-only); then search for any common 12-character substring.
    A hit is reported as a count and uids only."""
    hits, n_cmd, n_grams = _stt13_hits(trial)
    print(f"STT-13 {trial}: command lines read {n_cmd}, file 12-grams {n_grams}, commands with a common 12-gram {len(hits)}")
    assert n_cmd > 0
    assert hits == [], f"{trial}: {len(hits)} command line(s) share a 12-character substring with t73_links.json, e.g. {hits[:5]}"


def test_stt13_the_matcher_catches_a_leak_and_lets_allowed_names_and_ips_through():
    allowed = {"xpay.exe", "192.168.50.22"}
    file_grams = _grams(_strip("Invoke-Thing -Secret abc123 and 192.168.50.22 and Xpay.exe", allowed))
    leak = "powershell -x Invoke-Thing -Secret abc123 -y"
    assert any(g in file_grams for g in _grams(_strip(leak, allowed))), "a 12-character leak is not found"
    ok = "copy Xpay.exe \\\\192.168.50.22\\c$"
    assert not any(g in file_grams for g in _grams(_strip(ok, allowed)))
    assert _strip("192.168.50.22xpay.exe192.168.50.22", allowed) == []


@pytest.mark.parametrize("trial", DEV)
def test_stt13_no_account_name_and_no_image_path_of_the_db_is_a_value_in_the_check_file(trial):
    data = _check_data(trial)
    values = _all_strings(data)
    low_values = {v.lower() for v in values}
    db = trial_paths(REPO, trial).db
    accounts = {str(a).strip() for (a,) in _db_values(
        db, "SELECT account_name FROM events_dedup UNION SELECT subject_account FROM events_dedup") if a is not None}
    accounts = {a for a in accounts if a}
    assert accounts, f"{trial}: no account in the DB"
    as_value = sorted(a for a in accounts if a.lower() in low_values)
    assert as_value == [], f"{trial}: {len(as_value)} account name(s) are a JSON string value"
    joined = "\x00".join(values)
    cased = [a for a in accounts if len(a) >= 5 and a in joined]
    assert cased == [], f"{trial}: {len(cased)} account name(s) of 5+ characters occur inside a JSON string value"
    images: set[str] = set()
    for col in ("image", "parent_image", "source_image", "target_image"):
        images.update(str(v).strip() for (v,) in _db_values(db, f"SELECT DISTINCT {col} FROM events_dedup") if v)
    paths_ = {i.lower() for i in images if "\\" in i or "/" in i}
    assert paths_, f"{trial}: no image path in the DB"
    jl = joined.lower()
    found = sorted(p for p in paths_ if p in jl)
    assert found == [], f"{trial}: {len(found)} image path(s) occur in the check file"


@pytest.mark.parametrize("trial", DEV)
def test_stt13_no_key_of_the_check_file_names_an_account_image_or_command_field(trial):
    keys = _all_keys(_check_data(trial))
    exact = {"account", "accounts", "command", "cmd", "command_line", "image", "images"}
    parts = ("account_name", "subject_account", "session_account", "credential", "image", "command_line", "password",
             "user_name", "username")
    bad = sorted(k for k in keys if k.lower() in exact or any(p in k.lower() for p in parts))
    assert bad == [], f"{trial}: forbidden-looking key(s) {bad}"


# ------------------------------------------------------------------------------------------------ C15 on the check file
@pytest.mark.parametrize("trial", DEV)
def test_c15_every_uid_of_the_check_file_is_in_the_window_and_none_is_from_the_look_back(trial):
    data, ld = _check_data(trial), linked(trial)
    uids: set[str] = set()
    for h in data["hops"]:
        uids.update(h["member_logon_uids"])
        uids.update(h["followup_logon_uids"])
        uids.update(h["confirm_event_uids"])
        for r in h["links"]:
            uids.update(r["supporting_event_uids"])
            uids.update(r["source_session_logon_uid"])
    for a in data["artefacts"]:
        uids.update(a["event_uids"])
        if a["member_logon_uid"]:
            uids.add(a["member_logon_uid"])
    for lm in data["data_limits"].values():
        uids.add(lm["last_security_event_uid"])
        for v in lm["evidence_after_event_uids"].values():
            uids.update(v)
    rows = {u: r for r in ld.scan.in_window + ld.scan.link_rows for u in r["event_uids"]}
    lookback = {u for r in ld.scan.lookback for u in r["event_uids"]}
    assert uids, f"{trial}: no uid in the check file"
    missing = sorted(uids - set(rows))
    assert missing == [], f"{trial}: {len(missing)} uid(s) of the check file are in no in-window row, e.g. {missing[:5]}"
    assert uids.isdisjoint(lookback), f"{trial}: {len(uids & lookback)} uid(s) from the look-back"
    lo, hi = ld.checked.start_us, ld.checked.end_us + US_PER_MS
    bad = sorted(u for u in uids if not lo <= rows[u]["us"] < hi)
    assert bad == [], f"{trial}: {len(bad)} uid(s) outside the window by corrected time, e.g. {bad[:5]}"


# ------------------------------------------------------------------------------------------------ C16
def test_c16_s06_t01_ep_03_is_listed_with_its_last_security_event_72_s_before_the_window_end():
    data = _check_data("s06_t01")
    assert "ep-03" in data["data_limits"], f"hosts listed: {sorted(data['data_limits'])}"
    lm = data["data_limits"]["ep-03"]
    clock = lm["last_security_utc"]
    hh, mm, ss = (int(x) for x in clock[11:19].split(":"))
    frac = float("0" + clock[19:].rstrip("Z")) if clock[19:].rstrip("Z") else 0.0
    secs = hh * 3600 + mm * 60 + ss + frac
    print(f"C16 s06_t01 ep-03: last Security {clock} (corrected {lm['last_security_utc_corrected']}), "
          f"{lm['ms_before_window_end']} ms before the window end, evidence after {lm['evidence_after']}, "
          f"data_limitation {lm['data_limitation']}, hops near the end {lm['hops_near_end']}")
    assert abs(secs - (6 * 3600 + 23 * 60 + 26)) <= 1.0, f"last Security event at {clock}"
    assert 70000 <= lm["ms_before_window_end"] <= 74000
    # 048 item 13 as amended: the label is a consistent function of the evidence counts, never a verdict
    assert lm["data_limitation"] == int(sum(lm["evidence_after"].values()) > 0)
    for m, n in lm["evidence_after"].items():
        assert n == len(lm["evidence_after_event_uids"][m])
    if not lm["data_limitation"]:
        assert lm["hops_near_end"] == []


@pytest.mark.parametrize("trial", DEV)
def test_c16_every_host_label_is_consistent_with_its_evidence_and_is_reported(trial):
    data = _check_data(trial)
    labelled = []
    for host, lm in data["data_limits"].items():
        assert lm["data_limitation"] == int(sum(lm["evidence_after"].values()) > 0), f"{trial} {host}"
        assert set(lm["evidence_after"]) == {"sysmon3_port", "source_4648", "cmdline_target"}
        assert lm["ms_before_window_end"] is not None
        if lm["data_limitation"]:
            labelled.append((host, lm["evidence_after"], lm["hops_near_end"]))
        else:
            assert lm["hops_near_end"] == []
    assert data["counts"]["data_limitation_hosts"] == sorted(h for h, lm in data["data_limits"].items()
                                                              if lm["data_limitation"])
    print(f"C16 {trial}: hosts listed {sorted(data['data_limits'])}, labelled data_limitation {labelled}")


# ------------------------------------------------------------------------------------------------ C13 / STA-07
def _view(li) -> dict[str, dict]:
    """Per hop: candidate sessions (hex IDs) per method and the target_only reason."""
    out = {}
    for h in li.hopset.hops:
        L = li.links[h.hop_id]
        by_m: dict[str, tuple] = {}
        for m in (PORT, E4648, CMD):
            by_m[m] = tuple(sorted({r.source_session_id_hex for r in L.rows if r.method == m and r.session_key is not None}))
        out[h.hop_id] = {"methods": by_m, "reason": L.target_only_reason,
                         "all": tuple(sorted({x for v in by_m.values() for x in v}))}
    return out


@functools.lru_cache(maxsize=None)
def _sens(trial: str, items: tuple):
    assert trial in DEV, trial
    _paths_or_skip(trial)
    li, before, after = run_links(REPO, trial, dataclasses.replace(PARAMS, **dict(items)))
    assert before == after
    return li


def sens(trial: str, **kw):
    return _sens(trial, tuple(sorted(kw.items())))


def sens_diff(trial: str, **kw) -> dict[str, tuple[dict, dict]]:
    """{hop id: (baseline view, changed view)} for the hops whose candidate sessions differ. The hop set is equal (the
    parameters of these runs do not touch grouping)."""
    base, v = _view(sens(trial)), _view(sens(trial, **kw))
    assert set(base) == set(v), f"{trial}: the hop set changed"
    return {h: (base[h], v[h]) for h in base if base[h] != v[h]}


def all_diffs(**kw) -> dict[str, dict]:
    return {t: d for t in DEV for d in [sens_diff(t, **kw)] if d}


def smb1_hop_id() -> str:
    ld, key = linked("s06_t00"), load_key("s06_t00")
    return key_hop_of(ld, key, next(k for k in key["hops"] if k["hop_id"] == "s06-smb-1")).hop_id


def s02_t01_05_34_09_hop_id() -> str:
    ld = linked("s02_t01")
    day_us = 86_400_000_000
    target = 5 * 3600 + 34 * 60 + 9
    hops = [h for h in user_e2e_hops(ld) if abs((h.first_us % day_us) / 1e6 - target) <= 1.0]
    assert len(hops) == 1
    return hops[0].hop_id


def test_c13_the_unchanged_parameters_give_the_same_links_as_the_cached_baseline():
    for t in DEV:
        base = _view(sens(t))
        ld = linked(t)
        assert set(base) == set(ld.links)
        for h, v in base.items():
            L = ld.links[h]
            assert v["reason"] == L.target_only_reason
            assert v["all"] == tuple(sorted({hex_id(k[1]) for k in L.candidate_sessions}))


@pytest.mark.parametrize("after_s", [10.0, 30.0])
def test_c13_after_side_10_and_30_s_give_the_same_links_as_15_s_on_all_nine_trials(after_s):
    diffs = all_diffs(link_after_s=after_s)
    assert diffs == {}, f"after {after_s} s changes hops {[(t, sorted(d)) for t, d in diffs.items()]}"


def test_c13_after_side_5_s_makes_only_s06_smb_1_target_only():
    diffs = all_diffs(link_after_s=5.0)
    smb1 = smb1_hop_id()
    print(f"C13 after 5 s: changed hops { {t: sorted(d) for t, d in diffs.items()} }")
    assert {t: sorted(d) for t, d in diffs.items()} == {"s06_t00": [smb1]}
    before, after = diffs["s06_t00"][smb1]
    assert before["reason"] == "" and before["all"]
    assert after["reason"] == "no_evidence_in_range" and after["all"] == ()


def test_c13_look_back_120_s_adds_only_the_s02_t01_05_34_09_candidate_at_about_minus_92_s():
    diffs = all_diffs(link_lookback_s=120.0)
    hop = s02_t01_05_34_09_hop_id()
    print(f"C13 look-back 120 s: changed hops { {t: sorted(d) for t, d in diffs.items()} }")
    assert {t: sorted(d) for t, d in diffs.items()} == {"s02_t01": [hop]}
    before, after = diffs["s02_t01"][hop]
    assert before["all"] == () and before["reason"] == "no_evidence_in_range"
    assert len(after["all"]) == 1 and after["reason"] == ""
    L = sens("s02_t01", link_lookback_s=120.0).links[hop]
    deltas = [r.time_delta_ms for r in L.rows if r.session_key is not None]
    print(f"C13 look-back 120 s: new session {after['all']}, time_delta_ms {deltas}")
    assert deltas and all(-93500 <= d <= -91500 for d in deltas), f"time_delta_ms {deltas}"


def test_c13_look_back_300_s_gives_the_s03_t00_winrm_hop_a_second_candidate_session():
    diffs = all_diffs(link_lookback_s=300.0)
    ld, key = linked("s03_t00"), load_key("s03_t00")
    winrm = key_hop_of(ld, key, next(k for k in key["hops"] if k["hop_id"] == "s03-h1")).hop_id
    print(f"C13 look-back 300 s: changed hops { {t: sorted(d) for t, d in diffs.items()} }")
    assert "s03_t00" in diffs, "no hop of s03_t00 changes at a 300 s look-back (spec 10.4 says a second session appears)"
    assert sorted(diffs["s03_t00"]) == [winrm], f"s03_t00 changed hops {sorted(diffs['s03_t00'])}, expected only {winrm}"
    before, after = diffs["s03_t00"][winrm]
    assert len(before["all"]) == 1 and len(after["all"]) == 2 and set(before["all"]) < set(after["all"])
    (new,) = set(after["all"]) - set(before["all"])
    L = sens("s03_t00", link_lookback_s=300.0).links[winrm]
    deltas = sorted(r.time_delta_ms for r in L.rows if r.session_key is not None and r.source_session_id_hex == new)
    print(f"C13 look-back 300 s: s03_t00 {winrm} new session {new}, time_delta_ms {deltas}")
    assert deltas and all(-176000 <= d <= -170000 for d in deltas), f"time_delta_ms {deltas} (spec: command at -173 s)"
    # nothing is lost anywhere (a wider range only adds); the s02_t01 hop of the 120 s run is the only other change
    for t, d in diffs.items():
        for hop, (b, a) in d.items():
            assert set(b["all"]) <= set(a["all"]), f"{t} {hop}: a session is lost at 300 s"
    assert sorted(set(diffs) - {"s03_t00"}) == ["s02_t01"] and sorted(diffs["s02_t01"]) == [s02_t01_05_34_09_hop_id()]


def _winrm_user_hops(ld):
    return [h for h in user_e2e_hops(ld) if h.protocol == "winrm"]


@pytest.mark.parametrize("port_s", [2.0, 10.0])
def test_c13_port_join_at_2_and_10_s_links_6_of_7_winrm_hops_and_changes_no_hop_link(port_s):
    n_hops = n_port = 0
    for t in DEV:
        ld, li = linked(t), sens(t, port_join_s=port_s)
        for h in _winrm_user_hops(ld):
            n_hops += 1
            n_port += li.links[h.hop_id].candidate_counts[PORT] > 0
    assert (n_hops, n_port) == (7, 6), f"port join at {port_s} s: {n_port} of {n_hops} WinRM hops"
    assert all_diffs(port_join_s=port_s) == {}


def _followup_port_join(ld, f, hop, params):
    subj = src.subject_of(hop.target_host, hop.source_ip, f.logons, params)
    return src.port_join(subj, ld.scan, ld.index.processes, params)


def test_c13_port_join_at_10_s_joins_one_follow_up_group_and_links_none():
    counts = {}
    deltas = []
    for port_s in (2.0, 5.0, 10.0):
        p = dataclasses.replace(PARAMS, port_join_s=port_s)
        n = 0
        for t in ("s06_t00", "s06_t01"):
            ld = linked(t)
            for f, hop in _user_followups(ld):
                res = _followup_port_join(ld, f, hop, p)
                if res.evidence:
                    n += 1
                    if port_s == 10.0:
                        deltas += [c / 1e6 for c, _ in res.match_deltas_us]
        counts[port_s] = n
    print(f"C13 follow-up groups joined by the port join at 2 / 5 / 10 s: {counts}, corrected deltas {deltas}")
    assert counts == {2.0: 0, 5.0: 0, 10.0: 1}
    # spec 10.4: "-9.4 s" (the nearest match, -9.43 s); the group's other match is -9.58 s
    assert deltas and all(-9.6 <= d <= -9.3 for d in deltas), f"deltas {deltas} (spec: -9.4 s)"
    # ST-26: the follow-up group has no link rows in any run
    for t in ("s06_t00", "s06_t01"):
        li = sens(t, port_join_s=10.0)
        fol = {u for f in li.hopset.followups for lg in f.logons for u in lg.event_uids}
        assert fol and all(fol.isdisjoint(r.supporting_event_uids) for L in li.links.values() for r in L.rows)


def _raw_scan(scan):
    """A copy of the scan whose Sysmon 3 rows carry us = us_raw (the logged time)."""
    rows = [dict(r, us=r["us_raw"]) if (r["channel"], r["event_id"]) == ("Sysmon", 3) else r for r in scan.in_window]
    return dataclasses.replace(scan, in_window=rows)


def test_c13_port_join_on_raw_times_at_5_s_links_3_of_7_winrm_hops():
    res = {}
    for port_s in (2.0, 5.0):
        p = dataclasses.replace(PARAMS, port_join_s=port_s)
        joined, per_trial = 0, {}
        for t in DEV:
            ld = linked(t)
            scan2 = _raw_scan(ld.scan)
            for h in _winrm_user_hops(ld):
                members = [dataclasses.replace(m, us=m.us_raw) for m in h.members]
                subj = src.Subject(h.target_host, src.source_host_of(h.source_ip, PARAMS.lab_host_ips), tuple(members))
                ok = bool(src.port_join(subj, scan2, ld.index.processes, p).evidence)
                joined += ok
                per_trial.setdefault(t, []).append(int(ok))
        res[port_s] = (joined, per_trial)
    print(f"C13 raw-time port join: ±2 s {res[2.0][0]} of 7 {res[2.0][1]}; ±5 s {res[5.0][0]} of 7 {res[5.0][1]}")
    assert res[5.0][0] == 3, f"raw ±5 s: {res[5.0][0]} of 7 WinRM hops {res[5.0][1]} (spec 10.4 says 3 of 7)"
    failing = sorted(t for t, v in res[5.0][1].items() if 0 in v)
    assert {"s03_t01", "s06_t01"} <= set(failing), f"trials with a raw-time failure at ±5 s: {failing}"


def _groups_for_4648(ld):
    """The 21 user endpoint hops and the 2 follow-up groups, as (label, Subject)."""
    out = [(h.hop_id, src.hop_subject(h, PARAMS)) for h in user_e2e_hops(ld)]
    for f, hop in _user_followups(ld):
        out.append((f"{hop.hop_id}+fu", src.subject_of(hop.target_host, hop.source_ip, f.logons, PARAMS)))
    return out


def _n_4648_groups(params) -> tuple[int, int]:
    """(groups with a 4648 candidate session, groups examined) over the 21 user hops and the 2 follow-up groups."""
    n = total = 0
    for t in DEV:
        ld = linked(t)
        sessions = build_index(t, ld.scan, PARAMS).sessions  # a fresh index: by_4648 may add unknown-open sessions
        for _label, subj in _groups_for_4648(ld):
            total += 1
            n += bool(src.by_4648(subj, ld.scan, ld.t4648, sessions, params).sessions)
    return n, total


def test_c13_4648_alone_at_symmetric_2_5_10_s_loses_3_1_0_of_the_11_groups_that_have_one_at_minus_120_plus_10():
    wide, total = _n_4648_groups(dataclasses.replace(PARAMS, link_lookback_s=120.0, link_after_s=10.0))
    lost = {}
    for s in (2.0, 5.0, 10.0):
        n, tot = _n_4648_groups(dataclasses.replace(PARAMS, link_lookback_s=s, link_after_s=s))
        assert tot == total == 23
        lost[s] = wide - n
    print(f"C13 4648 alone: groups with one at [-120, +10] s: {wide} of {total}; lost at ±2 / ±5 / ±10 s: {lost}")
    assert wide == 11, f"{wide} groups have a 4648 candidate at [-120, +10] s (spec: 11)"
    assert (lost[2.0], lost[5.0], lost[10.0]) == (3, 1, 0), f"lost {lost} (spec: 3 / 1 / 0)"


def _hop_ids_of(hopset, uids):
    out = set()
    for h in hopset.hops:
        for m in h.members + h.followups:
            if set(uids) & set(m.event_uids):
                out.add(h.hop_id)
    return out


def _hops_at(trial: str, gap_s: float):
    ld = hopped(trial)
    p = dataclasses.replace(PARAMS, group_gap_s=gap_s)
    return build_hops(trial, ld.gate, ld.scan, build_index(trial, ld.scan, p).sessions, p)


def test_c13_grouping_gap_1_s_splits_the_s03_t01_winrm_hop_and_2_and_5_s_keep_it():
    """At 1 s the inside gap of 1.33 s splits the five logons. The second part has no trigger row and re-uses the first
    part's ports, so ST-26 attaches it to the first part as follow-up logons: the SPLIT shows as a smaller hop (3 members) plus
    a follow-up group of 2 logons, not as a second hop. Both readings (a second hop, or the follow-up) are accepted as a split."""
    ld = linked("s03_t01")
    cand = [h for h in ld.hs.hops if h.protocol == "winrm" and h.member_count == 5 and h.inside_gap_max_ms is not None
            and 1300 <= h.inside_gap_max_ms < 1340]
    assert len(cand) == 1
    uids = [u for m in cand[0].members for u in m.event_uids]
    shape = {}
    for g in (1.0, 2.0, 5.0):
        hs = _hops_at("s03_t01", g)
        member_in = {h.hop_id: sum(1 for m in h.members if set(m.event_uids) & set(uids)) for h in hs.hops}
        member_in = {k: v for k, v in member_in.items() if v}
        follow = sum(len(f.logons) for f in hs.followups if any(set(lg.event_uids) & set(uids) for lg in f.logons))
        shape[g] = (sorted(member_in.values()), follow)
    print(f"C13 s03_t01 five-member WinRM hop: (members of the hop(s) holding them, follow-up logons) at gap 1 / 2 / 5 s: {shape}")
    assert shape[2.0] == ([5], 0) and shape[5.0] == ([5], 0)
    assert shape[1.0] != ([5], 0) and sum(shape[1.0][0]) + shape[1.0][1] == 5, f"gap 1 s: {shape[1.0]}"


def test_c13_grouping_gap_5_s_merges_s04_a_and_b_into_one_hop_and_1_and_2_s_keep_them_apart():
    ld, key = linked("s04_t00"), load_key("s04_t00")
    uids = {}
    for name in ("s04-A-h1", "s04-B-h1"):
        kh = next(k for k in key["hops"] if k["hop_id"] == name)
        uids[name] = key_logon_uids(ld, key, kh)
        assert uids[name]
    n = {}
    for g in (1.0, 2.0, 5.0):
        hs = _hops_at("s04_t00", g)
        a, b = _hop_ids_of(hs, uids["s04-A-h1"]), _hop_ids_of(hs, uids["s04-B-h1"])
        assert len(a) == 1 and len(b) == 1, f"gap {g}: A in {sorted(a)}, B in {sorted(b)}"
        n[g] = len(a | b)
    print(f"C13 s04 A+B: hops holding them at gap 1 / 2 / 5 s: {n}")
    assert n == {1.0: 2, 2.0: 2, 5.0: 1}


def test_c13_044_kill_criterion_no_keyed_hop_needs_evidence_outside_minus_30_plus_15_s():
    """The key session of each of the 11 keyed hops is a candidate, and its nearest evidence lies inside
    [first member - 30 s, last member + 15 s]; widening the look-back to 300 s does not remove any key session."""
    rows = []
    for t, key, ld, hop, kh in keyed_hops():
        lids = key_source_lids(ld, key, kh)
        if not lids:
            continue
        L = ld.links[hop.hop_id]
        span_ms = round((hop.last_us - hop.first_us) / 1000)
        wide = sens(t, link_lookback_s=300.0).links[hop.hop_id]
        for lid in lids:
            mine = [r for r in L.rows if r.session_key is not None and r.source_session_id == lid]
            assert mine, f"{kh['hop_id']}: the key session {hex_id(lid)} has no link row"
            nearest = min((r.time_delta_ms for r in mine), key=abs)
            rows.append((kh["hop_id"], hex_id(lid), nearest))
            assert -30000 <= nearest <= 15000 + span_ms, f"{kh['hop_id']}: nearest evidence {nearest} ms"
            assert lid in {k[1] for k in wide.candidate_sessions}, f"{kh['hop_id']}: key session lost at 300 s"
    print(f"C13 key sessions and nearest evidence (ms): {rows}")
    assert len({r[0] for r in rows}) == 11


# ------------------------------------------------------------------------------------------------ C14
SMB_NAMED_KEYED = ["s02-h1", "s04-A-h1", "s04-B-h1", "s05-h1", "s06-smb-1", "s07-h-x", "s07-h-y"]


def test_c14_key_session_names_found_for_the_7_keyed_smb_hops_and_none_for_the_winrm_hops():
    smb, winrm, report = {}, {}, []
    for t, key, ld, hop, kh in keyed_hops():
        lids = key_source_lids(ld, key, kh)
        if not lids:
            continue
        L = ld.links[hop.hop_id]
        names = {n for r in L.rows if r.session_key is not None and r.source_session_id in lids for n in r.names_found}
        name_uids = {u for r in L.rows if r.session_key is not None and r.source_session_id in lids
                     for u in r.names_event_uids}
        report.append((kh["hop_id"], hop.protocol, len(names), len(name_uids)))
        (winrm if hop.protocol == "winrm" else smb)[kh["hop_id"]] = (names, name_uids)
    print(f"C14 (keyed hop, protocol, names found, naming events): {report}")
    assert sorted(smb) == sorted(SMB_NAMED_KEYED), f"keyed SMB hops with a source session: {sorted(smb)}"
    empty = sorted(h for h, (names, _) in smb.items() if not names)
    assert empty == [], f"key session without a target-side name in its command evidence: {empty}"
    assert all(u for _, u in smb.values())
    assert len(winrm) == 4
    named = sorted(h for h, (names, _) in winrm.items() if names)
    assert named == [], f"WinRM keyed hops with names found (WinRM hops have no names): {named}"


# ------------------------------------------------------------------------------------------------ STT-12 on the check file
def test_stt12_check_file_s06_t01_ep_03_hops_are_clock_unreliable_and_the_ep_01_to_ep_02_hop_is_not():
    data = _check_data("s06_t01")
    ep1 = EP_IP["ep-01"]
    to3 = [h for h in data["hops"] if h["protocol"] == "winrm" and h["target_host"] == "ep-03" and h["source_ip"] == ep1
           and h["source_host"] == "ep-01"]
    to2 = [h for h in data["hops"] if h["protocol"] == "winrm" and h["target_host"] == "ep-02" and h["source_ip"] == ep1
           and h["source_host"] == "ep-01"]
    assert to3 and to2, f"{len(to3)} ep-01->ep-03 and {len(to2)} ep-01->ep-02 WinRM hop records"
    assert all(h["clock_unreliable"] == 1 for h in to3) and all(r["clock_unreliable"] == 1 for h in to3 for r in h["links"])
    assert all(h["clock_unreliable"] == 0 for h in to2) and all(r["clock_unreliable"] == 0 for h in to2 for r in h["links"])
    assert all(h["gate_clock_unreliable"] == 1 for h in to2)           # kept apart from the stitcher's own flag


@pytest.mark.parametrize("trial", DEV)
def test_check_file_counts_agree_with_its_rows_and_every_hop_has_a_link_row(trial):
    data = _check_data(trial)
    c, hops = data["counts"], data["hops"]
    assert c["hops"] == len(hops) == len({h["hop_id"] for h in hops})
    assert c["seeds"] == sum(h["is_seed"] for h in hops)
    assert c["followup_groups"] == len(linked(trial).hs.followups)
    assert c["followup_logons"] == sum(len(h["followup_logon_uids"]) for h in hops)
    assert all(h["links"] for h in hops), f"{trial}: a hop with no link row"
    assert sum(1 for h in hops if h["target_only_reason"]) == sum(c["target_only_reasons"].values())
    assert [h["hop_id"] for h in hops] == sorted(h["hop_id"] for h in hops)
