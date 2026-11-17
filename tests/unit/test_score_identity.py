"""T9 score stage: IdentityCoherence (spec 05_score SC-50..SC-55, SCT-50..58; decision 064; Correction K; decisions 013,
014, 044 (c)). Written from the spec and decision 064 / 067 items 5 and 6, not from the implementation.

Facts come from `hop_identity.csv` (one row per hop, account, LSASS read; spec 03 ST-60..64). The stitcher decides
`order_ok` (move >= dump - 5 s, decision 014); the scorer must use it unchanged and never re-apply the tolerance.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from score import identity as idn  # noqa: E402
from score_fixtures import ident  # noqa: E402

SYSTEM_IMAGES = [
    r"C:\Windows\System32\wbem\wmiprvse.exe",
    r"C:\Windows\System32\csrss.exe",
    r"C:\Windows\System32\wininit.exe",
    r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.3-0\MsMpEng.exe",
    r"C:\Program Files\Windows Defender\MsMpEng.exe",
]
SYSTEM_ACCOUNTS = ["system", "network service", "local service"]


def one(rows, hop="h1", account="svc"):
    return idn.account_identity(hop, account, rows)


# ------------------------------------------------------------------------------------------------ SC-50
def test_open_session_and_move_after_dump_is_exposed():
    a = one([ident()])
    assert (a.value, a.status, a.applicable) == (1, "exposed", True)
    assert a.deciding_dump_event_uids == ("d1",) and a.open_session_uids == ("sess1",)
    assert a.time_delta_ms == "10000" and a.candidate_count == 1


def test_order_not_ok_gives_zero_even_with_an_open_session():
    a = one([ident(order_ok="0", order_margin_ms="-6000", gap_ms="-6000")])      # move 6 s before the dump
    assert (a.value, a.status) == (0, "not_exposed")
    assert a.deciding_dump_event_uids == ()


def test_scorer_uses_order_ok_unchanged_it_does_not_reapply_the_tolerance():
    # within the 5 s margin the stitcher says ok (move 4 s before the dump): the scorer takes it as written
    inside = one([ident(order_ok="1", order_margin_ms="-4000", gap_ms="-4000", order_within_tolerance="1")])
    assert inside.value == 1
    outside = one([ident(order_ok="0", order_margin_ms="-6000", gap_ms="-6000")])
    assert outside.value == 0


def test_no_open_session_gives_zero():
    a = one([ident(open_session_uids="", open_session_types="")])
    assert (a.value, a.status) == (0, "not_exposed")


def test_no_read_at_all_is_not_exposed_with_no_candidate():
    a = one([ident(dump_event_uid="", open_session_uids="", order_ok="", gap_ms="", dump_utc_corrected="",
                   dump_source_image="", dump_account="")])
    assert (a.value, a.status, a.candidate_count) == (0, "not_exposed", 0)


def test_move_hours_after_dump_with_session_still_open_is_one_limitation_l_sc6():
    a = one([ident(gap_ms=str(7 * 3600 * 1000), order_margin_ms=str(7 * 3600 * 1000))])
    assert a.value == 1 and a.time_delta_ms == str(7 * 3600 * 1000)


def test_value_is_one_when_any_one_of_several_reads_decides():
    rows = [ident(dump_event_uid="d1", order_ok="0", gap_ms="-9000"),
            ident(dump_event_uid="d2", dump_utc_corrected="2026-09-24T09:59:00.000000Z", gap_ms="70000"),
            ident(dump_event_uid="d3", open_session_uids="")]
    a = one(rows)
    assert a.value == 1 and a.deciding_dump_event_uids == ("d2",) and a.candidate_count == 3


def test_time_delta_is_the_gap_of_the_earliest_deciding_read():
    rows = [ident(dump_event_uid="late", dump_utc_corrected="2026-09-24T10:00:05.000000Z", gap_ms="5000"),
            ident(dump_event_uid="early", dump_utc_corrected="2026-09-24T09:59:00.000000Z", gap_ms="70000")]
    assert one(rows).time_delta_ms == "70000"


def test_a_target_only_hop_gets_a_value_like_any_other_the_facts_carry_no_tier():
    # the scorer sees no tier at all in the facts: a target_only hop gets a value like any other
    assert one([ident()]).value == 1


# ------------------------------------------------------------------------------------------------ end_unknown (SC-53, 067 item 6)
def test_end_unknown_session_is_not_open_and_is_shown_as_unknown_not_not_exposed():
    a = one([ident(open_session_uids="", end_unknown_session_uids="sessX")])
    assert a.value == 0 and a.status == "unknown:end_unknown_session" and a.applicable


def test_end_unknown_does_not_override_a_real_open_session():
    a = one([ident(open_session_uids="sess1", end_unknown_session_uids="sessX")])
    assert a.value == 1 and a.status == "exposed"


# ------------------------------------------------------------------------------------------------ SC-51 (b')
@pytest.mark.parametrize("image", SYSTEM_IMAGES)
@pytest.mark.parametrize("account", SYSTEM_ACCOUNTS)
def test_the_five_system_images_under_a_system_account_are_not_counted(image, account):
    assert idn.is_excluded_read(image, account)
    a = one([ident(dump_source_image=image, dump_account=account)])
    assert (a.value, a.candidate_count) == (0, 0)


def test_exclusion_is_case_insensitive():
    assert idn.is_excluded_read(r"C:\WINDOWS\SYSTEM32\CSRSS.EXE", "SYSTEM")
    assert idn.is_excluded_read(r"c:\programdata\microsoft\windows defender\platform\4.18.1-0\msmpeng.exe",
                                "Network Service")


@pytest.mark.parametrize("image,account", [
    (r"C:\Users\x\AppData\Local\Temp\MsMpEng.exe", "system"),         # renamed dumper outside the Defender folder
    (r"C:\Windows\Temp\csrss.exe", "system"),
    (r"C:\Windows\System32\wmiprvse.exe", "system"),                   # not its stated wbem folder
    (r"C:\Windows\System32\wbem\wmiprvse.exe", "svc_backup"),          # right folder, user account
    (r"C:\Program Files\Windows Defender\MsMpEng.exe", "admin_it"),
    (r"C:\Windows\System32\wininit.exe", ""),                          # no account
    (r"C:\Windows\System32\rundll32.exe", "system"),                   # all rundll32 rows stay counted
    (r"C:\ProgramData\Microsoft\Windows Defender\Platform\a\b\MsMpEng.exe", "system"),   # one version segment only
    (r"C:\Users\x\Temp\Windows Defender\Platform\4.18\MsMpEng.exe", "system"),
])
def test_a_renamed_binary_or_a_user_account_still_counts(image, account):
    assert not idn.is_excluded_read(image, account)
    a = one([ident(dump_source_image=image, dump_account=account)])
    assert (a.value, a.candidate_count) == (1, 1)


def test_an_excluded_read_never_decides_but_a_counted_read_beside_it_does():
    ex = ident(dump_event_uid="dx", dump_source_image=SYSTEM_IMAGES[3], dump_account="system")
    real = ident(dump_event_uid="dr")
    assert one([ex]).value == 0
    a = one([ex, real])
    assert a.value == 1 and a.deciding_dump_event_uids == ("dr",) and a.candidate_count == 1


def test_candidate_count_counts_distinct_counted_dump_events():
    rows = [ident(dump_event_uid="d1"), ident(dump_event_uid="d1", open_session_uids="sess2"),
            ident(dump_event_uid="d2")]
    assert one(rows).candidate_count == 2


# ------------------------------------------------------------------------------------------------ SC-52 not applicable
@pytest.mark.parametrize("reason", ["machine_account", "source_host_unknown", "source_host_no_logs"])
def test_not_applicable_rows_have_no_value_and_an_unknown_status(reason):
    a = one([ident(dump_event_uid="", not_applicable=reason, open_session_uids="")])
    assert (a.applicable, a.value, a.status) == (False, None, f"unknown:{reason}")
    assert a.not_applicable == reason


def hop(*accounts):
    return idn.hop_identities(accounts)


def acct(hid, name, rows):
    return idn.account_identity(hid, name, rows)


def test_hop_value_is_the_max_over_applicable_accounts():
    exposed, plain = acct("h", "a", [ident("h", "a")]), acct("h", "b", [ident("h", "b", open_session_uids="")])
    assert hop(exposed, plain)["h"].value == 1 and hop(plain, exposed)["h"].value == 1       # order of accounts irrelevant
    assert hop(plain, acct("h", "c", [ident("h", "c", open_session_uids="")]))["h"].value == 0
    assert hop(plain)["h"].crossing


def test_an_unknown_account_does_not_lower_or_raise_the_hop():
    machine = acct("h", "m$", [ident("h", "m$", dump_event_uid="", not_applicable="machine_account")])
    exposed = acct("h", "a", [ident("h", "a")])
    h = hop(machine, exposed)["h"]
    assert h.crossing and h.value == 1


def test_a_hop_with_only_not_applicable_accounts_is_no_crossing():
    machine = acct("h", "m$", [ident("h", "m$", dump_event_uid="", not_applicable="machine_account")])
    h = hop(machine)["h"]
    assert (h.crossing, h.value) == (False, 0)


# ------------------------------------------------------------------------------------------------ SC-53
def hv(hid, value, *, crossing=True, flagged=False):
    return idn.HopIdentity(hop_id=hid, crossing=crossing, value=value, flagged=flagged)


def test_coherence_is_coherent_crossings_over_crossings():
    hops = {"a": hv("a", 1), "b": hv("b", 0), "c": hv("c", 0)}
    p = idn.path_identity(["a", "b", "c"], hops)
    assert (p.n_crossings, p.n_coherent) == (3, 1) and p.coherence == pytest.approx(1 / 3)


def test_a_path_with_no_crossing_scores_zero_and_reports_zero_crossings():
    hops = {"a": hv("a", 0, crossing=False)}
    p = idn.path_identity(["a"], hops)
    assert (p.coherence, p.low, p.high, p.n_crossings) == (0.0, 0.0, 0.0, 0)


def test_one_exposed_hop_and_one_unknown_hop_gives_one_not_one_half():
    hops = {"a": hv("a", 1), "u": hv("u", 0, crossing=False)}
    p = idn.path_identity(["a", "u"], hops)
    assert p.coherence == 1.0 and p.n_crossings == 1


def test_background_hop_with_value_zero_dilutes_a_merged_path_atk_sc_05():
    hops = {"bg": hv("bg", 0), "x": hv("x", 1), "y": hv("y", 1)}
    assert idn.path_identity(["bg", "x", "y"], hops).coherence == pytest.approx(2 / 3)


def test_path_identity_ignores_hop_list_order_and_repeats():
    hops = {"a": hv("a", 1), "b": hv("b", 0)}
    assert idn.path_identity(["b", "a"], hops) == idn.path_identity(["a", "b"], hops)


# ------------------------------------------------------------------------------------------------ SC-54 clock flag
def flagged_rejecting_read():
    return ident(order_ok="0", order_margin_ms="-6000", gap_ms="-6000", order_within_uncertainty="1")


def test_a_rejecting_read_inside_clock_uncertainty_flags_the_crossing_value_stays_zero():
    a = one([flagged_rejecting_read()])
    assert a.value == 0 and a.order_within_uncertainty == 1
    h = hop(a)["h1"]
    assert h.flagged and h.value == 0


def test_flagged_deciding_read_flags_the_crossing_value_stays_one():
    a = one([ident(order_within_uncertainty="1")])
    assert a.value == 1 and a.order_within_uncertainty == 1


def test_identity_low_and_high_count_flagged_crossings_at_zero_and_at_one():
    hops = {"a": hv("a", 1), "b": hv("b", 0, flagged=True)}
    p = idn.path_identity(["a", "b"], hops)
    assert (p.coherence, p.low, p.high) == (0.5, 0.5, 1.0) and p.n_flagged == 1
    hops = {"a": hv("a", 1, flagged=True), "b": hv("b", 1)}
    p = idn.path_identity(["a", "b"], hops)
    assert (p.coherence, p.low, p.high) == (1.0, 0.5, 1.0)
    hops = {"a": hv("a", 0, flagged=True)}
    p = idn.path_identity(["a"], hops)
    assert (p.coherence, p.low, p.high) == (0.0, 0.0, 1.0)


def test_without_a_flag_low_equals_high_equals_coherence():
    hops = {"a": hv("a", 1), "b": hv("b", 0)}
    p = idn.path_identity(["a", "b"], hops)
    assert p.low == p.high == p.coherence == 0.5 and p.n_flagged == 0


def test_a_read_with_no_open_session_cannot_change_the_value_so_it_does_not_flag():
    a = one([ident(order_ok="0", open_session_uids="", order_within_uncertainty="1")])
    assert a.order_within_uncertainty == 0


# ------------------------------------------------------------------------------------------------ grouping
def test_account_identities_cover_every_hop_and_account_sorted():
    rows = [ident("h2", "b"), ident("h1", "z"), ident("h1", "a"), ident("h1", "a", dump_event_uid="d9")]
    got = idn.account_identities(rows)
    assert [(a.hop_id, a.account) for a in got] == [("h1", "a"), ("h1", "z"), ("h2", "b")]


def test_status_vocabulary():
    rows = [ident("h1", "a"), ident("h2", "b", open_session_uids=""),
            ident("h3", "c", dump_event_uid="", not_applicable="machine_account", open_session_uids=""),
            ident("h4", "d", open_session_uids="", end_unknown_session_uids="s")]
    for a in idn.account_identities(rows):
        assert a.status in {"exposed", "not_exposed"} or a.status.startswith("unknown:")
