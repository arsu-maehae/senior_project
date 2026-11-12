"""Independent check of the offsets (spec 08 CO-10, CO-11a; ATK-06, ATK-07, ATK-09).

WHY a check that never uses LogonGuid: the LogonGuid pairs cannot validate themselves (after
correction the offsets they measure are 0 by construction). A source Sysmon 3 connection and the
target 4624 it caused share IpAddress + IpPort, which ties two endpoint clocks directly. The join is
made on RAW times before any correction, so the correction cannot choose its own check partner, and
these pairs never enter the estimate. Pure: no file is read or written here.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping, Sequence

from . import params
from .common import host_of_ip, is_event, norm_ip, s_to_us, us_to_ms
from .changes import ClockChange
from .correct import Offsets, corrected_us, event_unreliable
from .pairs import nearest

Row = dict[str, Any]


def is_check_source(row: Mapping, lo_us: int, hi_excl_us: int,
                    endpoints: Sequence[str] = params.ENDPOINTS,
                    ports: Sequence[int] = params.CHECK_PORTS) -> bool:
    """A Sysmon 3 on an endpoint, to ANOTHER endpoint on a check port, with a source port, in the window.

    WHY endpoints only on both sides (ATK-09): dc01 is the reference whose own clock may step, so an
    endpoint-to-endpoint pair tests the correction without depending on dc01.
    """
    if not (is_event(row, "Sysmon", 3) and row.get("host") in endpoints):
        return False
    target = host_of_ip(row.get("destination_ip"))
    return (target in endpoints and target != row.get("host") and row.get("destination_port") in ports
            and row.get("source_port") is not None and lo_us <= row["us"] < hi_excl_us)


def target_candidates(src: Mapping, target_host: str, logons_by_host: Mapping[str, Sequence[Mapping]],
                      join_us: int) -> list[Mapping]:
    """Target-host 4624s with IpAddress = the source host's lab IP and IpPort = the Sysmon 3 source
    port, within +-``CHECK_JOIN_S`` of the Sysmon 3 on raw time (ATK-07)."""
    src_ip = norm_ip(params.LAB_HOST_IPS.get(src["host"]))
    return [e for e in logons_by_host.get(target_host, ())
            if norm_ip(e.get("source_ip")) == src_ip and e.get("source_port") == src.get("source_port")
            and abs(e["us"] - src["us"]) <= join_us]


def net_effect(abs_raw_ms: int, abs_corrected_ms: int | None) -> str | None:
    """``better`` / ``worse`` / ``same`` for |corrected| vs |raw| (ATK-06: the correction may hurt)."""
    if abs_corrected_ms is None:
        return None
    if abs_corrected_ms < abs_raw_ms:
        return "better"
    return "worse" if abs_corrected_ms > abs_raw_ms else "same"


def check_row(src: Mapping, tgt: Mapping, candidate_count: int, offsets: Offsets,
              review_us: int, kill_us: int, changes: Iterable[ClockChange] = ()) -> Row:
    """One check pair: raw and corrected delta = target - source, net effect, review and kill flags.

    The corrected delta is written only when both hosts' offsets are applied; otherwise it is empty
    and the row is ``clock_unreliable``. A wide host is corrected but still marked unreliable (CO-09).
    Owner D5: the row is also ``clock_unreliable`` when either event was logged before a counted clock
    change on its host (the host's one offset describes the clock after the change).
    """
    changes = tuple(changes)
    raw_us = tgt["us"] - src["us"]
    both = all(offsets.hosts.get(h) is not None and offsets.hosts[h].applied for h in (src["host"], tgt["host"]))
    corr_us = (corrected_us(tgt["us"], tgt["host"], offsets) - corrected_us(src["us"], src["host"], offsets)
               if both else None)
    abs_raw = abs(us_to_ms(raw_us))
    abs_corr = None if corr_us is None else abs(us_to_ms(corr_us))
    return {"source_host": src["host"], "target_host": tgt["host"],
            "destination_port": src.get("destination_port"), "source_port": src.get("source_port"),
            "event_uid_sysmon3": src["event_uid"], "event_uid_4624": tgt["event_uid"],
            "t_sysmon3_utc": src["event_utc"], "t_4624_utc": tgt["event_utc"], "method": params.CHECK_METHOD,
            "candidate_count": candidate_count, "ambiguous": candidate_count > 1,
            "time_delta_ms": us_to_ms(raw_us), "raw_delta_ms": us_to_ms(raw_us),
            "corrected_delta_ms": None if corr_us is None else us_to_ms(corr_us),
            "abs_raw_ms": abs_raw, "abs_corrected_ms": abs_corr, "net_effect": net_effect(abs_raw, abs_corr),
            "clock_unreliable": (event_unreliable(src["host"], src["us"], offsets, changes)
                                 or event_unreliable(tgt["host"], tgt["us"], offsets, changes)),
            "review": None if corr_us is None else abs(corr_us) > review_us,
            "kill": None if corr_us is None else abs(corr_us) > kill_us}


def check_pairs(events: Sequence[Mapping], offsets: Offsets, lo_us: int, hi_excl_us: int,
                join_s: float = params.CHECK_JOIN_S, review_s: float = params.CHECK_REVIEW_S,
                kill_s: float = params.CHECK_KILL_S,
                changes: Iterable[ClockChange] = ()) -> tuple[list[Row], list[str]]:
    """(check rows, uids of qualifying Sysmon 3s with no target 4624) for one trial (CO-10).

    The nearest candidate on raw time is taken (ties by event_uid); more than one candidate marks the
    row ambiguous. Rows are sorted by (source, target, port), then Sysmon 3 instant and uid.
    """
    logons: dict[str, list[Mapping]] = {}
    for e in events:
        if is_event(e, "Security", 4624) and e.get("host") in params.ENDPOINTS:
            logons.setdefault(e["host"], []).append(e)
    join_us, review_us, kill_us = s_to_us(join_s), s_to_us(review_s), s_to_us(kill_s)
    changes = tuple(changes)
    rows: list[Row] = []
    unjoined: list[str] = []
    sources = sorted((e for e in events if is_check_source(e, lo_us, hi_excl_us)),
                     key=lambda e: (e["us"], str(e["event_uid"])))
    for src in sources:
        target_host = host_of_ip(src.get("destination_ip"))
        assert target_host is not None
        cands = target_candidates(src, target_host, logons, join_us)
        if not cands:
            unjoined.append(str(src["event_uid"]))
            continue
        rows.append(check_row(src, nearest(src["us"], cands), len(cands), offsets, review_us, kill_us, changes))
    # Stable sort: within a group the (instant, uid) order of ``sources`` is kept (instants, not text).
    rows.sort(key=lambda r: (r["source_host"], r["target_host"], r["destination_port"]))
    return rows, unjoined


def check_summary(rows: Sequence[Mapping], unjoined: Sequence[str]) -> dict[str, Any]:
    """Counts for stats.json: groups (source, target, port), pairs, worst raw / corrected |delta|,
    review / kill / ambiguous counts, and the per-group net effect (ATK-06)."""
    groups = Counter((r["source_host"], r["target_host"], r["destination_port"]) for r in rows)
    corrected = [r["abs_corrected_ms"] for r in rows if r["abs_corrected_ms"] is not None]
    per_group = []
    for (s, t, port), n in sorted(groups.items()):
        g = [r for r in rows if (r["source_host"], r["target_host"], r["destination_port"]) == (s, t, port)]
        g_corr = [r["abs_corrected_ms"] for r in g if r["abs_corrected_ms"] is not None]
        per_group.append({"group": f"{s}->{t}:{port}", "pairs": n,
                          "worst_raw_abs_ms": max(r["abs_raw_ms"] for r in g),
                          "worst_corrected_abs_ms": max(g_corr) if g_corr else None,
                          "net_effect": dict(sorted(Counter(str(r["net_effect"]) for r in g).items()))})
    return {"groups": len(groups), "pairs": len(rows),
            "worst_raw_abs_ms": max((r["abs_raw_ms"] for r in rows), default=None),
            "worst_corrected_abs_ms": max(corrected, default=None),
            "review_count": sum(1 for r in rows if r["review"]),
            "kill_count": sum(1 for r in rows if r["kill"]),
            "ambiguous_count": sum(1 for r in rows if r["ambiguous"]),
            "uncorrected_count": sum(1 for r in rows if r["corrected_delta_ms"] is None),
            "unjoined_sysmon3": len(unjoined), "unjoined_sysmon3_uids": sorted(unjoined),
            "per_group": per_group}
