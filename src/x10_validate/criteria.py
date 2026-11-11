"""Criteria a-h of decision 029 for one trial (i and the cross-trial part of f are in ``cross``).

WHY one function per criterion: each returns ``{"status", "evidence"}`` with status PASS | WARN |
FAIL | n/a exactly as the 029 severity table says, so a tester can check each rule in isolation and
the owner can trace every status to counts, hosts, times and event_uids.
"""
from __future__ import annotations

from statistics import median
from typing import Mapping, Sequence

from .agent import Execution
from .db import iso
from .design import ScenarioDesign
from .events import Dump, guid_of, in_range, is_write
from .params import CHANNELS, CLOCK_WARN_S, CROSS_HOST_TOL_S, HOST_IP, HOSTS
from .textmatch import norm_account
from .window import Cluster


def result(status: str, **evidence) -> dict:
    """Uniform criterion result."""
    return {"status": status, "evidence": evidence}


# ----------------------------------------------------------------------------- a

def missing_files(ingest: Mapping | None, counts: Mapping[str, Mapping[str, int]]) -> tuple[list[tuple[str, str]], str]:
    """(host, channel) pairs without a file: from ingest.json when given, else from DB row counts."""
    if ingest is not None:
        miss = sorted({(m["host"], m["channel"]) for m in ingest.get("files_missing", [])})
        return miss, "ingest.json files_missing"
    miss = sorted((h, c) for h in HOSTS for c in CHANNELS if counts.get(h, {}).get(c, 0) == 0)
    return miss, "db rows (no ingest.json; an empty file cannot be told from a missing one)"


def crit_a(design: ScenarioDesign, ingest: Mapping | None, counts: Mapping[str, Mapping[str, int]]) -> dict:
    """Complete files: a whole attack-path host absent -> FAIL; off-path host or single logs -> WARN."""
    miss, basis = missing_files(ingest, counts)
    by_host: dict[str, list[str]] = {}
    for h, c in miss:
        by_host.setdefault(h, []).append(c)
    absent = sorted(h for h, cs in by_host.items() if set(CHANNELS) <= set(cs))
    path_absent = [h for h in absent if h in design.path_hosts]
    empty = sorted(f"{h}/{c}" for h in HOSTS for c in CHANNELS
                   if (h, c) not in set(miss) and counts.get(h, {}).get(c, 0) == 0)
    ev = {"basis": basis, "expected": len(HOSTS) * len(CHANNELS), "missing": [f"{h}/{c}" for h, c in miss],
          "hosts_absent": absent, "path_hosts": list(design.path_hosts),
          "present_but_no_rows_in_db": empty}
    if path_absent:
        return result("FAIL", reason=f"attack-path host(s) absent: {', '.join(path_absent)}", **ev)
    if miss:
        return result("WARN", reason="off-path host absent or single logs missing", **ev)
    return result("PASS", **ev)


# ----------------------------------------------------------------------------- b

def dump_steps(design: ScenarioDesign, dumps_w: Sequence[Dump]) -> list[dict]:
    """Designed LSASS reads found in the window (user token; S05 ep-02 also by account)."""
    out = []
    for dd in design.dumps:
        found = [d for d in dumps_w if d.host == dd.host and d.user_token and (dd.account is None or d.account == dd.account)]
        out.append({"step_id": dd.step_id, "host": dd.host, "required": dd.count, "found": len(found),
                    "present": len(found) >= dd.count, "accounts": [d.account for d in found],
                    "times_utc": [iso(d.ts) for d in found], "event_uids": [u for d in found for u in d.event_uids][:20]})
    return out


def crit_b(hops: Sequence[Mapping], dsteps: Sequence[Mapping], have_window: bool) -> dict:
    """Design chain: any designed step missing in the window -> FAIL."""
    if not have_window:
        return result("FAIL", reason="no design anchor in the DB, so no trial window and no step")
    missing = [f"{d['step_id']} ({d['found']}/{d['required']})" for d in dsteps if not d["present"]]
    missing += [f"{h['hop_id']}:{s}" for h in hops for s in h["missing_steps"]]
    found = [d["step_id"] for d in dsteps if d["present"]]
    found += [f"{h['hop_id']}:{s}" for h in hops for s in h["steps"] if h["steps"][s]["present"]]
    ev = {"missing": missing, "found": found,
          "hops": {h["hop_id"]: {"binding": h["binding"], "time_delta_ms": h["time_delta_ms"],
                                 "command_utc": h["execution"]["first_utc"] if h["execution"] else None} for h in hops}}
    return result("FAIL" if missing else "PASS", **ev)


# ----------------------------------------------------------------------------- c

def target_side_accounts(rows_w: Sequence[Mapping], source: str, target: str) -> dict[str, list[str]]:
    """Accounts seen on the target side of source -> target in the window, by event kind (029, c)."""
    ip = HOST_IP[source]
    sec = [r for r in rows_w if r["host"] == target and r["channel"] == "Security"]
    from_src = {r["target_logon_id"] for r in sec if r["event_id"] == 4624 and r["source_ip"] == ip and r["target_logon_id"]}
    out: dict[str, set[str]] = {"4624": set(), "5145": set(), "4697": set(), "4697_other_source": set()}
    for r in sec:
        if r["event_id"] == 4624 and r["logon_type"] in (3, 10) and r["source_ip"] == ip:
            out["4624"].add(norm_account(r["account_name"]))
        elif r["event_id"] == 5145 and r["source_ip"] == ip:
            out["5145"].add(norm_account(r["account_name"]))
        elif r["event_id"] == 4697:
            key = "4697" if r["subject_logon_id"] in from_src else "4697_other_source"
            out[key].add(norm_account(r["account_name"]))
    return {k: sorted(v) for k, v in out.items()}


def crit_c(design: ScenarioDesign, hops: Sequence[Mapping], rows_w: Sequence[Mapping]) -> dict:
    """Intended account must appear on the target side; S06 gives WARN instead of FAIL."""
    per_hop, bad = [], []
    for h in hops:
        seen = target_side_accounts(rows_w, h["source"], h["target"])
        rdp = h.get("rdp")
        # RDP (035): only the counted logons of the hop count; the 4624s of types 3/10 are still reported
        allacc = set(h["hop_accounts"]) if rdp else set(seen["4624"]) | set(seen["5145"]) | set(seen["4697"])
        ok = h["intended_account"] in allacc
        entry = {"hop_id": h["hop_id"], "intended": h["intended_account"], "observed_in_window": seen,
                 "observed_tied_to_hop": h["hop_accounts"], "intended_seen": ok}
        if rdp:
            entry["observed_logon_types"] = rdp["logon_types_observed"]
            entry["observed_accounts_all_types"] = rdp["accounts_observed"]
        if h["hop_id"] == "s07-Y":
            entry["note"] = "design svc_sql; t00 logged svc_backup for Y (decision 027)"
        per_hop.append(entry)
        if not ok:
            bad.append(h["hop_id"])
    status = "PASS" if not bad else design.c_severity
    return result(status, hops=per_hop, intended_missing=bad,
                  severity_note="S06: WARN instead of FAIL (owner, decision 029)" if design.scenario == "s06" else None)


# ----------------------------------------------------------------------------- d

def crit_d(design: ScenarioDesign, hops: Sequence[Mapping], rows_w: Sequence[Mapping], dumps_w: Sequence[Dump],
           guid_session: Mapping[str, int | None]) -> dict:
    """Benign track: S04 Track A must write a binary to ADMIN$ and read no credentials; S06 has no dump."""
    if design.benign == "s06_no_dump":
        ev = {"dumps_in_window": [{"host": d.host, "utc": iso(d.ts), "account": d.account,
                                   "event_uids": d.event_uids[:4]} for d in dumps_w]}
        return result("FAIL" if dumps_w else "PASS", rule="any rundll32 -> lsass Sysmon 10 in the window -> FAIL", **ev)
    if design.benign != "s04_track_a":
        return result("n/a", reason="no benign track in this scenario's design")
    track_a = next(h for h in hops if h["hop_id"] == "s04-A")
    sessions = set(track_a["execution"]["session_ids"]) if track_a["execution"] else set()
    writes = [r for r in rows_w if r["host"] == "ep-02" and r["channel"] == "Security" and r["event_id"] == 5145
              and norm_account(r["account_name"]) == "admin_it" and (r["share_name"] or "").upper().endswith("ADMIN$")
              and (r["relative_target_name"] or "").lower().endswith((".exe", ".dll")) and is_write(r) is not False]
    cred = [d for d in dumps_w if d.account == "admin_it"
            or any(guid_session.get(g) in sessions for g in d.process_guids if sessions)]
    ev = {"track_a_admin_binary_writes": len(writes), "write_event_uids": [r["event_uid"] for r in writes][:10],
          "write_source_ips": sorted({r["source_ip"] or "-" for r in writes}),
          "track_a_sessions": sorted(sessions),
          "credential_access": [{"host": d.host, "utc": iso(d.ts), "account": d.account, "event_uids": d.event_uids[:4]}
                                for d in cred]}
    reasons = []
    if not writes:
        reasons.append("no ADMIN$ binary write by admin_it on ep-02")
    if cred:
        reasons.append("credential access by admin_it or in the Track A session")
    return result("FAIL" if reasons else "PASS", reason="; ".join(reasons) or None, **ev)


# ----------------------------------------------------------------------------- e

def crit_e(design: ScenarioDesign, beacons: Sequence[Mapping], run_lo: float | None, run_hi: float | None) -> dict:
    """Agent evidence: each Caldera source host needs a splunkd -> 192.168.50.50:8888 Sysmon 3 in the run."""
    if not design.caldera_hosts:
        return result("n/a", reason="manual lane, no agent in the S01 design (decision 035)")
    if run_lo is None:
        return result("FAIL", reason="no trial window")
    per_host, missing = {}, []
    for host in design.caldera_hosts:
        inrun = [r for r in beacons if r["host"] == host and in_range(r["ts"], run_lo, run_hi)]
        per_host[host] = {"in_run": len(inrun), "any_time": sum(1 for r in beacons if r["host"] == host),
                          "first_utc": iso(inrun[0]["ts"]) if inrun else None,
                          "last_utc": iso(inrun[-1]["ts"]) if inrun else None,
                          "accounts": sorted({norm_account(r["account_name"]) for r in inrun}),
                          "event_uids": [r["event_uid"] for r in inrun][:5]}
        if not inrun:
            missing.append(host)
    ev = {"run_interval": [iso(run_lo), iso(run_hi)], "hosts": per_host,
          "not_required": "S04 Track A (manual)" if design.benign == "s04_track_a" else None}
    return result("FAIL" if missing else "PASS", reason=f"no agent beacon on {missing}" if missing else None, **ev)


# ----------------------------------------------------------------------------- f (intra-DB part)

def crit_f_local(older: Sequence[Cluster], window: tuple[float, float] | None) -> dict:
    """Older trials' anchors in the DB -> WARN; the overlap FAIL is added across trials (``cross``)."""
    if window is None:
        return result("n/a", reason="no trial window")
    ev = {"window": [iso(window[0]), iso(window[1])], "older_clusters": [c.summary() for c in older],
          "overlaps": []}
    if older:
        return result("WARN", reason=f"{len(older)} older anchor cluster(s) before the window", **ev)
    return result("PASS", **ev)


# ----------------------------------------------------------------------------- g

def mutual_nearest(a_rows: Sequence[Mapping], b_rows: Sequence[Mapping]) -> list[tuple[Mapping, Mapping]]:
    """Pairs (a, b) with the same LogonGuid where each is the other's nearest in time."""
    by_guid_b: dict[str, list[Mapping]] = {}
    for b in b_rows:
        by_guid_b.setdefault(guid_of(b), []).append(b)
    by_guid_a: dict[str, list[Mapping]] = {}
    for a in a_rows:
        by_guid_a.setdefault(guid_of(a), []).append(a)
    out = []
    for g, alist in by_guid_a.items():
        blist = by_guid_b.get(g, [])
        if not blist:
            continue
        for a in alist:
            b = min(blist, key=lambda x: abs(x["ts"] - a["ts"]))
            back = min(alist, key=lambda x: abs(x["ts"] - b["ts"]))
            if back is a:
                out.append((a, b))
    return out


def host_offsets(e4624: Sequence[Mapping], d4769: Sequence[Mapping]) -> dict[str, dict]:
    """Median (host - dc01) offset in seconds per endpoint, from mutual-nearest LogonGuid pairs."""
    out: dict[str, dict] = {}
    for host in sorted({r["host"] for r in e4624}):
        pairs = mutual_nearest([r for r in e4624 if r["host"] == host], d4769)
        if pairs:
            offs = [a["ts"] - b["ts"] for a, b in pairs]
            out[host] = {"median_s": round(median(offs), 3), "pairs": len(pairs),
                         "min_s": round(min(offs), 3), "max_s": round(max(offs), 3),
                         "example_pair_uids": [[a["event_uid"], b["event_uid"]] for a, b in pairs[:2]]}
    return out


def lower_bounds(hops: Sequence[Mapping]) -> list[dict]:
    """Target clock behind source clock by at least (command - 4624) when the 4624 is logged first."""
    out = []
    for h in hops:
        if h["_exec_ts"] is None or h["_first_logon_ts"] is None:
            continue
        lb = h["_exec_ts"] - h["_first_logon_ts"]
        if lb > 0:
            out.append({"hop_id": h["hop_id"], "pair": f"{h['source']}->{h['target']}", "lower_bound_s": round(lb, 3)})
    return out


def crit_g(e4624: Sequence[Mapping], d4769: Sequence[Mapping], hops: Sequence[Mapping], dc_security: bool) -> dict:
    """Clock offset: any host-pair offset > 5 s -> WARN; no dc01 Security -> n/a (never PASS)."""
    lbs = lower_bounds(hops)
    big_lb = [x for x in lbs if x["lower_bound_s"] > CLOCK_WARN_S]
    if not dc_security:
        return result("WARN" if big_lb else "n/a", reason="no dc01 Security log: offsets vs dc01 not measurable",
                      lower_bounds=lbs, lower_bounds_over_5s=big_lb)
    offs = host_offsets(e4624, d4769)
    meds = {"dc01": 0.0, **{h: v["median_s"] for h, v in offs.items()}}
    pairs = {}
    names = sorted(meds)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            pairs[f"{a}|{b}"] = round(meds[a] - meds[b], 3)
    over = {k: v for k, v in pairs.items() if abs(v) > CLOCK_WARN_S}
    ev = {"host_offsets_vs_dc01": offs, "host_pair_offsets_s": pairs, "pairs_over_5s": over,
          "hosts_unmeasured": [h for h in HOST_IP if h not in offs], "lower_bounds": lbs,
          "lower_bounds_over_5s": big_lb, "tolerance_s": CROSS_HOST_TOL_S}
    if not offs:
        return result("WARN" if big_lb else "n/a", reason="dc01 Security present but no LogonGuid pair in the window +- 30 min", **ev)
    return result("WARN" if (over or big_lb) else "PASS", **ev)


# ----------------------------------------------------------------------------- h

def _by_account(items: Sequence, key) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        out[key(it)] = out.get(key(it), 0) + 1
    return out


def _exec_brief(e: Execution) -> dict:
    return {"host": e.host, "target": e.target, "lane": e.lane, "utc": iso(e.ts_first), "account": e.account,
            "protocols": sorted(e.protocols), "event_uids": e.event_uids[:4]}


def _rdp_duplicates(design: ScenarioDesign, hops: Sequence[Mapping]) -> tuple[list[dict], list[dict]]:
    """RDP sessions beyond the designed hops of one (source, target): same account -> FAIL, else WARN (N19)."""
    fails, warns = [], []
    pairs = {(h["source"], h["target"]) for h in hops if h.get("rdp")}
    for src, tgt in sorted(pairs):
        k = sum(1 for h in design.hops if h.protocol == "RDP" and (h.source, h.target) == (src, tgt))
        sessions = [s for h in hops if h.get("rdp") and (h["source"], h["target"]) == (src, tgt) for s in h["rdp"]["sessions"]]
        if len(sessions) > k:
            counts = _by_account(sessions, lambda s: s["account"])
            same = {a: n for a, n in counts.items() if n > k}
            item = {"step": f"manual RDP {src}->{tgt}", "expected": k, "found_by_account": counts, "sessions": sessions}
            (fails if same else warns).append({**item, "why": "same user, same source, same target" if same else "another user"})
    return fails, warns


def crit_h(design: ScenarioDesign, groups: Mapping[tuple, Sequence[Execution]], execs_w: Sequence[Execution],
           dumps_w: Sequence[Dump], hops: Sequence[Mapping] = ()) -> dict:
    """Single run: indistinguishable duplicate of a design step -> FAIL; identifiable duplicate -> WARN."""
    fails, warns = _rdp_duplicates(design, hops)
    for dd in design.dumps:
        user = [d for d in dumps_w if d.host == dd.host and d.user_token]
        if len(user) > dd.count:
            counts = _by_account(user, lambda d: d.account)
            same = {a: n for a, n in counts.items() if n > dd.count}
            item = {"step": dd.step_id, "expected": dd.count, "found_by_account": counts,
                    "times_utc": [iso(d.ts) for d in user]}
            (fails if same else warns).append({**item, "why": "same user, same host" if same else "another user"})
    if design.dumps:
        dump_hosts = {dd.host for dd in design.dumps}
        for d in dumps_w:
            if not d.user_token:
                warns.append({"step": "dump", "why": "non-user token", "host": d.host, "utc": iso(d.ts),
                              "account": d.account, "event_uids": d.event_uids[:4]})
            elif d.host not in dump_hosts:
                warns.append({"step": "dump", "why": "other host", "host": d.host, "utc": iso(d.ts), "account": d.account})
    seen: set[int] = set()
    for (src, tgt, proto, lane), cands in groups.items():
        k = sum(1 for h in design.hops if (h.source, h.target, h.protocol, h.lane) == (src, tgt, proto, lane))
        step = f"{lane} {proto} {src}->{tgt}"
        if len(cands) > k:
            counts = _by_account(cands, lambda e: e.account)
            same = {a: n for a, n in counts.items() if n > k}
            item = {"step": step, "expected": k, "found_by_account": counts, "executions": [_exec_brief(e) for e in cands]}
            (fails if same else warns).append({**item, "why": "same user, same source, same target" if same else "another user"})
        for e in execs_w:
            if id(e) in seen or e.target != tgt or proto not in e.protocols:
                continue
            why = ("self-target" if e.self_target else "other host" if e.host != src
                   else "non-user token" if not e.user_token else None)
            if why and (e.lane == "agent" or lane == "manual"):
                seen.add(id(e))
                warns.append({"step": step, "why": why, **_exec_brief(e)})
    status = "FAIL" if fails else "WARN" if warns else "PASS"
    return result(status, duplicates_fail=fails, duplicates_identifiable=warns)
