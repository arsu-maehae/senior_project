"""The four trigger rules R4, R5, R6, R8 and the supporting signals (spec 02_gate GT-10..GT-16; decision 041).

WHY drafts: each rule returns ``TriggerDraft`` objects that keep the actual events (trigger,
anchor, supporting) rather than formatted text, so the output step can derive every column and
every disposition from the same objects, and each row stays traceable to its event uids.
All functions are pure: they take the in-window events and the suppression map and return rows.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from . import classify
from .classify import Suppression, logon_id, norm_ip, within
from .params import GateParams
from .timeutil import seconds_to_us

Row = dict[str, Any]


@dataclass(frozen=True)
class TriggerDraft:
    """One rule firing before formatting.

    ``method``/``tier`` describe only how the row is tied to its anchor logon (decision 041).
    ``ip_event`` is the event whose ``source_ip`` the row shows: the anchor, or for a tier-D R8
    row the WinRM 91 that preceded the wsmprovhost start; None means a blank IP.
    """
    rule: str
    trigger: Mapping
    anchor: Mapping | None
    supporting: tuple[Mapping, ...]
    method: str
    tier: str
    candidate_count: int
    ip_event: Mapping | None


def _by_time(rows: Sequence[Mapping]) -> tuple[Mapping, ...]:
    """Events ordered by (instant, uid) so supporting uid lists are reproducible."""
    return tuple(sorted(rows, key=lambda r: (r["us"], r["event_uid"])))


def _surviving(events: Sequence[Mapping], suppressed: Mapping[str, Suppression], pred) -> list[Mapping]:
    """Events of one kind not removed by GT-02..05 (the rules see only what suppression kept)."""
    return [r for r in events if pred(r) and r["event_uid"] not in suppressed]


def _index(rows: Sequence[Mapping], key_fn) -> dict[Any, list[Mapping]]:
    """Group rows by a key; rows whose key contains None are left out (NULL never joins, GT-18)."""
    out: dict[Any, list[Mapping]] = {}
    for r in rows:
        k = key_fn(r)
        if k is None or (isinstance(k, tuple) and any(p is None for p in k)):
            continue
        out.setdefault(k, []).append(r)
    return out


def _max_count(supporting: Sequence[Mapping], counts: Mapping[str, int], anchored: bool) -> int:
    """candidate_count (decision 041): max over supporting events of the anchors each matched;
    with no supporting event, 1 if the row has an anchor (or is its own), else 0."""
    if supporting:
        return max(counts.get(s["event_uid"], 1) for s in supporting)
    return 1 if anchored else 0


# ---------------------------------------------------------------- R4 SMB (GT-10)

def r4_rows(remote: Sequence[Mapping], events: Sequence[Mapping],
            suppressed: Mapping[str, Suppression]) -> list[TriggerDraft]:
    """R4: remote type 3 4624 with >= 1 surviving 5140/5145 on its host, subject_logon_id = its
    target_logon_id, at or after the logon. Supporting = all such share events; method logon_id, tier A.
    candidate_count = max over its share events of the number of logons each one matched.
    """
    shares = _index(_surviving(events, suppressed, classify.is_share),
                    lambda r: (r["host"], logon_id(r.get("subject_logon_id"))))
    type3 = [r for r in remote if r.get("logon_type") == 3]
    matched: dict[str, list[Mapping]] = {}
    counts: dict[str, int] = {}
    for logon in type3:
        key = (logon["host"], logon_id(logon.get("target_logon_id")))
        hits = [s for s in shares.get(key, []) if s["us"] >= logon["us"]] if key[1] is not None else []
        matched[logon["event_uid"]] = hits
        for s in hits:
            counts[s["event_uid"]] = counts.get(s["event_uid"], 0) + 1
    out = []
    for logon in type3:
        hits = matched[logon["event_uid"]]
        if hits:
            out.append(TriggerDraft("R4_smb", logon, logon, _by_time(hits), "logon_id", "A",
                                    _max_count(hits, counts, True), logon))
    return out


# ---------------------------------------------------------------- R5 RDP (GT-11)

def rdp_pair_method(logon: Mapping, s3: Mapping, tol_us: int) -> str | None:
    """How a 4624 pairs with an inbound 3389 Sysmon 3, or None.

    Same host, same non-blank source_ip (``norm_ip`` form, decision 041), |dt| <= tol (either order, inclusive). With a
    4624 port of 0/NULL (decision 015) IP + time is enough (``ip_time``); otherwise the ports must be
    equal and non-NULL (``ip_port_time``).
    """
    if logon["host"] != s3["host"]:
        return None
    ip = norm_ip(logon.get("source_ip"))
    if ip is None or ip != norm_ip(s3.get("source_ip")) or not within(logon["us"], s3["us"], tol_us):
        return None
    port = logon.get("source_port")
    if port in (None, 0):
        return "ip_time"
    return "ip_port_time" if s3.get("source_port") is not None and s3["source_port"] == port else None


def rdp_matches(remote: Sequence[Mapping], s3s: Sequence[Mapping], tol_us: int) -> dict[str, dict[str, str]]:
    """logon uid -> {Sysmon 3 uid: method} for every remote 4624 (type 3 or 10) / inbound 3389 pair."""
    by_key = _index(s3s, lambda r: (r["host"], norm_ip(r.get("source_ip"))))
    out: dict[str, dict[str, str]] = {}
    for logon in remote:
        hits = {}
        for s3 in by_key.get((logon["host"], norm_ip(logon.get("source_ip"))), []):
            method = rdp_pair_method(logon, s3, tol_us)
            if method:
                hits[s3["event_uid"]] = method
        out[logon["event_uid"]] = hits
    return out


def r5_rows(remote: Sequence[Mapping], events: Sequence[Mapping], suppressed: Mapping[str, Suppression],
            params: GateParams) -> tuple[list[TriggerDraft], dict[str, int]]:
    """R5 rows and, per type 3 R5 logon, the reverse count (Sysmon 3s matching it) for reason_detail.

    Type 10: own anchor, method none, tier A; matching inbound 3389 Sysmon 3s are added as supporting.
    Type 3: fires only with >= 1 matching Sysmon 3; method ip_port_time / ip_time, tier B.
    candidate_count (decision 041) = max over its Sysmon 3s of the number of remote 4624s (type 3 or
    10) each Sysmon 3 matched BY THE SAME METHOD as it matched this logon (``ip_port_time`` or
    ``ip_time``); a port match and an IP-only match of one Sysmon 3 are counted apart. For a type 10
    row the method is the pairing method of each supporting Sysmon 3, not the row's ``none``.
    """
    s3s = _surviving(events, suppressed, classify.is_inbound_rdp_sysmon3)
    s3_by_uid = {r["event_uid"]: r for r in s3s}
    matches = rdp_matches([r for r in remote if r.get("logon_type") in (3, 10)], s3s,
                          seconds_to_us(params.rdp_pair_s))
    counts = rdp_counts_per_method(matches)
    rows: list[TriggerDraft] = []
    reverse: dict[str, int] = {}
    for logon in remote:
        hits = matches.get(logon["event_uid"], {})
        support = _by_time([s3_by_uid[u] for u in hits])
        count = max((counts[(u, m)] for u, m in hits.items()), default=1)
        if logon.get("logon_type") == 10:
            rows.append(TriggerDraft("R5_rdp", logon, logon, support, "none", "A", count, logon))
        elif logon.get("logon_type") == 3 and hits:
            method = "ip_time" if logon.get("source_port") in (None, 0) else "ip_port_time"
            rows.append(TriggerDraft("R5_rdp", logon, logon, support, method, "B", count, logon))
            reverse[logon["event_uid"]] = len(hits)
    return rows, reverse


def rdp_counts_per_method(matches: Mapping[str, Mapping[str, str]]) -> dict[tuple[str, str], int]:
    """(Sysmon 3 uid, method) -> number of distinct logons that Sysmon 3 matched by that method.

    WHY per method: decision 041 counts, for each supporting event, the anchors it matched "the
    same way"; a port-exact match and an IP + time match are different evidence.
    """
    counts: dict[tuple[str, str], int] = {}
    for hits in matches.values():
        for uid, method in hits.items():
            counts[(uid, method)] = counts.get((uid, method), 0) + 1
    return counts


# ---------------------------------------------------------------- R6 service (GT-12)

def _anchors(remote_by_lid: Mapping[tuple, list[Mapping]], host: str, lid: int | None, before_us: int,
             types: tuple[int, ...]) -> list[Mapping]:
    """Remote 4624s of the given types on ``host`` with logon ID ``lid``, logged at or before ``before_us``."""
    if lid is None:
        return []
    return [a for a in remote_by_lid.get((host, lid), [])
            if a.get("logon_type") in types and a["us"] <= before_us]


def _per_anchor(rule: str, trigger: Mapping, anchors: Sequence[Mapping], supporting: tuple[Mapping, ...],
                ip_event_if_none: Mapping | None = None) -> list[TriggerDraft]:
    """One row per anchor, each with candidate_count = number of anchors; none -> one tier-D row (count 0)."""
    if not anchors:
        return [TriggerDraft(rule, trigger, None, supporting, "none", "D", 0, ip_event_if_none)]
    ordered = _by_time(anchors)
    return [TriggerDraft(rule, trigger, a, supporting, "logon_id", "A", len(ordered), a) for a in ordered]


def r6_rows(remote: Sequence[Mapping], events: Sequence[Mapping], suppressed: Mapping[str, Suppression],
            service_pairs: Mapping[str, str]) -> list[TriggerDraft]:
    """R6: every surviving 4697 (with its paired 7045 as supporting) and every unpaired surviving 7045.

    Anchor of a 4697 = remote 4624 type 3 or 10 on its host whose target_logon_id = the 4697's
    subject_logon_id, logged at or before it (decision 041). Anchored -> logon_id / A, one row per
    anchor; else none / D. A 7045 with no 4697 has no anchor (tier D); linking it is T7's job.
    """
    remote_by_lid = _index(remote, lambda r: (r["host"], logon_id(r.get("target_logon_id"))))
    by_uid = {r["event_uid"]: r for r in events}
    paired_7045_of = {v: k for k, v in service_pairs.items()}
    out: list[TriggerDraft] = []
    for ev in _surviving(events, suppressed, classify.is_4697):
        partner = paired_7045_of.get(ev["event_uid"])
        support = (by_uid[partner],) if partner and partner not in suppressed else ()
        anchors = _anchors(remote_by_lid, ev["host"], logon_id(ev.get("subject_logon_id")), ev["us"], (3, 10))
        out.extend(_per_anchor("R6_service", ev, anchors, support))
    for ev in _surviving(events, suppressed, classify.is_7045):
        if ev["event_uid"] not in service_pairs:
            out.append(TriggerDraft("R6_service", ev, None, (), "none", "D", 0, None))
    return out


# ---------------------------------------------------------------- R8 WinRM (GT-13)

def r8_rows(remote: Sequence[Mapping], events: Sequence[Mapping], suppressed: Mapping[str, Suppression],
            params: GateParams, wsm_pairs: Mapping[str, Mapping] | None = None) -> list[TriggerDraft]:
    """R8: every surviving wsmprovhost start (Sysmon 1, ``image``).

    Anchor = remote type 3 4624 on its host whose target_logon_id or target_linked_logon_id = the
    Sysmon 1 session_id, logged at or before it; one row per anchor (logon_id, A). Supporting WinRM 91
    of an anchored row: same host, clientIP = the anchor's source_ip (both ``norm_ip``), |91 - anchor| <= 5 s.
    A tier-D row takes the WinRM 91 paired with the Sysmon 1 (``classify.pair_wsmprovhost_91``: the
    earliest 91 0-5 s AFTER it, one-to-one; decision 042): its clientIP becomes the row's source_ip and
    its uid is supporting. A paired 91 that GT-02..05 removed is not used (the row's IP stays blank).
    """
    tol = seconds_to_us(params.winrm_pair_s)
    if wsm_pairs is None:
        wsm_pairs = classify.pair_wsmprovhost_91(events, tol)
    index = classify.r8_anchor_index(remote)
    w91 = _surviving(events, suppressed, classify.is_winrm91)
    out: list[TriggerDraft] = []
    for ev in _surviving(events, suppressed, classify.is_wsmprovhost_start):
        anchors = classify.r8_anchors(index, ev)
        if not anchors:
            paired = wsm_pairs.get(ev["event_uid"])
            if paired is not None and paired["event_uid"] in suppressed:
                paired = None
            out.append(TriggerDraft("R8_winrm", ev, None, (paired,) if paired else (), "none", "D", 0, paired))
            continue
        ordered = _by_time(anchors)
        for a in ordered:
            ip = norm_ip(a.get("source_ip"))
            support = _by_time([w for w in w91 if w["host"] == a["host"] and ip is not None
                                and norm_ip(w.get("source_ip")) == ip and within(w["us"], a["us"], tol)])
            out.append(TriggerDraft("R8_winrm", ev, a, support, "logon_id", "A", len(ordered), a))
    return out


# ---------------------------------------------------------------- supporting signals (GT-16)

def supporting_signals(events: Sequence[Mapping], excl_map: Mapping[tuple[str, int], str],
                       suppressed: Mapping[str, Suppression], params: GateParams) -> list[tuple[str, Mapping]]:
    """(rule, event) for R1_lsass, R3_explicit (4648) and R8_parent, after GT-01 and GT-02 only.

    GT-02 drops a 4648 by subject_logon_id and a Sysmon 10/1 by session_id tied to an excluded
    logon, and any event already excluded by GT-02 in the suppression map. GT-03..05 are not
    applied here (spec GT-16), so an R8_parent child in a system session is still listed.
    """
    gt02 = ("excluded_source_ip", "excluded_source_ip_session", "paired_excluded")
    out: list[tuple[str, Mapping]] = []
    for ev in events:
        if classify.is_r1(ev, params):
            rule, lid = "R1_lsass", logon_id(ev.get("session_id"))
        elif classify.is_4648(ev):
            rule, lid = "R3_explicit", logon_id(ev.get("subject_logon_id"))
        elif classify.is_wsmprovhost_child(ev):
            rule, lid = "R8_parent", logon_id(ev.get("session_id"))
        else:
            continue
        sup = suppressed.get(ev["event_uid"])
        if sup and sup.disposition in gt02:
            continue
        if lid is not None and (ev["host"], lid) in excl_map:
            continue
        out.append((rule, ev))
    return out
