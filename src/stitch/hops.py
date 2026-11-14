"""Remote logons (ST-03, ST-05), hop groups (ST-20, ST-21, ST-24), protocol (ST-22), seeds (ST-23) and
follow-up logons (ST-26) of one trial (spec 03_stitch; decision 048 items 7, 8, 9).

WHY pure: the inputs are the gate rows (``inputs.read_gate_rows``), the scan (``scan.ScanResult``) and the
T7.2 ``SessionIndex``; nothing here opens a file, so a test can build any grouping case from a handful of
dicts. No command text is read or imported here: a hop is built from 4624 facts and gate rows only.

Grouping compares the target host's own logged times (``us_raw``; 048 item 7, spec 10.2): every member of
a group is logged on one host, so the clock correction cannot change a gap. Hop ids follow the corrected
first-member time, so ids across target hosts are in cross-host order (ST-02). The account is never a key
(ST-21) and the source port is never a key (ST-24); a port is used only by the follow-up rule (ST-26).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Sequence

from gate.classify import norm_ip
from gate.timeutil import delta_ms, fmt_us, seconds_to_us

from .errors import StitchError
from .params import StitchParams
from .scan import ScanResult, is_logon
from .sessions import SessionIndex, SessionKey, hex_id, logon_id_int

if TYPE_CHECKING:  # WHY type-only: importing ``inputs`` at run time would pull file-reading code into this pure module
    from .inputs import GateRows

__all__ = ["RemoteLogon", "LogonGroup", "FollowupGroup", "Hop", "HopSet", "remote_logons", "group_hops",
           "attach_followups", "protocol_of", "build_hops", "hop_id_of", "PROTOCOL_ORDER",
           "SPLIT_PROBE_S", "MERGE_PROBE_S", "FOLLOWUP_KIND", "FOLLOWUP_METHOD", "FOLLOWUP_TIER"]

Row = Mapping[str, Any]

# ST-22: first rule family that applies wins. Gate rule names as in ``gate.params.RULES``.
PROTOCOL_ORDER: tuple[tuple[str, str], ...] = (("R8_winrm", "winrm"), ("R5_rdp", "rdp"),
                                               ("R6_service", "smb_service"), ("R4_smb", "smb"))
PROTOCOL_NONE = "none"

# Spec 3 flag names fix these two probes ("a 1 s gap would cut", "a 3 s gap would join"); they are flag
# definitions, not tunable parameters (048 item 7).
SPLIT_PROBE_S = 1.0
MERGE_PROBE_S = 3.0

# ST-26 with decision 048 item 9 (owner accepted): a follow-up logon is a ``followup_logon`` artefact linked by
# port reuse, tier C (one port can carry several hops, ST-24, so the tie is weaker than a file-name tie).
FOLLOWUP_KIND = "followup_logon"
FOLLOWUP_METHOD = "port_reuse"
FOLLOWUP_TIER = "C"


# ---------------------------------------------------------------- remote logons (ST-03, ST-05)

@dataclass
class RemoteLogon:
    """One remote logon: a gate anchor or unmatched row, joined by uid to its in-window 4624 of the scan.

    ``uid`` is the scan row's representative uid; ``event_uids`` every uid of that row (ST-05), and
    ``gate_uids`` the gate uids that mapped to it (more than one only for a near-duplicate pair both named by
    the gate). ``source_ip`` and ``ip_kind`` are the gate's (normalised by ``gate.classify.norm_ip``), so
    the stitcher groups on exactly the IP the gate classified. ``source_port``, ``account``, the logon ID,
    the package and the GUID come from the 4624 itself. ``rules`` / ``trigger_ids`` come from the trigger rows
    anchored on this logon (empty for an unmatched logon). ``clock_unreliable`` is the scan's ST-02 event flag,
    ``gate_clock_unreliable`` the gate's value (kept apart, ST-02).
    """
    uid: str
    event_uids: list[str]
    gate_uids: list[str]
    host: str
    us_raw: int
    us: int
    source_ip: str | None
    ip_kind: str
    source_port: int | None
    account: str | None
    account_key: str | None
    logon_id: int | None
    logon_id_hex: str
    authentication_package: str | None
    logon_guid: str | None
    machine_account: int
    rules: list[str]
    trigger_ids: list[str]
    gate_clock_unreliable: int
    clock_unreliable: int
    session_key: SessionKey | None

    @property
    def is_trigger(self) -> bool:
        """True when a gate trigger row is anchored on this logon (ST-23 seed condition)."""
        return bool(self.trigger_ids)

    @property
    def near_duplicate(self) -> bool:
        """True when the 4624 stands for more than one uid (ST-05)."""
        return len(self.event_uids) > 1


def _int_or_none(value: Any) -> int | None:
    """A port or flag as int; None for NULL / empty text (a NULL never matches, decision 005)."""
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _flag(value: Any) -> int:
    """A gate 0/1 text column (``clock_unreliable``, ``machine_account``) as 0 or 1; blank or ``false`` is 0."""
    text = str(value if value is not None else "").strip().lower()
    if text in ("", "0", "false"):
        return 0
    if text in ("1", "true"):
        return 1
    raise StitchError(f"gate flag value {value!r} is not 0/1")


def logon_index(scan: ScanResult) -> dict[str, Row]:
    """Every uid of every in-window 4624 row of the scan -> that (representative) row.

    WHY every uid: a gate row may name a non-representative copy of a near-duplicate pair; it must find the
    one row that stands for both (ST-05). Pre-window 4624s (``scan.lookback``) are not indexed: a hop member
    is in the window (ST-01).
    """
    out: dict[str, Row] = {}
    for row in scan.in_window:
        if is_logon(row):
            for u in row.get("event_uids") or [row["event_uid"]]:
                out[str(u)] = row
    return out


def _gate_logon_uid(gate_row: Row, unmatched: bool) -> str:
    """The 4624 a gate row stands for: ``anchor_logon_uid``; for an unmatched row, ``trigger_event_uid`` when
    the anchor is blank (ST-03; both are the 4624 in an unmatched row)."""
    uid = str(gate_row.get("anchor_logon_uid") or "").strip()
    if not uid and unmatched:
        uid = str(gate_row.get("trigger_event_uid") or "").strip()
    return uid


def _gate_rows_by_logon(gate: GateRows) -> list[tuple[str, Row, bool]]:
    """(4624 uid, gate row, is_trigger) for every remote-logon row (ST-03): triggers with a non-empty anchor,
    plus every unmatched row. A trigger row with no anchor (an R6 / R8 with no logon, tier D) starts nothing.

    Raises StitchError for an unmatched row naming no uid at all (it could not be placed in a hop).
    """
    out: list[tuple[str, Row, bool]] = []
    for r in gate.triggers:
        uid = _gate_logon_uid(r, unmatched=False)
        if uid:
            out.append((uid, r, True))
    for r in gate.unmatched:
        uid = _gate_logon_uid(r, unmatched=True)
        if not uid:
            raise StitchError(f"gate unmatched row {r.get('trigger_id')!r} names no logon uid")
        out.append((uid, r, False))
    return out


def _check_agrees(gate_row: Row, scan_row: Row) -> None:
    """The gate row and the scan's 4624 must describe the same logon (host, logon ID): ST-01, "the gate and
    the stitcher must agree". A mismatch means a stale gate folder or a different DB; never guess."""
    if str(gate_row.get("host") or "") != str(scan_row.get("host") or ""):
        raise StitchError(f"gate row {gate_row.get('trigger_id')!r}: host {gate_row.get('host')!r} differs from "
                          f"the 4624's host {scan_row.get('host')!r}")
    g_lid = logon_id_int(gate_row.get("target_logon_id"))
    s_lid = logon_id_int(scan_row.get("target_logon_id"))
    if g_lid != s_lid:
        raise StitchError(f"gate row {gate_row.get('trigger_id')!r}: logon ID differs from the 4624's")


def _make_logon(scan_row: Row, rows: list[tuple[str, Row, bool]], sessions: SessionIndex) -> RemoteLogon:
    """One ``RemoteLogon`` from its scan row and every gate row that maps to it (one, or more for ST-05).

    WHY the first gate row (by uid, then trigger before unmatched) for the IP, kind and machine flag: all
    gate rows of one logon describe the same 4624, so they agree; the rule and trigger lists are unions and
    ``gate_clock_unreliable`` the maximum, so nothing a gate row says is lost.
    """
    rows = sorted(rows, key=lambda t: (t[0], not t[2], str(t[1].get("trigger_id") or "")))
    first = rows[0][1]
    host = str(scan_row["host"])
    lid = logon_id_int(scan_row.get("target_logon_id"))
    session = sessions.session_at(host, lid, scan_row["us_raw"]) if lid is not None else None
    account = scan_row.get("account_name")
    trig = [r for _, r, is_trig in rows if is_trig]
    return RemoteLogon(
        uid=str(scan_row["event_uid"]),
        event_uids=[str(u) for u in (scan_row.get("event_uids") or [scan_row["event_uid"]])],
        gate_uids=sorted({u for u, _, _ in rows}),
        host=host,
        us_raw=scan_row["us_raw"],
        us=scan_row["us"],
        source_ip=norm_ip(first.get("source_ip")),
        ip_kind=str(first.get("ip_kind") or ""),
        source_port=_int_or_none(scan_row.get("source_port")),
        account=None if account is None else str(account),
        account_key=None if account is None else str(account).lower(),
        logon_id=lid,
        logon_id_hex="" if lid is None else hex_id(lid),
        authentication_package=scan_row.get("authentication_package"),
        logon_guid=scan_row.get("logon_guid"),
        machine_account=_flag(first.get("machine_account")),
        rules=sorted({str(r.get("rule")) for r in trig if r.get("rule")}),
        trigger_ids=sorted({str(r.get("trigger_id")) for r in trig if r.get("trigger_id")}),
        gate_clock_unreliable=max(_flag(r.get("clock_unreliable")) for _, r, _ in rows),
        clock_unreliable=int(scan_row.get("clock_unreliable") or 0),
        session_key=None if session is None else session.key,
    )


def remote_logons(gate: GateRows, scan: ScanResult, sessions: SessionIndex) -> list[RemoteLogon]:
    """ST-03 / ST-05: every remote logon of the gate files, once, joined to its in-window 4624.

    A gate uid that is no in-window 4624 of the scan raises StitchError (ST-01: the gate and the stitcher
    must agree; T7.2 A4 found every one maps). Gate uids that are copies of one collapsed near-duplicate
    become one logon carrying all uids (ST-05). Sorted by (host, us_raw, uid).
    """
    index = logon_index(scan)
    by_rep: dict[str, tuple[Row, list[tuple[str, Row, bool]]]] = {}
    for uid, grow, is_trig in _gate_rows_by_logon(gate):
        srow = index.get(uid)
        if srow is None:
            raise StitchError(f"gate logon uid {uid} ({grow.get('trigger_id')!r}) is not an in-window 4624 of "
                              f"the scan (ST-01: gate and stitcher must agree)")
        _check_agrees(grow, srow)
        by_rep.setdefault(str(srow["event_uid"]), (srow, []))[1].append((uid, grow, is_trig))
    logons = [_make_logon(srow, rows, sessions) for srow, rows in by_rep.values()]
    logons.sort(key=lambda lg: (lg.host, lg.us_raw, lg.uid))
    return logons


# ---------------------------------------------------------------- grouping (ST-20, ST-21, ST-24)

@dataclass
class LogonGroup:
    """Logons of one (target host, normalised source IP) whose consecutive gaps are <= ``GROUP_GAP_S``
    (ST-20), in member order (us_raw, uid). ``source_ip`` None = a blank-IP logon, always alone."""
    target_host: str
    source_ip: str | None
    members: list[RemoteLogon]

    @property
    def is_seed(self) -> bool:
        """ST-23: at least one gate trigger row among the members."""
        return any(m.is_trigger for m in self.members)

    @property
    def first(self) -> RemoteLogon:
        """First member (member order)."""
        return self.members[0]

    @property
    def last(self) -> RemoteLogon:
        """Last member (member order)."""
        return self.members[-1]


def _member_order(lg: RemoteLogon) -> tuple[int, str]:
    """Member order: the target host's logged time, then uid (048 item 7; deterministic ties)."""
    return lg.us_raw, lg.uid


def _bucket_key(lg: RemoteLogon) -> tuple[str, str]:
    """(target host, normalised source IP). Only called for a non-blank IP: a NULL never joins (005)."""
    assert lg.source_ip is not None
    return lg.host, lg.source_ip


def _split_bucket(logons: list[RemoteLogon], gap_us: int) -> list[list[RemoteLogon]]:
    """Cut one time-ordered bucket where the gap to the PREVIOUS logon exceeds ``gap_us`` (equal joins).

    WHY consecutive gaps and not a fixed window: a hop's logons arrive as a burst (IN-01); the rule needs no
    anchor, and the groups at a larger gap are unions of the groups at a smaller gap (STT-02).
    """
    out: list[list[RemoteLogon]] = []
    for lg in logons:
        if out and lg.us_raw - out[-1][-1].us_raw <= gap_us:
            out[-1].append(lg)
        else:
            out.append([lg])
    return out


def group_hops(logons: Iterable[RemoteLogon], params: StitchParams = StitchParams()) -> list[LogonGroup]:
    """ST-20 / ST-21 / ST-24: groups of logons by (target host, normalised source IP), consecutive gaps <=
    ``group_gap_s`` on the target's logged clock. A blank-IP logon is a group of its own. Neither the account
    nor the port is a key. Returned in (target host, source IP, first us_raw, first uid) order, blank-IP
    groups after the others of their host."""
    gap_us = seconds_to_us(params.group_gap_s)
    buckets: dict[tuple[str, str], list[RemoteLogon]] = {}
    groups: list[LogonGroup] = []
    for lg in logons:
        if lg.source_ip is None:
            groups.append(LogonGroup(lg.host, None, [lg]))
        else:
            buckets.setdefault(_bucket_key(lg), []).append(lg)
    for (host, ip), members in buckets.items():
        for part in _split_bucket(sorted(members, key=_member_order), gap_us):
            groups.append(LogonGroup(host, ip, part))
    groups.sort(key=_group_order)
    return groups


def _group_order(g: LogonGroup) -> tuple[str, int, str, int, str]:
    """Deterministic group order: host, blank IP last, IP, first member time and uid."""
    return g.target_host, int(g.source_ip is None), g.source_ip or "", g.first.us_raw, g.first.uid


# ---------------------------------------------------------------- follow-ups (ST-26)

def _ports(g: LogonGroup) -> set[int]:
    """Member ports of a group, NULL and 0 left out: neither names a connection (005; ST-41 "port > 0")."""
    return {m.source_port for m in g.members if m.source_port}


def _is_followup(g: LogonGroup, hop: LogonGroup | None, max_us: int) -> bool:
    """ST-26 (048 item 8): ``g`` (no trigger row) follows ``hop``, the nearest preceding hop of the same
    target and IP, when (i) ``hop`` is a seed, (ii) every member port of ``g`` is non-null and among the
    hop's member ports, and (iii) ``g`` starts at most ``max_us`` after the hop's last member (inclusive)."""
    if hop is None or g.is_seed or not hop.is_seed:
        return False
    hop_ports = _ports(hop)
    if any(not m.source_port or m.source_port not in hop_ports for m in g.members):
        return False
    return g.first.us_raw - hop.last.us_raw <= max_us


def attach_followups(groups: Sequence[LogonGroup], params: StitchParams = StitchParams()
                     ) -> tuple[list[LogonGroup], list[tuple[LogonGroup, LogonGroup]]]:
    """ST-26: split groups into hops and follow-up groups. Returns (hop groups, [(follow-up group, its hop)]).

    Per (target, IP), in time order, each group is compared with the nearest preceding group that became a
    hop; a follow-up group never becomes the "hop before" (048 item 8). Blank-IP groups are always hops (a
    NULL IP never matches). Without condition (i) the port rule would also take machine-account dc01 groups
    that follow other untriggered groups (spec 10.7).
    """
    max_us = seconds_to_us(params.followup_max_s)
    hops: list[LogonGroup] = []
    follow: list[tuple[LogonGroup, LogonGroup]] = []
    last_hop: dict[tuple[str, str], LogonGroup] = {}
    for g in sorted(groups, key=_group_order):
        if g.source_ip is None:
            hops.append(g)
            continue
        key = (g.target_host, g.source_ip)
        prev = last_hop.get(key)
        if _is_followup(g, prev, max_us):
            assert prev is not None
            follow.append((g, prev))
        else:
            hops.append(g)
            last_hop[key] = g
    return hops, follow


# ---------------------------------------------------------------- hops

def protocol_of(rules: Iterable[str]) -> str:
    """ST-22: the first of R8 -> winrm, R5 -> rdp, R6 -> smb_service, R4 -> smb present in ``rules``, else none."""
    have = set(rules)
    for rule, proto in PROTOCOL_ORDER:
        if rule in have:
            return proto
    return PROTOCOL_NONE


def hop_id_of(trial_id: str, n: int) -> str:
    """``<trial_id>-h<NNNN>``, 1-based, four digits (spec 3)."""
    return f"{trial_id}-h{n:04d}"


@dataclass
class FollowupGroup:
    """An untriggered group attached to a hop by ST-26: ``followup_logon`` artefacts, ``port_reuse``, tier C
    (048 item 9). ``time_delta_ms`` = its first logon minus the hop's last member (target clock);
    ``candidate_count`` = 1 because only the nearest preceding hop is ever compared; ``ports`` = the shared
    member ports that tie it."""
    hop_id: str
    logons: list[RemoteLogon]
    time_delta_ms: int
    ports: list[int]
    candidate_count: int = 1
    kind: str = FOLLOWUP_KIND
    method: str = FOLLOWUP_METHOD
    confidence_tier: str = FOLLOWUP_TIER


@dataclass
class Hop:
    """One hop (spec 3 ``hops.csv``, the columns T7.3 can know). Members are in member order (us_raw, uid).

    Gaps are milliseconds on the target's logged clock. ``inside_gap_max_ms`` is None for a one-member hop;
    ``prev_gap_ms`` / ``next_gap_ms`` are None when no hop of the same target and IP precedes / follows
    (always for a blank IP). ``source_host`` (task 4) and ``service_install_count`` (task 3) are not here.
    """
    hop_id: str
    target_host: str
    source_ip: str | None
    ip_kind: str
    members: list[RemoteLogon]
    protocol: str
    rules: list[str]
    trigger_ids: list[str]
    authentication_packages: list[str]
    mixed_account: int
    inside_gap_max_ms: int | None = None
    prev_gap_ms: int | None = None
    next_gap_ms: int | None = None
    gap_near_threshold: int = 0
    splits_at_1s: int = 0
    merges_at_3s: int = 0
    shares_port_with_hops: list[str] = field(default_factory=list)
    followups: list[RemoteLogon] = field(default_factory=list)
    followup_group_count: int = 0
    clock_unreliable: int = 0
    gate_clock_unreliable: int = 0
    machine_account_only: int = 0
    # µs gaps kept for the flags, so the band test is exact and not on rounded milliseconds.
    inside_gaps_us: list[int] = field(default_factory=list)
    prev_gap_us: int | None = None
    next_gap_us: int | None = None

    @property
    def is_seed(self) -> int:
        """ST-23: 1 if at least one gate trigger row among the members."""
        return int(bool(self.trigger_ids))

    @property
    def member_count(self) -> int:
        """Number of member logons (spec 3)."""
        return len(self.members)

    @property
    def first_us_raw(self) -> int:
        """First member's logged time on the target."""
        return self.members[0].us_raw

    @property
    def first_us(self) -> int:
        """First member's corrected time (ST-02)."""
        return self.members[0].us

    @property
    def last_us(self) -> int:
        """Last member's corrected time (ST-02)."""
        return self.members[-1].us

    @property
    def last_us_raw(self) -> int:
        """Last member's logged time on the target (ST-26 condition iii)."""
        return self.members[-1].us_raw

    @property
    def first_utc(self) -> str:
        """``first_utc`` text (spec 3)."""
        return fmt_us(self.first_us_raw)

    @property
    def first_utc_corrected(self) -> str:
        """``first_utc_corrected`` text (spec 3)."""
        return fmt_us(self.first_us)

    @property
    def last_utc_corrected(self) -> str:
        """``last_utc_corrected`` text (spec 3)."""
        return fmt_us(self.last_us)

    @property
    def member_uids(self) -> list[str]:
        """Every uid of every member, member order (ST-05 copies included)."""
        return [u for m in self.members for u in m.event_uids]


def _mixed(members: Sequence[RemoteLogon]) -> int:
    """ST-21: 1 when the members' lower-cased accounts differ (a NULL account counts as its own value)."""
    return int(len({m.account_key for m in members}) > 1)


def _inside_gaps(members: Sequence[RemoteLogon]) -> list[int]:
    """Gaps between consecutive members, µs, target clock."""
    return [b.us_raw - a.us_raw for a, b in zip(members, members[1:])]


def _new_hop(g: LogonGroup) -> Hop:
    """A ``Hop`` with its member-only fields; id, neighbour gaps, flags, ports and follow-ups come later."""
    rules = sorted({r for m in g.members for r in m.rules})
    gaps = _inside_gaps(g.members)
    return Hop(
        hop_id="", target_host=g.target_host, source_ip=g.source_ip, ip_kind=g.first.ip_kind,
        members=list(g.members), protocol=protocol_of(rules), rules=rules,
        trigger_ids=sorted({t for m in g.members for t in m.trigger_ids}),
        authentication_packages=sorted({str(m.authentication_package) for m in g.members
                                        if m.authentication_package}),
        mixed_account=_mixed(g.members),
        inside_gap_max_ms=delta_ms(max(gaps), 0) if gaps else None, inside_gaps_us=gaps,
        clock_unreliable=max(m.clock_unreliable for m in g.members),
        gate_clock_unreliable=max(m.gate_clock_unreliable for m in g.members),
        machine_account_only=int(all(m.machine_account == 1 for m in g.members)),
    )


def _hop_order(h: Hop) -> tuple[int, str]:
    """Hop id order (048 item 7): first member's corrected time, then its uid."""
    return h.first_us, h.members[0].uid


def _set_neighbour_gaps(hops: Sequence[Hop]) -> None:
    """``prev_gap`` / ``next_gap``: last member of the previous hop of the same target and IP to this hop's
    first member, and this hop's last member to the next one's first (target clock). Hops only: a follow-up
    group is not a hop (ST-26). A blank IP has no neighbour (a NULL never matches)."""
    by_key: dict[tuple[str, str], list[Hop]] = {}
    for h in hops:
        if h.source_ip is not None:
            by_key.setdefault((h.target_host, h.source_ip), []).append(h)
    for seq in by_key.values():
        seq.sort(key=lambda h: (h.first_us_raw, h.members[0].uid))
        for a, b in zip(seq, seq[1:]):
            gap = b.first_us_raw - a.last_us_raw
            a.next_gap_us, b.prev_gap_us = gap, gap
            a.next_gap_ms = b.prev_gap_ms = delta_ms(gap, 0)


def _set_flags(h: Hop, params: StitchParams) -> None:
    """ST-20 review flags (048 item 7), µs, inclusive bounds: ``gap_near_threshold`` = an inside, previous or
    next gap within ``group_review_band_s``; ``splits_at_1s`` = an inside gap > 1 s; ``merges_at_3s`` = the
    previous or next gap <= 3 s."""
    lo, hi = (seconds_to_us(v) for v in params.group_review_band_s)
    neighbours = [g for g in (h.prev_gap_us, h.next_gap_us) if g is not None]
    h.gap_near_threshold = int(any(lo <= g <= hi for g in h.inside_gaps_us + neighbours))
    h.splits_at_1s = int(any(g > seconds_to_us(SPLIT_PROBE_S) for g in h.inside_gaps_us))
    h.merges_at_3s = int(any(g <= seconds_to_us(MERGE_PROBE_S) for g in neighbours))


def _set_shared_ports(hops: Sequence[Hop]) -> None:
    """ST-24: other hops with a member on the same (source IP, source port); NULL IP, NULL or 0 port never
    shares (005). Listed only; the port is never a grouping key."""
    owners: dict[tuple[str, int], set[str]] = {}
    for h in hops:
        for m in h.members:
            if h.source_ip is not None and m.source_port:
                owners.setdefault((h.source_ip, m.source_port), set()).add(h.hop_id)
    for h in hops:
        others: set[str] = set()
        for m in h.members:
            if h.source_ip is not None and m.source_port:
                others |= owners[(h.source_ip, m.source_port)]
        h.shares_port_with_hops = sorted(others - {h.hop_id})


def _followup_record(g: LogonGroup, hop: Hop) -> FollowupGroup:
    """The traceable follow-up record (ST-26, 048 item 9): hop id, logons, delay after the hop's last member,
    and the shared ports (all of the group's ports, by condition ii)."""
    return FollowupGroup(hop_id=hop.hop_id, logons=list(g.members),
                         time_delta_ms=delta_ms(g.first.us_raw, hop.last_us_raw),
                         ports=sorted(_ports(g)))


# ---------------------------------------------------------------- the set

@dataclass
class HopSet:
    """Hops (by hop id), follow-up groups (by hop id, then first logon) and counts of one trial."""
    trial_id: str
    hops: list[Hop]
    followups: list[FollowupGroup]
    counts: dict[str, Any]


def _endpoint_hosts(params: StitchParams) -> dict[str, str]:
    """Normalised IP -> lab endpoint host (``ep-NN``) from ``lab_host_ips`` (spec 5, one definition).

    WHY here and only for a count: spec 10.1 counts "user endpoint -> endpoint" groups; the hop's
    ``source_host`` column itself is task 4 (ST-40).
    """
    out: dict[str, str] = {}
    for host, ip in params.lab_host_ips.items():
        n = norm_ip(ip)
        if n is not None and str(host).lower().startswith("ep-"):
            out[n] = str(host)
    return out


def _user_e2e(target: str, ip: str | None, members: Sequence[RemoteLogon], endpoints: Mapping[str, str]) -> bool:
    """User endpoint -> endpoint (spec 10.1): not every member a machine account, source IP owned by a lab
    endpoint, target an endpoint."""
    return (not all(m.machine_account == 1 for m in members) and ip is not None and ip in endpoints
            and target in endpoints.values())


def _counts(logons: Sequence[RemoteLogon], groups: Sequence[LogonGroup], hops: Sequence[Hop],
            follow: Sequence[FollowupGroup], params: StitchParams) -> dict[str, Any]:
    """Counts of the hop step (plan task 2). ``gap_near_threshold_user_e2e`` and the ``user_e2e_*`` counts are
    the spec 10.1 / 10.7 comparison values; protocols are counted over hops."""
    ep = _endpoint_hosts(params)
    protocols: dict[str, int] = {}
    for h in hops:
        protocols[h.protocol] = protocols.get(h.protocol, 0) + 1
    near = [h for h in hops if h.gap_near_threshold]
    e2e_groups = [g for g in groups if _user_e2e(g.target_host, g.source_ip, g.members, ep)]
    return {
        "remote_logons": len(logons),
        "groups_before_followups": len(groups),
        # Spec 10.1 "hop groups at 2 s" counts the groups of logons with a source IP; blank-IP logons are
        # single hops on top of them (10.1 note), so both numbers are kept.
        "ip_groups_before_followups": sum(1 for g in groups if g.source_ip is not None),
        "hops": len(hops),
        "seeds": sum(h.is_seed for h in hops),
        "followup_groups": len(follow),
        "followup_logons": sum(len(f.logons) for f in follow),
        "blank_ip_hops": sum(1 for h in hops if h.source_ip is None),
        "gap_near_threshold": len(near),
        "gap_near_threshold_user_e2e": sum(1 for h in near if _user_e2e(h.target_host, h.source_ip, h.members, ep)),
        "mixed_account": sum(h.mixed_account for h in hops),
        "near_duplicate_members": sum(1 for lg in logons if lg.near_duplicate),
        "user_e2e_groups_before_followups": len(e2e_groups),
        "user_e2e_seed_groups": sum(1 for g in e2e_groups if g.is_seed),
        "user_e2e_hops": sum(1 for h in hops if _user_e2e(h.target_host, h.source_ip, h.members, ep)),
        "protocols": dict(sorted(protocols.items())),
    }


def _check_sta01(logons: Sequence[RemoteLogon], hops: Sequence[Hop]) -> None:
    """STA-01 / ST-03: every remote logon is a member of exactly one hop or a follow-up of exactly one hop."""
    seen: dict[str, int] = {}
    for h in hops:
        for m in h.members + h.followups:
            seen[m.uid] = seen.get(m.uid, 0) + 1
    want = {lg.uid for lg in logons}
    bad = sorted(u for u, n in seen.items() if n != 1) + sorted(want - set(seen)) + sorted(set(seen) - want)
    if bad:
        raise StitchError(f"STA-01 broken: {len(bad)} remote logon(s) not in exactly one hop, e.g. {bad[0]}")


def build_hops(trial_id: str, gate: GateRows, scan: ScanResult, sessions: SessionIndex,
               params: StitchParams = StitchParams()) -> HopSet:
    """ST-03, ST-05, ST-20..ST-24, ST-26 for one trial: remote logons -> groups -> hops and follow-ups.

    Hop ids are given in (first member corrected time, first uid) order after the follow-ups are removed,
    so a follow-up group never takes a number. Raises StitchError when a gate logon is not in the scan or
    when STA-01 fails.
    """
    logons = remote_logons(gate, scan, sessions)
    groups = group_hops(logons, params)
    hop_groups, follow_pairs = attach_followups(groups, params)
    made = {id(g): _new_hop(g) for g in hop_groups}
    hops = sorted(made.values(), key=_hop_order)
    for n, h in enumerate(hops, start=1):
        h.hop_id = hop_id_of(trial_id, n)
    _set_neighbour_gaps(hops)
    for h in hops:
        _set_flags(h, params)
    _set_shared_ports(hops)
    follow: list[FollowupGroup] = []
    for g, parent in follow_pairs:
        hop = made[id(parent)]
        hop.followups.extend(g.members)
        hop.followup_group_count += 1
        follow.append(_followup_record(g, hop))
    follow.sort(key=lambda f: (f.hop_id, f.logons[0].us_raw, f.logons[0].uid))
    _check_sta01(logons, hops)
    return HopSet(trial_id=trial_id, hops=hops, followups=follow,
                  counts=_counts(logons, groups, hops, follow, params))
