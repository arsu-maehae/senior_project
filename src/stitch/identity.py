"""T7.4 identity inputs per (hop, moving account, LSASS read on the source host): spec 03_stitch ``hop_identity.csv``
(ST-60..ST-64; Correction K; decisions 013, 014, 039, 044 (c), 047; 049 item 6).

WHY facts and no value (ST-64): the stitcher lists, for every hop and account, every LSASS read on the source host
with who ran it and when, the order facts against the move, and the sessions of the moving account that were open
(or whose end is unknown) at each read. Which reads count as the credential access is OPEN Q9 (049 "Q9 stays
open"), so no read is chosen and nothing is filtered on account, image or time here; T9 computes the value.

WHY the linked session is never read (decision 013, identity input): IdentityCoherence uses only the moving account
(the target 4624) and the source host (by IP), so it is defined for every hop, ``target_only`` included. The
functions below take only ``source_host`` and ``target_only_reason`` from T7.3, never a link row or a verdict, so
changing the linked session cannot change an identity row (STT-11).

WHY two clocks: "move after the dump" is a cross-host comparison and uses corrected times with the decision 014
tolerance (``order_fields``); "session open at the dump" is a question about one host's own log and uses its
logged time (``sessions_at``; ST-63, 047 item 6), with the decision 039 look-back allowed for this check only.

Everything here is pure: gate rows, scan, hops, sessions and offsets in, frozen records out. No file access, no
command text (the image and account columns are DB fields of the Sysmon 10 row, 049 item 7).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from clock_offset.correct import Offsets, clock_unreliable as hosts_unreliable
from clock_offset.params import STATUS_NONE, STATUS_STALE
from gate.timeutil import US_PER_MS, delta_ms, seconds_to_us, to_us

from .errors import StitchError
from .hops import Hop, HopSet, RemoteLogon
from .params import StitchParams
from .scan import ScanResult
from .sessions import Session, SessionIndex, state_at
from .source import TARGET_ONLY_NO_LOGS, SubjectLinks

__all__ = ["NA_SOURCE_UNKNOWN", "NA_NO_LOGS", "NA_MACHINE", "NOT_APPLICABLE", "R1_RULE", "LsassRead", "lsass_reads",
           "order_fields", "sessions_at", "IdentityRow", "hop_identity", "build_identity", "accounts_of",
           "null_account_members", "UNCERTAIN_STATUSES"]

NA_SOURCE_UNKNOWN, NA_NO_LOGS, NA_MACHINE = "source_host_unknown", "source_host_no_logs", "machine_account"
# 049 item 6: the order in which ``not_applicable`` is decided per (hop, account), first that applies.
NOT_APPLICABLE: tuple[str, ...] = (NA_SOURCE_UNKNOWN, NA_NO_LOGS, NA_MACHINE)
# The gate rule whose supporting rows are the LSASS reads (ST-61; spec 02_gate GT-16).
R1_RULE = "R1_lsass"
# ST-62: a host with one of these statuses has no usable offset, so the order of a move and a dump on it cannot be
# trusted within any band; it sets ``order_within_uncertainty``. WHY not ``wide``: a wide host is corrected and
# reports its uncertainty (spec 08 CO-06), which the band already uses. Imported, never spelled here.
UNCERTAIN_STATUSES: frozenset[str] = frozenset({STATUS_NONE, STATUS_STALE})

if NA_NO_LOGS != TARGET_ONLY_NO_LOGS:  # WHY at import: 049 item 6 reuses the T7.3 reason's spelling on purpose
    raise ImportError(f"identity {NA_NO_LOGS!r} differs from the T7.3 target_only reason {TARGET_ONLY_NO_LOGS!r}")

Row = Mapping[str, Any]


# ---------------------------------------------------------------- LSASS reads (ST-61)

@dataclass(frozen=True)
class LsassRead:
    """One LSASS read: the ``R1_lsass`` row(s) of the gate's ``supporting.csv`` that join to one in-window Sysmon 10
    row of the scan.

    ``event_uid`` is the scan row's kept uid (its ``event_uid``; ST-05: near-duplicate copies are one event, so
    several supporting rows naming copies of one row give ONE read). ``supporting_uids`` are the gate uids that
    joined to it, sorted, so every ``supporting.csv`` row stays traceable. ``us_raw`` / ``us`` are the scan
    row's logged and corrected times (ST-02). ``source_image`` comes from the scan row, ``account`` from the gate
    row's ``account_name`` (the Sysmon 10 SourceUser); both are DB fields, never command text (049 item 7).
    ``clock_unreliable`` is the scan's ST-02 event flag (not the gate's, which also carries the window-edge flag;
    the two are kept apart as in ``hops.RemoteLogon``).
    """
    event_uid: str
    host: str
    us_raw: int
    us: int
    source_image: str | None
    account: str | None
    clock_unreliable: int
    supporting_uids: tuple[str, ...] = ()


def _text_or_none(value: Any) -> str | None:
    """A DB / CSV text value, None for NULL or empty (the gate writes NULL as an empty cell)."""
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _sysmon10_by_uid(scan: ScanResult) -> dict[str, Row]:
    """Every uid (ST-05 copies included) of every in-window Sysmon 10 row of the scan -> that row.

    WHY every uid: the gate may name a non-representative copy of a near-duplicate pair; it must find the one row
    that stands for both (as ``hops.logon_index`` does for 4624s).
    """
    out: dict[str, Row] = {}
    for row in scan.in_window:
        if (row.get("channel"), row.get("event_id")) == ("Sysmon", 10):
            for u in row.get("event_uids") or [row.get("event_uid")]:
                out[str(u)] = row
    return out


def _check_read_agrees(gate_row: Row, scan_row: Row) -> None:
    """The gate row and the scan row must describe the same event: same host and same corrected time (the same
    idea as ``hops._check_agrees``). A mismatch means a stale gate folder, another DB or other offsets; never
    guess which one is right."""
    uid = gate_row.get("event_uid")
    if str(gate_row.get("host") or "") != str(scan_row.get("host") or ""):
        raise StitchError(f"supporting row {uid}: host {gate_row.get('host')!r} differs from the Sysmon 10 row's "
                          f"host {scan_row.get('host')!r}")
    try:
        gate_us = to_us(str(gate_row.get("event_utc_corrected") or ""))
    except (TypeError, ValueError) as exc:
        raise StitchError(f"supporting row {uid}: no valid event_utc_corrected ({exc})") from exc
    if gate_us != scan_row["us"]:
        raise StitchError(f"supporting row {uid}: event_utc_corrected differs from the scan's corrected time "
                          f"(ST-01, ST-02: gate and stitcher must agree)")


def _read_account(gate_rows: Sequence[Row], kept_uid: str) -> str | None:
    """The ``account_name`` of the supporting rows of one read. WHY refuse a disagreement: copies of one event
    (ST-05) carry the same SourceUser; two different values mean the gate rows do not describe one event, and
    choosing one would be a guess."""
    accounts = {_text_or_none(g.get("account_name")) for g in gate_rows}
    if len(accounts) > 1:
        raise StitchError(f"supporting {R1_RULE} rows of event {kept_uid} disagree on account_name")
    return accounts.pop()


def lsass_reads(supporting: Iterable[Row], scan: ScanResult) -> list[LsassRead]:
    """Every LSASS read of ``supporting.csv`` (its ``R1_lsass`` rows) as an ``LsassRead``, sorted by (host, us,
    uid) (ST-61).

    WHY one read per scan row (ST-05): near-duplicate copies (one host, channel, record_id) are one event, so
    supporting rows that join to the same kept scan row give ONE read, named by the row's kept ``event_uid``,
    with every gate uid in ``supporting_uids``; otherwise one event would give two identity rows.
    ALL reads are kept: no filter on account, image or time, because which reads count is OPEN Q9 (049 item 6).
    Raises StitchError, checked per supporting row, when a uid is no in-window Sysmon 10 row of the scan, or when
    host or corrected time differ (ST-01: an LSASS read outside the window is never listed, and the gate never
    lists one); and when the rows of one read disagree on the account.
    """
    index = _sysmon10_by_uid(scan)
    by_row: dict[str, tuple[Row, list[Row]]] = {}
    for g in supporting:
        if g.get("rule") != R1_RULE:
            continue
        uid = str(g.get("event_uid") or "")
        srow = index.get(uid)
        if srow is None:
            raise StitchError(f"supporting {R1_RULE} uid {uid} is not an in-window Sysmon 10 row of the scan "
                              f"(ST-01: gate and stitcher must agree)")
        _check_read_agrees(g, srow)
        by_row.setdefault(str(srow["event_uid"]), (srow, []))[1].append(g)
    out: list[LsassRead] = []
    for kept_uid, (srow, grows) in by_row.items():
        out.append(LsassRead(event_uid=kept_uid, host=str(srow["host"]), us_raw=srow["us_raw"], us=srow["us"],
                             source_image=_text_or_none(srow.get("source_image")),
                             account=_read_account(grows, kept_uid),
                             clock_unreliable=int(srow.get("clock_unreliable") or 0),
                             supporting_uids=tuple(sorted({str(g.get("event_uid")) for g in grows}))))
    out.sort(key=lambda r: (r.host, r.us, r.event_uid))
    return out


# ---------------------------------------------------------------- order (ST-62)

def order_fields(move_us: int, dump_us: int, unc_source_ms: int | None, unc_target_ms: int | None,
                 hosts_bad: bool, params: StitchParams = StitchParams()) -> tuple[int, int, int, int, int]:
    """(gap_ms, order_margin_ms, order_ok, order_within_tolerance, order_within_uncertainty) of ST-62.

    gap = move - dump; margin = move - (dump - ORDER_TOL_S); ``order_ok`` = margin >= 0 (decision 014: the move
    may lie up to the tolerance before the dump, because the two times come from different hosts).
    ``order_within_tolerance`` = |gap| < ORDER_TOL_S. ``order_within_uncertainty`` = ``hosts_bad`` or |margin| <
    max(unc_source + unc_target, ORDER_UNC_FLOOR_S); a None uncertainty counts 0, so the floor applies.

    WHY microseconds for every comparison: rounding to milliseconds first could move a value across a boundary;
    only the written gap and margin are rounded (``delta_ms``). WHY a flag only (044 (c)): the band says the order
    decision is close to the clock error, not that it is wrong; ``order_ok`` is never changed by it.
    """
    tol_us = seconds_to_us(params.order_tol_s)
    floor_us = seconds_to_us(params.order_unc_floor_s)
    gap_us = move_us - dump_us
    margin_us = move_us - (dump_us - tol_us)
    band_us = max(((unc_source_ms or 0) + (unc_target_ms or 0)) * US_PER_MS, floor_us)
    return (delta_ms(move_us, dump_us), delta_ms(move_us, dump_us - tol_us), int(margin_us >= 0),
            int(abs(gap_us) < tol_us), int(bool(hosts_bad) or abs(margin_us) < band_us))


# ---------------------------------------------------------------- sessions at the dump (ST-63)

def _truthy(value: Any) -> bool:
    """A 0/1 flag from the DB or a gate CSV: 1 / True / ``"1"`` / ``"true"`` are true; NULL, 0, ``""``, ``"0"``
    and ``"false"`` are false. WHY not ``bool(value)``: a text ``"0"`` is truthy in Python."""
    if value is None:
        return False
    if isinstance(value, (bool, int)):
        return bool(value)
    return str(value).strip().lower() in ("1", "true")


def _counts_for(s: Session, host: str, account_key: str, params: StitchParams) -> bool:
    """ST-63 filter: the moving account's own user session on the source host.

    System logon IDs (``is_system`` or in ``params.system_logon_ids``) and machine accounts are excluded
    (Correction K is about a user's credentials). An unknown-open session has no account and never matches
    (a NULL never matches, decision 005).
    """
    return (s.host == host and s.account is not None and str(s.account).lower() == account_key
            and not s.is_system and s.logon_id not in params.system_logon_ids and not _truthy(s.machine_account))


def sessions_at(sessions: SessionIndex, host: str, account: str, at_us_raw: int,
                params: StitchParams = StitchParams()) -> tuple[list[Session], list[Session]]:
    """(open, end_unknown) sessions of ``account`` on ``host`` at the logged instant ``at_us_raw`` (ST-63).

    Uses ``SessionIndex.lookback_view`` (decision 039: a session opened before the window counts here, and only
    here) and ``sessions.state_at`` (closed by 4634 / 4647 or a boot boundary -> not open; a 1102 between the
    open and the instant -> ``end_unknown``, listed apart and not counted as open). The account is compared in
    lower case. Each list sorted by (open_us_raw, logon_id, seq).
    """
    key = str(account).lower()
    opened: list[Session] = []
    unknown: list[Session] = []
    for s in sessions.lookback_view():
        if not _counts_for(s, host, key, params):
            continue
        state = state_at(s, at_us_raw)
        if state == "open":
            opened.append(s)
        elif state == "end_unknown":
            unknown.append(s)

    def order(s: Session) -> tuple[int, int, int]:
        return (s.open_us_raw if s.open_us_raw is not None else 0), s.logon_id, s.seq

    return sorted(opened, key=order), sorted(unknown, key=order)


def _first_open_uid(s: Session) -> str:
    """The session's first opening 4624 uid (the smallest of ``open_uids``); "" for an unknown open (none)."""
    return min(s.open_uids) if s.open_uids else ""


# ---------------------------------------------------------------- identity rows (ST-60, ST-64)

@dataclass(frozen=True)
class IdentityRow:
    """One row of spec 3 ``hop_identity.csv``: one per (hop, account, LSASS read on the source host).

    Times are integer µs (``move_us``, ``dump_us`` corrected); the writer formats them. ``open_session_*`` are
    parallel tuples, one entry per open session (first open uid, logon type, hex logon ID).
    ``session_open_before_window`` = 1 when an open session's 4624 lies before the window (decision 039
    look-back). A ``not_applicable`` row, or a row of a hop with no read on its source host, has empty dump,
    order and session columns. ``offset_unc_*`` are the hosts' reported uncertainties whenever the host is
    known to the offsets (host facts, filled on every row).
    """
    hop_id: str
    account: str
    source_host: str | None
    move_us: int
    move_uid: str
    dump_event_uid: str
    dump_us: int | None
    dump_source_image: str | None
    dump_account: str | None
    gap_ms: int | None
    order_margin_ms: int | None
    order_ok: int | None
    order_within_tolerance: int | None
    order_within_uncertainty: int | None
    offset_unc_source_ms: int | None
    offset_unc_target_ms: int | None
    open_session_uids: tuple[str, ...]
    open_session_types: tuple[int | None, ...]
    open_session_ids_hex: tuple[str, ...]
    session_open_before_window: int
    end_unknown_session_uids: tuple[str, ...]
    not_applicable: str
    clock_unreliable: int


def null_account_members(hop: Hop) -> list[str]:
    """Uids of the hop's members whose 4624 has no account (NULL). WHY reported: such a member names no moving
    account, so it gives no identity row (``accounts_of`` skips it); the caller counts it."""
    return [m.uid for m in hop.members if m.account_key is None]


def accounts_of(hop: Hop) -> list[tuple[str, list[RemoteLogon]]]:
    """(account key, members of that account in (us, uid) order) per distinct member account, by account key.

    Members only: follow-up logons are not members (ST-26) and never give rows. A member with a NULL account is
    skipped: a NULL is no account and never matches (decision 005); ``null_account_members`` lists them.
    """
    by_key: dict[str, list[RemoteLogon]] = {}
    for m in hop.members:
        if m.account_key is not None:
            by_key.setdefault(m.account_key, []).append(m)
    return [(k, sorted(v, key=lambda m: (m.us, m.uid))) for k, v in sorted(by_key.items())]


def _not_applicable(source_host: str | None, target_only_reason: str, members: Sequence[RemoteLogon]) -> str:
    """049 item 6, first that applies: no known source host; a source host with no logs in the DB (so a missing
    fact never looks like "no LSASS read"); every member of the account a machine account (Correction K is about
    user credentials). "" when identity applies."""
    if source_host is None:
        return NA_SOURCE_UNKNOWN
    if target_only_reason == NA_NO_LOGS:
        return NA_NO_LOGS
    if all(_truthy(m.machine_account) for m in members):
        return NA_MACHINE
    return ""


def _unc_ms(host: str | None, offsets: Offsets | None) -> int | None:
    """The host's reported ``offset_unc_ms``; None for an unknown host, no offsets or a host not in the file."""
    if host is None or offsets is None:
        return None
    o = offsets.hosts.get(host)
    return None if o is None else o.offset_unc_ms


def _hosts_bad(source_host: str, target_host: str, offsets: Offsets | None) -> bool:
    """ST-62 "a none or stale host sets it": a host not in the offsets file counts as bad too (CO-09: never
    assume a clock is fine). With no offsets at all there is no clock judgement (as ``scan.kept_row``)."""
    if offsets is None:
        return False
    for h in (source_host, target_host):
        o = offsets.hosts.get(h)
        if o is None or o.status in UNCERTAIN_STATUSES:
            return True
    return False


def _host_clock_flag(source_host: str | None, target_host: str, offsets: Offsets | None) -> int:
    """ST-02 host part through the shared ``clock_offset.correct.clock_unreliable``; an unknown source host adds
    nothing (it has no clock to judge); no offsets -> 0 (as ``source._host_flag``)."""
    if offsets is None:
        return 0
    hosts = [h for h in (source_host, target_host) if h]
    return int(hosts_unreliable(*hosts, offsets=offsets))


def _empty_row(hop: Hop, first: RemoteLogon, source_host: str | None, not_applicable: str, unc_s: int | None,
               unc_t: int | None, clock_flag: int) -> IdentityRow:
    """A row with empty dump, order and session columns: a ``not_applicable`` row, or no read on the source host."""
    return IdentityRow(hop_id=hop.hop_id, account=str(first.account), source_host=source_host, move_us=first.us,
                       move_uid=first.uid, dump_event_uid="", dump_us=None, dump_source_image=None, dump_account=None,
                       gap_ms=None, order_margin_ms=None, order_ok=None, order_within_tolerance=None,
                       order_within_uncertainty=None, offset_unc_source_ms=unc_s, offset_unc_target_ms=unc_t,
                       open_session_uids=(), open_session_types=(), open_session_ids_hex=(),
                       session_open_before_window=0, end_unknown_session_uids=(), not_applicable=not_applicable,
                       clock_unreliable=clock_flag)


def _read_row(hop: Hop, first: RemoteLogon, source_host: str, read: LsassRead, sessions: SessionIndex,
              offsets: Offsets | None, unc_s: int | None, unc_t: int | None, clock_flag: int,
              params: StitchParams) -> IdentityRow:
    """The row of one (hop, account, read): order facts on corrected times, sessions on the source's own clock."""
    gap, margin, ok, in_tol, in_unc = order_fields(first.us, read.us, unc_s, unc_t,
                                                   _hosts_bad(source_host, hop.target_host, offsets), params)
    opened, unknown = sessions_at(sessions, source_host, str(first.account), read.us_raw, params)
    return IdentityRow(hop_id=hop.hop_id, account=str(first.account), source_host=source_host, move_us=first.us,
                       move_uid=first.uid, dump_event_uid=read.event_uid, dump_us=read.us,
                       dump_source_image=read.source_image, dump_account=read.account, gap_ms=gap,
                       order_margin_ms=margin, order_ok=ok, order_within_tolerance=in_tol,
                       order_within_uncertainty=in_unc, offset_unc_source_ms=unc_s, offset_unc_target_ms=unc_t,
                       open_session_uids=tuple(_first_open_uid(s) for s in opened),
                       open_session_types=tuple(s.logon_type for s in opened),
                       open_session_ids_hex=tuple(s.logon_id_hex for s in opened),
                       session_open_before_window=int(any(s.opened_before_window for s in opened)),
                       end_unknown_session_uids=tuple(_first_open_uid(s) for s in unknown),
                       not_applicable="", clock_unreliable=int(clock_flag or read.clock_unreliable))


def _row_order(r: IdentityRow) -> tuple[str, str, int, int, str]:
    """hop id, account (lower), dump time (empty first), dump uid."""
    return (r.hop_id, r.account.lower(), 0 if r.dump_us is None else 1,
            0 if r.dump_us is None else r.dump_us, r.dump_event_uid)


def hop_identity(hop: Hop, source_host: str | None, target_only_reason: str, reads: Sequence[LsassRead],
                 sessions: SessionIndex, offsets: Offsets | None,
                 params: StitchParams = StitchParams()) -> list[IdentityRow]:
    """The identity rows of one hop (ST-60..ST-64, 049 item 6).

    Per member account (``accounts_of``): the written account, ``move_us`` and ``move_uid`` are those of its first
    member by (us, uid). ``not_applicable`` (``_not_applicable``) gives one empty row. Otherwise one row per read
    whose host is ``source_host`` (every read: any account, any time, Q9 open), or one empty row when there is
    none. ``clock_unreliable`` = host part (source and target; target only when the source is unknown) OR any
    member of the account flagged OR the read flagged (ST-02).

    WHY only ``source_host`` and ``target_only_reason`` from T7.3 (decision 013): the linked session must not
    reach an identity row, so this function cannot even see it.
    """
    unc_s, unc_t = _unc_ms(source_host, offsets), _unc_ms(hop.target_host, offsets)
    host_flag = _host_clock_flag(source_host, hop.target_host, offsets)
    on_source = [r for r in reads if source_host is not None and r.host == source_host]
    rows: list[IdentityRow] = []
    for _key, members in accounts_of(hop):
        first = members[0]
        flag = int(host_flag or any(m.clock_unreliable for m in members))
        na = _not_applicable(source_host, target_only_reason, members)
        if na or not on_source:
            rows.append(_empty_row(hop, first, source_host, na, unc_s, unc_t, flag))
            continue
        assert source_host is not None  # _not_applicable returned "" only for a known source host
        rows.extend(_read_row(hop, first, source_host, r, sessions, offsets, unc_s, unc_t, flag, params)
                    for r in on_source)
    rows.sort(key=_row_order)
    return rows


def build_identity(hopset: HopSet, links: Mapping[str, SubjectLinks], reads: Sequence[LsassRead],
                   sessions: SessionIndex, offsets: Offsets | None,
                   params: StitchParams = StitchParams()) -> list[IdentityRow]:
    """``hop_identity`` for every hop of the set (follow-up groups are not hops, ST-26), in the file's row order.

    From each hop's ``SubjectLinks`` only ``source_host`` and ``target_only_reason`` are passed on (decision 013).
    Raises StitchError for a hop with no links entry (T7.3 builds one for every hop; a gap means a broken run).
    """
    rows: list[IdentityRow] = []
    for h in hopset.hops:
        sl = links.get(h.hop_id)
        if sl is None:
            raise StitchError(f"hop {h.hop_id} has no links entry (T7.3 builds one per hop)")
        rows.extend(hop_identity(h, sl.source_host, sl.target_only_reason, reads, sessions, offsets, params))
    rows.sort(key=_row_order)
    return rows
