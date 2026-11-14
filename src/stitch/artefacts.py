"""Target-side artefacts of each hop (spec 03_stitch ST-30..ST-34; decision 048 items 9, 10; input notes IN-02).

Share bursts (ST-30, ST-31), service installs paired as the gate pairs them (GT-12), the copy <-> install tie
(ST-32), the other artefacts (ST-33: wsmprovhost, WinRM 91 and inbound 3389 as the gate paired them),
follow-up logons as artefact rows (ST-26 with 048 item 9) and the spans (ST-34).

WHY pure: the inputs are the hop set (``hops.build_hops``), the scan (``scan.ScanResult``), the T7.2
``SessionIndex`` (read only: ``session_at`` never creates a session) and the gate rows; nothing here opens a
file, so every STT-03 case can be built from a handful of dicts. No command text is read or imported here:
every name comes from target-side event fields (``relative_target_name``, ``service_name``,
``service_image_path``), which spec 2 allows in outputs.

Every comparison is between events of the target host, so it uses the logged time ``us_raw`` (same host, the
clock correction cannot change a difference). A share or service event belongs to a member only when it is
in the window (the scan keeps only in-window link rows) and in the member's own session: ``session_at`` on the
event gives the member's session key (048 item 10). That is what keeps h-y's copy, logged under h-x's
logon ID 95 s later, from being treated as an unrelated event: it is still h-x's session, and only the ST-32
file-name tie may move it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Sequence

from gate.classify import (is_4697, is_7045, is_inbound_rdp_sysmon3, is_share, is_winrm91,
                           is_wsmprovhost_start, pair_services)
from gate.params import GateParams
from gate.timeutil import delta_ms, seconds_to_us

from .hops import FOLLOWUP_KIND, FOLLOWUP_METHOD, FOLLOWUP_TIER, Hop, HopSet, RemoteLogon
from .params import StitchParams
from .scan import ScanResult
from .sessions import SessionIndex, hex_id, logon_id_int

if TYPE_CHECKING:  # WHY type-only: importing ``inputs`` at run time would pull file-reading code into this pure module
    from .inputs import GateRows

__all__ = ["ShareBurst", "Install", "Tie", "ArtefactRow", "ArtefactSet", "MemberIndex", "build_artefacts",
           "share_bursts", "installs", "tie_copies", "attach_bursts", "install_rows", "other_artefacts",
           "followup_rows", "binary_file_name", "base_name", "SERVICE_PAIR_S", "METHOD_LOGON_ID",
           "METHOD_FILE_NAME_TIME", "METHOD_IP_TIME", "TIER_LOGON_ID", "TIER_FILE_NAME_TIME", "row_order"]

Row = Mapping[str, Any]

# GT-12 pairing tolerance: the gate's own value, never a stitcher copy (spec 5 "one definition"; 048 item 10).
# WHY not a StitchParams field: the pairing must be the gate's, and a field would also change the parameter
# block of the committed ``t72_index.json`` files.
SERVICE_PAIR_S: float = GateParams().service_pair_s

METHOD_LOGON_ID = "logon_id"
METHOD_FILE_NAME_TIME = "file_name_time"
METHOD_IP_TIME = "ip_time"
TIER_LOGON_ID = "A"            # ST-31 / ST-32: the event carries the member's logon ID in its session
TIER_FILE_NAME_TIME = "B"      # ST-32: file name and time only
TIER_WSMPROVHOST = "A"         # 048 item 9: wsmprovhost by session ID

KIND_BURST = "share_burst"
KIND_INSTALL = "service_install"
KIND_WINRM_HOST = "winrm_host"
KIND_WINRM_91 = "winrm_91"
KIND_RDP = "rdp_connection"

# Install status values (why an install has, or has no, hop).
STATUS_LOGON_ID = "logon_id"              # 4697 by a member's logon ID, same session
STATUS_TIED_7045 = "tied_7045_only"       # 7045 with no 4697, attached through an ST-32 tie
STATUS_NOT_REMOTE_SYSTEM = "not_remote_system_logon_id"
STATUS_NOT_REMOTE_NO_MEMBER = "not_remote_no_member"
STATUS_UNATTACHED = "unattached_7045_only"


# ---------------------------------------------------------------- names

def base_name(path: Any) -> str:
    """The part after the last ``\\`` or ``/`` of a stripped path; ``""`` for NULL or a bare separator.

    WHY both separators: 5145 ``relative_target_name`` uses ``\\`` but a service path may be written with
    ``/``; the file name is what ST-32 compares.
    """
    if path is None:
        return ""
    text = str(path).strip()
    cut = max(text.rfind("\\"), text.rfind("/"))
    return text[cut + 1:].strip()


def binary_file_name(image_path: Any) -> str:
    """Binary file name F of a ``service_image_path`` (ST-32), original spelling; ``""`` when none.

    Strip whitespace; a leading quote means the path is the quoted text, otherwise the first
    whitespace-separated token (the rest are arguments); then the base name. WHY: ``"C:\\x y\\a.exe" -k``
    and ``C:\\Windows\\a.exe -k`` must both give ``a.exe``. An unterminated quote takes the rest of the text.
    """
    if image_path is None:
        return ""
    text = str(image_path).strip()
    if not text:
        return ""
    if text[0] in "\"'":
        end = text.find(text[0], 1)
        path = text[1:end] if end > 0 else text[1:]
    else:
        path = text.split()[0]
    return base_name(path)


def _row_uids(row: Row) -> list[str]:
    """Every uid of a scan row (ST-05 copies included)."""
    return [str(u) for u in (row.get("event_uids") or [row["event_uid"]])]


def _uid_order(row: Row) -> tuple[int, str]:
    """Same-host order: logged time, then uid."""
    return row["us_raw"], str(row["event_uid"])


# ---------------------------------------------------------------- members

class MemberIndex:
    """(target host, logon ID) -> the hop members with that ID, for the session-checked lookups of 048 item 10.

    WHY a class with one query: shares, 4697s and wsmprovhost starts all ask the same question, "which member
    of which hop does this event belong to", and must answer it the same way.
    """

    def __init__(self, hops: Iterable[Hop]) -> None:
        self._by_key: dict[tuple[str, int], list[tuple[Hop, RemoteLogon]]] = {}
        for h in hops:
            for m in h.members:
                if m.logon_id is not None and m.session_key is not None:
                    self._by_key.setdefault((m.host, m.logon_id), []).append((h, m))

    def find(self, host: str, logon_id: Any, us_raw: int,
             sessions: SessionIndex) -> tuple[Hop, RemoteLogon] | None:
        """The member whose logon ID the event carries, when the event is at or after the member's 4624 and in
        the member's session (``session_at`` key equal to the member's key). None for a NULL ID or no match.

        WHY the session check: a logon ID can be reused after a boot; only the same session key proves the
        event was logged under this member's logon (048 item 10).
        """
        lid = logon_id_int(logon_id)
        if lid is None:
            return None
        found = sessions.session_at(host, lid, us_raw)
        if found is None:
            return None
        for h, m in self._by_key.get((host, lid), []):
            if m.us_raw <= us_raw and m.session_key == found.key:
                return h, m
        return None


# ---------------------------------------------------------------- bursts (ST-30)

@dataclass
class ShareBurst:
    """One share burst of one member logon (ST-30): its 5140 / 5145 events with gaps <= ``BURST_GAP_S``.

    ``file_writes`` = (lower-case base name, us_raw) of every 5145 with a non-empty file name, for the ST-32
    tie; ``exe_names`` = the ``.exe`` base names, original spelling, sorted unique case-insensitively.
    ``logged_under_hop_id`` is the hop of the member whose logon ID the events carry.
    """
    burst_id: str
    host: str
    logon_id: int
    logon_id_hex: str
    member_uid: str
    member_machine_account: int
    logged_under_hop_id: str
    event_uids: list[str]
    first_us_raw: int
    last_us_raw: int
    first_us: int
    exe_names: list[str]
    file_writes: list[tuple[str, int]]


def _member_share_rows(scan: ScanResult, members: MemberIndex, sessions: SessionIndex
                       ) -> tuple[dict[str, tuple[Hop, RemoteLogon, list[Row]]], list[Row]]:
    """In-window 5140 / 5145 link rows grouped by member uid, plus the share rows under no member (counted)."""
    by_member: dict[str, tuple[Hop, RemoteLogon, list[Row]]] = {}
    unattached: list[Row] = []
    for r in scan.link_rows:
        if not is_share(r):
            continue
        hit = members.find(str(r.get("host")), r.get("subject_logon_id"), r["us_raw"], sessions)
        if hit is None:
            unattached.append(r)
            continue
        h, m = hit
        by_member.setdefault(m.uid, (h, m, []))[2].append(r)
    return by_member, unattached


def _split_bursts(rows: Sequence[Row], gap_us: int) -> list[list[Row]]:
    """Cut time-ordered rows where the gap to the previous row exceeds ``gap_us`` (an equal gap joins)."""
    out: list[list[Row]] = []
    for r in sorted(rows, key=_uid_order):
        if out and r["us_raw"] - out[-1][-1]["us_raw"] <= gap_us:
            out[-1].append(r)
        else:
            out.append([r])
    return out


def _exe_names(rows: Sequence[Row]) -> list[str]:
    """``.exe`` base names of the 5145 rows, original spelling (first seen), unique case-insensitively."""
    seen: dict[str, str] = {}
    for r in rows:
        if r.get("event_id") == 5145:
            name = base_name(r.get("relative_target_name"))
            if name.lower().endswith(".exe") and name.lower() not in seen:
                seen[name.lower()] = name
    return sorted(seen.values(), key=lambda n: (n.lower(), n))


def _file_writes(rows: Sequence[Row]) -> list[tuple[str, int]]:
    """(lower-case base name, us_raw) of every 5145 with a file name: the writes ST-32 compares with F."""
    out = []
    for r in rows:
        if r.get("event_id") == 5145:
            name = base_name(r.get("relative_target_name"))
            if name:
                out.append((name.lower(), r["us_raw"]))
    return out


def share_bursts(trial_id: str, scan: ScanResult, members: MemberIndex, sessions: SessionIndex,
                 params: StitchParams = StitchParams()) -> tuple[list[ShareBurst], list[Row]]:
    """ST-30: bursts of every member logon, ids ``<trial>-b<NNNN>`` in (first corrected time, first uid) order.

    Returns (bursts, share rows under no member logon). WHY ids by corrected time: bursts on different
    target hosts then number in cross-host order, as hop ids do (ST-02).
    """
    gap_us = seconds_to_us(params.burst_gap_s)
    by_member, unattached = _member_share_rows(scan, members, sessions)
    drafts: list[tuple[Hop, RemoteLogon, list[Row]]] = []
    for h, m, rows in by_member.values():
        for part in _split_bursts(rows, gap_us):
            drafts.append((h, m, part))
    drafts.sort(key=lambda d: (min(r["us"] for r in d[2]), str(d[2][0]["event_uid"])))
    bursts = []
    for n, (h, m, part) in enumerate(drafts, start=1):
        assert m.logon_id is not None
        bursts.append(ShareBurst(
            burst_id=f"{trial_id}-b{n:04d}", host=m.host, logon_id=m.logon_id, logon_id_hex=hex_id(m.logon_id),
            member_uid=m.uid, member_machine_account=m.machine_account, logged_under_hop_id=h.hop_id,
            event_uids=sorted({u for r in part for u in _row_uids(r)}),
            first_us_raw=part[0]["us_raw"], last_us_raw=part[-1]["us_raw"], first_us=min(r["us"] for r in part),
            exe_names=_exe_names(part), file_writes=_file_writes(part)))
    return bursts, sorted(unattached, key=_uid_order)


# ---------------------------------------------------------------- installs (GT-12)

@dataclass
class Install:
    """One service install: a 4697 with its paired 7045 (if any), or a 7045 alone (GT-12 pairing).

    ``hop_id`` / ``member_uid`` are set when a member's logon ID installed it (``status`` logon_id); a 7045
    alone gets its hops from ``tie_copies`` (``tie_hop_ids``). ``binary_key`` is ``binary_name`` lower-case,
    the value ST-32 compares. ``first_us_raw`` is the install time (earliest of its 4697 / 7045).
    """
    install_id: str
    host: str
    uids_4697: list[str]
    uids_7045: list[str]
    service_name: str
    binary_name: str
    binary_key: str
    first_us_raw: int
    last_us_raw: int
    first_us: int
    subject_logon_id: int | None
    status: str
    hop_id: str | None = None
    member_uid: str = ""
    tie_hop_ids: list[str] = field(default_factory=list)
    untied_same_name_bursts: list[str] = field(default_factory=list)

    @property
    def event_uids(self) -> list[str]:
        """Every uid of the install (4697 and 7045, ST-05 copies included), sorted."""
        return sorted(set(self.uids_4697) | set(self.uids_7045))

    @property
    def can_tie(self) -> bool:
        """ST-32: a remote 4697 install or a 7045 alone may tie; a not-remote 4697 never does."""
        return self.status in (STATUS_LOGON_ID, STATUS_UNATTACHED, STATUS_TIED_7045)


def _install_status(row_4697: Row | None, members: MemberIndex, sessions: SessionIndex,
                    params: StitchParams) -> tuple[str, Hop | None, RemoteLogon | None, int | None]:
    """(status, hop, member, subject logon ID) of an install: by the 4697's SubjectLogonId in a member's
    session; a system logon ID or no member -> not remote; no 4697 -> unattached until a tie is found."""
    if row_4697 is None:
        return STATUS_UNATTACHED, None, None, None
    lid = logon_id_int(row_4697.get("subject_logon_id"))
    if lid is not None and lid in params.system_logon_ids:
        return STATUS_NOT_REMOTE_SYSTEM, None, None, lid
    hit = members.find(str(row_4697.get("host")), lid, row_4697["us_raw"], sessions)
    if hit is None:
        return STATUS_NOT_REMOTE_NO_MEMBER, None, None, lid
    return STATUS_LOGON_ID, hit[0], hit[1], lid


def _install_of(row_4697: Row | None, row_7045: Row | None, members: MemberIndex, sessions: SessionIndex,
                params: StitchParams) -> Install:
    """One ``Install`` (id set later). Service name and image path from the 4697, else the 7045."""
    rows = [r for r in (row_4697, row_7045) if r is not None]
    main = row_4697 if row_4697 is not None else row_7045
    assert main is not None
    image = main.get("service_image_path")
    if not str(image or "").strip() and row_7045 is not None:
        image = row_7045.get("service_image_path")
    name = binary_file_name(image)
    status, hop, member, lid = _install_status(row_4697, members, sessions, params)
    return Install(
        install_id="", host=str(main.get("host")),
        uids_4697=_row_uids(row_4697) if row_4697 is not None else [],
        uids_7045=_row_uids(row_7045) if row_7045 is not None else [],
        service_name=str(main.get("service_name") or "").strip(), binary_name=name, binary_key=name.lower(),
        first_us_raw=min(r["us_raw"] for r in rows), last_us_raw=max(r["us_raw"] for r in rows),
        first_us=min(r["us"] for r in rows), subject_logon_id=lid, status=status,
        hop_id=None if hop is None else hop.hop_id, member_uid="" if member is None else member.uid)


def installs(trial_id: str, scan: ScanResult, members: MemberIndex, sessions: SessionIndex,
             params: StitchParams = StitchParams(), service_pair_s: float = SERVICE_PAIR_S) -> list[Install]:
    """In-window 4697 / 7045 link rows paired with ``gate.classify.pair_services`` at the gate's tolerance,
    one ``Install`` per 4697 (with its 7045) or per unpaired 7045; ids ``<trial>-i<NNNN>`` in (first corrected
    time, first uid) order. An unpaired 4697 is an install of its own."""
    e7045 = [r for r in scan.link_rows if is_7045(r)]
    e4697 = [r for r in scan.link_rows if is_4697(r)]
    pairs = pair_services(e7045, e4697, service_pair_s)          # 7045 uid -> 4697 uid
    paired_7045_of = {v: k for k, v in pairs.items()}
    by_uid_7045 = {str(r["event_uid"]): r for r in e7045}
    out = [_install_of(r, by_uid_7045.get(paired_7045_of.get(str(r["event_uid"]), "")), members, sessions, params)
           for r in e4697]
    out += [_install_of(None, r, members, sessions, params) for r in e7045 if str(r["event_uid"]) not in pairs]
    out.sort(key=lambda i: (i.first_us, i.event_uids[0]))
    for n, inst in enumerate(out, start=1):
        inst.install_id = f"{trial_id}-i{n:04d}"
    return out


# ---------------------------------------------------------------- copy <-> install tie (ST-32)

@dataclass(frozen=True)
class Tie:
    """One ST-32 tie: install, burst, the hop it attaches to, the hop the burst was logged under, the gap from
    the burst's last same-name write to the install (ms, same host, >= 0) and the number of tied bursts of the
    install (``candidate_count``). A hop "has an ST-32 tie" (ST-47 ``service_admin_write``) when ``hop_id``
    is that hop."""
    install_id: str
    burst_id: str
    hop_id: str
    logged_under_hop_id: str
    delta_ms: int
    candidate_count: int
    method: str = METHOD_FILE_NAME_TIME


def _last_write(burst: ShareBurst, key: str) -> int | None:
    """us_raw of the burst's last 5145 whose file name equals ``key``; None when it has none."""
    times = [us for name, us in burst.file_writes if name == key]
    return max(times) if times else None


def _match(inst: Install, burst: ShareBurst, copy_us: int) -> tuple[str, int | None]:
    """``("tied", gap_us)``, ``("untied", None)`` for a same-name burst outside the limit, or ``("none", None)``.

    Tied when the burst's LAST same-name write is at or before the install and at most ``copy_us`` before it
    (both inclusive, ST-32). A burst whose last same-name write is after the install never ties.
    """
    if burst.host != inst.host or not inst.binary_key:
        return "none", None
    last = _last_write(burst, inst.binary_key)
    if last is None:
        return "none", None
    gap = inst.first_us_raw - last
    return ("tied", gap) if 0 <= gap <= copy_us else ("untied", None)


def tie_copies(installs_: Sequence[Install], bursts: Sequence[ShareBurst],
               params: StitchParams = StitchParams()) -> list[Tie]:
    """ST-32 for every install that may tie: every matching burst is tied (none is chosen); same-name bursts
    outside the limit go to ``untied_same_name_bursts``. A 4697 install ties to its own hop; a 7045 alone ties
    to the hop of each tied burst's logon and its status becomes ``tied_7045_only``. Mutates the installs'
    ``untied_same_name_bursts`` / ``tie_hop_ids`` / ``status`` and returns the ties sorted by
    (install id, burst id, hop id)."""
    copy_us = seconds_to_us(params.copy_install_s)
    ties: list[Tie] = []
    for inst in installs_:
        if not inst.can_tie:
            continue
        tied: list[tuple[ShareBurst, int]] = []
        untied: list[str] = []
        for b in bursts:
            verdict, gap = _match(inst, b, copy_us)
            if verdict == "tied" and gap is not None:
                tied.append((b, gap))
            elif verdict == "untied":
                untied.append(b.burst_id)
        inst.untied_same_name_bursts = sorted(untied)
        for b, gap in tied:
            hop_id = inst.hop_id if inst.status == STATUS_LOGON_ID else b.logged_under_hop_id
            assert hop_id is not None
            ties.append(Tie(inst.install_id, b.burst_id, hop_id, b.logged_under_hop_id, delta_ms(gap, 0), len(tied)))
        if inst.status != STATUS_LOGON_ID:
            inst.tie_hop_ids = sorted({b.logged_under_hop_id for b, _ in tied})
            inst.status = STATUS_TIED_7045 if tied else STATUS_UNATTACHED
    ties.sort(key=lambda t: (t.install_id, t.burst_id, t.hop_id))
    return ties


# ---------------------------------------------------------------- rows (ST-31..ST-34)

@dataclass
class ArtefactRow:
    """One ``hop_artefacts.csv`` row (spec 3). ``names`` and ``event_uids`` are lists (the writer joins them).
    ``ref_id`` is the burst or install id (empty otherwise), so a row can be traced to its tie records;
    ``first_us_raw`` / ``last_us_raw`` are the row's first and last event on the target host."""
    hop_id: str
    kind: str
    member_logon_uid: str
    logged_under_hop_id: str
    method: str
    candidate_count: int
    time_delta_ms: int
    supporting_span_ms: int
    confidence_tier: str
    event_uids: list[str]
    names: list[str]
    untied_same_name_bursts: list[str]
    ref_id: str
    first_us_raw: int
    last_us_raw: int


def _row(hop: Hop, kind: str, member_uid: str, logged_under: str, method: str, cc: int, tier: str,
         uids: Iterable[str], first_us_raw: int, last_us_raw: int, names: Sequence[str] = (),
         untied: Sequence[str] = (), ref_id: str = "") -> ArtefactRow:
    """An ``ArtefactRow`` with ``time_delta_ms`` = first event - hop first member 4624 and the row span (ST-34),
    both on the target's logged clock."""
    return ArtefactRow(hop_id=hop.hop_id, kind=kind, member_logon_uid=member_uid, logged_under_hop_id=logged_under,
                       method=method, candidate_count=cc, time_delta_ms=delta_ms(first_us_raw, hop.first_us_raw),
                       supporting_span_ms=delta_ms(last_us_raw, first_us_raw), confidence_tier=tier,
                       event_uids=sorted(set(uids)), names=list(names), untied_same_name_bursts=list(untied),
                       ref_id=ref_id, first_us_raw=first_us_raw, last_us_raw=last_us_raw)


def attach_bursts(bursts: Sequence[ShareBurst], ties: Sequence[Tie], hops: Mapping[str, Hop]) -> list[ArtefactRow]:
    """ST-31 / ST-32: a burst with no tie stays with its own hop (``logon_id``, A). A tied burst goes to each
    install hop of its ties: to its own hop with ``logon_id``, A (the tie is in ``ties``); to another hop with
    ``file_name_time``, B, ``candidate_count`` = the install's tied bursts, ``logged_under_hop_id`` = its own
    hop. A burst that moves is NOT also attached to its own hop unless one of its installs is its own hop's."""
    by_burst: dict[str, list[Tie]] = {}
    for t in ties:
        by_burst.setdefault(t.burst_id, []).append(t)
    out: list[ArtefactRow] = []
    for b in bursts:
        own = b.logged_under_hop_id
        targets: dict[str, int] = {}
        for t in by_burst.get(b.burst_id, []):
            targets[t.hop_id] = max(targets.get(t.hop_id, 0), t.candidate_count)
        if not targets:
            targets = {own: 1}
        for hop_id in sorted(targets):
            moved = hop_id != own
            out.append(_row(hops[hop_id], KIND_BURST, b.member_uid, own,
                            METHOD_FILE_NAME_TIME if moved else METHOD_LOGON_ID,
                            targets[hop_id] if moved else 1,
                            TIER_FILE_NAME_TIME if moved else TIER_LOGON_ID,
                            b.event_uids, b.first_us_raw, b.last_us_raw, b.exe_names, ref_id=b.burst_id))
    return out


def install_rows(installs_: Sequence[Install], ties: Sequence[Tie], hops: Mapping[str, Hop]) -> list[ArtefactRow]:
    """ST-32 install rows: a 4697 install on its logon's hop (``logon_id``, A, ``candidate_count`` 1); a 7045
    alone on each hop of its tied bursts (``file_name_time``, B, ``candidate_count`` = tied bursts, no member).
    Not-remote and unattached installs give no row. ``names`` = service name and binary file name."""
    tied_n: dict[str, int] = {}
    for t in ties:
        tied_n[t.install_id] = t.candidate_count
    out: list[ArtefactRow] = []
    for inst in installs_:
        names = [n for n in (inst.service_name, inst.binary_name) if n]
        if inst.status == STATUS_LOGON_ID and inst.hop_id is not None:
            out.append(_row(hops[inst.hop_id], KIND_INSTALL, inst.member_uid, inst.hop_id, METHOD_LOGON_ID, 1,
                            TIER_LOGON_ID, inst.event_uids, inst.first_us_raw, inst.last_us_raw, names,
                            inst.untied_same_name_bursts, inst.install_id))
        elif inst.status == STATUS_TIED_7045:
            for hop_id in inst.tie_hop_ids:
                out.append(_row(hops[hop_id], KIND_INSTALL, "", hop_id, METHOD_FILE_NAME_TIME,
                                tied_n.get(inst.install_id, 0), TIER_FILE_NAME_TIME, inst.event_uids,
                                inst.first_us_raw, inst.last_us_raw, names, inst.untied_same_name_bursts,
                                inst.install_id))
    return out


def _uid_rows(scan: ScanResult) -> dict[str, Row]:
    """Every uid (copies included) of every in-window scan row and link row -> that row."""
    out: dict[str, Row] = {}
    for r in list(scan.in_window) + list(scan.link_rows):
        for u in _row_uids(r):
            out[u] = r
    return out


def _split_uids(text: Any) -> list[str]:
    """A gate ``;``-joined uid cell as a list (blank cell -> [])."""
    return [u.strip() for u in str(text or "").split(";") if u.strip()]


def _member_triggers(hops: Sequence[Hop], gate_rows: GateRows) -> list[tuple[Hop, RemoteLogon, Row]]:
    """(hop, member, trigger row) for every gate trigger row anchored on a member (by any of its uids)."""
    by_uid: dict[str, tuple[Hop, RemoteLogon]] = {}
    for h in hops:
        for m in h.members:
            for u in set(m.event_uids) | set(m.gate_uids):
                by_uid[u] = (h, m)
    out = []
    for r in gate_rows.triggers:
        hit = by_uid.get(str(r.get("anchor_logon_uid") or "").strip())
        if hit is not None:
            out.append((hit[0], hit[1], r))
    return out


def _wsmprovhost_rows(scan: ScanResult, members: MemberIndex, sessions: SessionIndex) -> list[ArtefactRow]:
    """ST-33 ``winrm_host``: in-window wsmprovhost Sysmon 1 on the target whose ``session_id`` is a member's
    logon ID in the member's session (``logon_id``, A, 048 item 9); one row per process start."""
    out = []
    for r in scan.in_window:
        if not is_wsmprovhost_start(r):
            continue
        hit = members.find(str(r.get("host")), r.get("session_id"), r["us_raw"], sessions)
        if hit is not None:
            h, m = hit
            out.append(_row(h, KIND_WINRM_HOST, m.uid, h.hop_id, METHOD_LOGON_ID, 1, TIER_WSMPROVHOST,
                            _row_uids(r), r["us_raw"], r["us_raw"]))
    return out


def _gate_paired_rows(triggers: Sequence[tuple[Hop, RemoteLogon, Row]], uid_rows: Mapping[str, Row]
                      ) -> list[ArtefactRow]:
    """ST-33 ``winrm_91`` / ``rdp_connection``: the WinRM 91 and inbound 3389 Sysmon 3 uids of each member
    trigger row's ``supporting_event_uids``, as the gate paired them (``ip_time``, tier = the row's
    ``gate_tier``, 048 item 9); one row per (trigger row, kind). Other supporting uids are not read here."""
    out = []
    for h, m, trig in triggers:
        found: dict[str, list[Row]] = {}
        for u in _split_uids(trig.get("supporting_event_uids")):
            r = uid_rows.get(u)
            if r is None or str(r.get("host")) != h.target_host:
                continue
            kind = KIND_WINRM_91 if is_winrm91(r) else KIND_RDP if is_inbound_rdp_sysmon3(r) else None
            if kind is not None and all(x is not r for x in found.get(kind, [])):
                found.setdefault(kind, []).append(r)
        for kind, rows in sorted(found.items()):
            uids = [u for r in rows for u in _row_uids(r)]
            out.append(_row(h, kind, m.uid, h.hop_id, METHOD_IP_TIME, 1, str(trig.get("gate_tier") or ""),
                            uids, min(r["us_raw"] for r in rows), max(r["us_raw"] for r in rows)))
    return out


def other_artefacts(hopset: HopSet, scan: ScanResult, members: MemberIndex, sessions: SessionIndex,
                    gate_rows: GateRows) -> list[ArtefactRow]:
    """ST-33: ``winrm_host`` rows by session ID plus ``winrm_91`` / ``rdp_connection`` rows as the gate paired
    them."""
    triggers = _member_triggers(hopset.hops, gate_rows)
    return _wsmprovhost_rows(scan, members, sessions) + _gate_paired_rows(triggers, _uid_rows(scan))


def followup_rows(hopset: HopSet, hops: Mapping[str, Hop]) -> list[ArtefactRow]:
    """ST-26 with 048 item 9: one ``followup_logon`` row per follow-up group (``port_reuse``, C,
    ``candidate_count`` 1, no member), holding every uid of its logons. ``time_delta_ms`` is measured from the
    hop's FIRST member as the spec 3 column says (``FollowupGroup.time_delta_ms`` is from its last member)."""
    out = []
    for f in hopset.followups:
        h = hops[f.hop_id]
        uids = [u for lg in f.logons for u in lg.event_uids]
        out.append(_row(h, FOLLOWUP_KIND, "", h.hop_id, FOLLOWUP_METHOD, f.candidate_count, FOLLOWUP_TIER, uids,
                        min(lg.us_raw for lg in f.logons), max(lg.us_raw for lg in f.logons)))
    return out


# ---------------------------------------------------------------- the set

@dataclass
class ArtefactSet:
    """Artefact rows (sorted by hop id, first event time, kind, first uid), bursts, installs, ties, the per-hop
    ``service_install_count`` and ``supporting_span_ms`` (None when the hop has no artefact row), the per-hop
    diagnostics of gate supporting uids (``gate_support_moved``: shares logged under the hop's members that
    ST-32 moved to another hop; ``gate_support_not_attached``: the rest that no artefact row of the hop holds),
    and the counts."""
    rows: list[ArtefactRow]
    bursts: list[ShareBurst]
    installs: list[Install]
    ties: list[Tie]
    service_install_count: dict[str, int]
    supporting_span_ms: dict[str, int | None]
    gate_support_moved: dict[str, list[str]]
    gate_support_not_attached: dict[str, list[str]]
    counts: dict[str, Any]


def _row_order(r: ArtefactRow) -> tuple[str, int, str, str]:
    """Spec 3 order inside the file: hop id, first event (target clock), kind, first uid."""
    return r.hop_id, r.first_us_raw, r.kind, r.event_uids[0] if r.event_uids else ""


# Public name of the file order for the writer (``outputs.artefact_rows``, T7.4 task 3). WHY an alias and not a
# copy: ``hop_artefacts.csv`` must use exactly the order ``build_artefacts`` sorts by, from one definition.
row_order = _row_order


def _hop_spans(hops: Sequence[Hop], rows: Sequence[ArtefactRow]) -> dict[str, int | None]:
    """ST-34 hop span: first to last event over all its artefact rows, ms; None for a hop with none."""
    lo: dict[str, int] = {}
    hi: dict[str, int] = {}
    for r in rows:
        lo[r.hop_id] = min(lo.get(r.hop_id, r.first_us_raw), r.first_us_raw)
        hi[r.hop_id] = max(hi.get(r.hop_id, r.last_us_raw), r.last_us_raw)
    return {h.hop_id: (delta_ms(hi[h.hop_id], lo[h.hop_id]) if h.hop_id in lo else None) for h in hops}


def _gate_support(hops: Sequence[Hop], triggers: Sequence[tuple[Hop, RemoteLogon, Row]],
                  rows: Sequence[ArtefactRow]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Per hop: (gate supporting uids moved with a burst to another hop, those no artefact row holds)."""
    held: dict[str, set[str]] = {}
    for r in rows:
        held.setdefault(r.hop_id, set()).update(r.event_uids)
    moved_out: dict[str, set[str]] = {}
    for r in rows:
        if r.logged_under_hop_id != r.hop_id:
            moved_out.setdefault(r.logged_under_hop_id, set()).update(r.event_uids)
    support: dict[str, set[str]] = {}
    for h, _m, trig in triggers:
        support.setdefault(h.hop_id, set()).update(_split_uids(trig.get("supporting_event_uids")))
    moved: dict[str, list[str]] = {}
    missing: dict[str, list[str]] = {}
    for h in hops:
        s = support.get(h.hop_id, set()) - held.get(h.hop_id, set())
        mv = s & moved_out.get(h.hop_id, set())
        moved[h.hop_id] = sorted(mv)
        missing[h.hop_id] = sorted(s - mv)
    return moved, missing


def _counts(bursts: Sequence[ShareBurst], installs_: Sequence[Install], ties: Sequence[Tie],
            rows: Sequence[ArtefactRow], unattached_shares: Sequence[Row],
            service_install_count: Mapping[str, int], missing: Mapping[str, list[str]]) -> dict[str, Any]:
    """Counts of the artefact step (plan task 3; spec 10.3 comparison values)."""
    user_sessions: dict[str, int] = {}
    for b in bursts:
        if not b.member_machine_account:
            user_sessions[b.member_uid] = user_sessions.get(b.member_uid, 0) + 1
    remote = [i for i in installs_ if i.status in (STATUS_LOGON_ID, STATUS_TIED_7045)]
    tied_installs = {t.install_id for t in ties}
    kinds: dict[str, int] = {}
    for r in rows:
        kinds[r.kind] = kinds.get(r.kind, 0) + 1
    return {
        "bursts": len(bursts),
        "share_sessions": len({b.member_uid for b in bursts}),
        "user_share_sessions": len(user_sessions),
        "user_share_sessions_multi_burst": sum(1 for n in user_sessions.values() if n > 1),
        "share_events_unattached": len(unattached_shares),
        "installs_total": len(installs_),
        "installs_remote": len(remote),
        "installs_with_4697_and_7045": sum(1 for i in installs_ if i.uids_4697 and i.uids_7045),
        "installs_remote_with_4697_and_7045": sum(1 for i in remote if i.uids_4697 and i.uids_7045),
        "installs_tied": len(tied_installs),
        "installs_not_remote": sum(1 for i in installs_
                                   if i.status in (STATUS_NOT_REMOTE_SYSTEM, STATUS_NOT_REMOTE_NO_MEMBER)),
        "installs_not_remote_system_logon_id": sum(1 for i in installs_ if i.status == STATUS_NOT_REMOTE_SYSTEM),
        "installs_unattached": sum(1 for i in installs_ if i.status == STATUS_UNATTACHED),
        "ties": len(ties),
        "moved_bursts": len({r.ref_id for r in rows if r.kind == KIND_BURST and r.logged_under_hop_id != r.hop_id}),
        "untied_same_name_bursts": len({b for i in remote for b in i.untied_same_name_bursts}),
        "hops_with_more_than_one_install": sum(1 for n in service_install_count.values() if n > 1),
        "hops_with_gate_support_not_attached": sum(1 for v in missing.values() if v),
        "rows_by_kind": dict(sorted(kinds.items())),
    }


def build_artefacts(hopset: HopSet, scan: ScanResult, sessions: SessionIndex, gate_rows: GateRows,
                    params: StitchParams = StitchParams()) -> ArtefactSet:
    """ST-30..ST-34 for one trial: bursts, installs, ties, artefact rows, spans, install counts, diagnostics.

    Pure: reads only its arguments (``sessions`` through ``session_at``, which creates nothing).
    """
    hops_by_id = {h.hop_id: h for h in hopset.hops}
    members = MemberIndex(hopset.hops)
    bursts, unattached_shares = share_bursts(hopset.trial_id, scan, members, sessions, params)
    insts = installs(hopset.trial_id, scan, members, sessions, params)
    ties = tie_copies(insts, bursts, params)
    rows = (attach_bursts(bursts, ties, hops_by_id) + install_rows(insts, ties, hops_by_id)
            + other_artefacts(hopset, scan, members, sessions, gate_rows) + followup_rows(hopset, hops_by_id))
    rows.sort(key=_row_order)
    sic = {h.hop_id: 0 for h in hopset.hops}
    for r in rows:
        if r.kind == KIND_INSTALL:
            sic[r.hop_id] += 1
    triggers = _member_triggers(hopset.hops, gate_rows)
    moved, missing = _gate_support(hopset.hops, triggers, rows)
    return ArtefactSet(rows=rows, bursts=bursts, installs=insts, ties=ties, service_install_count=sic,
                       supporting_span_ms=_hop_spans(hopset.hops, rows), gate_support_moved=moved,
                       gate_support_not_attached=missing,
                       counts=_counts(bursts, insts, ties, rows, unattached_shares, sic, missing))
