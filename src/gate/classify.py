"""Event predicates, IP handling, service pairing and the suppression steps GT-02..GT-05 (spec 02_gate 4).

WHY pure functions on row dicts: every rule decision must be testable on synthetic rows and
traceable to the uids involved, so nothing here reads a file or keeps state between calls.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .params import GateParams
from .timeutil import seconds_to_us

Row = dict[str, Any]

WSMPROVHOST = "\\wsmprovhost.exe"
LSASS = "\\lsass.exe"
RDP_PORT = 3389
REMOTE_LOGON_TYPES = (3, 10)
INTERACTIVE_LOGON_TYPES = (2, 11)
DISPOSITION_LOGON_TYPES = (2, 3, 10, 11)


# ---------------------------------------------------------------- event kinds

def _is(row: Mapping, channel: str, event_id: int) -> bool:
    """Channel and event id together: event ids alone collide across channels."""
    return row.get("channel") == channel and row.get("event_id") == event_id


def is_4624(row: Mapping) -> bool:
    return _is(row, "Security", 4624)


def is_4648(row: Mapping) -> bool:
    return _is(row, "Security", 4648)


def is_4697(row: Mapping) -> bool:
    return _is(row, "Security", 4697)


def is_share(row: Mapping) -> bool:
    """5140 or 5145; both count as share access for R4 and the "share event" of GT-02 artefacts."""
    return row.get("channel") == "Security" and row.get("event_id") in (5140, 5145)


def is_7045(row: Mapping) -> bool:
    return _is(row, "System", 7045)


def is_winrm91(row: Mapping) -> bool:
    return _is(row, "WinRM", 91)


def ends_with(path: Any, suffix: str) -> bool:
    """Case-insensitive path suffix test; Windows paths vary in case between logs."""
    return isinstance(path, str) and path.strip().lower().endswith(suffix)


def is_wsmprovhost_start(row: Mapping) -> bool:
    """Sysmon 1 whose ``image`` is wsmprovhost: the R8 trigger (decision 038, image only)."""
    return _is(row, "Sysmon", 1) and ends_with(row.get("image"), WSMPROVHOST)


def is_wsmprovhost_child(row: Mapping) -> bool:
    """Sysmon 1 whose ``parent_image`` (not ``image``) is wsmprovhost: R8_parent supporting signal."""
    return (_is(row, "Sysmon", 1) and ends_with(row.get("parent_image"), WSMPROVHOST)
            and not ends_with(row.get("image"), WSMPROVHOST))


def is_rdp_sysmon3(row: Mapping) -> bool:
    """Sysmon 3 to destination port 3389 (any direction): the disposition set of spec 3."""
    return _is(row, "Sysmon", 3) and row.get("destination_port") == RDP_PORT


def is_inbound_rdp_sysmon3(row: Mapping) -> bool:
    """Inbound (``initiated`` = 0) 3389 Sysmon 3: the only kind that can pair with a 4624 (GT-11)."""
    return is_rdp_sysmon3(row) and row.get("initiated") == 0


def is_lsass_access(row: Mapping) -> bool:
    """Sysmon 10 into lsass.exe (any access mask; the mask test is in ``is_r1``)."""
    return _is(row, "Sysmon", 10) and ends_with(row.get("target_image"), LSASS)


def is_trigger_type(row: Mapping) -> bool:
    """Events that get exactly one dispositions.csv row (spec 3, amended by decision 041 for type 2/11)."""
    if is_4624(row):
        return row.get("logon_type") in DISPOSITION_LOGON_TYPES
    return (is_share(row) or is_7045(row) or is_4697(row) or is_winrm91(row) or is_rdp_sysmon3(row)
            or (_is(row, "Sysmon", 1) and (ends_with(row.get("image"), WSMPROVHOST)
                                           or ends_with(row.get("parent_image"), WSMPROVHOST))))


def is_kept_type(row: Mapping) -> bool:
    """Events the gate keeps after the clip: trigger types plus supporting-signal sources (4648, Sysmon 10)."""
    return is_trigger_type(row) or is_4648(row) or is_lsass_access(row)


# ---------------------------------------------------------------- IPs and logon IDs

def ip_text(value: Any) -> str | None:
    """Stripped IP text, or None when blank (NULL, empty or ``-``): blank never joins (GT-18)."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-") else text


def ip_kind(value: Any) -> str:
    """``ipv4`` / ``ipv6`` / ``link_local`` / ``blank`` (spec 3, GT-06).

    WHY unparseable non-blank text is ``blank``: the four kinds are fixed by the spec; the raw text
    is still written in ``source_ip`` so it stays visible, and it still joins by exact text.
    IPv4-mapped IPv6 (``::ffff:a.b.c.d``) is ``ipv6``, as ``ipaddress`` parses it.
    """
    text = ip_text(value)
    if text is None:
        return "blank"
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return "blank"
    if addr.version == 6 and addr.is_link_local:
        return "link_local"
    return "ipv4" if addr.version == 4 else "ipv6"


def logon_id(value: Any) -> int | None:
    """Logon ID as int, None if NULL (logon ID 0 is stored as NULL, decision 005): NULL never joins."""
    if value is None or value == "":
        return None
    return int(value)


def logon_hex(value: Any) -> str:
    """Display form ``0x`` + lowercase hex (D1); empty for NULL."""
    lid = logon_id(value)
    return "" if lid is None else f"0x{lid:x}"


def is_r1(row: Mapping, params: GateParams) -> bool:
    """R1: lsass access with a mask in the R1 set; masks compared as ints (hex case, leading zeros ignored)."""
    if not is_lsass_access(row):
        return False
    text = str(row.get("granted_access") or "").strip()
    try:
        return int(text, 16) in params.r1_access_masks
    except ValueError:
        return False


def within(a_us: int, b_us: int, tol_us: int) -> bool:
    """|a - b| <= tol, inclusive, either order (decision 041)."""
    return abs(a_us - b_us) <= tol_us


# ---------------------------------------------------------------- GT-02 map (unclipped)

def excluded_logon_map(logons_all: Iterable[Mapping], params: GateParams) -> dict[tuple[str, int], str]:
    """(host, target_logon_id) -> excluded IP(s) of every 4624 from a non-lab workstation, any time.

    WHY unclipped: a session opened before the window can still act inside it (GT-02(b)); the map
    can only remove events. Several IPs on one key are joined with ``;`` (sorted).
    """
    acc: dict[tuple[str, int], set[str]] = {}
    for row in logons_all:
        ip, lid = ip_text(row.get("source_ip")), logon_id(row.get("target_logon_id"))
        if ip in params.excluded_source_ips and lid is not None:
            acc.setdefault((row["host"], lid), set()).add(ip)
    return {k: ";".join(sorted(v)) for k, v in acc.items()}


def logon_ip_lookup(logons_all: Iterable[Mapping]) -> dict[tuple[str, int], list[str]]:
    """(host, target_logon_id) -> distinct non-blank source IPs of 4624s in the unclipped DB.

    Used only for the tier-D IP report in stats (spec 3), never to anchor or trigger.
    """
    acc: dict[tuple[str, int], set[str]] = {}
    for row in logons_all:
        lid = logon_id(row.get("target_logon_id"))
        if lid is None:
            continue
        ips = acc.setdefault((row["host"], lid), set())
        ip = ip_text(row.get("source_ip"))
        if ip is not None:
            ips.add(ip)
    return {k: sorted(v) for k, v in acc.items()}


# ---------------------------------------------------------------- GT-12 pairing

def _service_name(row: Mapping) -> str | None:
    """Service name for pairing: exact string after strip (case kept, owner rule 9); blank never pairs."""
    name = row.get("service_name")
    if name is None:
        return None
    name = str(name).strip()
    return name or None


def pair_services(e7045: Sequence[Mapping], e4697: Sequence[Mapping], tol_s: float) -> dict[str, str]:
    """7045 uid -> 4697 uid: same host, same service_name (exact after strip), |dt| <= tol, one-to-one.

    WHY greedy by distance: decision 041 says a 7045 pairs with the *nearest* same-name 4697 and
    each event is used once; sorting all candidate pairs by (|dt|, 7045 uid, 4697 uid) and taking
    them in order gives that, with ties broken by uid so the result is reproducible.
    """
    tol = seconds_to_us(tol_s)
    by_key: dict[tuple[str, str], list[Mapping]] = {}
    for b in e4697:
        name = _service_name(b)
        if name is not None:
            by_key.setdefault((b["host"], name), []).append(b)
    cands: list[tuple[int, str, str]] = []
    for a in e7045:
        name = _service_name(a)
        for b in by_key.get((a["host"], name), []) if name is not None else []:
            if within(a["us"], b["us"], tol):
                cands.append((abs(a["us"] - b["us"]), a["event_uid"], b["event_uid"]))
    cands.sort()
    pairs: dict[str, str] = {}
    used: set[str] = set()
    for _d, a_uid, b_uid in cands:
        if a_uid not in pairs and b_uid not in used:
            pairs[a_uid] = b_uid
            used.add(b_uid)
    return pairs


# ---------------------------------------------------------------- GT-02..GT-05

@dataclass(frozen=True)
class Suppression:
    """Why an event was removed before the rules: disposition, readable detail, excluded IP (if any)."""
    disposition: str
    detail: str
    excluded_ip: str | None = None


def _ip_suppression(row: Mapping, params: GateParams) -> Suppression | None:
    """GT-02(a)/(c) by the event's own remote address, else GT-05 loopback/self.

    GT-02(c) for Sysmon 3 applies to inbound connections only (the remote end is ``source_ip``);
    GT-05 applies to every event carrying a ``source_ip`` (4624, WinRM 91, Sysmon 3), as written,
    so an outbound 3389 Sysmon 3 (source = this host) is ``loopback_or_self``.
    """
    ip = ip_text(row.get("source_ip"))
    if ip is None:
        return None
    sysmon3 = _is(row, "Sysmon", 3)
    if ip in params.excluded_source_ips and (not sysmon3 or row.get("initiated") == 0):
        return Suppression("excluded_source_ip", f"source_ip={ip}", ip)
    if ip in params.loopback:
        return Suppression("loopback_or_self", f"source_ip={ip};loopback")
    if ip == params.lab_host_ips.get(str(row.get("host"))):
        return Suppression("loopback_or_self", f"source_ip={ip};own_host_ip")
    return None


def _session_suppression(row: Mapping, excl_map: Mapping[tuple[str, int], str]) -> Suppression | None:
    """GT-02(b): 5140/5145/4697 by subject_logon_id, Sysmon 1 by session_id, tied to an excluded logon."""
    if is_share(row) or is_4697(row):
        lid = logon_id(row.get("subject_logon_id"))
    elif _is(row, "Sysmon", 1):
        lid = logon_id(row.get("session_id"))
    else:
        return None
    ip = excl_map.get((row["host"], lid)) if lid is not None else None
    if ip is None:
        return None
    return Suppression("excluded_source_ip_session", f"logon_id=0x{lid:x};source_ip={ip}", ip)


def _winrm_session_suppression(row: Mapping, excluded_91: Sequence[Mapping], tol_us: int) -> Suppression | None:
    """GT-02(c): wsmprovhost start on the same host 0-5 s after an excluded WinRM 91 (latest such 91 named)."""
    if not is_wsmprovhost_start(row):
        return None
    hits = [w for w in excluded_91 if w["host"] == row["host"] and 0 <= row["us"] - w["us"] <= tol_us]
    if not hits:
        return None
    w = max(hits, key=lambda r: (r["us"], r["event_uid"]))
    ip = ip_text(w.get("source_ip"))
    return Suppression("excluded_source_ip_session", f"winrm91={w['event_uid']};source_ip={ip}", ip)


def _system_suppression(row: Mapping, params: GateParams) -> Suppression | None:
    """GT-04: the event's own logon ID is 996/997/999 (4624 target, 4697 subject, Sysmon 1 session)."""
    if is_4624(row):
        lid = logon_id(row.get("target_logon_id"))
    elif is_4697(row):
        lid = logon_id(row.get("subject_logon_id"))
    elif _is(row, "Sysmon", 1):
        lid = logon_id(row.get("session_id"))
    else:
        return None
    if lid is not None and lid in params.system_logon_ids:
        return Suppression("system_logon_id", f"logon_id=0x{lid:x}")
    return None


def own_suppression(row: Mapping, excl_map: Mapping[tuple[str, int], str], excluded_91: Sequence[Mapping],
                    params: GateParams) -> Suppression | None:
    """GT-02(a-c), GT-03, GT-04, GT-05 for one event, in the disposition precedence order (spec 3).

    Pairing-based exclusion of a 7045 (GT-02(d), GT-04) is applied afterwards by ``suppress_all``
    because it depends on the 4697's own result.
    """
    ip_sup = _ip_suppression(row, params)
    if ip_sup and ip_sup.disposition == "excluded_source_ip":
        return ip_sup
    sess = (_session_suppression(row, excl_map)
            or _winrm_session_suppression(row, excluded_91, seconds_to_us(params.winrm_pair_s)))
    if sess:
        return sess
    if is_4624(row) and row.get("logon_type") in INTERACTIVE_LOGON_TYPES:
        return Suppression("interactive_logon", f"logon_type={row.get('logon_type')}")
    return _system_suppression(row, params) or ip_sup


def suppress_all(events: Sequence[Mapping], excl_map: Mapping[tuple[str, int], str],
                 service_pairs: Mapping[str, str], params: GateParams) -> dict[str, Suppression]:
    """uid -> Suppression for every in-window event removed by GT-02..GT-05 (others absent).

    A 7045 paired with an excluded or system 4697 becomes ``paired_excluded`` (GT-02(d), GT-04),
    carrying the 4697's excluded IP for the per-IP count.
    """
    excluded_91 = [r for r in events if is_winrm91(r) and ip_text(r.get("source_ip")) in params.excluded_source_ips]
    out: dict[str, Suppression] = {}
    for row in events:
        sup = own_suppression(row, excl_map, excluded_91, params)
        if sup:
            out[row["event_uid"]] = sup
    for uid_7045, uid_4697 in service_pairs.items():
        sup_4697 = out.get(uid_4697)
        if sup_4697 and sup_4697.disposition in ("excluded_source_ip_session", "system_logon_id",
                                                 "excluded_source_ip"):
            out[uid_7045] = Suppression("paired_excluded",
                                        f"service_name_time;paired_4697={uid_4697};{sup_4697.disposition}",
                                        sup_4697.excluded_ip)
    return out


def is_remote_logon(row: Mapping, suppressed: Mapping[str, Suppression]) -> bool:
    """GT-06: a 4624 type 3/10 not removed by GT-02..05 (any ip_kind, blank and link-local included)."""
    return is_4624(row) and row.get("logon_type") in REMOTE_LOGON_TYPES and row["event_uid"] not in suppressed
