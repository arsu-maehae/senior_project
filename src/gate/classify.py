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


def is_outbound_sysmon3(row: Mapping) -> bool:
    """Sysmon 3 logged on the connecting host (``initiated`` = 1): its remote end is ``destination_ip``.

    WHY only ``initiated`` = 1: GT-02(c) and GT-05 (decision 041) name 1 as outbound and 0 as inbound.
    A NULL ``initiated`` is treated as inbound for the address checks (``source_ip`` is judged, the
    behaviour before decision 041), but it still never pairs for R5, which needs ``initiated`` = 0.
    """
    return _is(row, "Sysmon", 3) and row.get("initiated") == 1


def is_outbound_rdp_sysmon3(row: Mapping) -> bool:
    """Outbound 3389 Sysmon 3: the source-host side of an RDP connection (GT-05, decision 041)."""
    return is_rdp_sysmon3(row) and is_outbound_sysmon3(row)


def is_own_link_local_sysmon3(row: Mapping) -> bool:
    """Outbound Sysmon 3 (``initiated`` = 1) whose ``source_ip`` is IPv6 link-local: evidence E1 (decision 042).

    WHY: an outbound connection is logged on the connecting host, so its ``source_ip`` is an
    address of that host itself.
    """
    return is_outbound_sysmon3(row) and link_local_key(row.get("source_ip")) is not None


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
    """Stripped IP text as logged, or None when blank (NULL, empty or ``-``): blank never joins (GT-18).

    For display only (the original text written in ``source_ip``); every comparison uses ``norm_ip``.
    """
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-") else text


def norm_ip(value: Any) -> str | None:
    """IP text for comparisons: stripped; blank -> None; ``::ffff:a.b.c.d`` -> ``a.b.c.d`` (spec 2, decision 041).

    WHY only the IPv4-mapped form is rewritten: Windows can log the same IPv4 peer either way, and
    the excluded list, lab IPs and R5/WinRM pairings are written as IPv4. Other text (IPv6,
    link-local with a zone, unparseable) is returned unchanged so existing exact-text comparisons
    keep their meaning.
    """
    text = ip_text(value)
    if text is None:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped) if mapped is not None else text


def norm_ip_set(values: Iterable[Any]) -> frozenset[str]:
    """A parameter list of IPs in ``norm_ip`` form, so both sides of a membership test are normalised."""
    return frozenset(ip for ip in (norm_ip(v) for v in values) if ip is not None)


def ip_kind(value: Any) -> str:
    """``ipv4`` / ``ipv6`` / ``link_local`` / ``blank`` of the normalised address (spec 3, GT-06; decision 041).

    WHY unparseable non-blank text is ``blank``: the four kinds are fixed by the spec; the raw text
    is still written in ``source_ip`` so it stays visible, and it still joins by exact text.
    IPv4-mapped IPv6 (``::ffff:a.b.c.d``) is normalised first, so it is ``ipv4``.
    """
    text = norm_ip(value)
    if text is None:
        return "blank"
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return "blank"
    if addr.version == 6 and addr.is_link_local:
        return "link_local"
    return "ipv4" if addr.version == 4 else "ipv6"


def link_local_key(value: Any) -> str | None:
    """Compressed text of an IPv6 link-local address with any ``%zone`` removed; None for any other value.

    WHY a key and not the logged text: the same address can be logged as ``fe80::1``,
    ``fe80:0:0:0:0:0:0:1`` or ``fe80::1%12``. The own-link-local match (decision 042) compares these
    keys, so a host's own address is recognised whatever form a log uses.
    """
    text = ip_text(value)
    if text is None:
        return None
    try:
        addr = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    return addr.compressed if addr.version == 6 and addr.is_link_local else None


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
    can only remove events. Several IPs on one key are joined with ``;`` (sorted). IPs are in
    ``norm_ip`` form, so the per-IP stats are keyed by the normalised address (decision 041).
    """
    excluded = norm_ip_set(params.excluded_source_ips)
    acc: dict[tuple[str, int], set[str]] = {}
    for row in logons_all:
        ip, lid = norm_ip(row.get("source_ip")), logon_id(row.get("target_logon_id"))
        if ip in excluded and lid is not None:
            acc.setdefault((row["host"], lid), set()).add(ip)
    return {k: ";".join(sorted(v)) for k, v in acc.items()}


def logon_ip_lookup(logons_all: Iterable[Mapping]) -> dict[tuple[str, int], list[str]]:
    """(host, target_logon_id) -> distinct non-blank source IPs of 4624s in the unclipped DB.

    Used only for the tier-D IP report in stats (spec 3), never to anchor or trigger. The IPs are
    the original logged texts (spec 3.1); no comparison is made with them.
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


# ---------------------------------------------------------------- GT-05 own link-local addresses (decision 042)

def _bare_account(value: Any) -> str | None:
    """Account text, lowercase, without a ``DOMAIN\\`` prefix; None when blank."""
    if value is None:
        return None
    text = str(value).strip().rsplit("\\", 1)[-1].strip().lower()
    return text or None


def host_machine_accounts(logons_all: Iterable[Mapping], params: GateParams) -> dict[str, list[str]]:
    """host -> sorted distinct machine accounts (ending ``$``) that are the SUBJECT of 4624s logged on that host
    by a system logon ID (996/997/999), from the unclipped DB.

    WHY: the subject of a 4624 opened by SYSTEM is the host's own computer account (``lab\\dc-01$`` on
    dc01). It is read from the host's own events, never from a fixed list. E2 uses it only when a host
    has exactly one such account.
    """
    acc: dict[str, set[str]] = {}
    for row in logons_all:
        lid = logon_id(row.get("subject_logon_id"))
        name = _bare_account(row.get("subject_account"))
        if lid in params.system_logon_ids and name and name.endswith("$"):
            acc.setdefault(str(row["host"]), set()).add(name)
    return {h: sorted(v) for h, v in sorted(acc.items())}


@dataclass(frozen=True)
class OwnLinkLocal:
    """Each host's own IPv6 link-local addresses found in this trial DB (decision 042).

    ``own``: (host, address key) -> evidence text (``E1``, ``E2`` or ``E1/E2``); only these are
    treated as the host's own IP by GT-05. ``report``: the stats.json ``own_link_local`` value.
    """
    own: Mapping[tuple[str, str], str]
    report: Mapping[str, Any]


def own_link_local(logons_all: Sequence[Mapping], sysmon3_all: Sequence[Mapping],
                   params: GateParams) -> OwnLinkLocal:
    """Recognise each host's own IPv6 link-local addresses from that host's own events (unclipped DB).

    - **E1:** an outbound Sysmon 3 (``initiated`` = 1) logged on host H with link-local ``source_ip`` L.
    - **E2:** a remote 4624 (type 3/10) on H from L whose account is H's own machine account
      (``host_machine_accounts``, exactly one), and **every** 4624 on H from L uses that account.
    - **Conflict:** an address with evidence on more than one host is recognised for none of them.

    WHY unclipped: like the GT-02(b) map, this lookup can only reclassify a host's own address as self;
    it never adds an event. The account is used only to recognise an address, never to link events.
    """
    e1: dict[tuple[str, str], int] = {}
    for row in sysmon3_all:
        key = link_local_key(row.get("source_ip")) if is_own_link_local_sysmon3(row) else None
        if key is not None:
            e1[(str(row["host"]), key)] = e1.get((str(row["host"]), key), 0) + 1
    machine = host_machine_accounts(logons_all, params)
    accounts: dict[tuple[str, str], list[str | None]] = {}
    remote_n: dict[tuple[str, str], int] = {}
    for row in logons_all:
        key = link_local_key(row.get("source_ip"))
        if key is None:
            continue
        hk = (str(row["host"]), key)
        accounts.setdefault(hk, []).append(_bare_account(row.get("account_name")))
        if row.get("logon_type") in REMOTE_LOGON_TYPES:
            remote_n[hk] = remote_n.get(hk, 0) + 1
    e2: dict[tuple[str, str], int] = {}
    e2_rejected: list[dict[str, Any]] = []
    for hk, names in accounts.items():
        own_acct = machine.get(hk[0], [])
        if len(own_acct) != 1 or own_acct[0] not in names or not remote_n.get(hk):
            continue
        others = sorted({n or "" for n in names if n != own_acct[0]})
        if others:
            e2_rejected.append({"host": hk[0], "address": hk[1], "machine_account": own_acct[0],
                                "other_accounts": others})
            continue
        e2[hk] = sum(1 for n in names if n == own_acct[0])
    found = sorted(set(e1) | set(e2))
    hosts_of: dict[str, set[str]] = {}
    for host, key in found:
        hosts_of.setdefault(key, set()).add(host)

    def evidence(hk: tuple[str, str]) -> str:
        return "/".join(e for e, src in (("E1", e1), ("E2", e2)) if hk in src)

    own = {hk: evidence(hk) for hk in found if len(hosts_of[hk[1]]) == 1}
    per_host: dict[str, list[dict[str, Any]]] = {}
    for hk in sorted(own):
        per_host.setdefault(hk[0], []).append({"address": hk[1], "evidence": own[hk],
                                               "e1_sysmon3": e1.get(hk, 0), "e2_4624": e2.get(hk, 0)})
    conflicts = [{"address": key, "hosts": sorted(hs),
                  "evidence": {h: evidence((h, key)) for h in sorted(hs)}}
                 for key, hs in sorted(hosts_of.items()) if len(hs) > 1]
    report = {"per_host": per_host, "conflicts": conflicts, "machine_accounts": machine,
              "e2_rejected": sorted(e2_rejected, key=lambda r: (r["host"], r["address"]))}
    return OwnLinkLocal(own, report)


# ---------------------------------------------------------------- GT-13 / GT-02(c) WinRM pairing (decision 042)

def pair_wsmprovhost_91(events: Sequence[Mapping], tol_us: int) -> dict[str, Mapping]:
    """wsmprovhost start uid -> its WinRM 91: same host, the 91 0..tol AFTER the Sysmon 1 (inclusive), one-to-one.

    WHY this order: on all six t00 DBs every pair has the Sysmon 1 first (57-666 ms, 21 distinct
    pairs) and none has the 91 first (decision 042). Starts are taken in time order (uid breaks ties);
    each takes the earliest 91 in its range that no earlier start has taken. Pure time pairing over
    every in-window start and 91, before suppression, so GT-02(c) can see an excluded 91.
    """
    w91: dict[str, list[Mapping]] = {}
    for r in events:
        if is_winrm91(r):
            w91.setdefault(str(r["host"]), []).append(r)
    taken: set[str] = set()
    out: dict[str, Mapping] = {}
    starts = sorted((r for r in events if is_wsmprovhost_start(r)), key=lambda r: (r["us"], r["event_uid"]))
    for s in starts:
        cands = [w for w in w91.get(str(s["host"]), [])
                 if w["event_uid"] not in taken and 0 <= w["us"] - s["us"] <= tol_us]
        if cands:
            w = min(cands, key=lambda r: (r["us"], r["event_uid"]))
            taken.add(w["event_uid"])
            out[s["event_uid"]] = w
    return out


def r8_anchor_index(logons: Iterable[Mapping]) -> dict[tuple[str, int], list[Mapping]]:
    """(host, logon ID) -> type 3 4624s by ``target_logon_id`` and by ``target_linked_logon_id`` (GT-13 anchors)."""
    out: dict[tuple[str, int], list[Mapping]] = {}
    for a in logons:
        if a.get("logon_type") != 3:
            continue
        for lid in {logon_id(a.get("target_logon_id")), logon_id(a.get("target_linked_logon_id"))} - {None}:
            out.setdefault((str(a["host"]), lid), []).append(a)
    return out


def r8_anchors(index: Mapping[tuple[str, int], list[Mapping]], start: Mapping) -> list[Mapping]:
    """Anchors of a wsmprovhost start: indexed 4624s with its ``session_id``, logged at or before it."""
    lid = logon_id(start.get("session_id"))
    if lid is None:
        return []
    return [a for a in index.get((str(start["host"]), lid), []) if a["us"] <= start["us"]]


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


OUTBOUND_3389_REASON = "outbound 3389, source side of an RDP connection"


def remote_address(row: Mapping) -> tuple[str, Any]:
    """(column name, logged value) of the address GT-02(a)/(c) and GT-05 judge for this event.

    WHY: an outbound Sysmon 3 (``initiated`` = 1) is logged on the connecting host, so its
    ``source_ip`` is the host itself; the other end is ``destination_ip`` (decision 041). Every
    other event (4624, WinRM 91, inbound or NULL-``initiated`` Sysmon 3) is judged by ``source_ip``.
    """
    column = "destination_ip" if is_outbound_sysmon3(row) else "source_ip"
    return column, row.get(column)


def _ip_detail(column: str, logged: Any, ip: str) -> str:
    """``<column>=<logged text>``, plus the normalised form when it differs, for reason_detail."""
    text = ip_text(logged)
    return f"{column}={text}" if text == ip else f"{column}={text};normalised={ip}"


def _ip_suppression(row: Mapping, params: GateParams,
                    own_ll: Mapping[tuple[str, str], str] | None = None) -> Suppression | None:
    """GT-02(a)/(c) by the event's own remote address, else GT-05 loopback/self (decisions 041, 042).

    The address is ``remote_address`` after ``norm_ip``; both it and the parameter lists are
    normalised, so ``::ffff:192.168.50.99`` is excluded and ``::ffff:127.0.0.1`` is loopback. The
    excluded IP is carried in normalised form for the per-IP count. An outbound 3389 Sysmon 3 that
    is neither excluded nor loopback/self is not suppressed; it ends as ``no_rule`` with
    ``OUTBOUND_3389_REASON`` (``outputs.disposition_for``). ``own_ll`` holds each host's own IPv6
    link-local addresses found in this DB (``own_link_local``, decision 042): such an address is
    the host's own IP, reason ``own link-local (E1)``, ``(E2)`` or ``(E1/E2)``.
    """
    column, logged = remote_address(row)
    ip = norm_ip(logged)
    if ip is None:
        return None
    detail = _ip_detail(column, logged, ip)
    if ip in norm_ip_set(params.excluded_source_ips):
        return Suppression("excluded_source_ip", detail, ip)
    if ip in norm_ip_set(params.loopback):
        return Suppression("loopback_or_self", f"{detail};loopback")
    if ip == norm_ip(params.lab_host_ips.get(str(row.get("host")))):
        return Suppression("loopback_or_self", f"{detail};own_host_ip")
    key = link_local_key(ip)
    evidence = (own_ll or {}).get((str(row.get("host")), key)) if key is not None else None
    if evidence:
        return Suppression("loopback_or_self", f"{detail};own link-local ({evidence})")
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


def _winrm_session_suppression(row: Mapping, wsm_pairs: Mapping[str, Mapping], anchored: frozenset[str],
                               params: GateParams) -> Suppression | None:
    """GT-02(c) (decision 042): a wsmprovhost start whose paired WinRM 91 (``pair_wsmprovhost_91``) has an
    excluded clientIP and which has no tier-A anchor (a remote type 3 4624 that survived GT-02..05, so
    its IP is not excluded) -> excluded. WHY the anchor check: a lab-IP logon behind the process
    decides, never the time pairing alone.
    """
    if not is_wsmprovhost_start(row) or row["event_uid"] in anchored:
        return None
    w = wsm_pairs.get(row["event_uid"])
    ip = norm_ip(w.get("source_ip")) if w is not None else None
    if ip is None or ip not in norm_ip_set(params.excluded_source_ips):
        return None
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


def own_suppression(row: Mapping, excl_map: Mapping[tuple[str, int], str], wsm_pairs: Mapping[str, Mapping],
                    anchored: frozenset[str], params: GateParams,
                    own_ll: Mapping[tuple[str, str], str] | None = None) -> Suppression | None:
    """GT-02(a-c), GT-03, GT-04, GT-05 for one event, in the disposition precedence order (spec 3).

    Pairing-based exclusion of a 7045 (GT-02(d), GT-04) is applied afterwards by ``suppress_all``
    because it depends on the 4697's own result. ``wsm_pairs`` / ``anchored`` feed GT-02(c) and
    ``own_ll`` feeds GT-05 (decision 042).
    """
    ip_sup = _ip_suppression(row, params, own_ll)
    if ip_sup and ip_sup.disposition == "excluded_source_ip":
        return ip_sup
    sess = (_session_suppression(row, excl_map)
            or _winrm_session_suppression(row, wsm_pairs, anchored, params))
    if sess:
        return sess
    if is_4624(row) and row.get("logon_type") in INTERACTIVE_LOGON_TYPES:
        return Suppression("interactive_logon", f"logon_type={row.get('logon_type')}")
    return _system_suppression(row, params) or ip_sup


def suppress_all(events: Sequence[Mapping], excl_map: Mapping[tuple[str, int], str],
                 service_pairs: Mapping[str, str], params: GateParams,
                 own_ll: Mapping[tuple[str, str], str] | None = None,
                 wsm_pairs: Mapping[str, Mapping] | None = None) -> dict[str, Suppression]:
    """uid -> Suppression for every in-window event removed by GT-02..GT-05 (others absent).

    4624s are judged first: whether a wsmprovhost start has a tier-A anchor (GT-02(c), decision 042)
    depends on which type 3 logons survive, and a 4624's own result never depends on a Sysmon 1.
    A 7045 paired with an excluded or system 4697 becomes ``paired_excluded`` (GT-02(d), GT-04),
    carrying the 4697's excluded IP for the per-IP count.
    """
    if wsm_pairs is None:
        wsm_pairs = pair_wsmprovhost_91(events, seconds_to_us(params.winrm_pair_s))
    out: dict[str, Suppression] = {}
    logons = [r for r in events if is_4624(r)]
    for row in logons:
        sup = own_suppression(row, excl_map, wsm_pairs, frozenset(), params, own_ll)
        if sup:
            out[row["event_uid"]] = sup
    index = r8_anchor_index([r for r in logons if r.get("logon_type") in REMOTE_LOGON_TYPES
                             and r["event_uid"] not in out])
    anchored = frozenset(r["event_uid"] for r in events if is_wsmprovhost_start(r) and r8_anchors(index, r))
    for row in events:
        if is_4624(row):
            continue
        sup = own_suppression(row, excl_map, wsm_pairs, anchored, params, own_ll)
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
