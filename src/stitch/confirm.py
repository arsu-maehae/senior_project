"""Confirmation of a hop (spec 03_stitch ST-47; decisions 013, 015, 048 item 11).

``kerberos_logonguid``: a member 4624's LogonGuid equals the LogonGuid of an in-window dc01 4769. It confirms the
account and the target service of a Kerberos hop; it NEVER finds or sets the source session (Correction I:
"LogonGuid only confirms Kerberos hops"). NTLM SMB hops have no LogonGuid, so they have none.
``service_admin_write``: the hop has an ST-32 copy <-> install tie (``artefacts.Tie``).

WHY pure: the inputs are the members, the scan's in-window link rows and the artefact set; nothing here opens a
file, reads a session index or touches command text.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from gate.params import GateParams

from .artefacts import ArtefactSet
from .hops import Hop, RemoteLogon

__all__ = ["DC_HOST", "CONFIRM_KERBEROS", "CONFIRM_SERVICE", "CONFIRM_BOTH", "CONFIRM_NONE", "norm_logon_guid",
           "kerberos_confirm", "service_admin_write", "confirm_of"]

Row = Mapping[str, Any]

# ST-47 names "a dc01 4769". The host is the lab's domain controller as spelled in ``lab_host_ips`` (gate params,
# spec 5 "one definition") and in the DB ``host`` column. WHY a constant checked at import, not a lookup by a
# naming pattern: the lab has exactly one DC and its name is fixed; if the gate's host list ever renames it, the
# import fails instead of silently confirming nothing.
DC_HOST = "dc01"
if DC_HOST not in GateParams().lab_host_ips:
    raise ImportError(f"confirm.DC_HOST {DC_HOST!r} is not a lab host of gate.params.lab_host_ips")

CONFIRM_KERBEROS = "kerberos_logonguid"
CONFIRM_SERVICE = "service_admin_write"
CONFIRM_BOTH = f"{CONFIRM_KERBEROS};{CONFIRM_SERVICE}"
CONFIRM_NONE = "none"


def norm_logon_guid(value: Any) -> str | None:
    """A LogonGuid for comparison: stripped, braces removed, lower case (048 item 11). None for NULL / empty
    and for the all-zero GUID, which Windows writes when there is no Kerberos logon and so never confirms."""
    if value is None:
        return None
    text = str(value).strip().strip("{}").strip().lower()
    if not text or set(text.replace("-", "")) <= {"0"}:
        return None
    return text


def _row_uids(row: Row) -> list[str]:
    """Every uid of a scan row (ST-05 copies included)."""
    return [str(u) for u in (row.get("event_uids") or [row.get("event_uid")])]


def _is_dc_4769(row: Row, dc_host: str) -> bool:
    """A Security 4769 logged on the DC and inside the window (link rows are in-window by construction; a
    hand-built row with ``in_window`` False is refused too)."""
    return (row.get("channel") == "Security" and row.get("event_id") == 4769
            and str(row.get("host")) == dc_host and bool(row.get("in_window", True)))


def kerberos_confirm(members: Iterable[RemoteLogon], link_rows: Iterable[Row], dc_host: str = DC_HOST) -> list[str]:
    """ST-47: the uids (sorted, ST-05 copies included) of the in-window dc01 4769 link rows whose normalised
    LogonGuid equals a member's normalised LogonGuid; [] when none. A NULL or all-zero GUID never confirms.

    It reads no session and returns no session: the confirmation never sets a source session (STT-10).

    Note (048 item 11, "a match whose 4769 lies outside the window is counted, not used"): the scan keeps no
    out-of-window link row (ST-01; they are only counted per host and type in ``removed_by_window``), so such a
    match cannot be counted from the scan. It is reported to the owner for an amendment of 048; counting it would
    need a separate read of pre-/post-window 4769 GUIDs.
    """
    guids = {g for g in (norm_logon_guid(m.logon_guid) for m in members) if g is not None}
    if not guids:
        return []
    out: set[str] = set()
    for r in link_rows:
        if _is_dc_4769(r, dc_host) and norm_logon_guid(r.get("logon_guid")) in guids:
            out.update(_row_uids(r))
    return sorted(out)


def service_admin_write(hop_id: str, artefact_set: ArtefactSet) -> list[str]:
    """ST-47 ``service_admin_write`` evidence: the install uids (4697 / 7045) and the burst uids of every ST-32
    tie whose install belongs to ``hop_id`` (``Tie.hop_id``: the install's hop, or for a 7045 alone the hop of
    the tied burst's logon). Sorted, unique; [] when the hop has no tie."""
    installs = {i.install_id: i for i in artefact_set.installs}
    bursts = {b.burst_id: b for b in artefact_set.bursts}
    out: set[str] = set()
    for t in artefact_set.ties:
        if t.hop_id != hop_id:
            continue
        out.update(installs[t.install_id].event_uids)
        out.update(bursts[t.burst_id].event_uids)
    return sorted(out)


def confirm_of(hop: Hop, link_rows: Sequence[Row], artefact_set: ArtefactSet,
               dc_host: str = DC_HOST) -> tuple[str, list[str]]:
    """(``confirm``, ``confirm_event_uids``) of a hop (spec 3 ``hops.csv``): ``kerberos_logonguid``,
    ``service_admin_write``, both joined by ``;`` (Kerberos first), or ``none``; the uids of both, sorted."""
    krb = kerberos_confirm(hop.members, link_rows, dc_host)
    svc = service_admin_write(hop.hop_id, artefact_set)
    label = (CONFIRM_BOTH if krb and svc else CONFIRM_KERBEROS if krb else CONFIRM_SERVICE if svc
             else CONFIRM_NONE)
    return label, sorted(set(krb) | set(svc))
