"""Target-name matching, credential parsing and masking for agent command lines (AK-02, AK-13).

All functions are pure. WHY a separate module: boundary-aware matching is the crux of
the key (``192.168.50.2`` must not match ``192.168.50.22``) and is tested on its own.
"""
from __future__ import annotations

import base64
import re
from typing import Iterable, Mapping, Sequence

# Host label -> name forms accepted in a command line (case-insensitive).
HOST_NAME_FORMS: dict[str, tuple[str, ...]] = {
    "ep-01": ("ep-01", "endpoint-01"),
    "ep-02": ("ep-02", "endpoint-02"),
    "ep-03": ("ep-03", "endpoint-03"),
    "dc01": ("dc01", "dc-01"),
}
LAB_SUFFIX = r"(?:\.lab\.local)?"
_ENC_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])-(?:e|enc|ec|encodedcommand)\s+([A-Za-z0-9+/]{16,}={0,2})")
_USER_RE = re.compile(r"(?i)/user:(\S+)")
# Handles PSCredential("LAB\x",..), PSCredential('LAB\x',..) and the escaped form PSCredential(\"LAB\x\",..).
_PSCRED_RE = re.compile(r"""(?i)PSCredential\(\s*(?:\\?["'])?([^"',)]+)""")
MACHINE_OR_SYSTEM = {"system", "local service", "network service", "anonymous logon", "-", ""}


def name_pattern(host: str) -> re.Pattern[str]:
    """Regex for every name form of ``host`` with identifier boundaries on both sides."""
    forms = "|".join(re.escape(f) for f in HOST_NAME_FORMS.get(host, (host,)))
    return re.compile(rf"(?i)(?<![A-Za-z0-9_-])(?:{forms}){LAB_SUFFIX}(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9])")


def ip_pattern(ip: str) -> re.Pattern[str]:
    """Regex for a literal IPv4 that is not a prefix/suffix of a longer address."""
    return re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?!\d)(?!\.\d)")


def decode_encoded(text: str) -> tuple[list[str], bool]:
    """Decode ``-enc`` UTF-16LE base64 payloads for matching only.

    Returns (decoded strings, decode_failed). ``decode_failed`` is True when an
    ``-enc``-like token is present but does not decode to text (AKT-17).
    """
    decoded: list[str] = []
    failed = False
    for m in _ENC_RE.finditer(text):
        try:
            raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4), validate=True)
            txt = raw.decode("utf-16-le")
            if not txt or any(ord(c) < 9 for c in txt):
                raise ValueError("not text")
            decoded.append(txt)
        except Exception:  # noqa: BLE001 - any failure means "could not decode"
            failed = True
    return decoded, failed


def find_targets(texts: Iterable[str], ip_to_host: Mapping[str, str]) -> tuple[set[str], bool]:
    """Hosts named in ``texts`` (raw plus decoded), and whether a decode failed."""
    hay: list[str] = []
    failed = False
    for t in texts:
        hay.append(t)
        dec, bad = decode_encoded(t)
        hay.extend(dec)
        failed = failed or bad
    found: set[str] = set()
    for host in HOST_NAME_FORMS:
        pat = name_pattern(host)
        if any(pat.search(h) for h in hay):
            found.add(host)
    for ip, host in ip_to_host.items():
        pat = ip_pattern(ip)
        if any(pat.search(h) for h in hay):
            found.add(host)
    return found, failed


def normalise_account(name: str | None) -> str:
    """A LAB-domain-prefixed name and the bare name compare equal, case-insensitively (AK-07)."""
    if not name:
        return ""
    n = name.strip().strip("'\"").lower()
    if "\\" in n:
        n = n.split("\\", 1)[1]
    if "@" in n:
        n = n.split("@", 1)[0]
    return n


def is_user_account(name: str | None) -> bool:
    """False for system principals, ``-`` and machine accounts (trailing ``$``)."""
    n = normalise_account(name)
    return bool(n) and n not in MACHINE_OR_SYSTEM and not n.endswith("$") and not n.startswith(("umfd-", "dwm-"))


def credential_account(texts: Iterable[str]) -> str | None:
    """Account passed as ``/user:`` or ``PSCredential(...)``, before masking (decoded text too)."""
    for t in texts:
        for cand in [t, *decode_encoded(t)[0]]:
            m = _USER_RE.search(cand) or _PSCRED_RE.search(cand)
            if m:
                # an escaped quote leaves a trailing/leading backslash that is not part of the name
                return normalise_account(m.group(1).strip("\\'\" "))
    return None


def classify_protocol(text: str) -> str | None:
    """SMB, WinRM or RDP from the command text; ``None`` when the text shows none."""
    low = text.lower()
    if re.search(r"invoke-command|enter-pssession|new-pssession|winrs\b|-computername", low):
        return "WinRM"
    if re.search(r"mstsc|cmdkey\b.*termsrv|/v:\S+.*3389", low):
        return "RDP"
    if re.search(r"\\\\[^\\\s\"']+\\(admin\$|ipc\$|c\$)|sc(\.exe)?\s+\\\\|net(\.exe)?\s+use\s+\\\\|copy-item.*\\\\", low):
        return "SMB"
    return None


def artifact_names(texts: Iterable[str]) -> dict[str, list[str]]:
    """Service names, binary file names and shares the command itself carries (AK-03)."""
    services: list[str] = []
    binaries: list[str] = []
    shares: list[str] = []
    system_bins = {"powershell.exe", "sc.exe", "net.exe", "rundll32.exe", "cmd.exe"}
    for t in texts:
        services += [m.lower() for m in re.findall(r"(?i)\bsc(?:\.exe)?\"?\s+\\\\\S+\s+create\s+(\S+)", t)]
        binaries += [b.lower() for b in re.findall(r"(?i)([A-Za-z0-9_.-]+\.exe)\b", t) if b.lower() not in system_bins]
        shares += [s.lower() for s in re.findall(r"(?i)\\\\[^\\\s\"']+\\([A-Za-z0-9$]+)", t)]
    uniq = lambda xs: sorted(set(xs))  # noqa: E731
    return {"services": uniq(services), "binaries": uniq(binaries), "shares": uniq(shares)}


def mask_command(text: str) -> str:
    """Mask secrets as in log-check LC-13: value after ``/user:<acct> ``, ``-Password``,
    ``/p:`` and any ``$env:*PW*`` expansion.
    """
    out = re.sub(r"(?i)(/user:\S+\s+)(\S+)", r"\1***", text)
    out = re.sub(r"(?i)(-Password\s+)(\S+)", r"\1***", out)
    out = re.sub(r"(?i)(/p:)(\S+)", r"\1***", out)
    out = re.sub(r"(?i)\$env:[A-Za-z0-9_]*PW[A-Za-z0-9_]*", "***", out)
    return out


# Lab addressing (192.168.50.0/24); used only where the DB's Sysmon 3 rows do not show a host's address.
LAB_IP_FALLBACK = {"192.168.50.21": "ep-01", "192.168.50.22": "ep-02", "192.168.50.23": "ep-03"}


def lab_ip_to_host(rows: Sequence[Mapping]) -> dict[str, str]:
    """Map lab IPv4 -> host from Sysmon 3 (initiated) source addresses in the DB itself,
    with the fixed lab addresses as fallback (DB evidence wins)."""
    counts: dict[tuple[str, str], int] = {}
    for r in rows:
        ip = r.get("source_ip")
        if (r["channel"] == "Sysmon" and r["event_id"] == 3 and r.get("initiated") == 1 and ip
                and ip.startswith("192.168.50.")):
            counts[(ip, r["host"])] = counts.get((ip, r["host"]), 0) + 1
    best: dict[str, tuple[int, str]] = {}
    for (ip, host), n in counts.items():
        if ip not in best or n > best[ip][0]:
            best[ip] = (n, host)
    return {**LAB_IP_FALLBACK, **{ip: h for ip, (_, h) in best.items()}}
