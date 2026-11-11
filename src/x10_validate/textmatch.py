"""Command-line reading: -enc decoding, target naming, protocol and payload names.

WHY: decision 029 counts a command step only if the command names the target. WinRM targets sit
past any display cut and sometimes inside a base64 ``-enc`` payload (agent_evidence.md, finding 6),
and 192.168.50.2 must never be read as 192.168.50.22, so matching is boundary-aware on full text.
"""
from __future__ import annotations

import base64
import binascii
import json
import re

from .params import ENDPOINTS, HOST_IP, TOOL_BINARIES

_ENC = re.compile(r"(?:^|\s)-e(?:c|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", re.I)


def decode_enc(command_line: str | None) -> tuple[str, bool]:
    """Full text used for matching: the command line plus any decoded -enc payload.

    Returns (text, decode_failed). The decoded text is used for matching only, never stored.
    """
    text = command_line or ""
    failed = False
    for m in _ENC.finditer(text):
        try:
            text += "\n" + base64.b64decode(m.group(1), validate=False).decode("utf-16le")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            failed = True
    return text, failed


def _host_pattern(host: str) -> re.Pattern[str]:
    """Regex for every name form of one endpoint (ep-0N, endpoint-0N, FQDN, IP), boundary-aware."""
    n = host[-1]
    ip = re.escape(HOST_IP[host])
    names = rf"(?<![A-Za-z0-9-])(?:ep|endpoint)-0{n}(?![A-Za-z0-9-])"
    return re.compile(rf"(?<![\d.]){ip}(?![\d])|{names}", re.I)


_HOST_RE: dict[str, re.Pattern[str]] = {h: _host_pattern(h) for h in ENDPOINTS}


def named_hosts(text: str) -> set[str]:
    """Endpoints named anywhere in ``text``."""
    return {h for h, rx in _HOST_RE.items() if rx.search(text)}


def _unc_pattern(host: str) -> re.Pattern[str]:
    n = host[-1]
    ip = re.escape(HOST_IP[host])
    return re.compile(rf"\\\\(?:{ip}|(?:ep|endpoint)-0{n}(?:\.lab\.local)?)(?![\d.A-Za-z-])", re.I)


_UNC_RE: dict[str, re.Pattern[str]] = {h: _unc_pattern(h) for h in ENDPOINTS}
_WINRM_RE = re.compile(r"invoke-command|new-pssession|enter-pssession|\bwinrs\b|wsman|-computername\b", re.I)
_PSEXEC_RE = re.compile(r"psexec", re.I)


def protocols(text: str, target: str) -> set[str]:
    """Protocols a command uses towards ``target`` (SMB via UNC path or psexec, WinRM via PS remoting)."""
    out: set[str] = set()
    if _UNC_RE[target].search(text) or _PSEXEC_RE.search(text):
        out.add("SMB")
    if _WINRM_RE.search(text):
        out.add("WinRM")
    return out


_EXE_RE = re.compile(r"([A-Za-z0-9_.-]+\.(?:exe|dll))\b", re.I)
_SVC_RE = re.compile(r"\bsc(?:\.exe)?\s+\\\\\S+\s+(?:create|start|config)\s+\"?([A-Za-z0-9_.-]+)", re.I)
_NEWSVC_RE = re.compile(r"new-service\b[^;]*?-name\s+['\"]?([A-Za-z0-9_.-]+)", re.I)


def payload_names(text: str) -> set[str]:
    """Lower-case payload binary and service names a command mentions (tools excluded).

    WHY: names tie a command to its target-side 5145/7045/4697 (spec 07 AK-03 style binding by content),
    which separates two moves to one target (S07 X/Y, S04 Track A/B) better than time alone.
    """
    names = {m.group(1).lower() for m in _EXE_RE.finditer(text)} - TOOL_BINARIES
    names |= {m.group(1).lower() for m in _SVC_RE.finditer(text)}
    names |= {m.group(1).lower() for m in _NEWSVC_RE.finditer(text)}
    return {n for n in names if n not in {"comsvcs.dll"}}


_CRED_RE = re.compile(r"/user:(?:[A-Za-z0-9_.-]+\\)?([A-Za-z0-9_.$-]+)|PSCredential\(\s*[\"'\\]*(?:[A-Za-z0-9_.-]+\\+)?([A-Za-z0-9_.$-]+)", re.I)


def credential_accounts(text: str) -> set[str]:
    """Accounts a command asks for (``/user:`` or ``PSCredential``); reported, never matched (decision 027)."""
    out: set[str] = set()
    for m in _CRED_RE.finditer(text):
        out.add((m.group(1) or m.group(2)).lower())
    return out


def norm_account(name: str | None) -> str:
    """``LAB\\x`` -> ``x``, lower case."""
    return (name or "").split("\\")[-1].strip().lower()


def field(fv_json: str | None, key: str) -> str | None:
    """First value of ``key`` in the parser's ``field_values_json`` (lists of strings)."""
    if not fv_json:
        return None
    try:
        val = json.loads(fv_json).get(key)
    except (ValueError, AttributeError):
        return None
    if isinstance(val, list):
        return str(val[0]) if val else None
    return None if val is None else str(val)


_WINRM_URI = re.compile(r"\(([^\s()]*)\s+clientIP:\s*([^\s)]+)\)", re.I)


def winrm91_client(fv_json: str | None) -> tuple[str | None, str | None]:
    """(account, clientIP) from a WinRM 91 resourceUri such as ``(LAB\\admin_it clientIP: 192.168.50.21)``."""
    uri = field(fv_json, "resourceuri") or ""
    m = _WINRM_URI.search(uri)
    if not m:
        return None, None
    return norm_account(m.group(1).replace("\\\\", "\\")), m.group(2)
