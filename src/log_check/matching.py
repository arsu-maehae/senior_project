"""Pure text helpers: target-name matching, PowerShell -EncodedCommand decoding, masking.

Why these are separate and pure: they decide whether a source command is evidence for a
hop (LC-04), so the tester must be able to probe them with synthetic strings (LCT-04,
LCT-05, LCT-12) without a database.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable

MASK = "***"

# A name must not be glued to other name characters: `192.168.50.2` must not match inside
# `192.168.50.22`, `ep-0` must not match `ep-02`. A following `.label` is allowed so that
# `ep-02.lab.local` matches `ep-02`, but `.digit` is not (IP continuation).
_BEFORE = r"(?<![\w.\-])"
_AFTER = r"(?![\w\-]|\.\d)"

_ENCODED_SWITCH = "encodedcommand"
# PowerShell accepts any unambiguous prefix of -EncodedCommand (and -ec, -e).
_ENC_PREFIXES = sorted({"e", "ec"} | {_ENCODED_SWITCH[:n] for n in range(2, len(_ENCODED_SWITCH) + 1)},
                       key=len, reverse=True)
# The payload is captured as any non-space token so that a malformed payload is still seen
# (and reported as undecodable, reason c) instead of silently not matching the regex.
_ENC_RE = re.compile(
    r"(?i)(?:^|\s)[-/](?:" + "|".join(_ENC_PREFIXES) + r")\s+['\"]?([^\s'\"]+)['\"]?(?=\s|$)"
)
_POWERSHELL_RE = re.compile(r"(?i)powershell|pwsh")
_PRINTABLE_SHARE = 0.8  # decoded text below this share of printable chars is treated as undecodable


def target_name_forms(target_host: str, target_ip: str | None) -> tuple[str, ...]:
    """Names a command line may use for a host: `ep-0N`, `endpoint-0N` (the Windows name), the IP.

    `dc01` also gets `dc-01` (its Windows name, seen as the `dc-01$` machine account).
    """
    forms: list[str] = [target_host]
    match = re.fullmatch(r"ep-(\d+)", target_host)
    if match:
        forms.append(f"endpoint-{match.group(1)}")
    elif target_host == "dc01":
        forms.append("dc-01")
    if target_ip:
        forms.append(target_ip)
    return tuple(forms)


@lru_cache(maxsize=256)
def _name_regex(forms: tuple[str, ...]) -> re.Pattern[str]:
    """One compiled alternation per target; cached because it is reused for every command."""
    alternation = "|".join(re.escape(f) for f in sorted(forms, key=len, reverse=True))
    return re.compile(_BEFORE + "(?:" + alternation + ")" + _AFTER, re.IGNORECASE)


def names_target(text: str | None, forms: tuple[str, ...]) -> bool:
    """Case-insensitive, boundary-aware: does `text` name any of the target's forms?"""
    if not text or not forms:
        return False
    return _name_regex(forms).search(text) is not None


def encoded_payloads(command_line: str | None) -> list[str]:
    """Base64 tokens passed to -e/-ec/-enc/-EncodedCommand (any accepted prefix).

    Only PowerShell command lines are inspected: other tools also have an `-e` switch, and
    treating their arguments as payloads would turn reason (b) into a false reason (c).
    """
    if not command_line or not _POWERSHELL_RE.search(command_line):
        return []
    return [m.group(1) for m in _ENC_RE.finditer(command_line)]


def decode_powershell_b64(token: str) -> str | None:
    """Decode a PowerShell -EncodedCommand payload (base64 of UTF-16LE); None if it is not one.

    Text that decodes but is mostly unprintable is also None: random bytes often decode as
    UTF-16, and calling that "decoded" would hide reason (c) behind reason (b).
    """
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) % 2:
        return None
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return text if printable / len(text) >= _PRINTABLE_SHARE else None


@dataclass(frozen=True)
class CommandMatch:
    """Result of testing one command line against one target (LC-04 evidence + zero reason)."""

    matched: bool
    via: str | None          # "plain" | "decoded" | None
    undecodable: bool        # an encoded payload could not be decoded (reason c)


def match_command(command_line: str | None, forms: tuple[str, ...]) -> CommandMatch:
    """Plain match first; otherwise decode every encoded payload and match the decoded text.

    Decoding is for matching only: the decoded text is never stored or reported.
    """
    if names_target(command_line, forms):
        return CommandMatch(True, "plain", False)
    undecodable = False
    for token in encoded_payloads(command_line):
        decoded = decode_powershell_b64(token)
        if decoded is None:
            undecodable = True
        elif names_target(decoded, forms):
            return CommandMatch(True, "decoded", False)
    return CommandMatch(False, None, undecodable)


# --- LC-13 masking -----------------------------------------------------------------------

_VALUE = r"(\"[^\"]*\"|'[^']*'|[^\s;\"']+)"
_MASK_RULES: tuple[re.Pattern[str], ...] = (
    # net use ... /user:LAB\acct <password>   (skip when the next token is another switch)
    re.compile(r"(?i)(/user:\S+\s+)(?![/-])" + _VALUE),
    # -Password <value> ; a parenthesised expression is masked whole
    re.compile(r"(?i)(-Password\s+)(\([^)]*\)|" + _VALUE[1:-1] + r")"),
    # /p:<value>
    re.compile(r"(?i)(/p:)" + _VALUE),
    # ConvertTo-SecureString 'literal' -AsPlainText
    re.compile(r"(?i)(ConvertTo-SecureString\s+(?:-String\s+)?)(\"[^\"]*\"|'[^']*')"),
)
_MIN_SECRET_LEN = 4


def _strip_quotes(value: str) -> str:
    """Secrets are harvested without their quotes so they also match unquoted elsewhere."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def find_secrets(command_line: str | None) -> set[str]:
    """Literal values the masking rules would hide.

    A PowerShell variable such as `$env:SVC_BACKUP_PW` is only a name; its *expansion* appears
    literally in the child process (`net.exe ... /user:LAB\\svc_backup <password>`). Harvesting
    the literal lets `mask_command_line` hide it wherever else it is shown.
    """
    found: set[str] = set()
    if not command_line:
        return found
    for rule in _MASK_RULES:
        for m in rule.finditer(command_line):
            value = _strip_quotes(m.group(2))
            if len(value) >= _MIN_SECRET_LEN and not value.startswith(("$", "(")):
                found.add(value)
    return found


def harvest_secrets(command_lines: Iterable[str | None]) -> frozenset[str]:
    """Secrets across a whole trial, so a password masked in one row is masked in all rows."""
    found: set[str] = set()
    for line in command_lines:
        found |= find_secrets(line)
    return frozenset(found)


def mask_command_line(command_line: str | None, secrets: Iterable[str] = ()) -> str | None:
    """Apply LC-13: rule-based masking, then replace every harvested secret literal."""
    if command_line is None:
        return None
    masked = command_line
    for rule in _MASK_RULES:
        masked = rule.sub(lambda m: m.group(1) + MASK, masked)
    for secret in sorted(set(secrets), key=len, reverse=True):
        masked = re.sub(re.escape(secret), MASK, masked, flags=re.IGNORECASE)
    return masked
