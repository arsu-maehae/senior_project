"""Command text and 4648 target fields, read by uid and reduced to match facts (decision 048 item 1).

WHY one module: command lines hold lab passwords (spec 00 LC-13) and spec 03 section 2 forbids any part of
one in an output. This is the only stitcher module that selects the two command text columns of the view
(``params.SPEC_DB_COLUMNS`` only names them for the presence check), and nothing it returns carries text:
a command becomes a ``CmdResult`` (targets named, field kind, plain / decoded, undecodable, target-side
names found); a 4648 becomes its target texts, which are host names and IPs only.

WHY an own matcher (048, option B): reusing the log-check matcher would load the whole log-check package
and with it code that reads the answer keys. The rules below are written from the spec (ST-42, ST-43, ST-46):
boundary-aware, case-insensitive, PowerShell ``-EncodedCommand`` decoded for matching only.

The matching functions are pure (strings in, facts out). The two readers take an open read-only connection
from the caller (``inputs.load_link_inputs``), which brackets them with the DB SHA-256 check; they select
by ``event_uid`` only, so which events are read (in-window Sysmon 1 / 4688 / 4648, ST-01) is the caller's
choice and stays visible there.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import sqlite3
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Iterable, Iterator, Mapping, Sequence

from .params import VIEW

__all__ = ["FORM_KINDS", "VIAS", "TargetForms", "CmdResult", "target_name_forms", "match_text",
           "names_in_text", "is_powershell", "encoded_payloads", "decode_payload", "decoded_texts",
           "command_result", "read_command_results", "texts_of_4648", "read_4648_targets", "match_4648",
           "SQL_CHUNK"]

# Field kinds a target may be named by, in the order ``target_name_forms`` lists them.
FORM_KINDS: tuple[str, ...] = ("host_name", "windows_name", "ip")
# Where a command matched: in its own text, or only in a decoded -EncodedCommand payload.
VIAS: tuple[str, ...] = ("plain", "decoded")

# ((form, kind), ...): every text by which one target can be named, with the kind of each.
TargetForms = tuple[tuple[str, str], ...]

# WHY 900: SQLite's default limit of host parameters per statement is 999 on older builds.
SQL_CHUNK = 900

# Boundary rule (spec ST-42/43 "boundary-aware"): a name must not be glued to other name characters, so
# '192.168.50.2' never matches inside '192.168.50.22' and 'ep-0' never inside 'ep-02'. A following
# '.label' is allowed ('ep-02.lab.local', 'Endpoint-02.lab.local'), a following '.digit' is not (it would
# continue an IP). Anything of [\w.-] directly before the name blocks the match.
_BEFORE = r"(?<![\w.\-])"
_AFTER = r"(?![\w\-]|\.\d)"
# Target-side names (file and service names; spec ST-46, STT-07 "a name inside a longer file name does not
# match") use a stricter right edge: no [\w-] and no '.' + word character after the name, so 'Xpay' is not
# found in 'Xpay.exe' and 'Xpay.exe' not in 'Xpay.exe.config'; a sentence-ending '.' is still allowed.
_NAME_AFTER = r"(?![\w\-]|\.\w)"

_EP_HOST = re.compile(r"ep-(\d+)")
_DC_HOST, _DC_WINDOWS = "dc01", "dc-01"

_POWERSHELL = re.compile(r"powershell|pwsh", re.IGNORECASE)
_ENC_FULL = "encodedcommand"
# -e, -ec, and every prefix of -EncodedCommand ('-en', '-enc', ... '-encodedcommand'); longest first so the
# alternation never stops at a shorter switch. The switch must be followed by white space, so '-ex'
# (ExecutionPolicy) is never read as one.
_ENC_SWITCHES: tuple[str, ...] = tuple(sorted({"e", "ec"} | {_ENC_FULL[:n] for n in range(1, len(_ENC_FULL) + 1)},
                                              key=lambda s: (-len(s), s)))
# The payload is any non-space token (quotes stripped), so a malformed payload is seen and flagged
# undecodable instead of silently not matching.
_ENC_RE = re.compile(r"(?:^|\s)[-/](?:" + "|".join(_ENC_SWITCHES) + r")\s+['\"]?([^\s'\"]+)['\"]?(?=\s|$)",
                     re.IGNORECASE)
_MIN_PRINTABLE = 0.8   # decoded text below this printable share is random bytes, not a script

_4648_COLUMNS: tuple[str, ...] = ("destination_host", "destination_ip", "source_ip")
_4648_JSON_KEYS: tuple[str, ...] = ("targetservername", "targetinfo", "ipaddress")
_EMPTY_TEXTS = {"", "-"}


# ---------------------------------------------------------------- target names

def target_name_forms(host: str, ip: str | None) -> TargetForms:
    """The names a command or 4648 may use for one lab host, with their kind.

    ``host_name`` is the lab name ('ep-02', 'dc01'); ``windows_name`` is the Windows computer name the lab
    hosts carry ('endpoint-02' for ep-0N, 'dc-01' for dc01, seen in FQDNs and machine accounts); ``ip`` is
    the host's address when known. WHY both names: an operator may type either, and missing one would turn
    a real hop into ``target_only``.
    """
    name = str(host or "").strip().lower()
    forms: list[tuple[str, str]] = []
    if name:
        forms.append((name, "host_name"))
        m = _EP_HOST.fullmatch(name)
        if m:
            forms.append((f"endpoint-{m.group(1)}", "windows_name"))
        elif name == _DC_HOST:
            forms.append((_DC_WINDOWS, "windows_name"))
    addr = str(ip or "").strip()
    if addr:
        forms.append((addr, "ip"))
    return tuple(forms)


@lru_cache(maxsize=512)
def _alternation(texts: tuple[str, ...], after: str = _AFTER) -> tuple[re.Pattern[str], tuple[str, ...]]:
    """One boundary-aware, case-insensitive pattern for a set of names, and the names in pattern order.

    Longest first, so at one position the longer name wins; each name is its own named group ``n<i>``, so
    the caller learns WHICH name matched without comparing the text. Cached because the same probe is
    applied to many commands. ``after`` is the right boundary: ``_AFTER`` for host names (a '.label' may
    follow, FQDNs), ``_NAME_AFTER`` for target-side names.
    """
    ordered = tuple(sorted({t.lower() for t in texts if t}, key=lambda t: (-len(t), t)))
    alts = "|".join(f"(?P<n{i}>{re.escape(t)})" for i, t in enumerate(ordered))
    return re.compile(_BEFORE + "(?:" + alts + ")" + after, re.IGNORECASE), ordered


def _kind_of(forms: TargetForms) -> dict[str, str]:
    """Lower-case form -> kind; the first listed kind wins if two forms are equal (deterministic)."""
    out: dict[str, str] = {}
    for form, kind in forms:
        out.setdefault(form.lower(), kind)
    return out


def match_text(text: str | None, forms: TargetForms) -> str | None:
    """The kind of the first form (by position in ``text``) that names the target, or None.

    WHY the leftmost match: one deterministic answer per text, independent of the order of ``forms``.
    Empty text or no forms never match (a NULL never matches, decision 005).
    """
    usable = tuple((f, k) for f, k in forms if f)
    if not text or not usable:
        return None
    pattern, ordered = _alternation(tuple(f for f, _ in usable))
    m = pattern.search(text)
    if m is None or m.lastgroup is None:
        return None
    return _kind_of(usable)[ordered[int(m.lastgroup[1:])]]


def names_in_text(text: str | None, names: Iterable[str]) -> tuple[str, ...]:
    r"""The target-side names (file names, service names) that appear in ``text``, sorted.

    Left edge as for host names (no [\w.-] before, so 'pay.exe' is not found inside 'Xpay.exe'); right edge
    ``_NAME_AFTER`` (no [\w-] and no '.' + word character after, so 'Xpay' is not found in 'Xpay.exe' and
    'Xpay.exe' not in 'Xpay.exe.config', while 'Xpay.exe.' at a sentence end, before a quote, space or backslash,
    or at the end of the text is found; STT-07). WHY stricter than host names: a host may be followed by its
    domain, a file name by nothing that extends it. Each name is tested on its own (one name may contain
    another). The names returned are the given spellings, never the text's.
    """
    if not text:
        return ()
    return tuple(sorted({n for n in names if n and _alternation((n,), _NAME_AFTER)[0].search(text)}))


# ---------------------------------------------------------------- -EncodedCommand

def is_powershell(command: str | None) -> bool:
    """Only PowerShell command lines are decoded: other tools also have an ``-e`` switch, and reading
    their argument as a payload would flag a plain command as undecodable."""
    return bool(command) and _POWERSHELL.search(command) is not None


def encoded_payloads(command: str | None) -> list[str]:
    """The tokens given to -e / -ec / any prefix of -EncodedCommand (also with '/'), in text order."""
    if not is_powershell(command):
        return []
    return [m.group(1) for m in _ENC_RE.finditer(command or "")]


def decode_payload(token: str) -> str | None:
    """A PowerShell payload (base64 of UTF-16LE) as text, or None when it is not one.

    None for bad base64, an odd byte count, a failed UTF-16 decode, empty text, or text with less than
    80 % printable characters (random bytes often decode as UTF-16; calling that decoded would hide it).
    """
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) % 2:
        return None
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return text if text and printable / len(text) >= _MIN_PRINTABLE else None


def decoded_texts(command: str | None) -> tuple[tuple[str, ...], bool]:
    """(decoded payload texts, any payload undecodable). Decoding is for matching only; the caller must
    not keep the texts."""
    texts: list[str] = []
    undecodable = False
    for token in encoded_payloads(command):
        text = decode_payload(token)
        if text is None:
            undecodable = True
        else:
            texts.append(text)
    return tuple(texts), undecodable


# ---------------------------------------------------------------- command results

@dataclass(frozen=True)
class CmdResult:
    """What one Sysmon 1 / 4688 command line says, without any of its text.

    ``targets``: (target_host, kind, via) for every probed target the command names, sorted; ``via`` is
    'plain' when the command text names it, else 'decoded'. ``undecodable``: the command has at least one
    -EncodedCommand payload that could not be decoded (independent of whether a target matched).
    ``names_found``: (target_host, name) for each target-side name of a probed target found in the plain or
    decoded text, sorted, whether or not the command names that target (T7.4 filters by ``targets``).
    ``has_command``: the row has a non-empty command line (4688 often has none, spec 2).
    """
    event_uid: str
    targets: tuple[tuple[str, str, str], ...]
    undecodable: bool
    names_found: tuple[tuple[str, str], ...]
    has_command: bool


def _target_hit(plain: str, decoded: Sequence[str], forms: TargetForms) -> tuple[str, str] | None:
    """(kind, via) of the first match: plain text first, then each decoded payload in order."""
    kind = match_text(plain, forms)
    if kind is not None:
        return kind, "plain"
    for text in decoded:
        kind = match_text(text, forms)
        if kind is not None:
            return kind, "decoded"
    return None


def command_result(event_uid: str, command: str | None, probes: Sequence[tuple[str, TargetForms]],
                   names_by_target: Mapping[str, Iterable[str]]) -> CmdResult:
    """Pure: one command line against the probed targets of its host (ST-43) and their names (ST-46 data).

    Plain match first, then the decoded payloads. The text is used here and dropped; only the facts leave.
    """
    plain = command or ""
    decoded, undecodable = decoded_texts(plain)
    targets: set[tuple[str, str, str]] = set()
    names: set[tuple[str, str]] = set()
    for target_host, forms in probes:
        hit = _target_hit(plain, decoded, forms)
        if hit is not None:
            targets.add((target_host, hit[0], hit[1]))
        wanted = sorted(set(names_by_target.get(target_host, ())))
        for text in (plain, *decoded):
            names.update((target_host, n) for n in names_in_text(text, wanted))
    return CmdResult(event_uid=str(event_uid), targets=tuple(sorted(targets)), undecodable=undecodable,
                     names_found=tuple(sorted(names)), has_command=bool(plain.strip()))


def _chunks(items: Sequence[str], size: int = SQL_CHUNK) -> Iterator[Sequence[str]]:
    """Slices of at most ``size`` items, so no statement exceeds SQLite's parameter limit."""
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _select_by_uid(con: sqlite3.Connection, columns: Sequence[str], uids: Iterable[str]) -> Iterator[tuple]:
    """Rows of ``columns`` from the view for the given uids, chunked; uids are deduplicated and sorted so
    the read order does not depend on the caller's order."""
    wanted = sorted({str(u) for u in uids})
    for chunk in _chunks(wanted):
        sql = (f"SELECT {', '.join(columns)} FROM {VIEW} WHERE event_uid IN ({', '.join('?' * len(chunk))}) "
               f"ORDER BY event_uid")
        yield from (tuple(r) for r in con.execute(sql, tuple(chunk)))


def _is_command_event(channel: Any, event_id: Any) -> bool:
    """Sysmon 1 or Security 4688: the only rows whose command line is ST-43 evidence."""
    return (channel, event_id) in {("Sysmon", 1), ("Security", 4688)}


def read_command_results(con: sqlite3.Connection, uids_by_host: Mapping[str, Iterable[str]],
                         probes: Mapping[str, Sequence[tuple[str, TargetForms]]],
                         names_by_target: Mapping[str, Iterable[str]] | None = None) -> dict[str, CmdResult]:
    """uid -> ``CmdResult`` for every requested uid that is a Sysmon 1 / 4688 row of the host it was
    requested under.

    ``uids_by_host``: source host -> uids of its in-window process starts (the caller's choice, ST-01).
    ``probes``: source host -> (target_host, forms) to test. ``names_by_target``: target host -> its
    target-side names. A uid that is not a command event, or lies on another host than requested, gets no
    result (ST-43: evidence is on the source host). Every other requested uid gets one, also when nothing
    matched, so "absent" means "not a command event of that host" and never "no match".
    """
    names = names_by_target or {}
    host_of: dict[str, set[str]] = {}
    for host, uids in uids_by_host.items():
        for u in uids:
            host_of.setdefault(str(u), set()).add(str(host))
    out: dict[str, CmdResult] = {}
    cols = ("event_uid", "host", "channel", "event_id", "command_line")
    for uid, host, channel, event_id, command in _select_by_uid(con, cols, host_of):
        if not _is_command_event(channel, event_id) or str(host) not in host_of.get(str(uid), ()):
            continue
        out[str(uid)] = command_result(str(uid), command, probes.get(str(host), ()), names)
    return dict(sorted(out.items()))


# ---------------------------------------------------------------- 4648 target texts

def _flat(value: Any) -> list[str]:
    """A JSON value as texts: lists flattened, scalars as str, objects and None dropped."""
    if isinstance(value, list):
        return [t for v in value for t in _flat(v)]
    if value is None or isinstance(value, dict):
        return []
    return [str(value)]


def texts_of_4648(columns: Sequence[Any], field_json: str | None) -> tuple[str, ...]:
    """Pure: the target texts of one 4648 from its three columns and its JSON fields, in that order,
    without None, '' or '-' and without repeats.

    JSON keys are compared lower-case and only TargetServerName, TargetInfo and IpAddress are read; a JSON
    that does not parse gives the columns alone. WHY ``source_ip``: the normaliser maps the 4648 IpAddress
    (the server's address) into it.
    """
    texts: list[str] = [t for c in columns for t in _flat(c)]
    try:
        fields = json.loads(field_json) if field_json else {}
    except (TypeError, ValueError):
        fields = {}
    if isinstance(fields, dict):
        lower = {str(k).lower(): v for k, v in sorted(fields.items(), key=lambda kv: str(kv[0]))}
        for key in _4648_JSON_KEYS:
            texts.extend(_flat(lower.get(key)))
    out: list[str] = []
    for t in (s.strip() for s in texts):
        if t not in _EMPTY_TEXTS and t not in out:
            out.append(t)
    return tuple(out)


def read_4648_targets(con: sqlite3.Connection, uids: Iterable[str]) -> dict[str, tuple[str, ...]]:
    """uid -> target texts for every requested uid that is a Security 4648 (ST-42). Other uids are left
    out. Only host names / IPs leave this function; no other JSON field is returned."""
    cols = ("event_uid", "channel", "event_id", *_4648_COLUMNS, "field_values_json")
    out: dict[str, tuple[str, ...]] = {}
    for row in _select_by_uid(con, cols, uids):
        uid, channel, event_id = row[0], row[1], row[2]
        if (channel, event_id) != ("Security", 4648):
            continue
        out[str(uid)] = texts_of_4648(row[3:3 + len(_4648_COLUMNS)], row[-1])
    return dict(sorted(out.items()))


def match_4648(texts: Sequence[str], forms: TargetForms) -> str | None:
    """The kind of the first target text (in ``texts_of_4648`` order) that names the target, or None."""
    for text in texts:
        kind = match_text(text, forms)
        if kind is not None:
            return kind
    return None
