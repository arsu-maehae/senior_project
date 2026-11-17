"""Our own Sigma subset matcher (spec 04_label LB-04, LB-05, LB-12; decision 056 option D).

WHY our own and not pySigma: decision 056 (Q4) — no new matching dependency, and every step must be explainable
function by function. The subset is exactly LB-05; anything else is refused when a rule is compiled, so a rule can
never be half-understood.

The pieces, all pure:
- ``sigma_regex`` turns one Sigma value into a regular expression (wildcards ``*`` / ``?``, escapes ``\\*``, ``\\?``,
  ``\\\\``; any other backslash literal, LB-12);
- ``compile_item`` / ``compile_selection`` turn a detection entry into AND / OR groups of field tests;
- ``parse_condition`` turns the ``condition`` text into a small tree (``and``, ``or``, ``not``, parentheses,
  ``1 of x*``, ``all of x*``, ``1 of them``, ``all of them``);
- ``field_key`` maps a Sigma field name to the lower-case key of ``field_values_json`` (LB-04);
- ``match_detection`` evaluates a compiled detection on one event's fields.

Matching is case-insensitive (both sides lower-cased); integers in a rule are compared as their decimal text; a field
the event lacks (or holds only empty values for) makes every test on it false, in a selection and in a filter alike
(LB-04). A field holding several values matches when any one value satisfies the test.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .errors import LabelError

__all__ = ["Fields", "Item", "Selection", "Detection", "MATCH_MODIFIERS", "MODIFIER_ALL", "FIELD_MAP",
           "PROCESS_CREATION_4688_MAP", "field_key", "sigma_regex", "compile_item", "compile_selection",
           "tokenize", "parse_condition", "evaluate", "compile_detection", "match_item", "match_selection",
           "match_detection", "event_fields"]

# Lower-case key -> the event's values (raw text, as stored).
Fields = Mapping[str, Sequence[str]]

MATCH_MODIFIERS: tuple[str, ...] = ("contains", "startswith", "endswith")
MODIFIER_ALL = "all"

# LB-04: Sigma names whose key is not simply the lower-case name.
FIELD_MAP: Mapping[str, str] = {"Provider_Name": "provider"}
# LB-04: logsource process_creation on Security 4688. ``None`` = the field has no 4688 counterpart: never matches.
PROCESS_CREATION_4688_MAP: Mapping[str, str | None] = {
    "Image": "newprocessname", "ParentImage": "parentprocessname", "CommandLine": "commandline",
    "OriginalFileName": None,
}
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\*?$")


# ---------------------------------------------------------------- fields (LB-04)

def check_field_name(name: str) -> None:
    """Refuse a field name LB-04 cannot map. WHY: a name such as ``a.b`` or ``Foo_Bar`` has no lower-case key in our
    DB, and a silent miss would make the rule look dead instead of wrong (spec 2: refuse an unmapped field)."""
    if name in FIELD_MAP or name in PROCESS_CREATION_4688_MAP or _FIELD_NAME.match(name):
        return
    raise LabelError(f"refused: field {name!r} is outside the LB-04 field mapping")


def field_key(name: str, process_creation_4688: bool = False) -> str | None:
    """The ``field_values_json`` key of Sigma field ``name`` (LB-04); None when the field can never match.

    ``process_creation_4688`` is true only when a ``process_creation`` rule is applied to a Security 4688 event,
    whose process fields have other names than Sysmon 1's.
    """
    if process_creation_4688 and name in PROCESS_CREATION_4688_MAP:
        return PROCESS_CREATION_4688_MAP[name]
    return FIELD_MAP.get(name, name.lower())


def _value_text(value: Any) -> list[str]:
    """One stored value as a list of non-empty texts. WHY drop None: the DB stores an empty field as ``[null]``;
    an empty value is no value (LB-04), never the text ``None``."""
    if value is None:
        return []
    if isinstance(value, list):
        return [t for v in value for t in _value_text(v)]
    if isinstance(value, bool):
        return ["true" if value else "false"]
    return [str(value)]


def event_fields(raw: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """The parsed ``field_values_json`` object as lower-case key -> tuple of texts (spec 6: one-element lists are
    unwrapped; a longer list keeps every element). Keys with no value are left out, so ``absent`` and ``empty``
    are the same case (LB-04)."""
    out: dict[str, tuple[str, ...]] = {}
    for k, v in raw.items():
        texts = _value_text(v)
        if texts:
            out[str(k).lower()] = tuple(texts)
    return out


# ---------------------------------------------------------------- values (LB-05, LB-12)

def sigma_regex(value: str) -> str:
    """Regex text (no anchors) for one Sigma string value, lower-cased.

    LB-12: ``\\*`` and ``\\?`` are a literal ``*`` / ``?``, ``\\\\`` is one backslash, any other backslash is
    literal; an unescaped ``*`` matches any run of characters and ``?`` exactly one. WHY a scan and not
    ``str.replace``: escapes must be read left to right (``\\\\*`` is a backslash then a wildcard).
    """
    text = value.lower()
    out: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text) and text[i + 1] in "*?\\":
            out.append(re.escape(text[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def _pattern(value: Any, modifier: str) -> re.Pattern[str]:
    """Compiled full-match pattern of one rule value under ``modifier`` ('' = equals). Integers are compared as their
    decimal text (LB-05); booleans, floats, None and containers are refused: YAML 1.1 reads ``yes`` / ``no`` /
    ``null`` as such, and their Sigma meaning is outside the subset (decision 057 consequences)."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise LabelError(f"refused: rule value {value!r} ({type(value).__name__}) is outside the LB-05 subset")
    body = sigma_regex(str(value))
    if modifier == "contains":
        body = f".*{body}.*"
    elif modifier == "startswith":
        body = f"{body}.*"
    elif modifier == "endswith":
        body = f".*{body}"
    return re.compile(body, re.DOTALL)


@dataclass(frozen=True)
class Item:
    """One field test of a selection: ``field|modifier[|all]: value or list``."""
    field: str
    modifier: str                       # '' (equals), contains, startswith, endswith
    match_all: bool                     # ``|all``: every value must match (else any one)
    values: tuple[str, ...]             # the rule's literals as text (for reports and LBT-10)
    patterns: tuple[re.Pattern[str], ...]


def _split_key(key: str) -> tuple[str, str, bool]:
    """``Field|mod|all`` -> (field, modifier, all). Refuses an unknown or repeated modifier (LB-05)."""
    parts = str(key).split("|")
    name, mods = parts[0], parts[1:]
    check_field_name(name)
    modifier, match_all = "", False
    for m in mods:
        if m == MODIFIER_ALL and not match_all:
            match_all = True
        elif m in MATCH_MODIFIERS and not modifier:
            modifier = m
        else:
            raise LabelError(f"refused: modifier {m!r} in {key!r} is outside the LB-05 subset")
    return name, modifier, match_all


def compile_item(key: str, value: Any) -> Item:
    """One ``key: value`` entry of a selection map. A list means "any of" (``|all``: "all of"); an empty list is
    refused (it would match nothing or everything depending on the reader)."""
    name, modifier, match_all = _split_key(key)
    values = list(value) if isinstance(value, list) else [value]
    if not values:
        raise LabelError(f"refused: empty value list for {key!r}")
    patterns = tuple(_pattern(v, modifier) for v in values)
    return Item(field=name, modifier=modifier, match_all=match_all, values=tuple(str(v) for v in values),
                patterns=patterns)


@dataclass(frozen=True)
class Selection:
    """A detection identifier: OR over alternatives, each an AND over items. A map is one alternative; a list of
    maps (SR-40, SR-41) is several."""
    name: str
    alternatives: tuple[tuple[Item, ...], ...]


def _compile_map(name: str, entry: Any) -> tuple[Item, ...]:
    """One selection map -> its AND group. Refuses a non-map (keyword lists are outside LB-05) and an empty map."""
    if not isinstance(entry, dict) or not entry:
        raise LabelError(f"refused: selection {name!r} is not a non-empty field map (LB-05)")
    return tuple(compile_item(k, v) for k, v in entry.items())


def compile_selection(name: str, entry: Any) -> Selection:
    """A detection entry (map, or list of maps) -> Selection."""
    if not _IDENT.match(str(name)):
        raise LabelError(f"refused: detection identifier {name!r} is not a plain name")
    if isinstance(entry, list):
        if not entry:
            raise LabelError(f"refused: selection {name!r} is an empty list")
        return Selection(name, tuple(_compile_map(name, e) for e in entry))
    return Selection(name, (_compile_map(name, entry),))


# ---------------------------------------------------------------- condition (LB-05)

Node = tuple  # ("id", name) | ("not", node) | ("and", (nodes)) | ("or", (nodes)) | ("of", "1"|"all", (names))


def tokenize(text: str) -> list[str]:
    """Split a condition into ``(``, ``)`` and words."""
    return re.findall(r"\(|\)|[^\s()]+", str(text))


def _expand(pattern: str, identifiers: Sequence[str]) -> tuple[str, ...]:
    """Identifiers named by ``them`` or ``x*`` (sorted). ``them`` leaves out names starting with ``_`` (Sigma
    specification). A pattern naming no identifier is refused: it would make ``1 of`` always false silently."""
    if pattern == "them":
        names = [i for i in identifiers if not i.startswith("_")]
    elif _PATTERN.match(pattern):
        names = [i for i in identifiers if fnmatch.fnmatchcase(i, pattern)]
    else:
        raise LabelError(f"refused: '{pattern}' is not a supported identifier pattern (LB-05)")
    if not names:
        raise LabelError(f"refused: condition pattern {pattern!r} names no detection identifier")
    return tuple(sorted(names))


class _Parser:
    """Recursive descent: ``or`` < ``and`` < ``not`` < atom (Sigma precedence)."""

    def __init__(self, tokens: list[str], identifiers: Sequence[str]) -> None:
        self.toks, self.ids, self.pos = tokens, list(identifiers), 0

    def peek(self) -> str | None:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise LabelError("refused: condition ends early")
        self.pos += 1
        return tok

    def expr(self) -> Node:
        parts = [self.conj()]
        while self.peek() == "or":
            self.take()
            parts.append(self.conj())
        return parts[0] if len(parts) == 1 else ("or", tuple(parts))

    def conj(self) -> Node:
        parts = [self.neg()]
        while self.peek() == "and":
            self.take()
            parts.append(self.neg())
        return parts[0] if len(parts) == 1 else ("and", tuple(parts))

    def neg(self) -> Node:
        if self.peek() == "not":
            self.take()
            return ("not", self.neg())
        return self.atom()

    def atom(self) -> Node:
        tok = self.take()
        if tok == "(":
            node = self.expr()
            if self.take() != ")":
                raise LabelError("refused: unbalanced parentheses in condition")
            return node
        if tok in ("1", "all"):
            if self.take() != "of":
                raise LabelError(f"refused: '{tok}' must be followed by 'of' (LB-05)")
            return ("of", tok, _expand(self.take(), self.ids))
        if tok in ("and", "or", "not", ")", "of") or not _IDENT.match(tok):
            raise LabelError(f"refused: unexpected token {tok!r} in condition (LB-05)")
        if tok not in self.ids:
            raise LabelError(f"refused: condition names unknown identifier {tok!r}")
        return ("id", tok)


def parse_condition(text: Any, identifiers: Sequence[str]) -> Node:
    """Parse one condition string over the given identifiers. A list of conditions, ``|`` aggregations, ``near``
    and counts other than ``1`` / ``all`` are refused (LB-02, LB-05)."""
    if not isinstance(text, str) or not text.strip():
        raise LabelError("refused: condition must be one non-empty string (LB-05)")
    p = _Parser(tokenize(text), identifiers)
    node = p.expr()
    if p.peek() is not None:
        raise LabelError(f"refused: unexpected token {p.peek()!r} in condition (LB-05)")
    return node


def evaluate(node: Node, truth: Callable[[str], bool]) -> bool:
    """Value of a condition tree; ``truth(name)`` gives one identifier's value (the caller may cache it)."""
    kind = node[0]
    if kind == "id":
        return truth(node[1])
    if kind == "not":
        return not evaluate(node[1], truth)
    if kind == "and":
        return all(evaluate(n, truth) for n in node[1])
    if kind == "or":
        return any(evaluate(n, truth) for n in node[1])
    if kind == "of":
        test = all if node[1] == "all" else any
        return test(truth(n) for n in node[2])
    raise ValueError(f"unknown condition node {kind!r}")


# ---------------------------------------------------------------- detection

@dataclass(frozen=True)
class Detection:
    """A compiled ``detection`` block: selections by name and the condition tree."""
    selections: Mapping[str, Selection]
    condition: Node


def compile_detection(block: Any) -> Detection:
    """Compile a rule's ``detection`` map. Only identifiers and ``condition`` are allowed (``timeframe`` belongs to
    correlation, LB-02)."""
    if not isinstance(block, dict) or "condition" not in block:
        raise LabelError("refused: detection must be a map with a condition")
    sels = {str(k): compile_selection(str(k), v) for k, v in block.items() if k != "condition"}
    if "timeframe" in sels:
        raise LabelError("refused: timeframe is outside the LB-05 subset (LB-02)")
    if not sels:
        raise LabelError("refused: detection has no selection")
    return Detection(selections=sels, condition=parse_condition(block["condition"], list(sels)))


def match_item(item: Item, fields: Fields, process_creation_4688: bool = False) -> bool:
    """One field test. False when the field is unmapped for this event or absent (LB-04); otherwise true when some
    stored value satisfies the test (any rule value, or every rule value with ``|all``)."""
    key = field_key(item.field, process_creation_4688)
    if key is None:
        return False
    for value in fields.get(key, ()):
        text = value.lower()
        hits = (p.fullmatch(text) is not None for p in item.patterns)
        if all(hits) if item.match_all else any(hits):
            return True
    return False


def match_selection(sel: Selection, fields: Fields, process_creation_4688: bool = False) -> bool:
    """OR over the alternatives of AND over their items."""
    return any(all(match_item(i, fields, process_creation_4688) for i in alt) for alt in sel.alternatives)


def match_detection(det: Detection, fields: Fields, process_creation_4688: bool = False) -> bool:
    """Evaluate the condition on one event, computing each selection at most once."""
    cache: dict[str, bool] = {}

    def truth(name: str) -> bool:
        if name not in cache:
            cache[name] = match_selection(det.selections[name], fields, process_creation_4688)
        return cache[name]

    return evaluate(det.condition, truth)
