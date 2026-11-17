"""Labelling recall (PLAN T8.3; spec 04 §7 LBA-04 and its "Expected technique per key event" table). Pure.

One row per key event of a table kind: which technique the key event is expected to carry, whether the label stage
(``out/label/<trial>/event_labels.csv``) labelled it, and whether one of its labels carries the expected technique.
Recall = labelled with the expected technique / scored rows, per technique and overall.

WHY pure: the reading of the key (which key event is which kind) is the whole method of this measurement, so it must
be testable on synthetic keys and label rows without any file. The DB facts needed for the SMB kinds (share name and
relative target name of a 5140 / 5145) are passed in, already queried (``label_inputs``).

What the number means (stage review S04): ``COVERAGE_NOTE`` and ``MATCH_NOTE`` below, also written into the report.

Readings of the table (reported to the owner with T8.3):
- Every kind comes from the key (``steps[].kind``, ``hops[].protocol``, ``event_keys`` channel / event id and
  host), never from a label. The only DB facts used are the share name and the relative target name, because the
  table splits the SMB 5140 / 5145 events on them.
- "admin share" = a share whose last name part is ``ADMIN$``, ``IPC$`` or a drive letter + ``$`` (ATT&CK T1021.002
  names C$, ADMIN$ and IPC$). Any other share (a lab share) is no table kind.
- "copied executable" = a 5145 on ``ADMIN$`` or a drive share whose ``relative_target_name`` ends in an executable
  extension (``EXECUTABLE_EXTENSIONS``). The table says "(write)", but the AccessList is only in the event's field
  JSON, and no SQL in ``src/evaluate`` names it (test ``test_src_evaluate_never_selects_command_text_or_field_json``,
  guarding decision 051 item 8; decision 060 reading 1); so a non-write access to the copied file also counts here
  (open question to the owner, T8.3 report).
- "WinRM hop: wsmprovhost process" = every target-host Sysmon 1 / Security 4688 in ``target_event_uids`` of a WinRM
  key hop (the key lists the session-host process there; the image is not re-checked, which would repeat SR-40).
- "WinRM hop: source connection" = every source-host Sysmon 3 in ``port_join_event_uids`` of a WinRM key hop.
- "target 4624 of a hop" = every target-host Security 4624 in ``target_event_uids``: expected ``none``, reported,
  never scored.
- One row per key event: a uid listed by a hop takes the hop (its role); a step row exists only for a uid that no
  hop lists (the dump steps). Roles ``benign``, ``background`` (and an owner-excluded hop) are reported, never scored
  (spec LBA-04); confirmed steps are scored (LBA-02: every key dump must carry T1003.001).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .writers import csv_text, md_header

__all__ = ["EXPECTED", "KIND_ORDER", "COLUMNS", "NONE", "SCORED_ROLES", "ShareFacts", "KeyEvent", "share_leaf",
           "is_admin_share", "is_file_admin_share", "is_executable_name", "EXECUTABLE_EXTENSIONS", "smb_kind",
           "share_uids_needed", "hop_events",
           "step_events", "key_events", "label_index", "recall_row", "recall_rows", "unkinded_counts",
           "recall_counts", "label_counts", "trial_csv", "summary_md", "TrialRecall"]

NONE = "none"
# The table of spec 04 §7 under LBA-04, in its order: kind -> expected technique.
EXPECTED: dict[str, str] = {
    "lsass_dump": "T1003.001",          # step lsass_dump, Sysmon 10
    "smb_share": "T1021.002",           # SMB hop: target 5140 / 5145 on an admin share
    "smb_copy": "T1570",                # SMB hop: copied executable, 5145 (see the reading above)
    "service_install": "T1569.002",     # step service_exec / hop install, 7045 / 4697
    "winrm_process": "T1021.006",       # WinRM hop: wsmprovhost process, Sysmon 1 / 4688
    "winrm_source_conn": "T1021.006",   # WinRM hop: source connection to 5985, Sysmon 3 (source)
    "target_4624": NONE,                # target 4624 of a hop: reported only
}
KIND_ORDER: tuple[str, ...] = tuple(EXPECTED)
# Roles whose rows enter recall (spec LBA-04: benign and background are reported, never scored).
ROLE_ATTACK, ROLE_STEP, ROLE_STEP_UNCONFIRMED, ROLE_EXCLUDED = "attack", "step", "step_unconfirmed", "excluded"
SCORED_ROLES: frozenset[str] = frozenset({ROLE_ATTACK, ROLE_STEP})

# The spec's columns first (``hop_id or step_id`` -> ``hop_or_step_id``), then the facts that make a row traceable.
COLUMNS: tuple[str, ...] = ("trial_id", "hop_or_step_id", "kind", "event_uid", "expected_technique", "labelled",
                            "labelled_expected", "rule_ids", "role", "scored", "match_method", "label_techniques",
                            "label_run_sha256")

# Stage review S04: an honest statement of what the recall measures, written into label_recall.md.
COVERAGE_NOTE = ("This recall is rule coverage of the key events, not a detection rate. For T1569.002 (any key 7045 / "
                 "4697) and T1021.006 (any key Sysmon 1 / 4688 of a WinRM hop, or its 5985 Sysmon 3) coverage is close "
                 "to true by construction, because SR-30 / SR-31 / SR-40 / SR-41 match those event kinds broadly; "
                 "benign key rows of the same kinds get the same labels.")
MATCH_NOTE = ("labelled_expected = 1 when the expected technique is the primary technique OR one of the technique "
              "tags of a label row of the event (or of one of its near-duplicate copies).")

_DRIVE_SHARE = re.compile(r"[a-z]\$")
# What counts as an executable file name (the extension list of own rule SR-20, spec 04 §3.1).
EXECUTABLE_EXTENSIONS: tuple[str, ...] = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs")
_SMB, _WINRM = "smb", "winrm"


# ---------------------------------------------------------------- SMB share facts

@dataclass(frozen=True)
class ShareFacts:
    """The two DB columns of a 5140 / 5145 the table needs: ``share_name`` and ``relative_target_name`` (empty on a
    5140)."""
    share_name: str
    target_name: str


def share_leaf(share_name: str) -> str:
    """Last part of a share name, lower-cased (``\\\\*\\ADMIN$`` -> ``admin$``). WHY: Windows logs the share with a
    server prefix (spec 04 §10.3), and only the share itself says whether it is an admin share."""
    return str(share_name).strip().rstrip("\\").split("\\")[-1].lower()


def is_file_admin_share(share_name: str) -> bool:
    """``ADMIN$`` or a drive share (``C$``): the admin shares that hold files, so an executable there is a copy."""
    leaf = share_leaf(share_name)
    return leaf == "admin$" or _DRIVE_SHARE.fullmatch(leaf) is not None


def is_admin_share(share_name: str) -> bool:
    """A file admin share or ``IPC$`` (ATT&CK T1021.002: C$, ADMIN$, IPC$)."""
    return is_file_admin_share(share_name) or share_leaf(share_name) == "ipc$"


def is_executable_name(target_name: str) -> bool:
    """True when the file name ends in one of ``EXECUTABLE_EXTENSIONS`` (case-insensitive, trailing blanks
    ignored)."""
    return str(target_name).strip().lower().endswith(EXECUTABLE_EXTENSIONS)


def smb_kind(event_id: int, facts: ShareFacts | None) -> str | None:
    """``smb_copy`` (5145 naming an executable on a file admin share), ``smb_share`` (other 5140 / 5145 on an admin
    share), or None (another share, or no facts)."""
    if facts is None or not is_admin_share(facts.share_name):
        return None
    if event_id == 5145 and is_file_admin_share(facts.share_name) and is_executable_name(facts.target_name):
        return "smb_copy"
    return "smb_share"


# ---------------------------------------------------------------- key events by kind

@dataclass(frozen=True)
class KeyEvent:
    """One key event of a table kind, before the label join."""
    item_id: str        # hop_id or step_id
    role: str           # hop role, ``excluded``, ``step`` or ``step_unconfirmed``
    kind: str
    uid: str


def _ek(event_keys: Mapping[str, Mapping[str, Any]], uid: str) -> tuple[str, int | None, str]:
    """(channel, event_id, host) of a key uid from ``event_keys``; empty values when the key lists no entry."""
    e = event_keys.get(uid) or {}
    eid = e.get("event_id")
    return str(e.get("channel") or ""), eid if isinstance(eid, int) else None, str(e.get("host") or "")


def _protocol(hop: Mapping[str, Any]) -> str:
    """Key hop protocol, lower-cased (the key writes ``SMB`` / ``WinRM`` / ``RDP``)."""
    return str(hop.get("protocol") or "").lower()


def _hop_role(hop: Mapping[str, Any]) -> str:
    """The hop's role; an owner-excluded hop (AK-21) is reported as ``excluded`` and never scored."""
    return ROLE_EXCLUDED if hop.get("excluded") else str(hop.get("role") or "")


def share_uids_needed(key_data: Mapping[str, Any]) -> list[str]:
    """The uids whose share facts the SMB kinds need: target-host Security 5140 / 5145 of SMB key hops, sorted."""
    ek = key_data.get("event_keys") or {}
    out: set[str] = set()
    for hop in key_data.get("hops") or []:
        if _protocol(hop) != _SMB:
            continue
        for uid in hop.get("target_event_uids") or []:
            ch, eid, host = _ek(ek, uid)
            if ch == "Security" and eid in (5140, 5145) and host == hop.get("target_host"):
                out.add(uid)
    return sorted(out)


def _target_kind(hop: Mapping[str, Any], channel: str, eid: int | None, host: str,
                 share: ShareFacts | None) -> str | None:
    """Table kind of one ``target_event_uids`` entry of a key hop, or None (WinRM 91, a lab share, other host)."""
    if host != hop.get("target_host"):
        return None
    proto = _protocol(hop)
    if channel == "Security" and eid == 4624:
        return "target_4624"
    if (channel, eid) in (("System", 7045), ("Security", 4697)):
        return "service_install"
    if proto == _SMB and channel == "Security" and eid in (5140, 5145):
        return smb_kind(eid, share)
    if proto == _WINRM and (channel, eid) in (("Sysmon", 1), ("Security", 4688)):
        return "winrm_process"
    return None


def hop_events(hop: Mapping[str, Any], event_keys: Mapping[str, Mapping[str, Any]],
               shares: Mapping[str, ShareFacts]) -> list[KeyEvent]:
    """Key events of one hop: its ``target_event_uids`` of a table kind, and for WinRM its source-host Sysmon 3
    ``port_join_event_uids``."""
    hid, role = str(hop.get("hop_id") or ""), _hop_role(hop)
    out: list[KeyEvent] = []
    for uid in hop.get("target_event_uids") or []:
        ch, eid, host = _ek(event_keys, uid)
        kind = _target_kind(hop, ch, eid, host, shares.get(uid))
        if kind:
            out.append(KeyEvent(hid, role, kind, uid))
    if _protocol(hop) == _WINRM:
        for uid in hop.get("port_join_event_uids") or []:
            ch, eid, host = _ek(event_keys, uid)
            if (ch, eid) == ("Sysmon", 3) and host == hop.get("source_host"):
                out.append(KeyEvent(hid, role, "winrm_source_conn", uid))
    return out


def step_events(step: Mapping[str, Any], event_keys: Mapping[str, Mapping[str, Any]]) -> list[KeyEvent]:
    """Key events of one step: Sysmon 10 of an ``lsass_dump`` step; 7045 / 4697 of a ``service_exec`` step."""
    kind = str(step.get("kind") or "")
    want = {"lsass_dump": {("Sysmon", 10)}, "service_exec": {("System", 7045), ("Security", 4697)}}.get(kind)
    if not want:
        return []
    role = ROLE_STEP if step.get("status") == "confirmed" else ROLE_STEP_UNCONFIRMED
    row_kind = "lsass_dump" if kind == "lsass_dump" else "service_install"
    out: list[KeyEvent] = []
    for uid in step.get("event_uids") or []:
        ch, eid, _host = _ek(event_keys, uid)
        if (ch, eid) in want:
            out.append(KeyEvent(str(step.get("step_id") or ""), role, row_kind, uid))
    return out


def key_events(key_data: Mapping[str, Any], shares: Mapping[str, ShareFacts]) -> list[list[KeyEvent]]:
    """Key events grouped per uid (one group = one output row), in first-seen order.

    A uid listed by a hop is taken from the hop(s) only (the hop gives the role; a service_exec step repeats the
    hop's install). A step contributes only uids no hop lists. A uid in several hops keeps every hop."""
    ek = key_data.get("event_keys") or {}
    groups: dict[str, list[KeyEvent]] = {}
    for hop in key_data.get("hops") or []:
        for ev in hop_events(hop, ek, shares):
            groups.setdefault(ev.uid, []).append(ev)
    from_hops = set(groups)
    for step in key_data.get("steps") or []:
        for ev in step_events(step, ek):
            if ev.uid not in from_hops:
                groups.setdefault(ev.uid, []).append(ev)
    return list(groups.values())


def _all_key_uids(key_data: Mapping[str, Any]) -> list[str]:
    """Every uid the key lists anywhere (steps, every ``*_uids`` list of a hop, ``unconfirmed`` entries)."""
    out: list[str] = []
    for step in key_data.get("steps") or []:
        out += list(step.get("event_uids") or [])
    for item in list(key_data.get("hops") or []) + list(key_data.get("unconfirmed") or []):
        if not isinstance(item, Mapping):
            continue
        for name, value in item.items():
            if name.endswith("_uids") and isinstance(value, list):
                out += [u for u in value if isinstance(u, str)]
    return out


def unkinded_counts(key_data: Mapping[str, Any], row_uids: Iterable[str]) -> dict[str, int]:
    """``channel event_id`` -> number of distinct key uids that got no row (no table kind: agent and move commands,
    WinRM 91, lab-share events ...). WHY: nothing is dropped silently; these are counted in the report."""
    ek = key_data.get("event_keys") or {}
    done = set(row_uids)
    counts: dict[str, int] = {}
    for uid in sorted(set(_all_key_uids(key_data)) - done):
        ch, eid, _host = _ek(ek, uid)
        name = f"{ch or '?'} {eid if eid is not None else '?'}"
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items()))


# ---------------------------------------------------------------- label join

def _split(cell: str | None, sep: str) -> list[str]:
    """A joined cell to its non-empty parts."""
    return [p for p in (cell or "").split(sep) if p != ""]


def label_index(label_rows: Iterable[Mapping[str, str]]) -> dict[str, list[tuple[str, Mapping[str, str]]]]:
    """uid -> [(how, label row)]: every representative ``event_uid`` (how = ``uid``) and every near-duplicate copy
    in ``dup_uids`` (how = ``dup_uid``, ``|``-joined, spec 04 LB-03) points at its label rows."""
    out: dict[str, list[tuple[str, Mapping[str, str]]]] = {}
    for row in label_rows:
        out.setdefault(row["event_uid"], []).append(("uid", row))
        for dup in _split(row.get("dup_uids"), "|"):
            out.setdefault(dup, []).append(("dup_uid", row))
    return out


def _row_techniques(row: Mapping[str, str]) -> set[str]:
    """The primary technique and every technique tag of one label row."""
    return {row.get("technique") or ""} - {""} | set(_split(row.get("techniques"), ";"))


def recall_row(trial: str, group: Sequence[KeyEvent],
               index: Mapping[str, Sequence[tuple[str, Mapping[str, str]]]], *,
               label_run_sha256: str) -> dict[str, str]:
    """The output row of one key event (a group of KeyEvents with one uid).

    ``labelled`` = the uid or one of its copies has a label row; ``labelled_expected`` = one of those rows carries
    the expected technique as primary or tag (empty when nothing is expected). ``scored`` = 1 when a technique is
    expected and some role is scored (attack hop or confirmed step). ``label_run_sha256`` is the SHA-256 of the label
    ``run_info.json`` the row was built from (stage review S06), so a recall CSV left over from an older label run is
    visible."""
    uid = group[0].uid
    kind = min((ev.kind for ev in group), key=KIND_ORDER.index)
    expected = EXPECTED[kind]
    hits = list(index.get(uid, ()))
    techs = set().union(*(_row_techniques(r) for _how, r in hits)) if hits else set()
    how = "uid" if any(h == "uid" for h, _r in hits) else ("dup_uid" if hits else "none")
    roles = sorted({ev.role for ev in group})
    scored = expected != NONE and any(r in SCORED_ROLES for r in roles)
    return {"trial_id": trial, "hop_or_step_id": ";".join(sorted({ev.item_id for ev in group})), "kind": kind,
            "event_uid": uid, "expected_technique": expected, "labelled": "1" if hits else "0",
            "labelled_expected": "" if expected == NONE else ("1" if expected in techs else "0"),
            "rule_ids": ";".join(sorted({r["rule_id"] for _h, r in hits})), "role": ";".join(roles),
            "scored": "1" if scored else "0", "match_method": how, "label_techniques": ";".join(sorted(techs)),
            "label_run_sha256": label_run_sha256}


def recall_rows(trial: str, key_data: Mapping[str, Any], shares: Mapping[str, ShareFacts],
                label_rows: Sequence[Mapping[str, str]], *, label_run_sha256: str) -> list[dict[str, str]]:
    """Every row of one keyed trial, sorted by hop / step id, table order of the kind, then uid."""
    index = label_index(label_rows)
    rows = [recall_row(trial, g, index, label_run_sha256=label_run_sha256) for g in key_events(key_data, shares)]
    return sorted(rows, key=lambda r: (r["hop_or_step_id"], KIND_ORDER.index(r["kind"]), r["event_uid"]))


# ---------------------------------------------------------------- counts

def recall_counts(rows: Iterable[Mapping[str, str]]) -> dict[str, tuple[int, int]]:
    """expected technique -> (scored rows labelled with it, scored rows), plus ``overall``; in technique order."""
    acc: dict[str, list[int]] = {}
    for r in rows:
        if r["scored"] != "1":
            continue
        for name in (r["expected_technique"], "overall"):
            slot = acc.setdefault(name, [0, 0])
            slot[0] += r["labelled_expected"] == "1"
            slot[1] += 1
    order = [t for t in dict.fromkeys(EXPECTED.values()) if t in acc and t != NONE] + (
        ["overall"] if "overall" in acc else [])
    return {k: (acc[k][0], acc[k][1]) for k in order}


def label_counts(label_rows: Iterable[Mapping[str, str]]) -> dict[str, Any]:
    """Counts of one trial's labels, key-free (the t01 numbers): label rows, distinct labelled events, distinct
    events per technique (primary or tag) and label rows per rule."""
    rows = list(label_rows)
    per_tech: dict[str, set[str]] = {}
    per_rule: dict[str, int] = {}
    for r in rows:
        for t in _row_techniques(r):
            per_tech.setdefault(t, set()).add(r["event_uid"])
        per_rule[r["rule_id"]] = per_rule.get(r["rule_id"], 0) + 1
    return {"label_rows": len(rows), "labelled_events": len({r["event_uid"] for r in rows}),
            "events_per_technique": {t: len(u) for t, u in sorted(per_tech.items())},
            "rows_per_rule": dict(sorted(per_rule.items()))}


# ---------------------------------------------------------------- texts

def trial_csv(rows: Sequence[Mapping[str, str]]) -> str:
    """``label_recall.csv`` of one keyed trial."""
    return csv_text(COLUMNS, rows)


@dataclass(frozen=True)
class TrialRecall:
    """Everything one trial gives the report. ``rows`` is None for a trial without an approved key."""
    trial_id: str
    split: str
    rows: tuple[dict[str, str], ...] | None
    counts: Mapping[str, Any]
    unkinded: Mapping[str, int]
    inputs: Mapping[str, str]


def _table(columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> list[str]:
    """A Markdown table; an empty cell is shown as ``-``."""
    out = ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    out += ["| " + " | ".join(str(c) if str(c) != "" else "-" for c in r) + " |" for r in rows]
    return out


def _ratio(n: int, total: int) -> str:
    """``n/N (p %)``, one decimal."""
    return f"{n}/{total} ({100.0 * n / total:.1f} %)" if total else "0/0"


def _reported_rows(rows: Sequence[Mapping[str, str]]) -> list[tuple[str, str, int, int, str]]:
    """(role, kind, rows, labelled, labelled with the expected technique) of the unscored rows, sorted."""
    acc: dict[tuple[str, str], list[int]] = {}
    for r in rows:
        if r["scored"] == "1":
            continue
        slot = acc.setdefault((r["role"], r["kind"]), [0, 0, 0])
        slot[0] += 1
        slot[1] += r["labelled"] == "1"
        slot[2] += r["labelled_expected"] == "1"
    return [(role, kind, v[0], v[1], "-" if EXPECTED[kind] == NONE else str(v[2]))
            for (role, kind), v in sorted(acc.items(), key=lambda kv: (kv[0][0], KIND_ORDER.index(kv[0][1])))]


def summary_md(split: str, results: Sequence[TrialRecall]) -> str:
    """``label_recall.md``: recall per technique and overall over the keyed trials, every scored miss by uid, the
    reported-only rows, the key events of no table kind, and the key-free label counts of every trial."""
    keyed = [r for r in results if r.rows is not None]
    all_rows = [row for r in keyed for row in (r.rows or ())]
    lines = [md_header(split, None), "",
             f"Labelling recall (PLAN T8.3; spec 04 LBA-04) over {len(keyed)} keyed trials; "
             f"{len(results) - len(keyed)} trials without a key give counts only.", "",
             "Development numbers, not results (decision 019). Never run on t02–t10 before T10.",
             "Scored rows: attack key hops and confirmed key steps. Benign and background key hops and every target "
             "4624 (expected: none) are reported, never scored as right or wrong.", "", COVERAGE_NOTE, "",
             MATCH_NOTE, ""]
    lines += ["## Recall per expected technique (scored rows)", ""]
    lines += _table(("expected_technique", "labelled_expected / scored"),
                    [(t, _ratio(n, k)) for t, (n, k) in recall_counts(all_rows).items()])
    lines += ["", "## Recall per trial", ""]
    lines += _table(("trial_id", "rows", "scored", "labelled_expected / scored"),
                    [(r.trial_id, len(r.rows or ()), sum(x["scored"] == "1" for x in r.rows or ()),
                      _ratio(*recall_counts(r.rows or ()).get("overall", (0, 0)))) for r in keyed])
    misses = [x for x in all_rows if x["scored"] == "1" and x["labelled_expected"] != "1"]
    lines += ["", f"## Scored key events not labelled with the expected technique ({len(misses)})", ""]
    lines += _table(("trial_id", "hop_or_step_id", "kind", "event_uid", "expected_technique", "labelled",
                     "rule_ids"),
                    [(x["trial_id"], x["hop_or_step_id"], x["kind"], x["event_uid"], x["expected_technique"],
                      x["labelled"], x["rule_ids"]) for x in misses]) if misses else ["none"]
    lines += ["", "## Reported only (not scored)", ""]
    lines += _table(("role", "kind", "rows", "labelled", "labelled_expected"), _reported_rows(all_rows))
    lines += ["", "## Key events of no table kind (counted, no row)", ""]
    lines += _table(("trial_id", "channel event_id: distinct uids"),
                    [(r.trial_id, ", ".join(f"{k}: {v}" for k, v in r.unkinded.items())) for r in keyed])
    techs = sorted({t for r in results for t in r.counts["events_per_technique"]})
    lines += ["", "## Label counts per trial (key-free; the only numbers for trials without a key)", ""]
    lines += _table(("trial_id", "keyed", "label_rows", "labelled_events") + tuple(techs),
                    [(r.trial_id, "yes" if r.rows is not None else "no", r.counts["label_rows"],
                      r.counts["labelled_events"]) + tuple(r.counts["events_per_technique"].get(t, 0) for t in techs)
                     for r in results])
    rules = sorted({k for r in results for k in r.counts["rows_per_rule"]})
    lines += ["", "## Label rows per rule", ""]
    lines += _table(("trial_id",) + tuple(rules),
                    [(r.trial_id,) + tuple(r.counts["rows_per_rule"].get(k, 0) for k in rules) for r in results])
    names = sorted({k for r in results for k in r.inputs})
    lines += ["", "## Inputs (SHA-256)", ""]
    lines += _table(("trial_id",) + tuple(names), [(r.trial_id,) + tuple(r.inputs.get(n, "") for n in names)
                                                   for r in results])
    return "\n".join(lines) + "\n"
