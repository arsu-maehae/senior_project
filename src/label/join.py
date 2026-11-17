"""Node and hop join (spec 04_label LB-08, section 3.4 ``node_labels.csv`` / ``hop_labels.csv``).

WHY pure and separate: the labels never depend on the stitch outputs (spec 2: "node join only"); the join only reads
the stitcher's rows as text and the label matches, so a test can hand-build both. The join adds attributes and never
adds, drops or reorders a stitch row (spec 1): one node row per ``path_nodes.csv`` row, one hop row per ``hops.csv``
row, both in the stitcher's order.

A uid "has a label" when it is a label's representative uid or one of its LB-03 copies. A node is labelled when its
uid, or any ST-05 copy of it the stitcher lists in ``hops.csv`` ``member_logon_uids`` (``;`` between members, ``|``
between the copies of one member, decision 055), has a label (LB-08).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from gate.timeutil import to_us

from .errors import LabelError
from .labels import Match

__all__ = ["MEMBER_SEP", "COPY_SEP", "DUMP_OUTSIDE", "LabelFacts", "label_facts", "stitch_copy_groups",
           "uid_group", "node_facts", "node_label_rows", "dump_time_us", "dump_uids_of_hop", "hop_label_rows"]

MEMBER_SEP, COPY_SEP = ";", "|"
DUMP_OUTSIDE = "outside_window"      # spec 3.4: a dump read that is not an in-window event (ST-63 look-back)


@dataclass
class LabelFacts:
    """Per uid: the rule ids, primary techniques and highest level value of its labels."""
    rule_ids: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    max_level_value: int | None = None

    def add(self, other: "LabelFacts") -> None:
        """Merge another uid's facts into this one (a node and its copies)."""
        self.rule_ids |= other.rule_ids
        self.techniques |= other.techniques
        if other.max_level_value is not None:
            self.max_level_value = max(other.max_level_value, self.max_level_value or 0)


def label_facts(matches: Iterable[Match]) -> dict[str, LabelFacts]:
    """uid -> LabelFacts over every uid each label stands for (representative and LB-03 copies).

    WHY primary techniques (``technique``) and not every tag: the node and hop columns answer "which technique does
    this node show" (spec 7 recall table, §10.6), and a second tag such as T1059.001 is not a technique the rule was
    chosen for (Q3). All tags stay on the ``event_labels.csv`` row (``techniques``).
    """
    out: dict[str, LabelFacts] = {}
    for m in matches:
        for uid in m.event.uids:
            f = out.setdefault(uid, LabelFacts())
            f.rule_ids.add(m.rule.rule_id)
            f.techniques.add(m.rule.technique)
            f.max_level_value = max(m.rule.level_value, f.max_level_value or 0)
    return out


def stitch_copy_groups(hops: Iterable[Mapping[str, str]]) -> dict[str, frozenset[str]]:
    """uid -> all uids of the same event as the stitcher lists them in ``member_logon_uids`` (ST-05 copies)."""
    out: dict[str, frozenset[str]] = {}
    for h in hops:
        for item in h["member_logon_uids"].split(MEMBER_SEP):
            group = frozenset(u for u in item.split(COPY_SEP) if u)
            for u in group:
                out[u] = out.get(u, frozenset()) | group
    return out


def uid_group(uid: str, copies: Mapping[str, frozenset[str]]) -> frozenset[str]:
    """The uid and its stitcher copies."""
    return copies.get(uid, frozenset()) | {uid}


def node_facts(uid: str, facts: Mapping[str, LabelFacts], copies: Mapping[str, frozenset[str]]) -> LabelFacts:
    """Merged label facts of a node uid and its copies (empty when none is labelled)."""
    acc = LabelFacts()
    for u in sorted(uid_group(uid, copies)):
        if u in facts:
            acc.add(facts[u])
    return acc


def _joined(values: Iterable[str]) -> str:
    """Sorted distinct values, ``;``-joined."""
    return ";".join(sorted(set(values)))


def _level_text(value: int | None) -> str:
    """A level value as text, empty when there is none."""
    return "" if value is None else str(value)


def node_label_rows(path_nodes: Sequence[Mapping[str, str]], facts: Mapping[str, LabelFacts],
                    copies: Mapping[str, frozenset[str]]) -> list[dict[str, str]]:
    """One ``node_labels.csv`` row per ``path_nodes.csv`` row, in its order, labelled or not (LB-08, LBA-01).
    ``context`` is carried unchanged so T9 can choose (Q6)."""
    rows = []
    for n in path_nodes:
        f = node_facts(n["event_uid"], facts, copies)
        labelled = bool(f.rule_ids)
        rows.append({
            "path_id": n["path_id"], "hop_id": n["hop_id"], "role": n["role"],
            "context": n["context"], "host": n["host"], "event_uid": n["event_uid"],
            "labelled": "1" if labelled else "0", "rule_ids": _joined(f.rule_ids),
            "techniques": _joined(f.techniques), "max_level_value": _level_text(f.max_level_value),
        })
    return rows


def dump_time_us(text: str, hop_id: str) -> int:
    """A ``dump_utc_corrected`` cell as microseconds; LabelError when it is empty or does not parse (stage review
    S05 d). WHY a refusal and not 0: a dump with no usable time would silently sort first and could hide which read
    is which in ``dump_labelled``."""
    try:
        if not text:
            raise ValueError("empty")
        return to_us(text)
    except (ValueError, TypeError) as exc:
        raise LabelError(f"refused: hop_identity.csv hop {hop_id}: dump_utc_corrected does not parse ({exc})") from None


def dump_uids_of_hop(identity_rows: Iterable[Mapping[str, str]]) -> dict[str, list[str]]:
    """hop id -> distinct non-empty ``dump_event_uid`` values of its ``hop_identity.csv`` rows, ordered by the
    dump's corrected time, then uid (the file has several rows per hop, one per account and read)."""
    seen: dict[str, dict[str, int]] = {}
    for r in identity_rows:
        uid = r["dump_event_uid"]
        if not uid:
            continue
        us = dump_time_us(r["dump_utc_corrected"], r["hop_id"])
        slot = seen.setdefault(r["hop_id"], {})
        slot[uid] = min(us, slot.get(uid, us))
    return {h: [u for u, _t in sorted(d.items(), key=lambda kv: (kv[1], kv[0]))] for h, d in seen.items()}


def _dump_state(uid: str, facts: Mapping[str, LabelFacts], in_window: frozenset[str],
                copies: Mapping[str, frozenset[str]]) -> str:
    """``1`` labelled, ``0`` in-window and unlabelled, ``outside_window`` not an in-window event (look-back read)."""
    group = uid_group(uid, copies)
    if not group & in_window:
        return DUMP_OUTSIDE
    return "1" if any(u in facts for u in group) else "0"


def hop_label_rows(hops: Sequence[Mapping[str, str]], node_rows: Sequence[Mapping[str, str]],
                   identity_rows: Iterable[Mapping[str, str]], facts: Mapping[str, LabelFacts],
                   copies: Mapping[str, frozenset[str]], in_window: frozenset[str]) -> list[dict[str, str]]:
    """One ``hop_labels.csv`` row per ``hops.csv`` row, in its order (spec 3.4).

    ``n_node_events`` / ``n_labelled_node_events`` count distinct node event uids of the hop over all paths holding
    it (any ``context``); ``n_labelled_context0_node_events`` counts those labelled on a ``context`` = 0 node row, and
    ``techniques`` are those of the labelled ``context`` = 0 node rows only. WHY context 0 for techniques (stage
    review S03; owner Q6 / 056: context 1 stays out of NodeScore): the context = 1 rows hold the source-session LSASS
    reads (SR-01 / SR-02), so counting them would make a movement hop whose only label is a dump look labelled with
    a movement technique family. The dump columns are facts about the LSASS reads of the
    hop's ``hop_identity.csv`` rows: ``dump_labelled`` holds one value per uid of ``dump_event_uids``, in the same
    order (several reads per hop are the rule in the data); they never change identity (Q1, Q2; ATK-L02).
    """
    by_hop: dict[str, dict[str, dict[str, str]]] = {}
    ctx0: dict[str, dict[str, dict[str, str]]] = {}
    for n in node_rows:
        by_hop.setdefault(n["hop_id"], {})[n["event_uid"]] = n
        if n["context"] == "0" and n["labelled"] == "1":
            ctx0.setdefault(n["hop_id"], {})[n["event_uid"]] = n
    dumps = dump_uids_of_hop(identity_rows)
    rows = []
    for h in hops:
        hid = h["hop_id"]
        nodes = by_hop.get(hid, {})
        lab = [n for n in nodes.values() if n["labelled"] == "1"]
        lab0 = ctx0.get(hid, {})
        techs = {t for n in lab0.values() for t in n["techniques"].split(";") if t}
        d_uids = dumps.get(hid, [])
        d_facts = LabelFacts()
        for u in d_uids:
            d_facts.add(node_facts(u, facts, copies))
        rows.append({
            "hop_id": hid, "in_path": h["in_path"], "n_node_events": str(len(nodes)),
            "n_labelled_node_events": str(len(lab)), "n_labelled_context0_node_events": str(len(lab0)),
            "techniques": _joined(techs),
            "dump_event_uids": ";".join(d_uids),
            "dump_labelled": ";".join(_dump_state(u, facts, in_window, copies) for u in d_uids),
            "dump_rule_ids": _joined(d_facts.rule_ids), "dump_max_level_value": _level_text(d_facts.max_level_value),
        })
    return rows
