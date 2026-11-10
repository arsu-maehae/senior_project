"""LC-04h: Security 4648 coverage per hop instance (decision 013).

Why: LC-04e uses a 4648 only to rescue a command-line candidate whose account differs
from the 4624 account. LC-04h asks the independent question: on the source host, which
logon sessions issued explicit credentials to the target around the hop, whatever account
they used? That gives a second, command-line-free source-session candidate per hop
(method `source_4648`) and shows where it agrees or disagrees with the command-line join.
A 4648 is written by the client before it authenticates, with SubjectLogonId (the session
that asked), TargetUserName (`account_name`, credentials used) and TargetServerName.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .bridge import EXPLICIT_SQL, session_of, target_texts
from .checks_smb import HopEval, ZERO_UNKNOWN_SOURCE, confidence_tier
from .common import (INFO, PREDEFINED_LOGON_IDS, CheckResult, Context, account_from_subject,
                     gated_status, hex_id, session_logon)
from .db import normalise_sql
from .hops import HopInstance
from .matching import names_target, target_name_forms
from .params import Params
from .timeutil import delta_ms, seconds, to_display

METHOD_4648 = "source_4648"
COVERED_PROTOCOLS = ("SMB", "WinRM")
MATCH_DIRECT, MATCH_4648, MATCH_NONE = "direct", "4648", "none"  # decision 013 account_match

# Per-hop comparison of 4648 sessions with the LC-04 command-line sessions.
CMP_NO_4648 = "no_naming_4648"
CMP_NO_CMDLINE = "no_cmdline_session"
CMP_SAME = "same"
CMP_PARTIAL = "partial"
CMP_DIFFERS = "differs"


# --- pure evaluation ---------------------------------------------------------------------

def subject_account_of(row: dict[str, Any]) -> str | None:
    """4648 subject account (who asked), `lab\\svc_backup` → `svc_backup`.

    Falls back to SubjectUserName in field_values_json when the normalised column is empty,
    so a session is never shown without an account when the raw event has one.
    """
    account = account_from_subject(row.get("subject_account"))
    if account:
        return account
    try:
        fields = json.loads(row.get("field_values_json") or "{}")
    except json.JSONDecodeError:
        return None
    value = fields.get("subjectusername")
    value = value[0] if isinstance(value, list) and value else value
    return account_from_subject(value) if isinstance(value, str) and value != "-" else None


def naming_4648(rows: list[dict[str, Any]], forms: tuple[str, ...], t: datetime,
                before_s: float, after_s: float) -> list[dict[str, Any]]:
    """4648 rows in [t − before, t + after] whose target server names the target, ANY account.

    Uses the same target fields as the LC-04e bridge (bridge.target_texts) so that every
    bridging 4648 is also a covering 4648; only the account condition is dropped.
    """
    lo, hi = t - seconds(before_s), t + seconds(after_s)
    return [r for r in rows if r.get("t") is not None and lo <= r["t"] <= hi
            and any(names_target(text, forms) for text in target_texts(r))]


@dataclass
class Session4648:
    """One source logon session that issued ≥ 1 naming 4648 for a hop."""

    session_id: int | None
    rows: list[dict[str, Any]]
    subject_account: str | None
    logon: dict[str, Any] | None

    @property
    def event_uids(self) -> list[str]:
        return [r["event_uid"] for r in self.rows]

    @property
    def credentials(self) -> list[str]:
        """Accounts whose credentials this session used towards the target (TargetUserName)."""
        return sorted({r.get("account_name") or "" for r in self.rows} - {""})

    @property
    def predefined(self) -> bool:
        return self.session_id in PREDEFINED_LOGON_IDS

    def closest_t(self, t: datetime) -> datetime:
        """4648 nearest to the hop: one session can serve several hops (same reason as LC-04)."""
        return min((r["t"] for r in self.rows), key=lambda x: abs((x - t).total_seconds()))

    def account_match(self, hop_account: str) -> str:
        """Decision 013 account_match: `direct` if the session's own (subject) account is the
        4624 account; `4648` if not, but the credentials it supplied (TargetUserName) are;
        else `none`. Account is supporting evidence only: it sets the tier, never drops a row."""
        if self.subject_account == hop_account:
            return MATCH_DIRECT
        return MATCH_4648 if hop_account in self.credentials else MATCH_NONE


def group_sessions(rows: list[dict[str, Any]], host: str, logon_index: dict) -> list[Session4648]:
    """Distinct SubjectLogonId sessions, ordered by their first naming 4648.

    The subject account is taken from the 4648 itself (most frequent value, normally one);
    the source 4624 is looked up only for the logon type column.
    """
    by_sid: dict[int | None, list[dict[str, Any]]] = {}
    for r in sorted(rows, key=lambda r: (r["t"], r["event_uid"])):
        by_sid.setdefault(session_of(r), []).append(r)
    sessions = []
    for sid, group in by_sid.items():
        accounts = Counter(a for a in (subject_account_of(r) for r in group) if a)
        account = accounts.most_common(1)[0][0] if accounts else None
        logon = session_logon(logon_index, host, sid, group[0]["t"]) if sid is not None else None
        sessions.append(Session4648(sid, group, account, logon))
    return sessions


@dataclass
class Coverage:
    """LC-04h result for one hop instance."""

    rows: list[dict[str, Any]] = field(default_factory=list)
    sessions: list[Session4648] = field(default_factory=list)
    reason: str | None = None

    def consistent(self, hop_account: str) -> list[Session4648]:
        """Account-consistent sessions (LC-04g): account_match `direct` or `4648`."""
        return [s for s in self.sessions if s.account_match(hop_account) != MATCH_NONE]


def evaluate_coverage(hop: HopInstance, explicit_by_host: dict[str, list[dict[str, Any]]],
                      logon_index: dict, params: Params) -> Coverage:
    """Naming 4648s on the hop's source host in [t − CMD_BEFORE_S, t + CMD_AFTER_S]."""
    if hop.source_host is None:
        return Coverage(reason=ZERO_UNKNOWN_SOURCE)
    forms = target_name_forms(hop.target_host, params.host_ip.get(hop.target_host))
    rows = naming_4648(explicit_by_host.get(hop.source_host, []), forms, hop.t,
                       params.cmd_before_s, params.cmd_after_s)
    return Coverage(rows, group_sessions(rows, hop.source_host, logon_index))


def compare_with_cmdline(cov: Coverage, ev: HopEval | None) -> dict[str, Any]:
    """Do the 4648 sessions equal the LC-04 command-line session(s)?

    "The command-line session" = LC-04 sessions that pass the account filter incl. the
    LC-04e bridge (what data_reality.md calls the cmdline session, one per attack hop on
    t00). All LC-04 sessions before the filter are reported too, for the S04 case where
    the filter removes the other track.
    """
    cmd_all = [s.session_id for s in (ev.sessions if ev else [])]
    cmd_ok = [s.session_id for s in (ev.after_bridge if ev else [])]
    sids = [s.session_id for s in cov.sessions]
    if not sids:
        category = CMP_NO_4648
    elif not cmd_ok:
        category = CMP_NO_CMDLINE
    else:
        inside = sum(1 for sid in sids if sid in cmd_ok)
        category = CMP_SAME if inside == len(sids) else (CMP_PARTIAL if inside else CMP_DIFFERS)
    return {"comparison": category,
            "cmdline_sessions_account_consistent": [hex_id(x) for x in cmd_ok],
            "cmdline_sessions_all": [hex_id(x) for x in cmd_all],
            "sessions_in_cmdline_account_consistent": [hex_id(x) for x in sids if x in cmd_ok],
            "sessions_in_cmdline_all": [hex_id(x) for x in sids if x in cmd_all]}


def session_tier(s: Session4648, hop_account: str, n_consistent: int) -> str:
    """LC-04h tier: B for `direct` or `4648` with one consistent session, C for several, D for
    `none` (a 4648 is a name join, so never A; LC-04g)."""
    return confidence_tier(METHOD_4648, s.account_match(hop_account) != MATCH_NONE, n_consistent)


# --- report shaping ----------------------------------------------------------------------

def coverage_csv_rows(trial_id: str, hop: HopInstance, cov: Coverage) -> list[dict[str, Any]]:
    """hop_candidates.csv rows (method source_4648): one per distinct 4648 subject session.

    Count columns keep their meaning: before = all 4648 sessions; after_account = subject
    account equals the 4624 account (`direct`); after_4648_bridge = `direct` or `4648` (the
    LC-04e rule). The tier uses account_match (decision 013; see session_tier).
    No naming 4648 → no row (the absence is in report.json LC-04h).
    """
    after = [s for s in cov.sessions if s.account_match(hop.account_name) == MATCH_DIRECT]
    after_bridge = cov.consistent(hop.account_name)
    base = {"trial_id": trial_id, "protocol": hop.protocol, "hop_id": hop.hop_id,
            "target_host": hop.target_host, "target_event_uids": ";".join(hop.event_uids),
            "target_time_utc": to_display(hop.t), "account_name": hop.account_name,
            "source_ip": hop.source_ip, "source_port": hop.source_port,
            "source_host": hop.source_host or "", "method": METHOD_4648,
            "candidate_count_sessions_before_account": len(cov.sessions),
            "candidate_count_sessions_after_account": len(after),
            "candidate_count_sessions_after_4648_bridge": len(after_bridge)}
    rows = []
    for s in cov.sessions:
        rows.append({**base, "candidate_count_rows": len(s.rows),
                     "time_delta_ms": delta_ms(s.closest_t(hop.t), hop.t),
                     "confidence_tier": session_tier(s, hop.account_name, len(after_bridge)),
                     "candidate_session_id": hex_id(s.session_id) or "",
                     "candidate_account": s.subject_account or "",
                     "candidate_logon_type": (s.logon or {}).get("logon_type") or "",
                     "zero_reason": "",
                     "supporting_event_uids": ";".join(hop.event_uids + s.event_uids)})
    return rows


def _session_json(s: Session4648, hop: HopInstance, n_consistent: int) -> dict[str, Any]:
    """One entry per hop_candidates.csv source_4648 row, with account_match (not a CSV column)."""
    return {"session_id": hex_id(s.session_id), "subject_account": s.subject_account,
            "credentials_accounts": s.credentials,
            "account_match": s.account_match(hop.account_name),
            "confidence_tier": session_tier(s, hop.account_name, n_consistent),
            "predefined_system": s.predefined,
            "logon_type": (s.logon or {}).get("logon_type"),
            "logon_start": to_display(s.logon["t"]) if s.logon else None,
            "n_4648": len(s.rows), "first_4648": to_display(s.rows[0]["t"]),
            "time_delta_ms": delta_ms(s.closest_t(hop.t), hop.t),
            "target_servers": sorted({r.get("destination_host") or "" for r in s.rows} - {""}),
            "event_uids": s.event_uids}


def hop_coverage_json(hop: HopInstance, cov: Coverage, ev: HopEval | None, params: Params) -> dict[str, Any]:
    """Per-hop LC-04h detail for report.json."""
    return {"hop_id": hop.hop_id, "protocol": hop.protocol, "target_host": hop.target_host,
            "account_name": hop.account_name, "source_host": hop.source_host,
            "t_first_4624": to_display(hop.t), "scenario_account": hop.is_scenario_account(params),
            "reason": cov.reason, "n_4648": len(cov.rows), "n_sessions": len(cov.sessions),
            "n_sessions_account_consistent": len(cov.consistent(hop.account_name)),
            "account_match_counts": dict(Counter(s.account_match(hop.account_name) for s in cov.sessions)),
            "credentials_accounts": sorted({a for s in cov.sessions for a in s.credentials}),
            "sessions": [_session_json(s, hop, len(cov.consistent(hop.account_name))) for s in cov.sessions],
            **compare_with_cmdline(cov, ev)}


def summarise(details: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-trial counts asked by LC-04h (all covered hops, and scenario-account hops)."""
    def block(items: list[dict[str, Any]]) -> dict[str, Any]:
        cats = Counter(d["comparison"] for d in items)
        return {"hops": len(items),
                "with_naming_4648": [d["hop_id"] for d in items if d["n_4648"]],
                "without_naming_4648": [d["hop_id"] for d in items if not d["n_4648"]],
                "session_differs_from_cmdline": [d["hop_id"] for d in items
                                                 if d["comparison"] in (CMP_DIFFERS, CMP_PARTIAL)],
                "naming_4648_but_no_cmdline_session": [d["hop_id"] for d in items
                                                       if d["comparison"] == CMP_NO_CMDLINE],
                "comparison_counts": dict(cats)}
    return {"all": block(details), "scenario_account": block([d for d in details if d["scenario_account"]])}


def run_lc04h(ctx: Context, hops: list[HopInstance], explicit_by_host: dict[str, list[dict[str, Any]]],
              logon_index: dict, evals: dict[str, HopEval]) -> tuple[CheckResult, list[dict[str, Any]]]:
    """LC-04h on every SMB and WinRM hop instance; INFO (descriptive, decision 013)."""
    ctx.db.record("LC-04h", normalise_sql(EXPLICIT_SQL))
    ctx.db.share("LC-04h", "LC-04")  # hop instances and command-line sessions come from LC-04
    p = ctx.params
    covered = [h for h in hops if h.protocol in COVERED_PROTOCOLS]
    details, csv_rows = [], []
    for hop in covered:
        cov = evaluate_coverage(hop, explicit_by_host, logon_index, p)
        details.append(hop_coverage_json(hop, cov, evals.get(hop.hop_id), p))
        csv_rows += coverage_csv_rows(ctx.trial_id, hop, cov)
    summary_counts = summarise(details)
    a, s = summary_counts["all"], summary_counts["scenario_account"]
    summary = (f"{len(covered)} SMB/WinRM hop instances: {len(a['with_naming_4648'])} with ≥1 naming 4648, "
               f"{len(a['without_naming_4648'])} without, {len(a['session_differs_from_cmdline'])} where a 4648 "
               f"session differs from the cmdline session; scenario-account hops {s['hops']}: "
               f"{len(s['with_naming_4648'])} with / {len(s['without_naming_4648'])} without / "
               f"{len(s['session_differs_from_cmdline'])} differ")
    status, summary = gated_status(ctx, INFO, summary)
    return CheckResult(
        "LC-04h", "4648 coverage per SMB/WinRM hop (decision 013)", status, summary,
        "A second, command-line-free source-session candidate (method source_4648); where it "
        "differs from the command-line session the link is ambiguous for T7. Account is supporting "
        "evidence (account_match, decision 013). Kill criterion 3 of decision 013: a keyed hop "
        "using another account's credentials with no 4648 drops 4648 as a method.",
        {"params": {"CMD_BEFORE_S": p.cmd_before_s, "CMD_AFTER_S": p.cmd_after_s},
         "protocols": list(COVERED_PROTOCOLS), "summary": summary_counts, "hops": details}), csv_rows
