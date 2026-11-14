"""Development check of T7.3: ``python -m stitch.check_links --trial <id> [--repo PATH]`` (cwd=src or PYTHONPATH=src).

Runs ``links.run_links_checked`` (ST-00 with the development allowlist first, then one read-only hash bracket around
the scan, the command facts and the assembly) and writes ``out/stitch_check/<trial_id>/t73_links.json``: counts,
data limits, one row per hop with its link rows, and one row per artefact (plan T7.3 section 1). It is not a spec 03
output file; the spec 3 files start in T7.4 / T7.5.

What the file never holds (spec 2; spec 00 LC-13; plan section 1): any part of a command line, any account name
(member, source session or 4648 credential account), any image. Names in it are target-side names only (artefact
``names`` and the ``names_found`` of command evidence, both taken from target-side events). WHY the rows are built
field by field from an allowlist of keys and not by dumping the dataclasses: a field added to ``LinkRow`` or
``RemoteLogon`` later (an account, say) can then never leak into the file by accident.

WHY build first and write last: on any refusal nothing may be written (spec 2), so the folder is created only after
every check has passed and the JSON text is complete. A refusal prints ``refused: <reason>`` and exits 2. Sorted
keys, indent 1, no timestamps: two runs on the same inputs give the same bytes.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from gate.run import display_path
from gate.timeutil import fmt_us

from .artefacts import ArtefactRow
from .check_index import REPO, _reason, check_text
from .errors import StitchError
from .hops import Hop
from .index import jsonable, params_dict
from .links import HostLimit, LinkIndex, run_links_checked
from .params import CHECK_OUT_REL, TOOL_VERSION, StitchParams
from .source import LinkRow, SubjectLinks

__all__ = ["CHECK_FILE", "hop_record", "link_record", "artefact_record", "limit_record", "links_check_data",
           "run_check", "write_check", "main"]

CHECK_FILE = "t73_links.json"


def link_record(r: LinkRow) -> dict[str, Any]:
    """One link row: ids, counts, deltas, uids and target-side names; NO account (session or 4648 credential)."""
    return {
        "method": r.method,
        "session_methods": list(r.session_methods),
        "source_session_id_hex": r.source_session_id_hex,
        "session_unresolved_reason": r.session_unresolved_reason,
        "candidate_count": r.candidate_count,
        "matched_member_count": r.matched_member_count,
        "time_delta_ms": r.time_delta_ms,
        "time_delta_raw_ms": r.time_delta_raw_ms,
        "supporting_event_uids": list(r.supporting_event_uids),
        "clock_unreliable": r.clock_unreliable,
        "source_session_logon_type": r.source_session_logon_type,
        "source_session_logon_uid": list(r.source_session_logon_uids),
        "names_found": list(r.names_found),
    }


def hop_record(h: Hop, sl: SubjectLinks, li: LinkIndex) -> dict[str, Any]:
    """One hop: facts of its members (uids, hex IDs, ports; never accounts), flags, artefact summary, confirmation,
    link summary and its link rows. ``clock_unreliable`` = the members' event flags or the source / target host
    flag (ST-02: "a host of the row is none / wide / stale, or an event of the row ...")."""
    confirm, confirm_uids = li.confirm[h.hop_id]
    return {
        "hop_id": h.hop_id,
        "target_host": h.target_host,
        "source_ip": h.source_ip,
        "ip_kind": h.ip_kind,
        "source_host": sl.source_host,
        "protocol": h.protocol,
        "rules": list(h.rules),
        "is_seed": h.is_seed,
        "first_utc": h.first_utc,
        "first_utc_corrected": h.first_utc_corrected,
        "last_utc_corrected": h.last_utc_corrected,
        "member_count": h.member_count,
        "member_logon_uids": h.member_uids,
        "member_logon_ids_hex": [m.logon_id_hex for m in h.members],
        "member_ports": [m.source_port for m in h.members],
        "mixed_account": h.mixed_account,
        "authentication_packages": list(h.authentication_packages),
        "followup_logon_uids": [u for m in h.followups for u in m.event_uids],
        "inside_gap_max_ms": h.inside_gap_max_ms,
        "prev_gap_ms": h.prev_gap_ms,
        "next_gap_ms": h.next_gap_ms,
        "gap_near_threshold": h.gap_near_threshold,
        "splits_at_1s": h.splits_at_1s,
        "merges_at_3s": h.merges_at_3s,
        "shares_port_with_hops": list(h.shares_port_with_hops),
        "service_install_count": li.artefacts.service_install_count.get(h.hop_id, 0),
        "supporting_span_ms": li.artefacts.supporting_span_ms.get(h.hop_id),
        "confirm": confirm,
        "confirm_event_uids": list(confirm_uids),
        "candidate_count_all": sl.candidate_count_all,
        "evidence_before_range": sl.evidence_before_range,
        "evidence_after_range": sl.evidence_after_range,
        "target_only_reason": sl.target_only_reason,
        "clock_unreliable": max(h.clock_unreliable, sl.host_clock_unreliable),
        "gate_clock_unreliable": h.gate_clock_unreliable,
        "links": [link_record(r) for r in sl.rows],
    }


def artefact_record(r: ArtefactRow) -> dict[str, Any]:
    """One artefact row (spec 3 ``hop_artefacts.csv`` columns); ``names`` are target-side names only."""
    return {
        "hop_id": r.hop_id,
        "kind": r.kind,
        "member_logon_uid": r.member_logon_uid,
        "logged_under_hop_id": r.logged_under_hop_id,
        "method": r.method,
        "candidate_count": r.candidate_count,
        "time_delta_ms": r.time_delta_ms,
        "supporting_span_ms": r.supporting_span_ms,
        "confidence_tier": r.confidence_tier,
        "event_uids": list(r.event_uids),
        "names": list(r.names),
        "untied_same_name_bursts": list(r.untied_same_name_bursts),
    }


def limit_record(lim: HostLimit) -> dict[str, Any]:
    """One host of the data limits (048 item 13): times, counts and ids only."""
    return {
        "last_security_event_uid": lim.last_security_uid,
        "last_security_utc": fmt_us(lim.last_security_us_raw),
        "last_security_utc_corrected": fmt_us(lim.last_security_us),
        "ms_before_window_end": lim.ms_before_window_end,
        "evidence_after": dict(lim.evidence_after),
        "evidence_after_event_uids": {m: list(u) for m, u in lim.evidence_after_uids.items()},
        "data_limitation": lim.data_limitation,
        "hops_near_end": list(lim.hops_near_end),
    }


def _artefact_order(r: ArtefactRow) -> tuple[str, int, str, str]:
    """The artefact set's own order (hop id, first event, kind, first uid), restated so the file order is fixed."""
    return r.hop_id, r.first_us_raw, r.kind, r.event_uids[0] if r.event_uids else ""


def links_check_data(li: LinkIndex, extra: dict[str, Any]) -> dict[str, Any]:
    """The check-file dict: ``extra`` (file-level facts) plus trial id, tool version, counts, data limits, hops
    (by hop id) and artefacts. JSON-ready, keys sorted by ``jsonable``."""
    hops = sorted(li.hopset.hops, key=lambda h: h.hop_id)
    out: dict[str, Any] = dict(extra)
    out.update({
        "trial_id": li.trial_id,
        "tool_version": TOOL_VERSION,
        "counts": li.counts,
        "data_limits": {host: limit_record(lim) for host, lim in sorted(li.data_limits.items())},
        "hops": [hop_record(h, li.links[h.hop_id], li) for h in hops],
        "artefacts": [artefact_record(r) for r in sorted(li.artefacts.rows, key=_artefact_order)],
    })
    return jsonable(out)


def run_check(repo: Path, trial_id: str, params: StitchParams = StitchParams()) -> dict[str, Any]:
    """ST-00, scan, assembly for one trial; returns the check-file dict and writes nothing (StitchError on refusal)."""
    repo = Path(repo)
    li, checked, paths, before, after = run_links_checked(repo, trial_id, params)
    extra = {
        "db": {"path": display_path(paths.db, repo), "sha256_before": before, "sha256_after": after},
        "gate_stats_sha256": checked.gate_stats_sha256,
        "parameters": params_dict(params),
    }
    return links_check_data(li, extra)


def write_check(repo: Path, trial_id: str, data: dict[str, Any]) -> Path:
    """Write ``out/stitch_check/<trial_id>/t73_links.json`` (UTF-8, LF) through a temporary file and ``os.replace``,
    so an existing file is kept whole or replaced whole. The text is built before the folder is created."""
    text = check_text(data)
    out_dir = Path(repo) / CHECK_OUT_REL / trial_id
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / CHECK_FILE
    tmp = out_dir / (CHECK_FILE + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, target)
    return target


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run, write. Exit 0 on success, 2 on a refusal (reason on stderr, nothing written)."""
    ap = argparse.ArgumentParser(prog="stitch.check_links", description=__doc__)
    ap.add_argument("--trial", required=True)
    ap.add_argument("--repo", type=Path, default=REPO)
    a = ap.parse_args(argv)
    repo = a.repo.resolve()
    try:
        data = run_check(repo, a.trial)
    except StitchError as exc:
        print(f"refused: {_reason(exc)}", file=sys.stderr)
        return 2
    path = write_check(repo, a.trial, data)
    c = data["counts"]
    print(f"{a.trial}: {c['hops']} hop(s), {c['followup_groups']} follow-up group(s), "
          f"{len(data['artefacts'])} artefact row(s), data limitation host(s): {c['data_limitation_hosts'] or 'none'}")
    print(f"wrote {display_path(path, repo)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
