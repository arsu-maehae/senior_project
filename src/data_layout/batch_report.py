"""Pure helpers for the x10 batch ingest report: expected files, reconcile checks, Markdown.

Nothing here touches the disk; batch.py gathers the facts and passes them in, so every
check can be tested with plain dicts.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

# Decision 029, criterion a: 4 hosts x 5 logs per trial (owner: keep `dc01`, matching t00).
EXPECTED_HOSTS: tuple[str, ...] = ("dc01", "ep-01", "ep-02", "ep-03")
EXPECTED_CHANNELS: tuple[str, ...] = ("security", "system", "sysmon", "winrm", "powershell")

_NAME_HINTS: tuple[tuple[str, str], ...] = (
    ("sysmon", "sysmon"),
    ("winrm", "winrm"),
    ("powershell_operational", "powershell"),
    ("powershell-operational", "powershell"),
    ("_security", "security"),
    ("_system", "system"),
)


def channel_hint_from_name(file_name: str) -> Optional[str]:
    """Guess a channel from the export file name, for the dry-run plan and missing-file notes only.

    WHY: the real channel always comes from the first record (layout.classify_file); a name
    hint is only used where we must not parse (dry-run) or to explain why a slot is empty."""
    stem = file_name.lower().rsplit(".", 1)[0]
    for needle, channel in _NAME_HINTS:
        if needle in stem:
            return channel
    return None


def missing_slots(present: Iterable[tuple[str, str]],
                  ignored: Iterable[Mapping[str, str]] = ()) -> list[dict[str, str]]:
    """Expected (host, channel) slots with no copied file, each with a reason.

    WHY: missing files are recorded, never invented; an ignored file whose name points at
    the slot (e.g. an empty export) is named so the owner sees it was there but unusable."""
    have = set(present)
    ignored_by_slot: dict[tuple[str, str], str] = {}
    for row in ignored:
        hint = channel_hint_from_name(row["source_path"].rsplit("/", 1)[-1])
        if row.get("host") and hint:
            ignored_by_slot[(row["host"], hint)] = f"file present but ignored: {row['source_path']} ({row['reason']})"
    hosts_with_files = {h for h, _ in have} | {h for h, _ in ignored_by_slot}
    out = []
    for host in EXPECTED_HOSTS:
        for channel in EXPECTED_CHANNELS:
            if (host, channel) in have:
                continue
            reason = ignored_by_slot.get((host, channel)) or (
                "no file in the host folder" if host in hosts_with_files else "host folder absent")
            out.append({"host": host, "channel": channel, "reason": reason})
    return out


def extra_files(present: Iterable[tuple[str, str]]) -> list[dict[str, str]]:
    """Copied files outside the 4 x 5 grid (e.g. psclassic): kept, but listed so counts add up."""
    return [{"host": h, "channel": c} for h, c in sorted(set(present))
            if h not in EXPECTED_HOSTS or c not in EXPECTED_CHANNELS]


def _check(name: str, ok: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "detail": detail}


def file_checks(copied: Mapping[str, Mapping[str, Any]], manifest_rows: Mapping[str, Mapping[str, str]],
                converter: Mapping[str, Mapping[str, Any]], imported: Mapping[str, Mapping[str, Any]],
                incoming_sha: Mapping[str, str]) -> list[dict[str, Any]]:
    """Per-file accounting from incoming to DB, keyed by the trial-relative raw path (host/channel.evtx).

    WHY: the t00 import reconciled record counts file by file (NF-17); the batch repeats that
    chain end to end so a lost or duplicated record shows up at the step where it happened:
    incoming sha == raw sha == manifest sha == converter pre-run sha; manifest records ==
    converter attempted == emitted (0 parse errors) == import lines_read == kept + excluded."""
    checks = []
    for rel, cp in sorted(copied.items()):
        man, conv, imp = manifest_rows.get(rel), converter.get(rel), imported.get(rel)
        if man is None or conv is None or imp is None:
            missing = [n for n, v in (("manifest", man), ("converter", conv), ("import", imp)) if v is None]
            checks.append(_check(f"{rel}: present in every step", False, f"absent from {', '.join(missing)}"))
            continue
        shas = {incoming_sha.get(cp["source_path"]), cp["sha256"], man["sha256"], conv["pre_run_sha256"],
                conv["post_run_sha256"]}
        checks.append(_check(f"{rel}: sha256 incoming = raw = manifest = converter", len(shas) == 1,
                             "match" if len(shas) == 1 else f"distinct values {sorted(map(str, shas))}"))
        records = int(man["records"])
        att, emi, err = (int(conv["attempted_record_count"]), int(conv["emitted_event_count"]),
                         int(conv["parse_error_count"]))
        checks.append(_check(f"{rel}: records manifest = converter attempted = emitted, 0 parse errors",
                             records == att == emi and err == 0,
                             f"manifest {records}, attempted {att}, emitted {emi}, parse errors {err}"))
        split = int(imp["kept"]) + int(imp["excluded_not_relevant"]) + int(imp["excluded_bad_event_id"])
        checks.append(_check(f"{rel}: import lines_read = emitted = kept + excluded",
                             int(imp["lines_read"]) - int(imp["blank_lines"]) == emi == split,
                             f"lines {imp['lines_read']} (blank {imp['blank_lines']}), kept {imp['kept']}, "
                             f"not relevant {imp['excluded_not_relevant']}, bad id {imp['excluded_bad_event_id']}"))
    return checks


def trial_checks(import_report: Mapping[str, Any], copied_count: int, converter_files: int) -> list[dict[str, Any]]:
    """Trial-level reconcile: file counts agree and every post-load check of the t00 import passed."""
    per_file = import_report.get("per_file", [])
    kept = sum(int(p["kept"]) for p in per_file)
    events, dedup = int(import_report["events"]), int(import_report["events_dedup"])
    checks = [
        _check("files copied = converted = imported", copied_count == converter_files == len(per_file),
               f"copied {copied_count}, converted {converter_files}, imported {len(per_file)}"),
        _check("events = sum of kept", events == kept, f"events {events}, kept {kept}"),
        _check("events_dedup <= events", dedup <= events, f"events_dedup {dedup}, events {events}"),
    ]
    for name, passed in sorted(import_report.get("checks", {}).items()):
        checks.append(_check(f"import check {name}", passed, "PASS" if passed else "FAIL"))
    return checks


def hash_diff(before: Mapping[str, str], after: Mapping[str, str]) -> dict[str, Any]:
    """Compare incoming hashes taken before and after the trial; any difference is fatal."""
    changed = sorted(k for k in before.keys() & after.keys() if before[k] != after[k])
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    return {"files": len(before), "unchanged": not (changed or added or removed),
            "changed": changed, "added": added, "removed": removed}


def _fmt_bytes(n: Optional[int]) -> str:
    if n is None:
        return "n/a"
    return f"{n / (1 << 20):,.1f} MiB ({n:,} B)"


def render_markdown(report: Mapping[str, Any]) -> str:
    """Human-readable twin of ingest.json (same facts, no new ones)."""
    r = report
    lines = [f"# Ingest {r['trial_id']}", "",
             f"- status: **{r['status']}**" + (f" — {r['error']}" if r.get("error") else ""),
             f"- quarantine: {r['quarantine']}", f"- source: `{r['source_dir']}`",
             f"- raw: `{r['raw_dir']}`", f"- JSONL: `{r['jsonl_dir']}`", f"- database: `{r['database']}`",
             f"- manifest: `{r['manifest']}`", f"- started {r['started_utc']}, finished {r.get('finished_utc')}, "
             f"{r.get('duration_seconds')} s; phases {r.get('phase_seconds')}", "",
             "## Sizes", ""]
    for k, v in r.get("sizes_bytes", {}).items():
        lines.append(f"- {k}: {_fmt_bytes(v)}")
    lines += ["", f"## Files copied ({len(r.get('files_copied', []))})", "",
              "| source | dest | sha256 | size | action |", "|---|---|---|---:|---|"]
    for f in r.get("files_copied", []):
        lines.append(f"| `{f['source_path']}` | `{f['dest_path']}` | `{f['sha256'][:16]}…` | {f['size']:,} | {f['action']} |")
    lines += ["", f"## Files expected but missing ({len(r.get('files_missing', []))})", ""]
    lines += [f"- {m['host']} / {m['channel']}: {m['reason']}" for m in r.get("files_missing", [])] or ["- none"]
    lines += ["", "## Files ignored", ""]
    lines += [f"- `{f['source_path']}`: {f['reason']}" for f in r.get("files_ignored", [])] or ["- none"]
    lines += ["", "## Extra files (outside 4 hosts x 5 logs)", ""]
    lines += [f"- {e['host']} / {e['channel']}" for e in r.get("extra_files", [])] or ["- none"]
    lines += ["", "## Converter (EVTX -> JSONL)", "", "| file | attempted | emitted | parse errors | status |",
              "|---|---:|---:|---:|---|"]
    for c in r.get("converter", []):
        lines.append(f"| `{c['relative_path']}` | {c['attempted_record_count']:,} | {c['emitted_event_count']:,} | "
                     f"{c['parse_error_count']} | {c['status']} |")
    imp = r.get("import") or {}
    lines += ["", "## Import (JSONL -> SQLite)", ""]
    if imp:
        lines += [f"- events {imp['events']:,}; events_dedup {imp['events_dedup']:,}; "
                  f"exact duplicates {imp['duplicates_exact']:,}; near duplicates {imp['duplicates_near']:,}", "",
                  "| file | lines | kept | not relevant | bad id |", "|---|---:|---:|---:|---:|"]
        for p in imp.get("per_file", []):
            lines.append(f"| `{p['relative_path']}` | {p['lines_read']:,} | {p['kept']:,} | "
                         f"{p['excluded_not_relevant']:,} | {p['excluded_bad_event_id']} |")
    else:
        lines.append("- not run")
    rec = r.get("reconcile") or {}
    lines += ["", f"## Reconcile: {'ok' if rec.get('ok') else 'NOT ok'}", ""]
    lines += [f"- [{'x' if c['ok'] else ' '}] {c['name']} — {c['detail']}" for c in rec.get("checks", [])
              if not c["ok"]] or ["- every check passed"]
    lines.append(f"- {sum(c['ok'] for c in rec.get('checks', []))} of {len(rec.get('checks', []))} checks passed")
    h = r.get("incoming_hashes") or {}
    lines += ["", "## Incoming files (read-only check)", "",
              f"- {h.get('files')} files hashed before and after; unchanged: {h.get('unchanged')}"]
    for k in ("changed", "added", "removed"):
        if h.get(k):
            lines.append(f"- {k}: {', '.join(h[k])}")
    return "\n".join(lines) + "\n"
