from __future__ import annotations

import json
import os
import platform
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from . import __version__
from .inventory import discover, is_evtx_signature, reject_overlap, sha256_file

SCHEMA_VERSION = "1.0"
MAX_SMOKE_BYTES = 100 * 1024 * 1024
PREFERRED = (
    "ep-03/dryrun_s05/ep03_winrm_s05.evtx",
    "ep-02/dryrun_s07/ep02_system.evtx",
    "ep-01/dryrun_s06/ep01_powershell.evt",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_value(node: ET.Element) -> Any:
    children = list(node)
    if not children:
        return node.text
    return {"tag": _local(node.tag), "attributes": dict(node.attrib), "text": node.text,
            "children": [_xml_value(child) if list(child) else {"tag": _local(child.tag), "attributes": dict(child.attrib), "text": child.text} for child in children]}


def parse_event(xml_text: str, source: dict[str, Any], hints: dict[str, Any], record_index: int) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    system_node = next((n for n in root if _local(n.tag) == "System"), None)
    system: dict[str, Any] = {"provider": None, "event_id": None, "event_record_id": None,
                              "channel": None, "computer": None, "timestamp_raw": None}
    if system_node is not None:
        for child in system_node:
            key = {"Provider": "provider", "EventID": "event_id", "EventRecordID": "event_record_id",
                   "Channel": "channel", "Computer": "computer"}.get(_local(child.tag))
            if key:
                system[key] = child.attrib.get("Name") if key == "provider" else child.text
            if _local(child.tag) == "TimeCreated":
                system["timestamp_raw"] = child.attrib.get("SystemTime")
    event_data: list[dict[str, Any]] = []
    user_data: Any = None
    for child in root:
        if _local(child.tag) == "EventData":
            for data in child:
                if _local(data.tag) == "Data":
                    event_data.append({"name": data.attrib.get("Name"), "value": data.text})
        elif _local(child.tag) == "UserData":
            user_data = _xml_value(child)
    src = dict(source)
    src["record_index"] = record_index
    return {"schema_version": SCHEMA_VERSION, "source": src, "hints": hints, "system": system,
            "event_data": event_data, "user_data": user_data, "raw_xml": xml_text}


def _iter_records(path: Path) -> Iterable[Any]:
    from evtx._native import PyEvtxParser

    class Record:
        def __init__(self, value: Any):
            self.value = value

        def xml(self) -> str:
            if isinstance(self.value, BaseException):
                raise self.value
            if isinstance(self.value, dict):
                self.value = self.value.get("data")
            if not isinstance(self.value, str):
                raise TypeError(f"Parser returned {type(self.value).__name__}, expected XML text")
            return self.value

    parser = PyEvtxParser(str(path), number_of_threads=1)
    for value in parser.records():
        yield Record(value)


def _atomic_jsonl(path: Path, entries: Iterable[dict[str, Any]], overwrite: bool) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(path)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    count = 0
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            for entry in entries:
                out.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
                count += 1
            out.flush()
            os.fsync(out.fileno())
        validated = 0
        with open(tmp_name, "r", encoding="utf-8") as check:
            for line_no, line in enumerate(check, 1):
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"JSONL line {line_no} is not an object")
                validated += 1
        if validated != count:
            raise ValueError(f"Temporary output count mismatch: wrote {count}, validated {validated}")
        if path.exists() and not overwrite:
            raise FileExistsError(path)
        os.replace(tmp_name, path)
        return count
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def _select_smoke(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    eligible = [i for i in items if i.get("size_bytes", MAX_SMOKE_BYTES + 1) <= MAX_SMOKE_BYTES
                and i.get("evtx_signature") and "security" not in i["filename"].casefold()]
    by_path = {i["relative_path"].casefold(): i for i in eligible}
    chosen = [by_path[p] for p in PREFERRED if p in by_path]
    for item in sorted(eligible, key=lambda i: (i["size_bytes"], i["relative_path"].casefold())):
        if item not in chosen and len(chosen) < 3:
            chosen.append(item)
    return chosen[:3]


def convert(input_root: Path, output_root: Path, smoke: bool = False, overwrite: bool = False,
            command: str | None = None) -> dict[str, Any]:
    input_root = input_root.resolve(strict=True)
    output_root = output_root.resolve()
    reject_overlap(input_root, output_root)
    started = utc_now()
    inventory = list(discover(input_root))
    items = _select_smoke(inventory) if smoke else [i for i in inventory if i.get("evtx_signature")]
    if smoke and len(items) < 3:
        raise RuntimeError(f"SMOKE mode requires three small EVTX-compatible files; found {len(items)}."
                           " Run inventory and provide local samples before conversion.")
    output_root.mkdir(parents=True, exist_ok=True)
    manifest_path = output_root / "manifest.json"
    errors_path = output_root / "parse_errors.jsonl"
    report_path = output_root / "phase1_report.md"
    protected = [manifest_path, errors_path, report_path]
    if not overwrite:
        existing = [p for p in protected if p.exists()]
        if existing:
            raise FileExistsError(f"Refusing to overwrite existing outputs: {existing[0]}")
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for item in items:
        path = item["_path"]
        rel = item["relative_path"]
        output_rel = Path("per_file", *Path(rel).parts).with_suffix(".jsonl")
        final = output_root / output_rel
        pre = item["sha256"]
        status = "ok"
        attempted = emitted = failed = 0
        enumerate_reason = None
        hints = {"claimed_scenario": item.get("claimed_scenario"), "host_from_path": item.get("host_from_path")}
        src = {key: item.get(key) for key in ("relative_path", "filename", "sha256", "size_bytes")}
        def entries():
            nonlocal attempted, emitted, failed, status, enumerate_reason
            try:
                for record_index, record in enumerate(_iter_records(path), start=1):
                    attempted += 1
                    try:
                        xml_text = record.xml()
                        if isinstance(xml_text, bytes):
                            xml_text = xml_text.decode("utf-8", errors="replace")
                        event = parse_event(xml_text, src, hints, record_index)
                        emitted += 1
                        yield event
                    except Exception as exc:
                        failed += 1
                        errors.append({"source": rel, "record_index": record_index, "error_type": type(exc).__name__, "message": str(exc)[:500]})
            except Exception as exc:
                status = "failed"
                enumerate_reason = f"parser open/iteration error: {type(exc).__name__}: {str(exc)[:300]}"
                errors.append({"source": rel, "record_index": None, "error_type": type(exc).__name__, "message": str(exc)[:500], "scope": "file"})
        try:
            _atomic_jsonl(final, entries(), overwrite)
        except Exception as exc:
            status = "failed"
            enumerate_reason = enumerate_reason or f"output/parser failure: {type(exc).__name__}: {str(exc)[:300]}"
            errors.append({"source": rel, "record_index": None, "error_type": type(exc).__name__, "message": str(exc)[:500], "scope": "file"})
        try:
            post = sha256_file(path)
        except OSError as exc:
            post = None
            status = "failed"
            errors.append({"source": rel, "record_index": None, "error_type": type(exc).__name__, "message": str(exc)[:500], "scope": "post_hash"})
        if post != pre:
            status = "failed"
        rows.append({"relative_path": rel, "size_bytes": item["size_bytes"], "pre_run_sha256": pre,
                     "post_run_sha256": post, "evtx_signature": item["evtx_signature"], "status": status,
                     "attempted_record_count": attempted, "emitted_event_count": emitted,
                     "parse_error_count": failed + int(any(e.get("source") == rel and e.get("scope") == "file" for e in errors)),
                     "unaccounted_records_reason": enumerate_reason, "output_relative_path": output_rel.as_posix()})
    _atomic_jsonl(errors_path, iter(errors), overwrite)
    finished = utc_now()
    manifest = {"schema_version": SCHEMA_VERSION, "tool_version": __version__, "parser": "evtx (PyEvtxParser)",
                "parser_version": _parser_version(), "python_version": platform.python_version(),
                "started_utc": started, "finished_utc": finished, "run_mode": "smoke" if smoke else "full",
                "input_root": str(input_root), "output_root": str(output_root),
                "invocation": command or "python -m evtx_pipeline.cli convert --input <INPUT> --output <OUTPUT> --smoke",
                "selected_inputs": rows, "totals": {"files": len(rows), "attempted_records": sum(r["attempted_record_count"] for r in rows),
                    "emitted_events": sum(r["emitted_event_count"] for r in rows), "parse_errors": sum(r["parse_error_count"] for r in rows)},
                "warnings": [w for i in items for w in i.get("warnings", [])],
                "failures": [r["relative_path"] for r in rows if r["status"] != "ok"]}
    _atomic_jsonl(manifest_path, iter([manifest]), overwrite)
    report = render_report(manifest)
    _write_atomic_text(report_path, report, overwrite)
    return manifest


def _parser_version() -> str:
    try:
        from importlib.metadata import version
        return version("evtx")
    except Exception:
        return "unknown"


def _write_atomic_text(path: Path, text: str, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(path)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        if path.exists() and not overwrite:
            raise FileExistsError(path)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def render_report(manifest: dict[str, Any], validation: dict[str, Any] | None = None) -> str:
    lines = ["# Phase 1 EVTX/EVT conversion report", "", f"Mode: `{manifest.get('run_mode', 'unknown')}`",
             f"Started: {manifest.get('started_utc', 'unknown')}", f"Finished: {manifest.get('finished_utc', 'unknown')}", "",
             "| Input | Status | Bytes | Attempted | Emitted | Parse errors |",
             "|---|---:|---:|---:|---:|---:|"]
    for row in manifest["selected_inputs"]:
        lines.append(f"| `{row['relative_path']}` | {row['status']} | {row['size_bytes']} | {row['attempted_record_count']} | {row['emitted_event_count']} | {row['parse_error_count']} |")
    lines += ["", f"Totals: {manifest['totals']}", f"Validation: {validation or 'not yet run'}", ""]
    return "\n".join(lines)


def validate(input_root: Path, output_root: Path) -> dict[str, Any]:
    input_root = input_root.resolve(strict=True)
    output_root = output_root.resolve(strict=True)
    reject_overlap(input_root, output_root)
    manifest = json.loads((output_root / "manifest.json").read_text(encoding="utf-8"))
    errors = [json.loads(line) for line in (output_root / "parse_errors.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    issues: list[str] = []
    for row in manifest["selected_inputs"]:
        source_path = input_root / Path(row["relative_path"])
        if sha256_file(source_path) != row["pre_run_sha256"] or row["post_run_sha256"] != row["pre_run_sha256"]:
            issues.append(f"source hash mismatch: {row['relative_path']}")
        output_path = output_root / Path(row["output_relative_path"])
        count = 0
        if output_path.exists():
            with output_path.open(encoding="utf-8") as f:
                for line_no, line in enumerate(f, 1):
                    if not line.strip():
                        issues.append(f"blank output line: {output_path}:{line_no}"); continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        issues.append(f"invalid JSON: {output_path}:{line_no}"); continue
                    count += 1
                    if not all(k in event for k in ("schema_version", "source", "hints", "system", "event_data", "user_data", "raw_xml")):
                        issues.append(f"missing event schema fields: {output_path}:{line_no}")
                    if event.get("source", {}).get("relative_path") != row["relative_path"] or event.get("source", {}).get("sha256") != row["pre_run_sha256"]:
                        issues.append(f"event provenance mismatch: {output_path}:{line_no}")
        elif row["emitted_event_count"]:
            issues.append(f"missing output file: {row['output_relative_path']}")
        if count != row["emitted_event_count"]:
            issues.append(f"line count mismatch: {row['relative_path']} expected={row['emitted_event_count']} actual={count}")
        decodes = sum(1 for e in errors if e.get("source") == row["relative_path"] and e.get("record_index") is not None)
        if row.get("unaccounted_records_reason") is None and row["attempted_record_count"] != row["emitted_event_count"] + decodes:
            issues.append(f"record accounting mismatch: {row['relative_path']}")
    if any(output_root.rglob("*.tmp")):
        issues.append("temporary outputs remain")
    result = {"passed": not issues, "issues": issues, "validated_files": len(manifest["selected_inputs"]),
              "emitted_events": manifest["totals"]["emitted_events"]}
    manifest["validation"] = result
    (output_root / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output_root / "phase1_report.md").write_text(render_report(manifest, result), encoding="utf-8")
    return result

