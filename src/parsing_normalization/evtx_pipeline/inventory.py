from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Iterable

EVTX_MAGIC = b"ElfFile\x00"
CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path, chunk_size: int = CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_evtx_signature(path: Path) -> bool:
    with path.open("rb") as stream:
        return stream.read(len(EVTX_MAGIC)) == EVTX_MAGIC


def path_hints(relative_path: str) -> tuple[str | None, str | None]:
    """Infer only explicit host/scenario tokens; leave ambiguous names unset."""
    parts = Path(relative_path).parts
    host = next((part for part in parts if re.fullmatch(r"ep-\d+", part, re.I)), None)
    scenario = None
    for part in reversed(parts):
        match = re.search(r"(?:dryrun[_-]?)?s(\d{1,2})\b", part, re.I)
        if match:
            scenario = f"s{int(match.group(1)):02d}"
            break
    return host, scenario


def discover(input_root: Path) -> Iterable[dict[str, Any]]:
    root = input_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Input must be a directory: {root}")
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.casefold() not in {".evtx", ".evt"}:
            continue
        warnings: list[str] = []
        rel = path.relative_to(root).as_posix()
        try:
            signature = is_evtx_signature(path)
            if path.suffix.casefold() == ".evt" and signature:
                warnings.append(".evt extension contains EVTX signature; parser selection uses signature")
            elif path.suffix.casefold() == ".evtx" and not signature:
                warnings.append(".evtx extension does not contain EVTX signature")
            host, scenario = path_hints(rel)
            yield {
                "relative_path": rel,
                "filename": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "first_bytes_hex": _first_bytes(path),
                "evtx_signature": signature,
                "host_from_path": host,
                "claimed_scenario": scenario,
                "warnings": warnings,
                "_path": path,
            }
        except OSError as exc:
            yield {"relative_path": rel, "filename": path.name, "warnings": [f"discovery failed: {exc}"]}


def inventory_json(input_root: Path) -> dict[str, Any]:
    records = []
    for item in discover(input_root):
        item.pop("_path", None)
        records.append(item)
    return {"schema_version": "1.0", "input_root": str(input_root.resolve()), "files": records}


def _first_bytes(path: Path, count: int = 16) -> str:
    with path.open("rb") as stream:
        return stream.read(count).hex()


def reject_overlap(input_root: Path, output_root: Path) -> None:
    source = input_root.resolve(strict=True)
    output = output_root.resolve()
    if output == source or source in output.parents or output in source.parents:
        raise ValueError(f"Input and output directories overlap: input={source}, output={output}")

