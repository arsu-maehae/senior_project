"""Unit tests for the new pure module ``data_layout.clock_files`` (plan 2026-11-15, Task 4; spec 08 section 4.2).

API CONTRACT (names chosen by the tester; small pure functions, no hidden state):

  * ``EXPECTED_CLOCK_HOSTS == ("ep-01", "ep-02", "ep-03")``
  * ``clock_host(name: str) -> str | None``: ``"<HOST>_clock.txt"`` -> host via ``layout.normalise_host``
    (``EP-01_`` / ``ENDPOINT-02_`` / ``ep03_`` ...; host part case-insensitive). None for any other name, and None
    when the host is not one of EXPECTED_CLOCK_HOSTS (``EP-09_clock.txt``, ``LAPTOP_clock.txt``).
  * ``looks_like_clock_file(name: str) -> bool``: True when the name contains "clock" (any case) and is meant as a
    clock file, even if misnamed (``clock.txt``, ``EP-01-clock.txt``); False for event logs and other files.
  * ``scan_trial_folder(trial_dir: Path) -> ClockScan``: read-only walk; ``ClockScan`` (frozen dataclass) has
    ``found: dict[str, Path]`` (host -> file directly in the trial folder), ``refused: list[str]`` (one reason per
    problem; each names the offending file) and ``missing_hosts: list[str]`` (EXPECTED_CLOCK_HOSTS without a file,
    sorted). Refused: a clock-like name that does not parse, an unknown host, two files for one host, and any
    clock-like file below a subfolder. The file is never parsed.
  * ``clock_manifest_row(path, dest_rel, scenario, trial, host, source_path) -> dict`` with exactly
    ``layout.MANIFEST_COLUMNS``; channel "clock"; sha256 and size of ``path``; records/first_event_utc/
    last_event_utc "" (so export-span code ignores it).
  * ``append_clock_rows(manifest: Path, rows: list[dict]) -> int``: append rows whose ``path`` is not yet listed
    (idempotent), write the header only for a new file, never change existing bytes, keep the file's CRLF endings;
    returns the number added.
"""
from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from data_layout import layout as L  # noqa: E402


def cf():
    from data_layout import clock_files
    return clock_files


def snapshot(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


# ---------- names ----------

def test_expected_hosts():
    assert cf().EXPECTED_CLOCK_HOSTS == ("ep-01", "ep-02", "ep-03")


@pytest.mark.parametrize("name,host", [
    ("EP-01_clock.txt", "ep-01"), ("ep-02_clock.txt", "ep-02"), ("Ep-03_clock.txt", "ep-03"),
    ("ENDPOINT-01_clock.txt", "ep-01"), ("Endpoint-02_clock.txt", "ep-02"), ("ep03_clock.txt", "ep-03"),
    ("EP01_clock.txt", "ep-01"),
])
def test_clock_host_parses_through_normalise_host(name, host):
    assert cf().clock_host(name) == host
    assert L.normalise_host(name.removesuffix("_clock.txt")) == host


@pytest.mark.parametrize("name", [
    "clock.txt", "EP-01-clock.txt", "EP-01_clock", "EP-01_clock.txt.bak", "EP-01_clock.csv", "_clock.txt",
    "LAPTOP_clock.txt", "EP-09_clock.txt", "EP-04_clock.txt", "EP-01_Security.evtx", "notes.txt",
])
def test_clock_host_none_for_anything_else(name):
    assert cf().clock_host(name) is None


@pytest.mark.parametrize("name,expected", [
    ("EP-01_clock.txt", True), ("clock.txt", True), ("EP-01-clock.txt", True), ("LAPTOP_Clock.txt", True),
    ("notes.txt", False), ("ENDPOINT-01_Security.evtx", False), ("vmware-1.log", False),
])
def test_looks_like_clock_file(name, expected):
    assert cf().looks_like_clock_file(name) is expected


# ---------- folder scan ----------

def mk(tmp_path: Path, *rels: str) -> Path:
    base = tmp_path / "trial_01"
    base.mkdir()
    for r in rels:
        p = base / r
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(("data of " + r).encode())
    return base


def test_scan_finds_one_file_per_host_and_changes_nothing(tmp_path):
    base = mk(tmp_path, "EP-01_clock.txt", "ep-02_clock.txt", "ENDPOINT-03_clock.txt",
              "DC-01/DC-01_System.evtx", "ENDPOINT-01/ENDPOINT-01_System.evtx", "notes.txt")
    before = snapshot(tmp_path)
    s = cf().scan_trial_folder(base)
    assert {h: p.name for h, p in s.found.items()} == {"ep-01": "EP-01_clock.txt", "ep-02": "ep-02_clock.txt",
                                                        "ep-03": "ENDPOINT-03_clock.txt"}
    assert all(p.parent == base for p in s.found.values())
    assert s.refused == [] and s.missing_hosts == []
    assert snapshot(tmp_path) == before


def test_scan_missing_hosts_sorted_and_not_a_refusal(tmp_path):
    s = cf().scan_trial_folder(mk(tmp_path, "ep-03_clock.txt"))
    assert s.missing_hosts == ["ep-01", "ep-02"] and s.refused == [] and list(s.found) == ["ep-03"]


def test_scan_no_clock_files_at_all(tmp_path):
    s = cf().scan_trial_folder(mk(tmp_path, "DC-01/DC-01_System.evtx", "notes.txt"))
    assert s.found == {} and s.refused == [] and s.missing_hosts == ["ep-01", "ep-02", "ep-03"]


@pytest.mark.parametrize("rels,named", [
    (["clock.txt"], "clock.txt"),
    (["EP-01-clock.txt"], "EP-01-clock.txt"),
    (["LAPTOP_clock.txt"], "LAPTOP_clock.txt"),
    (["EP-09_clock.txt"], "EP-09_clock.txt"),
    (["EP-01_clock.txt", "ENDPOINT-01_clock.txt"], "ENDPOINT-01_clock.txt"),
    (["ENDPOINT-01/EP-01_clock.txt"], "EP-01_clock.txt"),
    (["ENDPOINT-01/clock.txt"], "clock.txt"),
])
def test_scan_refuses_and_names_the_file(tmp_path, rels, named):
    s = cf().scan_trial_folder(mk(tmp_path, *rels))
    assert s.refused and any(named in r for r in s.refused)
    assert all(isinstance(r, str) for r in s.refused)


def test_scan_subfolder_file_is_never_taken_as_a_reading(tmp_path):
    s = cf().scan_trial_folder(mk(tmp_path, "ENDPOINT-01/EP-01_clock.txt"))
    assert "ep-01" not in s.found and s.refused


def test_scan_two_files_one_host_are_not_guessed(tmp_path):
    s = cf().scan_trial_folder(mk(tmp_path, "EP-01_clock.txt", "ENDPOINT-01_clock.txt", "EP-02_clock.txt"))
    assert "ep-01" not in s.found  # neither of the two is picked
    assert s.refused


# ---------- manifest row and append ----------

def test_clock_manifest_row_contract(tmp_path):
    p = tmp_path / "ep-01_clock_copy.txt"
    p.write_bytes(b"\xff\xfeabc\r\n")
    row = cf().clock_manifest_row(p, "s04/t01/ep-01/clock.txt", "s04", "t01", "ep-01", "x10_v2/S04/trial_01/EP-01_clock.txt")
    assert list(row) == L.MANIFEST_COLUMNS
    assert row["path"] == "s04/t01/ep-01/clock.txt" and row["channel"] == "clock"
    assert row["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest() and int(row["size"]) == 7
    assert (row["scenario"], row["trial"], row["host"]) == ("s04", "t01", "ep-01")
    assert row["source_path"] == "x10_v2/S04/trial_01/EP-01_clock.txt"
    assert row["records"] == "" and row["first_event_utc"] == "" and row["last_event_utc"] == ""
    assert row["date"]


def _rows(tmp_path: Path):
    out = []
    for h in ("ep-01", "ep-02"):
        p = tmp_path / f"{h}.txt"
        p.write_bytes(h.encode())
        out.append(cf().clock_manifest_row(p, f"s04/t01/{h}/clock.txt", "s04", "t01", h, f"x10_v2/S04/trial_01/{h}_clock.txt"))
    return out


def test_append_creates_file_with_header_and_is_idempotent(tmp_path):
    m = tmp_path / "manifest.csv"
    rows = _rows(tmp_path)
    assert cf().append_clock_rows(m, rows) == 2
    first = m.read_bytes()
    assert first.splitlines()[0].decode().split(",") == L.MANIFEST_COLUMNS
    assert cf().append_clock_rows(m, rows) == 0
    assert m.read_bytes() == first
    with open(m, newline="", encoding="utf-8") as f:
        assert [r["host"] for r in csv.DictReader(f)] == ["ep-01", "ep-02"]


def test_append_never_changes_existing_lines_and_keeps_crlf(tmp_path):
    m = tmp_path / "manifest.csv"
    with open(m, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, L.MANIFEST_COLUMNS)  # default line terminator CRLF, like the real manifest
        w.writeheader()
        w.writerow({c: "1" for c in L.MANIFEST_COLUMNS})
    before = m.read_bytes()
    assert cf().append_clock_rows(m, _rows(tmp_path)) == 2
    after = m.read_bytes()
    assert after.startswith(before) and after.endswith(b"\r\n") and b"\r\r\n" not in after
    assert after.count(b"\n") == after.count(b"\r\n") == 4


def test_append_skips_a_path_already_listed(tmp_path):
    m = tmp_path / "manifest.csv"
    rows = _rows(tmp_path)
    cf().append_clock_rows(m, rows[:1])
    assert cf().append_clock_rows(m, rows) == 1
    with open(m, newline="", encoding="utf-8") as f:
        assert len(list(csv.DictReader(f))) == 2
