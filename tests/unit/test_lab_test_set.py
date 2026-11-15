"""Format test for docs/lab/test_set.csv (decision 052 item 4; plan 2026-11-15).

The file records the test set of the x10_v2 full reruns: header ``trial_id,scenario,split,accepted_date``, one row
per accepted trial. It is created header-only and filled in the lab. This test keeps it honest; ``check_rows`` is
exercised on synthetic good and bad row sets so the checker itself is known to bite.
"""
from __future__ import annotations

import csv
import re
from datetime import date
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CSV_PATH = REPO / "docs" / "lab" / "test_set.csv"
HEADER = ["trial_id", "scenario", "split", "accepted_date"]
SCENARIOS = {"s01", "s04", "s05", "s07"}
ID_RE = re.compile(r"^s0[1457]_t\d\d$")


def check_rows(rows: list[dict]) -> list[str]:
    """Every rule of the format; returns the list of violations (empty = ok)."""
    errs: list[str] = []
    seen: set[str] = set()
    dev: dict[str, list[str]] = {}
    for i, r in enumerate(rows, 2):
        tid = r.get("trial_id", "")
        if not ID_RE.match(tid):
            errs.append(f"line {i}: trial_id {tid!r} does not match ^s0[1457]_t\\d\\d$")
            continue
        scen = r.get("scenario", "")
        if scen not in SCENARIOS:
            errs.append(f"line {i}: scenario {scen!r} not in {sorted(SCENARIOS)}")
        if scen != tid.split("_")[0]:
            errs.append(f"line {i}: scenario {scen!r} does not match trial_id {tid!r}")
        split = r.get("split", "")
        if split not in ("development", "test"):
            errs.append(f"line {i}: split {split!r} is not development|test")
        try:
            date.fromisoformat(r.get("accepted_date", ""))
        except ValueError:
            errs.append(f"line {i}: accepted_date {r.get('accepted_date')!r} is not an ISO date")
        if tid in seen:
            errs.append(f"line {i}: duplicate trial_id {tid}")
        seen.add(tid)
        if split == "development":
            dev.setdefault(scen, []).append(tid)
    for scen, ids in dev.items():
        if len(ids) > 1:
            errs.append(f"scenario {scen}: more than one development row {ids}")
        for t in ids:
            if not t.endswith("_t01"):
                errs.append(f"scenario {scen}: development row {t} is not t01")
    return errs


def read_rows(path: Path) -> tuple[list[str], list[dict]]:
    with open(path, newline="", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        return list(rd.fieldnames or []), list(rd)


# ---------- the real file ----------

def test_file_exists_with_the_exact_header():
    assert CSV_PATH.is_file()
    header, _ = read_rows(CSV_PATH)
    assert header == HEADER


def test_real_rows_follow_the_format():
    _, rows = read_rows(CSV_PATH)
    assert check_rows(rows) == []


def test_file_has_no_bom_and_no_blank_data_lines():
    raw = CSV_PATH.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    lines = [ln for ln in raw.decode("utf-8").splitlines()]
    assert lines and lines[0] == ",".join(HEADER)
    assert all(ln.strip() for ln in lines[1:]), "blank line inside the file"


# ---------- the checker bites ----------

def good() -> list[dict]:
    return [
        {"trial_id": "s04_t01", "scenario": "s04", "split": "development", "accepted_date": "2026-11-24"},
        {"trial_id": "s04_t02", "scenario": "s04", "split": "test", "accepted_date": "2026-11-24"},
        {"trial_id": "s01_t01", "scenario": "s01", "split": "development", "accepted_date": "2026-11-25"},
        {"trial_id": "s05_t02", "scenario": "s05", "split": "test", "accepted_date": "2026-11-26"},
        {"trial_id": "s07_t10", "scenario": "s07", "split": "test", "accepted_date": "2026-11-27"},
    ]


def test_checker_accepts_a_good_set_and_the_empty_set():
    assert check_rows(good()) == []
    assert check_rows([]) == []


@pytest.mark.parametrize("mutate", [
    lambda r: r[1].update(trial_id="s02_t02", scenario="s02"),          # scenario not in the v2 list
    lambda r: r[1].update(trial_id="s04_t2"),                           # bad id shape
    lambda r: r[1].update(trial_id="S04_t02"),                          # upper case
    lambda r: r[1].update(trial_id="s05q_t02"),                         # quarantine id
    lambda r: r[1].update(scenario="s07"),                              # scenario does not match the id
    lambda r: r[1].update(split="train"),                               # bad split
    lambda r: r[1].update(accepted_date="24/11/2026"),                  # not ISO
    lambda r: r[1].update(accepted_date=""),
    lambda r: r.append(dict(r[1])),                                     # duplicate trial_id
    lambda r: r[1].update(split="development"),                         # two development rows in s04
    lambda r: r[1].update(trial_id="s04_t03", split="development") or r.pop(0),  # development row that is not t01
])
def test_checker_rejects_bad_rows(mutate):
    rows = good()
    mutate(rows)
    assert check_rows(rows), rows
