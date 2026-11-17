"""Shared synthetic world for the label-stage tests (T8.2d; spec 04_label sections 2-4 and 7).

Written from docs/specs/04_label.md and decisions 056 / 057 / 058, not from the implementation. Everything lives in a
pytest `tmp_path`: a fake repo from `stitch_fixtures.make_repo` (DB with `events_dedup`, clock files, window file, gate
files) plus hand-written stitch outputs under `out/stitch/<trial>/`. The real data folders are never opened here.

Command text: every command / script / ContextInfo / Payload cell is a neutral placeholder (no real value).
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_fixtures as cf  # noqa: E402
import stitch_fixtures as sf  # noqa: E402

TRIAL = sf.TRIAL                       # s04_t00, an allowlisted id

# Spec 3.4 columns, literal copies (a test compares them with the code's lists, so a drift fails loudly).
EVENT_COLUMNS = ["trial_id", "event_uid", "dup_uids", "host", "channel", "event_id", "record_id", "event_utc",
                 "event_utc_corrected", "rule_id", "rule_title", "rule_source", "sigma_id", "technique", "techniques",
                 "tactics", "level", "level_value", "count_key", "method", "clock_unreliable"]
NODE_COLUMNS = ["path_id", "hop_id", "role", "context", "host", "event_uid", "labelled", "rule_ids", "techniques",
                "max_level_value"]
HOP_COLUMNS = ["hop_id", "in_path", "n_node_events", "n_labelled_node_events", "n_labelled_context0_node_events",
               "techniques", "dump_event_uids", "dump_labelled", "dump_rule_ids", "dump_max_level_value"]
MANIFEST_COLUMNS = ["rule_id", "file", "sha256", "source", "sigma_id", "sigma_commit", "title", "author", "license",
                    "references", "technique", "techniques", "tactics", "level"]
OUTPUT_FILES = sorted(["event_labels.csv", "node_labels.csv", "hop_labels.csv", "rules_manifest.csv", "stats.json",
                       "report.md", "run_info.json"])
STITCH_FILES = ["path_nodes.csv", "hops.csv", "hop_artefacts.csv", "hop_identity.csv", "run_info.json"]

NODE_IN_COLUMNS = ["path_id", "hop_id", "role", "context", "host", "session_id", "event_uid", "link_id"]
HOP_IN_COLUMNS = ["hop_id", "in_path", "member_logon_uids"]
IDENTITY_IN_COLUMNS = ["hop_id", "account", "dump_event_uid", "dump_utc_corrected"]
ARTEFACT_IN_COLUMNS = ["hop_id", "kind", "event_uid"]

PLACEHOLDERS = {
    "commandline": "PLACEHOLDER-CMDLINE-alpha-0123456789",
    "parentcommandline": "PLACEHOLDER-PARENTCMD-bravo-9876543210",
    "scriptblocktext": "PLACEHOLDER-SCRIPTBLOCK-charlie-5555",
    "contextinfo": "PLACEHOLDER-CONTEXTINFO-delta-4444",
    "payload": "PLACEHOLDER-PAYLOAD-echo-3333",
    "userdata": "PLACEHOLDER-USERDATA-foxtrot-2222",
    "servicefilename": "PLACEHOLDER-SERVICEFILE-golf-1111",
    "imagepath": "PLACEHOLDER-IMAGEPATH-hotel-0000",
}


# ------------------------------------------------------------------------------------------------ events
def fev(uid: str, channel: str, event_id: int, fields: Mapping[str, Any] | None = None, *, host: str = "ep-01",
        off: float | None = 0.0, utc: str | None = None, record_id: int | None | str = "auto", **cols: Any) -> dict:
    """A DB row whose `field_values_json` holds `fields` (one-element lists, lower-case keys, `eventid` always)."""
    f: dict[str, Any] = {"eventid": [str(event_id)]}
    for k, v in (fields or {}).items():
        f[k.lower()] = v if isinstance(v, list) else [v]
    row = sf.ev(uid, channel, event_id, host=host, off=off, utc=utc, record_id=record_id, **cols)
    row["field_values_json"] = json.dumps(f)
    return row


def sysmon10(uid: str, *, source: str = r"C:\Windows\System32\rundll32.exe", off: float = 10.0,
             calltrace: str = r"C:\Windows\SYSTEM32\ntdll.dll+a|C:\Windows\system32\comsvcs.dll+b",
             access: str = "0x1038", host: str = "ep-01", **kw: Any) -> dict:
    return fev(uid, "Sysmon", 10, {"targetimage": r"C:\Windows\system32\lsass.exe", "sourceimage": source,
                                   "calltrace": calltrace, "grantedaccess": access, "sourceuser": r"LAB\alice"},
               host=host, off=off, **kw)


def wsman_proc(uid: str, channel: str, *, off: float, pid: int, host: str = "ep-02", **kw: Any) -> dict:
    """A wsmprovhost process event: Sysmon 1 (`image`) or Security 4688 (`newprocessname`, LB-04)."""
    key = "image" if channel == "Sysmon" else "newprocessname"
    eid = 1 if channel == "Sysmon" else 4688
    fields = {key: r"C:\Windows\System32\wsmprovhost.exe", "commandline": PLACEHOLDERS["commandline"],
              "parentcommandline": PLACEHOLDERS["parentcommandline"]}
    return fev(uid, channel, eid, fields, host=host, off=off, process_id=pid, **kw)


def svc4697(uid: str, name: str, *, off: float, host: str = "ep-02", stype: str = "0x10", **kw: Any) -> dict:
    return fev(uid, "Security", 4697, {"servicename": name, "servicetype": stype, "subjectusername": "alice",
                                       "servicefilename": PLACEHOLDERS["servicefilename"]},
               host=host, off=off, service_name=name, **kw)


def svc7045(uid: str, name: str, *, off: float, host: str = "ep-02", **kw: Any) -> dict:
    return fev(uid, "System", 7045, {"provider": "Service Control Manager", "servicename": name,
                                     "imagepath": PLACEHOLDERS["imagepath"]},
               host=host, off=off, service_name=name, **kw)


def plain4624(uid: str, *, off: float, host: str = "ep-02", **kw: Any) -> dict:
    """A plain network logon: no rule labels it."""
    return fev(uid, "Security", 4624, {"logontype": "3", "targetusername": "alice"}, host=host, off=off, **kw)


# ------------------------------------------------------------------------------------------------ stitch outputs
def _write_csv(path: Path, columns: Sequence[str], rows: Sequence[Mapping[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(columns), lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in columns})


def node(path_id: str, hop_id: str, uid: str, *, role: str = "artefact", context: str = "0", host: str = "ep-02") -> dict:
    return {"path_id": path_id, "hop_id": hop_id, "role": role, "context": context, "host": host, "event_uid": uid}


def hop(hop_id: str, *, in_path: str = "1", members: str = "") -> dict:
    return {"hop_id": hop_id, "in_path": in_path, "member_logon_uids": members}


def write_stitch(fake: sf.FakeRepo, nodes: Sequence[Mapping[str, str]] = (), hops: Sequence[Mapping[str, str]] = (),
                 identity: Sequence[Mapping[str, str]] = (), *, skip: Sequence[str] = (),
                 run_db_sha: str | None = None, node_columns: Sequence[str] = NODE_IN_COLUMNS,
                 identity_columns: Sequence[str] = IDENTITY_IN_COLUMNS) -> Path:
    """The five stitch files the labeller reads, under `out/stitch/<trial>/`, with a `run_info.json` as the real stitch
    writes it (stage review S05): `db.sha256_after` (the DB hash, or `run_db_sha` to break it), `gate_stats_sha256`,
    `window.offsets_sha256` / `window.clock_changes_sha256` (the current clock files) and `files.<name>.sha256` for each
    stitch CSV."""
    folder = fake.repo / "out" / "stitch" / fake.trial
    db_sha = run_db_sha if run_db_sha is not None else sf.sha256_of(fake.paths.db)
    parts = {"path_nodes.csv": (node_columns, nodes), "hops.csv": (HOP_IN_COLUMNS, hops),
             "hop_artefacts.csv": (ARTEFACT_IN_COLUMNS, ()), "hop_identity.csv": (identity_columns, identity)}
    files: dict[str, dict] = {}
    for name, (cols, rows) in parts.items():
        if name not in skip:
            _write_csv(folder / name, cols, rows)
            files[name] = {"rows": len(rows), "sha256": sha256_file(folder / name)}
    if "run_info.json" not in skip:
        folder.mkdir(parents=True, exist_ok=True)
        info = {"db": {"sha256_before": db_sha, "sha256_after": db_sha},
                "gate_stats_sha256": sha256_file(fake.stats_path) if fake.stats_path.is_file() else "0" * 64,
                "window": {"offsets_sha256": sha256_file(cf.offsets_path(fake.repo, fake.trial)),
                           "clock_changes_sha256": sha256_file(cf.changes_path(fake.repo, fake.trial))},
                "files": files}
        (folder / "run_info.json").write_text(json.dumps(info), encoding="utf-8")
    return folder


def edit_run_info(fake: sf.FakeRepo, fn) -> None:
    """Load the fake stitch run_info.json, let `fn(dict)` change it, write it back."""
    p = fake.repo / "out" / "stitch" / fake.trial / "run_info.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    fn(d)
    p.write_text(json.dumps(d), encoding="utf-8")


def build(tmp_path: Path, rows: Sequence[Mapping], nodes: Sequence[Mapping[str, str]] = (),
          hops: Sequence[Mapping[str, str]] = (), identity: Sequence[Mapping[str, str]] = (), *, name: str = "repo",
          skip_stitch: Sequence[str] = (), run_db_sha: str | None = None,
          node_columns: Sequence[str] = NODE_IN_COLUMNS, identity_columns: Sequence[str] = IDENTITY_IN_COLUMNS,
          **make_kw: Any) -> sf.FakeRepo:
    fake = sf.make_repo(tmp_path, rows, name=name, **make_kw)
    write_stitch(fake, nodes, hops, identity, skip=skip_stitch, run_db_sha=run_db_sha, node_columns=node_columns,
                 identity_columns=identity_columns)
    return fake


# ------------------------------------------------------------------------------------------------ running
def label_dir(fake: sf.FakeRepo) -> Path:
    return fake.repo / "out" / "label" / fake.trial


def cli(fake: sf.FakeRepo, out: Path | None = None, trial: str | None = None, extra: Sequence[str] = ()) -> int:
    import label.__main__ as lm
    argv = ["--trial", trial or fake.trial, "--repo", str(fake.repo)]
    if out is not None:
        argv += ["--out", str(out)]
    return lm.main(argv + list(extra))


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def header_of(path: Path) -> list[str]:
    with open(path, newline="", encoding="utf-8") as fh:
        return next(csv.reader(fh))


def blobs(folder: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(Path(folder).iterdir())}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tables(folder: Path) -> dict[str, list[dict[str, str]]]:
    return {n: read_csv(folder / n) for n in ("event_labels.csv", "node_labels.csv", "hop_labels.csv",
                                              "rules_manifest.csv")}


@dataclass
class World:
    fake: sf.FakeRepo
    out: Path
    code: int


def run_world(tmp_path: Path, rows: Sequence[Mapping], nodes: Sequence[Mapping[str, str]] = (),
              hops: Sequence[Mapping[str, str]] = (), identity: Sequence[Mapping[str, str]] = (), *, name: str = "repo",
              **make_kw: Any) -> World:
    """Build a fake repo, run the CLI into `<tmp>/<name>_out` (never under the fake repo's out/), return the result."""
    fake = build(tmp_path, rows, nodes, hops, identity, name=name, **make_kw)
    out = tmp_path / f"{name}_out"
    return World(fake, out, cli(fake, out))


# ------------------------------------------------------------------------------------------------ leak scan helpers
GRAM = 12
LEVEL_WORD = "informational"            # the one non-public-file word every output may carry (spec 7 LBT-07 exemption)
MIN_LEVEL_OVERLAP = 8                   # a window holding at least this many characters of the level word is the word


def text_grams(text: str, n: int = GRAM) -> set[str]:
    """Every n-character window of the case-folded text."""
    t = text.casefold()
    return {t[i:i + n] for i in range(len(t) - n + 1)}


def level_word_windows(text: str, n: int = GRAM) -> set[str]:
    """Windows of `text` that overlap an occurrence of the level word by at least MIN_LEVEL_OVERLAP characters
    (JSON quoting puts a quote or colon next to the word: such a window is the level word, not command text)."""
    t = text.casefold()
    out: set[str] = set()
    pos = t.find(LEVEL_WORD)
    while pos != -1:
        lo, hi = pos, pos + len(LEVEL_WORD)
        for i in range(max(0, lo - n), min(len(t) - n, hi) + 1):
            if min(i + n, hi) - max(i, lo) >= MIN_LEVEL_OVERLAP:
                out.add(t[i:i + n])
        pos = t.find(LEVEL_WORD, pos + 1)
    return out


def public_rule_grams() -> set[str]:
    """Windows of the public locked rule files and manifest (src/label/rules/*.yml, manifest.csv)."""
    from label import params as lp
    text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(Path(lp.RULES_DIR).iterdir())
                     if p.suffix in (".yml", ".csv"))
    return text_grams(text)


def output_windows(text: str, exempt: set[str]) -> set[str]:
    """The windows of one output text that are neither public rule text nor the level word."""
    return text_grams(text) - exempt - level_word_windows(text)
