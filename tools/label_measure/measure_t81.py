"""T8.1 measurement for spec 04_label (development trials only, read-only, counts only).

Never prints or saves any command line, script block, ContextInfo or Payload value, nor any part of one.
Rule predicates mirror the Sigma YAML of spec 04 section 3.1 (SigmaHQ commit 54967d6), as written.
Usage: python out/label_measure/measure_t81.py
"""
from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from clock_offset.correct import corrected_us, is_unreliable, load_offsets  # noqa: E402
from gate.timeutil import to_us  # noqa: E402
from stitch.errors import StitchError  # noqa: E402
from stitch.inputs import check_allowlist  # noqa: E402
from stitch.params import ALLOWED_TRIALS  # noqa: E402
from trial_window.window import offsets_path  # noqa: E402

OUT = REPO / "out" / "label_measure"
SENSITIVE = ("commandline", "parentcommandline", "scriptblocktext", "contextinfo", "payload", "userdata")
KEYED = ("s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00")


# ------------------------------------------------------------------ helpers
def sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def low(v) -> str:
    return "" if v is None else str(v).lower()


def ends(v, *suffixes) -> bool:
    s = low(v)
    return any(s.endswith(x.lower()) for x in suffixes)


def has(v, *parts) -> bool:
    s = low(v)
    return any(p.lower() in s for p in parts)


def eq(v, *vals) -> bool:
    s = low(v)
    return any(s == str(x).lower() for x in vals)


# ------------------------------------------------------------------ rules (spec 04 section 3.1, as written)
def sr01(ch, eid, f):  # a49fa4d5
    return (ch, eid) == ("Sysmon", 10) and ends(f.get("targetimage"), "\\lsass.exe") \
        and ends(f.get("sourceimage"), "\\rundll32.exe") and has(f.get("calltrace"), "comsvcs.dll")


def sr02(ch, eid, f):  # 5ef9853e
    if (ch, eid) != ("Sysmon", 10):
        return False
    sel = ends(f.get("targetimage"), "\\lsass.exe") \
        and has(f.get("grantedaccess"), "0x1038", "0x1438", "0x143a", "0x1fffff") \
        and has(f.get("calltrace"), "dbgcore.dll", "dbghelp.dll", "kernel32.dll", "kernelbase.dll", "ntdll.dll")
    f_sys = has(f.get("sourceuser"), "AUTHORI", "AUTORI")
    ct = low(f.get("calltrace"))
    f_thor = all(x.lower() in ct for x in (":\\windows\\temp\\asgard2-agent\\", "\\thor\\thor64.exe+", "|unknown(")) \
        and eq(f.get("grantedaccess"), "0x103800")
    f_sysmon = ends(f.get("sourceimage"), ":\\Windows\\Sysmon64.exe", ":\\Windows\\Sysmon64a.exe")
    return sel and not (f_sys or f_thor or f_sysmon)


def sr03(ch, eid, f):  # aa35a627
    return (ch, eid) == ("Sysmon", 10) and ends(f.get("targetimage"), "\\lsass.exe") \
        and ends(f.get("sourceimage"), ":\\Windows\\system32\\wsmprovhost.exe") \
        and not eq(f.get("grantedaccess"), "0x80000000")


def sr10(ch, eid, f):  # 098d7118: ShareName equals 'Admin$'
    return (ch, eid) == ("Security", 5140) and eq(f.get("sharename"), "Admin$") \
        and not ends(f.get("subjectusername"), "$")


def sr11(ch, eid, f):  # b210394c
    return (ch, eid) == ("Security", 5145) and ends(f.get("sharename"), "C$") and eq(f.get("accessmask"), "0x2") \
        and not ends(f.get("subjectusername"), "$") and not eq(f.get("ipaddress"), "::1")


def sr12(ch, eid, f):  # 586a8d6b: ShareName '\\*\IPC$' (literal *), RelativeTargetName svcctl, AccessList WriteData
    return (ch, eid) == ("Security", 5145) and eq(f.get("sharename"), "\\\\*\\IPC$") \
        and eq(f.get("relativetargetname"), "svcctl") and has(f.get("accesslist"), "WriteData")


EXE = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs")


def sr20(ch, eid, f):  # own
    return (ch, eid) == ("Security", 5145) and ends(f.get("sharename"), "ADMIN$", "C$") \
        and ends(f.get("relativetargetname"), *EXE) and has(f.get("accesslist"), "%%4417")


def sr30(ch, eid, f):  # own
    return (ch, eid) == ("System", 7045) and eq(f.get("provider"), "Service Control Manager")


def sr31(ch, eid, f):  # own
    return (ch, eid) == ("Security", 4697)


def sr40(ch, eid, f):  # 734f8d9b
    if (ch, eid) == ("Sysmon", 1):
        return ends(f.get("image"), "\\wsmprovhost.exe") or ends(f.get("parentimage"), "\\wsmprovhost.exe")
    if (ch, eid) == ("Security", 4688):
        return ends(f.get("newprocessname"), "\\wsmprovhost.exe") or ends(f.get("parentprocessname"), "\\wsmprovhost.exe")
    return False


def sr41(ch, eid, f):  # c539afac
    if (ch, eid) != ("Sysmon", 3):
        return False
    sel = eq(f.get("destinationport"), 5985, 5986) and eq(f.get("initiated"), "true") \
        and eq(f.get("sourceisipv6"), "false")
    u = low(f.get("user"))
    f_svc = has(u, "NETWORK SERVICE", "NETZWERKDIENST", "SERVICIO DE RED", "SERVIZIO DI RETE") \
        or ("service r" in u and "seau" in u)
    f_lo = eq(f.get("sourceip"), "::1", "127.0.0.1") and eq(f.get("destinationip"), "::1", "127.0.0.1")
    f_avast = eq(f.get("image"), "C:\\Program Files\\Avast Software\\Avast\\AvastSvc.exe",
                 "C:\\Program Files (x86)\\Avast Software\\Avast\\AvastSvc.exe")
    return sel and not (f_svc or f_lo or f_avast)


def sr42(ch, eid, f):  # 96b9f619
    if (ch, eid) != ("PowerShell", 4103):
        return False
    ci = low(f.get("contextinfo"))
    sel = " = serverremotehost " in ci and "wsmprovhost.exe" in ci
    flt = "\\windows\\system32\\windowspowershell\\v1.0\\modules\\microsoft.powershell.archive\\microsoft.powershell.archive.psm1" in ci
    return sel and not flt


def sr50(ch, eid, f):  # own
    return (ch, eid) == ("Security", 4624) and eq(f.get("logontype"), 10)


def sr60(ch, eid, f):  # 941e5c45
    if (ch, eid) != ("Security", 4648):
        return False
    sel = ends(f.get("processname"), "\\cmd.exe", "\\powershell.exe", "\\pwsh.exe", "\\winrs.exe", "\\wmic.exe",
               "\\net.exe", "\\net1.exe", "\\reg.exe")
    f1 = eq(f.get("targetservername"), "localhost")
    f2 = ends(f.get("subjectusername"), "$") and ends(f.get("targetusername"), "$")
    return sel and not (f1 or f2)


def sr61(ch, eid, f):  # 8eef149c
    if (ch, eid) != ("Security", 4624):
        return False
    s3 = eq(f.get("subjectusersid"), "S-1-0-0") and eq(f.get("logontype"), 3) \
        and eq(f.get("logonprocessname"), "NtLmSsp") and eq(f.get("keylength"), 0)
    s9 = eq(f.get("logontype"), 9) and eq(f.get("logonprocessname"), "seclogo")
    return (s3 or s9) and not eq(f.get("targetusername"), "ANONYMOUS LOGON")


RULES = {"SR-01": (sr01, "T1003.001"), "SR-02": (sr02, "T1003.001"), "SR-03": (sr03, "T1003.001"),
         "SR-10": (sr10, "T1021.002"), "SR-11": (sr11, "T1021.002"), "SR-12": (sr12, "T1021.002"),
         "SR-20": (sr20, "T1570"), "SR-30": (sr30, "T1569.002"), "SR-31": (sr31, "T1569.002"),
         "SR-40": (sr40, "T1021.006"), "SR-41": (sr41, "T1021.006"), "SR-42": (sr42, "T1021.006"),
         "SR-50": (sr50, "T1021.001"), "SR-60": (sr60, "T1078"), "SR-61": (sr61, "T1550.002")}

# fields each rule reads, per (channel, event_id) (measurement 3)
RULE_FIELDS = {
    ("Sysmon", 10): ["targetimage", "sourceimage", "calltrace", "grantedaccess", "sourceuser"],
    ("Security", 5140): ["sharename", "subjectusername"],
    ("Security", 5145): ["sharename", "accessmask", "accesslist", "relativetargetname", "subjectusername", "ipaddress"],
    ("System", 7045): ["provider", "imagepath", "servicename"],
    ("Security", 4697): ["servicename", "servicefilename"],
    ("Sysmon", 1): ["image", "parentimage"],
    ("Security", 4688): ["newprocessname", "parentprocessname"],
    ("Sysmon", 3): ["destinationport", "initiated", "sourceisipv6", "user", "sourceip", "destinationip", "image"],
    ("PowerShell", 4103): ["contextinfo"],
    ("Security", 4624): ["logontype", "subjectusersid", "logonprocessname", "keylength", "targetusername"],
    ("Security", 4648): ["processname", "targetservername", "subjectusername", "targetusername"],
}
# non-sensitive value formats worth showing (measurement 3)
FORMAT_FIELDS = {("Security", 5140): ["sharename"], ("Security", 5145): ["sharename", "accessmask", "accesslist"],
                 ("System", 7045): ["provider"], ("Sysmon", 3): ["initiated", "sourceisipv6"],
                 ("Security", 4624): ["logonprocessname", "keylength"]}
EXPECTED = {"lsass_dump": "T1003.001", "service_exec": "T1569.002"}


# ------------------------------------------------------------------ key reading (measurement only; src never does)
def key_events(trial: str) -> dict:
    p = REPO / "ground_truth" / "approved" / f"{trial}.yaml"
    if not p.exists():
        return {}
    k = json.loads(p.read_text(encoding="utf-8"))
    ev = {}  # uid -> list of (kind, role, hop_id/step_id)

    def add(uid, kind, role, ref):
        ev.setdefault(uid, []).append((kind, role, ref))
    for s in k.get("steps", []):
        for u in s.get("event_uids", []):
            add(u, "step_" + s["kind"], "attack", s["step_id"])
    for h in k.get("hops", []):
        role = h.get("role") or "unknown"
        for u in h.get("target_event_uids", []):
            add(u, "hop_target", role, h["hop_id"])
        for u in h.get("port_join_event_uids", []):
            add(u, "hop_source_sysmon3", role, h["hop_id"])
        for u in h.get("agent_event_uids", []):
            add(u, "hop_source_command", role, h["hop_id"])
        for u in (h.get("identity_basis") or {}).get("dump_event_uids", []):
            add(u, "hop_dump", role, h["hop_id"])
    for bp in k.get("benign_paths", []) or []:
        for u in bp.get("event_uids", []) if isinstance(bp, dict) else []:
            add(u, "benign_path_event", "benign", bp.get("path_id"))
    return {"events": ev, "key": k}


def read_csv(p: Path) -> list[dict]:
    with p.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


# ------------------------------------------------------------------ per trial
def measure(trial: str) -> dict:
    check_allowlist(trial)  # before any file is opened
    db = REPO / "data" / "processed" / f"{trial}.sqlite3"
    h_before = sha(db)
    gate = json.loads((REPO / "out" / "gate" / trial / "stats.json").read_text(encoding="utf-8"))
    assert gate["db"]["sha256_after"] == h_before, "DB hash differs from gate stats"
    row = gate["window"]["row"]
    w0, w1 = to_us(row["start_utc"]), to_us(row["end_utc"])
    offsets = load_offsets(offsets_path(REPO, trial))
    sdir = REPO / "out" / "stitch" / trial
    nodes = read_csv(sdir / "path_nodes.csv")
    hops = read_csv(sdir / "hops.csv")
    ident = read_csv(sdir / "hop_identity.csv")
    supp = read_csv(REPO / "out" / "gate" / trial / "supporting.csv")
    near_dup = gate.get("near_duplicate_uids") or []

    # uid -> representative (ST-05 copies in hops.csv member_logon_uids)
    rep = {}
    for h in hops:
        for item in filter(None, h["member_logon_uids"].split(";")):
            parts = item.split("|")
            for u in parts:
                rep[u] = parts[0]

    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    events = {}
    outside = 0
    multi = Counter()
    for uid, host, ch, eid, utc, fv, mach in con.execute(
            "select event_uid, host, channel, event_id, event_utc, field_values_json, machine_account from events_dedup"):
        cu = corrected_us(to_us(utc), host, offsets)
        if not (w0 <= cu <= w1):
            outside += 1
            continue
        raw = json.loads(fv) if fv else {}
        f = {}
        for k, v in raw.items():  # values are stored as lists; one element in every case measured
            if isinstance(v, list):
                if len(v) > 1:
                    multi[(ch, int(eid), k)] += 1
                v = v[0] if len(v) == 1 else " ".join(map(str, v)) if v else None
            f[k] = v
        events[uid] = (host, ch, int(eid), f, int(mach or 0))
    con.close()

    # measurement 3: field coverage + safe formats
    cov = defaultdict(lambda: Counter())
    totals = Counter()
    fmt = defaultdict(Counter)
    for uid, (host, ch, eid, f, mach) in events.items():
        key = (ch, eid)
        if key in RULE_FIELDS:
            totals[key] += 1
            for fld in RULE_FIELDS[key]:
                if f.get(fld) not in (None, ""):
                    cov[key][fld] += 1
        for fld in FORMAT_FIELDS.get(key, []):
            v = f.get(fld)
            if fld == "accesslist" and v:
                v = " ".join(sorted(set(t for t in str(v).split() if t.startswith("%%"))))
            fmt[f"{ch} {eid} {fld}"][str(v)] += 1
    coverage = {f"{k[0]} {k[1]}": {"rows": totals[k], **{fld: round(cov[k][fld] / totals[k], 4) if totals[k] else None
                                                       for fld in RULE_FIELDS[k]}} for k in RULE_FIELDS}
    lsass_masks = Counter(str(f.get("grantedaccess")) for (_, ch, eid, f, _) in events.values()
                          if (ch, eid) == ("Sysmon", 10) and ends(f.get("targetimage"), "\\lsass.exe"))
    admin_write_ext = Counter()
    for (_, ch, eid, f, _) in events.values():
        if (ch, eid) == ("Security", 5145) and ends(f.get("sharename"), "ADMIN$", "C$"):
            name = low(f.get("relativetargetname"))
            ext = name.rsplit(".", 1)[-1] if "." in name.rsplit("\\", 1)[-1] else "(none)"
            admin_write_ext[ext] += 1

    # measurement 4: rule hits
    hits = defaultdict(set)  # rule -> uids
    by_uid = defaultdict(set)
    for uid, (host, ch, eid, f, mach) in events.items():
        for rid, (fn, _) in RULES.items():
            if fn(ch, eid, f):
                hits[rid].add(uid)
                by_uid[uid].add(rid)
    volume = {rid: {"in_window": len(u),
                    "machine_account": sum(events[x][4] for x in u),
                    "hosts": dict(Counter(events[x][0] for x in u))} for rid, u in sorted(hits.items())}
    no_match = [r for r in RULES if r not in hits]

    def labels_of(uid):
        return by_uid.get(uid, set()) | by_uid.get(rep.get(uid, uid), set())

    # measurement 2: path nodes by role, and key events as nodes
    node_uids = defaultdict(set)  # uid -> roles
    role_counts = Counter()
    role_lab = Counter()
    for n in nodes:
        u = n["event_uid"]
        h, ch, eid = (events[u][0], events[u][1], events[u][2]) if u in events else ("?", "?", 0)
        role_counts[(n["role"], n["context"], ch, eid)] += 1
        if labels_of(u):
            role_lab[(n["role"], n["context"], ch, eid)] += 1
        node_uids[u].add(n["role"])
        node_uids[rep.get(u, u)].add(n["role"])
    nodes_tbl = [{"role": r, "context": c, "channel": ch, "event_id": e, "rows": v, "labelled": role_lab[(r, c, ch, e)]}
                 for (r, c, ch, e), v in sorted(role_counts.items())]
    # node rule hits split by node role/context
    node_hits = defaultdict(Counter)
    for n in nodes:
        for rid in labels_of(n["event_uid"]):
            node_hits[rid][f'{n["role"]}/ctx{n["context"]}'] += 1

    # key events
    kinfo = key_events(trial) if trial in KEYED else {}
    key_tbl = []
    if kinfo:
        for uid, refs in kinfo["events"].items():
            for kind, role, ref in refs:
                e = events.get(uid)
                key_tbl.append({"kind": kind, "role": role, "ref": ref,
                                "channel": e[1] if e else kinfo["key"]["event_keys"].get(uid, {}).get("channel"),
                                "event_id": e[2] if e else kinfo["key"]["event_keys"].get(uid, {}).get("event_id"),
                                "in_window": e is not None,
                                "is_path_node": uid in node_uids, "node_roles": sorted(node_uids.get(uid, [])),
                                "rules": sorted(labels_of(uid))})
    key_summary = Counter()
    for r in key_tbl:
        key_summary[(r["kind"], r["role"], r["channel"], r["event_id"], r["is_path_node"],
                     ";".join(r["rules"]) or "-")] += 1

    # measurement 5 / Q1: dumps
    r1 = {r["event_uid"] for r in supp if r["rule"] == "R1_lsass"}
    dumps_ident = {r["dump_event_uid"] for r in ident if r["dump_event_uid"]}
    t1003 = hits["SR-01"] | hits["SR-02"] | hits["SR-03"]
    q9 = {"r1_lsass_rows": len(r1), "t1003_labelled": len(t1003),
          "r1_and_t1003": len(r1 & t1003), "r1_not_t1003": len(r1 - t1003), "t1003_not_r1": len(t1003 - r1),
          "r1_not_t1003_masks": dict(Counter(str(events[u][3].get("grantedaccess")) for u in r1 - t1003 if u in events)),
          "r1_not_t1003_source_images": dict(Counter(low(events[u][3].get("sourceimage")).rsplit("\\", 1)[-1]
                                                     for u in r1 - t1003 if u in events)),
          "hop_identity_dumps": len(dumps_ident), "hop_identity_dumps_labelled_t1003": len(dumps_ident & t1003),
          "hop_identity_dumps_path_nodes": len([u for u in dumps_ident if u in node_uids])}

    # background / benign / unkeyed hop node labels
    hop_role = {}
    if kinfo:
        uid2keyhop = {}
        for h in kinfo["key"].get("hops", []):
            for u in h.get("target_event_uids", []):
                uid2keyhop[u] = h.get("role") or "unknown"
        for h in hops:
            members = {p for item in h["member_logon_uids"].split(";") for p in item.split("|") if p}
            roles = {uid2keyhop[u] for u in members if u in uid2keyhop}
            hop_role[h["hop_id"]] = ";".join(sorted(roles)) or "unkeyed"
    hop_role_labels = defaultdict(Counter)
    for n in nodes:
        rl = hop_role.get(n["hop_id"], "no_key")
        for rid in labels_of(n["event_uid"]):
            hop_role_labels[rl][rid] += 1
    hop_role_nodes = Counter(hop_role.get(n["hop_id"], "no_key") for n in nodes)

    h_after = sha(db)
    return {"trial": trial, "db_sha256_before": h_before, "db_sha256_after": h_after, "same": h_before == h_after,
            "events_in_window": len(events), "events_outside_window": outside,
            "multi_value_fields": {f"{c} {e} {k}": n for (c, e, k), n in multi.items() if k not in SENSITIVE},
            "multi_value_sensitive_rows": sum(n for (c, e, k), n in multi.items() if k in SENSITIVE), "near_duplicate_uids": len(near_dup),
            "coverage": coverage, "formats": {k: dict(v.most_common(12)) for k, v in fmt.items()},
            "lsass_target_masks": dict(lsass_masks.most_common(15)), "admin_share_5145_ext": dict(admin_write_ext),
            "rule_volume": volume, "rules_no_match": no_match, "node_hits": {k: dict(v) for k, v in node_hits.items()},
            "nodes_by_role": nodes_tbl, "path_nodes": len(nodes),
            "key_summary": [dict(zip(("kind", "role", "channel", "event_id", "is_path_node", "rules"), k), n=v)
                            for k, v in sorted(key_summary.items(), key=lambda x: [str(y) for y in x[0]])],
            "q9": q9, "hop_role_nodes": dict(hop_role_nodes),
            "hop_role_labels": {k: dict(v) for k, v in hop_role_labels.items()},
            "key_step_kinds": sorted({s["kind"] for s in kinfo["key"].get("steps", [])}) if kinfo else []}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    log = []
    try:
        check_allowlist("s02_t02")
        log.append("ALLOWLIST FAILED: s02_t02 accepted")
    except StitchError as exc:
        log.append(f"allowlist refusal ok for s02_t02: {str(exc)[:80]}...")
    res = {"allowed": list(ALLOWED_TRIALS), "log": log, "trials": {}}
    for t in ALLOWED_TRIALS:
        res["trials"][t] = measure(t)
        print(t, "done", res["trials"][t]["same"], flush=True)
    (OUT / "t81_measure.json").write_text(json.dumps(res, indent=1, sort_keys=True, default=str), encoding="utf-8")
    print("\n".join(log))


if __name__ == "__main__":
    main()
