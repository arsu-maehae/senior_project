"""T8.1: per key hop, techniques labelled on the stitch hop's nodes (context 0 / 1). Counts and ids only."""
import json, sys
from collections import defaultdict
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import measure_t81 as m

for t in m.KEYED:
    m.check_allowlist(t)
    sdir = m.REPO / "out" / "stitch" / t
    nodes = m.read_csv(sdir / "path_nodes.csv"); hops = m.read_csv(sdir / "hops.csv")
    key = json.loads((m.REPO / "ground_truth" / "approved" / f"{t}.yaml").read_text(encoding="utf-8"))
    import sqlite3
    con = sqlite3.connect(f"file:{(m.REPO/'data'/'processed'/f'{t}.sqlite3').as_posix()}?mode=ro", uri=True)
    uids = {n["event_uid"] for n in nodes}
    lab = defaultdict(set)
    q = "select event_uid, channel, event_id, field_values_json from events_dedup where event_uid in (%s)" % ",".join("?" * len(uids))
    for uid, ch, eid, fv in con.execute(q, list(uids)):
        f = {k: (v[0] if isinstance(v, list) and len(v) == 1 else v) for k, v in json.loads(fv or "{}").items()}
        for rid, (fn, tech) in m.RULES.items():
            if fn(ch, int(eid), f):
                lab[uid].add(tech)
    con.close()
    member = {}
    for h in hops:
        for item in h["member_logon_uids"].split(";"):
            for u in item.split("|"):
                member[u] = h["hop_id"]
    for kh in key["hops"]:
        sh = {member.get(u) for u in kh.get("target_event_uids", []) if u in member} - {None}
        c0, c1 = set(), set()
        for n in nodes:
            if n["hop_id"] in sh:
                (c1 if n["context"] == "1" else c0).update(lab.get(n["event_uid"], ()))
        print(t, kh["hop_id"], kh.get("role"), kh.get("protocol"), sorted(sh), "ctx0:", sorted(c0), "ctx1:", sorted(c1 - c0))
