"""T8.1 leak check (spec 04 LB-09 / LBT-07 style), development trials only, read-only.

Does any 12-character substring of a DB command / script value (command_line, commandline, parentcommandline,
scriptblocktext, contextinfo, payload, userdata) or of a key `agent_command` occur in the given files?
Prints counts. With --show it also prints the overlapping substrings: they are by definition text of the checked files
themselves, so printing them reveals nothing new. Overlaps that also occur in public SigmaHQ rule text
(out/label_measure/public_tokens.txt, a local concatenation of the pinned SigmaHQ rule files; not committed) are
counted as explained.

Usage: python tools/label_measure/leakcheck_t81.py [--show] FILE...
"""
import json
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from stitch.inputs import check_allowlist  # noqa: E402
from stitch.params import ALLOWED_TRIALS  # noqa: E402

N = 12
KEYS = ("commandline", "parentcommandline", "scriptblocktext", "contextinfo", "payload", "userdata")


def main(argv: list[str]) -> None:
    show = "--show" in argv
    targets = [Path(p) for p in argv if p != "--show"]
    subs: dict[str, set[str]] = {}
    for p in targets:
        t = p.read_text(encoding="utf-8", errors="replace").lower()
        for i in range(len(t) - N + 1):
            subs.setdefault(t[i:i + N], set()).add(p.name)
    hits: dict[str, set[str]] = {}

    def scan(v) -> None:
        v = str(v).lower()
        for i in range(len(v) - N + 1):
            s = v[i:i + N]
            if s in subs:
                hits[s] = subs[s]

    for t in ALLOWED_TRIALS:
        check_allowlist(t)  # development trials only (decision 046 / 053)
        con = sqlite3.connect(f"file:{(REPO / 'data' / 'processed' / f'{t}.sqlite3').as_posix()}?mode=ro", uri=True)
        for cl, fv in con.execute("select command_line, field_values_json from events_dedup "
                                  "where command_line is not null or channel in ('PowerShell','Sysmon','Security')"):
            if cl:
                scan(cl)
            if fv and any(k in fv for k in KEYS):
                d = json.loads(fv)
                for k in KEYS:
                    for v in (d.get(k) or []):
                        scan(v)
        con.close()
    for k in (REPO / "ground_truth" / "approved").glob("*.yaml"):
        for h in json.loads(k.read_text(encoding="utf-8")).get("hops", []):
            if h.get("agent_command"):
                scan(h["agent_command"])
    pub = REPO / "out" / "label_measure" / "public_tokens.txt"
    public = pub.read_text(encoding="utf-8").lower() if pub.exists() else ""
    safe = {s for s in hits if s in public}
    print("files:", [p.name for p in targets])
    print("12-char hits total:", len(hits), "| also in public SigmaHQ text:", len(safe),
          "| other:", len(hits) - len(safe), "" if public else "(public_tokens.txt absent)")
    if show:
        for s, f in sorted(hits.items()):
            if s not in safe:
                print("  other:", repr(s), sorted(f))


if __name__ == "__main__":
    main(sys.argv[1:])
