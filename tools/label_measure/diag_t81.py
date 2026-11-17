"""T8.1 diagnostics: counts only, development trials only, read-only. No sensitive text printed."""
import json, sqlite3, sys
from collections import Counter
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from stitch.inputs import check_allowlist
from stitch.params import ALLOWED_TRIALS
from clock_offset.correct import corrected_us, load_offsets
from gate.timeutil import to_us
from trial_window.window import offsets_path

def un(v):
    return v[0] if isinstance(v, list) and len(v) == 1 else v

tot = Counter(); svc = Counter(); svc_hosts = Counter()
for t in ALLOWED_TRIALS:
    check_allowlist(t)
    g = json.loads((REPO/"out"/"gate"/t/"stats.json").read_text(encoding="utf-8"))
    w0, w1 = to_us(g["window"]["row"]["start_utc"]), to_us(g["window"]["row"]["end_utc"])
    off = load_offsets(offsets_path(REPO, t))
    con = sqlite3.connect(f"file:{(REPO/'data'/'processed'/f'{t}.sqlite3').as_posix()}?mode=ro", uri=True)
    c = Counter()
    for host, ch, eid, utc, fv, mach in con.execute("select host,channel,event_id,event_utc,field_values_json,machine_account from events_dedup where (channel,event_id) in (values ('Security',5140),('Security',5145),('Security',4624),('PowerShell',4103),('Security',4697),('PowerShell',4104))"):
        if not (w0 <= corrected_us(to_us(utc), host, off) <= w1):
            continue
        f = {k: un(v) for k, v in json.loads(fv or "{}").items()}
        sn = str(f.get("sharename") or "").lower()
        if eid == 5140 and sn.endswith("admin$"): c["5140_admin$_any_account"] += 1; c["5140_admin$_user"] += not str(f.get("subjectusername","")).endswith("$")
        if eid == 5140 and sn.endswith("c$"): c["5140_c$"] += 1
        if eid == 5145 and sn.endswith("ipc$") and str(f.get("relativetargetname","")).lower() == "svcctl": c["5145_ipc_svcctl"] += 1
        if eid == 5145 and sn.endswith("admin$"): c["5145_admin$"] += 1
        if eid == 4624 and str(f.get("logonprocessname","")).strip().lower() == "ntlmssp":
            c["4624_ntlmssp_stripped"] += 1
            if str(f.get("logontype")) == "3" and str(f.get("keylength")) == "0" and f.get("subjectusersid") == "S-1-0-0": c["4624_pth2_selection_if_stripped"] += 1
        if ch == "PowerShell" and eid == 4103:
            ci = str(f.get("contextinfo") or "").lower()
            c["4103_rows"] += 1
            c["4103_ci_has_serverremotehost"] += "serverremotehost" in ci
            c["4103_ci_has_' = serverremotehost '"] += " = serverremotehost " in ci
            c["4103_ci_has_wsmprovhost"] += "wsmprovhost.exe" in ci
        if ch == "PowerShell" and eid == 4104:
            c["4104_rows"] += 1
        if eid == 4697:
            svc[(t, str(f.get("servicename")), "machine" if mach else "user")] += 1
    con.close()
    print(t, dict(c))
print()
names = Counter()
for (t, n, k), v in svc.items():
    names[(n, k)] += v
for (n, k), v in names.most_common(15): print(v, k, n)
