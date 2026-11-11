# 038 — Gate rule choices where handoff §7.2 is ambiguous

**Date:** 2026-11-11 · **Status:** accepted (owner, 2026-11-11, with spec 02_gate approval; `gate_tier` name set by the owner) · **Task:** T6 (6.1)

## Context
Handoff §7.2 gives the gate as a table and as pseudo-code, and they disagree in places: the table's R4 is "4624 type 3 **then** 5140/5145", the pseudo-code fires on any remote type 3/10 logon; the table's R8 says "`Image`/`ParentImage` ends `wsmprovhost.exe`"; `is_remote` is not defined for a blank (`-`) IP. The attacker review of the spec draft (ATK-03, 07, 08) showed each reading changes which hops reach T7. CLAUDE.md also asks every linking row to carry `confidence_tier`, a name that T7 uses for its link tiers.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| R4 fires on any remote type 3 (pseudo-code) | Highest recall | Every Kerberos/Group Policy logon becomes an "SMB" trigger | 4624 type 3 volume per DB (t3 findings) |
| R4 needs a share event (table) + remote logons that fire nothing go to `unmatched_remote.csv` for T7 | Rule means what it says; no logon is lost | One more output file | background hops are 4624-led (decision 026) |
| R8 on `Image` or `ParentImage` | Catches children | Every child of one WinRM session fires again | §3.6.3 |
| R8 on `Image` only; children (`ParentImage`) listed as `R8_parent` supporting | One trigger per session start; children still visible | – | – |
| Blank / link-local IP never remote | Strict | Kerberos logons with `-` IP never fire | decision 015 |
| Blank / link-local IP may fire, flagged `ip_kind` | Recall first (§7.1) | Some local noise | – |

## Decision
R4 requires a 5140/5145 tied by logon ID (the table); remote type 3/10 logons that fire no rule are written to `unmatched_remote.csv`, which T7 reads. R8 fires on `Image` only; `ParentImage` matches go to `supporting.csv` as `R8_parent`. Blank and link-local source IPs count as remote and can fire, with `ip_kind` set. The gate's tier column is named **`gate_tier`** (owner, 2026-11-11): it is the CLAUDE.md "confidence tier" for a gate row (A logon ID, B IP/port/time or service name/time, D no anchor), renamed so it is never confused with the T7 link tiers. Spec 02_gate GT-06, GT-10, GT-13, GT-15, section 3.

## Consequences
The trigger list stays small enough to read, and no remote logon is dropped (it is either a trigger or in `unmatched_remote.csv`). GTA-01 requires attack and benign key hops in `triggers.csv`; background hops may be in either file. Every reader of gate output must use `gate_tier`, and T7's rows keep `confidence_tier`.

## Kill criteria
If on t00 an attack or benign key hop lands only in `unmatched_remote.csv`, the R4 reading is revisited with the owner before T7.

## Committee answer
**EN:** Where the original gate description could be read two ways, we chose the reading in its rule table and kept every remote logon that fires no rule in a separate list, so nothing is lost before linking.
**TH:** ในจุดที่คำอธิบาย gate เดิมตีความได้สองแบบ เราเลือกตามตารางกฎ และเก็บ logon ระยะไกลที่ไม่เข้ากฎใดไว้ในรายการแยก จึงไม่มีสิ่งใดหายไปก่อนขั้นเชื่อมโยง
