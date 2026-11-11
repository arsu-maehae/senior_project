# 041 — Gate implementation readings (owner answers to ten open points in spec 02_gate)

**Date:** 2026-11-12 · **Status:** accepted (owner, 2026-11-12, answers given before T6.2 coding) · **Task:** T6 (6.2) · **Amends:** spec 02_gate §2 refusals, §3, §5, GT-11, GT-12, GT-13, GT-15, GTT-07 · **Relates to:** 038

## Context
Before coding `src/gate/`, twelve points (R6 `method`/`gate_tier` found while briefing the implementer; window-row refusals found in its report) in the approved spec could be read two ways, and two rules disagreed: §3 lists only 4624 type 3/10 in the disposition set, so GT-03's `interactive_logon` disposition could never appear; GT-15 ("a remote 4624 that fires no rule") did not say whether a logon that is only the anchor of an R6 (4697) or R8 (wsmprovhost) row has fired. Other gaps: how many rows when an R6/R8 trigger matches several anchors (near-duplicate 4624s, GT-18); which logon types may anchor R6 and whether the anchor must precede the trigger; what `time_delta_ms` and `candidate_count` measure when the trigger is not the anchor; the time reference of the WinRM 91 supporting event and the tier-D `source_ip`; the direction and boundary of the 5 s pairings. Each reading changes which rows reach T7. The user's instruction for T6.2 was to ask, not decide.

## Options considered
| Point | Chosen (owner) | Alternative(s) put to the owner |
|---|---|---|
| Anchor-only 4624 (GT-15) | counts as fired: disposition `trigger`, not in `unmatched_remote.csv` | also written to `unmatched_remote.csv` |
| Several anchors (GT-12/13) | one row per anchor, `candidate_count` = n | one row, earliest anchor |
| R6 anchor | remote 4624 type 3 or 10, anchor time ≤ 4697 time | type 3/10 any time; type 3 only |
| R8 anchor order | anchor time ≤ Sysmon 1 time | no order condition |
| `time_delta_ms` | earliest of (trigger if not the anchor, supporting events) − anchor | earliest supporting event only (null for a lone 4697) |
| WinRM 91 (GT-13) | anchored: same host, anchor IP, \|91 − anchor\| ≤ 5 s; tier D: latest 91 0–5 s before the Sysmon 1 gives `source_ip` | Sysmon 1 time in both cases; tier-D `source_ip` null |
| Dispositions | R8_parent Sysmon 1 → `supporting`; 3389 Sysmon 3 matching a type 10 R5 → added to its supporting uids, `supporting` | `no_rule` for one or both |
| Type 2/11 (§3 vs GT-03) | added to the disposition set (`interactive_logon`) | keep the set, count in stats only |
| 5 s pairings (R5, R6, WinRM anchor) | symmetric, inclusive \|Δt\| ≤ 5.000 s; a 7045 pairs with the nearest same-name 4697, one-to-one, ties by uid | exclusive; directional |
| R6 `method` / `gate_tier` (GT-12 said method `service_name_time` with an anchor of tier A; §3 tier B = "service name + time") | `method`/`gate_tier` describe the tie to the anchor logon: anchored → `logon_id`, A; no anchor → `none`, D; the 7045 pairing is shown by its uid in `supporting_event_uids` and `service_name_time` in its `reason_detail`; `service_name_time` removed from the method list and from the tier B wording (no rule uses it) | paired rows `service_name_time` with tier A; or with tier B |
| Window row vs DB (§2 listed three refusals only) | refuse when the row's `db_sha256` ≠ the DB's SHA-256, or its `time_basis` ≠ the gate's `TIME_BASIS`; GTT-07 tests both | refuse on hash only; record both in stats only |
| `candidate_count` | per supporting event, distinct anchors it matched by the same method; the row takes the maximum; no supporting event: 1 if anchored, 0 if not; R6/R8: anchors matching the trigger | anchors sharing any supporting event |

Evidence: spec 02_gate §3, §4, §6; decision 038; `events_dedup` columns checked on `data/sample/s04_t00` (WinRM 91 clientIP is stored in `source_ip`; 86 of 88 4697 in s04_t00 are by logon ID 999 and 2 by other logon IDs, so R6 anchors are few and GT-04 removes most 4697).

## Decision
The gate is implemented with the readings in the "Chosen" column. The rule text in `docs/specs/02_gate.md` is amended at each place, marked "amended by the owner 2026-11-12 (decision 041)", so the spec matches the code. GT-02(c) stays "within 5 s after", as written.

## Consequences
Every remote type 3/10 logon is still in exactly one of `triggers.csv` (as trigger or anchor) or `unmatched_remote.csv`; none is in both. Near-duplicate logons give duplicate R6/R8 rows that T7 must group by `anchor_logon_uid` (GT-14). Requiring the anchor before the trigger turns a 4697 logged before its 4624 (same host, so no skew) into a tier-D local install, visible in stats. `dispositions.csv` grows by the in-window type 2/11 logons.

## Kill criteria
If on t00 (GTA-01) an attack or benign key hop's 4697 or wsmprovhost lands in tier D only because its 4624 is logged after it, the order condition is revisited with the owner. If symmetric 5 s pairing gives `candidate_count` > 1 on any key hop, the sensitivity counts at 2 s and 10 s are reviewed first.

## Committee answer
**EN:** Where the gate specification left a choice open, the project owner chose each reading before any code was written, and the specification was updated to match, so the code does exactly what the document says and no logon is lost or counted twice.
**TH:** ในจุดที่ข้อกำหนดของ gate ยังเปิดให้เลือก เจ้าของโครงการเป็นผู้เลือกการตีความแต่ละข้อก่อนเขียนโค้ด และปรับข้อกำหนดให้ตรงกัน โค้ดจึงทำตามเอกสารทุกประการ และไม่มี logon ใดหายหรือถูกนับซ้ำ
