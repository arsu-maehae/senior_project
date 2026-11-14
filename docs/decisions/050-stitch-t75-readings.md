# 050 — Readings for T7.5: chaining, paths, nodes, notes, spellings

**Date:** 2026-11-14 · **Status:** **accepted (owner, T7.5 plan approval 2026-11-14).** · **Task:** T7 (7.5) · **Relates to:** spec [03_stitch](../specs/03_stitch.md) ST-04, ST-23, ST-70..ST-74, STT-13, STT-14; owner answers Q6, Q7, Q13, Q15 (b), Q16 (a); 013, 014, 039, 046, 049

## Context
ST-70..74 fix the path rules, but a few readings are left open: how "maximal chains that share a hop are merged" is computed, the edge boundaries, what a `session` edge compares, which sessions and events the notes use, how some columns are spelled, and the node rules in detail. A read-only prototype on the T7.4 outputs of the nine development trials (scratchpad, counts only) gave exactly the spec §10.7 recount:
- 2 `host_time` edges, both in s05_t00: s05_t00-h0030 → h0032 (118.827 s) and h0010 → h0032 (450.762 s);
- 0 `session` edges;
- no edge in the other eight trials.

## Options considered
| Item | Option chosen | Alternative | Why |
|---|---|---|---|
| Merge | weakly connected components of the edge graph over chainable seeds | enumerate maximal chains, then merge pairwise | same result as the transitive ST-73 merge; membership never depends on chain enumeration |
| Chain list | `merged_from` = maximal simple chains (no repeated hop) | chains from parentless hops only | ±5 s allows a 2-cycle (A→B and B→A both within tolerance); a cycle has no parentless hop |
| Edge flag | `order_within_tolerance` = \|Δ\| ≤ 5 s | \|Δ\| < 5 s (ST-62's form) | the edge exists at Δ ≥ −5 s, so every negative-Δ edge is flagged, including Δ = −5 s exactly |
| Session edge | full session key (host, logon ID, boot epoch) | bare logon ID | a logon ID can repeat after a boot (047) |
| Machine-only | DB `machine_account` flag on every member | account ends with `$` | one definition (`Hop.machine_account_only`), as identity uses |
| Notes | rank-1 sessions (any tier); every node event uid | every candidate session | candidates of rank 2 are the ones the rank rejected (s04 A/B would note each other through their tier D rows) |

## Decision
1. **Paths.** A path is a weakly connected component over the chainable seeds. A chainable seed is a seed (ST-23) that is not machine-account-only (Q15 (b)). Every other seed is its own path. `merged_from` lists the component's maximal simple chains, spelled `h…>h…` and `|`-joined. Path ids are `<trial>-p<NNNN>`, ordered by first hop (corrected time, then hop id). `isolated` = 1 hop and no edge.
2. **Edges.** H1 → H2 when H2's source host is known and equals H1's target host, and H2.first ≥ H1.first − 5 s (corrected). `time_delta_ms` = H2.first − H1.first. `order_within_tolerance` = \|Δ\| ≤ 5 s. `clock_unreliable` = the larger of the two hops' `hops.csv` values. A hop with an unknown source host never chains.
3. **`session` edge.** One of H2's rank-1 tier A / B sessions has the same session key as one of H1's members. Otherwise the edge is `host_time`.
4. **Machine-account-only** = `machine_account` = 1 on every member.
5. **Notes.** `shared_source_session_with` = other paths with a hop whose rank-1 session key equals one of this path's. `shared_event_with` = other paths sharing any `path_nodes` event uid, context rows included. Notes never merge paths (ST-73).
6. **Spellings.** `hosts` = `source>target` per hop, in hop order, `;`-joined. The source is the source host, else the source IP, else empty. Why per hop: a merged path such as s05 is not a line, because two hops enter ep-02. `edge_types` = `host_time:N;session:M`.
7. **Nodes (ST-71).** One row per (path, hop, role, event uid, link id).
   - `target_logon`: member uids, context 0.
   - `artefact`: artefact row uids; `followup_logon` rows get context 1.
   - `source_evidence`: the evidence uids of rank-1 session rows, any tier, context 0 (the spec text).
   - `source_session_event`: rank-1 tier A / B sessions only, events with corrected time ≤ the hop's last member's corrected time (no tolerance), context 1.
   - `target_session_event`: the members' sessions on the target, whole window, context 1.
   - Follow-up logons' sessions add no nodes. Link ids are the `links.csv` ids, from one shared numbering function.
8. **STT-13.** `hops.csv` `member_accounts` joins the blanked account columns of 049 item 7, with the same check that each value equals its DB field. `report.md` holds no command, account, image or target-side name text.

## Consequences
- s05_t00 has one merged path, {s05-t1, s05-h1, s05-h2}, and s05-h2 is flagged `multi_chain_parent` (L-ST2). Every other development seed is its own path.
- No development result depends on items 2 (boundary), 3 or the tier part of item 7. Synthetic tests (STT-14) cover each of them.
- The T7.4 files (`links.csv`, `hop_artefacts.csv`, `hop_identity.csv`) and the t72/t73 check files must stay byte-identical. Baseline: `out/stitch_check/<trial>/t74_run_info.json`.

## Kill criteria
- A development trial whose edge or path set differs from §10.7 / the prototype: report it to the owner before T7.5 is marked done.
- Any T7.4 output that changes bytes: stop, because T7.5 must not change T7.2–T7.4 results.
- Maximal-chain enumeration too slow on a real trial: report it. Path membership does not depend on it.

## Committee answer
**EN:** A path joins two hops only when the second hop leaves the host the first one entered, after it arrived. Chains that share a hop are merged, as the locked rule says, and the shared hop is flagged so a reader can see that two movements met there. Sharing an agent session or an event is written as a note and never merges paths, so separate attack steps stay separate.
**TH:** เส้นทางจะเชื่อมสอง hop เข้าด้วยกันก็ต่อเมื่อ hop ที่สองออกจากเครื่องที่ hop แรกเข้าไป และเกิดหลังจากนั้น สายที่ใช้ hop ร่วมกันจะถูกรวมตามกฎที่ล็อกไว้ และ hop ที่ใช้ร่วมกันจะถูกติดธงไว้ เพื่อให้ผู้อ่านเห็นว่ามีการเคลื่อนที่สองครั้งมาบรรจบกันที่จุดนั้น การใช้เซสชันของเอเจนต์หรือเหตุการณ์ร่วมกันจะถูกบันทึกเป็นหมายเหตุเท่านั้นและจะไม่ทำให้เส้นทางถูกรวมกัน ขั้นตอนการโจมตีที่แยกกันจึงยังคงแยกกัน
