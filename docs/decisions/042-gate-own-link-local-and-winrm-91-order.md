# 042 — Gate: each host's own IPv6 link-local addresses (F1) and the WinRM 91 order (F4)

**Date:** 2026-11-12 · **Status:** accepted (owner, 2026-11-12, including evidence E2) · **Task:** T6 review follow-ups · **Amends:** spec 02_gate §2 columns, §3.1, §5 `WINRM_PAIR_S`, GT-02(c), GT-05, GT-13, §7 (GTT-19, GTT-20); replaces the WinRM 91 order of decision 041 · **Review:** [02_gate-2026-11-12](../reviews/02_gate-2026-11-12.md) F1, F4

## Context
- **F1.** dc01 logs on to itself over its own link-local address `fe80::f374:6da8:f7ba:1a61` (account `dc-01$`, Kerberos, type 3). GT-05 compared only the IPv4 `LAB_HOST_IPS`, so these logons fired R4: 23 trigger rows (7/4/4/2/4/2 in s02–s07 t00) and 126 `unmatched_remote` rows (17/22/19/27/18/23).
- **F4.** GT-13 (tier D) and GT-02(c) paired a wsmprovhost Sysmon 1 with a WinRM 91 0–5 s *before* it. Read-only SQL on the six t00 DBs found:
  - 0 pairs in that order.
  - 21 distinct pairs in the other order: the Sysmon 1 comes first, gap min 57 / median 78 / max 666 ms. In window: 82, 666 and 109 ms (s03, s05, s06).
  - Each wsmprovhost has exactly one 91 within 5 s.
  - The 91 clientIP equals the anchor IP in 3/3 in-window pairs.
  - So neither rule could ever fire on this data.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| F1: fixed list of each host's link-local addresses | simple | breaks when an address changes (ep-03 had `e1d4…` on 2026-09-17, `6577…` later); a hand-made list is not data-driven | 2 ep-03 addresses in the DBs |
| F1: treat all link-local as self | removes the 23/126 rows | would hide a real cross-host link-local logon | rejected by the owner |
| **F1: own addresses from each host's own events in the same DB (E1, E2, conflict rule)** | data-driven, per trial, per host; a cross-host link-local logon stays remote | dc01 has no E1 evidence, so E2 uses the account to recognise (never to link) | dc01 Sysmon only in s02/s05, no outbound fe80 |
| F4: keep the spec order (91 before Sysmon 1) | none | never fires (0 pairs) | stats `sensitivity` |
| F4: symmetric \|Δt\| ≤ 5 s | robust to either order | a wider window for an exclusion rule (removes events) | – |
| **F4: 91 0–5 s after the Sysmon 1, 1:1, earliest first** | matches 21/21 pairs; 7.5× margin over the observed max | assumes an order seen only on t00 | measured above |

## Decision
**Own link-local (GT-05).** Built per trial DB, unclipped, and it can only reclassify a host's own address:
- **E1:** an outbound Sysmon 3 (`initiated` = 1) on host H with link-local `source_ip` L → L is H's own address.
- **E2:** a remote 4624 (type 3/10) on H from L whose account is H's own machine account → L is H's own address.
  - The machine account is read from H's own 4624s opened by a system logon ID (subject account, domain stripped). E2 is used only when H has exactly one such account.
  - Guard: every 4624 on H from L must use that account.
- **Conflict rule:** an address with evidence on more than one host is recognised for none of them.
- Addresses are compared as compressed link-local text with any `%zone` removed.
- A recognised (H, L) is H's own IP: `loopback_or_self`, `reason_detail` ending `own link-local (E1)`, `(E2)` or `(E1/E2)`.
- New `stats.json` key `own_link_local` = `{per_host, conflicts, machine_accounts, e2_rejected}`.
- New read column: `subject_account`.

**WinRM (GT-13, GT-02(c)).**
- A wsmprovhost Sysmon 1 pairs with the earliest WinRM 91 on the same host 0–5 s **after** it. Pairing is 1:1: starts are taken in time order, and each 91 is used once. It is computed over all in-window starts and 91s, before suppression.
- **GT-02(c):** a start is excluded only if its paired 91's clientIP is excluded **and** it has no tier-A anchor. A tier-A anchor is a remote type 3 4624 that survived GT-02..05, with `session_id` matched by logon ID and logged at or before the start.
- **Tier D:** the paired 91 gives `source_ip` and a supporting uid. Implementation reading: a paired 91 removed by GT-02..05 (e.g. loopback) is not used, so the row's IP stays blank.
- `winrm_91_to_wsmprovhost_pairs` now counts 91s 0..t s after the Sysmon 1.

## Result on t00 (gate rerun 2026-11-12)
- Triggers fell by 7/4/4/2/4/2 = 23 and unmatched rows by 17/22/19/27/18/23 = 126, exactly as proposed.
  - Every removed row is a dc01 link-local row.
  - No row was added, and no kept row changed.
- All 15 key hops are still in `triggers.csv` at tier A.
- Own addresses found:
  - dc01 `f374…` by E2 in all six trials.
  - ep-01, ep-02 and ep-03 addresses by E1.
  - No conflicts, no E2 rejections.
- The 8 dc01 `no_rule` 5140s (F13) are now `loopback_or_self` (own link-local).
- WinRM pairs in window: 1/1/1 (s03/s05/s06). GT-02(c) exclusions: 0. Tier-D rows: 0.

## Consequences
- Self-logons over link-local no longer reach T7.
- A cross-host link-local logon, or an address with no evidence, still fires (GTT-19).
- E2 depends on the account text; an attacker using the host's own machine account from another host over link-local would be suppressed only if no other account ever logs on from that address and no other host shows the address as its own. State this as a limitation.
- The WinRM order is proven on t00 only.
- GT-02(c) and tier D still never fire on t00; they are covered by synthetic tests (GTT-20) only.

## Kill criteria
- On any later development trial, a 91 found 0–5 s *before* a wsmprovhost with no 91 after it → revisit the order (symmetric pairing).
- A link-local address recognised as own that is shown, by a key hop, to be another host's → revisit E2.
- Any conflict listed in stats → review that trial.

## Committee answer
**EN:** The gate removes a host's logons to itself. A link-local address counts as "self" only when that host's own logs prove it is its own: its own outgoing connections, or logons as its own computer account. So a real cross-host connection is never hidden. The WinRM pairing follows the order measured in the data: the process starts first, then the WinRM event, in 21 of 21 pairs.
**TH:** เกตตัดการล็อกออนที่เครื่องเข้าหาตัวเองออก โดยถือว่าที่อยู่ link-local เป็นของเครื่องนั้นก็ต่อเมื่อบันทึกของเครื่องนั้นเองพิสูจน์ได้ว่าเป็นของมัน คือการเชื่อมต่อขาออกของมันเอง หรือการล็อกออนด้วยบัญชีคอมพิวเตอร์ของมันเอง จึงไม่ซ่อนการเชื่อมต่อข้ามเครื่องจริง ส่วนการจับคู่ WinRM ใช้ลำดับที่วัดได้จากข้อมูล คือโปรเซสเริ่มก่อนแล้วจึงเกิดเหตุการณ์ WinRM ครบทั้ง 21 จาก 21 คู่
