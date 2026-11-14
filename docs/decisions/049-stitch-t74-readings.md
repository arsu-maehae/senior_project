# 049 — Readings for T7.4: account match, tiers, ranks, name check, identity rows

**Date:** 2026-11-14 · **Status:** **accepted (owner, T7.4 plan approval 2026-11-14).** Readings 1–7 accepted; reading 1 carries limitation L-ST4; reading 6 amends spec 03_stitch §3 (`not_applicable` gains `source_host_no_logs`); reading 7 adds an STT-13 note · **Task:** T7 (7.4) · **Relates to:** spec [03_stitch](../specs/03_stitch.md) ST-45..ST-50, ST-60..ST-64, STT-13; 013, 014, 039, 044, 047, 048

## Context
Spec 03_stitch fixes the T7.4 rules but leaves some readings open:
- the order of the tier clauses when they overlap;
- how `tie`, `link_rank` and `rank_basis` are spelled;
- what rows without a session carry;
- how `name_check` finds its event uids;
- what an identity row says for a source host with no logs;
- how STT-13 treats image and account columns.

Task 0 applied the readings below as a read-only prototype on the nine development trials. DBs were opened read-only through `inputs.load_link_inputs`, and all nine SHA-256 values were the same before and after. The script lives in the session scratchpad and prints counts and uids only. Results:

- **Candidates.** 16 hops have candidates: 18 (hop, session) pairs. Every candidate session's 4624 is inside the window (`opened_before_window` False), so `direct` can always be computed.
- **Tiers.**
  - WinRM: 6 A (s03_t00, s03_t01, s05_t00, s06_t00 ep-01→ep-02, s06_t01 ×2) and 1 B (s06_t00 ep-01→ep-03, no Sysmon 3).
  - SMB: 9 B and 2 D. The two D are the other-track sessions of s04 A and B.
  - Tier C: 0. Ties: 0. Every port-joined session is `direct` (3) or `4648` (3, S06), so reading 1 changes no development tier.
- **Account match.** S06 agent session `svc_backup`, with 4648 credentials `admin_it`. In both mixed hops (s06_t00 s06-smb-1, s06_t01 h0026) the values per member are `4648;direct;direct` and the best is `direct`.
- **S04.** In track A the session 0xd6398 is B, rank 1, `name_check` match; 0x17c46 is D, rank 2, no_match. Track B is the reverse. `rank_basis` = tier.
- **Name check.** `match` for the first-ranked session of every SMB hop with names (9); `no_names` on every WinRM hop.
- **Identity, 15 keyed hops.** Every Q9 variant equals the key's `identity_expected` on 15 of 15: {all R1 reads, non-system reads, the key's rule (nearest non-system read with `order_ok`)} × {`end_unknown` not counted, counted}.
  - Smallest deciding dump-to-move gap: 38.386 s (s04-A). Largest on keyed hops: 65.241 s.
  - No keyed row has `order_within_tolerance` or `order_within_uncertainty` = 1.
  - Every value-1 keyed hop has a deciding row with no pre-window open.
- **Identity, user endpoint → endpoint.** 23 (hop, account) pairs: value 1 for 11 and 0 for 12. The totals equal §10.6, but the make-up differs. §10.6 counted 23 *groups*, including the 2 S06 follow-up groups; ST-26 now attaches those to their hop, so they have no identity rows of their own. The 2 mixed S06 hops now give one row set per account (2 accounts each). Both follow-up groups and both extra accounts have value 0.
- **Pre-window opens.** 8 (hop, account) pairs get value 1 only through a session whose 4624 is before the window. All are `svc_backup` hops from ep-02 to dc01 (s06_t00 ×2, s07_t00 ×2, s02_t01 ×2, s03_t01, s06_t01): no key hop, no endpoint → endpoint hop. This is the decision 039 look-back working as designed. It is flagged by `session_open_before_window` = 1 and is reported, not hidden.
- **Hosts with no logs.** The 5 `source_host_no_logs` hops (s07_t00 ep-03 → dc01) are all machine accounts.

## Decision
1. **Tier order (ST-48).** For each (hop, session):
   - `account_match` = none → **D** (checked first);
   - else `sysmon3_port` found this session and no other → **A**;
   - else `sysmon3_port` found several sessions including this one → **C**;
   - else (found by 4648 / command line) the hop's only account-consistent session over all methods → **B**, otherwise **C**.

   Why: 013 says "the tier uses `account_match`", and the D clause of ST-48 has no exception. A hop with all ports 0 can never reach A (port 0 never joins).

   **Limitation L-ST4 (owner):** a port-joined session whose 4624 account differs from the moving account gets tier D under the locked tier rule, for example a session using injected credentials with no 4648. In that case the strongest technical link gets the lowest tier. No development hop is affected. No rule change.
2. **`account_match`, per member.**
   - `direct`: the member's 4624 account equals the session's own in-window 4624 account (`window_open`), compared in lower case.
   - `4648`: the member's account equals one of the session's `credential_accounts` (TargetUserName of its in-range 4648s naming the target).
   - else `none`. A NULL account never matches.

   The best value written is direct > 4648 > none (for display). For the tier and the rank, direct and 4648 count the same (owner Q14). `candidate_count_account` = the hop's sessions whose best value is not none.
3. **Rank (ST-50).**
   - `link_rank` = dense rank of the hop's sessions by (tier, account-consistent before none, `name_check` match before the rest). Time is never a key (Q14).
   - `tie` = 1 on every row of a session that shares rank 1 with another session; else 0.
   - `rank_basis` ∈ `only` (one session), `tier`, `account_match`, `name_check`, `equal` (all sessions on one rank). It names the first key that separates the session's rank group from the next group up, or, for rank 1, from rank 2.
   - Values are repeated on all rows of the session.
4. **Rows with no session.** An unresolved row (`session_unresolved_reason` set) and the `target_only` row get:
   - tier D;
   - `account_match` none (every member none, member count 0);
   - `name_check` = `no_names` / `no_match` from the hop's names;
   - empty `link_rank`, `tie` 0, `rank_basis` `no_session` / `target_only`.

   The internal reason `no_session_id` (a NULL logon ID; 0 development rows) is written with that spelling.
5. **`name_check` (ST-46).**
   - The names are those of the hop's own `share_burst` and `service_install` rows, including a burst moved to the hop by ST-32.
   - `match` when one of them was found (boundary-aware, 048 item 1) in a command that is this session's own `cmdline_target` evidence for this hop.
   - `name_check_names` = the matched names; `name_check_event_uids` = the command events that held them.
   - `source.Evidence` gains `names_by_uid` (uid → names found, text-free) so the uids are exact. This is the only change to T7.3 code.
   - The check never changes tier, method, `candidate_count` or `confirm` (044 (a)).
6. **Identity rows (ST-60..64).** One row per (hop, account, R1_lsass row of `supporting.csv` on the source host).
   - `not_applicable` is set per (hop, account), first that applies:
     - `source_host_unknown`;
     - **`source_host_no_logs`** (owner: the missing fact must be explicit, not look like "no LSASS read"; spec §3 amended);
     - `machine_account` (all the account's members are machine accounts).
   - A hop whose source host has no R1 row gives one row per account with empty dump columns.
   - **Q9 stays open.** Every R1 row is listed (system, service and domain accounts; before and after the move), with `dump_source_image` and `dump_account` from its in-window Sysmon 10 row. `end_unknown` sessions are listed apart from open ones. No value is computed and no read is chosen.
7. **STT-13 on the spec output files.** The spec's image and account columns (`dump_source_image`, `dump_account`, `account`, `source_session_account`) hold DB field values that can also occur inside command lines (`rundll32.exe` is 12 characters). The substring scan blanks those columns. A second test checks that every value in them equals the DB field of the event its row references (the dump's Sysmon 10 `source_image` / `account_name`; the member and session 4624 `account_name`). This shows they carry no command text.

## Consequences
- No development tier, rank or identity value depends on readings 1, 3, 4 or 6. Synthetic tests (STT-06..09, STT-15) cover each one.
- T9 receives every LSASS read and both session lists, so it can settle Q9 in its own spec.

## Kill criteria
- A development hop whose tier changes under reading 1 (a port-joined session with `account_match` none) → report it to the owner before T7.5.
- Any Q9 variant that disagrees with a keyed hop's `identity_expected` → stop and report; do not choose a variant.

## Committee answer
**EN:** A link's tier says how much evidence ties the source session to the move. If the session's account matches neither the logon nor its explicit credentials, the link gets the lowest tier, even when a network connection ties them. We state that as a limitation. For identity we list every LSASS read with who ran it and when, and leave the choice of which reads count to the scoring stage. On the development data every choice gives the answer key's value.
**TH:** ระดับ (tier) ของการเชื่อมโยงบอกว่ามีหลักฐานผูกเซสชันต้นทางกับการเคลื่อนที่มากเพียงใด ถ้าบัญชีของเซสชันไม่ตรงกับบัญชีที่ล็อกออนและไม่ตรงกับข้อมูลรับรองที่ระบุไว้ การเชื่อมโยงจะได้ระดับต่ำสุด แม้จะมีการเชื่อมต่อเครือข่ายผูกไว้ก็ตาม เราระบุเรื่องนี้เป็นข้อจำกัด สำหรับตัวตน เราบันทึกการอ่าน LSASS ทุกครั้งพร้อมผู้ที่รันและเวลา และปล่อยให้ขั้นให้คะแนนเป็นผู้เลือกว่าจะนับการอ่านใด บนข้อมูลชุดพัฒนา ทุกทางเลือกให้ค่าตรงกับเฉลย
