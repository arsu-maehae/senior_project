# 044 — Council: SMB/NTLM source linking, link time windows, offset uncertainty and identity (T7 spec)

**Date:** 2026-11-13 · **Status:** **proposed — council verdict of 2026-11-13, awaiting the owner; nothing here is approved** · **Task:** T7 (7.1) · **Relates to:** 011, 013, 014, 015, 039, 043 (Q12), spec [03_stitch](../specs/03_stitch.md), input notes [03_stitch_input_notes](../specs/03_stitch_input_notes.md), review [08_clock_offset-2026-11-12](../reviews/08_clock_offset-2026-11-12.md) SF-6, SF-7

## Brief (owner, 2026-11-13; council skill step 0)

**Decision, in one sentence.** How the stitcher (T7) links a target-side hop to a source session when the hop is
NTLM over SMB (no Sysmon 3, no LogonGuid), with which time windows on clock-corrected times, and whether the
clock offset uncertainty may change a hop's identity value.

**Stage.** T7 stitch (`docs/specs/03_stitch.md`).

**Constraints.** No re-runs. Development data only (s02–s07 t00; s02_t01, s03_t01, s06_t01); t02–t10 are never
opened and never used to choose anything. Locked in CLAUDE.md: account is a supporting check, never a join or
grouping condition (Correction I, decision 013); LogonGuid only confirms; identity uses the moving account and
the source host, never the linked session; no threshold; isolated paths are never dropped; every link row
records method, candidate count, time gap, tier, event uids. No approved keys for t01.

**Success.** T7.6: the key's source session is among the candidates of every keyed development hop with its
`candidate_count` recorded; S04's two tracks are never cross-linked; s07 path Y gets its own file copy; the
attack path is among the candidate paths in every development trial.

### Question (a) — NTLM SMB linking
**Owner's lean:** decision 013 plus a name check, with these limits (owner's words, 2026-11-13):
- the name check is a **supporting field recorded per link**;
- it **may break a tie** between candidates;
- it **reads the same command line as the command-line method, so it must not count as independent evidence**;
- **the council decides whether it may change the tier.**

("Name check" = the target's file or service name, taken from the target-side 5145 / 4697 / 7045 events of the
hop, appears in the commands of the candidate source session.)

Advisers may not treat the lean as the default.

Also to answer under (a):
- **Limitation wording (owner's fear 3).** SMB linking rests on the command line for 10 of 14 SMB groups and
  the port join links 0 of 14. Say how the spec reports this as a limitation.

### Question (b) — time windows, on corrected times
**Owner's lean:** keep decision 014's values (port join ±5 s; command line from 120 s before to 10 s after).
The council must answer each of these with a value and its margin:
- **Look-back for 4648 and command line: 120 s vs 30 s.** Evidence: the s02_t01 false candidate at 92 s
  (`admin_it` logon 05:34:09, candidate `svc_backup` session, `account_match` none); 30 s loses no keyed hop.
- **The "after" side.** 5 s loses `s06-smb-1` (nearest command at +6.75 s corrected). Give a value with its margin.
- **Grouping gap.** 2 s sits between 1.33 s (largest gap inside one hop, s03_t01 WinRM) and 2.47 s (gap between
  the two S04 tracks). State the margin and what happens on test trials that fall outside it.

### Question (c) — spec 08 Q12
**Owner's lean:** flag only. The identity value stays as locked (move ≥ dump − 5 s on corrected times); a hop
inside 5 s + offset_unc(source) + offset_unc(target) only gets a flag.

### Owner's fears (advisers attack these first)
1. **Wrong source session:** several candidate sessions on the source host and the wrong one ranked first.
2. **Hops merged or split wrongly:** grouping or artefact bursts glue two hops together or cut one apart.
3. **Fits t00 tooling only:** the rules work because Caldera names targets by IP on t00.

### Not in this brief (owner, 2026-11-13)
- Path chaining for the two-hop key path `s05-p1` goes to the spec's OPEN table only.
- The s06_t00 offset bias is noted as evidence for review 08 SF-6 / SF-7; **the clock step is not changed now**.

## Evidence
Spec 03_stitch §10 (measurements, development trials only, read-only); files in `out/stitch_measure/`.

## Correction to the brief (found by the council's fact-check, 2026-11-13)
The brief's item "5 s loses `s06-smb-1`" came from my measurement summary and is **true only with a 30 s
look-back**. At 120 s the hop keeps its session through the evidence of the earlier WinRM hop to the same target
(a command at −85.81 s, 4648s at −84.9 … −76.3 s). The look-back and the "after" side therefore had to be decided
together. The brief's "10 of 14" was also measured at 120 s: at the chosen 30 s it is 9 of 14, the tenth being the
s02_t01 candidate with `account_match` none. Decision 014 does not fix 120 s / 10 s with evidence: it carries them over from spec 00 as parameters
and sets only a 5 s floor.

## Options considered
| Question | Option | Pros | Cons | Evidence |
|---|---|---|---|---|
| (a) | Name check may lift a tier | uses a signal that ignores the account | same command line as the method, so the tier would count one event twice; no development hop is tier C | spec 03 §10.4: 0 ambiguous hops left after `account_match` |
| (a) | **Name check = recorded field and tie-break only (chosen)** | cannot inflate a tier; visible per link | has never broken a tie on development data (untested) | 5 of 5 advisers |
| (b) look-back | 120 s (owner's lean) | wider recall | one hop is linked only through another hop's evidence (s06-smb-1); one false candidate at −92 s | §10.4, fact-check item 1 |
| (b) look-back | **30 s (chosen)** | every hop's own evidence is inside (widest −10.51 s; follow-up groups −15.50 s) | fitted on nine trials | §10.5 |
| (b) look-back | two rings: record to 120 s, tier from 30 s | keeps recall | a rule nobody measured; more rows that mean "probably another hop" | researcher |
| (b) after | 10 s (owner's lean) | smallest value that holds | margin 2.85 s, below the largest uncertainty sum (4.73 s) and near the observed clock residual | §10.5, §10.8 |
| (b) after | **15 s (chosen)** | margin 7.85 s; adds no candidate on development data (results at 10 s and 30 s are identical) | not causal evidence: it absorbs clock residual | §10.4 sensitivity |
| (b) grouping | **2 s on target + source IP (chosen)** | no key hop merged or split on t00 | margin 0.67 / 0.47 s from one observation per side, for user endpoint → endpoint hops only | §10.2 |
| (c) | Widen the order test by the uncertainty | uses the measured uncertainty | changes a locked rule; `offset_unc` understates the real error; no development case | §10.6, §10.8; review 08 SF-6 |
| (c) | **Flag only (chosen)** | locked value unchanged; uncertain hops visible | the flag needs a floor to mean anything | 5 of 5 advisers |

## Decision (chairman's verdict — proposed, awaiting the owner)
**THE CALL.**
- **(a)** Keep decision 013's three methods. `name_check` is a field recorded per link, computed only from the
  commands that are the link's own command-line evidence, matched boundary-aware. It may order candidates that are
  otherwise equal. It never changes the tier, `candidate_count`, `method` or `confirm`.
- **(b)** `LINK_LOOKBACK_S` = **30 s** and `LINK_AFTER_S` = **15 s** for the 4648 and command-line methods;
  `PORT_JOIN_S` = 5 s; `GROUP_GAP_S` = **2 s** on (target host, source IP). Evidence between 120 s and 30 s before,
  and between 15 s and 30 s after, is counted per hop, never made a candidate. The values are frozen: a test trial
  whose gaps fall outside the margins gets the same rule, a flag and a count, never its own value.
- **(c)** Flag only. The identity value stays as locked. `order_within_uncertainty` is set when the move lies
  within the summed offset uncertainty of the boundary (dump − 5 s), with a floor on that uncertainty.

**CONFIDENCE.** (a) high: unanimous, and it changes no development result. (b) medium for 30 s and 2 s, low for
15 s: all three come from nine trials. (c) high for flag only, low for the floor value.

**WHY.** A check that reads the same command line cannot raise confidence in that command line. At 120 s a hop
can be "linked" by another hop's evidence, which is the wrong-session failure the owner fears most. Clock residuals
of 1.5 s and more are measured (spec 03 §10.8), so a 2.85 s margin on the "after" side is too thin, and the
reported uncertainty is too small to decide an identity value.

**BIGGEST RISK.** At the chosen range SMB source links rest on one signal (the command line names the target) for
7 of 14 groups, two signals for 2, none for 5; the grouping margin rests on one pair of hops.

**WHERE THE COUNCIL SPLIT.** After side: 10 s (fact-checker, committee member) vs 15 s (attacker, implementer;
researcher 15 s to record, 10 s for the tier). Look-back before the peer review: 120 s (committee member), 60 s
(attacker), 30 s (others); after it, 30 s for all, the researcher keeping a 120 s outer ring. The attacker also
wants a guard that logons owning different install names never share a hop; not adopted (unmeasured), flagged instead.

**WHERE I MIGHT BE FOOLING MYSELF.** My own brief carried a wrong statement (corrected above). Every value is
chosen and checked on the same nine trials; the three t01 trials have no key. The +6.75 s command of s06-smb-1 may
not be the command that caused that logon. Tier B on SMB is agreement with the rule the key also uses.

**NEXT STEPS (implementer, after the owner approves the spec).** `src/stitch/` as in spec 03; name and 4648
helpers moved to a shared module (the `log_check` grouping and bridge functions key or filter on the account and
are not reused); per-hop gap and install-count columns; the out-of-range evidence counts.

**TEST IDEAS (tester).** Blanking `name_check` changes only `link_rank` and `tie`. Groups at a larger gap are
unions of groups at a smaller one. Two sessions of one account naming the same file give `tie` = 1 and tier C.
A hop whose only evidence lies 60 s back is `target_only` with the count set. A hop 4 s inside the order boundary
with uncertainties of 1.76 s and 2.97 s is flagged and keeps its value.

**KILL CRITERIA.**
1. A keyed development hop whose key session is not among its first-ranked links → (a) and ST-50 are reopened.
2. A keyed development hop that needs evidence outside [−30 s, +15 s], or whose link count changes between 15 s
   and 30 s → (b) goes back to the council. Never tuned per trial.
3. On a keyed development trial, two key hops in one group or one key hop split at 2 s → the grouping key is reopened.
4. A development hop inside the uncertainty band → the owner decides (c) with that hop in hand.
5. Decision 013's kill criteria stay in force.

## Consequences
- Spec 03_stitch ST-20, ST-42, ST-43, ST-46, ST-50, ST-62 and §5 carry these values. Decision 014's sentence "the
  command-line window stays [t − 120 s, t + 10 s]" is amended to [t − 30 s, t + 15 s] for T7 **if the owner
  accepts**; its 5 s floor and the order rule are unchanged. CLAUDE.md is not edited.
- **Limitation to state in the report (owner's fear 3):** "For NTLM SMB hops the source session is found from a
  command on the source host that names the target (9 of 14 development groups at the chosen range; 2 of them also
  by a 4648; 5 have no source candidate). The port join links none of them, because Sysmon did not log SMB and an SMB connection belongs to the kernel, and
  NTLM has no LogonGuid confirmation. Where two methods exist (6 WinRM hops) they name the same session in 6 of 6.
  A tier B link on SMB therefore means agreement with the command-line rule, not measured accuracy. It depends on
  tooling that names its target (limitations L10, L11); how it holds on the test trials is to be measured."
  The spec reports, per trial, the number of SMB hops linked by 0, 1 and 2 methods.
- No Windows event the lab could have collected ties an NTLM SMB logon to a source logon session other than
  process-level evidence (researcher; Microsoft event documentation for 4648, 5156, 4776 and the NTLM audit events),
  so this limitation is structural.

## Committee answer
**EN:** For file-share moves our logs give one usable sign of where the move came from: a command on the source
machine that names the target. We keep every candidate, we do not let a second look at the same command count as
extra proof, and we chose the time windows so that a move is never tied to an earlier move's command. A clock that
may be off only raises a flag; it never changes the identity result.
**TH:** สำหรับการเคลื่อนที่ผ่าน file share ล็อกของเรามีหลักฐานที่ใช้ได้เพียงอย่างเดียวว่าการเคลื่อนที่มาจากเซสชันใด คือคำสั่งบนเครื่องต้นทางที่ระบุชื่อเครื่องปลายทาง เราเก็บผู้สมัครทุกเซสชัน ไม่นับการอ่านคำสั่งเดิมซ้ำเป็นหลักฐานเพิ่ม และเลือกช่วงเวลาเพื่อไม่ให้การเคลื่อนที่ครั้งหนึ่งถูกผูกกับคำสั่งของครั้งก่อนหน้า นาฬิกาที่อาจคลาดเคลื่อนทำได้เพียงติดธงเตือน ไม่เปลี่ยนผลด้าน identity

## Appendix A — advisers' answers, round 1 (saved as received, 2026-11-13; authorship shown, the peer review sees them anonymised)

### Attacker
(a) The name check never changes the tier and never changes `candidate_count`. It reads the same commands as ST-43. In §10.4 the key session is the only candidate in 9 of 11 keyed hops, so "name_check match 7 of 7" tests nothing; in the 2 ambiguous groups (s04 A and B) `account_match` already leaves one session. Both signals are close to circular (decision 013: accounts coincide by lab construction). Worst failure: two same-account sessions both run commands naming the same file; both get `match`, `tie` = 1, and the wrong one sits at rank 1 with no flag (not in current data). Test: synthetic hop, two sessions of one account, both naming the same `.exe` → `tie` = 1, tier C, all rows used. Limitation wording: "SMB source links rest on the command line alone for 10 of 14 groups; the 4648 adds a second method for 2, both S06; the port join links 0 of 14; 4 are `target_only`. Tier B on SMB means agreement with the key's own rule, not accuracy; it holds while the tooling names targets by literal IP (L11, decision 013)." Report these counts per trial.
(b) Look-back: the −92 s candidate is tier D, so 30 vs 120 s changes only `candidate_count`, never the tier. Position **60 s**: 49 s above the widest burst (−10.51 s), 32 s below the false candidate; a cut at 30 s is fitted to 9 trials, a slower operator is UNVERIFIED. After side: 10 s leaves 3.25 s over +6.75 and 2.85 s over +7.15, thin; the +6.75 s value is itself the physically impossible kind SF-7 flags. Position **15 s** (margins 8.25 / 7.85 s); report 10 and 30. Grouping: margin 0.67 s below, 0.47 s above; the upper side rests on one pair (s04 A → B), UNVERIFIED for t02–t10. A test hop with an inside gap above 2 s splits: under ST-25 only one part matches the key, the other becomes an unkeyed non-seed hop. Two key hops closer than 2 s glue and T7.6 cannot separate them. Tests: gaps of 2.0 s and 2.001 s; two hops with different install names at 1.5 s. Add a rule that members owning different install or binary names do not merge.
(c) Flag only, never change the value. But `offset_unc` understates the error (≤ 0.64 s reported in s06_t00 against a ≥ 1.55 s to +6.75 s bias, §10.8, SF-6), so the flag needs a floor or it stays silent. No development hop is flagged either way (smallest gap 38.4 s): needs a synthetic test, a hop at dump + 4 s with unc 4.73 s. The flag must reach T9.
Result that would prove the main worry: on a rerun trial, a keyed SMB hop whose key session is not rank 1, or whose command line does not name the target by IP.

### Committee member
1. Why believe an SMB link that rests on a command line? The spec does not claim it is right: 10 of 14 link that way, port join 0, 4 `target_only`; tier B at most; STA-05 calls 11 of 11 agreement, "not accuracy". **Weakest answer:** key and linker share one rule, so these nine trials cannot show the link is correct. Fear 3 stands.
2. Is the name check new evidence? No (ST-46). In the only ambiguous case (s04 A/B) `account_match` already left one session.
3. Why 2 s? One observation on each side (1.328 s, 2.47 s): margins 0.67 and 0.47 s. The 1.328 s is from s03_t01, which has no approved key, so "one hop" there is UNVERIFIED.
4. Why 120 or 30 s, why +10 s? 120 s predates the measurements (decision 014, not read: UNVERIFIED). 30 s was fitted to one false candidate and +10 s to one hop. §10.8 says a source event cannot follow its logon, so +10 s absorbs clock error.
5. Why may an uncertain clock decide identity? Untested: no development hop is inside the band; §10.8 shows errors ≥ 1.55 s where `offset_unc` is 0.001–0.64 s, so the band is too narrow.
Decisions: (a) the name check never changes the tier; tie-break only, after `account_match`. Limitation: NTLM SMB source sessions come from the source command line (10 of 14; port join 0; 4 unlinked); tooling that does not name the target gives `target_only`; tier B is agreement, not measured accuracy. (b) Freeze all three values; on test, report hops in the 1–3 s band and results at the §5 alternatives, no retuning. Look-back **120 s** (fixed before the data; its only measured cost is one tier D row). After **+10 s**, margin 2.85 s, declared as fitted. Grouping **2 s**, margins 0.67 / 0.47 s. (c) Flag only; report the count of flagged hops and IdentityCoherence with them as 1 and as 0; state that `offset_unc` understates the error.

### Implementer
(a) The name check must not change the tier: a lift would make `confidence_tier` depend on ST-32's file-name tie, itself tier B; no development case (s04 A/B is settled by `account_match`), so testable on synthetic rows only. Schema: add `name_check_event_uids`, `name_check_same_event` (1 when the matching command is the row's own ST-43 evidence), `rank_basis`. Test: blanking `name_check` leaves tier, method, `candidate_count`, `confirm` identical; only `link_rank` and `tie` move. Allowing a lift costs `tier_base` and `tier_raised_by`, about 0.5 day. Limitation: report methods per protocol (SMB 0 / 2 / 10 / 4 of 14) and a `target_form` column (ip or hostname); wording "tier B is agreement with the command-line rule, not accuracy; to be measured". The t00 form distribution is UNVERIFIED.
(b) Look-back **30 s** (margin 19.5 s). After **10 s** (margin 2.85 s, thin: about the 2.6 s same-day spread of one host's offset, §10.8). Count, never list, evidence in [−120, −30) and (+10, +30] in `stats.json`. Grouping **2 s**; members share one host clock, so the 0.67 / 0.47 s margins are tool timing only. Visibility: per hop `splits_at_1s`, `merges_at_3s`, `service_install_count` (> 1 signals an over-merge); test that groups at a larger gap are unions of groups at a smaller one. In-band trial: same rule, flag and count, never a per-trial value; T10 reports with and without flagged hops.
(c) Flag only. Widening needs a second value column, a direction rule and an amended locked decision, with no development case. Add `offset_unc_source_ms`, `offset_unc_target_ms`, `order_margin_ms`. **The drafted flag is centred on move = dump, not on the boundary dump − 5 s: define it as |order margin| < uncertainty sum.**
Layout `src/stitch/`: `params`, `inputs` (refusals, gate CSVs, own loader), `sessions`, `hops`, `artefacts`, `evidence`, `links`, `identity`, `paths`, `outputs`, `run`. Move to `lab_common`: the `matching` name and decoder functions, `bridge.target_texts` / `session_of`, `checks_dumps.session_state` / `build_history` (datetime-typed; the gate uses integer microseconds), one timeutil, `open_ro`, `sha256_file`. Not reusable: `hops.group_hop_instances` (keys on account) and `bridge.bridges` (filters on account) contradict ST-21 and ST-45. First tests: STT-02 with the union property; STT-03; STT-06/07 invariance. Riskiest rule: **ST-32** (moves an artefact between hops on file name and time, 6 cases, needs service-path parsing, feeds `name_check`, rank and path nodes). Under-specified: tier B "only such session" (scope across methods, mixed-account hops); `link_rank` per row or per session; name-match rule (boundary, minimum length); "nearest" in `time_delta_ms`; the `rules` column; STT-13's definition of command text; ST-71 node volume; whether pre-window 4624s can be loaded for ST-63 (UNVERIFIED). Effort (days): helper move 0.5; 7.2 1.5; 7.3 3; 7.4 1; 7.5 1 + 1.5 after Q6/Q7; 7.6 1; 7.7 2; identity rows 1.

### Researcher (no file written)
Q1, source-side events for NTLM SMB. 4648 carries SubjectLogonId, process, TargetServerName and network address: the only event that names both the remote server and a local session; the lab has it (`source_4648`). Microsoft says it fires when a process supplies explicit credentials, not for every SMB connection (inference: fits 2 of 14). NTLM 8001 on the client: target server, user, client process name, no logon ID; for SMB the PID is 4 (kernel redirector); needs an audit policy not collected. 5156: PID and application, no logon ID; not collected; inference: PID 4 for SMB. 4776 on the DC: source workstation name only. SMBClient logs: field lists UNVERIFIED. Inference: even with more collection no Windows event ties NTLM SMB to a source session except process-level evidence (4648, command line), so the SMB limitation is structural, not a defect of the stitcher.
Q2. No published rule joins a target-side file or service name to a source command line (Splunk and CAR rules treat 5145 / 7045 as single events; MITRE DET0530 names a 5–10 minute window between remote file access and execution as an example only). `name_check` as corroboration is UNVERIFIED in the literature; it reads the same event as `cmdline_target`, so it is not independent (inference).
Q3. No guidance on short windows. HADES p.6: one remote authentication creates several logon events with different logon IDs, the count depends on SMB or RDP; no gap value. Hopper uses a 24-hour window (secondary summary). All window values must come from our own data.
Positions. (a) Name check tie-break only, never the tier. Option C: a `signal_basis` column listing which of port, 4648, command line fired; limitation "SMB source linking has one signal for 8 of 14 groups, two for 2, none for 4; agreement between methods is not accuracy." (b) **Option C, two rings:** record candidates out to 120 s back, but only candidates inside 30 s count toward `candidate_count_account` and the tier; candidates outside the 30 s ring are capped at D. After side: keep 10 s; margin thin; the +6.75 s command cannot follow the logon it caused, so it is clock residual or logging lag, larger than the reported `offset_unc`. Grouping: keep 2 s with the review flag; links and identity are per member and per account. (c) Flag only; no source settles flag vs widen vs discard (King and Chen use happens-before, secondary, UNVERIFIED). Option C: also write, next to the locked value, the value recomputed at 5 s + unc as a sensitivity column that does not enter the ranking; reported unc understates the real error (§10.8), so widening on it would under-cover.
Sources: Microsoft Learn event pages 4648, 5156, 4776, 4624; Microsoft NTLM auditing events (8001–8004); JPCERT tool analysis sheet (PsExec); MITRE DET0530; Hopper (arXiv 2105.13442, secondary summary); docs/papers/HADES.pdf pp.5–6, 11.

### Fact-checker
**Blocking (brief or draft text that is wrong and must be fixed before a verdict leans on it):**
1. **"After 5 s loses s06-smb-1" is false at the draft's own 120 s look-back; it is true only with a 30 s look-back.** At 120 s the hop keeps its session through a command at −85.81 s and 4648s at −84.9 … −76.3 s, i.e. the evidence of the earlier WinRM hop to the same target. Look-back and "after" side cannot be decided separately. (`all_summary.json` s06_t00: `cmd[-120,+5]` {0:1, 1:4} = `cmd[-120,+10]`; `cmd[-30,+5]` {0:2, 1:3}.)
2. **ST-46 as written is not the rule that was measured.** The script checks names only in commands that already matched the target (substring match, not boundary-aware); ST-46 says any command line of the session. "7 of 7" supports the narrow rule only.
3. **The 0.67 s / 0.47 s grouping margin holds only for the 23 user endpoint → endpoint groups.** Over all remote logons the 2 s cut falls inside a continuous run of gaps (1.926, 1.95, 1.987, 2.089, 2.105, 2.117, 2.123 s).

Locked decisions: no option breaks one (ST-21, ST-45 account never a key or filter; ST-60 identity ignores the link; ST-04 no threshold; ST-47 LogonGuid only confirms; decision 013 itself says the tier uses `account_match`).
Positions. (a) `name_check` recorded field and tie-break only, no tier change: no development hop is tier C, and it has never changed an order (agrees with `account_match` in 2 of 2). "Not independent" is true (same field, session, window); its real value is that it does not use the account. Limitation wording: "SMB source sessions are found from the command naming the target (10 of 14 development groups, 2 also by 4648). The port join links 0 of 14 and NTLM has no LogonGuid confirmation, so tier B is agreement with the key's rule, not accuracy. This depends on the tooling (L10, L11); expected to hold on test trials, to be measured." (b) Look-back **30 s**: 19.5 s to the widest needed burst (−10.51 s), 55.8 s to the nearest foreign evidence. After **10 s**: margin 3.25 s (command), 2.98 s (4648), on one hop, below the largest uncertainty sum 4.73 s. Grouping **2 s**: margin 0.67 / 0.47 s for user hops, about 0.01 / 0.09 s for dc01 groups; outside it S04 A and B become one mixed-account hop, or one hop splits; both show through `gap_near_threshold`, and seed counts change. (c) Flag only: matches Correction K and decision 014 as written; widening stays inside CLAUDE.md's "≥ 5 s" but amends 014 and 043 item 5; `offset_unc` understates the real error; no development hop is in either band.

| Location | Assumption | Verdict | Evidence |
|---|---|---|---|
| §10.4 sensitivity, §5 `LINK_AFTER_S`; brief (b) | After 5 s loses s06-smb-1 | WRONG at 120 s; true at 30 s | as item 1; `group_detail.json` group 30: commands at −85.81 and +6.75 … +7.15 s, 4648 at −84.91 … −76.26 and +7.02 s |
| ST-46; §10.4 "7 of 7" | The measured rule is the written rule | WRONG | script builds the text only from target-matching commands |
| ST-46 "not independent" | True of the rule | VERIFIED | same `command_line` field, session, window as ST-43 |
| ST-50 tie-break | `name_check` has broken a tie | UNTESTED | no group with > 1 account-consistent or > 1 name-matching session in nine trials; s04 A and B already differ by tier (B vs D) |
| Q1 option (b), C → B lift | Evidence supports it | UNTESTED | 0 tier-C hops; would blunt 013 kill criterion 2 |
| Decision 014 | It fixes 120 s / 10 s | WRONG | text: "at least 5 s (parameter, default 5 s for port joins; the command-line window stays [t − 120 s, t + 10 s], spec 00_log_check)". 5 s is a floor; 120 / 10 carried over without evidence; no 4648 window. 30 s amends that sentence, not CLAUDE.md |
| §10.4, §10.5 | 30 s loses no keyed hop, removes the −92 s candidate | VERIFIED | s02_t01 `cmd[-30,+10]` vs `[-120,+10]` |
| §10.2 | 1.33 s and 2.47 s bound the 2 s cut | VERIFIED for the 23 user groups; WRONG for all groups; 2.47 s recurring on other trials UNTESTED | one pair, one trial |
| ST-20 | Clock error does not move grouping | VERIFIED | same target host, the offset cancels |
| ST-62; brief (c) | Flag only matches K and 014 | VERIFIED | handoff l.147; 014; 043 item 5 and Q12 |
| §10.6 | No hop within 5 s or 5 s + uncertainty; largest sum 4.73 s | VERIFIED | gaps 38.386 and 141.352 s |
| ST-62 `order_within_uncertainty` | `offset_unc` bounds the pair error | WRONG | s06_t00 ep-01 639 ms + ep-02 1 ms vs port join +1.553 … +1.571 s; the measurement treats a `none` host as 0 |
| §10.8 | +6.75 s is a lower bound on the offset error | UNTESTED | presumes that command caused the logon; if so the error exceeds 5 s (043 kill criterion); 014's kill criterion "keyed hop outside 5 s" is arguably met on corrected times (raw +3.97 s) |
| §10.1, §10.4 | other spot checks | VERIFIED | s02_t00 row; s04_t00 21 groups; port ±10 s at −9.434 s; 4648 losses 3 / 1 / 0 |

## Appendix B — anonymous peer review (round 2; A = implementer, B = fact-checker, C = attacker, D = researcher, E = committee member)
| Reviewer | Ranking of the other four | Strongest point named | Biggest blind spot named | Own view changed? |
|---|---|---|---|---|
| A (implementer) | B > C > D > E | B: look-back and "after" are coupled; decision 014 never fixed 120 s / 10 s | all trust `gap_near_threshold`, which fires constantly on dc01 groups; nobody tests ST-32 | after side 10 s → **15 s**; ST-46 to the narrow rule; flag with an uncertainty floor |
| B (fact-checker) | A > C > D > E | A: the `log_check` grouping and bridge helpers key or filter on the account, so they cannot be reused | none of the four saw that s06-smb-1 is held by evidence 85 s back; C's 60 s / 15 s and D's two rings are unmeasured | no (30 s / 10 s / 2 s; tie-break only; flag only) |
| C (attacker) | B > A > D > E | B: s06-smb-1 at a 120 s look-back | nobody tests evidence of one hop credited to a later hop; no guard against merging hops with different install names | look-back 60 s → **30 s**; after stays 15 s |
| D (researcher) | B > A > C > E | B: the coupling; 014 gives only a 5 s floor | E's "fixed before the data" is contradicted; C's values are unevidenced | two rings kept (120 s record, 30 s tier); after 15 s record, 10 s tier; flag on the boundary |
| E (committee member) | B > A > D > C | B: the coupling | all accept "agreement, not accuracy" and stop; none uses the WinRM hops, where port join and command line both fire, as the only key-independent check | look-back 120 s → **30 s**; after stays 10 s; margin claimed for user hops only |
