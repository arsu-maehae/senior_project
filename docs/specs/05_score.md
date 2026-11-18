# Stage spec: 05_score

**Owner:** <stage owner> · **Status:** **approved (owner, 2026-11-18)**: all §8 proposals accepted, with two
changes (Q4: weak templates named in L-SC7; Q13: H3 strict, MRR(`full`) > MRR(`b1`)); data-checker, researcher and
attacker review merged ([review](../reviews/05_score-spec-2026-11-18.md)); records 062–066 ·
**Last updated:** 2026-11-18

Decisions this spec rests on: Correction G (NodeScore substitution, no isolated-path filter), Correction J (rank, no
θ), Correction K (identity definition), [013](../decisions/013-council-correction-i-amended.md) (identity input),
[014](../decisions/014-cross-host-time-tolerance.md) (≥ 5 s order tolerance), [018](../decisions/018-s04-both-tracks-exposed.md)
/ [021](../decisions/021-s04-track-a-source-session.md) (ties reported as ties), [019](../decisions/019-dev-test-split.md)
(split), [044](../decisions/044-stitch-linking-and-windows-council.md) (c) (clock flag reaches T9),
[045](../decisions/045-tier-rule-scope.md) (tier rule scope), [046](../decisions/046-stitch-development-allowlist.md)
(allowlist), [049](../decisions/049-stitch-t74-readings.md) (identity facts), [054](../decisions/054-t77-out-guard-and-out-option.md)
(`--out`, out/ guard), [056](../decisions/056-sigma-rule-list-lock.md) (dump only through identity; `context` = 1 out of
NodeScore; Q13 and the order table deferred here), [058](../decisions/058-label-implementation-readings.md)
(`count_key`), [061](../decisions/061-label-stage-review-fixes.md). Owner additions 2026-11-18: baselines B0/B1 in this
spec (§3.6), success criteria written before any test trial is scored (§7.3), λ and w1–w3 frozen with a commit hash
before the test keys are unlocked (§5.2).

## 1. Purpose
Turn the stitcher's candidate paths (T7) and the Sigma labels on their nodes (T8) into **one ranked list per trial**:
every candidate path with its LengthScore, NodeScore, IdentityCoherence and path score, highest first, nothing
dropped. The path score orders paths for an analyst; it is **not a probability** and no threshold θ is applied
(Correction J).

## 2. Input contract
One trial at a time, `trial_id` in the allowlist (SC-01). All inputs are files of earlier stages; the stage opens **no
database** and **never reads `ground_truth/`**.

| File | Columns used | Meaning |
|---|---|---|
| `out/stitch/<t>/paths.csv` | `path_id, hop_ids, hosts, n_hops, isolated, merged_from, edge_types` | the candidate paths (ST-70..73); every row is ranked |
| `out/stitch/<t>/path_edges.csv` | `path_id, from_hop_id, to_hop_id, link_type, time_delta_ms, clock_unreliable` | chain order of hops inside a path (ST-72) |
| `out/stitch/<t>/hops.csv` | `hop_id, first_utc_corrected, source_host, target_host, protocol, member_accounts, best_tier, candidate_count, multi_chain_parent, clock_unreliable` | hop facts |
| `out/stitch/<t>/hop_identity.csv` | all columns (spec 03 ST-60..64) | identity facts per (hop, account, LSASS read) |
| `out/label/<t>/node_labels.csv` | `path_id, hop_id, role, context, event_uid, labelled, rule_ids, techniques, max_level_value` | labels on path nodes |
| `out/label/<t>/event_labels.csv` | `event_uid, count_key, rule_id, technique, tactics, level_value, event_utc_corrected, host` | per-match rows: `count_key` (LB-11) and the per-event facts B0 needs |
| `out/label/<t>/run_info.json` | `stitch_files_sha256` | freshness check (SC-02) |
| `src/score/order_table.json` (in git) | templates, technique → tactic | the own order reference (§5.1, decision record) |

## 3. Output contract
Location `out/score/<trial_id>/` (or `--out`). Files are byte-identical between runs except `run_info.json`
`generated_utc`. Scores are written with 12 decimals (review ATK-SC-24: the written value is the value ties are
decided on; first draft said 6); ties are decided on the value rounded to 12 decimals
(SC-40).

### 3.1 `ranked_paths.csv` — one row per (variant, path)
| Column | Type | Meaning |
|---|---|---|
| `trial_id` | str | |
| `variant` | str | `full`, `b1` or `b2` (§3.6) |
| `rank` | int | competition rank (1, 1, 3 …): tied paths share the best rank (SC-41) |
| `tie_size` | int | number of paths sharing this rank (1 = no tie) |
| `path_id` | str | from `paths.csv` |
| `score` | float | w1·LengthScore + w2·NodeScore + w3·IdentityCoherence (variant weights) |
| `length_score`, `edge_score`, `seq_len` | float, float, int | SC-20..23 |
| `node_score`, `n_node_units` | float, int | SC-30..33 |
| `node_score_ctx1` | float | NodeScore with labelled `context` = 1 nodes included; reported only, never in `score` (SC-30) |
| `identity_coherence`, `identity_low`, `identity_high` | float | SC-50..55; low/high decided per account (069 item 2): a hop is 1 in low if some account is exposed and not clock-flagged, 1 in high if some account is exposed or flagged |
| `n_crossings`, `n_crossings_coherent`, `n_crossings_flagged` | int | applicable hops (SC-52) |
| `n_hops_unknown` | int | path hops with no applicable account (every account `unknown:<reason>`; review ATK-SC-06) |
| `n_hops`, `hop_ids`, `hosts`, `isolated`, `merged_from`, `multi_chain_parent` | | copied from stitch |
| `technique_sequence` | str | `T1021.002>T1570>T1569.002` (SC-21) |
| `best_tier_min` | str | weakest T7 link tier over the path's hops (045: reported, not used in the score) |
| `clock_unreliable` | 0/1 | any hop or edge flag |

Example: `s04_t00,full,1,2,s04_t00-p0005,0.xxxxxx,…,T1021.002>T1570>T1569.002,…` (values after §5 is frozen).

### 3.2 `path_steps.csv` — one row per transition of a path's technique sequence (the "edges" of Eq. 5–7)
`path_id, step, from_technique, to_technique, from_tactic, to_tactic, tactic_score, technique_score, score_e, basis
(direct / indirect / same_tactic / absent), method (= technique_sequence), candidate_count (= 1), time_delta_ms (from
the first event of `from` to the first of `to`; empty within one hop, SC-21), from_event_uids, to_event_uids`.

### 3.3 `path_node_units.csv` — one row per NodeScore unit
`path_id, count_key, event_uids, hop_id, techniques, level_value` (SC-31).

### 3.4 `hop_identity_values.csv` — one row per (hop, account)
`hop_id, account, value (1 / 0 / empty), identity_status, applicable (0/1), not_applicable, method (= correction_k), candidate_count
(R1 reads counted after SC-51), deciding_dump_event_uids, open_session_uids, time_delta_ms (gap of the earliest
deciding read), order_within_uncertainty, session_open_before_window, hop_best_tier (the T7 tier, reported only),
clock_unreliable`.

### 3.5 `stats.json`, `report.md`, `run_info.json`
Stats: paths per variant, ties, paths with no labelled unit, identity value counts, host_time edge gaps (L-ST5
measurement), parameter values. `run_info.json` as in the stitch/label stages: tool version, parameters (λ, w, α, β, a,
b, ε, order-table SHA-256), input file SHA-256s, output file SHA-256s and rows.

### 3.6 Baselines (owner 2026-11-18) — same scoring and ranking code, a `variant` switch only
| Variant | Candidates | Score | Handoff §14.3 name |
|---|---|---|---|
| `full` | stitch paths | w1·L + w2·N + w3·I | Full |
| `b1` | stitch paths | (w1·L + w2·N) / (w1 + w2): linking without IdentityCoherence; renormalised so scores stay in [0, 1] and comparable across trials (S06 check) | B3 ("full with w₃ = 0") |
| `b2` | stitch paths | NodeScore only (w = 0, 1, 0): order-blind (owner Q12) | B2 ("order-blind scoring, NodeScore only, HADES-style") |
| `b0` | **no linking**: every labelled event unit (`count_key`) of the trial window, any host, any `context` (owner Q12) | NodeScore of the one unit (L and I are 0 by construction: no sequence, no hop) | B0 ("alerts only") |
| chance line | stitch paths | none: the expected value of a uniformly random order (computed by `evaluate --rank`, no rows here) | – |

`b0` rows go to `b0_ranked.csv` (`trial_id, variant, rank, tie_size, unit_id (= count_key), event_uids, host,
techniques, level_value, score`). Owner Q12: `b2` (= handoff B2) and the chance line are added; the handoff's B1
(linked paths in time order, no ranking) is **not built**, and the chance line takes its place as the "linked, not
ranked" reference (065). T9 runs all variants on
development trials only; T10 runs them on the test trials beside `full` with the frozen parameters. `ranked_paths.csv`
holds the `full`, `b1` and `b2` rows (`variant` column); `stats.json` reports paths per trial for the chance line.

## 4. Rules
| ID | Rule | Source |
|---|---|---|
| SC-01 | **Allowlist.** `--trial` must be in `DEVELOPMENT_TRIALS` (one shared list); anything else is refused before a file is opened. T10 widens it by its own record after the key lock. | 019, 046 |
| SC-02 | **Fresh inputs.** Refuse when `out/label/<t>/run_info.json` `stitch_files_sha256` differs from the current stitch files, or a required file or column is missing, or a path hop's `member_accounts` lacks a `hop_identity.csv` row (069 item 3; further checks 067 item 7). | 054 pattern; label run_info; 067, 069 |
| SC-03 | **No ground truth, no DB.** `src/score` never opens `ground_truth/` or `data/`. | 019; spec 07 |
| SC-04 | **Every path ranked.** Each `paths.csv` row appears exactly once per variant; nothing is dropped, merged or split here (merging is the stitcher's, ST-73). | Correction J, G.4 |
| SC-10 | **Order reference** = `src/score/order_table.json`: hand-built technique templates (TPPR's technique-PT replaced) and one tactic per technique (tactic-PT = templates mapped to tactics). Built from ATT&CK / CTI pages, never from lab logs; each template cites its source. Pinned by SHA-256 in code and in the decision record. | handoff §11.4 Option B, Correction G.5; PLAN 9.1 |
| SC-20 | **Technique set of a hop** = the distinct primary `techniques` of its labelled `context` = 0 nodes (secondary tags excluded, 056 Q3). T1003.001 never enters (dump only through identity, 056 item 7). | 056 items 7, Q3 |
| SC-21 | **Technique sequence of a path** (OPEN Q3, proposal S1): hops in chain order (`path_edges`, then `first_utc_corrected`, then `hop_id`); within a hop, its technique set sorted by the order table's stage (position in the reference), then technique ID; across the path keep the **first appearance** of each technique. Within-hop order does not use event times. | TPPR §3.3.1 (p. 5: techniques ordered "according to their order of appearance in the document"), Correction G.5 |
| SC-21b | **Hop boundary** (OPEN Q3b, review ATK-SC-05): the transition from the last technique of a hop to the first new technique of the next chained hop is scored as a direct step (`basis` = `hop_chain`), because the stitcher's chain edge (ST-72) already fixes that order; only within-hop transitions, and boundaries between sibling hops of a merged path that have no chain edge between them (069), are scored against the templates. A path's score must not change when its hop list is given in another order (test). | ST-72; review ATK-SC-05 |
| SC-22 | **Edge score** of a transition u → v (TPPR Eq. 5 with the ScoreNI term removed, OPEN Q5): ScoreE = α·TacticScore + β·TechniqueScore, α + β = 1. TacticScore = min(b, Σ_{p∈P(TA_u,TA_v)} (1/len p) / out(TA_u) · b), same tactic = b (Eq. 2); TechniqueScore = a·max(Π_direct, max_p 1/len p, ε) (Eq. 3). `basis` records which term decided. | TPPR Eq. 2, 3, 5 (p. 6) |
| SC-22a | **Tree reading (062).** Technique-PT = prefix tree of the templates (shared prefixes merge, TPPR §3.3.1, Fig. 5). Tactic-PT = prefix tree of the templates' tactic sequences (each template mapped technique → tactic **with consecutive repeated tactics filtered out**, as TPPR p. 5 does — fact-check 2026-11-18; shared prefixes merge). For u → v: P(·) = downward paths from **any** node labelled u (or TA_u) to a descendant labelled v (or TA_v); len(p) = edges; out(TA_u) = number of children summed over all nodes labelled TA_u. TacticScore = b if TA_u = TA_v, else min(b, b·Σ 1/len(p) / out(TA_u)), 0 if no path or out = 0. TechniqueScore = a·max(Π_direct, max over paths of len ≥ 2 of 1/len(p), ε), Π_direct = 1 iff some u-node has a v child. `basis` = `direct` (Π_direct = 1), else `same_tactic` (TA_u = TA_v), else `indirect` (a path exists), else `absent`; a technique not in any template gives `absent` (TacticScore from its tactic still applies). `hop_chain` steps score ScoreE = α·b + β·a. **Readings, stated:** Eq. 2 itself has no cap; "same tactic = b" and the min(b, …) cap follow TPPR's Fig. 6a text (p. 7, "receives the maximum score b"); "any u-node" and "indirect = len ≥ 2" are our reading of P(·). | TPPR §3.3.1 (p. 5), Eq. 2, 3 (p. 6), Fig. 5, 6a (p. 7) |
| SC-23 | **LengthScore** = (1 − e^(−len/λ)) · EdgeScore, len = number of transitions (`seq_len`), EdgeScore = mean ScoreE (Eq. 6). A path with fewer than two techniques has len 0, EdgeScore 0, LengthScore 0. **Substitution, stated:** TPPR's Eq. 6/7 run over the candidate path's provenance-graph edges; here the "edges" are transitions of the path's technique sequence (review ATK-SC-11). | TPPR Eq. 6, 7 (p. 7); Correction G.3 |
| SC-30 | **NodeScore scope** = labelled `context` = 0 nodes of the path (owner, 056 item 7). It is stated as a reading of *which nodes belong to the path* (their events are session context, ST-71); because its **effect** is to keep the dump (SR-01/02, level 3) out of NodeScore, the report also states it as a restriction and gives NodeScore with `context` = 1 included beside it (`node_score_ctx1`, reported only; review ATK-SC-03). | CLAUDE.md; 056 item 7 and consequence; Correction G.1 |
| SC-31 | **NodeScore unit** = one `count_key` (one action counted once, LB-11): the unit's level = highest `level_value` over its nodes and rules. NodeScore = mean unit level / 4. | Correction G.1; 058; review ATK-S10 |
| SC-32 | **No labelled unit** → NodeScore 0, `n_node_units` 0 (OPEN Q2). | spec 04 §9 |
| SC-33 | **Levels** as locked: informational 0, low 1, medium 2, high 3, critical 4; own rules low (056 item 5). Q13 asymmetry: OPEN Q1. | 056 |
| SC-50 | **Hop crossing value (Correction K).** For a hop and one member account: 1 iff some counted LSASS read (SC-51) on the source host has `order_ok` = 1 (move ≥ dump − 5 s, decision 014) **and** a non-empty `open_session_uids`; else 0. Uses only the moving account and the source host (013), so `target_only` hops get a value. | Correction K; 013; 014; ST-60..63 |
| SC-51 | **Counted reads** (OPEN Q7): proposal (b′): the `R1_lsass` rows minus reads whose source image is one of `wmiprvse.exe`, `MsMpEng.exe`, `csrss.exe`, `wininit.exe` **at its stated system folder** (case-insensitive: `C:\Windows\System32\wbem\wmiprvse.exe`, `C:\Windows\System32\csrss.exe`, `C:\Windows\System32\wininit.exe`, `C:\ProgramData\Microsoft\Windows Defender\Platform\<version>\MsMpEng.exe`, `C:\Program Files\Windows Defender\MsMpEng.exe` — all five forms occur on development data) **and** whose `dump_account` is `system`, `network service` or `local service`; a same-named binary elsewhere or under a user account still counts (review ATK-SC-04). `end_unknown` sessions are not counted as open (ST-63). | 056 item 8; spec 03 Q9 |
| SC-52 | **Applicable crossings.** A (hop, account) with `not_applicable` set (machine account, unknown source host, source host without logs) is not a crossing. A hop's value = max over its applicable accounts (OPEN Q8). The path's crossings = its hops with at least one applicable account. Because unknown hops leave the denominator, a path with one exposed hop and one unknown hop gets I = 1, not 0.5 ("scores 0" holds per hop only). Sessions with system logon IDs 0x3e4/0x3e5/0x3e7 and machine accounts are never open sessions (ST-63). | Correction K item 4 (machine accounts, system logon IDs); ST-60 and 049 (unknown / no-logs source host) |
| SC-53 | **IdentityCoherence** = coherent crossings / crossings. A path with no crossing → 0 (handoff §12.4 code), shown with `n_crossings` = 0 (OPEN Q9). Each (hop, account) row carries `identity_status` = `exposed` / `not_exposed` / `unknown:<reason>` (machine account, source host unknown, source host without logs, Security log cleared between a session's opening and the dump = `end_unknown`, ST-63; a session with no logoff event is open, handoff §12.4 l. 975) so "no evidence" is never read as "not exposed" in the report, although both score 0 (review ATK-SC-06). | handoff §12.4; review ATK-SC-06 |
| SC-54 | **Clock flag (044 (c)).** The value uses `order_ok` unchanged; `identity_low` / `identity_high` recompute the path value with clock-flagged reads (`order_within_uncertainty` = 1 on a deciding or a rejecting read) counted against and for exposure, **per account** (069 item 2: hop low = some account robustly exposed; hop high = some account exposed or flagged). | 044 (c); ST-62 |
| SC-55 | Correction K wording: "exposed", never "stolen"; the report says so. | CLAUDE.md wording |
| SC-40 | **Score** = w1·LengthScore + w2·NodeScore + w3·IdentityCoherence, w ≥ 0, Σw = 1, so every score is in [0, 1] and comparable across trials. | CLAUDE.md; handoff §12.3 |
| SC-41 | **Ranking.** Scores are summed with `math.fsum` over components in a fixed order and rounded to 12 decimals (review ATK-SC-13). Sort descending; equal scores share the best rank (competition ranking) and `tie_size`; listing order inside a tie is `path_id` for **display only** — no metric may use it (§7.3, review ATK-SC-01). No θ. | Correction J; 018, 021 |
| SC-42 | **Frozen parameters.** λ, w1–w3, α, β, a, b, ε and the order-table hash live in `src/score/params.py`, pinned by a test to the freeze record (§5.2). | owner 2026-11-18 |
| SC-60 | **CLI.** `python -m score --trial <t> | --development [--repo] [--out]`; refusals print `refused:` and exit 2; output folder written via the stitch `.tmp`/`.old` swap and `lab_common.outdir` guard. | 054 |
| SC-61 | Every row that links events carries `method`, `candidate_count`, `time_delta_ms`, supporting `event_uid`s, and the tier where one exists (`hop_best_tier`, reported only). `path_steps.csv` rows are **scoring steps, not links**: they pair the first events of two techniques already in one path to show the order score, measure nothing across hosts and carry no tier (045 scope, review FC-8). | CLAUDE.md code rules; 045 |

## 5. Parameters
| Name | Value | Why | Sensitivity test? |
|---|---|---|---|
| λ | **frozen (066)** 1/ln 2 ≈ 1.443 (one transition → length factor 0.5) | a-priori, not tuned (OPEN Q11) | yes, T10 around the frozen value |
| w1, w2, w3 | **frozen (066)** 1/3 each | a-priori equal weights (handoff §12.4 l.977: sweep for stability, not an optimum) | yes, simplex sweep |
| α, β | **frozen (066)** 0.5, 0.5 (ScoreNI weight 0) | OPEN Q5 | reported |
| a, b | 1, 1 | scale only; scores stay in [0, 1] | no |
| ε | 0.01 | "negligible probability for unobserved transitions" (TPPR p. 6) | reported |
| ORDER_TOL_S | 5 s (read from stitch facts, not re-applied) | 014 | no |

### 5.1 Order reference (proposal; citations verified by the researcher before owner review; decision record 062)
Technique → tactic: T1078 initial-access; T1003.001 credential-access; T1550.002 lateral-movement; T1021.001 /
T1021.002 / T1021.006 lateral-movement; T1570 lateral-movement; T1569.002 execution. Stage order for SC-21 = first
position in the templates below.

Citations per transition: [docs/research/score_order_templates.md](../research/score_order_templates.md)
(researcher, 2026-11-18; ATT&CK v19+ content, quotes via a summarising fetch, to be fact-checked).

| # | Template | Support |
|---|---|---|
| R1 | T1078 → T1003.001 → T1021.002 → T1569.002 | handoff §11.4 (SMB path). T1003.001→T1021.002→T1569.002: S0029, CISA AA25-071A, DFIR Report. T1078→T1003.001: campaign level only (weak) |
| R2 | T1078 → T1003.001 → T1021.001 | handoff §11.4 (RDP path) **shortened**: its tail T1021.001 → T1569.002 has no source (researcher); T1003.001→T1021.001 from the T1021.001 page |
| R3 | T1003.001 → T1021.002 → T1570 | handoff §11.4 (move + tool transfer); T1021.002, T1570, S0029 |
| R4 | T1003.001 → T1021.002 → T1570 → T1569.002 | S0029 PsExec; T1570 → T1569.002 from DFIR Report (Nitrogen, BlackSuit) |
| R5 | T1078 → T1003.001 → T1021.006 | weak: T1021.006 says only "use Valid Accounts"; Storm-0501 shows dump then Evil-WinRM without a stated order |

**T1550.002 (spec 04 Q10):** the first proposal R4 had T1003.001 → T1550.002 → T1021.002; no source joins
pass-the-hash to the SMB move, so T1550.002 is in **no template** and every transition to or from it gets TechniqueScore = ε while TacticScore still applies (e.g. T1550.002 → T1021.002, same tactic: ScoreE = 0.5·1 + 0.5·0.01 = 0.505; review FC-2) (OPEN
Q4). SR-61 matches nothing on development data. **T1078 tactic:** ATT&CK now lists Stealth (Defense Evasion was
split in v19), Persistence, Privilege Escalation, Initial Access; initial-access is kept for its first position in
the templates. **Order trap:** ATT&CK's matrix puts Execution before Lateral Movement, but R1/R4 need T1569.002 after
T1021.002 (PsExec behaviour, S0029), so the stage order of SC-21 comes from template positions, never from tactic
IDs.

**Disclosure:** the spec author saw the development technique sequences (§10.1) before proposing R4/R5. The
templates come from ATT&CK and CTI pages, two of them are weakly supported, and the test trials stay unseen; the
record states all three.

### 5.2 Choosing and freezing λ and w (PLAN 9.5; owner 2026-11-18)
1. The frozen values **are the a-priori values above** (review ATK-SC-12: a search against six keyed trials, one of
   which (S04) no weight can fix, would leak development knowledge).
2. On the **development trials only**, run `full` over a grid (w on the simplex in steps of 0.1; λ ∈ {0.5, 1,
   1/ln 2, 2, 3, 5}) and report the key attack path rank per keyed trial, the S06 check and the size of the region
   around the default where no development rank changes. The sweep is **for stability only**; it never moves the
   values. If a development key attack path is not at rank 1 (ties as in §7.3) under the defaults, it is reported, and
   only the owner may change a value, by its own record, before the freeze.
3. If S01 t01 (RDP, development) is ingested before the freeze, it is run through the whole chain and reported first
   (review ATK-SC-06: the RDP path is otherwise first seen on test data).
4. One decision record freezes λ, w1–w3, α, β, a, b, ε, the order-table SHA-256 **and the H1–H5 numbers and readings
   of §7.3**, **with the commit hash**, before T5.7 unlocks the test keys. No retuning on test data. T10 reports
   sensitivity around the frozen values only.

## 6. Edge cases (from attacker review)
Attacker review 2026-11-18 (ATK-SC-01..13, [review](../reviews/05_score-spec-2026-11-18.md)).
| Case | Where | Expected behaviour | Test ID |
|---|---|---|---|
| ATK-SC-01 Equal components, attack vs benign (s04 track A benign, B attack: same techniques, levels, both exposed) | s04_t00 p0004/p0005; s07 p0005/p0006; the 38 zero-score paths | tie, both rank 1, `tie_size` 2 (018, 021); metrics use the expected-value tie reading; swapping `path_id`s changes no metric | SCT-41, SCT-42 |
| ATK-SC-03 Dump kept out of NodeScore | s07 p0005/p0006 (SR-01 level 3 on `context` = 1) | `node_score_ctx1` reported beside `node_score`; score uses `context` = 0 (056) | SCT-34 |
| ATK-SC-04 Dumper renamed `MsMpEng.exe` outside the Defender folder, or run by a user | hypothetical | read counted (SC-51 b′) | SCT-56 |
| ATK-SC-05 Multi-hop path: execution → initial-access at the hop boundary would score ε | s05_t00-p0004 (h0010 background, h0030, h0032) | boundary step `hop_chain` (SC-21b) only across a real chain edge; sibling hops of a merged path (no chain edge) are scored against the templates (069, review ATK-SC-17); hop-list order does not change the score | SCT-21b |
| ATK-SC-05 Benign background hop dilutes identity in a merged path | s05_t00-p0004: h0010 value 0 → I = 2/3 | as specified (merge is the stitcher's); stated in the report | SCT-53 |
| ATK-SC-06 "No evidence" vs "not exposed" | machine-account hops; s07 ep-03 `source_host_no_logs`; RDP (S01, no dev trial) | both 0 in the score; `identity_status` = `unknown:<reason>` | SCT-57 |
| ATK-SC-07 Move hours after a dump with a session still open | hypothetical (s04 gaps 38 s / 41 s) | value 1 (Correction K sets no upper bound); `time_delta_ms` reported; limitation L-SC6 | SCT-58 |
| ATK-SC-08 Hop with an exposed benign account and an unexposed attacker account | s06_t00-h0037, s06_t01-h0026 (both 0 on dev) | max over accounts → 1; per-account rows written (Q8) | SCT-52 |
| ATK-SC-09 No labelled technique but exposed | hypothetical | L = 0, N = 0, I = 1 → w3; reported margin to the nearest benign path | SCT-32 |
| ATK-SC-10 Adding a template changes out() and every TacticScore | order table | table pinned by SHA-256 in the freeze record | SCT-42 |
| ATK-SC-13 Float ties at the rounding boundary; source clock 6 s skew on a quick attack | hypothetical | `fsum` + 12-decimal rounding; flagged crossing gives `identity_low` ≠ `identity_high` | SCT-41, SCT-55 |

## 7. Acceptance tests
### 7.1 Development (s02–s07 t00 keyed; s02_t01, s03_t01, s06_t01 unkeyed)
- **SCA-01** every `paths.csv` row is ranked exactly once per variant; `b0_ranked.csv` has one row per labelled unit.
- **SCA-02** on the 15 keyed hops, the hop value (SC-50..52) equals the key's `identity_expected` (PLAN done-when).
- **SCA-03** two runs byte-identical (except `generated_utc`); input SHA-256s unchanged.
- **SCA-04** every `score`, `length_score`, `node_score`, `identity_coherence` recomputed from the CSVs by an
  independent test helper equals the written value.
- **SCA-05** test trials refused; `src/score` contains no `ground_truth` path and opens no DB (static + runtime check).
- **SCA-06** development ranking report (`python -m evaluate --rank`): key attack path rank (optimistic and
  pessimistic under ties), score gap, S06 check, for `full`, `b1`, `b0`. **Development numbers, not results**; no
  pass/fail except SCA-02.

### 7.2 Unit tests (synthetic)
SCT-20..23 Eq. 2, 3, 5–7 on hand-computed trees and sequences (direct, indirect, same tactic, absent, len 0/1);
SCT-30..33 NodeScore units, `count_key`, empty path; SCT-40..42 score, ties, frozen-parameter pin; SCT-50..55
identity (order margin, open session, end_unknown, excluded images, not_applicable, multi-account, clock flag low/high);
SCT-60 CLI refusals and `--out` guard.

### 7.3 Success criteria for T10 — written before any test trial is scored (owner 2026-11-18)
Hypotheses, **expected, to be measured**; T10 reports each as held / not held, with the frozen parameters. Attack test
trials = S01–S05, S07 t02–t10 (k per handoff §14.2: 1, S07 2). A key attack path "matches" a candidate at node
Jaccard ≥ 0.5 (handoff §14.2).

**Tie reading (review ATK-SC-01).** Primary: **expected value under a random order inside each tie group** — a match
in a tie group of size t starting at rank r has expected rank r + (t − 1)/2 (owner 2026-11-18: s04 A/B, a 2-way tie at
the top, counts as rank 1.5, reciprocal rank 1/1.5), top-1 credit 1/t when r = 1, and top-k
credit = the expected share of the group inside the first k places. Optimistic (r) and pessimistic (r + t − 1)
readings are reported as sensitivity. `path_id` order is never used.

**Chance line (review ATK-SC-02).** For every hypothesis T10 also reports the number of candidate paths per trial and
the value a uniformly random order would get (expected top-1 = 1/n), so a held hypothesis can be read against chance.

| ID | Hypothesis (proposed numbers, OPEN Q13) |
|---|---|
| H1 | `full`: top-1 rate (primary tie reading) ≥ 0.80 over attack test trials. |
| H2 | `full`: MRR ≥ 0.85 over attack test trials (replaces "top k + 2", which is vacuous in trials with ≤ 3 paths). |
| H3 | **IdentityCoherence adds ranking value** (identity term ablation, owner 2026-11-18: strict): MRR(`full`) **>** MRR(`b1`) over attack test trials. Top-1 rates and the difference are reported beside it. Equal MRR means H3 is not held; that is a valid, reportable result (Correction K item 1). |
| H4 | `full` vs `b0`, **equal node budgets** (review ATK-SC-02): `b0` takes its highest-ranked units until it holds as many event nodes as `full`'s top-k paths; node recall against the key attack nodes is higher for `full`. |
| H5 | S06 check, per trial: in each S06 test trial the highest benign path score under `full` is below the **lowest** key attack path score of the S01–S05, S07 test trials (primary); the share of attack trials whose key attack path scores above it is reported (handoff §14.2 "distribution"). |

**Stated limits of H1–H3 (review ATK-SC-02, L-SC5).** Inside one protocol, attack and benign paths have equal
LengthScore and NodeScore (L-SC1), so their order comes from IdentityCoherence, whose definition the answer keys
share (Correction K). H1 then measures the ranking given exposure, not an independent check of identity. Test
trials repeat the development scenarios, so the hypotheses measure repeatability, not generalisation to new attacks.
No hypothesis is worded as "reduces false positives", "detects stolen accounts" or "identifies the attacker".

## 8. OPEN questions
| # | Question | Options / proposal | Needs council? |
|---|---|---|---|
| Q1 | (= spec 04 Q13) Level asymmetry: on `context` = 0 units SMB attack paths average 1.00, WinRM paths 1.92–2.43, attack or benign (§10.2) | (a) accept and state it: NodeScore is protocol-sensitive; separating attack from benign inside one protocol is identity's job (Correction K) — **proposal**; (b) own rules medium: SMB rises to 1.50–1.75, still below WinRM 2.00–2.43; (c) one unit per technique per hop: SMB 1.00, WinRM 2.00–2.50, no change in order. No option removes the asymmetry (§10.2 table) | no |
| Q2 | NodeScore of a path with no labelled unit | (a) 0 — **proposal**; (b) undefined and the term dropped for that path (weights renormalised) — makes unlabelled paths incomparable | no |
| Q3 | Technique sequence | **S1** (SC-21: within a hop by order-table stage, across hops by chain order; first appearance) — **proposal**; S2: strict event-time order of every unit. Measured (§10.1): within a WinRM hop the 4648 (T1078) and `wsmprovhost` (T1021.006) alternate (s03_t01: 6 alternations), so S2 scores sub-second event order and repeats | no (cheap to change) |
| Q4 | Order reference | Option B templates R1–R5 (§5.1, R2 shortened, T1550.002 in no template) — **proposal**, cited by the researcher; R1's first link and R5 are weakly supported (keep, stated) or drop R5 (then every WinRM transition T1078 → T1021.006 is absent = ε). Option A (CTI-mined) is out of time | no |
| Q3b | Hop boundary in a multi-hop path | `hop_chain` = direct (SC-21b) — **proposal**; or score it against the templates (s05 execution → initial-access = ε, penalising the only multi-hop key path, ATK-SC-05) | no |
| Q5 | TPPR Eq. 5 ScoreNI term | (a) drop it (α + β = 1) — **proposal**, stated as a substitution: on a technique chain Eq. 4 gives 0 for a one-edge path, 1 at the ends and 2 inside, so it encodes only position and length, which LengthScore already carries (corrected after ATK-SC-11); (b) degrees from the stitch hop graph (multi-hop paths only: 1 of 53) | no |
| Q6 | `len(CP)` | transitions of the technique sequence (SC-23) — **proposal**; or number of hops (52 of 53 paths have 1 hop, so the length factor would be a constant) | no |
| Q7 | (= spec 03 Q9) Which R1 reads count; `end_unknown` | (a) all R1 rows; (b) R1 minus the four OS/AV images — **proposal**: Correction K speaks of a credential-access event, these images read LSASS routinely (in-path hops: 18 rundll32 vs 42 OS/AV distinct read events, §10.3); limitation: a dump run inside one of these images is not counted. Development values are identical under (a) and (b), with or without `end_unknown` (§10.3). `end_unknown` not counted (ST-63) | no |
| Q8 | Hop with several user accounts | max over accounts (the hop is the unit of "fraction of hops", CLAUDE.md) — **proposal**; or each (hop, account) a crossing. Development: 2 hops, both 0 either way | no |
| Q9 | Path with no crossing | 0 (handoff §12.4) — **proposal**; or excluded from the identity term | no |
| Q10 | Clock-flagged crossings | value from `order_ok`, plus `identity_low`/`identity_high` (SC-54) — **proposal**; development has 0 flagged crossings (049 §10.6) | no |
| Q11 | λ and w | freeze the a-priori defaults; development sweep for stability only (§5.2, changed after ATK-SC-12) — **proposal**; or the nearest grid point that fixes a development miss (leaks development knowledge) | no |
| Q12 | Baseline candidate unit and the ladder | B0 = one candidate per labelled unit, any host and `context` — **proposal**; or one per host. Handoff's B1 (time order) and B2 (NodeScore only) not built (owner named B0, B1); options: add `b2` (w = 0, 1, 0) and a random-order line at no cost (ATK-SC-02 also suggests a gate-only line) | no |
| Q13 | Success criteria | tie reading (expected value; optimistic / pessimistic as sensitivity), H1–H5 numbers and the chance line (§7.3) — owner sets them now; frozen with λ/w in one record with the commit hash | no |
| Q14 | NodeScore protocol asymmetry and the dump (ATK-SC-03): the attacker estimates an exposed benign WinRM path and an SMB attack path both near 0.62 under the defaults, inside the noise of α and the templates | (a) keep 056 item 7 (`context` = 0 only), report `node_score_ctx1` and the margin — **proposal**; (b) reopen 056 item 7 by council (count `context` = 1 labels) | only for (b) |

**Owner answers 2026-11-18:** every proposal above accepted (Q12: `b2` and the chance line added; Q14 (a), no
council), with two changes: Q4 — R5 and R1's first step named as weakly supported in L-SC7; Q13 — numbers accepted,
H3 strict (MRR(`full`) > MRR(`b1`)), ties by expected rank (2-way tie at the top = rank 1.5). Records:
[062](../decisions/062-score-order-reference-and-sequence.md) (Q3–Q6), [063](../decisions/063-score-nodescore-readings.md)
(Q1, Q2, Q14), [064](../decisions/064-score-identity-readings.md) (Q7–Q10), [065](../decisions/065-score-baselines-and-success-criteria.md)
(Q12, Q13), [066](../decisions/066-score-parameter-freeze.md) (Q11).

**Council:** none proposed. Every choice above is local to `src/score`, recomputed in seconds and does not change a
locked decision. Q7 (b) narrows Correction K's "credential-access event" by image and Q5 removes one TPPR term; both
are recorded as stated substitutions.

## 9. Out of scope
Linking, merging, labelling (T7, T8). Metrics on test trials, ROC-AUC, processing time (T10). Weight choice on test
data. A UI threshold. Any claim that a score is a probability.

### 9.1 Limitations stated by this spec
- L-SC1 Within one protocol, attack and benign hops carry the same `context` = 0 techniques and levels (§10.2), so
  LengthScore and NodeScore cannot order them; only IdentityCoherence can, and it measures exposure, not theft.
- L-SC2 The order reference is hand-built (Option B), not mined; its templates encode what ATT&CK pages describe.
- L-SC3 On single-hop paths (52 of 53 development paths) the "order" signal reduces to which techniques co-occur in
  the hop (SC-21 S1); true order exists only between hops.
- L-SC4 IdentityCoherence inherits the stitcher's limits L-ST5..L-ST9 and Correction K's "exposed ≠ stolen".
- L-SC5 The answer keys use Correction K's definition, so identity agreement with the keys (SCA-02) checks the code,
  not the definition (ATK-SC-02).
- L-SC6 Correction K sets no upper bound on the dump-to-move gap: a session that stays open makes any later move by
  that account count as exposed (ATK-SC-07).
- L-SC7 **Weakly supported templates (owner Q4):** R5 (T1078 → T1003.001 → T1021.006) and the first step
  T1078 → T1003.001 shared by R1, R2 and R5 are supported only at campaign level, not as a stated sequence
  ([research](../research/score_order_templates.md)). R4 and R5 were written after the development sequences were
  seen (ATK-SC-10).

## 10. Measurements (development trials only, read-only, 2026-11-18)
Scripts: scratchpad `measure_paths.py`, `measure_identity.py` (to be committed under `tools/score_measure/` in 9.2).

### 10.1 Paths and technique sets (`context` = 0, `count_key` units)
- 53 paths in 9 trials; 52 single-hop, 1 three-hop (s05_t00-p0004); **38 paths have no labelled unit** (machine-account
  and background SMB hops).
- SMB-with-service hops (s02 attack has no service: T1021.002, T1570): {T1021.002, T1570, T1569.002}, 4 units, mean
  level 1.00 — s04 A (benign) and B (attack), s07 x and y, s02_t01.
- WinRM hops: {T1078, T1021.006}, 6–10 units, mean 2.00–2.43 (s03 attack 2.25; s06 benign 2.33 / 2.00; t01 2.33,
  2.43, 2.40). Event-time order alternates T1021.006 / T1078 (s03_t01: 6 alternations).
- s06 SMB benign: {T1021.002, T1569.002}, 2 units, 1.00.
- s05_t00-p0004: hops s05-t1 (background, no label), s05-h1 (SMB), s05-h2 (WinRM), 13 units, 1.92.

### 10.2 NodeScore inputs per key hop (Q1)
SMB attack 1.00 (s02, s04-B, s07-x, s07-y); SMB benign 1.00 (s04-A, s06-smb-1); WinRM attack 2.25 (s03), WinRM benign
2.33 / 2.00 (s06). `count_key` changes one value (s05 path 1.86 → 1.92). Q1 options (data-checker, mean unit level):

| Key hop | Protocol | Role | current | (b) own rules medium | (c) one unit per technique per hop |
|---|---|---|---|---|---|
| s02-h1 | smb | attack | 1.00 | 1.667 | 1.00 |
| s03-h1 | winrm | attack | 2.25 | 2.25 | 2.50 |
| s04-A-h1 | smb_service | benign | 1.00 | 1.75 | 1.00 |
| s04-B-h1 | smb_service | attack | 1.00 | 1.75 | 1.00 |
| s05-h1 | smb_service | attack | 1.00 | 1.75 | 1.00 |
| s05-h2 | winrm | attack | 2.333 | 2.333 | 2.50 |
| s06-winrm-1 | winrm | benign | 2.333 | 2.333 | 2.50 |
| s06-winrm-2 | winrm | benign | 2.00 | 2.00 | 2.00 |
| s06-smb-1 | smb_service | benign | 1.00 | 1.50 | 1.00 |
| s07-h-x / s07-h-y | smb_service | attack | 1.00 | 1.75 | 1.00 |

Whole path s05_t00-p0004: 1.923 / 2.154 / 1.60. Unkeyed t01: s02_t01-p0006 1.00 / 1.75 / 1.00; s03_t01-p0004,
s06_t01-p0003, s06_t01-p0005 2.33–2.43 / same / 2.50; s06_t01-p0006 1.00 / 1.50 / 1.00.

### 10.3 Identity facts on path hops
- 61 (hop, account) pairs in paths: 12 value 1, 15 value 0, 33 machine account, 1 source host without logs
  (data-checker 2026-11-18; first draft said 63).
- The four variants {all R1, R1 minus OS/AV images} × {`end_unknown` counted, not} give identical values on all 61.
- LSASS reads by image, `hop_identity` rows with a dump over **all** hops (457 rows; fact-check corrected the
  data-checker's 674): rundll32 126, wmiprvse 109, MsMpEng 104, wininit 59, csrss 59. On **in-path** hops (143 rows,
  109 of them with a dump): rundll32 36, wmiprvse 13, MsMpEng 14, wininit 23,
  csrss 23; as distinct dump events: rundll32 18, wmiprvse 12, MsMpEng 12, wininit 9, csrss 9.
- Hop value (max over applicable accounts) equals `identity_expected` on 15 of 15 keyed hops (data-checker). s04-A
  (benign) and s04-B (attack) are both 1: exposed, not separated.
- Hops with two user accounts: 2 (s06). Rows with `session_open_before_window`: 8; `clock_unreliable`: 4;
  `order_within_uncertainty`/`within_tolerance`: 0.
