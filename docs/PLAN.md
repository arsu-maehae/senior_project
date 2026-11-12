# Build plan

Status marks: `[ ]` todo · `[~]` in progress · `[x]` done. The coordinator (`/next`) updates this file.
Critical path: T1 → T3 → T4 → T6 → **T7** → T9 → T10. T2, T5, T8 run alongside. T6b (clock offset correction) runs alongside T6 and must be done before any trial collected on or after 2026-10-26 is gated and before T7.6 on t01.

Data split (decision 019): **development** = t00 (dry run) for S02–S07 + t01 for all 7 scenarios once ingested (S01 t00 is excluded: target side only — source EP-01 and DC01 files are S02 exports filed under S01) · **test** = t02–t10 for all 7 scenarios (locked answer keys).
Never tune code or weights on the test set.

## T0. Setup — depends on: nothing  (DONE 2026-11-09)
- [x] 0.1 Repo layout (src/, tests/unit, tests/sample, docs/, data/, out/, ground_truth/drafts, ground_truth/approved)
- [x] 0.2 Kit installed; `/agents` shows 6 agents; skills listed
- [x] 0.3 Python venv works; existing parser tests run
- [x] 0.4 Papers in docs/papers/
**Done when:** a first `/next` run produces a plan for T1.

## T1. Standardise the data — depends on: T0  (DONE 2026-11-09; 1.5 stays open for the real trials)
- [x] 1.1 Layout `data/raw/<scenario>/<trial>/<host>/<channel>.evtx`
- [x] 1.2 Mapping CSV for the dry runs (old path → new path)
- [x] 1.3 Resolve: S01 EP-02 exported twice, the `.evt` file in S06, non-log files
- [x] 1.4 Copy script using the mapping (never move originals)
- [ ] 1.5 Same for the ×10 trials as they arrive (`/ingest-trial`) — scripts ready, no trials yet
- [x] 1.6 `data/manifest.csv` (path, hash, size, scenario, trial, host, channel)
- [x] 1.7 `docs/data_inventory.md`: expected vs present hosts/channels per scenario
**Done when:** every gap in the inventory is fixed or explained. (S01 t00 gap explained, decision 001; S06 expectations settled in T5.)

## T2. Collect S01 ×10 — owner: user (manual RDP)
- [ ] 2.1 Checklist for one trial (revert → run → export)
- [ ] 2.2 Ten trials collected → `/ingest-trial`

## T3. Normaliser fixes — depends on: T1 — spec: docs/specs/01_normalise_fixes.md  (DONE 2026-11-10)
- [x] 3.1 trial_id; no hard-coded counts/paths (NF-01, NF-02)
- [x] 3.2 IpPort → source_port (NF-03)
- [x] 3.3 account_name; Sysmon 10 SourceUser (NF-04, NF-05)
- [x] 3.4 No Execution ProcessID fallback for Security/System/WinRM (NF-06)
- [x] 3.5 Views events_display (hex) and events_dedup (NF-07, NF-08)
- [x] 3.6 One DB per trial, relevant events + logoffs, raw pointer (NF-09)
- [x] 3.7 Host names one style (NF-10)
- [x] 3.8 Unit tests with one real example per event type
- [x] 3.9 Import all available trials; counts match manifests
**Done when:** tests pass and counts match.

## T4. Data reality check — depends on: T3  (DONE 2026-11-10)
- [x] 4.1 `/log-check` on the development trial of every scenario
- [x] 4.2 `docs/research/data_reality.md`: per scenario, which linking evidence exists
- [x] 4.3 Decision records for problems that affect linking or identity
**Done when:** the linking design can be based on measured evidence.

## T5. Answer keys — depends on: T1 (alongside T3–T7)
- [x] 5.1 YAML format (steps → event ids, paths, benign paths, expected identity per hop)
- [x] 5.2 Draft helper from the agent process tree (splunkd.exe) + handoff intended steps + target-side events (decision 020; Caldera logs lost)
- [x] 5.3 Development key drafts → user approves → ground_truth/approved/  (S02–S07 t00 approved by the owner, commit 94b19b5; t01 keys follow when t01 is ingested)
- [x] 5.4 (records 021–025, owner approved the keys) Settle S04-A identity, S05 hop 2, S07 accounts, S06 benign paths
- [x] 5.5 Every listed event exists in the logs  (verify ok on the six approved keys, 0 failures)
- [ ] 5.6 Test key drafts → user approves
- [ ] 5.7 Lock test keys: git tag `answer-keys-locked` (before T10). Gate (AK-21): every hop in an approved key is `confirmed` or explicitly excluded by the owner; no `unconfirmed` hop may remain; every hop has `role` (attack | benign | background)

## T6. Gate — depends on: T4 — spec: docs/specs/02_gate.md (create with /stage-spec)
- [x] 6.1 Spec from handoff §7.2 — docs/specs/02_gate.md approved by the owner 2026-11-11 (decisions 037–039)
- [x] 6.2 Implement as specified; trigger list + stats per trial (done 2026-11-12, t00 s02–s07; out/gate/<trial>/)
- [x] 6.3 Tests + stage review (done 2026-11-12: GTT-01..18, GTA-01..04 and GTA-06 pass on t00, GTA-05 skipped; review docs/reviews/02_gate-2026-11-12.md, no blocking items)
- [x] 6.4 *(done for t00 only, 2026-11-12; other trials wait for the decision 032 clock correction)* Trial window clip (decision 026, owner 2026-11-10; window source amended by decision 039, owner 2026-11-11): the pipeline clips each trial DB to that trial's window BEFORE gating and linking, so earlier trials' events and paths are never scored (the 07:05:15 admin_it logon appears in the s05, s06 and s07 DBs; files start 2026-09-17). The window is computed from the agent process tree into `data/trial_windows.csv` by `src/trial_window` (decision 040; S01: operator-recorded start/end); the pipeline never reads `ground_truth/`. On the six t00 trials its start must equal the start of the key's `agent.run_interval`, and every key-hop event must lie inside it (GTA-06, decision 040). Until the decision 032 clock correction exists, only t00 trials are gated. Acceptance test: an event outside the window never reaches the gate or the stitcher (tests in 02_gate.md; repeated for the stitcher in 7.7)
- [ ] 6.5 R5 (RDP) real-data test on the S01 ×10 trials once ingested. Until then R5 is proven on synthetic data only (GTT-05/10/16): the t00 trials contain no port 3389 events and S01 t00 is excluded (decision 019). Review docs/reviews/02_gate-2026-11-12.md
**Done when:** every movement in the development answer keys produces a trigger.

## T6b. Clock offset correction — depends on: T4 (alongside T6) — spec: docs/specs/08_clock_offset.md — decision 032
- [x] 6b.1 *(step 1 = method approved by the owner 2026-11-12, decision 043 accepted for step 1; step 2 open, see 6b.4)* Spec docs/specs/08_clock_offset.md: per-host, per-trial offset vs dc01 = median of 1:1 mutual-nearest endpoint 4624 ↔ dc01 4769 LogonGuid pairs; method decided on development data only (t00, valid t01; s04_t01/s07_t01 as clock-only evidence), never on test trials
- [ ] 6b.2 Implement as a separate step: offsets stored per trial next to the DB and reported with every result; original times kept; a host with no usable pairs gets no correction and the trial is flagged; also: 02_gate / trial_window switch to corrected times (spec 08 §4.1; refusal per CO-17); spec 01 amendment so new ingests keep Security 4616 and System 1 (CO-18, no re-ingest of existing trials); read-only clock-change scan of existing trials' decoded exports (CO-19); rerun clock-reading ingest and w32tm parser (CO-12)
- [ ] 6b.3 Tests + stage review (includes the decision 032 kill criterion: corrected host pairs within 5 s)
- [ ] 6b.4 Step 2 (after the x10_v2 ingest): confirm MIN_PAIRS, MAX_LOO_SHIFT_S, READING_AGREE_S and the late_gap_s limit on the rerun t01 trials (not synced) and their start/end w32tm readings (spec 08 CO-11b, CO-12); t02–t10 readings are reported, never used to tune
**Must be done before:** gating any trial collected on or after 2026-10-26 (spec 02_gate §2.2), and T7.6 link accuracy on t01.

## T7. Cross-host linking — depends on: T6 — CRITICAL — spec: docs/specs/03_stitch.md
- [ ] 7.1 Spec; council on the NTLM linking approach and the time window. Input notes the spec must handle: docs/specs/03_stitch_input_notes.md (IN-01 several 4624s per hop, IN-02 file copy under an earlier session; F2, F3 of review 02_gate-2026-11-12)
- [ ] 7.2 Sessions per host (Logon ID); process trees (ProcessGuid)
- [ ] 7.3 Cross-host links per protocol (Correction I); Kerberos confirmation
- [ ] 7.4 Every link records method, candidate count, time gap, confidence
- [ ] 7.5 Candidate paths from triggers; merge on shared nodes; never drop isolated paths
- [ ] 7.6 Link accuracy vs development keys (on t01: after T6b)
- [ ] 7.7 Tests + stage review (includes: an event outside the trial's window never reaches the stitcher as an anchor, trigger or path node; exception, decision 039: a source-host session open logged before the window may be looked up for the identity check only)
**Done when:** the attack path is among the candidates in every development trial.

## T8. Sigma labelling — depends on: T4 (alongside T7) — spec: docs/specs/04_label.md
- [ ] 8.1 In-scope techniques; 1–3 rules each (rule, source, level); lock the list
- [ ] 8.2 Run rules; join matches to events/nodes
- [ ] 8.3 Labelling recall vs development keys
- [ ] 8.4 Tests + stage review

## T9. Scoring and identity — depends on: T7, T8 — spec: docs/specs/05_score.md
- [ ] 9.1 Own tactic-order table (decision record: substitute for TPPR's tree)
- [ ] 9.2 Edge order score, LengthScore, NodeScore
- [ ] 9.3 IdentityCoherence (Correction K)
- [ ] 9.4 Path score + ranking (no θ); ranked list per trial
- [ ] 9.5 Weights and λ chosen on the development set only (decision record)
- [ ] 9.6 Tests + stage review
**Done when:** ranked output on every development trial; identity values match the keys.

## T10. Evaluation — depends on: T9, T5.7 — spec: docs/specs/06_evaluate.md
- [ ] 10.1 Baselines B0–B3 + Full
- [ ] 10.2 Metrics per handoff §14.2 + processing time
- [ ] 10.3 Dry run of the evaluation on the development set
- [ ] 10.4 `/eval-run` on the test set, once
- [ ] 10.5 Weight sensitivity; results tables; fact-checked summary
- [ ] 10.6 Ablation independent of the key's evidence: run the stitcher with the command-line source-session method disabled (ports and 4648 only) and score it against the same keys, so at least one result does not rest on the evidence the key uses (decision 020, spec 07 limits)

## T11. Output, demo, report — depends on: T10
- [ ] 11.1 HTML/CSV report per trial (ranked paths, identity per hop, evidence)
- [ ] 11.2 Demo script (S04 or S05)
- [ ] 11.3 (If time) web UI · 11.4 (If time) path severity column
- [ ] 11.5 Report chapters from specs, decisions, results; limitations; future work
- [ ] 11.6 `/explain-module` for every stage before the final defense
