# Build plan

Status marks: `[ ]` todo · `[~]` in progress · `[x]` done. The coordinator (`/next`) updates this file.
Critical path: T1 → T3 → T4 → T6 → **T7** → T9 → T10. T2, T5, T8 run alongside.

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
- [ ] 5.3 Development key drafts → user approves → ground_truth/approved/  (drafts built for S02–S07 t00; waiting for approval)
- [ ] 5.4 (records 021–025 proposed, waiting for approval) Settle S04-A identity, S05 hop 2, S07 accounts, S06 benign paths
- [ ] 5.5 Every listed event exists in the logs  (verify ok on 6 drafts; waiting for approval)
- [ ] 5.6 Test key drafts → user approves
- [ ] 5.7 Lock test keys: git tag `answer-keys-locked` (before T10). Gate (AK-21): every hop in an approved key is `confirmed` or explicitly excluded by the owner; no `unconfirmed` hop may remain; every hop has `role` (attack | benign | background)

## T6. Gate — depends on: T4 — spec: docs/specs/02_gate.md (create with /stage-spec)
- [ ] 6.1 Spec from handoff §7.2
- [ ] 6.2 Implement as specified; trigger list + stats per trial
- [ ] 6.3 Tests + stage review
**Done when:** every movement in the development answer keys produces a trigger.

## T7. Cross-host linking — depends on: T6 — CRITICAL — spec: docs/specs/03_stitch.md
- [ ] 7.1 Spec; council on the NTLM linking approach and the time window
- [ ] 7.2 Sessions per host (Logon ID); process trees (ProcessGuid)
- [ ] 7.3 Cross-host links per protocol (Correction I); Kerberos confirmation
- [ ] 7.4 Every link records method, candidate count, time gap, confidence
- [ ] 7.5 Candidate paths from triggers; merge on shared nodes; never drop isolated paths
- [ ] 7.6 Link accuracy vs development keys
- [ ] 7.7 Tests + stage review
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
