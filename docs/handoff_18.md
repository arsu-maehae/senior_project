# Handoff — Identity-Aware Cross-Host Attack Path Reconstruction (Complete) — handoff_18

> **Purpose:** a complete, self-contained handoff so a fresh conversation (or new collaborator) can understand the entire project with zero prior context — the goal, the two base papers, the full pipeline, the scoring math, the honest strengths/risks, the corrections made along the way, and what's left to decide.

> **📝 REVISION NOTE (handoff_18 — PROPOSAL DEFENSE DONE, 2026-11-03).** The Project 1 proposal defense was held on **Mon 2 Nov 2026** and passed ("pretty rough but overall OK"). **Nothing deleted — superseded text is marked ⛔ in place; the new material is §24.** What moved:
> 1. **NEW §24** — the committee's 11 questions with the prepared answers, the advisor's feedback, the design changes adopted, new limitations and future work, and next actions (supersedes §23.8).
> 2. **Design change (§24.3 D1):** normalisation keeps the **original hex Logon ID** alongside the integer — integer for joins, hex for display. §9.1 and §23.5 references to "hex → int" are read through this.
> 3. **Wording change (§24.3 D2):** every claim that the system "reduces false positives" / "shows fewer false paths" is a **hypothesis to be measured** (B1 vs Full), never a result. Applies to slides, report and future-work text.
> 4. **Advisor feedback (§24.2):** project approved to continue on the current plan; **path severity** (impact label, separate from the ranking score) added as a **stretch item** only if time is spare.
> 5. **Limitations and future work extended (§24.4–§24.5):** wide time windows and multi-hop depth; protections disabled on the foothold; database servers (DB audit logs, MSSQLSvc Kerberos) and path severity.
> 6. **Status line** updated (defense passed; build phase begins).
> Unchanged and still correct: Corrections A, D–L; §19–§23 (except §23.8, superseded by §24.6).
>
> **📝 REVISION NOTE (handoff_17 — DECISIONS LOCKED for the defense, 2026-10-30).** The file circulated as `handoff_16` still carried handoff_15 content (no handoff_16 changes existed); this revision brings it in line with the final 91-slide deck and the 3-speaker defense script. **Nothing deleted — superseded text is marked ⛔ in place; new decisions are Corrections J–L (§0) and the new §23.** What moved:
> 1. **Correction J (NEW, supersedes Correction C and every "retain if score > θ" line):** the system **ranks** candidate paths by path score, highest first, with **no retention threshold θ**. Evaluation uses **threshold-free** metrics (top-1 rate, MRR, node P/R/F1 on the top-k paths with k = number of answer-key attack paths, score gap, optional pooled ROC-AUC). θ survives only as an optional display filter in the UI. §12.3, §12.4, §12.7, §12.8, §14.2–§14.6, §17 and §21.8 are marked ⛔ and corrected in place.
> 2. **Correction K (NEW, closes §16 item 0 and Correction H.2):** the identity term is **kept** as the one ★ proposed term, tested by w₃ on/off, and the thesis does not rest on it. **Exposed set = every account with a logon session open on the source host at dump time t1** (the slide definition). The §12.4 code (which returned the account that *ran* the dump) is ⛔ and replaced.
> 3. **Correction L (NEW, presentation framing):** the deck presents **linking (HADES-style) + ordering (TPPR-style) + one proposed identity term**. The "HADES's trigger never fires on stolen valid passwords" argument (Correction F ★1) is **kept for Q&A only** — it was removed from the slides. Correction F stays correct as the thesis-level contribution ranking.
> 4. **Evaluation baselines locked** as a ladder: alerts only → linked, no ranking → order-blind scoring → full with w₃ = 0 → full (§14.3).
> 5. **Status line** corrected (parser finished; S01 ×10 is the only remaining collection; build not started).
> 6. **NEW §23** — final deck and script state, known slide errors and how the script steers around them, wording rules, ITDR positioning, JSONL rationale, future-work framing, Kerberos/NTLM note, progress estimate, and next actions (supersedes §22.7).
> Unchanged and still correct: Corrections A, D, E, G, H (except H.2, now decided), I; the lab, Option D, E1–E10, the collected data, the gate rule table (§7.2), session stitching (§9 as corrected by I), §19–§21 execution records, §22.2–§22.6.
>
> **📝 REVISION NOTE (handoff_15 — FRAMING CORRECTED after reading HADES and TPPR in full, 2026-10-29).** Both base papers were read end to end (HADES arXiv:2407.18858v1; TPPR arXiv:2510.22191v1). Several load-bearing claims in this handoff turned out to be **contradicted by the papers themselves**. **Nothing deleted — superseded text is marked ⛔ in place, and the new, paper-verified position is in Corrections E–H (§0) and the new §22.** What moved:
> 1. **Correction E (NEW, supersedes Correction B):** HADES **already separates** an attacker from a legitimate user of the *same stolen credentials* — by logon-session causality. The paper uses this exact example (Alice's stolen credentials, both Alice and the attacker reaching the Exchange Server from Workstation 1). "HADES stitches compromised and legitimate reuse identically" is **false** and must not be said again.
> 2. **Correction F (NEW):** the contribution order is **re-ranked**. ★1 = reconstructing **stolen-valid-credential movement over a normal Kerberos sequence**, an attack class HADES's on-demand Stage 1 is not designed to trigger on (Correction D, now paper-verified and promoted); ★2 = ATT&CK-order path ranking on a cross-host graph; ★3 = node-level reconstruction evaluation. The identity-coherence term is **demoted to an optional, exploratory experiment**.
> 3. **Correction G (NEW):** TPPR facts that change the design — NodeScore is a GNN anomaly score (we have none → must be redefined); LengthScore only penalizes *short* paths; TPPR **deletes paths that share no node with another path** (would delete a lone single-hop attack path); ATT-SPT order = order of mention in CTI text.
> 4. **Correction H (NEW):** identity-term semantics — "exposed ≠ stolen"; two inconsistent definitions of the compromised identity exist (this handoff's code uses *the account that ran the dump*; the thesis/slides use *every account signed in at dump time*); the lab never reuses a stolen credential (Option D runs the agent *as* the moving account).
> 5. **NEW §22** — defense-prep record (2026-10-29): prior-art search result, slide-deck decisions (PoC framing, merged attack slide, revised identity slide), backing sources, the W1–W4 weak-points list, Sophos ITDR positioning, and next actions.
> 6. Citation fix: HADES TDSC DOI is **10.1109/TDSC.2025.3611866** (not …3611814); TDSC title is "HADES: *Detecting and Investigating* Active Directory Attacks via Whole Network Provenance Analytics", IEEE TDSC 23(1), 936–953, 2026.
> 7. **Correction I (NEW, added later on 2026-10-29):** LogonGuid is **not** the cross-host bridge to the source session — it links the **DC's 4769 ↔ the target's 4624** only. The link from the target back to the **foothold session** is the **network-connection match** (target 4624 source IP + time ↔ foothold outbound connection → that process's session). §9.4's `trace_backward()` had a bug (its "preferred" GUID path returns a DC-side value). §5.3, §5.4, §9.2, §9.4, §17, §18.1, §18.2 are marked ⛔ and corrected in place.
> Unchanged and still correct: the lab, Option D, the E1–E10 environmental findings, the collected data, the Stage-1 rule table (§7.2), the within-host session-stitching design (§9.1–9.2 session-ID part), the evaluation metrics (§14.2).
>
> **📝 REVISION NOTE (handoff_13 — Phase 4 automation BUILT; S02 ×10 COLLECTED).** On 2026-10-14/15 the lab was permanently re-hosted across **three physical PCs** and the Phase 4 collection tooling was built, debugged live, and used to collect **S02 ×10**. **Nothing deleted — only added/superseded-in-place.** What moved:
> 1. **NEW §20 "Phase 4 Execution Record"** — the 3-PC topology, the shared-file READY/GO/COLLECTED handshake, the looping per-host workers with remote-WinRM auto-collection, the one-line N-trial conductor, the measured timing (≈2.5 min/trial → **N = 10**), the live-run failure modes and their fixes, the collection-integrity rules, and the status of every remaining scenario.
> 2. **§19.5 Phase-4 prerequisites are now CLOSED** — all ability YAMLs are patched (comsvcs/registry-env/hostname/single-line), `run_trials.ps1` / `run_trials_3.ps1` were **retired** (single-host 5-VM orchestrators; the lab is now permanently 3-host) and replaced by the §20 worker + conductor design. E10 (trust desync) recurred live — see §20.7.
> 3. **Lab topology note:** §5.1 / §19 describe a "5-VM lab." That is still the VM inventory, but the VMs now live on **3 hosts** (A: DC-01 + Caldera, VirtualBox; B: EP-01, VirtualBox; C: EP-02 + EP-03, VMware Workstation). Network (flat `192.168.50.0/24`), domain, and agent design (Option D) are unchanged.
> 4. **Eval scaffolding drafted (parked):** `ground_truth.yaml`, `GROUND_TRUTH_README.md`, `score_paths.py` exist as a first draft. ⚠️ The draft's identity/endpoint labels were NOT taken from §19 and **contain errors** — see §20.9 before using it.
> 5. **Status line** updated: *Phase 4 not started* → *Phase 4 in progress (tools built, S02 ×10 done, 6 scenarios remaining); parser (Half 2) not started*.
> Already correct and unchanged: design (§0–§18), scoring math (§12), Option D (§19.2), the E1–E10 environmental findings (§19.3), the w₃ expectation table (§19.4).
>
> **📝 REVISION NOTE (handoff_12 — Phase 3 dry-runs COMPLETE; all 7 scenarios executed).** Between 2026-09-24 and 2026-10-12 every scenario (S01–S07) was executed end-to-end in the live lab and its telemetry verified against the T3 spec. **Nothing deleted — only added.** This is the first handoff revision that records *execution* rather than *design*; the design below is unchanged and was confirmed, not altered, by the dry-runs. What moved:
> 1. **NEW §19 "Phase 3 Dry-Run Record"** — the authoritative in-handoff summary of what was run and what it produced: per-scenario pass status, the **Option D** agent architecture (the single most important execution-level discovery — see below), the cross-scenario environmental findings (VBoxService LSASS noise, RDP LogonType-3-by-IP, the 1053-cosmetic rule, WinRM-needs-hostname), the live-confirmed GrantedAccess masks, and the open YAML-audit list that gates Phase 4. Full detail lives in the per-scenario `findings_*.md` files; §19 is the index + the design-relevant residue.
> 2. **Status line** updated: *design phase complete* → *design complete + Phase 3 dry-runs complete; Phase 4 (automated trials) + parser (Half 2) not started*.
> 3. **Caldera version** corrected 5.1.0+ → **5.3.0** (the version actually run; §18.3 note kept — v5.1.0+ remains the CVE-2025-27364 floor).
> 4. **Option D** (agent-as-scheduled-task-under-domain-account) is recorded in §19.2 as a genuine design element §5.1 never named. It is *why* identity attribution works at all: without it the Sandcat agent authenticates as the machine account (`EP-01$`) and every 4624/5145 shows `EP-01$` instead of `svc_backup`, which breaks the identity stitching the whole thesis rests on.
> Already correct and unchanged: the scoring math (§12), the pipeline (§6–§14), the scenario design (T3), comsvcs tooling (§5.1), and the six→seven scenario framing (S07 is the second ablation variant, already present as T3 Scenario 07).
>
> **📝 REVISION NOTE (handoff_11 — dump prerequisites + tooling reaffirmed).** Setup sessions (2026-09-22) clarified how the locked comsvcs dumper actually runs in this lab. **Nothing deleted — only clarified.**
> 1. **comsvcs.dll stays the LSASS dumper** (§5.1, unchanged intent), but it requires **Defender fully disabled** (`DisableRealtimeMonitoring` + `DisableBehaviorMonitoring`) **and `RunAsPPL=0` + reboot** on the two dump hosts (EP-01, EP-02), baked into the golden snapshot. Confirmed Event 10 on both (`GrantedAccess` 0x1410/0x1FFFFF).
> 2. **`rdrleakdiag.exe` was evaluated and rejected** — it fails to complete a dump on the Win 11 endpoints and leaves a lsass snapshot-clone that breaks `(Get-Process lsass).Id`. Any downstream file that briefly switched to rdrleakdiag is reverted to comsvcs.
> 3. **Only EP-01 and EP-02 dump LSASS** (EP-02 in Scenario 05 hop-2). DC-01 and EP-03 never dump.
> 4. **Domain confirmed `lab.local` / NetBIOS `LAB`**; scenario scripts/runbook use `LAB\`. See lab-inventory.md §3/§7.

> **📝 REVISION NOTE (handoff_5).** This version applies fixes agreed in a later session. **Nothing was deleted — only corrected or added.** Summary of changes, so a reader can see exactly what moved:
> 1. **NEW Correction D (§0)** — the biggest fix: the Stage-1 gate triggers on **lateral movement (logon events)**, NOT Kerberos-sequence anomalies, because this project's stolen-valid-credential attacks produce a *complete* Kerberos sequence. Includes the precise Pass-the-Ticket caveat and the peer-reviewed backing (Hopper, Latte, Bowman, MITRE T1021, NoDoze, HOLMES).
> 2. **§7 retitled** "Stage 1 — Lateral-Movement Gate"; §7.1 reframed with a pointer to Correction D (original Kerberos text retained as it correctly describes HADES's own model + the supporting rules).
> 3. **§7.2** — added **R8 (WinRM)** to the main rule gate; clarified primary (R4/R5/R6/R8) vs supporting (R1/R2/R3/R7) triggers; added RDP LogonType caveat; updated the `rule_gate` pseudocode with a suppression-first block.
> 4. **Scope line + §3.6 status** — WinRM confirmed **IN SCOPE** (scenario-03), no longer "under consideration"; added the five-scenario list and the one-line attack model.
> 5. **§6** pipeline box 2 relabeled "Lateral-movement gate."
> 6. **§5.1/§5.5** — confirmed 5-VM lab (DC + 3 endpoints + Caldera), **flat `192.168.50.0/24` network** (VLAN segmentation dropped from the data path; it changes no measured variable and is retained only as an optional appendix invariance check), network-agnostic golden images, and locked tooling (comsvcs.dll MiniDump for LSASS; Caldera abilities; Scenario 4 Track A manual). Technique list promoted T1021.006 + T1059.001 to core; added optional Discovery techniques.
> 7. **§9.2** — added the **LogonGuid-may-not-match** real-world caveat (fallback join now mandatory; validate GUID-match during setup).
> 8. **§18.2 / §18.3** — reclassified 4768/4769 as primarily stitching keys; expanded the citation map with Hopper/Latte/Bowman/log2vec/NoDoze/HOLMES/MITRE T1021/Caldera/Atomic + citation-weight guidance.
> 9. **§17** — added pitfalls for the gate framing and the LogonGuid mismatch.
>
> Items already correct in the prior version and therefore left as-is: the scoring math (§12), the HADES-vs-TPPR role table (§3.1), Corrections A/B/C, the Hopper identity-coherence positioning (§12.6), and the identity-coherence-is-a-hypothesis warning (§12.5).

> **📝 REVISION NOTE (T3 sync).** A later pass reconciled this handoff with the finalized **T3** scenario document. **Nothing deleted — only corrected or added.**
> 1. **Scenario count 5 → 6.** The scope line and §5.5 now list **six** scenarios; the previously-implicit **multi-hop mixed-protocol** case (EP-01→EP-02→EP-03, SMB then WinRM, with a second LSASS dump on the EP-02 pivot) is now explicit as scenario-05, and the benign baseline is scenario-06. (Change-log item 4 above still refers to the earlier "five-scenario list" — kept as historical record.)
> 2. **§5.5** — technique-to-scenario mapping extended so SMB/WinRM/T1570/T1569.002/T1059.001 also show their role in the multi-hop chain; added the explicit six-scenario description and a pointer to T3 as the authoritative per-event source.
> 3. **§14.5** — added the **Track A enrichment warning**: the ablation is only valid if Track A is structurally comparable to Track B, and Track A is the sole legitimate cross-host movement in the suite.
> 4. **§17** — clock-sync pitfall extended with the **explicit-UTC (ISO-8601 `Z`) manifest requirement** and the pre-capture `w32tm` skew check.
> Already correct and left as-is: the flat-network decision (§5.1/§5.5), WinRM-core status, comsvcs.dll tooling, the 4262 / 168-169 build-dependency flags (§3.6), and the GrantedAccess mask *set* in R1 (§7.2).

> **📝 REVISION NOTE (scenario-backing).** A later pass added external-literature backing for the six-scenario evaluation suite, answering the reviewer question "is six enough / are these real / reasonable." **Nothing deleted — only added.**
> 1. **NEW §14.7** — "Scenario Suite Sufficiency — Backing & Precedent": the real/reasonable/sufficient framing, an evidence table of how comparable PIDS and attack-reconstruction systems sized their evaluations (HADES=3, DEPCOMM=6 lab, SLEUTH=8, HOLMES=9, POIROT=10, ATLAS=10, APT29 plan=2), the methodological cover from the two field surveys, and a reviewer-gap analysis with cheap remediations.
> 2. **§18.3 → NEW §18.3.1** — expanded citation map with the comparison systems, the two surveys (PIDS Survey CSUR 2022; OmniSec SoK 2025), and the dataset/scale references (LMDG, LANL, DARPA OpTC), each tagged by how to use it.
> 3. **Per-scenario backing** (each scenario → MITRE technique + emulation precedent + peer-reviewed evaluation precedent) lives in **T3 §5**, the authoritative per-scenario document; §14.7 here defends the *set*, T3 §5 anchors each *member*.
> 4. **Table of Contents** — added the §14.7 line.
> Guardrails recorded in both docs: never attribute P/R/F1 to HADES (it reports FP/FN counts only); the HADES TDSC-2025 DOI suffix needs verification; LMDG is a dataset (cite for testbed/labeling precedent, not detection scores).

**Project title:** Design and Implementation of an Identity-Aware Attack Path Reconstruction System Using EDR and Authentication Logs
**Institution:** KMUTNB — Dept. of Electrical & Computer Engineering (Project 1, semester 1/2569)
**Status (handoff_18, 2026-11-03):** **Proposal defense PASSED (Mon 2 Nov 2026); advisor: continue on the current plan.** Collection: S02–S07 ×10 done, **S01 ×10 (manual RDP) still pending**. Parser/ingest done. **Build phase starts now:** gate + Sigma + answer keys → stitching (Nov, critical path) → scoring + identity (Dec) → evaluation (Jan). See §24.
⛔ *handoff_17 status line (kept for record):* **Status (handoff_17, 2026-10-30):** Design complete; Phase 3 dry-runs complete (§19); **Phase 4: S02–S07 ×10 collected, S01 ×10 (manual RDP) in progress** (§21); **EVTX → JSONL → normalisation → SQLite ingest DONE** (2.98 M events, 0 parse errors); gate + Sigma rules and answer keys in progress; **stitching, scoring, identity term, evaluation and web UI not started**. Proposal defense Mon 2 Nov 2026 with the final 91-slide deck (§23). Read Corrections J–L, then E–I (§0).
⛔ *Previous status line (kept for record):* Status: Design complete; **Phase 3 dry-runs complete (all 7 scenarios executed & telemetry verified, 2026-09-24 → 2026-10-12 — see §19)**; **Phase 4 IN PROGRESS (2026-10-15): collection tooling built; S02 ×10 collected; S01, S03–S07 remaining — see §20)**; the parser (Half 2, the thesis contribution) not yet started. **2026-10-29: framing corrected against the full base papers — read Corrections E–H first (§0) and §22.**
**Scope:** RDP + SMB + **WinRM / PowerShell Remoting (T1021.006)** lateral movement. *(WinRM is now confirmed IN SCOPE — it is scenario-03 of the six attack scenarios and exercises HADES's session-*linking* mechanism, a genuinely different tracer code path from RDP's reassignment. The §3.6 material, originally written as "under consideration," is now core; treat its "if WinRM is added" conditionals as decided-yes.)*
**Attack model in one line:** stolen-but-valid credentials moving across hosts over *normal* Kerberos — NOT Kerberos-protocol abuse (see Correction D). The six scenarios: (1) RDP, (2) SMB+service, (3) WinRM, (4) concurrent same-target movement (attacker `svc_backup` + admin `admin_it` → EP-02) [⛔ was "the ablation centerpiece"; now a test of session stitching + ranking first, identity-term ablation second — Correction F], (5) multi-hop mixed-protocol (EP-01→EP-02→EP-03, SMB then WinRM), (6) benign baseline. Detailed per-event telemetry for all six lives in the **T3** scenario document, which is the authoritative source for the event breakdowns; this handoff carries only the design rationale.

---

## Table of Contents

0. Corrections log (READ — these overturn earlier reasoning)
1. Project in one line + the honest framing
2. The two base papers and how they combine
3. Critical conceptual distinctions
3.5 The clean delta over scoped HADES (what TPPR-on-top actually adds)
3.6 Third protocol under consideration — WinRM / PowerShell Remoting (T1021.006)
4. Intermediate outputs (clean vs noisy graphs)
5. Data generation
6. The pipeline — the 8 boxes
7. Stage 1 — Lateral-movement gate (the trigger) [formerly "Authentication anomaly detection" — see Correction D]
8. The cheap-path vs expensive-path gate
9. Session-based tracing — correlation in depth (incl. session-ID mechanics)
10. ATT&CK labeling (Sigma)
11. Sequence path reasoning + the ATT-SPT reference tree
12. The full scoring system + identity-coherence (computation + sources)
13. HADES output & threat-scoring clarification
14. Evaluation design
14.7 Scenario suite sufficiency — backing & precedent [is six enough / real / reasonable]
15. Honest assessment — is this a valid thesis?
16. Open items
17. Pitfalls
18. Appendices — glossary, event-ID reference, citation map
19. Phase 3 dry-run record [execution log — added in handoff_12: per-scenario status, Option D, environmental findings, Phase-4 open items]
20. Phase 4 execution record [added in handoff_13: 3-PC lab, handshake protocol, auto-collect workers, N=10, live failure modes, integrity rules, status, ground-truth corrections]
21. Phase 4 execution record — session 2 [added in handoff_14: S02–S07 ×10 done, S01 pending; combined auto-collect workers + 0-decision guard; S05 Caldera rebuild; ground truth corrected]
22. Defense-prep record & paper-verified reframing [added in handoff_15, 2026-10-29: prior-art result, slide decisions, weak points W1–W4, Sophos ITDR, next actions]
23. Final defense state & locked decisions [added in handoff_17, 2026-10-30: ranking without θ, exposed-set definition, baselines ladder, final deck + script, known slide errors, wording rules, next actions]
24. Proposal defense outcome [added in handoff_18, 2026-11-03: committee questions + answers, advisor feedback, design changes, new limitations/future work, path-severity stretch item, next actions]

---

# 0. Corrections Log (READ FIRST — these overturn earlier reasoning)

> **⚠️ READ J–L FIRST (2026-10-30).** Corrections J–L lock the decisions made while finishing the defense deck. They supersede Correction C and §16 item 0, and settle Correction H.2.

## Correction J — rank paths, no retention threshold θ (supersedes Correction C)

**Earlier:** "Retain if `ConfidenceScore(CP) > θ`; then merge retained paths"; sweep θ; report Precision / FNR vs θ (Correction C, §12.3, §12.7, §14.3 item 4, §14.6, §17).

**Decided (2026-10-30):** the system outputs **every candidate path, ranked by path score, highest first**. No path is dropped by a cut-off.

| Item | Decision |
|---|---|
| Output | Ranked list of candidate paths, each with its path score and per-hop identity result |
| θ | **Not part of the method.** Optional display filter in the UI only (the mock-up slider). If ever reported, only as a supplementary P / FNR-vs-θ figure |
| Score meaning | A **path score** for ordering, **not a probability**. Never call it "confidence %" or "likelihood" |
| Merge step | Merge only paths that share nodes; **never** drop a path for being isolated (Correction G.4 still applies) |
| Metrics | Threshold-free (§14.2): top-1 rate, MRR, node P/R/F1 on top-k (k = number of answer-key attack paths in the trial), FNR = 1 − Recall, score gap, optional pooled ROC-AUC; plus processing time |

**Why:** a logon gate starts a trace for every lateral login (admin and attacker alike), so the analyst needs an order, not a yes/no. TPPR's θ only applied to scores on its own unnormalised scale and needed tuning per dataset; ranking removes that tuning and the "what θ did you pick?" question. TPPR's own ablation (w/o path scoring: Recall 100 %, Precision 10.72 %) is still the motivation for scoring at all.

## Correction K — identity term kept as the proposed term; exposed-set definition decided (settles H.2, closes §16 item 0)

1. **Kept.** IdentityCoherence is the **one ★ proposed term**, weighted by w₃ and tested with w₃ on/off. The thesis does **not** rest on it (Correction F still holds); a zero gain is a valid, reportable result.
2. **Definition (matches slides 32 and 59):** a cross-host hop `e` from source host `h` at time `t2` is **coherent** iff there was a credential-access event on `h` (Sysmon 10 on `lsass.exe`, T1003.001) at some `t1 < t2`, **and** the moving account had a logon session **open on `h` at `t1`** (exposed), **and** the move is out of `h` after `t1`. Path value = fraction of coherent cross-host hops.
3. **Consequences to state openly:** account B (exposed, then moves, never used by the attacker) also scores 1 (W1, exposed ≠ stolen). Under this definition **S04-A (`admin_it`) scores 1, not 0, if `admin_it` had a session open on EP-01 at the S04-B dump** — slide 78 shows `admin_it` explorer → PowerShell on EP-01 (session 0xd6398). Check the logon time of 0xd6398 before fixing the S04 answer key.
4. **Exclusions:** machine accounts (`*$`) and system logon IDs `0x3e4 / 0x3e5 / 0x3e7`. Restricting to interactive / RemoteInteractive / service / batch logon types (H.5) is future work, not the base definition.
5. The old §12.4 code (returns the account that *ran* the dump) is ⛔; the replacement is in §12.4.

## Correction L — presentation framing for the defense (does not change Correction F)

- **On the slides:** the project combines **linking across machines (adapted from HADES)** + **ranking by attack-stage order (adapted from TPPR)** + **one proposed identity term (★, to be tested)**. The comparison table marks HADES's identity column as △ (separates by login session), ours as ★ (proposed, not ✓).
- **Q&A only:** "HADES's stage 1 fires only on 7 known login-abuse patterns (e.g. Pass-the-Hash, Golden Ticket); a stolen valid password matches none, so HADES never starts" (Correction D / F ★1). The bridge sentence was removed from the slide by the student's choice.
- **Never say** (in addition to §17 / §22.2): the system "identifies the attacker", "separates the attacker from legitimate reuse of the same account", "detects stolen accounts", "points to the right account to reset", or that the gate / node-level P/R are "new" (gate = adapted design that starts wider; node-level metrics come from TPPR).

> **⚠️ READ E–H FIRST (2026-10-29).** Corrections E–H were made after reading both base papers in full. They **supersede Correction B** and refine Correction D. Where any later section contradicts E–H, E–H wins.

## Correction E — HADES ALREADY separates attacker from legitimate user of the same credentials (supersedes B)

**Earlier (WRONG):** "HADES stitches a compromised-credential move and a legitimate reuse of the same account identically and never distinguishes them" (Correction B, §1, §2, §3.1, §3.5, §15.1, §18.4).

**Paper-verified (TRUE):** HADES §IV-B states the problem and solves it. Quote: *"Alice's credentials were stolen by the attacker. Given that both Alice and the attacker have accessed the Exchange Sever from the Workstation 1 using the same credentials, this approach* [logon-event correlation] *would still create false-dependencies."* Its logon-session-based tracing instead creates *"a whole-network provenance graph representing activities conducted by exactly one true identity, be it the attacker or a normal user."* Each remote logon session on a target is traced back to **exactly one** initiating logon session on the source host, so the attacker's activity and the real user's activity land in **different graphs**.

**Also corrected (claims made in the 2026-10-29 chat, now retracted):**
- *"HADES checks whether the jumping process accessed LSASS"* — **wrong.** HADES §IV-C: for each cross-machine edge it counts credential-access techniques executed in the corresponding hosts **before** the edge, inside the traced attack graph (`CHECKCREDENTIALACCESS(AG, Tω, R)`), and for each such technique checks whether *that technique's* process accessed `lsass.exe`, which makes it **more severe**. It is a severity weight, not a check on the jumping process.
- *"Real attackers log in as the stolen account in a new session, so HADES's chain breaks"* — **probably wrong.** The remote logon on the target is still initiated by the attacker's process in its source-host session, and HADES traces back to that exact session, so the theft and the move normally stay in one graph.

**Consequence:** the identity-coherence term **cannot** be justified as "doing what HADES cannot." See Correction F for what the thesis now rests on.

## Correction F — the contribution is RE-RANKED (identity term demoted)

| Rank | Contribution | Paper backing |
|---|---|---|
| ★ 1 | **Reconstruct stolen-valid-credential lateral movement over a normal (complete) Kerberos sequence** — an attack class HADES's trigger is not designed to fire on — via a logon-event gate (§7) + HADES-style session stitching (§9) | HADES §IV-A / Fig. 5: Stage 1 detects only 7 broken-sequence attacks (AS-REP Roasting, Kerberoasting, Pass-the-Ticket, Overpass-the-Hash, Pass-the-Hash, Silver Ticket, Golden Ticket). HADES §VI-A: *"Only when HADES's stage 1 detects a potential lateral movement, it runs its stage 2."* All three HADES datasets are protocol-abuse attacks (Golden Ticket, Kerberoasting, Pass-the-Hash). |
| ★ 2 | **ATT&CK-order path ranking on a cross-host graph** (TPPR scoring on a HADES-style graph) | HADES Eq. 1–2 are order-agnostic sums ranking whole graphs; TPPR is single-host. Prior-art search (2026-10-29) found no paper combining both. |
| ★ 3 | **Node-level reconstruction evaluation** (Precision / Recall / F1 / FNR) for this attack class | HADES reports only FP/FN per dataset with TP = 1. |
| 4 | Identity-coherence term — **optional exploratory experiment**, expected gain small or zero | See Correction H |

> **handoff_17 (Correction K):** the open decision below is **closed** — the term is kept as the ★ proposed term with a w₃ on/off test; Correction F's ranking of contributions is unchanged. On the slides it is presented per Correction L.

**Why the identity term's expected gain is small:** in this project the gate fires on *normal* logons, so the admin's move and the attacker's move both trigger. Session stitching (HADES) separates them into different paths; the attacker's path contains the LSASS-dump node, so ATT&CK-order scoring (TPPR) should already rank it higher. The identity term mostly repeats that signal.

**"Identity-aware" in the title is still accurate** — it now refers primarily to **logon-session identity tracing** (HADES calls these "identity-based remote access types"), with the identity-coherence term as a tested extension. *(Open decision for the student — keep the term as a small experiment, or drop it. Recommended: keep it as a one-row ablation, framed as exploratory. §16 item 0.)*

## Correction G — TPPR facts that change the design

1. **NodeScore (Eq. 8) = mean GNN anomaly score**, from an unsupervised model trained on benign data (TPPR §3.2.1). This project has **no anomaly model** (Sigma labeling instead) → **NodeScore must be redefined** (e.g. Sigma rule level / severity) and stated as a substitution.
2. **TTP labels come from TREC** (deep-learning, few-shot) in TPPR; this project uses Sigma rules → a stated simplification.
3. **LengthScore = (1 − e^(−len/λ)) · EdgeScore** (Eq. 7). Length only penalizes **short** paths; long paths are *not* penalized for length — they score low only if their **average edge score** is low. The ATT&CK-order signal lives **inside** LengthScore (via EdgeScore). Do not describe LengthScore as "too long or too short scores low."
4. **Merging (§3.4): "Paths that do not intersect with any others … are considered low-confidence and are subsequently filtered out."** 🔴 In single-path scenarios (S01, S02, S03) this would **delete the true attack path**. This rule must be dropped or changed, and the change stated.
5. **ATT-SPT order = order of appearance of technique IDs in CTI report text** (§3.3.1), not observed execution order. Hand-built templates are a defensible simplification.
6. **Evidence for θ:** TPPR ablation "w/o PS" (no path scoring) gives Recall 100 % but Precision 10.72 %. θ sensitivity: θ ≈ 3.0–3.5 gives near-zero FNR but low precision; higher θ raises precision and FNR (§4.5).
7. **Weights α, β, a, b, λ, w1, w2 are not reported**; the preprint's author block is a placeholder ("Name1"). Treat TPPR as an **unreviewed preprint**; rely on its method, not its numbers; choose and justify weights by sensitivity analysis.
8. Single host confirmed: node attributes are PID / Name / Path / Cmd / IP — no user or logon field; merging uses process ID.

## Correction H — identity-term semantics (if the term is kept)

1. **Exposed ≠ stolen.** Sysmon 10 proves a process opened `lsass.exe`; it never says *whose* credentials were taken. The term can only test whether the moving account was **exposed** (in memory) at dump time, then moved out of that host.
2. **Two inconsistent definitions exist — pick one:** ✅ **DECIDED (handoff_17, Correction K): the slide definition — every account with a session open on the source host at dump time.**
   - §12.4 code here: `compromised_identity_before()` returns **the account that ran the dump** (`node["account"]` of the T1003.001 node).
   - Thesis Ch. 3 / slides: **every account signed in on the source host at dump time** (candidate exposed set).
   These give different results. Under the slide definition, S04-A (`admin_it`, whose scheduled-task agent `SandcatAgent_admin` runs on EP-01) may be **in** the exposed set and score 1.0, not the expected 0.0 (§19.4). Check the S04 logs for an `admin_it` logon session on EP-01 at dump time.
3. **Known failure mode (both definitions):** an innocent account also signed in on the foothold at dump time that then moves out of it is flagged exactly like the attacker. The term cannot tell them apart.
4. **The lab never reuses a stolen credential.** Option D runs each agent *as* the moving account; the dump is a theft *trace*, not the source of the credential used. This is acceptable for a PoC but must be **stated openly** (expected question: "why would `svc_backup` steal its own password?"). It also means the case where the identity term could beat HADES (thief's account ≠ moving account, with the causal chain broken) is **not exercised** by the current suite.
5. **Refinement (future work):** network logons (Type 3) normally do not leave reusable credentials in LSASS; restricting the exposed set to interactive / RemoteInteractive / service / batch logons would shrink false positives.


Two conclusions from later sessions **replace** things said earlier. A new chat must not repeat the old versions.

## Correction I — LogonGuid is a DC ↔ target confirmation key, NOT the bridge to the source session

**Earlier (WRONG/overstated):** "the logon GUID is **the cross-host bridge**"; "4624 TargetLogonGuid = **primary stitching key**"; mental model "logon GUID = **which session caused which, across machines**"; §9.4 code tries the GUID first ("Preferred") and IP + account + time only as "Fallback".

**Corrected (TRUE):**

| Link needed | Key that actually does it |
|---|---|
| Activity **inside** one host | Session ID / LogonId (host-local) |
| **DC ↔ target** — which ticket became which logon | **LogonGuid** (4769 on DC ↔ 4624 on target; Microsoft: a GUID "that can help you correlate" these events). Fallback: client IP + account + time + ServiceName. |
| **Target ↔ source (foothold) session** — which session on the foothold started this logon | **Network-connection match:** target 4624 (`IpAddress`, time, and `IpPort` if populated) ↔ foothold outbound connection (Sysmon 3: dest IP, dest port, time) → that process's LogonId (via its Sysmon 1 / 4688 record). 4648 on the source (explicit credentials) also carries LogonGuid + SubjectLogonId and can link directly **when present**. |

**Why the old code was wrong:** the only other event carrying the same LogonGuid is the DC's 4769, which lives on the DC. `trace_backward()` returned *that* event's `session_id`, i.e. a DC-side value, never the foothold session.

**Per-protocol source-side anchor (verify each in the S01–S03 logs before building):**
- **RDP:** `mstsc.exe` Sysmon 3 → dest port 3389 → its LogonId.
- **WinRM:** client `powershell.exe` Sysmon 3 → dest port 5985 (plus WinRM/Operational event 6 on the source) → its LogonId.
- **SMB:** ⚠️ outbound SMB is made by the kernel redirector, so Sysmon 3 typically shows `Image = System` (PID 4) — **no user session**. Anchor instead on the **command process** (Sysmon 1 whose command line names the target, e.g. `\\EP-02\ADMIN$`, `sc \\EP-02 create …`) or on 4648 if explicit credentials were used, matched by time. Check this in S02 before relying on it.

**Account match on the source side is not guaranteed:** the process's user (Sysmon 3/1 `User`) is the account *running* the tool; with explicit or stolen credentials the logon on the target may be a *different* account. In this lab they coincide only because of Option D. Treat account as a supporting check, not a required join condition.

**Where LogonGuid still matters:** exact 1:1 DC ↔ target match (no time window); the DC's independent confirmation of account and target service; proof a Kerberos ticket was used (non-zero GUID). It is a **supporting key**, not the headline. Report "% of cross-host edges confirmed by LogonGuid vs fallback" as a small evaluation number.

**Do not confuse** Sysmon's own `LogonGuid` field (computed by Sysmon per logon session on each host) with the Security-log LogonGuid in 4624/4769/4648. Never join a DC 4769 to a Sysmon `LogonGuid`.

## Correction A — HADES's tracing ALREADY drops benign activity

**Earlier (WRONG/overstated):** "Your scoped graph will be noisy with benign RDP/SMB tangled in, and the TPPR layer cleans it up; the contribution reduces benign false positives."

**Corrected (TRUE):** HADES's session-based tracing *itself* removes benign activity — via (1) session partitioning (only involved sessions traced), (2) discarding activity under predefined system logon IDs `0x3e4/0x3e5/0x3e7` (>90% of events on the Exchange Server in the paper), and (3) causal, identity-based stitching (the 479 → 4 result). **You are keeping the tracing, so most benign activity is already gone before scoring.**

**Consequence:** Do **NOT** justify the project as "reducing benign false positives" — a reviewer who knows HADES will reject it. The real, defensible delta is **Correction B**.

## Correction B — the real contribution is distinguishing *compromised* vs *legitimate* identity reuse

> ⛔ **SUPERSEDED by Correction E (2026-10-29).** HADES's own paper shows it separates the attacker from the legitimate user of the same credentials via logon-session tracing. Kept below as historical record only — do not repeat it.

HADES stitches by identity but **trusts the stitch**: a **compromised-credential move** and a **legitimate reuse of the same account** look **identical** to it. HADES never flags which is which. **Your identity-coherence term makes that distinction explicit** — it flags when the identity crossing a host boundary was *compromised on the previous host* (attack) versus a normal user legitimately reusing their account (benign).

**This is the honest core of the thesis.** Frame the contribution as *"flagging compromised-identity cross-host movement,"* not *"cleaning up benign noise."*

## Correction C — the retention threshold θ is tunable, not 0.5

> ⛔ **SUPERSEDED by Correction J (2026-10-30):** there is no retention threshold; paths are ranked. Kept as historical record — the TPPR facts about θ's scale remain true.

Earlier examples used `θ = 0.5` as an illustrative normalized number. TPPR's scores are NOT normalized to [0,1] (they carry parameters `b`, `λ`), so θ is a **tunable parameter**. TPPR sweeps θ ≈ **3.0–5.5** (Figs 10–11). Report precision/FNR vs θ.

## Correction D — the Stage-1 gate triggers on LATERAL MOVEMENT, not on Kerberos anomalies

**Earlier framing (imprecise / misleading if read alone):** the Stage-1 box was titled "Authentication anomaly detection" and §7.1 describes it as firing on "incomplete/abnormal auth sequences (HADES's idea)" — Pass-the-Ticket (TGS with no TGT), Golden Ticket, NTLM-instead-of-Kerberos, etc.

**Corrected (TRUE for THIS project):** HADES's Kerberos-sequence-incompletion model detects attacks **ON the Kerberos protocol** (ticket forgery/abuse: Golden/Silver Ticket, Kerberoasting, Pass-the-Ticket). **This project's attacks are different** — they use **stolen-but-valid credentials over normal Kerberos** (RDP LogonType 10, SMB LogonType 3, WinRM LogonType 3). A stolen valid credential reproduces the **complete, well-formed** TGT→TGS→service sequence, so it produces **no Kerberos-incompletion anomaly** and would NOT be caught by HADES's Stage-1 model. **Paper-verified (2026-10-29):** HADES is on-demand — *"Only when HADES's stage 1 detects a potential lateral movement, it runs its stage 2"* (§VI-A) — so for this attack class HADES's Stage 2 would never run. ⛔ The earlier sentence "HADES defers benign complete sequences to its Stage-2 tracing" was inaccurate and is withdrawn.

**Consequence:** the correct Stage-1 signal for this project is **the observable act of cross-host lateral movement** — logon-type / remote-access events (4624 LogonType 3/10, 4769 cross-host service tickets, 5140/5145 SMB share access, WinRM 6/91/193). This is exactly what the existing §7.2 rule table already does: **R4 (SMB), R5 (RDP), R6 (service), R8 (WinRM) are the PRIMARY triggers; the Kerberos/NTLM rules R2/R7 are only SUPPORTING signals kept for free.** So the rule table is already right; only the *title* and the §7.1 *framing* need to be read through this correction.

**Precise caveat (to avoid an examiner counterexample):** "stolen-credential movement produces no Kerberos anomaly" holds specifically when the **full** AS→TGS→service flow is reproduced (stolen password, or a session that legitimately obtained its own TGT). Pass-the-Ticket and Golden Ticket *do* skip the TGT-request step and therefore *do* create a structural anomaly — but those are not this project's attack model. State the claim as "for stolen-valid-credential movement over a complete Kerberos sequence," not "for all stolen-credential movement."

**Backing (peer-reviewed):** triggering lateral-movement detection on **logon events** rather than Kerberos-protocol anomalies is the established approach — **Hopper** (Ho et al., USENIX Security 2021) builds detection on login events and explicitly covers pass-the-hash/privilege escalation "so long as movement produces a login event"; **Latte** (Liu et al., MILCOM 2018) uses 4769 for cross-host access graphs; **Bowman et al.** (RAID 2020) uses authentication-graph anomaly detection; **MITRE ATT&CK T1021** documents the exact Event IDs/LogonTypes. The two-stage "cheap high-recall filter → precise second stage" shape is standard (HADES itself, **NoDoze** NDSS 2019, **HOLMES** IEEE S&P 2019). Committee framing: *"HADES's Stage-1 targets authentication-protocol anomalies, so by construction it does not fire on normal-Kerberos stolen-credential movement — and because HADES runs Stage 2 only after a Stage-1 alert, that movement is never traced. For that attack class the correct high-recall signal is the logon/remote-access event, validated by Hopper, Latte, and MITRE T1021, and deferring precision to a later stage follows the same two-stage paradigm as HADES, NoDoze, and HOLMES."* Present this as a **complementary adaptation** of HADES, not a refutation.

> **Diagram label fix:** the pipeline box currently reading "Auth anomaly detection — cheap filter, triggers trace" should read **"Lateral-movement gate — cross-host logon triggers trace."** The academic umbrella term for this component is **Lateral Movement Detection (LMD)**.

---

# 1. Project in One Line + The Honest Framing

## One line

**(handoff_15)** Build a small-scale **proof of concept** that reconstructs **stolen-valid-credential lateral movement over normal Kerberos** — which HADES's anomaly trigger is not designed to catch — using a logon-event gate plus HADES-style logon-session stitching, ranks the resulting cross-host paths by **ATT&CK order** (TPPR-style scoring), and evaluates reconstruction completeness; an identity-coherence term is tested as an optional extension.

> ⛔ Previous one-liner (kept for record): *Reimplement a scoped version of HADES's identity-based cross-host stitching (trigger + logon-session tracing), then add a TPPR-inspired sequence-reasoning layer on top — extended with a novel identity-coherence term — and evaluate how completely and accurately it reconstructs the true attack path.*

## The honest framing (critical)

- **You are NOT improving on HADES.** Full HADES already reconstructs attacks well.
- **Your scoped version will reconstruct WORSE than full HADES** (you remove machinery: session-ID reassignment, session linking, all 8 remote-access types).
- **The TPPR-inspired layer + identity term RECOVER value the scoping lost and ADD one capability neither base method has — they do not add accuracy beyond full HADES.**

Defensible framing:
> **(handoff_15)** *"I investigate whether a logon-event gate plus session stitching can reconstruct stolen-valid-credential lateral movement that HADES's anomaly trigger does not fire on, and whether ATT&CK-order path ranking separates the real attack path from normal admin movement on a cross-host graph. As an extension, I test whether an identity-coherence term adds anything beyond attack order."*
>
> ⛔ Superseded: *"…whether the identity term flags compromised-identity cross-host movement that HADES cannot distinguish from legitimate reuse."* (false — Correction E)

Framing table:

| Weak framing (will be challenged) | Honest framing (defensible) |
|---|---|
| "My system reconstructs better than HADES" | "I recover reconstruction accuracy on a simplified tracer" |
| "TPPR on top reduces benign false positives" | **WRONG — HADES tracing already does this** |
| "Reduce false positives" (as the goal) | "Reconstruct the movement HADES's trigger misses, and rank it by attack order" |
| "HADES can't tell attacker from legitimate user of the same account" | **WRONG — HADES session tracing does this (Correction E)** |

## Two refinements a new chat must carry

1. ⛔ ~~The contribution is identity-coherence~~ → **The contribution is the re-ranked list in Correction F**: (★1) the attack class HADES's trigger misses, (★2) ATT&CK-order path ranking across hosts, (★3) reconstruction evaluation; identity-coherence is an optional ablation. Still NOT benign-noise reduction (Correction A).
2. **Not a swap.** You are NOT replacing HADES's scoring with TPPR's. HADES scoring and TPPR reasoning do different jobs (§3). You add a reasoning capability HADES lacks, plus the identity term in neither paper.

---

# 2. The Two Base Papers and How They Combine

| Paper | Year | Contribution used | What it lacks |
|---|---|---|---|
| **HADES** (arXiv:2407.18858; IEEE TDSC 23(1) 2026, DOI 10.1109/TDSC.2025.3611866) | 2024 | Cross-host stitching via **logon session ID** (separates true identities causally) | Only *triages* whole graphs; order-agnostic scoring; **on-demand: never traces movement its Kerberos-anomaly Stage 1 does not flag** (stolen valid credentials over normal Kerberos); evaluation = FP/FN only |
| **TPPR** (arXiv:2510.22191, unreviewed preprint) | 2025 | ATT&CK **sequence** path reasoning | Single-host; identity-blind; depends on a GNN anomaly model + TREC labels (not reproduced here) |

Each solves half the problem: HADES stitches across machines but only scores for triage (and only starts on a Kerberos anomaly); TPPR reasons about ordered paths but is single-host. **This thesis triggers on lateral-movement logons (so normal-Kerberos stolen-credential movement is traced), puts TPPR-style ordered reasoning on HADES-style stitched graphs, and tests an identity-coherence term as an extension (Correction F).**

### Reused vs new

| Component | Status | Cite as |
|---|---|---|
| Log parsing, per-host provenance graph | Reused (standard) | — |
| Cross-host stitching via logon session ID | **Reused from HADES** | HADES |
| TPPR edge/path scoring equations | **Reused from TPPR** | TPPR |
| Hand-built templates replacing TPPR's mined ATT-SPT | **Your substitution** | note explicitly |
| **Logon-event gate for normal-Kerberos stolen-credential movement** (replaces HADES's anomaly trigger) | ★ NEW (adaptation) — ★1 in Correction F | contribution |
| ATT&CK-sequence path ranking on a cross-host graph | ★ NEW (the fusion) — ★2 | contribution |
| Reconstruction-completeness evaluation (node-level P/R/F1/FNR) | ★ NEW — ★3 | contribution |
| Identity-coherence scoring term | Optional extension (exploratory) — see Corrections E, H | proposed, tested by ablation |
| NodeScore from Sigma severity (TPPR uses a GNN anomaly score) | **Your substitution** | note explicitly (Correction G) |
| Dropping TPPR's "remove non-intersecting paths" merge rule | **Your substitution** | note explicitly (Correction G) |

---

# 3. Critical Conceptual Distinctions

## 3.1 HADES scoring vs TPPR reasoning vs your contribution

| Dimension | HADES threat scoring | TPPR path reasoning | This thesis |
|---|---|---|---|
| **Question** | "Is this graph worth investigating?" | "Which path *is* the attack?" | Same as TPPR, **across hosts** |
| **Purpose** | Triage / prioritization | Forensic reconstruction | Cross-host reconstruction |
| **Order-aware?** | **No** (magnitude aggregate) | **Yes** (ordered transition match) | **Yes** |
| **Separates chains sharing a node?** | No | **Yes** | **Yes** |
| **Cross-host?** | **Yes** | No | **Yes** |
| **Separates attacker from legitimate user of the same credentials?** | **Yes — by logon-session causality** (Correction E) | No (identity-blind) | Yes (inherits HADES session tracing); identity term = optional extra |
| **Traces normal-Kerberos stolen-credential movement?** | **No — Stage 2 runs only after a Kerberos-anomaly alert** | n/a | **Yes** ★ (logon-event gate) |
| **Output** | A number per graph | A reconstructed sub-graph | Ranked cross-host path |

**One-sentence reviewer defense:** *HADES scores whole graphs by severity for triage; it is order-agnostic and single-graph. My layer scores individual cross-host paths by ordered ATT&CK sequence and identity lineage for reconstruction — a different question HADES's formula structurally cannot answer.*

Nuance: HADES's *tracing* preserves order/causality; only its *scoring formula* is order-agnostic. What HADES lacks is comparing the observed technique sequence against ordered reference sequences — TPPR's ATT-SPT does that.

## 3.2 Shared-node discrimination (the sharpest illustration)

TPPR Case #2 (Fig 9): two attack chains share one node; two predecessors are possible; TPPR checks its sequence tree (one transition far more common) and attaches the node to the correct chain, splitting them. HADES's scoring cannot do this (never selects paths inside a graph; order-agnostic).

---

# 3.5 The Clean Delta Over Scoped HADES (what TPPR-on-top actually adds)

Hold the scoped tracer fixed. Both "scoped HADES alone" and "scoped HADES + TPPR" produce the **same stitched graph**. The delta:

| # | What your version adds | Scoped HADES has it? | Honest value |
|---|---|---|---|
| 1 | The **specific attack path**, extracted + ordered | ❌ (gives graph + severity number) | **Modest** (form difference) |
| 2 | **Ranking by ATT&CK sequence** (kill-chain order) | ❌ (scoring order-agnostic) | **Modest** |
| 3 | ⛔ ~~Identity-coherence — flag compromised vs legitimate cross-host moves~~ | ✅ **HADES already separates them by session (Correction E)** | **Small / unproven** — optional ablation only |
| 4 | **Traces movement HADES's Stage 1 never flags** (stolen valid credentials, complete Kerberos sequence) | ❌ (on-demand; no alert → no trace) | **Strong — the real delta (Correction F ★1)** |

**Bottom line (handoff_15):** the genuine, defensible deltas are **#4** (the attack class HADES's trigger misses) and **#2** (ATT&CK-order ranking across hosts — needed because a logon-event gate fires on *both* admin and attacker movement, so something must rank them). ⛔ The old bottom line ("tell attacker-driven movement apart from legitimate movement HADES treats identically") is **false** — Correction E.

**Important caveat on delta size:** the value of #1/#2 scales with how tangled the graph is — but since HADES tracing already de-noises (Correction A), don't overclaim these. #3's value does **not** depend on graph noise; it depends on whether attacks reuse compromised credentials (which they do).

---

# 3.6 Third Protocol Under Consideration — WinRM / PowerShell Remoting (T1021.006)

HADES identifies **8 standard remote access types**: RDP, SSH, PowerShell-Remoting (WinRM), WMI, RPC, PsExec, Network Share (SMB), and internal web-server request. Of the six not currently in scope, **WinRM is the strongest candidate** to add as a third protocol.

## 3.6.1 Why WinRM (and not the alternatives)

| Protocol | Verdict | Reason |
|---|---|---|
| **WinRM (T1021.006)** | ✅ **Recommended** | Exercises **logon session *linking*** (not just reassignment, which RDP already covers) — a genuinely different HADES mechanic. Common in APT29/WizardSpider emulation plans. Dual-use in practice (admin scripting vs. attacker lateral movement) → gives a real identity-ambiguous test scenario. |
| WMI | Secondary candidate | Similar "spawns under a service-like session" pattern to WinRM but less-evidenced as a *named* lateral vector in target emulation plans. Natural 4th protocol if scope allows. |
| PsExec | Already in scope | Rides on SMB + service creation — this is already your R6 rule / T1569.002. Not a new protocol. |
| SSH | Not recommended | Rare in native Windows AD environments; weak ecological validity; no reassignment/linking novelty. |
| RPC | Not recommended | Underlies WMI/PsExec rather than being its own attacker-facing path; hard to isolate as a scenario. |
| Internal web-server request | Not recommended | Real (HADES's own case study), but requires standing up IIS/Exchange-style infrastructure — too heavy for the project timeline. |

## 3.6.2 ATT&CK mapping

**T1021.006 – Remote Services: Windows Remote Management (WinRM)**, sub-technique of T1021 (Remote Services), tactic Lateral Movement (TA0008), Windows platform. Ports **5985 (HTTP) / 5986 (HTTPS)**.

> ⚠️ **Legacy-ID note:** older MITRE emulation plans and blog posts use the now-deprecated ID **T1028** for WinRM — this was merged into T1021.006. Treat any T1028 reference in source material as equivalent to T1021.006.

**Companion techniques that co-occur with WinRM in APT29's emulation plan** (Center for Threat-Informed Defense Adversary Emulation Library):
- **T1078 / T1078.002** — Valid Accounts (the credentials used to open the WinRM session)
- **T1003.001** — LSASS credential dump (already in scope)
- **T1570** — Lateral Tool Transfer (already in scope; e.g., copying Mimikatz over an established PS session)
- **T1569.002** — Service Execution (already in scope)
- **T1059.001** — PowerShell (the payload delivered *through* the WinRM transport — tag both together)
- **T1057** — Process Discovery (frequently run immediately after a WinRM session opens)

**Net new technique to add:** just **T1021.006** itself, plus **T1059.001** as a tightly-coupled companion for the labeling step (§10) since SigmaHQ tags WinRM detection rules with both. The other five above are already covered by existing scope items — WinRM slots into your existing technique set rather than requiring a parallel one.

## 3.6.3 Detection event set (four logs, not one)

Unlike RDP/SMB (mostly Security + Sysmon), WinRM detection needs **four logs**:

| Log | Event ID(s) | What it gives you | Confidence |
|---|---|---|---|
| **Microsoft-Windows-WinRM/Operational** | **6** — `WSManSessioninitialize` ("Creating WSMan Session"), source side, carries remote host address | Session start on the **client/source** | Manifest-confirmed |
| Microsoft-Windows-WinRM/Operational | **91** — `Requesthandling` ("Creating WSMan shell on servers"), records the authenticating account | Session/shell creation on the **target** | Manifest-confirmed |
| Microsoft-Windows-WinRM/Operational | **193** — `Userauthorization`, post-auth authorization check | Server-side authorization | Manifest-confirmed |
| Microsoft-Windows-WinRM/Operational | 168 / 169 — session creation / "User [acct] authenticated successfully…" | Supporting detail | ⚠️ Community/DFIR-sourced, **not** in the Win10-17134 manifest — confirm against your own testbed's build before relying on these |
| **Security** | **4624**, `LogonType=3` (Network) | WinRM logon signature on target | Confirmed |
| Security | **4262** (added July 2022, KB5015807/KB5015814) | **Source IP + machine name** for the inbound WinRM connection — the single most useful modern event for recovering the source host | Confirmed |
| Security | 4648, 4672 | Explicit-cred logon, privileged logon (supporting) | Confirmed |
| **Microsoft-Windows-PowerShell/Operational** | **4103** (module logging), **4104** (script-block logging) | The actual commands run over the session; 4104 carries `HostApplication=…\wsmprovhost.exe` — joinable to process telemetry | Confirmed |
| **Sysmon** | **Event ID 1** — `wsmprovhost.exe` as Image or ParentImage | Definitive target-host process artifact of an active PS-Remoting session | Confirmed |
| Sysmon | Event ID 3 — outbound/inbound 5985/5986 | Network-level corroboration | Confirmed (requires Sysmon 3 enabled — already a project prerequisite per §17) |

**Practical correlation pattern** (used in published KQL hunts): join **Event ID 6 on the source** with **Event ID 91 on the target**, matched on username within ~1 minute, to reconstruct one WinRM hop — this is the SIEM-level analogue of what your stitching (§9) needs to reconstruct causally.

## 3.6.4 Why this maps cleanly onto HADES's session-*linking* mechanism

Per the HADES paper (§IV-B.5, "Logon session linking"): remote commands sent via PowerShell-Remoting are executed by **`wsmprovhost.exe`**, spawned by an instance of `svchost.exe` running under the **System logon session (predefined ID `0x3e7`)**. HADES links the user's true logon session to this predefined session and performs **backward-tracing** within it until it finds the root process responsible — then **reassigns** the attacker's system activities to their true session ID (the paper's worked example reassigns to `0x2476c741`), separating them from unrelated System-session activity caused by other users' requests.

This is mechanically distinct from what RDP already exercises in your scope (**reassignment** due to Fast User Switching on a *user-owned* long-running session) — WinRM instead requires **linking through a *predefined system* session**, which is a genuinely different code path in the tracer. Adding it demonstrates a second, harder case of the same underlying idea rather than just repeating RDP's logic on a new port.

**Suggested new rule for the Stage 1 gate (§7.2):**

| Rule | Fires when… | Event + fields | Maps to |
|---|---|---|---|
| **R8 · WinRM session** | wsmprovhost.exe spawned, correlated to a `LogonType=3` logon | Sysmon **1** (`Image` or `ParentImage` ends `wsmprovhost.exe`) + **4624** `LogonType=3` | T1021.006 |

## 3.6.5 Sigma rules available as authoritative references

All tagged `attack.t1021.006` in the SigmaHQ repository:
- `proc_creation_win_winrm_remote_powershell_session_process.yml` — wsmprovhost.exe as Image/ParentImage (author Roberto Rodriguez)
- `posh_pc_remote_powershell_session.yml` / `posh_pm_remote_powershell_session.yml` — PowerShell classic/module logging, `HostName=ServerRemoteHost`
- **`proc_access_win_lsass_remote_access_trough_winrm.yml`** — LSASS access via `wsmprovhost.exe` — directly ties WinRM to the **existing T1003.001 scope item**, useful for your credential-access correlation
- `net_connection_win_susp_remote_powershell_session.yml` — outbound 5985/5986 from a non-service account
- `proc_creation_win_winrshost_command_execution.yml` — child processes of `winrshost.exe` (WinRs variant)

## 3.6.6 Literature-gap check (for §16 Open Item #1)

No independent 2020–2026 paper was found that performs identity/logon-session-based provenance tracing linking WinRM (`wsmprovhost.exe` / `0x3e7`) across hosts as a T1021.006 detection mechanism, **other than HADES itself**:
- **Hopper** (USENIX Security 2021) — authentication-graph only, no provenance, no session linking; HADES explicitly critiques its inference algorithm as less reliable.
- **Latte** (MILCOM 2018) — connection/authentication-graph based, not provenance-based.
- Other PIDS (TRACE, Winnower, RapSheet, Unicorn) — intra-machine only or not WinRM-specific.
- Two 2024–2025 arXiv papers on lateral-movement dataset generation / graph classification exist but do not do provenance/logon-session cross-host tracing with WinRM linking.

**Conclusion:** extending HADES's WinRM session-linking into a dedicated cross-host detector, scored via your identity-coherence term, remains a defensible, non-duplicative addition — but re-run this check (Google Scholar "cited by" on HADES) before committing, per §16 Open Item #1.

## 3.6.7 Caveats

- Event IDs **168/169 are not confirmed in the Win10-17134 WinRM manifest** — verify against your actual lab build before citing them as fixed IDs in the final report; 6/91/193 are manifest-confirmed and safer to lean on.
- Sysmon Event ID 3 must be explicitly enabled (already a pitfall noted in §17) — WinRM network-level corroboration depends on it.
- `wsmprovhost.exe` parentage (`svchost.exe` → System session) is documented in HADES and Microsoft's WS-Management architecture docs, but confirm actual parentage on your specific Windows build — it can differ across versions.
- HADES is now also published as **IEEE TDSC 2025, DOI 10.1109/TDSC.2025.3611814** (in addition to arXiv:2407.18858) — cite both.

---

# 4. Intermediate Outputs (Clean vs Noisy Graphs)

| | HADES (before scoring) | TPPR (before reasoning) |
|---|---|---|
| **Name in paper** | Low-level whole-network provenance graph (Fig 3, and Fig 10 for APT29) | Anomaly subgraph (Fig 3/6a) |
| **What's in it** | **Only the true cross-host chain** (tracing already de-noised) | **Many candidate paths + false positives** |
| **Is it the answer?** | Basically yes | No — a pile of possibilities |
| **Next step does** | Assigns a priority **number** | **Selects + orders** the real path |

Note (per Correction A): HADES's clean graph is a property of its *tracing*, which you keep. So your scoped graph is cleaner than earlier claimed — which is why the contribution rests on identity-coherence (#3 above), not noise reduction.

---

# 5. Data Generation

## 5.1 Lab setup (minimal — no cloud, no SIEM, no storage array)

| Component | Requirement |
|---|---|
| Domain Controller | 1 Windows Server VM (DC-01) |
| Endpoints | 3 Windows client VMs, domain-joined (EP-01 foothold, EP-02 file server, EP-03 WinRM target) |
| Attack infra | 1 Ubuntu VM running Caldera C2 |
| Logging | Sysmon (+ config) + Windows Security log on all |
| Attack runner | Caldera (primary) + Atomic Red Team (validation/spot-check) |
| Analysis machine | Any laptop/PC to parse exported logs |

**Confirmed lab = 5 VMs** (DC-01 + EP-01/02/03 + Caldera). The network is **flat `192.168.50.0/24`** — a single isolated port group, no router, no firewall, no VLANs. This is deliberate, not a fallback: no stage of the pipeline consumes subnet information. Stitching rides on `LogonGuid` (KDC-issued, topology-blind), logon session IDs (host-local), and event coverage — none of which change with segmentation. The only input a VLAN design alters is the *value* in `4624 IpAddress`, and the IP→IP join in T5 matches identically whether the addresses are same-subnet or cross-subnet. Segmentation would add three failure modes (routing breaking Kerberos → all-zero `LogonGuid`; NAT rewriting `IpAddress` → broken T5 join; NTP blocked across boundaries → clock skew) and zero information to the results. Golden images remain **network-agnostic** — IP is assigned at ESXi import — so a segmented topology can still be spun up later as a one-run *invariance check* ("reconstruction output is identical under flat and 3-VLAN routed topologies") if a reviewer asks for ecological realism. That optional pass belongs in an appendix, not the data-generation path. See the separate ESXi export runbook.

**Tooling decisions (locked; prerequisites clarified 2026-09-22):** LSASS dumping uses **`comsvcs.dll` MiniDump** (`rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <pid> <out> full`) rather than Mimikatz — it produces the cleanest, most repeatable **Sysmon Event 10** signal (`SourceImage=rundll32.exe`, `TargetImage=lsass.exe`, `GrantedAccess` 0x1410/0x1FFFFF), the required trigger for the identity-coherence term. **Defender blocks comsvcs by default**, so every dump-running endpoint (EP-01, EP-02) has Defender fully disabled and LSASS unprotected in the golden snapshot: `RunAsPPL=0` + reboot (LSA Protection otherwise blocks all LSASS reads) and `DisableRealtimeMonitoring`/`DisableBehaviorMonitoring` = true. `rdrleakdiag.exe` was trialled as a Defender-tolerant alternative but fails to complete a dump on the Win 11 endpoints (0-byte `.hlk`, lingering lsass snapshot-clone that breaks `(Get-Process lsass).Id`), so comsvcs remains the standard. Only EP-01 and EP-02 dump LSASS (EP-02 in Scenario 05 hop-2); DC-01 and EP-03 never do. All execution runs as **Caldera abilities** (the operation log doubles as the `ground_truth.json` seed) — **except Scenario 4 Track A** (the legitimate `admin_it` activity), which MUST be run **manually/interactively**, because scripting it through Caldera would give it the same process ancestry as the attack and destroy the identity-ambiguity the ablation depends on.

## 5.2 Tools

| Tool | Job | Note |
|---|---|---|
| **Sysmon** | Endpoint logging (process, network, LSASS) | Needs a real config (SwiftOnSecurity / Olaf Hartong) — default logs almost nothing |
| **Windows Security log** | Authentication between hosts | Built-in; **only source of the logon session ID** |
| **Atomic Red Team** | Fire single ATT&CK techniques | Validate logging early |
| **Caldera** (MITRE) | Run full multi-step attack chains | Produces realistic kill chains + ground truth |
| **`wevtutil` / `Get-WinEvent`** | Export logs to disk | Native PowerShell, no install |

## 5.3 Logs used (scoped to RDP + SMB)

**Security log (DC + hosts):** 4624 (logon; LogonType, TargetLogonId, TargetLogonGuid, IpAddress — key stitching event; ⛔ LogonGuid is the DC-confirmation key, IpAddress + time is the link to the source — Correction I), 4625 (failed logon), 4648 (explicit-cred logon), 4672 (special privileges), 4768/4769 (Kerberos TGT/TGS), 5140/5145 (share access), 4697/7045 (service installed).

**Sysmon log (each host):** 1 (process creation; LogonId, ProcessGuid), 3 (network connection — links host→host), 10 (process access → LSASS — cred dump), 11 (file creation — tool transfer).

## 5.4 The join keys

| Join key | Fields | Links |
|---|---|---|
| **Logon session ID** | `LogonId` (Sysmon 1) = `TargetLogonId` (Security 4624) | Process ↔ its logon session (INTRA-host only — see §9) |
| **Logon GUID** | `TargetLogonGuid` (4624) ↔ DC ticket event (4769) | DC auth ↔ target logon **only** (confirmation key; ⛔ not the bridge to the source session — Correction I) |
| **Source IP + time (+ port)** | target 4624 `IpAddress`/`IpPort` ↔ source Sysmon 3 dest IP/port | **Target logon ↔ foothold session** (the real cross-host link; SMB needs the command-process anchor — Correction I) |
| **IP address** | `IpAddress` (4624) ↔ Sysmon 3 dest IP | Connection on Host A ↔ logon on Host B |
| **ProcessGuid** | `ProcessGuid` (Sysmon) | Events of the same process |

`LogonType` is the scope filter: keep **`10` = RDP** and **`3` = SMB**; drop the rest.

> **If WinRM (§3.6) is added:** WinRM also logs as `LogonType=3`, so the scope filter alone can't separate it from SMB — you'd additionally need **Microsoft-Windows-WinRM/Operational** (Event IDs 6, 91, 193) and **Microsoft-Windows-PowerShell/Operational** (4103, 4104) log sources, plus Sysmon 1 matching on `wsmprovhost.exe`, since WinRM isn't distinguishable from Security-log fields alone. See §3.6.3 for the full event set.

## 5.5 Attack simulation methodology

Attacks are **known in advance** → ground-truth labels for free. **Confirmed technique set (WinRM now in scope):**

| Tactic | Technique | Role |
|---|---|---|
| Credential Access | **T1003.001** LSASS dump | the identity-coherence trigger |
| Defense Evasion / Identity | **T1078** Valid Accounts | the `w3` core (compromised vs legitimate) |
| Lateral Movement | **T1021.001** RDP | scenario-01 |
| Lateral Movement | **T1021.002** SMB | scenario-02; also hop-1 of scenario-05 |
| Lateral Movement | **T1021.006** WinRM | scenario-03 *(now core, not optional)*; also hop-2 of scenario-05 |
| Lateral Movement | **T1570** Lateral Tool Transfer | scenarios 01/02; staging in scenario-05 |
| Execution | **T1569.002** Service Execution | scenario-02; hop-1 execution in scenario-05 |
| Execution | **T1059.001** PowerShell | scenario-03 (payload through the WinRM transport); hop-2 in scenario-05 |

Validate one with Atomic Red Team → chain with Caldera → record ground truth.

**The six scenarios (as built in T3):** (1) RDP single-hop, (2) SMB + remote service, (3) WinRM / PSRP, (4) identity-ambiguous ablation [★ the `w3` centerpiece], (5) **multi-hop mixed-protocol** — EP-01 →(SMB)→ EP-02 →(WinRM)→ EP-03, with a *second* LSASS dump on the EP-02 pivot to harvest `admin_it` before hop 2, and (6) benign baseline. Scenario 5 is the only chain that pivots host *and* protocol mid-stream; it is the strongest test of cross-host reconstruction and re-establishes causality from telemetry alone at each boundary (no network-level signal, since the lab is flat). Scenarios 1–5 reuse the technique set above; no new techniques are introduced by the multi-hop case.

**Optional — Discovery techniques to consider adding:** the set above spans Credential Access → Lateral Movement → Execution but has **no Discovery stage**, which both HADES and TPPR score on and which makes chains look realistic. Consider adding **T1087** (Account Discovery) and/or **T1018** (Remote System Discovery) as cheap precursors so the ATT-SPT sequence-reasoning (§11) has a fuller tactic chain (Discovery → Credential Access → Lateral Movement → Execution) to reason over. Not required, but strengthens the scenarios and the sequence scoring.

## 5.6 Storage — simple

Windows writes every event to native **`.evtx`** files automatically. Lab attack logs are **megabytes, not gigabytes** (HADES's 150–250 GB came from logging everything for days). **No extra storage device, no log server, no SIEM.** Workflow: run attack → export once (`wevtutil epl ...`) → copy to laptop → replay offline in timestamp order (reproducible; simulates HADES's live trigger).

## 5.7 Early-start tip

Prototype on a pre-parsed **OTRF (Mordor)** lateral-movement dataset weeks before the lab is ready. **OpTC alone will NOT work** — no DC auth logs.

---

# 6. The Pipeline — The 8 Boxes

| # | Box | Origin | What it does |
|---|---|---|---|
| 1 | Data generation | Setup | Lab AD + Caldera attacks → logs |
| 2 | Lateral-movement gate *(formerly "auth anomaly detection" — see Correction D)* | Reused (HADES two-stage idea) + adapted trigger | Cheap high-recall filter on cross-host logon/movement events; **triggers** the trace |
| 3 | Session-based tracing | Reused (HADES) | **Correlation** — stitch hosts by logon session ID + GUID |
| 4 | ATT&CK labeling | Reused (Sigma) | Tag each node with a technique ID |
| 5 | Sequence path reasoning | **Your contribution** | Rank paths by attack order + identity coherence |
| 6 | Visualization | Output | Attack path + timeline |
| 7 | Evaluation | **Your contribution** | Reconstruction completeness |

Stage 1 (trigger) answers *"worth investigating?"* (cheap, noisy). Stage 2 (stitch + label + reason) answers *"what was the attack path?"* (expensive, accurate). Contribution lives in Box 5 + Evaluation.

---

# 7. Stage 1 — Lateral-Movement Gate (the trigger)
<!-- Section retitled per Correction D. Formerly "Authentication Anomaly Detection." -->

> **⚠️ READ Correction D (§0) FIRST.** For THIS project the gate's primary signal is **cross-host lateral movement** (logon-type / remote-access events), NOT Kerberos-sequence incompletion. The Kerberos-anomaly description below is retained because it accurately describes HADES's *own* Stage-1 model and remains valid for the supporting rules (R2/R7) — but it is **not** what fires the gate on this project's stolen-valid-credential RDP/SMB/WinRM attacks. The academic name for this component is **Lateral Movement Detection (LMD)**.

## 7.1 Concept

A cheap, rule-based **trigger**, not a detector. **Primary trigger = the observable act of cross-host lateral movement** (a network/remote-interactive logon or a remote service install) — see the R4/R5/R6/R8 rows in §7.2, which are the rules that actually fire on this project's scenarios. This is backed by the logon-event lateral-movement-detection literature (Hopper, USENIX Security 2021; Latte, MILCOM 2018; MITRE ATT&CK T1021) — see Correction D for the full citation map.

**Why not Kerberos-incompletion (HADES's own idea):** HADES's Stage-1 fires on **incomplete/abnormal** auth sequences — normal Kerberos = complete ordered handshake (TGT req → TGT → TGS req → TGS → access), and protocol-abuse attacks break it: Pass-the-Hash (NTLM instead of Kerberos), Pass-the-Ticket (TGS with no TGT), Golden Ticket (TGS with forged TGT). **But this project's attacks use stolen-but-valid credentials that reproduce the COMPLETE Kerberos sequence**, so they raise no such anomaly (Correction D). The incompletion signals are therefore kept only as **supporting** rules (R2 NTLM, R7 TGS-without-TGT), useful for free if a protocol-abuse variant appears, but never relied on as the primary gate.

**Stage 1 is allowed to be noisy.** Its only job is to point Stage 2 at the right place. Misconception: "Stage 1 detects the attack." Reality: it only raises a flag; Stage 2 confirms. **By design it over-triggers — including on a legitimate admin performing the same RDP/SMB/WinRM movement** — which is correct: separating the compromised move from the legitimate one is Stage 2's job (the identity-coherence term, §12), not the gate's. This high-recall-first / precise-later split is the standard two-stage detection paradigm (HADES, NoDoze NDSS 2019, HOLMES IEEE S&P 2019).

## 7.2 Rule gate — all conditions

| Rule | Fires when… | Event + fields | Maps to |
|---|---|---|---|
| **R1 · LSASS access** | Process opens `lsass.exe` with suspicious mask | Sysmon **10**, `TargetImage` ends `lsass.exe`, `GrantedAccess` in {`0x1010`,`0x1410`,`0x143a`,`0x1fffff`} | T1003.001 |
| **R2 · NTLM domain logon** | Domain logon uses NTLM not Kerberos | **4624**, `AuthenticationPackageName=NTLM`, `LogonType` in {3,10} | Pass-the-Hash |
| **R3 · Explicit-cred logon** | Logon uses alternate credentials | **4648** | Lateral movement |
| **R4 · SMB movement** | Network logon + share access | **4624** `LogonType=3` then **5140/5145** | T1021.002 |
| **R5 · RDP movement** | Remote-interactive logon | **4624** `LogonType=10` | T1021.001 |
| **R6 · Service install** | Service installed (PsExec-style) | **7045** or **4697** | T1569.002 |
| **R7 · TGS without TGT** | Service ticket with no preceding TGT | **4769** with no matching **4768** in window | Pass-the-Ticket |
| **R8 · WinRM session** | `wsmprovhost.exe` spawned, correlated to a `LogonType=3` logon | Sysmon **1** (`Image`/`ParentImage` ends `wsmprovhost.exe`) + **4624** `LogonType=3`; optional WinRM/Operational **6/91/193** + **4262** | T1021.006 |

**Primary triggers (start Stage 2 — the rules that fire on THIS project's scenarios):** **R4 (SMB), R5 (RDP), R6 (service), R8 (WinRM)** — all lateral-movement / remote-access signals. **Supporting signals (confirmation during correlation/scoring, NOT primary triggers):** R1 (LSASS access — also the identity-coherence trigger, §12), R2 (NTLM), R3 (explicit-cred), R7 (TGS-without-TGT). **Design principle: movement triggers; credential access confirms.** Per Correction D, R2/R7 (the Kerberos/NTLM-anomaly rules) are kept for free but are *not* what catches stolen-valid-credential movement — R4/R5/R6/R8 are.

> **R5 / RDP LogonType caveat:** RDP normally yields `LogonType=10` (RemoteInteractive), but connecting by IP with NLA can yield `LogonType=3`. A robust RDP rule should not rely on Type 10 alone — accept a remote-sourced Type 3 that resolves to an RDP session (Sysmon 3 port 3389) as well.

```python
def rule_gate(e):
    # --- SUPPRESSION FIRST (Correction D): ignore local/interactive/byproduct ---
    if e["event_type"] == "logon" and e["logon_type"] in (2, 11):
        return None                                   # interactive/cached = local, not movement
    if e.get("session_id") in ("0x3e7", "0x3e4", "0x3e5") and not e.get("share_access"):
        return None                                   # system/service byproduct logon
    if e.get("source_ip") in ("127.0.0.1", "::1"):
        return None                                   # loopback self-logon

    # --- PRIMARY TRIGGERS: cross-host lateral movement ---
    if e["event_type"] == "logon" and e["logon_type"] in (3, 10) and is_remote(e):
        return trigger(e, signal="lateral_movement")  # R4 SMB / R5 RDP
    if e["raw_event_id"] in (7045, 4697):
        return trigger(e, signal="service_exec")      # R6
    if e.get("image", "").endswith("wsmprovhost.exe"):
        return trigger(e, signal="winrm")             # R8
    if e["raw_event_id"] == 4769 and is_machine_account(e.get("service_name")) \
       and e.get("client_address") not in ("::1", None):
        return trigger(e, signal="cross_host_tgs")    # optional cross-host TGS safety net

    return None  # no trigger -> effectively dropped
```
Note the **suppression block runs first** — it is what keeps the benign baseline scenario (normal Type-2/3 local activity) silent, which is what makes the false-positive rate meaningful. If the benign scenario emits *any* trigger, tighten the suppression block before proceeding.

---

# 8. The Cheap-Path vs Expensive-Path Gate

```
Every event                          Almost no events
─────────────►  [ RULE GATE ]  ─────────────►
  (cheap)          fires?           (expensive)
[1] PARSE                          [4] CORRELATE
[2] NORMALIZE                       └► stitch cross-host graph
[3] MERGE (sort by time)            └► deep trace + reasoning
[5] CHECK RULES
     │
   no match ──► DROP (event ends here)
```

- **Cheap path** (parse → normalize → merge → check rules): every event; fast; intentionally noisy.
- **Expensive path** (correlate → stitch → trace → reason): only when a rule fires; rare.

This is HADES's **on-demand tracing** (Stage 1 ~ms/event; ~90% of events discarded early as forensics-irrelevant). Offline: "runs on every event" = "your script loops over every event once"; the `else` (no match) is silent — move to next event. That's how a normal event ends.

---

# 9. Session-Based Tracing — Correlation In Depth (incl. session-ID mechanics)

Box 3. Correlation answers *"which other events belong to the same attack chain?"* by matching **keys** in **two directions**. **Time position is NEVER a matching criterion — only keys.**

## 9.1 What the session ID is, and who issues it

- **Windows (the LSA) creates the session ID** at each successful logon — you never generate it; you read it.
- It identifies **one authenticated session on one machine**, is a hex number (e.g. `0x3e7`), unique **until reboot**, and labels every process/file/action in that logon.
  > **handoff_18 (§24.3 D1):** normalisation stores it **twice** — `logon_id_int` (for exact joins across sources) and `logon_id_hex` (original text, for display and for analysts, who read Logon IDs in hex).
- **Read it from:** `TargetLogonId` (Security 4624) and `LogonId` (Sysmon 1) — **same value, two names** — which normalization unifies into `session_id`.
- **Predefined IDs `0x3e4/0x3e5/0x3e7`** = system/service sessions (Network Service, Local Service, System); mostly discarded as forensics-irrelevant (>90% of events).

## 9.2 CRITICAL: session ID is host-LOCAL — it does NOT cross hosts

- **Grouping within a host** uses the session ID (same ID on same host = same session = group).
- **The session ID does NOT travel across hosts.** When the attacker moves A→B, **Host B assigns a brand-new, unrelated session ID**. You cannot match hosts by session ID — they'll never be equal.

```
Host A: attacker session 0xAAA  ──(SMB/RDP move)──►  Host B: NEW session 0xBBB
0xAAA and 0xBBB are unrelated numbers.
```

- ⛔ **(superseded by Correction I — read the corrected version below the caveat)** **Cross-host linking uses a different key: the logon GUID.** The DC's ticket event (4769) and Host B's logon (4624) share the **same** `LogonGuid` / `TargetLogonGuid` — that's the bridge. Supporting links: **source IP** (Host B's logon shows Host A's IP ↔ Host A's Sysmon 3 outbound) and **account** (same username).

> **⚠️ Real-world caveat — LogonGuid may not always match.** Microsoft documents `LogonGuid` as *intended* to correlate a member host's 4624 with the DC's 4769, but practitioner sources (e.g. Ultimate Windows Security) report the GUIDs **do not always match** in practice across member-host logon events and DC authentication events. Do **not** treat GUID-match as the sole join. The fallback join (source IP + account + timestamp window + `ServiceName`) in §9.4 is therefore **required, not optional**. **Add to Phase-1 logging validation:** confirm not just "LogonGuid non-zero" but "LogonGuid *matches across host-4624 and DC-4769*" on a known cross-host logon — discovering a mismatch during setup is far cheaper than at stitching (T5). This is also worth *discussing* in the thesis: it's a known real-world wrinkle in HADES's central mechanism, and handling it strengthens the work.

> **✅ Corrected (Correction I):** cross-host linking has **two different links**. (a) **Target logon → foothold session:** match the target's 4624 (`IpAddress`, time, `IpPort` if populated) to the foothold's outbound connection (Sysmon 3) and take that process's LogonId; for SMB use the command process (Sysmon 1 naming the target) because Sysmon 3 shows `System`. (b) **Target logon ↔ DC ticket:** LogonGuid (4769 ↔ 4624), fallback client IP + account + time + ServiceName — this *confirms* the account and target service. The mental model below ("logon GUID = which session caused which") is ⛔ wrong.

**So stitching is TWO steps:** (1) group activity *within* each host by session ID; (2) link the separate per-host sessions *across* hosts via logon GUID / IP / account. Mental model: session ID = "what belongs together here"; logon GUID = "which session caused which, across machines."

## 9.3 Join keys and indexing

```python
from collections import defaultdict
by_session = defaultdict(list)   # session_id -> events (INTRA-host grouping)
by_host_ip = defaultdict(list)   # (host, ip)  -> logon events
by_guid    = defaultdict(list)   # logon_guid  -> events (CROSS-host bridge)
net_conns  = defaultdict(list)   # host        -> Sysmon 3 events

for e in events:
    if e["session_id"]: by_session[e["session_id"]].append(e)
    if e["raw_event_id"] == 4624: by_host_ip[(e["host"], e["source_ip"])].append(e)
    if e.get("logon_guid"): by_guid[e["logon_guid"]].append(e)
    if e["raw_event_id"] == 3:    net_conns[e["host"]].append(e)
```

## 9.4 Cross-machine backward (exactly one parent)

HADES: a logon on the target results from **exactly one** logon session on the source. Use the target logon's `source_ip` + time (+ port) to find the outbound connection on the source host, then that process's session. Use LogonGuid only to **confirm** the logon against the DC's 4769 (Correction I).

> ⛔ The original code below has a bug: its "preferred" GUID path returns the DC 4769's `session_id`, not the foothold session. Use the corrected version that follows it.

```python
def trace_backward(target_logon):
    # Preferred: match by shared logon GUID (DC-issued, crosses hosts)
    for e in by_guid.get(target_logon["logon_guid"], []):
        if e["host"] != target_logon["host"]:
            return e["session_id"]
    # Fallback: source IP + account + time window
    for host, conns in net_conns.items():
        for c in conns:
            if c["dest_ip"] == target_logon["host_ip"] \
               and c["account"] == target_logon["account"] \
               and near_in_time(c, target_logon):
                return c["session_id"]
    return None  # reached entry point (external IP)
```

**✅ Corrected `trace_backward()` (handoff_15, Correction I):**
```python
PORT = {"rdp": 3389, "smb": 445, "winrm": 5985}

def trace_backward(target_logon):
    """Return (source_host, source_session_id, dc_confirmation) or None."""
    src_ip = target_logon["source_ip"]
    if not src_ip or src_ip in ("-", "127.0.0.1", "::1"):
        return None                                   # local / unknown -> entry point
    src_host = host_by_ip(src_ip, target_logon["time"])   # IP -> host at that time

    # (a) Link to the foothold SESSION via the outbound connection
    session = None
    for c in net_conns.get(src_host, []):
        if c["dest_ip"] == target_logon["host_ip"] \
           and c["dest_port"] == PORT[target_logon["access_type"]] \
           and near_in_time(c, target_logon) \
           and (not target_logon.get("source_port") or c["src_port"] == target_logon["source_port"]):
            if c["image"].lower() != "system":        # SMB shows System (PID 4): no session
                session = logon_id_of_process(c["process_guid"])
                break
    if session is None and target_logon["access_type"] == "smb":
        session = session_from_command_process(src_host, target_logon)   # Sysmon 1 naming \\target, near in time
    if session is None:
        session = session_from_4648(src_host, target_logon)              # explicit creds, if present

    # (b) Confirm with the DC (does NOT give the source session)
    dc = None
    guid = target_logon.get("logon_guid")
    if guid and guid != ZERO_GUID:
        dc = next((e for e in by_guid.get(guid, []) if e["raw_event_id"] == 4769), None)
    if dc is None:                                    # fallback confirmation
        dc = match_4769(client_ip=src_ip, account=target_logon["account"],
                        service_host=target_logon["host"], near=target_logon["time"])
    return src_host, session, dc
```
Record for each edge which path produced it (`guid` / `fallback` for the DC link; `sysmon3` / `command` / `4648` for the source link) so the evaluation can report the match rates.

## 9.5 Cross-machine forward (possibly many children)

Forward branches — one machine can log into several. From a session, find outbound connections (Sysmon 3); for each destination, find the matching 4624 logon (same source IP + account).

```python
def trace_forward(session_id):
    children = []
    for e in by_session[session_id]:
        if e["raw_event_id"] == 3:
            for logon in by_host_ip[(host_of(e["dest_ip"]), source_ip_of(session_id))]:
                if logon["account"] == e["account"]:
                    children.append(logon["session_id"])
    return children
```

## 9.6 The loop and end condition

```python
def stitch(trigger_event):
    graph, queue = set(), [trigger_event["session_id"]]
    while queue:
        sid = queue.pop()
        if sid in graph: continue
        graph.add(sid)
        parent   = trace_backward(first_logon(sid))   # one
        children = trace_forward(sid)                  # many
        queue += ([parent] + children) if parent else children
    return graph
```

Backward stops at an external IP / non-domain source; forward stops at leaf sessions.

## 9.7 Why a benign event between attack steps is skipped

Timeline `t1 attack on A → t2 normal Host B login → t3 move A→C (fires) → t4 execute on C`: rule fires at t3; backward (IP+account/GUID) reaches t1; forward (Sysmon 3) reaches t4; **Host B login (t2)** has its own session ID + own account (`alice`) + own IP → shares no key → excluded despite sitting between t1 and t3 in time. Result: `t1 → t3 → t4`. This is HADES's 479 → 4 dependency-explosion fix, and the foundation of the tracing.

---

# 10. ATT&CK Labeling (Sigma)

Box 4. Tags each node with `(technique, tactic)` via Sigma rules. **Adds attributes to existing nodes — does not change the graph structure.**

```python
node = {"event": "smb_logon", "host": "FS1", "session_id": "0x3e7", "account": "svc-backup",
        "technique": "T1021.002", "tactic": "Lateral Movement"}  # last two added by labeling
```

**Sigma is NOT the ATT-SPT tree.** Two separate artifacts:

| Artifact | Step | Job | Ordering? |
|---|---|---|---|
| **Sigma YAML** | Labeling (Box 4) | Tag each node's technique | ❌ No |
| **ATT-SPT tree** | Reasoning (Box 5) | Score whether the node *sequence* is valid | ✅ Yes |

Sigma has no concept of order. You need both.

**How many Sigma rules?** ~8–12 (floor ~6, ceiling ~15). Some techniques have 2 signals (SMB: 4624 LogonType=3 + 5140/5145; service exec: 7045 + 4697); supporting signals (NTLM, explicit-cred) add a couple. Target ~8–10. Most conditions already exist in your Stage 1 rule gate — labeling reformats them as YAML with a technique tag.

**If WinRM is added:** add **2–3 more rules** (T1021.006 process-based: `wsmprovhost.exe`; network-based: outbound 5985/5986; optionally the LSASS-via-WinRM rule tying it to T1003.001) — pushes the total to roughly **10–13**, still within the original ceiling. Authoritative SigmaHQ references are listed in §3.6.5.

```yaml
# T1021.002 - SMB lateral movement
detection:
  selection: {EventID: 4624, LogonType: 3}
  condition: selection
tags: [attack.lateral_movement, attack.t1021.002]
```

Labeling method: **Sigma (deterministic), not TPPR's TREC (neural)** — training-free, explainable. This is the intended substitution.

---

# 11. Sequence Path Reasoning + the ATT-SPT Reference Tree

Box 5 — your first contribution.

## 11.1 Same graph, one structural operation

The labeled graph passes **directly** into reasoning — same data type (NetworkX), no conversion. The one operation is **path extraction** (TPPR §3.3.3): walk the graph (leaf out-degree 0 → entry in-degree 0) to enumerate **candidate paths**, then score them. Engineering rule: **one graph object** across tracing → labeling → reasoning, attributes added in place.

```python
G = build_graph(events)      # tracing
G = label_nodes(G, sigma)    # labeling — adds .technique/.tactic in place
paths = extract_paths(G)     # reasoning — walks the SAME G
scores = [score(p, att_spt) for p in paths]
```

## 11.2 The reference — a tree (ATT-SPT), not a flat table

Two prefix trees: **technique-PT** (ordered technique sequences) and **tactic-PT** (same, mapped to tactics). A transition is scored by how it sits in the tree: direct = highest; indirect = lower (decays with length); same-tactic = direct/high; absent = ~0; branchy source = divided down.

## 11.3 How TPPR builds it (§3.3.1)

From **CTI reports** (AlienVault OTX, MISP, VirusTotal, APT28): extract MITRE IDs via regex → order into a sequence per report → insert into a prefix tree (new prefix = new branch; matching prefix = append tail) → map to tactics. Fig 5 example: 4 sequences merged by shared prefix. Scoring example (Fig 6a): direct same-tactic = `b`; direct-but-branchy = `0.5b`; indirect = `0.2083b`; absent = `0`.

## 11.4 How YOU build it — two options

- **Option A — CTI-mined (like TPPR):** pull real RDP/SMB campaign reports, extract sequences. Stronger, more work.
- **Option B — hand-built templates:** encode valid orders from MITRE ATT&CK. Simpler, training-free, but **you must justify each ordering**.

```
Templates (Option B):
  T1078 → T1003.001 → T1021.002 → T1569.002   (SMB path)
  T1078 → T1003.001 → T1021.001 → T1569.002   (RDP path)
  T1003.001 → T1021.002 → T1570               (move + tool transfer)
```
```python
att_spt = {
  "T1078": {"T1003.001": {"T1021.002": {"T1569.002": {}},
                          "T1021.001": {"T1569.002": {}}}},
  "T1003.001": {"T1021.002": {"T1570": {}}}
}   # a dict/JSON prefix tree — NOT YAML
```

**Data separation is mandatory:** build the tree from CTI/ATT&CK; test against **lab logs** — never the same data.

---

# 12. The Full Scoring System + Identity-Coherence

Design rule: **keep TPPR's equations exactly (citable); add the identity term as one factor in TPPR's own weighted-sum form** (in-framework extension).

> **⚠️ handoff_15 (Correction G):** three TPPR elements cannot be used as-is — (1) **NodeScore** is a GNN anomaly score in TPPR; redefine it here (e.g. Sigma rule level) and say so; (2) **LengthScore** penalizes only short paths (the order signal sits inside it via EdgeScore); (3) TPPR's merge step **deletes non-intersecting paths** — drop that rule or single-hop attack paths (S01–S03) are lost. The identity term is now an **optional extension** (Corrections E, F, H).

## 12.1 Level 1 — Edge score (TPPR Eq 5, unchanged)

```
ScoreE(e) = α·TacticScore(e) + β·TechniqueScore(e) + (1−α−β)·ScoreNI(e)
TacticScore(e)    = [ Σ_{p∈P(TAs,TAt)} 1/len(p) ] / out(TAs) · b        (Eq 2)
TechniqueScore(e) = a · max( Π_direct , max_p 1/len(p) , ε )            (Eq 3)
ScoreNI(e)        = u.indeg/u.outdeg + v.outdeg/v.indeg                (Eq 4)
```
100% TPPR — cite directly; only the reference source changes (templates vs mined tree).

## 12.2 Level 2 — Path factors

```
EdgeScore(CP)         = mean_{e∈CP} ScoreE(e)                          (Eq 6, TPPR)
LengthScore(CP)       = (1 − e^{−len(CP)/λ}) · EdgeScore(CP)           (Eq 7, TPPR)
NodeScore(CP)         = mean_{v∈CP} AbnormalScore(v)                   (Eq 8, TPPR)
IdentityCoherence(CP) = [ Σ_{e∈X(CP)} coherent(e) ] / |X(CP)|          (★ NEW — yours)
```

## 12.3 Level 3 — Path confidence (TPPR Eq 9 + one term)

```
ConfidenceScore(CP) = w1·LengthScore(CP) + w2·NodeScore(CP) + w3·IdentityCoherence(CP)
```
⛔ ~~Retain if `ConfidenceScore(CP) > θ`; then merge retained paths sharing nodes.~~ → **handoff_17 (Correction J): rank all candidate paths by this score, highest first; merge only paths that share nodes; drop nothing.** The score is a path score for ordering, not a probability. **The ONLY new element is `w3·IdentityCoherence`.**

> NodeScore here = mean **Sigma rule level** of the path's labelled nodes (informational 0 … critical 4, normalised to [0,1]) — a stated substitution for TPPR's GNN anomaly score (Correction G.1). The Thai text on slide 58 calls it "ความผิดปกติ"; the spoken script says "ความรุนแรงของกฎ Sigma".

## 12.4 The identity-coherence term — definitions and computation

It lives **inside Box 5**, as a **path-level factor** computed after candidate-path extraction.

**Definitions:**
- **Compromised identity** `I_c(e)` = the account whose credentials were accessed on the source host before the move (the account of the T1003.001 / credential-access node earlier on that host).
  > ✅ **handoff_17 (Correction K):** decided — **exposed set = every account with a logon session open on the source host at dump time t1**. Use the replacement code after the ⛔ block below.
  > ⚠️ **handoff_15 (Correction H):** the code below returns **the account that ran the dump**, which is *not* the stolen account in a real attack, and differs from the thesis/slide definition (**every account signed in on the source host at dump time = "exposed"**). Pick one before building. Either way the term measures **exposed, not stolen**.
- **Moving identity** `I_m(e)` = the account performing the cross-host move — the `TargetUserName` on the **4624 logon** that is the cross-host edge (`edge["account"]`).

```
coherent(e) = 1  if I_m(e) == I_c(e)      (move uses the compromised identity)
            = 0  if I_m(e) ≠ I_c(e)
            = 0  if I_c(e) is undefined    (move with no prior credential access)
IdentityCoherence(CP) = fraction of cross-host moves in CP that are coherent
```

**Computation (all inputs already in the stitched/labeled graph):**
```python
def identity_coherence(path, graph):
    xedges = [e for e in path.edges if e["cross_host"]]
    if not xedges:
        return 0.0
    coherent = 0
    for e in xedges:
        compromised = compromised_identity_before(e.source_host, e.timestamp, graph)
        moving = e["account"]                      # TargetUserName on the cross-host 4624
        if compromised is not None and moving == compromised:
            coherent += 1
    return coherent / len(xedges)

def compromised_identity_before(host, before_time, graph):
    for node in graph.nodes_on_host(host):
        if node["technique"] == "T1003.001" and node["timestamp"] < before_time:
            return node["account"]                 # account whose creds were dumped
    return None
```

⛔ **The code above is superseded (handoff_17, Correction K)** — it uses the account that *ran* the dump. Build this instead:

```python
SYSTEM_LOGON_IDS = {0x3e4, 0x3e5, 0x3e7}

def exposed_accounts(host, t1, sessions):
    """Accounts with a logon session open on `host` at time t1 (the dump)."""
    out = set()
    for s in sessions.on_host(host):                    # from 4624 / 4634 / 4647 (+ Sysmon 1 for sessions seen only via processes)
        if s.logon_id in SYSTEM_LOGON_IDS or s.account.endswith("$"):
            continue
        if s.start <= t1 and (s.end is None or s.end > t1):
            out.add(s.account)                          # normalised, lower-case
    return out

def coherent(edge, graph, sessions):
    """1 if the moving account was exposed on the source host by a dump before this move."""
    dumps = [n["timestamp"] for n in graph.nodes_on_host(edge.source_host)
             if n["technique"] == "T1003.001" and n["timestamp"] < edge.timestamp]
    return int(any(edge["account"] in exposed_accounts(edge.source_host, t1, sessions) for t1 in dumps))

def identity_coherence(path, graph, sessions):
    xedges = [e for e in path.edges if e["cross_host"]]
    return sum(coherent(e, graph, sessions) for e in xedges) / len(xedges) if xedges else 0.0
```

Note: a session with no logoff event is treated as open (`end is None`). Report how many hops depended on that assumption.

Interpretation: `1.0` = every crossing was made by an account **exposed** on its source host before the move; `0.0` = none was (benign, or no credential access). ⛔ ~~Set `w3` substantial; tune weights + θ on a validation split.~~ → **handoff_17:** no θ (Correction J); choose w1–w3 by a small sensitivity sweep and report rank stability, not a tuned optimum.

## 12.5 ⚠️ VALIDITY WARNING — identity-coherence is a HYPOTHESIS, not validated

**No paper defines this term — it was designed for this project.** It is a *reasonable formalization* of HADES's insight, NOT a proven formula. Rules:
1. **Never write "this is validated."** Write "we propose this factor and evaluate it."
2. Validate by **ablation** (with vs without `w3`) — the only validation that counts.
3. Be prepared for a modest gain or needed adjustment. That's normal research.

If asked "how do you know it's valid?": *"It's our proposed contribution, grounded in HADES's insight, validated empirically via ablation in Section X."*

## 12.6 Sources that ground the IDEA (you cannot cite the exact term)

| Your term's claim | Supporting source | Use |
|---|---|---|
| "Credentials enable lateral movement" | **HADES §IV-C** | The motivation for tying identity to cross-host moves |
| "Credential theft → identity used to move" | **MITRE ATT&CK** T1003 → T1021 | Justify the compromised→move linkage |
| "Identity-driven attacks dominate (80%)" | **CrowdStrike / industry reports** (HADES intro) | Real-world prevalence |
| "Weighted-sum multi-factor path scoring" | **TPPR Eq 5, 9** | The framework you extend |
| **Lateral movement via login/credential analysis** | **Hopper** (Ho et al., USENIX Security 2021; HADES ref [64]) | **Strongest single reference** — see below |

**HADES positioning (handoff_15 — must come first):** HADES §IV-C already weights credential access (especially LSASS access) before each cross-machine edge, per host and inside the traced graph, and its session tracing already separates true identities (Correction E). The identity term is at most an **account-level refinement** of that host-level signal — never present it as something HADES lacks entirely.

**Hopper positioning (your key related-work paragraph):** Hopper flags **credential-switching** during lateral movement as suspicious (attacker uses a *different* credential when moving). Your identity-coherence is effectively the **inverse, positive** signal: *whether the same compromised identity is carried across hosts*, scored inside a reconstruction framework. Write: *"Hopper treats credential-switching as a lateral-movement signal; we instead score identity-coherence — preservation of the compromised identity across a host boundary — as a positive attack signal within path reconstruction."* This positions your term as related-but-distinct from a peer-reviewed method (justification without claiming pre-validation).

## 12.7 Parameters, threshold, citation map

Parameters `α,β,b,a,ε,λ,w1,w2,w3` carry over from TPPR (TPPR does not report its values — choose and justify them). ⛔ ~~`θ` … tune it (TPPR sweeps ≈3.0–5.5; scores unnormalized).~~ → **handoff_17 (Correction J): no θ in the method; ranking only.**

| Element | Cite as |
|---|---|
| ScoreE (Eq 5), Tactic/Technique/NI (Eq 2–4), LengthScore (Eq 7), NodeScore form (Eq 8), path form (Eq 9) | **TPPR** |
| ⛔ threshold + merge → **ranking, merge without dropping isolated paths** | Your substitution (Corrections G.4, J) |
| NodeScore from Sigma rule level | Your substitution (Correction G.1) |
| Hand-built templates replacing ATT-SPT | Your substitution (note it) |
| **IdentityCoherence term + `w3`** | ★ Your contribution |

Thesis sentence: *"We adopt TPPR's edge and path scoring (Eq 5, 9) unchanged, computed over hand-built attack-progression templates, and extend the path confidence with an identity-coherence factor that rewards cross-host transitions preserving the compromised identity lineage."*

## 12.8 Worked example (numeric)

Two candidate paths (weights/θ illustrative). Path A (real, `svc-backup` throughout): LSASS dump → SMB move → service. Path B (benign coincidence): RDP move by `jsmith` → app.

| | Sequence | Identity | Severity | Combined |
|---|---|---|---|---|
| Path A | 0.83 | 1.0 | 0.9 | ⛔ ~~0.91 → kept~~ **0.91 → rank 1** |
| Path B | 0.15 | 0.0 | 0.2 | ⛔ ~~0.10 → dropped~~ **0.10 → rank 2** |

> handoff_17: both paths stay in the output (Correction J); the result is the order and the score gap (0.81).

**Ablation insight:** if Path B *mimicked* the attack sequence (0.83 vs 0.83), sequence alone couldn't separate them — **only the identity term** (1.0 vs 0.0) rejects Path B. That is exactly what the ablation must demonstrate.

> ⚠️ **handoff_15:** in practice Path B rarely mimics the full sequence — the attacker's path contains the LSASS-dump node (session-linked), the admin's does not, so ATT&CK-order scoring alone should already separate them. Expect a **small or zero** w₃ gain, and report it honestly.

---

# 13. HADES Output & Threat-Scoring Clarification

## 13.1 Which figure is HADES's real output

- **Fig. 10 (APT29 graph) = HADES's real output** — the rich low-level whole-network provenance graph (processes, files, sockets, across machines).
- **Fig. 11 = CAD's output** — CAD is the **Commercial Attack Detector** (the baseline HADES beats). It's 4 sparse boxes, shown to contrast how little the commercial tool produces.

## 13.2 What HADES's threat score scores (NOT node severity)

HADES scores the **whole graph**, computed from **cross-machine edges** by **technique frequency + variety** — NOT node severity, NOT a single path.

```
Level 1 (per cross-machine edge):  TS_E = Σ (Freq(teq_i) × Var(tac_i))^w_i     (Eq 1)
Level 2 (whole graph):             TS_G = Σ (TS_i × (DA + 1) × Criticality)     (Eq 2)
```
- `Freq` = how often techniques in a tactic fired; `Var` = how many distinct techniques; `w_i` = tactic weight (credential access highest).
- `DA` = domain-admin creds involved (0/1); `Criticality` = per attack type.

**Nuance:** lsass-memory access is weighted **more severe** — but that's a *weighting factor inside the frequency/variety calculation*, not a standalone per-node severity score. **Paper-verified (handoff_15):** credential access is counted *per cross-machine edge*, for techniques executed **before** the edge **inside the traced attack graph** (`CHECKCREDENTIALACCESS(AG, Tω, R)`); the LSASS check is on the process performing the credential-access technique, **not** on the process making the jump. **AD TTP rules** (Sigma, converted to queries) feed **only** this scoring step — they detect AD discovery + credential access *inside the already-reconstructed graph* to supply the `Freq`/`Var` counts. Their role is enrichment/labeling for scoring, not detection.

**Contrast with your scoring:** HADES scores the *whole graph* by frequency/variety (order-agnostic, triage). You score *individual paths* by ordered sequence + identity coherence (reconstruction). Node severity enters *your* system through TPPR's `NodeScore` term, not as the whole score.

---

# 14. Evaluation Design

Box 7 — your second contribution. Answers *"how completely and accurately does it reconstruct the true attack path?"*

## 14.1 Ground truth

You scripted the attacks → the Caldera/Atomic playbook IS the answer key (no manual labeling). Compare system output (reconstructed path) vs ground truth node by node.

## 14.2 Metrics (used by HADES and TPPR)

TP/FP/FN; Precision = TP/(TP+FP) (clean); **Recall = TP/(TP+FN) (complete ← headline metric)**; F1; FNR = FN/(TP+FN). **Recall is the headline** — it measures the "completeness" the purpose names.

**handoff_17 (Correction J) — what the node counts are computed on, and the ranking metrics:**

| Metric | Definition | Answers |
|---|---|---|
| Node P / R / F1 / FNR on **top-k** | Nodes of the k highest-ranked paths vs answer-key nodes; **k = number of answer-key attack paths in that trial** (1 for S01–S05, 2 for S07) | Is what the analyst sees first complete and clean? |
| **Top-1 rate** | Fraction of attack trials whose rank-1 path matches an answer-key attack path (node Jaccard ≥ 0.5) | Does the attack come first? |
| **MRR** | Mean of 1 / rank of the first matching attack path | How far down is it when it is not first? |
| **Score gap** | Lowest attack-path score − highest benign-path score in the trial (> 0 = clean separation) | How clearly separated? (S04, S07) |
| **S06 check** | S06 has no attack path: its highest benign score vs the distribution of attack-path scores in S01–S05 | Do benign paths rank below attacks? (replaces "S06 FPR = 0") |
| Pooled ROC-AUC (optional) | Path-level, attack vs benign, all trials | Threshold-free summary |
| Processing time | Per scenario and per stage | Advisor request |


## 14.3 Four parts

1. **Reconstruction quality** — P/R/F1 per scenario + average (like TPPR Table 3).
2. **Ablation (★ your proof)** — `w3>0` (full) vs `w3=0` (ablated). If precision drops without the identity term, you've proven it. **The single most important experiment** (mirrors TPPR Table 4).
3. **Baseline comparison** — vs raw stitched graph (no reasoning), Sigma-alone, HADES-style scoring only (mirrors HADES vs SIEM/commercial; TPPR vs SPARSE/DepImpact).
   **handoff_17 — locked ladder (same data, same metrics):** B0 alerts only (Sigma-labelled nodes, no linking) → B1 linked paths, no ranking (time order) → B2 order-blind scoring (NodeScore only, HADES-style) → B3 full with w₃ = 0 → Full. **Do not compare numbers with HADES or TPPR** (different data and metrics).
4. **Sensitivity** — ⛔ ~~sweep θ and `w3`, plot Precision + FNR~~ → **handoff_17:** sweep w1–w3 and report whether the **ranking** (top-1 rate, MRR) stays stable; a P/FNR-vs-θ curve is optional supplementary only.

## 14.4 Runner

```python
def evaluate(reconstructed, ground_truth):
    tp = len(reconstructed & ground_truth)
    fp = len(reconstructed - ground_truth)
    fn = len(ground_truth - reconstructed)
    p = tp/(tp+fp) if tp+fp else 0
    r = tp/(tp+fn) if tp+fn else 0
    f1 = 2*p*r/(p+r) if p+r else 0
    return p, r, f1
```

handoff_17 — ranking metrics (Correction J):

```python
def jaccard(a, b): return len(a & b) / len(a | b) if a | b else 0.0

def rank_metrics(ranked_paths, truth_paths, match=0.5):
    """ranked_paths: list of node-sets, highest score first. truth_paths: list of node-sets."""
    hits = [i for i, p in enumerate(ranked_paths, 1) if any(jaccard(p, t) >= match for t in truth_paths)]
    top1 = 1.0 if hits and hits[0] == 1 else 0.0
    rr = 1.0 / hits[0] if hits else 0.0
    k = len(truth_paths)
    topk_nodes = set().union(*ranked_paths[:k]) if ranked_paths else set()
    p, r, f1 = evaluate(topk_nodes, set().union(*truth_paths))
    return {"top1": top1, "rr": rr, "precision": p, "recall": r, "f1": f1, "fnr": 1 - r}
```

## 14.5 Evaluation scenarios — include an identity-ambiguous case

> ⚠️ **handoff_15 reframing:** S04 (attacker + admin moving to the same target at the same time) is now first a test of **session stitching** (two separate paths, not merged) and **ATT&CK-order ranking** (attacker path ranked above admin path) — ★1/★2 in Correction F. The w₃ ablation on S04/S07 is a secondary, exploratory result. The current suite does **not** exercise the one case where an identity term could beat HADES (thief's account ≠ moving account with a broken causal chain) — Correction H.4.

Because the contribution is identity-coherence (not noise reduction), design at least one scenario where **a benign account and a compromised account both move across hosts**, so the identity term has something to discriminate. Without such a case, the ablation can't show the term's value. Optional: runtime (Stage 1 ms/event; Stage 2 s/graph).

**WinRM (§3.6) is a good source for this scenario:** it's dual-use in practice — admins legitimately script over PowerShell Remoting *and* attackers abuse it for stealthy lateral movement — giving a naturally identity-ambiguous case rather than a contrived one.

> **⚠️ The ambiguous scenario (Scenario 4) is only useful if Track A is rich enough.** Merely *having* a benign track is not sufficient. Track A (the legitimate `admin_it` movement) must be **structurally comparable** to Track B (the malicious `svc_backup` movement) — same event *shapes* (4624 Type 3/10, 4769, Sysmon 1, ideally a benign service/scheduled-task creation mirroring Track B's 7045), overlapping in the same time window on the same target host — so that an identity-blind scorer (`w3 = 0`) genuinely cannot separate them and only the identity-lineage signal distinguishes the two. A single benign SMB read is too thin: if `w3 = 0` already suppresses Track A for unrelated reasons (no service creation, no LSASS precursor), the ablation delta is not attributable to identity coherence and the result is uninterpretable. Track A is also the **only** legitimate cross-host movement in the entire suite — Scenario 6's benign users have no cross-host access by design — so the whole `w3` result rests on this one track. Treat Scenario 4 as not ready for evaluation until Track A meets this bar.
>
> **✅ DONE (Gap-3 fix, T3 Scenario 04).** Track A has been enriched to a five-event chain (4.1A auth → 4.2A admin-share write of `HealthAgent.exe` → 4.3A benign `HealthAgentSvc` service execution as SYSTEM) that mirrors Track B's event shapes exactly, differing only by the absence of a preceding LSASS node for `admin_it`. The four capture-time gates (shape parity, temporal overlap, identity-blind indistinguishability, manual execution of Track A) are recorded in **T3 Scenario 04 §6** and must pass before the ablation (T11). Residual limitation: this is still *one* legitimate-movement track — for a second independent control, add a benign cross-host action to Scenario 06 (T3 §4.5) or a second ablation variant (§14.7.5).

## 14.6 "Done" checklist

Reconstruction table (★ headline: Recall on S01–S05 ⛔ ~~, no attack path on S06~~ → **S06 benign paths rank below attack paths**, Correction J); ranking result on S04/S07 (attacker path above admin path; top-1 rate, MRR, score gap); baseline table (**B0–B3 ladder, §14.3**); ablation table (order scoring on/off; w₃ on/off); sensitivity plots (⛔ ~~θ,~~ weights → rank stability); processing time per scenario (requested by the advisor). ⛔ ~~"If the ablation shows the identity term improves precision … the thesis is proven"~~ — the thesis no longer rests on w₃ (Correction F).

## 14.7 Scenario Suite Sufficiency — Backing & Precedent

> **The question this section answers:** *"Only six scenarios — is that enough, and are they real/reasonable?"* This is the single most predictable evaluation-design challenge. The answer holds because "enough / real / reasonable" are **three separate claims**, each needing a different kind of source. Per-scenario anchoring lives in **T3 §5**; this section defends the *set*.

### 14.7.1 The one distinction that settles most of the objection

Your suite is a **mechanism demonstration**, not a **statistical-generalization study**. Keep these apart and most of "six is too few" evaporates; conflate them and it collapses on you.

| Claim type | What it proves | What it needs | Is this you? |
|---|---|---|---|
| **Mechanism demonstration** | The identity-coherence term *works* — distinguishes compromised from legitimate movement | A handful of clean, labeled scenarios + an ablation | ✅ **This thesis** |
| **Statistical generalization** | It works on X% of real-world lateral movement in general | Huge labeled datasets (LANL, OpTC, millions of events) | ❌ Do **not** claim |

For a mechanism demonstration, six ground-truth-labeled scenarios is at/above the field norm. For generalization you would need LANL/OpTC-scale data — out of scope, and OpTC lacks the DC authentication logs this approach requires anyway (HADES makes the same exclusion).

### 14.7.2 Evidence table — how comparable systems sized their evaluations

Benchmarked against landmark provenance-based intrusion-detection and attack-reconstruction systems, single-digit hand-built, ground-truth-labeled scenario sets are the accepted norm.

| System | Venue / Year | # distinct attack scenarios | Note |
|---|---|---|---|
| **HADES** (the paper you scope down from) | IEEE TDSC 2025 (arXiv:2407.18858) | **3** emulated datasets, one TP each | APT29 / Oilrig / WizardSpider; 3–4 hosts each; reports FP/FN + threat-score CDF, **not** P/R/F1 |
| **DEPCOMM** | IEEE S&P 2022 | **6** lab (+8 DARPA TC) | Graph summarization; Kill-Chain per attack |
| **SLEUTH** | USENIX Security 2017 | **8** | DARPA red-team engagement |
| **HOLMES** | IEEE S&P 2019 | **9** | DARPA TC; single tuned threshold |
| **POIROT** | ACM CCS 2019 | **10** | DARPA TC + public incident reports |
| **ATLAS** | USENIX Security 2021 | **10** | 2 Windows hosts; ground-truth attack stories |
| **RapSheet** | IEEE S&P 2020 | **3** simulated campaigns | APT3 / APT29 / custom, via MITRE Caldera |
| **Kairos** | IEEE S&P 2024 | Manzoor (6) + DARPA TC + OpTC; **14-scenario** ablation | Per-scenario benign/attack split; §5.4 ablation |
| **MITRE APT29 Emulation Plan** | CTID | **2** scenarios | Flagship community plan uses a *small curated* set — direct precedent |
| **Hopper** *(the outlier)* | USENIX Security 2021 | **326 simulated + 1 red-team** | *Statistical* detector on 780M logins / 15 months — the other question, not yours |
| **★ This project** | — | **6** + explicit ablation + P/R/F1 | At/above norm; **more thorough than HADES's own three** |

**The strongest single sentence in the defense:** *HADES — the system I re-implement — evaluated on only three emulated datasets, one true positive each, on 3–4-host testbeds. My six scenarios with Precision/Recall/F1 plus an explicit ablation is a more thorough evaluation than the paper I scoped down from.* (This is in HADES §VI; each dataset states `TP=1`.)

### 14.7.3 Methodological cover — why the field accepts small, scripted suites

This is a structural constraint, not a shortcut. Both surveys of the area — the **PIDS Survey** (ACM Computing Surveys 55(7), Art. 135, 2022) and the **OmniSec SoK** (arXiv:2503.03108, 2025) — name the *absence of realistic labeled cross-host datasets* as the field's central bottleneck. Scripting the attack yourself yields a **perfect answer key** you can never get from real-world captures without error-prone manual labeling. The field trades scale for label-exactness, and reviewers accept that trade for mechanism papers.

### 14.7.4 Coverage — why *these* six are the right slice

- **RDP + SMB + WinRM are the canonical Windows credential-based LM set** — precisely the Windows sub-techniques MITRE catalogs under **T1021 Remote Services** (T1021.001 / .002 / .006). DCOM (.003) is niche; SSH (.004) / VNC (.005) are non-Windows/legacy. You picked *the* subset, not a weird one.
- **The kill chain** (T1003.001 LSASS → T1078.002 stolen valid credentials → move → T1569.002 / T1059.001 execute) is faithful to HADES's own credential-access-enables-movement threat model.
- **Scenario 05** (SMB→WinRM with a pivot dump) mirrors **APT29 Emulation Plan Scenario 2** (WinRM → T1570 → LSASS/KRBTGT to a DC) — a real adversary's actual sequence.
- **Benign control (06) and ablation (04) are expected, not optional** — every major system measures FPR against benign activity, and component-isolating ablation is standard (Kairos §5.4; TPPR ablation table). Your identity-ambiguous scenario *is* the ablation vehicle for `w3`, which is methodologically exactly right.

### 14.7.5 Reviewer gaps and cheap remediations (name these yourself)

Declaring these as *threats to validity* before the examiner does converts an attack into evidence of rigor.

| Gap a reviewer will raise | Severity | Cheap remediation | Published precedent to cite |
|---|---|---|---|
| **One instance per scenario** → no variance-bearing number | High (fix first) | **Addressed:** automated runner (`run_trials.ps1`, both manual + Caldera-API modes) runs each scenario **10×** with randomized surface details; report mean ± SD. Runbook §7. | Caldera-as-scripted-engine precedent (LMDG arXiv:2508.02942; COHORT arXiv:2606.30479); ML-reproducibility norm that a *single* run misleads and ≥5–10 runs are needed for a stable mean±SD (Henderson et al. 2018; Agarwal et al. 2021). **No security-specific "N trials" standard exists — 10 is chosen on general statistical grounds, see note below.** |
| **Missing high-frequency vectors** — WMI (T1047), scheduled tasks (T1053.005), Kerberos ticket-forgery (Golden/Silver/PtT, T1550) | Medium–High | Add **one WMI/scheduled-task** scenario **+ one ticket-forgery** scenario → lifts to **8**, and intersects HADES's own attack set (Golden-Ticket, Kerberoasting, PtH) | APT29 plan uses WMI; HADES evaluates ticket-based attacks |
| **Thin benign baseline** (single cross-host run) — self-flagged in §14.5 / T3 §4.3 | High | **Partially fixed:** Track A enriched (Gap-3, T3 Scenario 04) + Scenario 06 benign-look-alike corpus specified (T3 §4.5). **Still open:** only one legitimate *cross-host* track — add a second (Scenario 06 benign cross-host action, or a second ablation variant) | Hopper (15 mo/780M logins); Kairos; LMDG (<1% malicious) |
| **No scale / host-count stress** | Low (scope out) | Acknowledge as a scope limit; name the scale path | LANL (Kent 2015); DARPA OpTC (arXiv:2103.03080); LMDG |
| **`w3` validated on one ablation case** | Medium | **Addressed:** **Scenario 07** (concurrent dual-compromise, T3) added as the *under-fire* counterpart to Scenario 04's *over-fire* test — the two cover both error directions. Run 10× like every scenario. | Two-error-direction classifier eval (FP vs FN); concurrent multi-identity attacks in LMDG; bidirectional ablation in Kairos §5.4 |

> **On the trial count (5 vs 10) — honest backing.** There is **no attack-emulation-specific published standard** for how many times to repeat a scenario; searching the methodology literature returns general experimental-statistics guidance, not a security rule. What the literature *does* support: (a) a **single** run is unreliable — Henderson et al., *Deep Reinforcement Learning that Matters* (AAAI 2018) and Agarwal et al., *Deep RL at the Edge of the Statistical Precipice* (NeurIPS 2021) both show small run-counts mislead; (b) the standard error of the mean shrinks with $1/\sqrt{n}$, so the jump from 1→5 removes most single-run noise and 5→10 meaningfully tightens the interval with diminishing returns after ~10 for a lab this size (MachineLearningMastery repeat-estimation analysis; standard SEM statistics). **Decision: 10.** Rationale: the runner automates execution, so 10 vs 5 costs only wall-clock time, not human effort — you buy the tighter mean±SD for free. **5 is the acceptable floor** if disk/time is constrained; below 5 you cannot defend a variance estimate. Do **not** cite a paper claiming "use N trials for attack scenarios" — none exists; cite the general SEM/reproducibility grounds instead.

### 14.7.6 What to explicitly declare out of scope (with justification)

*Justified exclusion is stronger than shallow inclusion.* Consistent with HADES's stated threat model of credential-based movement on a small controlled testbed, declare out of scope: exploitation-based lateral movement (**T1210**); SSH/VNC (non-Windows/legacy); internal spearphishing (**T1534**); and enterprise-scale evaluation (cite LANL/OpTC/LMDG as the path not attempted).

### 14.7.7 Verdict

**Six is enough — for a mechanism demonstration** (at/above field norm; more thorough than HADES's own three), **the six are the right slice** (MITRE's canonical Windows set + faithful kill chain + textbook control/ablation), and **the biggest live risks are overclaiming generalization, one-instance-per-scenario, and the thin benign baseline** — the first fixed by framing, the latter two by the cheap remediations above. Full per-scenario anchoring: **T3 §5**. Reference details: **§18.3.1**.

---

# 15. Honest Assessment — Is This a Valid Thesis?

**Yes, acceptable — but not because it beats HADES.** Full HADES reconstructs well; your scoped version reconstructs *worse*; the TPPR layer + identity term *recover* value and *add* one capability. Whether it helps "significantly" is **unknown until the ablation runs**; the thesis is valid even if the gain is modest, provided it's measured honestly.

## 15.1 The main risk and the CORRECTED defense

**Risk:** *"You took a working system, made it weaker, and added a layer to compensate — what's the point?"*

**Defense (handoff_15 — paper-verified; do NOT lead with benign-noise reduction or with "HADES can't tell identities apart"):**
1. **The attack class HADES's trigger misses (strongest).** *"HADES starts tracing only after a Kerberos-anomaly alert. Stolen valid passwords produce a normal Kerberos sequence, so HADES never traces them. Our gate triggers on the lateral-movement logon itself, and our session stitching and ranking reconstruct the path."*
2. **Ordered path ranking across hosts.** A logon gate fires on admin and attacker movement alike; ATT&CK-order scoring ranks the attack path first (HADES ranks whole graphs, order-agnostic; TPPR is single-host).
3. ⛔ ~~The identity capability is genuinely new~~ — HADES already separates identities by session (Correction E). The identity term is an optional, honestly-reported extension.
2. **Deployability.** Full HADES needs heavy machinery + huge logs (150–250 GB); your scoped version is lighter — provided it's genuinely lighter, not just worse.
3. **Ordered path output.** You produce an extracted, ordered attack path vs HADES's graph + severity number (modest).

## 15.2 Succeeds vs fails

| Succeeds if | Fails if |
|---|---|
| You reconstruct the normal-Kerberos stolen-credential paths (Recall) | You claim "better than HADES" without proof |
| ATT&CK-order ranking puts the attack path above admin movement (S04/S07) | You claim "HADES can't tell attacker from legitimate user" (FALSE — Correction E) |
| You report the w₃ ablation honestly, even if the gain is zero | You frame it as "benign-noise reduction" (WRONG — HADES tracing does that) |
| You state the PoC limits (lab, Option D, exposed ≠ stolen) yourself | You present the identity term as validated or as the core contribution |

> **handoff_17 (Correction L):** at the proposal defense, point 1 is held for Q&A; the slides lead with linking + ordering + the proposed identity term.

**handoff_15:** ⛔ ~~"The thesis lives or dies on the ablation"~~ → **the thesis rests on reconstructing the attack class HADES's trigger misses, ranking it by attack order across hosts, and measuring reconstruction honestly.** The w₃ ablation is a secondary result.

## 15.3 Recommendation

**handoff_15:** (1) Frame the contribution per Correction F (attack class HADES's trigger misses → ordered cross-host ranking → reconstruction evaluation); (2) keep the identity term as an optional ablation, framed "exposed, not stolen"; (3) fix the three TPPR adaptation points (Correction G); (4) state the Option D / no-credential-reuse limitation openly; (5) cited-by sweep — done via Semantic Scholar (2026-10-29, §22.2); repeat on Google Scholar before submission. ⛔ Old recommendation ("make the identity ablation the centerpiece") withdrawn.

---

# 16. Open Items (Decide Before Committing)

0. ✅ **CLOSED (handoff_17, Correction K): kept as the ★ proposed term, w₃ on/off; exposed set = every account signed in on the source at dump time.** ⛔ Original item: **(handoff_15, decide first) Identity term: keep as a small exploratory ablation, or drop it** and define "identity-aware" purely as logon-session identity tracing? Recommended: keep as one ablation row. Then choose **one** definition of the compromised/exposed identity (Correction H.2) and check S04-A against it.
0a. **Redefine NodeScore** without a GNN (e.g. Sigma rule level) and **drop TPPR's non-intersecting-path filter** (Correction G).
0b. **Verify the S04 logs:** was `admin_it` logged on to EP-01 at the S04-B dump time? *(handoff_17: still open — check the logon time of session 0xd6398; under Correction K this decides whether S04-A's answer-key identity value is 0 or 1.)*
0d. **(handoff_17) S07 Path Y account:** the design says `svc_sql`, the collected data uses `svc_backup` for both paths over one SMB session (0x49cdfa). Fix the answer key to the data, not the design.
0c. **Google Scholar "cited by" check on HADES** (Semantic Scholar missed Commander, JISA 2025).

1. **HADES cited-by sweep (highest priority).** Confirm no 2025–2026 paper already fuses TTP-sequence reasoning with session-based cross-host provenance tracing, or already does compromised-vs-legitimate identity scoring across hosts. *If one exists:* lean on the specific identity-coherence formulation + open dataset + comparative evaluation.
2. **Dataset route.** Self-generated lab (recommended) vs public. OpTC alone won't work (no DC auth logs).
3. **ATT-SPT build route.** Option A (CTI-mined, stronger) vs Option B (hand-built templates, simpler, justify orderings).
4. **Schedule.** Confirm 6- vs 8-month defense window (thesis starts ~June 2569).
5. **Third protocol decision (WinRM).** Confirm whether to add WinRM/PowerShell Remoting (T1021.006, §3.6) to scope. If yes: update title/abstract scope line, add ~2–3 Sigma rules (§10), add rule R8 (§7.2), add the four-log detection set (§3.6.3) to the data-generation pipeline, and re-run the HADES cited-by sweep specifically for WinRM session-linking work (§3.6.6) before finalizing the novelty claim.

---

# 17. Pitfalls (Consolidated)

**Data generation:** Sysmon 10 off by default → enable `ProcessAccess`; share auditing (5145) off by default → enable via GPO; default Sysmon logs almost nothing → real config; `.evtx` binary → convert to XML/JSON; **unsynced VM clocks → sync all VMs to the DC** (`w32tm /resync /force`, verify < 1 s skew before every capture; stitching depends on timestamps). **Record all ground-truth manifest timestamps in explicit UTC (ISO-8601 with trailing `Z`)** — a mix of local time and UTC across hosts silently inverts event order and breaks both the T3 monotonicity gate and T5 cross-host ordering.

**Correlation / stitching:** don't correlate by time window alone → require a **key match**; keep `LogonGuid` after normalize (it confirms DC ↔ target; ⛔ not "the cross-host bridge" — the link to the source session is IP + time + port ↔ Sysmon 3, Correction I; session ID is host-local); for SMB, Sysmon 3 shows `System` — anchor on the command process; never join a DC 4769 to Sysmon's own `LogonGuid` field; Sysmon 3 must be enabled (forward tracing needs it); forward branches, backward is single.

**Labeling / reasoning:** don't confuse Sigma (labels nodes) with ATT-SPT (scores order); only label the ~6 in-scope techniques; unlabeled attack node mid-path breaks sequence scoring; don't average identity into every edge (keep it a path-level factor); ⛔ ~~**θ is tunable, not 0.5**~~ → **no θ — rank (Correction J)**; never call the path score a probability.

**Evaluation / framing:** don't test on the same attacks used to build the reference tree (circular); **don't skip the ablation** (only proof); include an identity-ambiguous scenario; don't claim the identity term is validated before results; **don't frame as "benign-noise reduction"** (HADES tracing already does that — Correction A); reframe as compromised-vs-legitimate identity.

**Design:** don't over-invest in Stage 1 (noisy trigger by design); Stage 1 doesn't "detect" — it flags; Stage 2 confirms.

**handoff_15 pitfalls (paper-verified):** never say "HADES can't distinguish compromised vs legitimate reuse" (Correction E); never say "HADES checks whether the jumping process accessed LSASS"; never say the identity term detects *stolen* accounts — only *exposed* ones; never describe LengthScore as penalizing long paths; don't keep TPPR's "drop non-intersecting paths" rule; don't present NodeScore as TPPR's (it's a substitution); never attribute P/R/F1 to HADES; cite TPPR as an unreviewed preprint; never call LSASS dumping "the most common" credential theft (it is the most *documented* host-local one); never claim the lab reuses stolen credentials (Option D).

**Stage-1 framing (Correction D):** do **NOT** describe the gate as a "Kerberos-anomaly detector" — this project's stolen-valid-credential attacks produce a *complete* Kerberos sequence and raise no anomaly; the gate triggers on **lateral-movement logon events** (R4/R5/R6/R8), with Kerberos/NTLM rules (R2/R7) only supporting. State the "no Kerberos anomaly" claim precisely (holds for full AS→TGS→service reproduction; Pass-the-Ticket/Golden Ticket DO create an anomaly). Frame as a **complementary adaptation** of HADES, not a refutation. Don't rely on RDP being LogonType 10 (IP+NLA gives Type 3).

**Cross-host stitching (LogonGuid):** don't treat `LogonGuid` match as the sole cross-host join — it may not always match between host-4624 and DC-4769 in practice (§9.2). The IP+account+time+ServiceName fallback is **required**. Validate GUID-match (not just non-zero) during logging setup.

---

# 18. Appendices

## 18.1 Glossary

| Term | Meaning |
|---|---|
| **Logon session ID** | Windows/LSA-assigned ID (`LogonId` / `TargetLogonId`) grouping all activity of one authenticated session **on one host**; unique until reboot; **host-local (does not cross hosts)** |
| **Logon GUID** | Identifier shared between the DC's ticket event (4769) and the destination host's logon (4624) for one Kerberos authentication; **confirms DC ↔ target** (all zeros when not captured, e.g. NTLM). ⛔ Not the link to the source session (Correction I). Not the same as Sysmon's `LogonGuid` field. |
| **Compromised identity** | The account whose credentials were accessed on the source host (the T1003.001 node's account) |
| **Moving identity** | The account performing a cross-host move (the `TargetUserName` on the cross-host 4624 logon) |
| **Identity coherence** | This project's new scoring term: fraction of cross-host moves where the moving identity equals the identity compromised on the source host |
| **On-demand tracing** | Run deep tracing only after a Stage 1 trigger — HADES's efficiency mechanism |
| **Dependency explosion** | False edges from correlating by time/connection instead of causality/identity (HADES's 479 → 4) |
| **LOLBins** | Living-Off-the-Land Binaries — native tools (net, netstat) abused by attackers |
| **ATT-SPT** | Attack tactic/technique sequential pattern tree (TPPR); the ordered-sequence knowledge base for scoring |
| **technique-PT / tactic-PT** | The two prefix trees inside ATT-SPT |
| **Sigma** | Open-source SIEM detection-rule format (YAML); used to label nodes with techniques |
| **Ablation** | Removing one component (here `w3`) to measure its contribution — the core validation experiment |
| **Ground truth** | The known true attack chain (from the attack scripts) used as the evaluation answer key |
| **CAD** | Commercial Attack Detector — the baseline HADES compares against (Fig 11) |
| **Hopper** | Ho et al., USENIX Security 2021 — lateral-movement detection via login paths / credential-switching; nearest related work to identity-coherence |
| **WinRM** | Windows Remote Management — protocol/service for remote command execution (T1021.006); ports 5985 (HTTP)/5986 (HTTPS); candidate third protocol, see §3.6 |
| **`wsmprovhost.exe`** | The WinRM provider host process spawned on the **target** machine to execute a PowerShell Remoting session; the definitive process-level artifact of WinRM lateral movement |
| **Session linking** (WinRM case) | HADES links a user's true logon session to the predefined System session (`0x3e7`) under which `wsmprovhost.exe` runs, then backward-traces to find the true initiating identity — distinct from RDP's *reassignment* mechanism |

## 18.2 Event-ID quick reference

| Event ID | Source | Meaning | Used for |
|---|---|---|---|
| 4624 | Security | Successful logon | Stitching (LogonType, TargetLogonId, TargetLogonGuid, IpAddress) |
| 4625 | Security | Failed logon | Anomaly signal |
| 4648 | Security | Logon w/ explicit creds | Lateral-movement hint |
| 4672 | Security | Special privileges | Privilege escalation |
| 4768 | Security | Kerberos TGT request | Cross-host context; supporting anomaly signal only (R7). *Per Correction D, NOT a primary trigger for this project.* |
| 4769 | Security | Kerberos TGS request | **PRIMARY USE: DC-side confirmation of each cross-host logon** — carries `LogonGuid` (matches the target's 4624) and `ServiceName` (target host). ⛔ Not the link to the source session (Correction I). Secondary: supporting anomaly signal (R7). *Not the detection trigger.* |
| 5140/5145 | Security | Network share access | SMB movement |
| 4697/7045 | Security | Service installed | SMB execution |
| 1 | Sysmon | Process creation | Endpoint activity (LogonId, ProcessGuid) |
| 3 | Sysmon | Network connection | Cross-host forward tracing |
| 10 | Sysmon | Process access → LSASS | Credential dump |
| 11 | Sysmon | File creation | Lateral tool transfer |

### 18.2.1 WinRM-specific event IDs (if §3.6 is added)

| Event ID | Source | Meaning | Used for | Confidence |
|---|---|---|---|---|
| 6 | WinRM/Operational | `WSManSessioninitialize` — session creation, source side | WinRM hop, source end | Manifest-confirmed |
| 91 | WinRM/Operational | `Requesthandling` — shell creation, records authenticating account | WinRM hop, target end (join with ID 6 by username, ~1 min window) | Manifest-confirmed |
| 193 | WinRM/Operational | `Userauthorization` — post-auth authorization check | Server-side authorization | Manifest-confirmed |
| 168 / 169 | WinRM/Operational | Session creation / "User [acct] authenticated successfully…" | Supporting detail | ⚠️ Community/DFIR-sourced — confirm against your lab's Windows build |
| 4262 | Security | IP-address audit for inbound WinRM (added KB5015807/KB5015814, July 2022) | Source IP + machine name recovery | Confirmed |
| 4103 | PowerShell/Operational | Module logging | Pipeline/cmdlet detail | Confirmed |
| 4104 | PowerShell/Operational | Script-block logging (full script text; `HostApplication=…\wsmprovhost.exe`) | Command content + process join | Confirmed |
| 1 (reused) | Sysmon | Process creation — `wsmprovhost.exe` as Image/ParentImage | Definitive target-host WinRM artifact | Confirmed |
| 3 (reused) | Sysmon | Network connection to/from 5985/5986 | Network-level corroboration | Confirmed (needs Sysmon 3 enabled) |

## 18.3 Base-paper reference

| Paper | ID | Key sections |
|---|---|---|
| HADES | arXiv:2407.18858 ("Detecting Active Directory Attacks via Whole Network Provenance Analytics"); published as IEEE TDSC 23(1):936–953, 2026, **DOI 10.1109/TDSC.2025.3611866**, title "HADES: Detecting **and Investigating** Active Directory Attacks via Whole Network Provenance Analytics" (⛔ …3611814 was wrong) | §IV-A auth anomaly; §IV-B logon-session tracing (incl. §IV-B.5 session linking — the WinRM mechanism, §3.6); §IV-C threat scoring; Figs 2–3, 10 (real output), 11 (CAD baseline) |
| TPPR | arXiv:2510.22191 (single-author **unreviewed preprint**; placeholder author block; weights not reported — Correction G) | §3.2 anomaly subgraph; §3.3 path reasoning (Eq 2–5); §3.4 scoring/merging (Eq 6–9); §4 evaluation; Figs 5–6, Tables 3–5 |
| Hopper | USENIX Security 2021 (HADES ref [64]); https://www.usenix.org/conference/usenixsecurity21/presentation/ho | **Primary backing for the logon-event Stage-1 gate** (Correction D) AND related work for identity-coherence (credential-switching signal). Detects lateral movement from login events, not Kerberos anomalies; covers pass-the-hash "so long as movement produces a login event." |
| Latte | MILCOM 2018; https://ieeexplore.ieee.org/document/8599726 | Backs using **4769 Kerberos service tickets** to build cross-host access graphs (corroborates gate rule R8/cross-host-TGS). |
| Bowman et al. | RAID 2020; https://www.usenix.org/conference/raid2020/presentation/bowman | Peer-reviewed authentication-graph anomaly detection — corroborates logon-event-based LMD. |
| log2vec | CCS 2019; https://dl.acm.org/doi/10.1145/3319535.3363224 | Logon-event graph embedding for detection — optional corroboration (ML-based, different technique from our rule-based gate). |
| NoDoze | NDSS 2019; https://www.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage/ | Backs the **two-stage cheap-filter → triage** paradigm (Correction D); 86% measured false-alarm reduction on 364 alerts. |
| HOLMES | IEEE S&P 2019; https://ieeexplore.ieee.org/document/8835390 | Coarse TTP signatures (recall) + correlation refinement (precision) — corroborates the two-stage design. |
| MITRE ATT&CK T1021 | attack.mitre.org/techniques/T1021/ | Authoritative source for the Event IDs / LogonTypes that signal lateral movement (RDP/SMB/WinRM) — the gate's trigger signals. |
| MITRE ATT&CK T1021.006 | attack.mitre.org | WinRM/PowerShell Remoting technique definition; Version 1.2, last modified 24 Oct 2025 |
| SigmaHQ WinRM rules | github.com/SigmaHQ/sigma | See §3.6.5 for specific rule filenames used as event-ID references |
| Caldera (MITRE) | caldera.readthedocs.io ; github.com/apache/caldera | Attack orchestration (**lab runs v5.3.0**; v5.1.0+ is the CVE-2025-27364 floor); operation log seeds `ground_truth.json`. Agents deployed via **Option D** scheduled-task pattern — see §19.2. |
| Atomic Red Team | atomicredteam.io ; github.com/redcanaryco/atomic-red-team | Single-technique validation/spot-check (`Invoke-AtomicTest`) |

> **Citation-weight guidance (for the thesis bibliography):** **Core 4 (load-bearing, cite prominently):** HADES (baseline), TPPR (scoring base), Hopper (logon-gate backing), MITRE T1021 (trigger signals). **Supporting 2 (cite once each):** NoDoze (two-stage paradigm), Latte (4769 cross-host). **Optional 3 (cite only if an examiner presses on whether logon-graph LMD is established):** Bowman, log2vec, HOLMES. Don't over-cite the optional three — they corroborate the *field*, not your specific rule-based method, and leaning on the ML-based ones (log2vec, Bowman) slightly muddies "my gate is rule-based, not ML."

> **Link-verification note:** the URLs above are canonical publisher/repository locations verified for paper *identity*, but DOI/venue pages occasionally move — confirm each resolves before finalizing the bibliography.

## 18.3.1 Evaluation-design & scenario-sufficiency references (scenario-backing pass)

These back the "is six enough / real / reasonable" argument in §14.7 and the per-scenario table in T3 §5. Grouped by how to use each, so the bibliography stays honestly scoped.

**A — Systems that establish evaluation-size norms (cite for "six is at/above the norm"):**

| System | Venue / Year | Scenario count used | How to cite it |
|---|---|---|---|
| HADES | IEEE TDSC 2025; arXiv:2407.18858 | 3 emulated datasets, TP=1 each | "The system I re-implement evaluated on three" — the anchor comparison |
| DEPCOMM | IEEE S&P 2022 | 6 lab (+8 DARPA TC) | Same-order lab-scenario count as this project |
| SLEUTH | USENIX Security 2017 | 8 | Small hand-built suite is accepted |
| HOLMES | IEEE S&P 2019 | 9 | Two-stage design + small scenario set |
| POIROT | ACM CCS 2019 | 10 | Attack-campaign reconstruction on ~10 cases |
| ATLAS | USENIX Security 2021 | 10 (2 Windows hosts) | Cross-host reconstruction on a tiny testbed |
| RapSheet | IEEE S&P 2020 | 3 Caldera campaigns | Caldera-built APT3/APT29 evaluation precedent |
| Kairos | IEEE S&P 2024 | Manzoor 6 + DARPA/OpTC; 14-scenario ablation | Per-scenario benign split + ablation precedent |
| MITRE APT29 Emulation Plan | CTID | 2 scenarios | A curated small set is accepted practice |
| Hopper | USENIX Security 2021 | 326 + 1 red-team / 780M logins | The *statistical-generalization* contrast (what you are **not** attempting) |

**B — Field surveys (cite for "small scripted labeled suites are the accepted methodology"):**
- **PIDS Survey** — Zipperle et al., *Provenance-based Intrusion Detection Systems: A Survey*, ACM Computing Surveys 55(7), Art. 135, 2022.
- **OmniSec SoK** — *SoK: Knowledge is All You Need … with LLMs*, arXiv:2503.03108, 2025. Both name the absence of realistic labeled datasets as the field's central bottleneck.

**C — Datasets / scale precedent (cite for testbed & labeling methodology ONLY — not detection scores):**
- **LMDG** — Mabrouk et al., arXiv:2508.02942, 2025. 25-VM AD testbed, Caldera-built, 7 LM scenarios / 35 embedded attacks, malicious events <1% of activity, Process-Tree-Labeling ground truth. **Dataset, not a detector — no P/R/F1.**
- **LANL** — Kent, *Comprehensive, Multi-Source Cyber-Security Events*, 2015 (csr.lanl.gov/data/cyber1). 58 days, 1.6B events, red-team labels — the scale baseline.
- **DARPA OpTC** — Anjum et al., arXiv:2103.03080. 1,000 Windows-10 hosts, ~17.4B events. Note: **lacks DC authentication logs**, so unusable for this approach's stitching (same reason HADES excludes it).

**D — Coverage authority (cite for "RDP/SMB/WinRM is the canonical Windows LM set"):**
- MITRE ATT&CK **T1021 Remote Services** + sub-techniques .001/.002/.006 (attack.mitre.org). Already in §18.3 for trigger signals; here it also authorizes the *choice of protocols*.

> **Guardrails (repeat of T3 §5.3, kept here for the bibliography step):** (1) never attribute P/R/F1 to HADES — it reports FP/FN counts + reduction rates only; (2) verify the HADES TDSC-2025 DOI suffix (secondary sources differ: …/3611814 vs …/3611866) against the final IEEE version; (3) LMDG is a dataset — cite for testbed/labeling, never detection performance; (4) scenario counts in table A reflect each paper's foregrounded evaluation set and can shift depending on whether DARPA sub-engagements are counted separately.

## 18.4 One-paragraph project description (for intro/defense)

> **handoff_17 version (use this for the proposal defense — Correction L):** *This project builds a small proof of concept that rebuilds lateral-movement attack paths across Windows machines from standard logs (Sysmon, Security, WinRM, PowerShell) and a Domain Controller. It starts a trace at each cross-host login over RDP, SMB or WinRM, links events across machines by login session, IP and time (confirmed by the DC's Kerberos tickets where available), labels steps with MITRE ATT&CK through Sigma rules, and ranks every candidate path by a path score adapted from TPPR that rewards attack-stage order. We propose one extra term — whether the moving account was signed in on its source machine when credentials were read there (exposed, not necessarily stolen) — and test whether it improves the ranking. It is evaluated on seven self-generated, ground-truth-labelled scenarios ×10 trials in a 5-VM lab with node-level Precision, Recall, F1 and FNR on the top-ranked paths, top-1 rate and MRR, against simpler versions of itself.*
>
> ⛔ handoff_15 version (still accurate for the thesis; its HADES-trigger argument is Q&A-only at the defense): *This work is a small-scale proof of concept for reconstructing lateral movement that uses stolen but valid credentials over a normal Kerberos sequence — movement that HADES's anomaly-based trigger is not designed to flag, so HADES never traces it. It triggers on the lateral-movement logon itself (RDP, SMB, WinRM), links events across hosts with HADES-style logon-session stitching and the DC's LogonGuid, labels steps with MITRE ATT&CK via Sigma rules, and ranks the resulting cross-host paths by ATT&CK order using TPPR-style scoring. It is evaluated on self-generated, ground-truth-labeled scenarios in a 5-VM lab by node-level Precision, Recall, F1 and FNR, with ablations; an identity-coherence term — whether the moving account was exposed on its source host before the move — is tested as an optional extension.*
>
> ⛔ Previous version (contains the false "HADES stitches identically" claim — Correction E):
> *This work reimplements a scoped version of HADES's identity-based cross-host tracing — the authentication-anomaly trigger and logon-session stitching over RDP and SMB — producing a cross-host provenance graph. On top of this graph it introduces a TPPR-inspired sequence-reasoning layer that reconstructs the true ordered attack path, extended with a novel identity-coherence term that flags whether the identity crossing each host boundary was compromised on the previous host. HADES stitches compromised-credential movement and legitimate reuse identically and never distinguishes them; the identity-coherence term makes that distinction explicit. The term is a proposed contribution, grounded in HADES's credential-access-enables-movement insight and positioned against Hopper's credential-switching signal, and is validated empirically via ablation against reconstruction completeness on self-generated, ground-truth-labeled attack scenarios that include identity-ambiguous cases.*

---

# 19. Phase 3 Dry-Run Record (execution log — added in handoff_12)

> **What this section is.** A self-contained record of the Phase 3 dry-run campaign so a fresh chat understands *what has actually been run in the lab* versus what is still only designed. Everything in §0–§18 is design/rationale and is unchanged. This section is the execution residue: per-scenario pass status, the one genuinely new architectural element the runs surfaced (Option D), the environmental findings that become parser rules, and the open items that gate Phase 4. **Primary sources:** `findings_s01_s04.md`, `findings_s05.md`, `findings_s06.md`, `findings_s07.md`. When those disagree with memory, they win; when they disagree with T3's *design*, T3 wins and the finding is a capture note.

## 19.1 Headline status

**All 7 scenarios dry-run executed and telemetry-verified.** Phase 3 (manual/one-shot dry-runs) is **complete**. The purpose of Phase 3 was *not* to measure the system — the parser does not exist yet — but to prove each scenario reliably emits the exact telemetry T3 promises, so the `.evtx` captures can seed parser development and the Phase 4 automated trials.

| Scenario | Type | Protocol | Exec mode | Lab date | Status | Source |
|---|---|---|---|---|---|---|
| **S01** | RDP single-hop | RDP 3389 | Manual | 2026-09-24 | ✅ complete | findings_s01_s04 |
| **S02** | SMB + remote service | SMB 445 | Caldera | 2026-09-24 | ✅ complete | findings_s01_s04 |
| **S03** | WinRM / PSRP | WinRM 5985 | Caldera | 2026-09-24 | ✅ complete | findings_s01_s04 |
| **S04** | Ablation — **over-fire** control | Mixed (SMB) | Caldera + **manual** Track A | 2026-09-24 | ✅ complete | findings_s01_s04 |
| **S05** | Multi-hop SMB→WinRM | SMB + WinRM | Caldera (2 ops) | 2026-10-12 | ✅ complete | findings_s05 |
| **S06** | Benign baseline (FPR=0) | WinRM + SMB | Caldera | 2026-10-12 | ✅ complete | findings_s06 |
| **S07** | Dual-compromise — **under-fire** control | SMB ×2 | Caldera | 2026-10-12 | ✅ complete | findings_s07 |

**Thesis-critical result:** the two scenarios the `w₃` contribution lives or dies on both captured cleanly —
- **S04 (over-fire):** Track B (`svc_backup`, with LSASS dump) and Track A (`admin_it`, no dump) ran concurrently to EP-02 with a **3-second overlap** between the two service installs (requirement was ≤10 s), reached on attempt #5 after four timing misses. Track A was executed **manually** (not via Caldera) so its process ancestry differs from Track B — the enrichment that makes the ablation fair. One dump, two Sysmon-10 records for `svc_backup`, zero dumps for `admin_it`: confirmed.
- **S07 (under-fire):** two *both-malicious* paths (`svc_backup`→`XferService`, `svc_sql`→`SyncService`) to EP-02, each with its own LSASS root. Both must score `w₃=1.0`; neither may be suppressed. Captured on first attempt. (Actual gap between paths was ~110 s, not the spec's ~10 s, because of Caldera polling — judged acceptable since the graph engine must disambiguate regardless of gap; tightenable for Phase 4 by merging into one ability with `Start-Sleep`.)

Together with **S06** (benign look-alikes, expected `w₃=0.0` throughout), the suite now has both error directions of `w₃` covered — false-positive control (S04 + S06) and false-negative control (S07) — which is exactly the two-direction validation a reviewer expects of a new scoring term (ties back to §14.7.5 and T3 Scenario 07).

## 19.2 Option D — agent architecture (the key execution-level discovery)

**This is the most important thing the dry-runs added that the design docs did not already contain.** It belongs in the master handoff because identity attribution is a *precondition* for the entire thesis, not an implementation detail.

**Problem.** When the Caldera Sandcat agent runs as a service under SYSTEM, it inherits the **machine-account token** (`EP-01$`). Every outbound `sc.exe` / SMB / SCM-RPC call then authenticates as `EP-01$`, so the `4624` (logon) and `5145` (share access) events on the target show the attacker identity as **`EP-01$` instead of `svc_backup`**. That silently breaks identity-based stitching — and identity is the whole basis of the `w₃` term. A system that can't see `svc_backup` crossing the host boundary has nothing to score.

**Solution (Option D).** Deploy each agent as a **Windows Scheduled Task that runs the Sandcat binary under a specific domain-account credential**, giving the process a full domain-user token. Named "Option D" because options A–C (service under SYSTEM, `runas`, token manipulation) each failed to attribute identity correctly.

**Agents as deployed (baked into the `clean-joined-logging-verified` snapshot):**

| Task | Host | Runs as | Caldera group | Used by |
|---|---|---|---|---|
| `SandcatAgent` | EP-01 | `LAB\svc_backup` | `foothold` | S01, S02, S04-B, S05-hop1, S07-X |
| `SandcatAgent_admin` | EP-01 | `LAB\admin_it` | `foothold_admin` | S03, S06 |
| `SandcatAgent_sql` | EP-01 | `LAB\svc_sql` | `foothold_sql` | S07-Y |
| `SandcatPivotAdmin` | EP-02 | `LAB\admin_it` | `pivot_admin` | S05-hop2 (EP-02 as pivot source) |
| `SandcatAgent` | EP-02 | `LAB\ENDPOINT-02$` (machine acct) | `red` | legacy / not used for identity scenarios |

All tasks persist across snapshot revert and reconnect on boot. Agent binary is `C:\Users\Public\splunkd.exe` (a renamed Sandcat — **not** `sandcat.exe`; the name mismatch cost debugging time in S05). **S02 was the smoke test that validated Option D** — it was the first scenario to confirm the agent authenticates as `svc_backup` rather than `EP-01$`.

**Consequence for the parser / scoring:** the identity on the `4624`/`5145`/`7045` `SubjectUserName` fields is trustworthy *because of* Option D. If a future run shows `EP-01$` where a domain account is expected, the agent reverted to machine-account context and the capture is void.

## 19.3 Cross-scenario environmental findings (these become parser Stage-1 rules)

The dry-runs surfaced real-telemetry behavior that the idealized T3 per-event payloads do not show. Each maps to a parser rule and is already reflected in the `findings_s01_s04.md §7–§8` gate design.

| # | Finding | Severity | Parser consequence |
|---|---|---|---|
| **E1** | **VBoxService.exe accesses lsass.exe ~every 5 s** (3 Sysmon-10 events / 5 s), `GrantedAccess 0x1400`, `SourceUser NT AUTHORITY\SYSTEM`. Floods the Sysmon-10 channel and caused false "no dump" diagnoses in S04. | HIGH | **Suppress** Sysmon 10 where `SourceImage CONTAINS 'VBoxService.exe'`. Always query with `-MaxEvents 100`+ and filter positively for `rundll32` + `0x1410\|0x1fffff`. |
| **E2** | **svchost.exe SYSTEM access to lsass** at boot, `GrantedAccess 0x1000`. | MED | Suppress Sysmon 10 where `SourceImage CONTAINS 'svchost.exe' AND SourceUser = SYSTEM`. |
| **E3** | **Attack-dump signature confirmed live:** one comsvcs dump → **two** Sysmon-10 records, `GrantedAccess 0x1FFFFF` **and** `0x1410`, `SourceImage rundll32.exe`, domain `SourceUser`. Masks observed on both EP-01 and EP-02. | — | R1 must match **presence** of LSASS access with a domain SourceUser, accepting either mask — **not** an exact-mask equality (T3's illustrative `0x1F0FFF` would miss real dumps). One dump = two records is expected, not a double-count. |
| **E4** | **RDP by IP on Win11 NLA logs LogonType 3, not 10.** NLA pre-auth creates a Type-3 network logon; Type 10 only appears once the graphical session is up; Type 7 on reconnect; Type 11 cached. | MED | R5 (RDP) must accept a remote-sourced **Type 3** as RDP evidence when corroborated by **Sysmon 3** (`DestPort 3389`, `RuleName RDP`). Don't require Type 10. (Already noted in §7.2 R5 caveat — now confirmed live in S01.) |
| **E5** | **Caldera marks every SMB service-install "failed" (error 1053).** Stub payloads (`PktDrop.exe`, `Stage.exe`, `Xpay/Ypay.exe`, `HealthAgent.exe`) don't answer the SCM start handshake. | LOW (cosmetic) | Judge success by **telemetry, not Caldera status**: `[SC] CreateService SUCCESS` in stdout + Event **7045** present. `run_trials.ps1` must not treat 1053 as a failed trial. |
| **E6** | **WinRM over Kerberos needs a hostname, not an IP** — Kerberos needs the `WSMAN/Endpoint-03.lab.local` SPN; an IP has no SPN and NTLM fallback needs TrustedHosts (unset). S03 first attempt failed on this. | MED | All WinRM abilities target `Endpoint-XX.lab.local`. (S03's ability YAML still has the IP — see §19.5 open items.) |
| **E7** | **EP-03 must be powered on** for S03/S05 or WinRM fails silently. Pre-flight `Test-WSMan Endpoint-03.lab.local`. | — | Runbook pre-flight; no parser impact. |

Three more operational lessons (no parser impact, but they gate reliable capture):
- **E8 — `$env:VAR` is blank inside scheduled-task agents.** Machine-scope env vars are not in a scheduled-task process's inherited block. Use `[Environment]::GetEnvironmentVariable('NAME','Machine')` (reads the registry directly). Discovered in S05; applies to every credential-bearing ability.
- **E9 — Caldera v5.3.0 strips newlines from multi-line `command: |` YAML**, concatenating lines (`(Get-Process lsass).Idrundll32.exe`). All ability commands must be **single-line, semicolon-joined**.
- **E10 — machine-account trust desync** after independently re-snapshotting one VM (`Test-ComputerSecureChannel = False`, errors 0x80090322 / 1789). Fix: re-snapshot **all 5 VMs together** after confirming trust; add `Test-ComputerSecureChannel` to Phase-4 pre-flight. (S06.)

## 19.4 `w₃` expectation table (confirmed achievable across the suite)

Every scenario's expected identity-coherence outcome was confirmed *reachable* from the captured telemetry (the dump-precursor is present exactly where it should be, absent exactly where it should be):

| Scenario / path | LSASS dump precursor? | Expected `w₃` | Role |
|---|---|---|---|
| S02 `svc_backup`→EP-02 | ✅ | 1.0 | baseline TP |
| S03 `admin_it`→EP-03 | ✅ | 1.0 | TP, WinRM |
| S04-A `admin_it`→EP-02 (benign) | ❌ | 0.0 | **over-fire control** |
| S04-B `svc_backup`→EP-02 | ✅ | 1.0 | paired attack |
| S05-H1 `svc_backup`→EP-02 | ✅ | 1.0 | multi-hop |
| S05-H2 `admin_it`→EP-03 | ✅ (dump on EP-02 pivot) | 1.0 | cross-protocol hop |
| S06 all `admin_it` benign | ❌ | 0.0 | **FPR=0 control** |
| S07-X `svc_backup`→EP-02 | ✅ | 1.0 | **under-fire** path 1 |
| S07-Y `svc_sql`→EP-02 | ✅ | 1.0 | **under-fire** path 2 |

> ⚠️ **handoff_15:** these expected values assume §12.4's definition (**the account that ran the dump**). Under the thesis/slide definition (**every account signed in at dump time**), S04-A may score 1.0 if `admin_it` had a logon session on EP-01 when `svc_backup` dumped LSASS (`SandcatAgent_admin` runs as `admin_it` on EP-01). Verify before using this table (Correction H.2).

Note the subtlety the parser must handle (from S07): both EP-01 LSASS dumps run under the *same* foothold-agent process identity; the *dumped target credential* (svc_backup vs svc_sql) is internal to the dump. The two dumps must be keyed by **identity + timestamp/PID**, then each correlated to the specific EP-02 `4624` that used that identity — not collapsed into one root.

## 19.5 Open items that gate Phase 4 (carried from the findings files)

**Ability-YAML audit (must fix before automated trials) — status from `findings_s07.md §12.2`:**

| Ability file | `$env:`→registry | multi-line→single | other | status |
|---|---|---|---|---|
| `lab-lsass-dump-s02.yml` | n/a | ❌ | ❌ **still references `rdrleakdiag.exe`** → change to comsvcs | **not fixed** |
| `lab-smb-service-s02.yml` | ✅ | ✅ | — | done (fixed in S05) |
| `lab-lsass-dump-s03.yml` | n/a | ❌ | — | not fixed |
| `lab-winrm-s03.yml` | ❌ | ❌ | ❌ **uses IP not hostname** (E6) | not fixed |
| `lab-lsass-dump-s04b.yml` | n/a | ❌ | — | not fixed |
| `lab-smb-updater-s04b.yml` | ❌ | ❌ | — | not fixed |
| S05 / S06 / S07 abilities | ✅ | ✅ | ✅ | done |

**Other Phase-4 prerequisites (none started):**
1. **`run_trials.ps1`** — the automated trial runner (10× per scenario). Needs: 1053-cosmetic handling (E5), S05 two-operation sequencing, `Test-ComputerSecureChannel` pre-flight (E10), per-trial snapshot revert for log isolation, UTC-Z manifest timestamps.
2. **`run_trials_3.ps1` reconciliation** — still uses `rdrleakdiag.exe`; change to comsvcs to match every ability.
3. **The parser (Half 2 — the actual thesis contribution).** Not started. Build order unchanged: parse `.evtx` → Stage-1 gate (suppress E1/E2 noise, detect R1–R5) → stitch (HADES logon-session; source link = IP + time + port ↔ Sysmon 3 / command process; DC confirmation = LogonGuid — Correction I) → label (Sigma) → score (TPPR + `w₃`) → evaluate (P/R/F1 + ablation). Dry-run `.evtx` captures are the development input.

**Cosmetic doc inconsistency to be aware of (not a lab problem):** T3's per-event payloads use `2026-09-15` timestamps; the S01–S04 lab ran `2026-09-24`; S05–S07 ran `2026-10-12`. These are illustrative-vs-actual, not a contradiction — but ground-truth manifests must use each run's real UTC-Z times, not T3's placeholders.

## 19.6 One-paragraph "where the project stands" (for a fresh chat)

> *Design is complete and all seven evaluation scenarios have been dry-run executed in the live 5-VM lab (Caldera v5.3.0 on a flat `192.168.50.0/24` AD domain `lab.local`), with telemetry verified against the T3 spec. The decisive enabler was **Option D** — deploying each Caldera agent as a scheduled task under a specific domain account — without which attacker identity logs as the machine account and the whole identity-coherence idea has nothing to score. The two ablation scenarios that carry the contribution both captured cleanly: S04 (over-fire, benign vs. malicious concurrent, 3 s overlap, Track A run manually) and S07 (under-fire, two concurrent compromised identities, both must flag). What remains is all of "Half 2": fix the six un-audited ability YAMLs, write `run_trials.ps1`, run Phase 4 (10× per scenario), and build the parser/stitcher/scorer that is the thesis's actual engineering contribution — none of which is started.*

---

# 20. Phase 4 Execution Record (added in handoff_13)

> **What this section is.** The record of Phase 4 — running each scenario N times to produce captures for the parser. It covers the *collection* side only; no scoring has been run (the parser does not exist). **Primary source:** `phase4_plan.md` (living plan + decision log, kept current). When this section and `phase4_plan.md` disagree, `phase4_plan.md` wins. Phase 4 changes **no thesis design**; it is data collection.

## 20.1 Headline status (2026-10-15)

| Item | Status |
|---|---|
| Lab re-hosted across 3 PCs (permanent) | ✅ |
| Ability YAMLs patched (9 files) | ✅ |
| Collection tooling built + hardened | ✅ |
| One timed trial → **N = 10** | ✅ (≈ 2.5 min/trial) |
| **S02 ×10 collected** | ✅ (trials 01–10 on the share, 4 host folders each) |
| S01, S03, S04, S05, S06, S07 ×10 | ⬜ not yet run |
| C4 contamination grep (one-time proof) | ⬜ not yet run |
| Per-trial attack-success verification | ⬜ **not yet done** — see §20.8 |
| `clean-aligned` snapshot re-baseline | ⬜ recommended, not done — see §20.7 |
| Parser (Half 2) | ⬜ not started |

## 20.2 Topology — 3 hosts, flat `192.168.50.0/24`

| Host | Hypervisor | Owns | Role |
|---|---|---|---|
| **PC-A** (`DESKTOP-VSUAVJ5`, workgroup) | VirtualBox | DC-01 `.10`, Caldera `.50` | conductor + **hosts the share** `\\192.168.50.99\evtx` = `C:\evtx_share` |
| **PC-B** | VirtualBox | EP-01 `.21` | foothold origin of every scenario |
| **PC-C** | VMware Workstation | EP-02 `.22`, EP-03 `.23` | targets; VMs encrypted (Win11 vTPM) → `vmrun -vp` |

- **PC-C `.vmx` filenames are inverted vs. roles:** EP-02 (.22) = `E:\VMware\Endpoint-02\Endpoint-03.vmx`; EP-03 (.23) = `E:\VMware\Endpoint-03\Endpoint-02.vmx` (verified via `getGuestIPAddress`). Do not "correct" them.
- No host can revert another host's VMs (`VBoxManage` / `vmrun` are host-local), so the tooling is **one worker per host + one conductor**.
- **Revert policy:** DC-01, EP-01, EP-02, EP-03 are **reverted every trial**. **DC-01 must revert** — its Kerberos 4768/4769 and LogonGuid state must be clean per trial; skipping the revert would carry state across trials and contaminate stitching. **Caldera is persistent** (never reverted — a revert once wiped its API key and the re-applied abilities).
- **Snapshots:** VBox hosts revert with `restorecurrent` (both VBox hosts have *duplicate-named* snapshots, so name-based restore is ambiguous). VMware revert is by exact name: EP-02 = `clean-joined-logging-verirfied7` *(sic — the typo is real)*, EP-03 = `clean-joined-logging-verified 3` *(trailing digit after a space)*. Do not click "Take Snapshot" on A/B VMs mid-campaign — it moves the `restorecurrent` pointer.

## 20.3 The tools

| Tool | Host | Role |
|---|---|---|
| `revert_and_wait.ps1 -Owner A\|B` | A, B | **Looping worker** (VirtualBox) |
| `revert_and_wait_vmware.ps1` | C | **Looping worker** (VMware) |
| `fire_scenario.ps1` | A | **Conductor**: REST-fire op(s) → manifest row → signal GO → wait for collection |

Retired: `run_trials.ps1` / `run_trials_3.ps1` (single-host 5-VM orchestrators), `export_trial.ps1` and `collect_trial.ps1` (superseded by the in-worker collect step).

**Worker cycle (repeats forever until Ctrl+C):** clear own `READY` → revert own VMs → boot → wait reachable (DC: TCP 389 then a 45 s settle; endpoints: TCP 445; Caldera: TCP 8888) → write `READY_<owner>` → **wait for GO** → **collect own guests' logs** → clear `READY_<owner>` → write `COLLECTED_<owner>=<trial>` → loop.

**Collection mechanism:** after the attack, the worker opens a **remote WinRM session from the host into each of its guests** (as `LAB\admin_it`), runs `wevtutil epl` for five channels (Security, System, Sysmon/Operational, WinRM/Operational, PowerShell/Operational) to a local staging dir, then authenticates to the share (`net use` as `DESKTOP-VSUAVJ5\evtxwriter`) and copies to `\\192.168.50.99\evtx\<Sxx>\trial_NN\<HOST>\`. No VM login by a human; no export script baked into any snapshot.

**Conductor (one scenario, N trials, one line):**
```powershell
1..10 | % { .\fire_scenario.ps1 -Scenario S02 -Trial $_ -WaitReady }
```
`-Trial N` is just the label/folder number for that one call (`trial_NN`); the range supplies the loop. `-Trial 0` is rejected (falsy in PowerShell) — start at 1. To resume after stopping partway, re-run with the remaining range (e.g. `5..10`) rather than the full `1..10`, to avoid re-firing completed trials.

**Signaling protocol (shared-file over the share, race-safe):** flags live in `\\192.168.50.99\evtx\ready\`. Conductor waits for `READY_A`, `READY_B`, `READY_C` (fresh within 30 min) before firing; after firing it clears any stale `COLLECTED_*` **before** writing `GO.txt = "<scenario> <trial>"` (so a leftover flag from a prior trial can't be mistaken for completion); each worker sees `GO`, collects, writes `COLLECTED_<owner>=<trial>`; conductor waits for all three to match the current trial number before moving on.

## 20.4 N — decided

**N = 10, all scenarios.** Set from one timed live S02 trial: fire → all collected ≈ 2.5 minutes. Comfortably under any time budget; the floor of 5 (from §14.7's honest-statistics guidance) was not needed.

## 20.5 Manual-step scenarios

S01 (RDP, no Caldera adversary) and S04 (ablation Track A) still require a human action mid-loop. `fire_scenario.ps1` pauses and prompts; the operator performs the step and presses Enter to resume. This does not block the auto-loop — it just means S01/S04 campaigns need an operator present, unlike S02/S03/S05/S06/S07 which can run fully unattended once started.

## 20.6 Live failure modes encountered during S02 ×10, and their fixes

| Symptom | Cause | Fix now in place |
|---|---|---|
| `script is not digitally signed` | PowerShell execution policy | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` per window, each host |
| `revertToSnapshot` fails on a name that looks right | snapshot name guessed instead of read | always confirm with `listSnapshots`; use the exact VMware names in §20.2 |
| `COLLECT FAILED ... TrustedHosts` | WinRM client-side trust not configured on the host | `Start-Service WinRM; Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.50.*' -Force` on **every** host before starting its worker |
| One guest's logs silently missing from a trial, worker still reported success | collector ran before that guest's WinRM listener (port 5985) was up; failure was swallowed | workers now **wait for port 5985**, **retry the collect 3×**, and on persistent failure print a visible `MISSING` warning and write a `FAILED_<owner>_<trial>` marker instead of silently succeeding |
| DC-01 logs missing from early trials | same TrustedHosts gap, on PC-A | fixed; affected trials were re-fired |
| Cross-host SMB step hits error 1789 (machine-account trust) | snapshot misalignment between DC-01 and the endpoints (same root cause as E10 in §19.3) | worked around for S02 using the latest available snapshots; **not fully resolved** — see §20.7 |
| Manifest has duplicate rows for a re-fired trial | CSV append-only logging | dedupe rule: keep only the **last** row per `(scenario, trial)`; the share only ever holds the latest overwrite of that trial's logs, so earlier rows point to data that no longer exists |

**Trial-completeness check** (run after each scenario's ×10):
```powershell
Get-ChildItem C:\evtx_share\S02 -Directory | % {
  $n = (Get-ChildItem $_.FullName -Directory).Count
  if ($n -lt 4) { "$($_.Name): only $n/4 hosts" }
}
```
Prints nothing on a clean campaign; any line means that trial must be re-fired.

## 20.7 Outstanding risk — `clean-aligned` re-baseline not yet done

E10 (§19.3) — machine-account trust desync from independently re-snapshotting one VM — recurred live during S02. The workaround (reverting to whatever recent snapshots exist) got S02 done but does not remove the root cause for the remaining scenarios, particularly ones with more cross-host steps. **Recommended before continuing:** repair trust on all four domain-joined VMs (`Test-ComputerSecureChannel -Repair`), set `DisablePasswordChange=1`, set `PasswordNeverExpires` on the service accounts, then **re-snapshot all four VMs together** under one new name (e.g. `clean-aligned`) so they share a consistent trust state. Not yet done as of this handoff.

## 20.8 Gap — no per-trial attack-success verification yet

`ground_truth.yaml` (§20.9) encodes the **intended** path per scenario — what was launched, not confirmation it fired completely in a given trial. S02 trial 2 already demonstrated the gap in practice (truncated by the 1789 error mid-campaign, before the fix). **Needed before scoring:** a verifier that reads each trial's real `.evtx`, confirms the scenario's anchor events (the specific EIDs in `ground_truth.yaml`) actually appear inside `[start_utc, end_utc]`, and flags trials where a step is missing — so scoring is never run against a trial that silently under-fired. This must be an independent signature check on raw events, not derived from the system being evaluated, or the evaluation becomes circular. Not yet built; planned as `verify_truth.py`.

## 20.9 Ground-truth draft exists but is NOT yet trustworthy — corrections needed against §19

A first-pass `ground_truth.yaml` + `GROUND_TRUTH_README.md` + `score_paths.py` were drafted for the eventual P/R/F1 evaluation, **before** this handoff's author cross-checked them against §19.2's Option D agent table. They should **not** be used as-is. Known corrections required:

| Draft said | §19.2 says | Fix needed |
|---|---|---|
| Generic identity `svc_it` | The real accounts are `svc_backup` (foothold/S02/S04-B/S05-hop1/S07-X), `admin_it` (S03/S06/S05-hop2), `svc_sql` (S07-Y) | rename every identity placeholder to match §19.2's table exactly |
| S07's second identity marked `svc_ops` (placeholder) | §19.4/§19.2 confirm it is `svc_sql` | fix S07 identity |
| Some host/edge endpoints marked `# CONFIRM` | §19 + T3 are authoritative | re-derive every edge from §19's per-scenario findings and T3, not guessed |

**Action before any scoring work resumes:** rewrite `ground_truth.yaml` identity and edge fields directly from §19.2's agent table and T3, remove the placeholder values, and only then build §20.8's verifier against it.

## 20.10 Phase 4 decision log (supersedes/extends §19.5's open-items list)

| Decision | Value | Date |
|---|---|---|
| Lab hosting | 3 physical PCs, permanent (not a temporary split) | 2026-10-14 |
| All 9 ability YAMLs | patched, §19.5's audit list closed | 2026-10-14 |
| `run_trials.ps1` / `run_trials_3.ps1` | retired, replaced by §20.3 worker + conductor | 2026-10-14/15 |
| DC-01 revert policy | revert every trial (not persistent) | 2026-10-15 |
| Caldera revert policy | persistent, never reverted | 2026-10-14 |
| Collection method | remote WinRM from host into guests, no manual VM login | 2026-10-15 |
| Signaling method | shared-file READY/GO/COLLECTED handshake | 2026-10-15 |
| N | 10, all scenarios | 2026-10-15 |
| S02 campaign | ×10 collected and verified complete (4 host folders/trial) | 2026-10-15 |
| `clean-aligned` re-baseline | recommended, not yet done | 2026-10-15 open |
| Per-trial attack-success verification | not yet built | 2026-10-15 open |
| Ground-truth draft identity/endpoint errors | known, not yet corrected | 2026-10-15 open |

## 20.11 Immediate next actions for a fresh chat picking this up

1. Decide whether to do the §20.7 `clean-aligned` re-baseline before continuing (reduces risk for the remaining 6 scenarios, especially ones with more cross-host steps).
2. Run S01, S03, S04, S05, S06, S07 ×10 using the §20.3 tools (same one-line conductor pattern, scenario name changed; S01/S04 need an operator present for the manual step).
3. Run the one-time C4 contamination grep on a completed trial (method is in `phase4_plan.md` §11).
4. Correct `ground_truth.yaml` per §20.9, then build `verify_truth.py` per §20.8.
5. Once all 7 scenarios' ×10 are collected and verified, Phase 4 is done and Half 2 (the parser) begins.

---

---

# 21. Phase 4 Execution Record — Session 2 (added in handoff_14, 2026-10-28)

> This section supersedes §20's in-progress status, §20.9's "ground truth not trustworthy"
> open item (now RESOLVED), and §20.11's action list. §0–§19 design content unchanged.

## 21.1 Headline status (2026-10-28)

| Scenario | Trials | Status |
|---|---|---|
| S01 | 0/10 | **PENDING — manual RDP** (no Caldera adversary; operator must run it) |
| S02 | 10/10 | done |
| S03 | 10/10 | done |
| S04 | 10/10 | done (Track A fired manually each trial) |
| S05 | 10/10 | done (**after a full Caldera rebuild — see §21.3**) |
| S06 | 10/10 | done (benign control) |
| S07 | 10/10 | done (dual identity) |

**Phase 4 is one scenario (S01 ×10) away from complete.**

## 21.2 Automation — final form (supersedes §20.3 tooling)

The §20.3 worker+conductor evolved into a **combined auto-looping** design:

- **`revert_and_wait.ps1`** (VBox, Owners A/B) and **`revert_and_wait_vmware.ps1`** (VMware, C):
  one looping script per host — *clear READY → revert + boot + wait (445) → write READY →
  wait for GO → collect own guests' .evtx over remote WinRM → clear READY → write COLLECTED → loop.*
  No VM login. Each host runs it **once** and leaves it looping.
- **Hardened collector** (added after a silent EP-03 miss on S05): waits for WinRM (5985),
  **retries 3×**, and on real failure prints red `MISSING` + drops `FAILED_<owner>_<trial>.txt`.
- **`fire_scenario.ps1`**: auto-loops via `1..N | % { .\fire_scenario.ps1 -Scenario Sxx -Trial $_ -WaitReady }`,
  writes `GO`, waits `COLLECTED_A/B/C`, and now carries a **0-decision guard** — after each op it
  queries Caldera for executed links and prints `abilities executed (links): N`, or red
  `0 DECISIONS … TRIAL VOID` + a `ZERODEC_*` marker. A `links` column was added to `manifest.csv`.

**Run pattern (per campaign):** three hosts each start their worker once; PC-A runs the one-line
loop in a second window. S01/S04 pause mid-loop for the manual step.

## 21.3 S05 was MISSING from Caldera — rebuilt this session

Symptom: S05 operations finished instantly with **0 decisions** (empty op graph). Root cause:
S05's adversaries **and** abilities were lost in an earlier Caldera revert and never restored
(only the other 5 scenarios were rebuilt). This is the single most important execution-level
finding of the session.

**Rebuilt (two-hop WinRM, matching findings_s05):**
- Abilities `lab-s05-hop1-winrm.yml` / `lab-s05-hop2-winrm.yml` — **`executors:` list format**
  (Caldera 5.3 silently rejects the legacy `platforms:` dict).
- Adversaries `lab-s05-hop1-adversary.yml` / `lab-s05-hop2-adversary.yml` — **flat mapping**
  (no leading `-`; adversary YAML ≠ ability YAML format).
- UUIDs hardcoded to what `fire_scenario` expects: Hop1 `c324f4e0-…`, Hop2 `9d17f592-…`.
- Installed under `~/caldera/plugins/stockpile/data/{abilities/lateral-movement,adversaries}/`,
  `sudo systemctl restart caldera`, verified via `/api/v2/adversaries/<id>`.
- Correct run = `links: 1` per hop (one agent per group).

**Lesson for any future Caldera content:** ability = list with `executors:`; adversary = flat
mapping with `atomic_ordering:`. Verify load via the API, not just the UI dropdown.

## 21.4 Caldera operations do NOT persist across restart (clarified)

Operations are in-memory; every `systemctl restart` empties the operations dropdown and old
`op_id`s 404. **This does not lose ground truth** — scoring uses `ground_truth.yaml` (answer key)
+ collected `.evtx` (per-trial data) + `manifest.csv` (window). The Caldera operation report is
only a supplementary record; if wanted, pull it **immediately** after each op
(`POST /api/v2/operations/{id}/report`) before any restart. (Closes §20.8's concern: per-trial
attack-success is now confirmed by the `links` count + presence of anchor events in the EVTX.)

## 21.5 Ground truth CORRECTED — §20.9 RESOLVED

`ground_truth.yaml` was rewritten against `findings_s01_s04/_s05/_s06/_s07.md`. All placeholder
identities resolved and **four structural path errors** fixed.

**Identities (real accounts, pw `***`, Domain Admins):**
`svc_backup` (foothold: S01/S02/S04-TrackB/S05-hop1/S07-X), `admin_it` (foothold_admin:
S03/S04-TrackA/S05-hop2/S06), `svc_sql` (foothold_sql: S07-Y).

| Scenario | Error fixed |
|---|---|
| S01 | was admin_it / CALDERA→EP-01 → now **svc_backup, EP-01→EP-02 RDP** (4624 Type 10) |
| S02 | LSASS root moved to **EP-01** (was EP-02) |
| S03 | target **EP-02→EP-03**; LSASS root added on EP-01 |
| S04 | redefined: **2 identities** — Track B `svc_backup` (has LSASS) = true path; Track A `admin_it` (no LSASS) = distractor w₃ must NOT elevate (over-fire control) |
| S05 | svc_backup hop1 + admin_it hop2; both LSASS roots added (EP-01 + EP-02) |
| S07 | Path Y target **EP-03→EP-02** (both paths hit EP-02); svc_backup / svc_sql |

**Scoring implication:** `cred_access_lsass` (LSASS-dump) edges are now part of the true edge set
(S02/S03/S04 = 2 edges, S05 = 4, S07 = 2 same-key edges separated by identity). **The TPPR
predicted output must emit LSASS-dump edges** or they score as false negatives. S07's two edges
share an edge-key on purpose — the under-fire test; the scorer's multiset + identity-aware keys
handle it.

## 21.6 Decision log additions (extends §20.10)

| Decision | Value | Date |
|---|---|---|
| Automation final form | combined looping worker + auto-collect + 0-decision guard | 2026-10-28 |
| Collect hardening | WinRM-wait + 3× retry + MISSING/FAILED markers | 2026-10-28 |
| S05 Caldera content | rebuilt (two-hop WinRM), executors+flat-mapping formats | 2026-10-28 |
| S02–S07 ×10 | collected (S05 after rebuild) | 2026-10-28 |
| S01 ×10 | still pending (manual RDP) | 2026-10-28 open |
| Ground truth | corrected & verified against findings (§20.9 closed) | 2026-10-28 |
| Caldera op persistence | confirmed ephemeral; not relied on for ground truth | 2026-10-28 |

## 21.7 Known watch-items (carry forward)

1. **`conf/default.yml` PermissionError** on each restart (from `chattr +i`) — recovers, auth works;
   only act if `fire_scenario` starts returning 401s.
2. **TrustedHosts + WinRM** must be set on each host per session before collecting:
   `Start-Service WinRM; Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.50.*' -Force`.
3. **VMware snapshot names** are exact-string + quirky: EP-02 `clean-joined-logging-verirfied7`
   (typo, no space), EP-03 `clean-joined-logging-verified 3` (trailing space).
4. **Manifest has duplicate rows** from re-fires → dedupe to `manifest_clean.csv` (keep last per
   scenario,trial) before scoring.
5. **Older S02–S07 trials predate the 0-decision guard** — spot-check the manifest's `links` column
   (or re-confirm anchor events in the EVTX) so no banked trial was silently empty.

## 21.8 Immediate next actions (supersedes §20.11)

1. **Run S01 ×10 manually** — RDP EP-01→EP-02 as `svc_backup`, **after a clean revert** (so it logs
   4624 Type 10 fresh, not Type 7 reconnect). Collect via the same worker flow.
2. **Dedupe `manifest.csv`** → `manifest_clean.csv` (re-fires appended rows; share holds only the
   latest overwrite — earlier rows point to gone data).
3. **Audit completeness:** every `trial_NN` has 4 host folders; every manifest row `links ≥ 1`;
   no leftover `ZERODEC_*` / `FAILED_*` markers in `…\ready\`.
4. **Half 2 begins:** build the TPPR parser → `predicted/<Sxx>/trial_NN.json`; ensure it emits the
   `cred_access_lsass` edges; run `score_paths.py --ground-truth ground_truth.yaml --predicted
   ./predicted --manifest manifest_clean.csv`.
5. Validate w₃ at the controls: **S04 over-fire** (admin_it Track A not elevated — ⚠ may be elevated under Correction K, see §16 0b), ⛔ ~~**S06 FPR=0**~~ → **S06 benign paths rank below attack paths** (Correction J),
   **S07 under-fire** (two identities, not collapsed), **S05 chain** (two hops connected).

*End of handoff_14. Design sections §0–§18 unchanged from handoff_11. §19 = Phase 3 dry-run. §20 = Phase 4 collection campaign (as of 2026-10-15, S02 ×10). §21 = Phase 4 session 2 (2026-10-28): S02–S07 ×10 complete, S01 pending; combined auto-collect automation + 0-decision guard; S05 Caldera rebuild; ground_truth.yaml corrected (§20.9 closed). Per-scenario detail: `findings_s01_s04.md`, `findings_s05.md`, `findings_s06.md`, `findings_s07.md`. Scenario spec: `T3`. Scoring: `ground_truth.yaml`, `GROUND_TRUTH_README.md`, `score_paths.py`. Session report: `session_report_2026-10-28.md`.*

---

# 22. Defense-Prep Record & Paper-Verified Reframing (added in handoff_15, 2026-10-29)

> Context: Project 1 proposal defense on **Monday 2 Nov 2026**. This section records what was decided while preparing it. Corrections E–H (§0) carry the technical reframing; this section carries the evidence, the deck decisions and the actions.

## 22.1 Status (unchanged from §21, restated)

| Done | In progress | Not started |
|---|---|---|
| 5-VM lab; S02–S07 ×10 collected; 7/7 smoke tests; EVTX → JSONL → SQLite ingest (2.98 M events, 0 parse errors) | S01 ×10 (manual RDP); Stage-1 gate | Stitching, labeling, scoring, identity term, ablation, evaluation |

## 22.2 Prior-art search (2026-10-29)

- **No paper or tool found** combining (i) logon-session cross-host stitching of Windows logs, (ii) ordered ATT&CK path ranking and (iii) an exposed-account coherence term. Safe wording: *"To our knowledge, no published work combines …"*.
- Each part has prior art: HADES and **Commander** (Liu, Bao, Hagenmeyer, JISA 91 (2025) 104057, DOI 10.1016/j.jisa.2025.104057 — add to Ch. 2) for cross-host reconstruction; **RapSheet** (IEEE S&P 2020) is order-aware (kill-chain subsequence) on host-level EDR alerts; **Hopper** (USENIX Sec 2021) detects credential switching; **Microsoft Defender predictive shielding** (preview Nov 2025, "contain user" GA Mar 2026) restricts accounts exposed on a device after credential theft (closed product, no published method).
- Semantic Scholar: TPPR has 0 citing papers; HADES had 9, none overlapping (list incomplete — missed Commander).
- **Never say:** "first to reconstruct cross-host paths from Windows logs" (HADES/Commander); "first to tell attackers from legitimate users" (HADES session tracing, Hopper, Microsoft); "order-aware cross-host reasoning never done" (RapSheet partly).

## 22.3 Backing sources for the attack chain (Steal → Reuse → Move → Execute)

| Source | Type | What it shows |
|---|---|---|
| CISA AA25-071A, Medusa (2025) | US gov advisory | Mimikatz on LSASS (T1003.001) → RDP (T1021.001) → PsExec (T1569.002) |
| CISA AA23-136A, BianLian (2023) | US gov advisory | "harvest credentials from … LSASS memory [T1003.001]", comsvcs.dll MiniDump (same as our lab); "PsExec and RDP with valid accounts for lateral movement" |
| The DFIR Report, PYSA/Mespinoza (Nov 2020) | Real incident report | PowerShell + comsvcs.dll LSASS dump; RDP with legitimate accounts; PsExec |
| Sophos Active Adversary Report 1H 2024 (vendor) | Supporting | RDP abused in 90 % of incidents, internal lateral movement in 90 % of those |

LSASS justification: **most documented host-local credential theft** (MITRE ATT&CK), not the most common theft overall (phishing / infostealers / leaked passwords dominate).

## 22.4 Deck decisions (draft slides built as .pptx this session)

1. **PoC framing slide** (after "How it works"): title "This project is a proof of concept"; 3 cards — (1) *A small-scale system that rebuilds the attack path across machines* (tag: Foundation · a simpler version of HADES); (2) *Score how likely each path is a real attack, using attack order* (tag: Order from TPPR); (3) identity card reworded to **"Flag the account that was exposed to the password theft, then moved — and test whether this separates the attacker better than attack order alone"** (tag: ★ Our new idea · to be tested). After Corrections E–F, card 3 should be presented as the optional extension and card 1/2 wording should mention the attack class HADES's trigger misses.
2. **Merged attack slide** (old "Our scope: Lateral Movement" + "The attack we target"): 3 source cards on top, 4 technique columns below; "no cracking needed" removed (Option D — no real reuse).
3. **Revised "How the identity check works"**: subtitle "…อยู่ในเครื่องตอนเกิดการขโมยหรือไม่?"; 3 checks (exposed at t1; theft before move; moved out of that host); "Coherent" defined; outcomes A (flagged), C (not flagged), **B (also flagged — limit: exposed ≠ stolen)**; footnote that its value beyond attack order is tested.
4. **Rule adopted for all slides:** never use a term before the deck has explained it.
5. **Positioning vs EDR / ITDR (advisor framing):** "EDR/ITDR raises the alert and locks accounts; our system rebuilds the path afterwards." Sophos ITDR (Oct 2025, on Secureworks Taegis; Entra-ID-centred posture checks, dark-web monitoring, detection, lock/reset) describes no path reconstruction, ranking, or same-account separation.

## 22.5 Weak points to state on the Limitations slide

| # | Weak point |
|---|---|
| W1 | **Exposed ≠ stolen** — an innocent account signed in on the foothold at dump time that then moves out of it is flagged like the attacker |
| W2 | **Attack order (with session stitching) may already separate the paths** — the identity term may add nothing; the ablation decides |
| W3 | Only theft that leaves a trace on the host (LSASS); phishing, leaked passwords, DC-side theft give the identity term nothing |
| W4 | The lab does not reuse the stolen credential (Option D runs the agent as the moving account); an LSASS dump normally yields hashes/keys, not passwords |
| W5 | TPPR adaptations: no anomaly model (NodeScore redefined), hand-built templates, merge rule changed, weights self-chosen |
| W6 | Small self-built lab, scripted attacks, offline upload only (not real-time) |

## 22.6 Advisor feedback to carry (2026-10-28/29)

- Understand the work yourself; review from many angles ("don't just ask AI").
- Chapter 2: ~3 papers per keyword theme (EDR, Attack Path Reconstruction, Identity-based threats, AD Security, Session Hijacking, Pass-the-Hash, Token Manipulation, Lateral Movement, Security Event Log Analysis, MITRE ATT&CK) — peer-reviewed work on Session Hijacking and Token Manipulation is thin; say so.
- Show what was actually produced, not just documents.
- Problem table: problem / solution / beneficiaries (university network admins, lecturers, students) / metrics (detection rate = Recall; add **processing time per scenario**). Reword "session hijacking via DC" to "impersonating a real user with a stolen valid password"; Pass-the-Hash shares the theft step but uses NTLM (natural extension).

## 22.7 Immediate next actions (supersede §21.8 ordering for the defense; §21.8 still applies to the build)

> ⛔ **handoff_17:** items 1–4 are done or superseded (identity decision → Correction K; status slide = slide 73; Q&A answers → §23.6). Items 5–7 carry into §23.8.

1. Decide §16 item 0 (keep or drop the identity term) and apply it to slides 20–25/PoC/Limitations consistently (use "exposed", never "stolen"/"compromised").
2. Add an honest status slide (done / in progress / not started).
3. Fix the HADES DOI and title in Ch. 2 / references; add Commander; mark TPPR as a preprint.
4. Prepare answers: "Isn't this just HADES?" → ★1 + ★2; "Why would svc_backup steal its own password?" → Option D; "What about B?" → W1; "Doesn't Sophos/Microsoft do this?" → §22.4 item 5.
5. After the defense: run S01 ×10; build the parser with the Correction G changes and the corrected `trace_backward()` (Correction I); check S04-A exposure (Correction H.2).
6. **Check in the collected logs (Correction I):** (a) is target 4624 `LogonGuid` non-zero and equal to the DC 4769 for S01–S03; (b) is 4624 `IpPort` populated; (c) does S02's outbound SMB show `Image = System` in Sysmon 3; (d) the S01 slide's 4769 shows `Service: ENDPOINT-01$` — for an EP-01 → EP-02 RDP move it should name EP-02, so confirm the right 4769 was picked.
7. **Slides:** describe cross-host linking as "source IP + time, confirmed by the DC's LogonGuid" — not "LogonGuid links the machines".

*End of handoff_15. §0 Corrections E–I and §22 added 2026-10-29 after reading HADES (arXiv:2407.18858v1) and TPPR (arXiv:2510.22191v1) in full; superseded text marked ⛔ in place. Everything from handoff_14 is retained.*


---

# 23. Final Defense State & Locked Decisions (added in handoff_17, 2026-10-30)

> Context: proposal defense **Mon 2 Nov 2026**. The deck is frozen — the student will **not** edit slides further; the 3-speaker script steers around remaining slide errors verbally.

## 23.1 Status

| Done | In progress | Not started |
|---|---|---|
| Research; 5-VM lab on 3 PCs; 7/7 scenarios smoke-tested; S02–S07 ×10 collected; parser EVTX → JSONL → normalisation → SQLite (2,981,147 events, 0 errors; trial 1 = 85 files, 2.526 GB) | **S01 ×10 (manual RDP, clean revert each trial)**; gate (R4–R8) + Sigma rules; answer keys | Cross-host stitching; scoring; identity term; evaluation (B0–B3 + full); web UI |

**Progress estimate after S01 is finished: ≈ 35 / 100** (effort-weighted, Project 1 + 2). All method parts remain: stitching 15, scoring + identity 12, evaluation 10, gate/Sigma ≈ 5, answer keys ≈ 6, web UI 8, report + defense 7. **November = stitching (critical path).** If stitching slips into December, shrink the web UI first, never the evaluation.

## 23.2 Deliverables produced in this chat

| File | What it is |
|---|---|
| `Mock_Defense_Script_Final.docx` | 3-speaker Thai script for the 91-slide final draft, same format as the team's original; **32:44 planned** (A 10:15, B 11:46, C 10:43; 9 handovers), ⚠ steering notes, Q&A table (15 questions), time-checkpoint table |
| `Draft4_Answers.docx` | 14-concern answer document (38 pp.) |
| `Draft4_slide_takes.pptx`, `Future_work_slide.pptx`, `Slides_21_24_fixed.pptx`, `Slide_23_each_paper.pptx` | Slide proposals (only partly adopted into the final deck) |

Speaker plan: A (อมรเทพ, lead) 1–4, 22–32, 59–60, 86–91 · C (Software) 5–21, 33–35, 61–65, 82–85 · B (Data) 36–58, 66–81.

## 23.3 Known errors still on the final deck (script handles each verbally — do not read them aloud)

| Slide | Error on slide | What is said instead |
|---|---|---|
| 2 | "Which login was the attacker?" | "which login belongs to the attack path" — the system ranks, it does not name a person |
| 5 | ">97% … are password spray" | "password spray **or brute force**" (Microsoft MDDR 2025) |
| 21 | Tool table: duplicate identity column, SIEM/ITDR marks shifted | Speak the message only; last column was meant to be "open / runs on saved logs"; admit ITDR is better at login-behaviour detection |
| 23 | "keep paths with score > 0"; arrow label "LogonGuid" | "high-scoring paths"; "login session + DC tickets" |
| 27 | Subtitle "separates the attacker from legitimate reuse of the same account"; HIGH/LOW CONFIDENCE | Never read; "higher / lower score" |
| 28 | "Points to the right account to reset" | Not said; identity term orders the investigation |
| 32 | "the threshold θ decides what is shown" | Not said (Correction J) |
| 33 | "drop > 90%" | "drops most events" (not measured) |
| 35 | "stitching rides on LogonGuid" | Linking uses IP, time and login sessions; LogonGuid confirms Kerberos logins only |
| 36 | S06 "False-positive test", S07 "Two-error-direction test" | S06 = benign paths should rank below attacks; S07 = two concurrent attack paths: two paths or merged? |
| 43 / 67 | S07 Path Y = `svc_sql` | Real runs used `svc_backup` for both paths |
| 44 | "Planned: 10 trials", "Exercution" | S02–S07 ×10 collected |
| 58 | Thai: NodeScore = "ความผิดปกติ" | Sigma rule severity |
| 59 | "signed in on the source machine **with malicious activity**" | Correction K definition |
| 60 | ★ NEW on gate and on node-level P/R | Gate = adapted, starts wider; metrics from TPPR; only the identity term is new |
| 62 | θ slider, RETAINED | Optional display filter, not the method |
| 66 | FNR only, no baselines | Script adds top-1 rate and the baseline comparison |
| 67 | S04-A identity 0; S07 accounts | §16 0b / 0d |
| 74 | S06 row "4624 T2/T3 (Local)" | Real data is WinRM + remote service install |
| 75 | S01 data wrong (`lsass_s02.dmp`, 4778, `ENDPOINT-01$` ticket) | Click through; S01 still being collected |
| 76 | Service install 05:42:05 before logon 05:42:45; DC box "4624" | Narrate order logon → file → service → process only |
| 80 | "Trial records: not yet verified" | Said openly |
| 85 | Query screenshot unreadable | "Manual SQL query, preview of stage 3" |
| 89 | Old future-work card titles | Script speaks the system-capability version (§23.5) |
| 90 | T4 (parse/normalise) shown "Pending" | "Done ahead of plan" |

## 23.4 Wording rules (slides, script, thesis)

- Say **"ranks paths"**, **"exposed"**, **"proposed / to be tested"**. Never "identifies the attacker", "detects stolen accounts", "separates the attacker from the account owner".
- **Path score**, not probability or confidence %.
- Define every term before using it (advisor rule).
- **Kerberos** is the authentication protocol of **Active Directory** (the DC acts as the KDC); Windows uses it only on domain-joined machines. Workgroup / local-account logons, and domain logons made by **IP address**, fall back to **NTLM** — which is why the lab's SMB logons (run by IP) are NTLM and carry no LogonGuid. Suggested line for slide 14: *"Kerberos เป็นโปรโตคอลยืนยันตัวตนที่ Active Directory ใช้ โดย DC ทำหน้าที่ออกตั๋ว ถ้าเครื่องไม่ได้อยู่ใน domain หรือเชื่อมต่อด้วย IP Windows จะใช้ NTLM แทน"*.

## 23.5 Positioning and design rationale recorded this chat

- **Tools & ITDR:** commercial XDR/ITDR (Microsoft Defender for Identity, CrowdStrike Falcon Identity, Sophos ITDR) link across hosts and detect login behaviour better than this project, but are closed (method not measurable), must be deployed before the incident, and do not output an ordered, attack-stage-ranked path. Open tools each do one piece (Hayabusa / Chainsaw = Sigma on EVTX; BloodHound = attack paths from AD permissions, not from logs; **LogonTracer** = closest — who logged on where — but no on-host follow-through and no stage order). **Niche: open, measurable, runs on saved logs, linked + ordered.**
- **"Order-aware"** = ranks a path by whether its ATT&CK tactic sequence fits attack order (steal → move → execute), not just time order.
- **Why JSONL:** simplest format that keeps every raw field even when fields vary by event ID, streams line by line, and lets the pipeline re-run without re-parsing EVTX. Not the fastest (Parquet is, but needs a fixed schema); SQLite is the query/join layer.
- **Preliminary-result picture for SQLite:** one session on ep-01 in time order (slide 52) and a cross-host query (slide 85, manual).
- **Expected output (slide 61), four parts:** extracted path step by step with technique + evidence event; all candidate paths ranked by score, no cut-off; identity result per hop; run summary (events dropped per stage, time). All values illustrative.
- **Future work as system capabilities** (each fixes a limitation): knows whose password was actually used (4648 / logon type 9 + per-account baseline; fixes L1, L2) · shows fewer false paths (trace only after a theft; learned weights; L3) · works live (WEF / SIEM streaming; L6) · follows more ways to move (WMI, DCOM, SSH, Linux, Entra ID; L5).
  > **handoff_18 (D2):** "shows fewer false paths" is an expected effect to be measured, not a claimed result.

## 23.6 Q&A answers prepared (full table in the script, section 3)

Why not HADES (7 login-abuse patterns; stolen valid password matches none) · PtH after the LSASS dump (that case is HADES's; ours is a real-password login, e.g. offline-cracked weak service password) · lab never reuses the password (Option D, stated) · HADES already separates users (by session after its alarm; we add exposure scoring and start without the alarm) · B also scores 1 (narrows to exposed accounts; weight, not verdict) · order already separates (maybe — the w₃ test answers; identity helps where linking is only host-level, e.g. SMB as System) · gate fires on admin logins (price of starting earlier; ranking must sort; S04/S06 test it) · own answer key (from Caldera logs, separate queries, locked before testing; HADES/TPPR did the same) · no HADES/TPPR number comparison (different data) · no θ (system does not decide yes/no; top-1 rate measured) · NTLM / LogonGuid (IP-based SMB → NTLM; link by IP + account + time) · XDR/ITDR (closed, unmeasurable, pre-deployed) · why JSONL · schedule · one-sentence novelty.

## 23.7 Pitfalls added

- Don't build a θ cut-off into the pipeline or the UI default view.
- Don't fix the S04 / S07 answer keys from the design document — fix them from the collected logs.
- Don't count a session with no logoff event as closed (Correction K note).
- Don't compare the project's numbers with HADES's or TPPR's published numbers.

## 23.8 Immediate next actions (supersede §22.7)

> ⛔ **handoff_18:** superseded by §24.6. Item 1 (defense) is done.

1. **Defense (Mon 2 Nov):** rehearse with the script twice (full text), then once from cues only; replace 【ชื่อ B】/【ชื่อ C】; keep to the checkpoint table.
2. **Finish S01 ×10** (manual RDP after clean revert → fresh 4624 Type 10).
3. Dedupe `manifest.csv` → `manifest_clean.csv`; completeness audit (§21.8 items 2–3).
4. **Log checks before stitching (from §22.7 item 6):** LogonGuid non-zero and equal to DC 4769 for Kerberos hops; 4624 `IpPort` populated; S02 outbound SMB Sysmon 3 `Image = System`; correct 4769 for S01.
5. **Answer keys:** S04-A identity value (session 0xd6398 logon time vs dump time); S07 both paths `svc_backup`; S06 row per real data.
6. **November:** stitching on S02 and S04 first (NTLM hops → IP + account + time; Kerberos hops → confirm with LogonGuid).
7. **December:** scoring (Sigma-level NodeScore, no isolated-path drop, ranking) + identity term (Correction K code). **January:** B0–B3 + full evaluation with the §14.2 metrics and processing time.

*End of handoff_17. Corrections J–L and §23 added 2026-10-30; everything from handoff_15 is retained, superseded text marked ⛔ in place.*


---

# 24. Proposal Defense Outcome (added in handoff_18, 2026-11-03)

> The Project 1 proposal defense took place on **Mon 2 Nov 2026**. The student's own assessment: "pretty rough but overall OK". The committee focused on **design choices** and **flaws of the system**. The advisor approved continuing on the current plan.

## 24.1 Committee questions and the answers to carry forward

### Design and tools

| # | Question (as asked) | Answer to give / write in the report | Action |
|---|---|---|---|
| Q1 | How is the provenance graph built? Is there a ready-made tool or library? | Built in Python with **NetworkX**: nodes = processes, files, network connections, login sessions (Sysmon 1/3/10/11, Security 4624); edges = parent→child (ProcessGuid), process→session (LogonId), network connection, cross-host logon. Open provenance systems exist (**SPADE, CamFlow**) but target **Linux** audit data; to our knowledge no open tool builds **cross-host** provenance from Windows EVTX + DC logs. Libraries used: EVTX parsing, NetworkX, Sigma tooling (Chainsaw / Hayabusa / pySigma) | Report: a "tools considered" table (tool, platform, what it gives, why not used) |
| Q3 | What is the input of Caldera? | **Agent** (Sandcat; deployed per Option D as a scheduled task under a domain account) + **abilities** (YAML: one command per technique, `executors:` list) + **adversary** (ordered list of abilities) + **operation** (adversary + agent group + planner + facts such as target hostnames). Output = operation log (command, host, time) → seeds the answer key | Report: short methodology paragraph + one ability example |
| Q5 | Why change binary EVTX to JSONL? | EVTX is a binary chunked format needing a special parser on every read; convert **once** to text that keeps every raw field (fields vary by event ID), streams line by line, is tool-independent, and lets the pipeline re-run without re-parsing. SQLite is the query/join layer | None (already in §23.5) |
| Q6 | Why hex → int in normalisation? An analyst would read hex | **Accepted as a valid point.** Integers are used because the same Logon ID can appear with different case / leading zeros / formats across sources, and integer equality is exact and fast for joins. **Fix: keep both** (D1) | **Design change D1** |
| Q7 | Why SQLite? Many databases exist; can it query ~2 million rows? | Single file, no server, embedded in Python, reproducible, enough for offline single-user batch analysis. **Yes** — with indexes on the join keys (host, logon_id, time, ip, account), a few million rows is small for SQLite; the 2.98 M-event ingest already works. Alternatives: PostgreSQL (multi-user server), Elasticsearch / OpenSearch (SIEM-style search), **DuckDB** (columnar, faster for large scans/aggregations — the upgrade path) | Report: measure and report query times for the stitching queries; name DuckDB as the upgrade path |
| Q8 | (Answer about) linking across machines | Target **4624** (source IP, account, time, logon type) ↔ source **Sysmon 3** outbound connection (dest IP / port, time) → that process → its **LogonId** session. Kerberos logons confirmed by DC **4769 ↔ 4624 LogonGuid**. SMB: Sysmon 3 shows `System` → anchor on the command process. WinRM: `powershell.exe` → 5985, then `wsmprovhost.exe` on the target. RDP: `mstsc.exe` → 3389. (Correction I) | Report: one small diagram per protocol |
| Q9 | No need to explain the equations in detail | Presentation feedback: show the intuition on slides (what each score part rewards); keep the full equations in the methodology chapter | Final-defense deck |

### Limits of the system

| # | Question | Answer | Action |
|---|---|---|---|
| Q2 | What are the analyst's challenges — a wide time window, or the depth of events? Are they a problem? | **Both are real.** Wide window → more data and more chance of wrong time-based links. Depth (many hops) → candidate paths multiply and link errors compound hop by hop. Mitigations: join on **keys**, not time alone; **rank** instead of cut; measure processing time. The lab uses short windows and ≤ 2 hops | **Limitation L7 + L8** (§24.4); report processing time vs. data size |
| Q4 | If the attacker goes from a file server to a database server, should you watch the DB dump (and where it connects from) or the DB usage log? | **Both sides.** Source: which process connected (Sysmon 3 to 1433 / 3306 / 5432) and as which account. DB side: logins and queries (SQL Server Audit / DB audit log; large SELECT, `BACKUP DATABASE`, dump tools). If the DB uses **Windows authentication**, the login appears as DC **4769 for `MSSQLSvc/<host>`** + a **4624** on the DB server, so the existing linking already covers the move; the dump itself would be a new node type (Collection / Exfiltration) | **Future work F5** (§24.5) |
| Q10 | Why design scenarios where the attacker has that much control of the foothold? | The project starts **after** the foothold is compromised ("assume breach"); initial access is out of scope. Defender and LSA protection (RunAsPPL) were disabled so the credential theft is **visible and repeatable** for testing — a lab simplification. In environments with Credential Guard / LSA protection, LSASS dumping is harder, and theft may leave no trace (identity term → 0) | **Limitation L9** (§24.4); **future scenario with protections on** (F6) |

### Unproven claim

| # | Question | Answer | Action |
|---|---|---|---|
| Q11 | How do you know you can reduce false positives when you haven't started? | **We don't know yet — it is a hypothesis.** The evaluation tests it: B1 (linked paths, no ranking) vs Full ranking on the same trials, using node precision on the top-k paths, top-1 rate, and S04 / S06. Motivation only: TPPR's ablation without path scoring gave Recall 100 % but Precision 10.72 %. No claim until measured | **Wording change D2** |

## 24.2 Advisor feedback

- **The project is OK; follow the present plan.**
- **If time is spare: add the severity of the path.**

**Interpretation and decision:**

| | Current path score | Path severity (stretch) |
|---|---|---|
| Question | "How much does this path **look like** an attack?" | "If it **is** an attack, how **bad** is it?" |
| Use | Ranking (evaluated) | A label next to each path: Low / Medium / High / Critical (displayed, not evaluated) |
| Inputs (already available) | Order, Sigma level, identity | Target criticality (DC > server > workstation) · highest privilege used (Domain Admins member) · worst step (max Sigma level) · reach (number of hosts) |
| Precedent | TPPR | **HADES Eq. 2** multiplies by **(DA + 1)** for domain-admin credentials and by an attack **Criticality** factor |

- **Rule:** severity is a **separate column**; it must **not** change the ranking, so the evaluation (B0–B3, Full) stays clean.
- **When:** after the January evaluation, or alongside the web UI. Estimated 1–2 days once scoring exists.
- Note: all three lab accounts are Domain Admins (`svc_backup`, `admin_it`, `svc_sql`, §21.5), so the privilege input will not discriminate in this lab — say so, or make privilege tiers configurable per account.

## 24.3 Design and wording changes adopted

| ID | Change | Where it applies |
|---|---|---|
| **D1** | Store Logon ID as **both** `logon_id_int` (joins) and `logon_id_hex` (original string, display). Same rule for any other hex field used in joins (e.g. process IDs in Security events) | Normaliser, SQLite schema, UI; §9.1 note |
| **D2** | "Reduces false positives / shows fewer false paths" → **"we expect fewer false paths at the top of the ranking and will measure it (B1 vs Full)"** | Report, final deck, future-work card 2 |
| **D3** | Report **query / processing time** per stage and per scenario, with data size (events, rows) | Evaluation chapter (advisor request from §22.6 + Q7) |
| **D4** | Equations: intuition on slides, full form in the methodology chapter | Final deck, report |

## 24.4 Limitations added (extend §22.5 W1–W6 and slide 88)

| # | Limitation |
|---|---|
| L7 | **Wide time windows:** real dwell times are long; time-based joins get more ambiguous as the window grows. Lab trials are minutes long |
| L8 | **Depth:** at most 2 hops tested (S05); candidate paths and link errors grow with depth |
| L9 | **Foothold protections disabled** (Defender off, RunAsPPL = 0) so the dump is visible; with Credential Guard / LSA protection the theft may leave no trace and the identity term gives 0 |

## 24.5 Future work added

| # | Item |
|---|---|
| F5 | **Database servers:** add DB audit logs (SQL Server Audit, MySQL / PostgreSQL logs) as a new node type; Windows-authenticated DB logins already appear as 4769 `MSSQLSvc/<host>` + 4624 |
| F6 | **Scenario with protections on** (Credential Guard / LSA protection) to test behaviour when the theft is not visible |
| F7 | **Path severity** label (§24.2) if not completed as the stretch item |
| F8 | **Scale:** DuckDB / columnar storage and bounded depth / time-window parameters with a sensitivity check |

## 24.6 Immediate next actions (supersede §23.8)

1. **Finish S01 ×10** (manual RDP after clean revert → fresh 4624 Type 10).
2. Dedupe `manifest.csv` → `manifest_clean.csv`; completeness audit (§21.8 items 2–3).
3. **Apply D1** in the normaliser and SQLite schema (re-run ingest if the hex field was dropped).
4. **Log checks before stitching** (§22.7 item 6): LogonGuid non-zero and equal to DC 4769 for Kerberos hops; 4624 `IpPort` populated; S02 outbound SMB Sysmon 3 `Image = System`; correct 4769 for S01.
5. **Answer keys:** S04-A identity value (session 0xd6398 logon time vs dump time); S05 hop 2 (`admin_it` session open on EP-02 before dump #2); S07 both paths' real accounts; S06 row per real data.
6. **Gate + Sigma:** lock the rule list (technique, rule, source = SigmaHQ / own, level) before testing; plan a labelling-recall check against the answer keys.
7. **November:** stitching on S02 and S04 first (NTLM hops → IP + account + time; Kerberos hops → confirm with LogonGuid); record query times (D3).
8. **December:** scoring (Sigma-level NodeScore, no isolated-path drop, ranking) + identity term (Correction K code). **January:** B0–B3 + Full evaluation with the §14.2 metrics and processing time. **Then, if time allows:** path severity (§24.2), web UI.

*End of handoff_18. §24 added 2026-11-03 after the proposal defense; everything from handoff_17 is retained, superseded text marked ⛔ in place.*
