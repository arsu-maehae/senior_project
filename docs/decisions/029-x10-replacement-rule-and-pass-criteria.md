# 029 — ×10 trials: replacement rule and pass criteria (fixed before looking at the data)

**Date:** 2026-11-10 · **Status:** accepted (owner, 2026-11-10) · **Task:** ×10 ingest and validation

Written before any file of `data/incoming/x10/` was opened. Nothing here may be changed after the validation results are seen, except through a new decision record that says why.

## Context
The ×10 trials (S02, S03, S04, S06, S07, `trial_01`..`trial_10` = `t01`..`t10`) are the remaining development trials (t01) and the whole test set (t02–t10, decision 019). Before any scoring, each trial must be shown to contain the scenario as designed. The S05 ×10 is reported to have been run with the wrong design and is quarantined (decision 030). Known gaps reported by the owner: S02 trial_03 and trial_04 have no DC-01 Sysmon or Security log; S05 trial_06 and trial_09 have no ENDPOINT-02 or ENDPOINT-03 folders.

## Decision 1 — replacement rule
1. A trial with at least one FAIL is broken. It is replaced by a new trial of the same design with a new number (`trial_11` onwards), never by re-running into the old number.
2. Broken trials are archived (kept in `data/incoming`, `data/raw` and their DB, marked in the validation report), never deleted.
3. If most or all trials of a scenario fail on the design chain (criterion b) or on the same criterion, the scenario gets a full rerun of ten new trials.
4. The rule is fixed now, before any scoring. Replacement trials are validated with the same criteria.

## Decision 2 — pass criteria and severity
Hosts: `ep-01`, `ep-02`, `ep-03`, `dc01` (owner: keep `dc01`, matching t00). Logs per host: Security, System, Sysmon, PowerShell, WinRM (5 per host, 20 per trial).

Attack-path hosts per scenario (hosts that hold a design step, decisions 021–027): S02 ep-01, ep-02 · S03 ep-01, ep-03 · S04 ep-01, ep-02 · S06 ep-01, ep-02, ep-03 · S07 ep-01, ep-02 · S05 (quarantine) ep-01, ep-02, ep-03. `dc01` is off the path for every scenario (SMB hops are NTLM; DC data is used only for the clock check g).

| ID | Criterion | FAIL | WARN | How it is measured |
|---|---|---|---|---|
| a | Complete files (4 hosts × 5 logs) | a host on the attack path is missing (any of its 5 logs absent counts as missing that log; a whole host absent is FAIL if on the path) | a host off the path is missing, or single logs missing on any host | file count per host and channel in the trial folder |
| b | Design chain | any design step is missing | – | see design steps below; a step is present only if its events are found in the trial window |
| c | Accounts on the target | the intended (design) account never appears on the target side (4624 on the target host from the source IP, or 4697/5145 subject) | S06 only: WARN instead of FAIL (owner: S06 is the benign control) | intended account per hop below; the observed target-side account is always reported next to it; S07 path Y intended `svc_sql` (design), observed account reported, see decision 027 |
| d | Benign track | S04 Track A has no ADMIN$ share write (5145 on ep-02, admin_it, `ADMIN$`, a binary name) or has a credential-access event (rundll32 → lsass Sysmon 10 by admin_it, or in the Track A session); S06 shows an attack path (any rundll32 → lsass Sysmon 10 in the trial window) | – | event counts |
| e | Agent evidence | a Caldera-run step has no `splunkd.exe` (`C:\Users\Public\splunkd.exe`) Sysmon 3 → `192.168.50.50:8888` on its source host in the trial run | – | not required for manual tracks (S04 Track A) |
| f | Trial windows | two trials' windows overlap | events of older trials inside the file (agent-child commands, dumps or remote 4624 before the window start) | window = [first design anchor − 60 s, last design anchor + 300 s]; anchors = agent-child commands of the design, rundll32 → lsass dumps, target 4624 of design hops; computed by the validator itself |
| g | Clock offset | – | any host-pair offset exceeds 5 s | per-host offset vs dc01 from mutual-nearest 4624 ↔ dc01 4769 LogonGuid pairs (median); host-pair offset = difference of medians; also lower bounds from target events logged before their source command. **No dc01 Security log → "n/a" with the reason, never PASS** (a lower bound > 5 s still gives WARN) |
| h | Single run | a stray duplicate run of a design step cannot be told apart from the real one (same step, same source host, same user account, both naming the target) | a duplicate run can be identified and excluded (self-target, non-user token such as SYSTEM, other host) | count executions of each design step |
| i | Consistency | – | the trial's shape differs from the scenario's other trials | shape = hosts present, design steps found, service names, target-side accounts, protocol; compared with the scenario's majority shape |

Design steps (from handoff §19–21 as corrected by decisions 021–027; service and binary names are not fixed — any 7045/4697 on the target whose image is an `.exe` directly under `C:\Windows\` after the hop's 4624 counts; names are reported and compared under i):
- **S02:** LSASS dump on ep-01 (rundll32 → lsass, user token) · agent command on ep-01 naming ep-02 · ep-02 4624 from ep-01's IP · 5145 write of a binary to `ADMIN$` on ep-02 · service created on ep-02 (7045 or 4697). Intended account `svc_backup`.
- **S03:** LSASS dump on ep-01 · agent command on ep-01 naming ep-03 (WinRM) · ep-03 4624 from ep-01's IP · WinRM 91 or `wsmprovhost.exe` on ep-03. Intended account `admin_it` (source ep-01, decision 025).
- **S04 Track B:** LSASS dump on ep-01 · agent command on ep-01 naming ep-02 · ep-02 4624 · 5145 binary write · service created. Intended `svc_backup`.
- **S04 Track A (manual, decision 021):** a command in an interactive (non-agent) session on ep-01 naming ep-02 · ep-02 4624 · 5145 binary write to `ADMIN$` · service created. Intended `admin_it`. No agent evidence required.
- **S06:** WinRM ep-01 → ep-02 · WinRM ep-01 → ep-03 · SMB service install ep-01 → ep-02 (decision 024). Intended `admin_it` (c is WARN only). No dump (d).
- **S07:** two LSASS dumps on ep-01 · two agent commands on ep-01 naming ep-02 · two ep-02 4624s · two services created on ep-02 (X and Y). Intended accounts X `svc_backup`, Y `svc_sql` (design; decision 027 records that t00 logged `svc_backup` for Y).
- **S05 (quarantine only):** hop 1 SMB ep-01 → ep-02 (`svc_backup`, dump on ep-01) · dump on ep-02 by `admin_it` · hop 2 WinRM ep-02 → ep-03 (`admin_it`).

## Decision 3 — scenario verdict
- **pass:** no trial has a FAIL.
- **replace N:** N trials have at least one FAIL; each is replaced by `trial_11` onwards (decision 1).
- **full rerun:** most or all trials (≥ 6 of 10) fail, or they fail on the same design criterion (b).
WARNs never change the verdict; they are listed for the owner.

## Decision 4 — disk headroom
Before the bulk ingest, free space on D: is checked against the estimated size of the new `data/raw` copies plus the DBs (and JSONL). If the headroom after the estimate is below 20 %, the ingest stops.

## Consequences
The validator is independent: it does not import `src/answer_key`, `src/log_check` link results or any stitcher (tested). Criteria and severities above are the ones applied; any measurement detail the validator needs beyond this table is recorded in the validation report as an implementation note, not as a new criterion.

## Kill criteria
If a criterion turns out to be unmeasurable on the data (for example a log type never exported), the report says "not measurable" for it and the owner decides; the criterion is not dropped silently.

## Committee answer
**EN:** We fixed what counts as a broken trial and how it is replaced before we looked at the results, so no trial was kept or dropped because of its score.
**TH:** เรากำหนดว่าอะไรคือรอบที่เสียและวิธีแทนที่ก่อนดูผล จึงไม่มีรอบใดถูกเก็บหรือตัดทิ้งเพราะคะแนนของมัน

## Note added after the B1 file scan (2026-11-11, facts only, criteria unchanged)
The scan of `data/incoming/x10` shows the missing ENDPOINT-02 and ENDPOINT-03 folders in **S05 trial_06** and **S06 trial_09** (not S05 trial_09, which is complete). S02 trial_03 and trial_04 lack DC-01 Sysmon and Security, as stated. The endpoint logs were not cleared between trials (for example s02_t03 ep-03 Security holds records from 2026-09-21 to 2026-10-15), which criterion f measures.

Amended after the validation run by decision 031 (criterion f window anchors and end clip; owner accepted 2026-11-11). No verdict depends on f.
