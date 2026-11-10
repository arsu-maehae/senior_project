# 020 — Answer-key provenance: log-based keys

**Date:** 2026-11-10 · **Status:** accepted (owner instruction, T5 start) · **Task:** T5

## Context
The Caldera operation logs for the October trials (15–31 Oct) were not saved. On the Caldera VM, `data/object_store` is dated 22 Sep (before the trials), and `data/results` holds 140 files (15 Oct 05:32 to 31 Oct 08:28) that look encrypted (`base64 -d` fails) and have no mapping to commands. A folder `s05-backup-20261031_052818` holds the S05 definitions (`lab-s05-hop1-adversary.yml`, `lab-s05-hop1-winrm.yml`, `lab-s05-hop2-adversary.yml`, `lab-s05-hop2-winrm.yml`); definitions for other scenarios may be elsewhere in `data/`. None of these are in the repo yet. Handoff §21.4 already records that Caldera operations do not persist across restart.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Wait for the Caldera files and key from them | Closest to "the playbook is the key" (handoff l.1063) | Results are unreadable; keys would block T6–T7 |
| B. Build keys from the saved logs: the agent's process tree is the record of what Caldera executed, combined with the handoff's intended steps and target-side events | Available now; independent of the stitcher if hops are confirmed only by commands naming the target | Weaker than operation logs; needs an `unconfirmed` status for steps the tree cannot show |
| C. Link hops by time/account to the target-side events | Complete paths | That is the stitcher's own rule, so evaluation would be circular |

## Decision
Option B. Evidence that `splunkd.exe` is the Caldera agent and the parent of the attack commands: `docs/research/agent_evidence.md`. Rules (spec `docs/specs/07_answer_key.md`): a hop is `confirmed` only when an agent-tree command line names the target host or IP and matches a handoff step (`basis: command_names_target`); a hop found only by time and account has `basis: time_account_only` and is `unconfirmed`; a step missing from the agent tree is `unconfirmed`, never guessed; the key code never reads `log_check` or stitcher output. TPPR also built its ground truth by manual log analysis (TPPR §4.1.3; the fact-checker verifies the section number against `docs/papers/`). The Caldera ability/adversary definitions and result files will be added later as a cross-check only, not as a source of truth; a TODO is in `docs/PROGRESS.md`.

## Consequences
Keys are log-derived and share the same logs as the pipeline; independence rests on the rules above, not on a separate data source. The report must say so (limitation). Hops with a command-line basis are the same kind of evidence as the stitcher's tier B method; the key therefore also requires a matching handoff step, and the evaluation reports the confirmed/unconfirmed split.

## Kill criteria
If the Caldera results become readable and disagree with a confirmed key hop, replace the key from the Caldera record and record the mismatch here. If more than a small share of hops is `unconfirmed`, ask the owner before approving the drafts.

## Committee answer
**EN:** Our attack records were lost, so we rebuild the answer key from the agent's own process tree and the planned steps, and mark anything we cannot see as unconfirmed; we do not use our own linker to decide what is true.
**TH:** บันทึกการโจมตีของ Caldera สูญหาย เราจึงสร้างเฉลยจาก process tree ของตัว agent และขั้นตอนที่วางแผนไว้ และทำเครื่องหมายสิ่งที่มองไม่เห็นว่ายังไม่ยืนยัน เราไม่ใช้ตัวเชื่อมของเราเองตัดสินว่าอะไรจริง
