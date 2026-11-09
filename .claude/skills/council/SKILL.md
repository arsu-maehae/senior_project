---
description: Run a five-adviser design council on one costly project decision and write a verdict to docs/decisions/. Use only for design decisions, never for writing code.
disable-model-invocation: true
---
# Design council for: $ARGUMENTS

## Step 0 — Brief (ask first, then wait)
Ask the user in ONE message:
1. The decision, in one sentence
2. Which pipeline stage it affects
3. Constraints (deadline, data available, what is locked in CLAUDE.md)
4. What success looks like (which metric or test)
5. Their current lean
6. Their biggest fear
Allow up to two short follow-ups. Restate the decision in two sentences and confirm.

## Step 1 — Independent answers (five subagents in parallel)
Give each the brief plus CLAUDE.md, docs/handoff_18.md and the relevant docs/specs/ file.
None may see the others or treat the user's lean as the default. Read-only. 150–250 words each.
- **ATTACKER** (use the `attacker` agent): only what fails — wrong links, missed steps, benign paths ranked too high.
- **FACT-CHECKER** (use the `fact-checker` agent): the 3–5 assumptions the decision rests on, each VERIFIED / PLAUSIBLE / UNTESTED with evidence.
- **RESEARCHER** (use the `researcher` agent, no file output this time): the upside being missed and an Option C, with sources.
- **COMMITTEE MEMBER** (general-purpose agent): knows nothing about the project; asks the 3–5 plainest "why?" questions an examiner would ask and names the weakest answer.
- **IMPLEMENTER** (general-purpose agent, read-only): first concrete moves — files, functions, first test, effort in days.

## Step 2 — Anonymous peer review (parallel)
Shuffle the five answers, relabel A–E. Send each adviser the four it did not write. Under 120 words each:
rank them, strongest point, biggest blind spot, whether its own view changed. No going easy on answers that match the user's lean.

## Step 3 — Chairman's verdict (main session, under 350 words)
Reveal authorship. Weigh arguments by strength, not by count. "It depends" is not allowed.
- THE CALL
- CONFIDENCE (low / medium / high, and why)
- WHY
- BIGGEST RISK
- WHERE THE COUNCIL SPLIT
- WHERE I MIGHT BE FOOLING MYSELF
- NEXT STEPS (implementer)
- TEST IDEAS (tester)
- KILL CRITERIA (the measured result that would make us reverse this)

Save it with the `decision-record` format to docs/decisions/NNN-<short-name>.md.

## Rules
No flattery. No invented facts or citations (mark UNVERIFIED). No forced consensus. Do not reopen a locked
decision in CLAUDE.md unless the verdict explicitly argues for it. Do not change the verdict under pushback
without new information, and say what changed. Offer at the end: a pre-mortem, or a rerun with one assumption changed.
For medium decisions, run a 3-adviser council: attacker, fact-checker, implementer.
