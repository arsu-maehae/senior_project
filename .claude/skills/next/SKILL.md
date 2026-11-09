---
description: Coordinator. Pick the next big task from docs/PLAN.md, plan it, and after the user says go, carry out all its small tasks with the project's agents, recording every decision.
disable-model-invocation: true
---
# Next big task $ARGUMENTS

## 1. Orient (read only)
Read CLAUDE.md, docs/PLAN.md, docs/PROGRESS.md and the latest files in docs/decisions/ and docs/reviews/.
If $ARGUMENTS names a task (e.g. T3), use it; otherwise pick the first big task whose dependencies are done.

## 2. Plan and wait
Show the user, in under 30 lines:
- the big task and its small tasks, in order
- which agents you will use for each (implementer, tester, data-checker, fact-checker, attacker, researcher)
- the decisions you expect to make, and the evidence you will base each on
- what you need from the user (data, answer-key approval, papers) — ask now, not halfway
- the "done when" check from PLAN.md
Then STOP and wait for "go".

## 3. Execute (after "go")
For each small task:
1. If it needs a spec that does not exist, run the stage-spec procedure first.
2. Use the `implementer` for code, then the `tester`. Use the `data-checker` whenever a step depends on what the logs contain.
3. Any non-trivial choice → decision record in docs/decisions/ with evidence (counts, spec rule ID, paper section in docs/papers/). Use the `researcher` if evidence is missing; use the council procedure only for choices that would be costly to reverse.
4. Tests pass → `git commit -m "<task id>: <what>"` (never push) → one line in docs/PROGRESS.md.
Stop early only for the reasons listed in CLAUDE.md "How work runs".

## 4. Close the big task
- Run the stage-review procedure for any stage built; fix blocking items.
- Ask the `fact-checker` to check the decision records written in this task against the papers and CLAUDE.md.
- Tick the task in docs/PLAN.md and write a PROGRESS.md summary: built, decisions (with links), test results, open questions, what the user must check by hand (10 sample rows per output).
- Report to the user in under 25 lines. Suggest `/explain-module` for the stage owner.
