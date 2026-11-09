---
description: Draft or update the spec for one pipeline stage from the handoff and existing code, then get it attacked before anyone codes. Use at the start of every stage.
disable-model-invocation: true
---
# Stage spec: $ARGUMENTS

1. Read CLAUDE.md, docs/handoff_18.md (sections for this stage), docs/specs/_TEMPLATE.md,
   any existing docs/specs/$ARGUMENTS.md, and the code of the stage before it (its output contract).
2. Ask the `data-checker` to confirm the input events/fields this stage needs exist in `data/sample/`.
3. Fill every section of the template in docs/specs/$ARGUMENTS.md. Each rule gets an ID (e.g. ST-03)
   so tests and reviews can cite it. Mark anything undecided as OPEN with options.
4. Send the draft to the `attacker`. Add its relevant cases to the "Edge cases" section, each with
   the scenario/trial where it occurs.
5. Show the user: the OPEN questions, the attacker's top 3 cases, and what needs a council.
Do not write code. The stage owner approves the spec before `implementer` starts.
