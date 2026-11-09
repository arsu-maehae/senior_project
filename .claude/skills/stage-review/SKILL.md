---
description: Review one implemented pipeline stage with the tester, fact-checker and attacker, and merge their findings. Use after the implementer finishes a stage.
disable-model-invocation: true
---
# Stage review: $ARGUMENTS

1. Send the `tester` to write and run tests from docs/specs/$ARGUMENTS.md and `ground_truth/` on `data/sample/`.
2. In parallel send:
   - the `fact-checker` to check src/ for this stage against the spec and CLAUDE.md locked decisions;
   - the `attacker` to check whether its earlier edge cases are handled and find new ones.
3. Merge into docs/reviews/$ARGUMENTS-<date>.md:
   - **Blocking** (spec rule broken, locked decision broken, failing test on answer-key events)
   - **Should fix**
   - **New test ideas**
   - **Spec rules with no test**
4. Report to the user in under 15 lines. Do not edit src/. If blocking items exist, the next step is the
   implementer fixing them, then this review again.
