---
description: Explain one module or stage to the team member who owns it, then quiz them, so they can defend it at the final defense. Use before marking a stage done.
disable-model-invocation: true
---
# Explain: $ARGUMENTS

1. Read the code, its spec and its decision records.
2. Explain in this order, simply first:
   - What the stage does in two sentences, and where it sits in the pipeline
   - Input → output, with one real example row from data/sample/
   - Walk through each function: what it does and WHY it is written that way
   - Which locked decisions (CLAUDE.md) it implements
   - Known limitations and edge cases
3. Then ask the owner 5 questions a committee member would ask (e.g. "why join on IpPort and not only time?"),
   one at a time. After each answer, say what was right, what was missing, and the stronger answer.
4. End with a list of the owner's weak spots to review. Write nothing to src/.
