# Stage spec: <NN_name>

**Owner:** <team member> · **Status:** draft / approved · **Last updated:** <date>

## 1. Purpose
Two sentences: what this stage does and why the pipeline needs it.

## 2. Input contract
Source (table/view/file), required columns and their meaning, assumptions (e.g. one DB per trial).

## 3. Output contract
Table/file name, every column with type and meaning, one example row. Location: `out/<stage>/<trial_id>/`.

## 4. Rules
| ID | Rule | Source (handoff § / correction / paper) |
|---|---|---|
| XX-01 | ... | ... |

## 5. Parameters
| Name | Value | Why | Sensitivity test? |
|---|---|---|---|

## 6. Edge cases (from attacker review)
| Case | Where it occurs (scenario/trial) | Expected behaviour | Test ID |
|---|---|---|---|

## 7. Acceptance tests
On `data/sample/` (S02 t01, S04 t01, S05 t01): what must be true, tied to answer-key events.

## 8. OPEN questions
| Question | Options | Needs council? |
|---|---|---|

## 9. Out of scope
What this stage deliberately does not do.
