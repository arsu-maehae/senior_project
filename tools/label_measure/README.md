# T8.1 measurement scripts (spec 04_label §10)

Committed by owner answer Q14 (decision 056) so that the T8.1 measurements can be repeated. They are not pipeline
code: they live outside `src/` because they read the answer keys, and `src/label` must never open `ground_truth/`.

- **Development trials only.** Each script calls `stitch.inputs.check_allowlist` before opening a trial, so
  t02–t10 are refused (decisions 019, 046, 053).
- **Read-only.** DBs are opened `mode=ro`, and `measure_t81.py` checks the SHA-256 before and after.
- **Counts only.** No command line, script block, ContextInfo, Payload or UserData text is printed or saved. Outputs go
  to the gitignored `out/label_measure/`.

| Script | Spec 04 |
|---|---|
| `measure_t81.py` | §10.1–10.5: key events, path nodes, field coverage and formats, rule hits as written in §3.1 (before decision 056), R1_lsass vs T1003.001 |
| `diag_t81.py` | §10.4 no-match causes; 4697 service names |
| `perhop_t81.py` | §10.6 techniques per key hop |
| `leakcheck_t81.py` | §10 / review §4 leak check |

The rule predicates in `measure_t81.py` mirror the **§3.1 candidate list as written**. They are a record of the
measurement, not the locked rules. The locked rules are `src/label/rules/` (decision 056).

Run from the repository root, for example `python tools/label_measure/measure_t81.py`.
