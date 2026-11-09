# Stage review: 01_normalise_fixes (T3) — 2026-11-10

Reviewers: tester (3 passes), fact-checker (code + records 004–009; 010 and spec 4c separately), attacker (spec review and implemented-stage re-check), data-checker (7 t00 databases). Spec: `docs/specs/01_normalise_fixes.md`. Code: `evtx_pipeline/trial_normalize.py`, `trial_import.py`, `cli.py` (`import-trial`). Tests: `tests/unit/test_trial_normalize.py`, `test_trial_import.py`, `test_nf21_26.py`.

## Blocking
None open. Fixed during the review:
- NF-11 for 4647 (real events carry only TargetLogonId): spec and code fixed (commit 57dec16).
- NF-21 IPv6 `clientIP` with `%zone` in WinRM 91: spec and code fixed (commit 0e8ccc8).
- Decision 010's premise (fixed 2–7 s Sysmon gap) was wrong: corrected with measured gaps.

## Should fix (open, owner to decide)
1. **No trial time window (attacker N1).** Each DB holds the whole campaign history of its hosts (days 09-17 to 10-12). The stitch stage must apply windows from the answer keys (T5/T6). Not a normaliser rule.
2. **Missing-file check (N7).** The importer cannot tell that an expected host/channel file is absent. `docs/data_inventory.md` is the expectation list; T4 should check it.
3. **`normalization_issues` not recorded (N8).** Failed IP/GUID/integer conversions become NULL without a row in `normalization_errors`.
4. **`canonical_host` regex is unanchored (attacker).** A foreign `WorkstationName` containing "ep" + digits can become `ep-NN` in `source_host`/`destination_host`. No such value in t00.
5. **Accounting caveat.** `lines_read == sum of categories` is true by construction; the real checks are the manifest count and `events == kept`. An accounting mismatch writes no report.
6. **Dedup digest ignores the host folder.** Same payload and same `Computer` in two folders count as one event (strict xfail documents it).
7. **Known column meanings:** 4648 `account_name` is the account whose credentials were used; 4625/4697/4776 have no `session_id`; PowerShell 4103/4104 and 5145 `share_path` details are in `field_values_json` only where noted in the spec.

## Data findings that affect later stages (see `docs/research/t3_data_findings.md`)
- No SMB/RDP/WinRM Sysmon 3 on the endpoints of S02, S04, S07; `Image = System` only in S01 ep-03. Correction I cannot be applied as written to those trials. T4 must decide before T6/T7.
- Sysmon record time vs `UtcTime` has outliers on ep-02/ep-03 (clock steps), up to 16.6 h.
- s06 has no rundll32 LSASS read; s01 t00 and s02 share dc01/ep-01 data.

## New test ideas
- Real duplicate-export case (spec trial 1, §21.8) once such a trial exists.
- An end-to-end run where `journal_mode` is not `delete`.
- 4778/4779 and 4648 rows from a trial that has them in the development set.

## Spec rules with no test
None skipped. Partly covered: NF-02 (behavioural only), NF-26 "report before rename" (inferred), NF-T11 (two DBs for the same bytes).

## Result
261 tests pass, 1 strict xfail. Old files (`normalize.py`, `full_import.py`, `smoke_import.py`, `profile.py`, `schema.py`) and the 7 old tests are unchanged (git diff empty). Seven DBs imported, row counts reconcile with the manifests; `data/sample/` holds S02, S04, S05 t00.
