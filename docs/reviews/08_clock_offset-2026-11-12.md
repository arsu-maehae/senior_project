# Stage review: 08_clock_offset (implementation, T6b.3), 2026-11-12

PLAN 6b.3. Spec: [08_clock_offset.md](../specs/08_clock_offset.md) (step 1 approved). It is consumed by [02_gate.md](../specs/02_gate.md) (passages marked "T6b.2, decision 043").
Decision: [043](../decisions/043-clock-offset-method.md), including the T6b.2 implementation amendment.
Code reviewed:
- `src/clock_offset/`;
- the T6b.2 changes in `src/trial_window/`, `src/gate/` and `src/lab_common/manifest.py`;
- the CO-18 filter in `src/parsing_normalization/evtx_pipeline/{trial_normalize,trial_import}.py`.

Commits: 3391357, fd30632, a42e206, 64eef5d.

**Reviewers:**
- **tester** (in T6b.2): wrote `tests/unit/test_clock_offset.py` (COT-01..21, COA-01..04, 06..08) and updated `test_gate.py`, `test_trial_window.py`, `test_gate_real.py` (GTT-07 replaced, GTT-21, GTA-05 redefined, GTA-06 on the raw basis, GTA-07 new) and `test_trial_normalize.py` / `test_trial_import.py` (CO-18).
- **fact-checker**: checked the code against spec 08, spec 02, NF-09, decision 043 and the CLAUDE.md locked decisions.
- **attacker**: read only code, specs and outputs; it did not open `ground_truth/`, `tests/` or the DBs.

The orchestrator checked these claims read-only against the outputs, DBs and keys; each is marked "verified" below:
- the `params.py` hash;
- ATK-18;
- ATK-20;
- ATK-21.

## Run and results
- **Offsets:** `python -m clock_offset` on the 11 allowlisted trials (9 development + 2 clock-only).
  - All offsets equal spec §10.1. COA-01 is within 1 ms of the T6b.1 measurement script, which was rerun read-only.
  - Status: s06_t01 ep-03 `wide`, s07_t01 ep-03 `none`. The four hosts with no exported logs are `none` and not flagged.
- **CO-10 independent check:** 18 pairs in 6 groups. Raw worst 18.35 s, corrected worst 1.58 s, 0 above the 2.5 s review level and 0 above the 5 s kill level. 11 pairs have 2 candidates (WinRM keep-alive); the nearest is always the first logon (§10.5).
- **CO-19 scan:** `clock_change_in_window` is false on all 11 trials.
  - Every export hit is `expected_before_first_pair` (snapshot-revert catch-up) or `routine` (0–2 ms).
  - The ep-01 4616 found in both the s06_t00 and s07_t00 exports is the known same-day overlap of those trials' exports (decision 026). Noted, no action.
- **Window and gate on the six t00 trials** (corrected basis):
  - Trigger, unmatched and supporting rows are identical to the pre-switch baseline, and all 15 key hops are in `triggers.csv` at tier A.
  - The edge differences were accepted by the owner: 5 dc01 `::1` `loopback_or_self` dispositions and changed edge counts.
  - `clock_unreliable` is 0 on every row, `clock_flag` is empty, and `clock_change_in_window` is false.
- **Key events:**
  - COA-08: 0 of the 225 key-hop events of the six t00 keys were logged before a counted step.
  - GTA-07: all 225 lie inside the corrected windows, at least 50 s from either edge.
- **Tests:** full suite 1667 passed, 1 skipped (GTA-05: no development trial with a .97/.98/.99 session), 1 xfailed (pre-existing).
- **Params freeze (verified):** the SHA-256 of `src/clock_offset/params.py` with CRLF→LF is `9dcd662b…82e3`, which equals decision 043. Exactly `MIN_PAIRS`, `MAX_LOO_SHIFT_S`, `READING_AGREE_S` and `MIN_CLOCK_STEP_MS` are marked provisional.
- **Rule by rule** (fact-checker), each implemented as written:
  - CO-01..CO-10 and CO-14..CO-19 (as amended);
  - CO-09's single shared corrected-time function, used by both trial_window and the gate;
  - GT-00 order with nothing written on refusal, GT-01 on corrected times, the §3 columns and the §3.1 `clock` key;
  - the trial_window corrected basis and per-host manifest span;
  - the CO-18 filter.
- **Wording and data rules:** no wording-rule breaks. `src` never reads `ground_truth/` and never names a test trial.

## Blocking
None. No spec rule or locked decision is broken, no answer-key event is affected, and every test passes.

## Should fix
Ranked by likely damage. "Before test gating" means it should be fixed before any t02–t10 trial is gated (T9/T10). None of these occurs in the current development data.

| # | Source | Finding | Where | When |
|---|---|---|---|---|
| SF-1 | ATK-14 | A counted step found only in the **export** (every pre-CO-18 DB, i.e. all 70 existing trials) sets only `clock_change_in_window`. It does not cut pairs, make the host `stale`, or feed CO-17, so a step between pairs would leave a median that mixes two clock epochs on `ok`. CO-15 cuts on DB changes only, which matches the spec text, but this is a design gap for the existing trials. | `run.py:224`, `pairs.py:255-269`, `scan.py:325-372` | before test gating |
| SF-2 | ATK-13 | A planned resync (CO-12, t02–t10) logged **after** ep-01's start-of-trial pair burst drops those pairs (cut rule). ep-01 becomes `none`, and CO-17 refuses the trial even though the host is then within about 1 s of dc01. Option: carry the pre-step pairs across with the logged PreviousTime/NewTime. Depends on when the lab runs the resync. | `pairs.py:206-232`, `correct.py:152-168` | before the reruns are gated |
| SF-3 | S1 + ATK-16 | `--no-scan` rewrites `clock_changes.csv` with DB changes only, which is header-only for every existing DB, and nothing in the file says so. Window and gate accept it, so the export steps lose their `clock_unreliable` marking. Also, neither consumer checks the offsets or clock-changes file's `trial_id` against the trial, and the changes file carries no `db_sha256`; s04_t00 and s05_t00 share a header-only hash. | `__main__.py:47-60`, `run.py:318-322`, `correct.py:191-209`, `window.py:410-420`, `gate/inputs.py:112-131` | next code change |
| SF-4 | ATK-15 | Skipped or unplaceable export files (sha not in the manifest, missing file, zone-less timestamp) still give `clock_change_in_window = false`. `coverage_complete = false` is not carried forward. | `scan.py:343-365`, `correct.py:218-228` | next code change |
| SF-5 | ATK-17 | A backward step: the pair cut compares with the change's recorded (new, lower) time, so pairs recorded in the overlap [new, previous] are kept. The `clock_unreliable` interval handles the overlap, so the two rules disagree. Hypothetical: every dev step is forward. | `pairs.py:225` vs `changes.py:221-231` | next code change |
| SF-6 | ATK-18 (verified) | `offset_unc_ms` (= loo shift) understates the uncertainty on hosts whose pairs are one burst or one periodic task. s07_t00 ep-02: 12 of its 13 pairs are `admin_it` type-4 batch logons at 60 s intervals with alternating-sign deltas; the median equals the one type-7 pair (+74 ms); there is no CO-10 check. s04_t01 ep-03: 2 pairs, unc 56 ms. Matters when T7 widens the order tolerance by `offset_unc` (spec 08 §4.1 item 7). | `estimate.py:47-56,105` | T7 council (Q12) / step 2 |
| SF-7 | ATK-19 | CO-10 judges \|Δ\| only. A target logon cannot precede its source connection, yet 3 of the 6 groups have corrected Δ < −0.4 s (s06_t00 −1.57, s03_t01 −0.82, s06_t01 ep-03 −0.48). That hints at a bias, and a −4.9 s value would pass the kill test. Add an asymmetric review level. | `check.py:83-84` | step 2 |
| SF-8 | S2 | Spec 08 §2 says S01 uses the operator window, but `compute_trial` refuses a trial with no agent roots, so no S01 trial can get an offsets file, and trial_window and the gate would refuse every S01 trial. No effect today (s01_t00 excluded; S01 ×10 not ingested). | `run.py:214-216` | before S01 ×10 |
| SF-9 | S3 | Spec 08 §3 says clock pairs carry no tier. CLAUDE.md asks every linking row for a tier, and decision 038 covers only `gate_tier`/`confidence_tier`. The exemption needs a line in a decision record. | spec 08 §3, decision 043 | docs |
| SF-10 | S4, N11, N12, N13 / ATK-31 | Spec and decision text is out of date in four places: spec 08 line 24 ("none is present in the 11 measured trials" is true of the DBs only); decision 043 line 62 ("a clock step inside a trial is invisible"); the step-2 lists omit `MIN_CLOCK_STEP_MS`; spec §3 omits the `clock_changes.csv` columns `channel`, `event_id`, `last_boot_before_utc`. | docs | docs |

## Notes (no change needed now)
- **ATK-20 (verified):** the s06_t01 ep-03 `wide` status comes from one hop-logon pair (`admin_it` type 3, +5.99 s). Without it the host has 2 pairs and `ok`, and the CO-10 residual (−0.48 s) supports the median, so `wide` here is a false alarm. Candidate for step 2: report the status without lab-IP pairs.
- **ATK-21 (verified, no key event affected):**
  - In s02_t00, ep-02 events logged before its mid-window reboot (05:37:46) use the post-boot offset and are not flagged, because boots are excluded from the CO-15 `clock_unreliable` rule.
  - All 10 ep-02 key events are at 05:42:45–46, after the boot and the step.
- **ATK-22:** a dc01 step or reboot does not cut the endpoints' pairs; it only flags (`no_pairs`). Hypothetical.
- **ATK-23:** sub-threshold steps (< 1 s) do not accumulate. The routine shifts in the data are 0–2 ms.
- **ATK-24:** an unresolvable DB shift pointer counts as a step, which can cause a false `stale`. Only for new ingests whose JSONL files have been removed.
- **ATK-25:** CO-17 refusals may correlate with scenario (e.g. s07_t01 ep-03 has 1 pair). Report refusal counts per scenario when the reruns arrive.
- **ATK-26:** one physical step is listed twice (System 1 + 4616, ms apart). Counts double; flags are unaffected.
- **ATK-27:** `late_gap_s` subtracts times from two host clocks (raw). Cosmetic.
- **ATK-28:** the tool accepts test-trial ids (CO-01 refuses only quarantine and s01_t00). The CLI default is the allowlist, and spec §9 forbids using t02–t10 to choose anything. A "test" role label in stats would make misuse visible.
- **ATK-29 / N4:** the parameter-freeze hash covers `params.py` only. It does not cover the values imported from `trial_window.params`, `readings.SIGN_CONVENTION`/`WINDOWS_TZ` or `scan.KERNEL_GENERAL_PROVIDER`.
- **ATK-30:** on ep-01 the burst pairs are tight and the later pairs higher. That is consistent with a one-sided ticket-to-logon latency. The median is approved for step 1; report burst-only and minimum estimates beside it for step 2.
- **Fact-checker notes:**
  - N1: classification uses the kept-pair bounds, so a DB change that cut pairs becomes `expected` (deliberate; spec silent).
  - N2: the stale test has no window-start bound (two spec passages differ slightly).
  - N3: a shift rounded to whole ms before the 1 s test, so 999.5 ms counts.
  - N5: see SF-3.
  - N6: `clock_flag` and the 4616/System 1 test are each written twice (identical).
  - N7: `co17_date` has no type hint; `WINDOWS_TZ` is a mutable module dict; `run` and `scan` import each other at call time.
  - N8: `read_manifest_span` compares text (unchanged since T6).
  - N9: trial_window's default trials are the t00s only.
  - N10: `post_sync` and `end` can be the same reading.
  - N14: the spec §3 example row is missing four columns.
- **Readings parser (attacker):** no misreading could be constructed. Locale labels and DST zones are refused rather than guessed. A reading's local time is on the host's own possibly skewed clock, so a reading taken seconds after the run end could be assigned to the wrong phase. Confirm at the first rerun session, together with the sign and the time zone.

## New test ideas
- SF-1: an export hit between ep-01's pairs should cut the pairs or give `stale`.
- SF-2: s04_t01 ep-01 with a synthetic counted 4616 at 04:09:15 (inside the burst) → expected behaviour to be decided.
- SF-3: `--no-scan` then window and gate → refuse; swapped `clock_changes.csv` between two trials → refuse.
- SF-4: a renamed `system.jsonl` → flag `unknown`, or refuse.
- SF-5: a −12 s step with pairs at T−10 s and T+3 s (old clock) → both dropped.
- SF-7: corrected Δ < −0.5 s → review flag (s06_t00 would show).
- ATK-22: a dc01 +10 s step between two ep-01 pairs.
- ATK-24: a routine 4616 with an unresolvable pointer must not refuse the trial.
- ATK-25: CO-17 refusal count per scenario.

## Spec rules with no test or no implementation
- **Deferred to step 2:** CO-11(b) and CO-12 agreement / drift (COA-05). `READING_AGREE_S` is only reported.
- **Planned only:** the §4.2 ingest copy of `<HOST>_clock.txt`.
- **Not implemented:** spec 08 §2, the S01 operator window for the clock step (SF-8).
- **Only real-data GTA-05 branch untested:** GTA-05's stop-and-report branch, until a development trial has a .97/.98/.99 session.
- **Behaviour the specs do not state, so untested:** a host or manifest host missing from the offsets file; raw-basis `start_host`/`end_host`; the wording of the `report.md` clock section.
- **Not separately testable:** `DC_EDGE_S` = 120 s apart from `MAX_PAIR_DELTA_S` = 60 s.

## Verdict
No blocking item, so T6b.2 and T6b.3 are done. Step 2 (PLAN 6b.4) stays open. SF-1..SF-4 should be fixed before any t02–t10 trial is gated, and SF-2 before the rerun t02–t10 trials are gated (it depends on when the resync is run). SF-6, SF-7 and the ATK-20/30 notes are inputs to step 2 and the T7 council. SF-9 and SF-10 are documentation.

## Resolution of SF-1..SF-4 (2026-11-12, owner decisions in decision 043 items 11–12)
| # | Resolution |
|---|---|
| SF-1 | **Fixed.** Clock changes found by the CO-19 export scan count like DB rows for the CO-15 cut and for `stale` (deduplicated on host, channel, event id and instant). The owner set the flag and classification to be measured against the host's **original** pairs (before the cut): a counted step between them is `between_pairs` and flags the trial, while the cut still drops the earlier pairs. Spec 08 CO-15 and CO-19 amended. |
| SF-2 | **Resolved by procedure, no code.** Lab-order check: on all 11 allowlisted trials, ep-01's offset pairs are its boot logons 4–35 s after the boot, so the planned resync would land after them and refuse every rerun trial. Owner: no rerun trial is synced; each trial gets a reading before the scenario and one after collection on EP-01/02/03, each followed by `tzutil /g`. The D2 cut is unchanged. Spec 08 CO-12 and Q8, decisions 043 (item 11) and 032, and `docs/lab/rerun_plan.md` amended (commit bab68d8). |
| SF-3 | **Fixed.** `--no-scan` is removed, and `run(write=True, scan=False)` raises. The offsets file carries `clock_changes_sha256` and `clock_scan`. trial_window and the gate refuse when an offsets or changes row names another trial, when the changes file does not match its hash, or when an `ok`/`wide` row has no `offset_ms`. The `params.py` hash is re-recorded in 043 (`0068779d…`); no parameter value changed. |
| SF-4 | **Fixed.** A skipped manifest-listed export, or a clock-change record without a time, gives `clock_scan = incomplete` and a null flag, and the trial is refused (owner). A host or channel with no file in the manifest is not a skip. |

**Effect on the development data:**
- On the 11 allowlisted trials, every offset value, `pairs.csv`, `clock_changes.csv` and `clock_events.csv` is identical to before.
- Every scan is `complete`.
- On the six t00 trials the four gate CSVs are byte-identical; only `offsets_sha256` changed in `data/trial_windows.csv`.

SF-5..SF-10 stay open (step 2, T7 council, docs).
