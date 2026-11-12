# Stage spec: 08_clock_offset

**Owner:** <stage owner> · **Status:** **step 1 (method) approved by the owner, 2026-11-12** (answers in §8). **Step 2 open:** `MIN_PAIRS`, `MAX_LOO_SHIFT_S`, `READING_AGREE_S` and the `late_gap_s` limit (Q11) are confirmed on the rerun t01 trials (2026-11-23..28) and their start and end clock readings, once ingested · **Last updated:** 2026-11-12

Decisions: [032](../decisions/032-x10-clock-sync-and-offset-correction.md) (offset correction for kept trials, kill criteria), [014](../decisions/014-cross-host-time-tolerance.md) (5 s tolerance; option C "correct each host" — this stage implements it for the trials 032 names, the tolerance is unchanged), [039](../decisions/039-gate-window-input-and-clock.md) (gate and window use corrected times once this exists), [043](../decisions/043-clock-offset-method.md) (method; accepted for step 1, 2026-11-12). Measurements: §10. Attacker review: [08_clock_offset-spec-2026-11-12](../reviews/08_clock_offset-spec-2026-11-12.md).

## 1. Purpose
For each trial, this step estimates how far each endpoint's clock is from dc01's clock, using the trial's own Kerberos evidence. Each endpoint 4624 that carries a LogonGuid is paired with the dc01 4769 that has the same LogonGuid. The step writes one offset per host next to the trial DB. From 2026-10-26, ep-01 ran 10–27 s behind dc01. The 5 s cross-host joins (decision 014), the trial window clip and the Correction K order check ("the move happened after the dump") would therefore all compare times from clocks that disagree. With the offsets, the gate, the window step and T7 compare **corrected** times. The original times are never changed.

## 2. Input contract
| Input | What is read | Notes |
|---|---|---|
| Trial DB | `data/processed/<trial_id>.sqlite3`, view `events_dedup`, opened read-only | One DB per trial (NF-09). Hash before = hash after. |
| Search span | the trial's agent-run window computed **in memory on raw times** with `trial_window.window.computed_window` (agent tree, decision 040), widened by `PAIR_PAD_S` on both sides | Not read from `data/trial_windows.csv`: that file is computed on corrected times after this step (§4.1). No clock refusal applies here. S01 uses the operator window (spec 02_gate §2.1). |
| Manifest | `data/manifest.csv` export span (`lab_common.manifest.read_manifest_span`) | Only for the window clip, as in trial_window. |
| Parameters | `src/clock_offset/params.py` (§5) | |

Columns used: `event_uid, host, channel, event_id, event_utc, logon_guid, logon_guid_state, logon_type, account_name, source_ip, service_name`.
- `logon_guid` is stored lower-case, without braces. An all-zero GUID is stored as NULL with `logon_guid_state = 'zero'`, and NULL never pairs (data-checker 2026-11-12, `data/sample/`).
- `event_utc` is the instant used (decision 010). Instants are compared, never text.
- The step never opens `ground_truth/` and never reads the answer keys.
- It reads only `events_dedup`.

Not available in the DB: Security 4616 ("system time was changed") and the System Kernel-General / Time-Service events. The normaliser does not keep them, and none is present in the 11 measured trials (§10.6). **In the existing DBs, a clock step inside a trial cannot be seen.** Owner Q6: new ingests keep these events (CO-18), and a read-only scan covers the existing trials' exports (CO-19).

## 3. Output contract
**`data/processed/<trial_id>.clock_offsets.csv`**: one row per endpoint (ep-01, ep-02, ep-03), plus a dc01 row with offset 0. It sits next to the DB, as decision 032 asks. The file is rebuilt on every run and is byte-identical on the same inputs.

| Column | Type | Meaning |
|---|---|---|
| trial_id | text | `<scenario>_<trial>` |
| host | text | `dc01`, `ep-01`, `ep-02`, `ep-03` |
| offset_ms | int/empty | estimated host − dc01 clock offset, in ms. Corrected time = `event_utc − offset_ms`. Empty when `offset_status` is `none`. dc01 = 0. |
| offset_status | text | `reference` (dc01, unverified: there is no absolute time), `ok`, `wide` (estimate unstable, CO-06), `stale` (the host booted after its last pair, inside the window, CO-15), `none` (not corrected, CO-07). Every status except `reference` and `ok` flags the trial (CO-08). |
| offset_unc_ms | int/empty | uncertainty carried to T7: `loo_shift_ms` (CO-06, ATK-03) |
| n_pairs | int | number of 1:1 pairs used |
| n_dropped_far | int | pairs dropped because \|delta\| > `MAX_PAIR_DELTA_S` (CO-02, ATK-02) |
| n_pairs_lab_ip | int | pairs whose 4624 `source_ip` is a lab host (hop logons), reported for audit (ATK-02) |
| late_gap_s | int/empty | seconds from the host's last paired 4624 to the **last agent event in the trial window** (the last Sysmon 1 of the agent tree, i.e. the uncut window end − 300 s; raw times, like the rest of this step). *(owner 2026-11-12, after T6b.2)* The earlier bracket "(window end − 300 s)" was wrong wherever the manifest clip cuts the window end (7 of the 11 measured trials); §10.7 is corrected. Shows how far the estimate is extrapolated (ATK-01) |
| min_ms, q1_ms, median_ms, q3_ms, max_ms | int/empty | distribution of the pair deltas (host 4624 − dc01 4769) |
| loo_shift_ms | int/empty | largest change of the median when any one pair is left out (CO-06) |
| pair_span_s | int/empty | seconds between the first and the last paired 4624 |
| host_has_events | bool | the host has any event in the trial window (CO-08). *(Owner 2026-11-12, T6b.2: computed on the raw agent window, a few seconds from the corrected one at the edges; accepted, since it only asks whether a host has any events in the trial. `clock_flag` and CO-17 use it.)* |
| method | text | `logonguid_4624_4769_mutual_nearest_median` |
| search_start_utc, search_end_utc | text | the search span used |
| db_sha256 | text | SHA-256 of the trial DB the offsets were computed from |
| tool_version | text | code version |

Example row (s06_t01, measured): `s06_t01,ep-01,-18781,ok,5,-18828,-18816,-18781,-15260,-10986,1760,35,true,logonguid_4624_4769_mutual_nearest_median,…`. With `MAX_LOO_SHIFT_S = 2.5`, ep-01's 1.76 s gives `ok`.

**`out/clock_offset/<trial_id>/`**:
- `pairs.csv`: one row per pair, with `host, event_uid_4624, event_uid_4769, logon_guid, t_4624_utc, t_4769_utc, delta_ms, logon_type, account_name, service_name, method, candidate_count, time_delta_ms`. Here `candidate_count` is the number of dc01 4769s with that GUID in the span, and `time_delta_ms` = `delta_ms`.
- `stats.json`: counts of GUID-bearing 4624/4769, pairs dropped by the mutual-nearest rule per host, and the independent check of CO-10.
- `report.md`: a short human-readable summary.

*(Added by the owner 2026-11-12, T6b.2, decision 043.)* **`data/processed/<trial_id>.clock_changes.csv`**, next to the offsets file: one row per clock change found in the DB (CO-18) or in the exports (CO-19). Columns: `trial_id, host, change_utc, previous_time, new_time, shift_ms, counted, classification, source (db|export), event_uid_or_record, source_sha256`; sorted by host, then `change_utc`; byte-identical on rerun. The consumers' `clock_unreliable` rule for events before a counted change (CO-15) reads it, and its SHA-256 is recorded in the window row like the offsets file. `out/clock_offset/<trial_id>/` also gets `clock_events.csv` and `clock_scan.json` (CO-19).

Every row that links events records `method`, `candidate_count`, `time_delta_ms` and the supporting `event_uid`s (CLAUDE.md code rules). The tier concept does not apply to clock pairs: no `gate_tier`/`confidence_tier` here.

## 4. Rules
| ID | Rule | Source |
|---|---|---|
| CO-01 | **Allowed trial.** Refuse quarantined trials (`s05q_*`, `quarantine/`, decision 030) and `s01_t00` (decision 019). Every other trial may be measured. Measuring is not gating, and the result is written before any scoring. | 019, 030 |
| CO-02 | **Evidence.** Endpoint side: Security 4624 on ep-01/02/03 with a non-NULL `logon_guid`. DC side: Security 4769 on dc01 with a non-NULL `logon_guid`. Both lie in the search span (4769s up to 120 s beyond the span edges, so pairs at the edge keep their partner). No other event pairs. *(ATK-02)* After pairing, a pair with \|delta\| > `MAX_PAIR_DELTA_S` is dropped and counted in `n_dropped_far`. This stops a lone GUID pair minutes apart (ticket cache, GUID reuse) from moving a host by minutes. Hop logons (4624 from a lab IP) are kept, because they measure the same host clock, and counted in `n_pairs_lab_ip`. | 032 (criterion g measure, validator N11); §10.2; §10.7 (largest measured \|delta\| 18.83 s, so 60 s drops no measured pair) |
| CO-03 | **Pairing: 1:1 mutual nearest.** Within one GUID, a 4624 and a 4769 pair only if each is the other's nearest in time. Every 4624 and every 4769 is used at most once per host. GUIDs reused by several 4624s or 4769s then yield at most the closest pairs, never every combination. | §10.3: rule A is the only tested rule with every independent check ≤ 5 s (B "nearest per 4624" 6.22 s, D "no type 4" 6.52 s, C "unique GUID only" leaves hosts unmeasured) |
| CO-04 | **Delta** = 4624 instant (host clock) − 4769 instant (dc01 clock). | 032 |
| CO-05 | **Estimate** = median of a host's deltas, when `n_pairs ≥ MIN_PAIRS`. dc01's offset is 0 by definition (dc01 is the reference; there is no absolute time, decision 014). The minimum and the mean are not used. | §10.1: single deltas scatter ±3–9 s in **both** directions around a stable centre (s07_t00 ep-02, 13 pairs at 60 s intervals, −4.06 … +8.52); dc01 same-clock 1:1 pairs have a median latency of 4–8 ms, so the scatter is endpoint-side ticket timing, not network delay. The median ignores it; the minimum assumes one-sided latency (§10.3, minimum variant) |
| CO-06 | **Stability.** `loo_shift` = max over pairs of \|median(all) − median(all but that pair)\|. If `loo_shift > MAX_LOO_SHIFT_S`, the status is `wide`. *(Owner Q4)* A `wide` host **is corrected**, never left raw. The trial is flagged, and the flag is carried into every result (CO-17). With 2 pairs, `loo_shift` is half their gap, so a 2-pair host whose pairs differ by more than 5 s is `wide`. | §10.4; spread and IQR are reported but not used, because single-pair scatter makes them large even where the estimate is confirmed (s06_t01 ep-01: spread 7.84 s, independent residual ≤ 0.48 s) |
| CO-07 | **Too few pairs.** `n_pairs < MIN_PAIRS` gives status `none`: no correction (raw times for that host), `offset_ms` empty, and the trial flagged (decision 032). *(Owner Q3)* A host with 1 pair is **not corrected** (`MIN_PAIRS = 2`, provisional until step 2); the single delta is reported for audit only. | 032 Decision 3 |
| CO-08 | **Flag scope.** The trial flag `clock_flag` lists each host with status `none`, `wide` or `stale` **that has events in the trial window**. A host with no events in the window (e.g. ep-03 in s02_t00, s04_t00, s07_t00, ep-02 in s03_t00, whose logs were not exported) has nothing to correct and is reported, not flagged. | §10.1 (the 0-pair hosts all lack Security logs, validator criterion a) |
| CO-09 | **Original times are kept.** The DB is never written. Consumers compute `event_utc_corrected = event_utc − offset_ms(host)` with one shared pure function. Every output that uses a time writes both `event_utc` (original) and `event_utc_corrected`. A host with status `none` gives `event_utc_corrected = event_utc`. *(ATK-03)* Every output row that compares times across two hosts carries `clock_unreliable = true` when either host is `none`, `wide` or `stale`. A mixed row (one side corrected, the other not) is therefore marked on the row itself, not only through the trial-level `clock_flag`. | 032 Decision 3; 039 Q4 |
| CO-10 | **Independent check (per trial, reported).** Cross-host pairs that do not use LogonGuid: a source Sysmon 3 to another lab host on 445/3389/5985/5986, joined to the target 4624 with `IpAddress` = source IP and `IpPort` = the Sysmon 3 source port. *(ATK-07)* The join is made on **raw** times, nearest within ±`CHECK_JOIN_S`, before any correction, and a port with more than one candidate is reported as ambiguous. The correction therefore cannot choose its own check partner. For each pair, report raw and corrected Δ = target − source, and \|raw\| vs \|corrected\| (net effect, ATK-06). These pairs never enter the estimate. The source and target are both endpoints, so the check does not depend on dc01's clock (ATK-09). | §10.5. A connection precedes its logon by milliseconds to about 1 s (s05_t00, s06_t00 raw 1.2–1.8 s while offsets are small), so a corrected \|Δ\| > 5 s means the correction is wrong for that host pair |
| CO-11 | **Kill criterion (decision 032), applied on development data before step 2.** The correction is not used if (a) any development CO-10 pair has corrected \|Δ\| > 5 s, or (b) any rerun t01 host's computed offset differs from the lab's clock reading for that host by more than `READING_AGREE_S` (CO-12). Then the owner decides which trials are excluded or rerun (032, 039 kill criteria). *(ATK-07)* A **review level** of 2.5 s also applies: any check pair above it is reported to the owner, but it does not kill the correction by itself (032 fixes the kill at 5 s). Measured today: (a) passes, worst corrected \|Δ\| 1.58 s over 6 groups / 18 pairs (raw worst 18.35 s), and no pair is above the 2.5 s review level (§10.5). (a) rests on **one** skewed trial (s06_t01, source ep-01, 2 groups). (b) waits for the reruns. **Limit:** the LogonGuid pairs cannot validate themselves; after correction, the host-pair offsets they measure are 0 by construction. Only CO-10 and CO-12 are independent. | 032 Kill criteria |
| CO-12 | **Rerun clock readings (owner 2026-11-12; Q5, Q8 option c).** **Procedure:** the rerun trials run 2026-11-23..28.<br>• **t01 of each scenario (development):** not synced, so it keeps its real skew. One reading before the run and **one after collection**, so drift during the trial is measured.<br>• **t02–t10 (test):** a reading, then a time sync, then a reading after the sync; both are recorded.<br>**Format:** `w32tm /stripchart` text, followed by *(owner 2026-11-12, T6b.2)* the output of `tzutil /g` (the Windows time-zone name), one file per VM per trial, saved as `<HOST>_clock.txt` in the trial folder (`data/incoming/x10_v2/<scenario>/trial_NN/`). The ingest copies it, never edited, to `data/raw/<scenario>/<trial>/<host>/clock.txt` and records it in `data/manifest.csv` (T6b.2).<br>**Parsing:** the parser reads the `Tracking <target>` line, which must name dc01 (otherwise the file is reported as invalid), and the `o:` offset values with their timestamps. Each reading is stored as host − dc01, with the raw text kept. w32tm prints local wall-clock time. The parser converts it to UTC with the time zone from the `tzutil /g` line, mapped to IANA by an explicit table. If the line is missing, the time zone is a required argument. If neither is present, or the name is unknown and no argument is given, the file is invalid. The time zone is confirmed at the first rerun session, together with the sign. The sign convention is checked once, at the first rerun session, on a host whose LogonGuid estimate is \|x\| > 2 s. Within a file, readings are assigned by time: before the run = start; after the run or after collection = end; after a sync = post-sync.<br>**Step 2 uses only the t01 readings:**<br>• the computed offset must lie within `READING_AGREE_S` of [start reading, end reading];<br>• a start–end difference above 2.5 s is reported as drift and the trial is flagged;<br>• these readings also set the `late_gap_s` limit (Q11).<br>The t02–t10 readings are reported with the results and **never used to change a parameter**. Those trials are synced and have no end reading, so drift during them is measured only by CO-10 (a stated limit). This is the only check that covers ep-02/ep-03 and hosts with no WinRM hop. | owner additions A2, Q5, Q8 |
| CO-13 | **Applies to every host and every trial**, whatever the size of the offset. There is no "only correct above x s" threshold, so nothing more is tuned. Trials before 2026-10-26 are corrected too (ep-03 at +3.5…+4.5 s while ep-01 sits at −2.3 s gives host pairs of 5–6 s, e.g. s03_t01 ep-01→ep-03 raw 5.68 s → corrected 0.82 s). *(ATK-06)* On small offsets the correction can be slightly worse than raw. In s06_t00 ep-01→ep-02, raw 1.22 s became corrected −1.57 s, about 0.35 s worse in absolute terms (raw also contains the ~0–1 s real connect-to-logon delay). The net effect is reported per check pair (§10.5). The spec does not claim the correction is never harmful. *(Owner Q10)* Every host is corrected; there is **no minimum offset**. | §10.5; validator g |
| CO-14 | **Determinism.** Rows are sorted by host. Ties in the nearest search are broken by `event_uid`. The same DB gives byte-identical files. | code rules |
| CO-15 | **Reboots (ATK-08).** Only pairs whose 4624 is after the host's last boot/shutdown event (System 41, 1074, 6005, 6006, 6008) before the host's first pair are used. A boot on the host **after** its last pair and before the window end gives status `stale`: the estimate describes a clock from before the restart. It is not applied (treated as `none`) and the trial is flagged. In DBs ingested before CO-18 this is the only clock-change signal in the DB; CO-18 adds the clock-change events to new ingests, and CO-19 scans the existing trials.<br>*(Amended by the owner 2026-11-12, T6b.2, decision 043.)* **Counted change:** a boot/shutdown event always counts. A clock change (4616, Kernel-General System 1) counts only when \|shift\| ≥ `MIN_CLOCK_STEP_MS` (1 s, provisional). A smaller one is `routine`: Windows logs 0–2 ms time-service adjustments (s06_t00, s07_t00 ep-02, §10.6). It is listed and changes nothing. A clock change whose shift cannot be read counts. **Cut:** a counted change between two pairs drops every pair at or before it, so only pairs after the last counted change before the host's last pair are used. Fewer than `MIN_PAIRS` left gives `none`. A counted change after the host's last kept pair, inside the window, gives `stale`. A counted change before the first pair is reported as `expected`. *(This replaces the self-contradictory "one before its first pair drops the earlier pairs" of CO-18.)* In a DB, the shift of a 4616/System 1 row is read from its JSONL line through the row's `source_relative_path` + `source_line` (NF-09), read-only. **Events before a counted change:** every event on a host logged before a counted clock change (\|shift\| ≥ 1 s; boots not included) has `clock_unreliable = 1` in every output, because the host's single offset describes its clock after the change. "Logged before" means recorded time in [the host's last boot before the change, max(previous time, change time)). For a backward step (shift < 0), the interval runs up to and including the previous time, so the overlap [new time, previous time] counts as unreliable. | §10.7: in all 11 trials every host's pairs come after its last boot (e.g. s02_t00 ep-02 boot 05:37:46, pairs from 05:37:58); no host is `stale` |
| CO-16 | **Extrapolation is reported, not gated (ATK-01).** ep-01's pairs are start-of-trial logons; the attack comes later. `late_gap_s` and `pair_span_s` are reported. A drift or slew after the burst is detectable only by CO-10 (where a WinRM hop exists) and by CO-12's start-and-end readings. Requiring ≥ 2 pair clusters (attacker's proposal) would leave ep-01 uncorrected in every measured trial, the worst outcome for the host with the skew, so it is not adopted. A `late_gap_s` limit is decided in step 2 from the start/end readings (Q11). | §10.7 (late gap −50 … 351 s on the development t01s, 161 / 305 s on the clock-only t01s, 141 … 515 s on t00; corrected 2026-11-12, see §3); s06_t01: the check pairs 4 min after the burst agree within 0.48 s with the −18.8 s cluster, not with the later −15.3 / −11.0 pairs, so those pairs are scatter, not a slew toward dc01 |
| CO-17 | **Gate use of flagged hosts (owner Q2).** A trial whose window starts on or after 2026-10-26 is **refused** when any host with events in the window is uncorrected (`none` or `stale`). Raw times on such a host may be up to 27 s wrong (decision 032). Before 2026-10-26, such a trial runs with that host on raw times, and `clock_flag` plus the row-level `clock_unreliable` (CO-09) are carried. A `wide` host is corrected and runs, and its flag is carried into every result (gate, T7, T9). | owner 2026-11-12 |
| CO-18 | **Clock-change events in new ingests (owner Q6).** New ingests keep Security 4616 ("system time was changed") and System event 1 in the trial DB. This needs an amendment to spec 01 (NF-09, `TRIAL_RELEVANT_EVENT_IDS` in `src/parsing_normalization/evtx_pipeline/trial_normalize.py`), made in T6b.2. *(Amended by the owner 2026-11-12, T6b.2, decision 043.)* System 1 is kept **only when its provider is `Microsoft-Windows-Kernel-General`**. Event id 1 is used by other System providers too (e.g. a resume-from-sleep event), and the DB has no provider column, so the ingest filter checks the decoded record's `system.provider` before the row is written. A System 1 with another provider or no provider is not kept. Every System 1 in a DB ingested after this change is therefore a Kernel-General time change. **Existing trials are not re-ingested.** Where a DB holds these events, CO-15 also treats them as a clock change: one after the host's last pair gives `stale`, and only pairs after the host's last clock change before its first pair are used.<br>*(Owner 2026-11-12, T6b.2, decision 043)* **Expected change on the synced reruns:** on t02–t10 the forced `w32tm /resync` (CO-12) logs a 4616 at the start of each trial. That is the planned sync, not an anomaly. The rule above handles it, because the pairs after the sync are the ones used. It is reported as `expected` (a 4616 before the host's first pair), separately from an unexpected change after the host's last pair (`stale`). | owner 2026-11-12 |
| CO-19 | **Read-only scan of existing trials for clock changes (owner Q6).** This scan is a separate check: it writes nothing into any DB.<br>**Source:** the decoded full exports of each trial, `data/processed/jsonl/<trial>/per_file/<host>/{security,system}.jsonl`. They hold every EVTX record before the DB filter. Each file is matched to `data/manifest.csv` by the `source.sha256` of its records; a mismatch is reported and the file is skipped. The files are only read.<br>**What it looks for:** Security 4616, and System 1 with provider `Microsoft-Windows-Kernel-General`, within the trial's raw search span (agent window ± `PAIR_PAD_S`).<br>**Output:** `out/clock_offset/<trial>/clock_events.csv`, with host, channel, event id, provider, `timestamp_raw`, previous and new time where the event logs them, the shift in ms, `record_index` and `source.sha256`. Any hit sets the trial flag `clock_change_in_window`, reported with every result; the owner decides on the trial.<br>*(Amended by the owner 2026-11-12, T6b.2, decision 043, after the first scan found hits in 9 of the 11 allowlisted trials, all before the host's first pair or routine.)* The flag is set **only by a counted change (CO-15) after the host's first pair** (`between_pairs`, `after_last_pair`), **or by one on a host with no pairs** (`no_pairs`, dc01 included). A counted change before the first pair (`expected_before_first_pair`: the planned resync, or a snapshot-revert catch-up) and a `routine` change do not set it. Every hit stays in `clock_events.csv` and the report, with `classification` and `counted`. For every counted change inside the agent window, the report lists the host's DB events logged before it, with their real time (recorded + shift) inside the window, and the literal count recorded in [window start, change time). A test checks that no key-hop event of the development trials was logged before a counted change on its host; if one was, the run stops for the owner. The DB and export changes are written together to `data/processed/<trial>.clock_changes.csv`, which the consumers use for the CO-15 `clock_unreliable` rule.<br>**Scope:** it runs on all trials as a data-quality flag. It derives no parameter and is never used to tune. | owner 2026-11-12 |

### 4.1 How the gate and the window step switch from raw to corrected (amendments listed, not made here)
These changes belong to spec 02_gate, `src/trial_window` and (CO-18) spec 01. Step 1 is approved, so they are made in T6b.2.
1. **Order of steps:** `clock_offset` (this step) → `trial_window` (on corrected times) → gate. The pair search uses a raw-time window only to bound the search, padded by `PAIR_PAD_S` (30 min ≫ 27 s skew). So no step needs its own output first.
2. **`CLOCK_CORRECTION_AVAILABLE`** (in `src/trial_window/params.py`) becomes true once this step exists. The flag then means "corrected times are required". `TIME_BASIS = "corrected"`.
3. The **2026-10-26 refusal** (`RAW_TIME_CUTOFF_DATE`, 02_gate §2.2, GT-00, GTT-07) is replaced by:
   - refuse when `<trial>.clock_offsets.csv` is missing;
   - refuse when its `db_sha256` differs from the DB;
   - refuse when the window row's `offsets_sha256` (new column in `trial_windows.csv`) differs from the offsets file;
   - refuse a trial whose window starts on or after 2026-10-26 when a host with events in the window is `none` or `stale` (CO-17);
   - otherwise run, carrying `clock_flag` (and `clock_change_in_window`, CO-19) into `stats.json` and every output row.
4. **`trial_window`** computes the agent-tree window on corrected times (each Sysmon 1's host offset applied) and writes `time_basis = corrected` and `offsets_sha256`.
5. **Gate:**
   - GT-01 clips on `event_utc_corrected`;
   - every cross-host pairing uses corrected times (R5 type 3 ↔ 3389, WinRM 91 ↔ anchor);
   - same-host pairings are unaffected, because one offset per host cancels;
   - outputs add `event_utc_corrected` next to `event_utc`;
   - `stats.json` adds `clock_flag` and the offsets used.
6. **GTA-06** (computed window start = the key's `run_interval` start) compares raw times. The keys are in raw time, and the corrected start moves by the agent host's offset (t00 ep-01: −1.14 … +3.37 s, §10.1). *(Owner Q7, accepted)* GTA-06 compares a raw-basis window computed for the test only. The keys are never edited.
7. **T7/T9:** decision 014's 5 s tolerance and the Correction K order check use corrected times. The offsets, `clock_flag` and `clock_unreliable` are reported with every result (032). *(Owner Q12)* **No change to the identity value now.** `offset_unc` (per host) and `clock_unreliable` (per row) are carried to T7. How they enter the order check is decided in the T7 spec council. Candidate on the table (ATK-03): the `order_within_tolerance` flag at \|move − dump\| < 5 s + `offset_unc`(source) + `offset_unc`(target).
8. *(ATK-11)* **New 02_gate test:** on the development trials, no key-hop event is removed by the clip on the corrected basis, and the `near_window` counts are reported before and after correction.
9. *(T6b.2 finding, 2026-11-12)* Item 5's "cross-host pairing (R5 type 3 ↔ 3389, WinRM 91 ↔ anchor)" is imprecise. In the gate code (`rdp_pair_method`, `r8_rows`, `pair_wsmprovhost_91`, `pair_services`), every pairing requires both events on the **same host**, so one offset per host cancels and these pairings are unchanged by the correction. On the gate side, only the GT-01 clip (and the `near_window` counts) depends on the time basis. The real cross-host comparisons (decision 014, Correction K) are in T7/T9.

### 4.2 Ingest of the rerun clock readings (plan only, T6b.2; built with the x10_v2 ingest)
No code touches `data/raw` in T6b.2. The x10_v2 ingest will:
- find `data/incoming/x10_v2/<scenario>/trial_NN/<HOST>_clock.txt`, one per VM;
- copy it byte for byte to `data/raw/<scenario>/<trial>/<host>/clock.txt` (host lower-case, as for the EVTX files), **refusing to overwrite** an existing file;
- add a `data/manifest.csv` row (`channel = clock`, sha256, size, source_path; `records` and the event times empty);
- leave parsing to `src/clock_offset/readings.py` (CO-12), which only reads the copy.
The incoming file is never edited. A file whose `Tracking` line does not name dc01 is still copied, and is reported as invalid by the parser.

## 5. Parameters
| Name | Value | Why | Sensitivity test? |
|---|---|---|---|
| `PAIR_PAD_S` | 1800 s | same as validator N11. Pairs cluster at trial start (ep-01 pair span 2–35 s on most trials, §10.1), so the pad only has to cover the run; 30 min ≫ the largest skew (27 s). Earlier snapshot days in the DB are days away and stay out (data-checker) | yes: ±10 min vs ±30 min vs whole DB (§10.1 whole-DB column: same pairs on all 11 trials) |
| `DC_EDGE_S` | 120 s | 4769 partner of an edge pair just outside the span | no |
| `MIN_PAIRS` | **2 (provisional, step 2)** | 2 is the smallest sample with a median and a stability value. With 3, s07_t01 ep-01 (2 pairs, −12.26 s; validator −12.26 s) would stay uncorrected, a raw error of ≥ 12 s. 1 pair has no stability value; owner Q3: not corrected | yes: 2 vs 3 on the rerun t01s with clock readings |
| `MAX_LOO_SHIFT_S` | **2.5 s (provisional, step 2)** | half of the 5 s tolerance (decision 014), set from the tolerance, not fitted to the data. In development + clock-only data only s06_t01 ep-03 exceeds it (2.97 s; its independent residual is −0.48 s) | yes, on the reruns |
| `READING_AGREE_S` | 2.5 s (proposal) | same reasoning: half the tolerance | after reruns |
| `MIN_CLOCK_STEP_MS` | **1000 ms (provisional, step 2; owner 2026-11-12)** | smallest clock change that counts (CO-15). Measured on the exports of the 11 allowlisted trials: routine time-service adjustments 0–2 ms; real steps 8.48 s (s02_t00 ep-02) to hours (revert catch-up). 1 s is far above the routine and well below the 5 s tolerance. | yes, on the reruns (t01 readings) |
| `CHECK_PORTS` | 445, 3389, 5985, 5986 | ports with a target 4624 carrying `IpPort` | no |
| `MAX_PAIR_DELTA_S` | 60 s | ATK-02: a bound above the largest real skew (27 s, decision 032) and the largest measured \|delta\| (18.83 s), well below the reuse outliers (360–400 s, §10.4) | report `n_dropped_far` |
| `CHECK_JOIN_S` | 60 s, raw time | ATK-07: wider than any raw offset (27 s), and joined before correction | no |
| `CHECK_REVIEW_S` | 2.5 s | ATK-07: review level for CO-10; the kill stays 5 s (032) | no |

**Parameter freeze (ATK-10).** `params.py` is committed, and its hash is recorded in decision 043 before the step-2 rerun check. Step 2 may change only `MIN_PAIRS`, `MAX_LOO_SHIFT_S`, `READING_AGREE_S` and `MIN_CLOCK_STEP_MS`, and only from the rerun t01 trials and their readings. Facts about test trials (s02_t03/t04 with no dc01 Security; the s06_t04 −25 s example in 032) come from the validator report, which covers all trials. They were used here only to name edge cases. **No parameter is derived from them.**

## 6. Edge cases (from attacker review)
Full review: [08_clock_offset-spec-2026-11-12](../reviews/08_clock_offset-spec-2026-11-12.md), ATK-01..12.

| Case | Where it occurs (scenario/trial) | Expected behaviour | Test ID |
|---|---|---|---|
| ep-01's pairs all come from one burst at trial start (type 4 svc_sql/admin_it/svc_backup + type 3 `endpoint-01$`), not from the attack | every measured trial (span 2–35 s; s02_t00 708 s) | estimate as normal; `pair_span_s` reported. A drift after the burst is caught only by CO-10/CO-12 (s06_t01: burst 06:18:28, check pairs 06:22:12–56, residual ≤ 0.48 s) | COA-02 |
| GUID shared by several 4624s or 4769s | s06_t01 ep-03 (5 4624s per GUID), dc01 self-pairs up to 360 s | 1:1 mutual nearest (CO-03). Never all combinations | COT-03 |
| host with no Security log exported | s02_t00/s04_t00/s07_t00 ep-03, s03_t00 ep-02 | `none`, `host_has_events = false`, not flagged (CO-08) | COT-08 |
| host with 1 pair | s07_t01 ep-03 | `none` with the single delta in `pairs.csv` (CO-07, owner Q3) | COT-07 |
| test trial with no dc01 Security log | s02_t03, s02_t04 (validator a) | every endpoint `none`, trial flagged; refused if on or after 2026-10-26, else run raw with the flag (CO-17) | COT-09 |
| ATK-01: clock steps or slews between the start-of-trial burst and the attack | hypothetical. s06_t01 shows no slew (check pairs 4 min later agree within 0.48 s) | reported via `late_gap_s` (CO-16); caught only by CO-10 / CO-12 start-end readings; a limit is set in step 2 (Q11) | COT-13 (synthetic 12 s step after the burst: status stays `ok`, `late_gap_s` reported; documents the limit) |
| ATK-02: lone GUID pair minutes apart (ticket cache, reuse) | hypothetical. Reuse outliers up to 400 s seen in dc01 self-pairs (s03_t00) | dropped by `MAX_PAIR_DELTA_S`, counted in `n_dropped_far` (CO-02) | COT-14 (a 600 s pair is dropped; 2 pairs 300 s apart lose one, so `none`) |
| ATK-02: 2–3 pairs, one far | s07_t01 ep-01 (2 pairs, 3.5 s apart, `loo_shift` 1.75) | `ok` at 2.5 s; a gap > 5 s gives `wide`, corrected and flagged (owner Q4) | COT-05, COT-06 |
| ATK-03: dump/move order inside the combined error | not in current data (t00 gaps ≥ 38 s, decision 014) | T7 flag widened by both hosts' `offset_unc` (§4.1 item 7) | test in 03_stitch |
| ATK-03: cross-host row with one host corrected and one `none`/`wide`/`stale` | hypothetical (every measured host with events has ≥ 2 pairs) | `clock_unreliable = true` on the row (CO-09) | COT-12 |
| ATK-05: reading taken on dc01 against the endpoint, so the sign flips | rerun procedure | stored as host − dc01; sign checked once (CO-12) | COA-05 |
| ATK-06: correction slightly worse than raw on a small offset | s06_t00 ep-01→ep-02 (raw 1.22 → corrected −1.57 s) | reported per check pair; no claim of no harm; no-op band per Q10 | COA-02 |
| ATK-07: check partner chosen after correction | (design) | raw-time join ±60 s, ambiguity reported (CO-10) | COT-15 |
| ATK-08: host reboots mid-trial after its pairs | none in the 11 trials (§10.7) | `stale`, not applied, flagged (CO-15) | COT-16 |
| ATK-09: dc01 itself steps | S04 t00 had `dc01_skew_possible` (decision 014) | endpoint-to-endpoint comparisons cancel; dc01 marked `reference` (unverified); CO-10 uses endpoint pairs only | – |
| ATK-12: host with Sysmon but no Security events in the window | hypothetical | `none`, `host_has_events = true`, so flagged (its Sysmon events cannot be corrected) | COT-08 |
| ATK-12: retried 4769 with the same GUID a few ms apart | possible in any trial | 1:1 mutual nearest keeps one | COT-03 |

## 7. Acceptance tests
Unit (synthetic, COT): COT-01 refusals (CO-01). COT-02 NULL / zero GUID never pairs. COT-03 1:1 mutual nearest with reused GUIDs. COT-04 delta sign (host behind dc01 → negative offset → corrected time later). COT-05 median and `loo_shift`, including n = 2. COT-06 `wide` status. COT-07 `MIN_PAIRS` boundary. COT-08 flag scope (host without events). COT-09 no dc01 4769 at all. COT-10 determinism (byte-identical). COT-11 the DB hash is unchanged and nothing under `ground_truth/` is opened. COT-12 the corrected-time function: `none` → unchanged, plus flag; a mixed-host row gets `clock_unreliable`. COT-13 synthetic step after the burst (documents the limit). COT-14 `MAX_PAIR_DELTA_S`. COT-15 the CO-10 join runs on raw time and reports ambiguity. COT-16 a reboot after the last pair gives `stale`; *(amended 2026-11-12)* a reboot between two pair groups drops the earlier group. COT-17 the parameter file hash matches the hash recorded in 043 (freeze). COT-18 (CO-18) a DB holding a 4616 or Kernel-General System 1 with \|shift\| ≥ 1 s on a host after its last pair gives `stale`; one between pair groups drops the earlier pairs; one before the first pair is `expected`; one with \|shift\| < 1 s is `routine` and changes nothing *(amended 2026-11-12, decision 043)*; events logged before a counted change are `clock_unreliable`. COT-19 (CO-19) the scan finds a synthetic 4616 and a Kernel-General 1 inside the span, ignores one outside it and a System 1 from another provider, skips a file whose sha256 is not in the manifest, and writes nothing outside `out/clock_offset/`. COT-20 (CO-17) refusal on or after 2026-10-26 with a `none` or `stale` host that has events; no refusal before that date; `wide` runs flagged. COT-21 (CO-12) parsing of a `w32tm /stripchart` text: target must be dc01; start, end and post-sync readings are assigned by time.

Real data (COA, development trials only):
- COA-01: for the 9 development trials, offsets equal the §10.1 values within 1 ms (regression).
- COA-02: CO-10 on development data; every corrected \|Δ\| ≤ 5 s (the kill criterion, CO-11a); today 18/18.
- COA-03: s06_t01: ep-01 offset ∈ [−19.5, −18.0] s and `ok`; the ep-01→ep-02/ep-03 WinRM pairs go from raw 16.7/18.3 s to corrected ≤ 1 s.
- COA-04: the s04_t01/s07_t01 clock-only rows are produced and labelled `clock-only`; they are never passed to the gate (decision 034).
- COA-05 (after the reruns, step 2): CO-12 agreement for every rerun t01 host.
- COA-06: the four hosts with no exported logs are `none` and not flagged.
- COA-07: CO-19 scan report on the 9 development trials (and the 2 clock-only trials): the hits per trial are listed, and the trial flag matches the hits.
- The gate amendments (§4.1) get their own tests in 02_gate (GTT-07 replaced; new GTA-07 for item 8). *(Amended by the owner 2026-11-12, T6b.2.)* GTA-05 is **not** run on s04_t01: that trial is clock-only and never gated (COA-04, decision 034). GTA-05 is redefined in 02_gate to run on **any development trial with a .97/.98/.99 session** (e.g. a rerun t01), and stays skipped with that reason until such a trial exists. `trial_window` refuses the clock-only trials (`CLOCK_ONLY_TRIALS`).

## 8. Owner answers, step 1 (2026-11-12)
| # | Question | Owner answer | Rule changed |
|---|---|---|---|
| Q1 | Skew-period evidence is thin (s06_t01; plus clock-only s04_t01/s07_t01) | Recommendation accepted: approve the method now; confirm the parameters on the rerun t01s (step 2) | status line, §5 |
| Q2 | Gate and flagged hosts | Refuse a trial with an uncorrected host on or after 2026-10-26; run `wide` hosts with a flag carried into every result | CO-17, §4.1 item 3 |
| Q3 | 1 pair | Not corrected (`MIN_PAIRS = 2`, provisional until step 2) | CO-07, §5 |
| Q4 | `wide` host | Corrected, status `wide`; never left raw | CO-06 |
| Q5 | Rerun reading format | `w32tm /stripchart` text files, one per VM per trial, `<HOST>_clock.txt` in the trial folder | CO-12 |
| Q6 | Clock steps invisible | Keep Security 4616 and System 1 for **new ingests only**; no re-ingest now; a read-only scan of existing trials' exports flags any trial with one in the window | CO-18, CO-19, CO-15, §9 |
| Q7 | GTA-06 basis | Recommendation accepted: raw-basis window for the test only | §4.1 item 6 |
| Q8 | Sync in the reruns | Option (c): each scenario's t01 (development) is not synced, with readings before the run and after collection; t02–t10 are synced after a reading, and both readings are recorded | CO-12 |
| Q9 | Decision 014's last sentence | Recommendation accepted: amended by 043; tolerance unchanged | 043, 014 header |
| Q10 | No-op band | None: every host corrected, no minimum offset | CO-13 |
| Q11 | `late_gap_s` limit | Open for step 2, set from the t01 start/end readings | CO-16 |
| Q12 | Offset uncertainty and identity | No change to the identity value now; `offset_unc` and `clock_unreliable` carried to T7; decided in the T7 spec council | §4.1 item 7 |

**Still open (step 2, after the x10_v2 ingest):** `MIN_PAIRS`, `MAX_LOO_SHIFT_S`, `READING_AGREE_S`, and the `late_gap_s` limit (Q11). They are confirmed on the rerun t01 trials and their start/end readings only (CO-11b, CO-12).

## 9. Out of scope
- Re-ingesting existing trials to add clock-change events (owner Q6: new ingests only; CO-19 scans the existing ones).
- Changing decision 014's tolerance (stays 5 s, 032).
- Drift within a trial (one offset per host per trial; no step or slope model, see Q6).
- An absolute time reference (dc01 is the reference).
- Correcting dc01.
- Editing DB times.
- Choosing which trials to rerun (owner).
- Gating or scoring the clock-only trials s04_t01/s07_t01.
- Looking at t02–t10 to choose anything.

## 10. Measurements (development + clock-only, read-only, 2026-11-12)
Script: a scratch script with a hard allowlist of the 9 development trials (s02–s07 t00; s02_t01, s03_t01, s06_t01) and the 2 clock-only trials (s04_t01, s07_t01, owner A1). It refused `s02_t02` when tried. DBs were opened `mode=ro` and their SHA-256 was unchanged after the run.

Which t01 trials qualify: s02_t01 (validator all PASS), s03_t01 and s06_t01 (no FAIL; g WARN only), per `docs/research/x10_design_validation.md` §2 and decision 034.
- Not development: s04_t01 (b, c, d FAIL) and s07_t01 (c FAIL). They are used here for clock only (A1).
- S05 t01: quarantine (030); the v2 rerun is not ingested.
- S01 t01: not collected.

Offset = host − dc01, in seconds. Negative means the host is behind. Window = the agent-tree window ±30 min (raw).

### 10.1 Per trial and host (rule A: 1:1 mutual nearest, median)
| trial | role | date | host | pairs | min | median | max | IQR | spread | LOO shift | types (count) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| s02_t00 | dev | 09-24 | ep-01 | 6 | +0.08 | +1.68 | +3.98 | 1.84 | 3.90 | 0.13 | T3 2, T4 3, T7 1 |
| | | | ep-02 | 3 | −0.26 | +0.25 | +0.34 | 0.30 | 0.60 | 0.25 | T3 2, T7 1 |
| | | | ep-03 | 0 | | | | | | | (no logs) |
| s03_t00 | dev | 09-24 | ep-01 | 6 | +2.46 | +2.61 | +3.71 | 0.44 | 1.25 | 0.01 | |
| | | | ep-02 | 0 | | | | | | | (no logs) |
| | | | ep-03 | 4 | +3.74 | +3.80 | +5.03 | 0.36 | 1.29 | 0.02 | |
| s04_t00 | dev | 09-24 | ep-01 | 6 | −1.38 | −1.14 | +5.74 | 1.69 | 7.12 | 0.16 | |
| | | | ep-02 | 3 | −2.51 | −1.66 | +0.38 | 1.44 | 2.89 | 1.02 | |
| | | | ep-03 | 0 | | | | | | | (no logs) |
| s05_t00 | dev | 10-12 | ep-01 | 4 | +0.79 | +0.80 | +1.35 | 0.15 | 0.56 | 0.01 | |
| | | | ep-02 | 23 | +0.64 | +2.68 | +5.96 | 0.02 | 5.32 | 0.00 | T4 20 |
| | | | ep-03 | 5 | +3.49 | +4.53 | +7.01 | 0.44 | 3.52 | 0.20 | |
| s06_t00 | dev | 10-12 | ep-01 | 6 | −1.36 | −0.68 | +3.25 | 1.54 | 4.61 | 0.64 | |
| | | | ep-02 | 12 | +0.20 | +2.10 | +3.18 | 0.28 | 2.98 | 0.00 | |
| | | | ep-03 | 5 | +1.76 | +3.80 | +4.78 | 2.07 | 3.01 | 0.81 | |
| s07_t00 | dev | 10-12 | ep-01 | 6 | +3.28 | +3.37 | +7.05 | 1.29 | 3.77 | 0.06 | |
| | | | ep-02 | 13 | −4.06 | +0.07 | +8.52 | 8.56 | 12.58 | 1.12 | T4 12 (60 s task) |
| | | | ep-03 | 0 | | | | | | | (no logs) |
| s02_t01 | dev | 10-15 | ep-01 | 2 | +3.42 | +3.76 | +4.10 | 0.34 | 0.67 | 0.34 | |
| | | | ep-02 | 10 | −2.77 | +0.74 | +3.11 | 0.63 | 5.88 | 0.01 | |
| | | | ep-03 | 2 | +2.99 | +3.55 | +4.10 | 0.56 | 1.11 | 0.56 | |
| s03_t01 | dev | 10-15 | ep-01 | 5 | −2.32 | −2.25 | +0.71 | 2.30 | 3.03 | 1.14 | |
| | | | ep-02 | 10 | +1.46 | +1.88 | +1.89 | 0.01 | 0.43 | 0.00 | |
| | | | ep-03 | 3 | +3.84 | +3.91 | +3.95 | 0.06 | 0.11 | 0.04 | |
| **s06_t01** | **dev** | **10-27** | **ep-01** | **5** | **−18.83** | **−18.78** | **−10.99** | 3.56 | 7.84 | 1.76 | T4 3, T3 2 |
| | | | ep-02 | 8 | −2.98 | −2.24 | +2.99 | 4.00 | 5.97 | 0.51 | |
| | | | ep-03 | 3 | −0.28 | +0.04 | +5.99 | 3.13 | 6.27 | **2.97** | |
| s04_t01 | clock-only | 10-26 | ep-01 | 5 | −14.83 | −14.66 | −13.96 | 0.10 | 0.87 | 0.03 | T4 3, T3 2 |
| | | | ep-02 | 5 | −1.92 | −0.56 | +3.83 | 1.53 | 5.74 | 0.51 | |
| | | | ep-03 | 2 | +3.15 | +3.20 | +3.26 | 0.06 | 0.11 | 0.06 | |
| s07_t01 | clock-only | 10-27 | ep-01 | 2 | −14.01 | −12.26 | −10.51 | 1.75 | 3.50 | 1.75 | T3 2 |
| | | | ep-02 | 6 | −2.44 | −0.41 | +0.46 | 1.02 | 2.90 | 0.15 | |
| | | | ep-03 | 1 | −0.05 | −0.05 | −0.05 | | | | |

Same pairs and medians over the whole DB as within ±30 min, on all 11 trials (no pair comes from an earlier snapshot day). Before 2026-10-26, every endpoint is within −2.3 … +4.5 s of dc01.

### 10.2 ep-01 from 2026-10-26 onward (each pair)
| trial | 4624 (ep-01) | type | account | dc01 4769 | service | delta |
|---|---|---|---|---|---|---|
| s04_t01 | 04:09:04.785 | 4 | svc_backup | 04:09:19.510 | ENDPOINT-01$ | −14.726 |
| s04_t01 | 04:09:04.791 | 4 | svc_sql | 04:09:19.618 | ENDPOINT-01$ | −14.827 |
| s04_t01 | 04:09:04.811 | 4 | admin_it | 04:09:19.470 | ENDPOINT-01$ | −14.660 |
| s04_t01 | 04:09:09.773 | 3 | endpoint-01$ (::1) | 04:09:23.731 | ENDPOINT-01$ | −13.957 |
| s04_t01 | 04:09:25.724 | 3 | endpoint-01$ | 04:09:40.353 | ENDPOINT-01$ | −14.629 |
| s06_t01 | 06:18:28.759 | 4 | svc_sql | 06:18:47.540 | ENDPOINT-01$ | −18.781 |
| s06_t01 | 06:18:29.125 | 4 | admin_it | 06:18:47.953 | ENDPOINT-01$ | −18.828 |
| s06_t01 | 06:18:29.227 | 4 | svc_backup | 06:18:48.043 | ENDPOINT-01$ | −18.816 |
| s06_t01 | 06:18:35.648 | 3 | endpoint-01$ (::1) | 06:18:50.908 | ENDPOINT-01$ | −15.260 |
| s06_t01 | 06:19:03.809 | 3 | endpoint-01$ | 06:19:14.795 | ENDPOINT-01$ | −10.986 |
| s07_t01 | 08:39:23.593 | 3 | endpoint-01$ (::1) | 08:39:34.100 | ENDPOINT-01$ | −10.507 |
| s07_t01 | 08:39:31.147 | 3 | endpoint-01$ | 08:39:45.156 | ENDPOINT-01$ | −14.009 |

Summary:
- ep-01 is −14.7 s (10-26 04:09), −18.8 s (10-27 06:18) and −12.3 s (10-27 08:39, 2 pairs; −14.0 s by the nearest-per-4624 rule) behind dc01.
- It changes between trials (snapshot revert), so the correction must be per trial. A single correction for the day would be wrong.
- Every ep-01 pair is a start-of-trial logon on ep-01 itself; none is an attack hop.
- Event uids are in `out/clock_offset/<trial>/pairs.csv` once implemented, and in the scratch output now.

### 10.3 Pairing rule comparison (n pairs / median, s)
The independent check is the worst corrected \|Δ\| of the CO-10 pairs under each rule:

| check pair | raw | A mutual 1:1 | B nearest per 4624 | C unique GUID only | D A without type 4 |
|---|---|---|---|---|---|
| s03_t00 ep-01→ep-03:5985 (2) | +2.77 | +1.58 | +1.33 | +0.35 | +2.14 |
| s05_t00 ep-02→ep-03:5985 (3) | +1.84 | −0.04 | −1.08 | +0.16 | +0.29 |
| s06_t00 ep-01→ep-02:5985 (3) | +1.22 | −1.57 | −1.44 | −2.23 | −0.66 |
| s03_t01 ep-01→ep-03:5985 (3) | +5.68 | −0.82 | −1.48 | −0.83 | +2.14 |
| s06_t01 ep-01→ep-02:5985 (3) | +16.75 | +0.20 | +1.03 | −1.52 | **+6.52** |
| s06_t01 ep-01→ep-03:5985 (4) | +18.35 | −0.48 | **−6.22** | n/a (ep-03 unmeasured) | **+5.18** |

- B fails because ep-03 GUIDs are reused (s06_t01 ep-03: B median +6.10, A median +0.04).
- D fails because ep-01's good pairs are type 4.
- C leaves 9 hosts with 0–1 pairs.
- Minimum instead of median (rule A): worst corrected \|Δ\| 1.49 s, which also passes here. It is rejected because the scatter is two-sided (CO-05).

### 10.4 dc01 same-clock 1:1 pairs (latency)
Median latency is +4 to +8 ms in all 11 trials. p95 is ≤ 0.1 s. A few outliers reach 400 s (s03_t00) through GUID reuse, which the 1:1 rule mostly removes. Many-to-many pairing (data-checker) gives medians of 2–76 s. So the endpoint scatter of ±3–9 s is not network or KDC latency.

### 10.5 Independent check (CO-10) — kill criterion (a)
| | groups | pairs | worst raw \|Δ\| | worst corrected \|Δ\| (rule A) |
|---|---|---|---|---|
| all development | 6 | 18 | 18.35 s | 1.58 s |
| of which on or after 10-26 (s06_t01) | 2 | 7 | 18.35 s | 0.48 s |
| clock-only s04_t01, s07_t01 | 0 | 0 | – | – (no WinRM hop from a lab host; S07 is SMB, and Sysmon logs no endpoint→endpoint 445) |

Net effect per check group (ATK-06), \|raw\| → \|corrected\| (s):
- s03_t00: 2.77 → 1.58
- s05_t00: 1.84 → 0.04
- s06_t00: 1.22 → **1.57 (worse)**
- s03_t01: 5.68 → 0.82
- s06_t01: 16.75 → 0.20, and 18.35 → 0.48

So 5 of 6 groups improve.

*(owner 2026-11-12, after T6b.2)* **Ambiguity of the check join:** 11 of the 18 check pairs have **two** candidate target 4624s on the same source port within ±60 s (`candidate_count` = 2). The second one is a WinRM keep-alive logon 0.5–12 s after the first. On raw time the nearest candidate is always the first logon, so every Δ above, and the kill criterion, are unchanged. The raw values also hold the real connect-to-logon delay of about 0–1 s, so a small negative corrected value (target logon before the connection) is estimator error. Every check pair is joined on raw time (CO-10).

- Raw is > 5 s in 3 of 6 groups (s03_t01 5.68 s, s06_t01 16.75 and 18.35 s). Corrected is ≤ 1.58 s in all 6.
- Check pairs come 4 min after ep-01's pairs in s06_t01 (06:22:12–06:22:56 vs 06:18:28), so the offset held for at least that long.
- Coverage limit: WinRM hops only. ep-02 → ep-03 occurs once (s05_t00). ep-01 / ep-02 / ep-03 as a target with SMB are not covered, which is why CO-12 is needed.

### 10.7 Checks added after the attacker review
| trial | largest \|pair delta\| (s) | ep-01 last pair | last agent event | ep-01 late gap (s) | pairs from a lab-IP 4624 | endpoint boots in [first pair, window end] |
|---|---|---|---|---|---|---|
| s02_t00 | 3.98 | 05:35:51 | 05:42:47 | 416 | 0 | ep-02 6005 05:37:46 (ep-02 pairs from 05:37:58, after it) |
| s03_t00 | 5.03 | 09:37:27 | 09:41:33 | 246 | 1 | ep-01 6005 09:37:10 (before ep-01 pairs) |
| s04_t00 | 5.74 | 10:55:16 | **10:57:38** | **141** (was −9) | 0 | ep-01 6005 10:54:43 (before) |
| s05_t00 | 7.01 | 07:04:18 | 07:12:45 | 507 | 1 | none |
| s06_t00 | 4.78 | 08:59:22 | **09:04:35** | **312** (was 183) | 2 | none |
| s07_t00 | 8.52 | 09:10:58 | **09:19:34** | **515** (was 360) | 0 | none |
| s02_t01 | 4.10 | 05:33:29 | 05:32:40 | −50 | 0 | none |
| s03_t01 | 3.95 | 08:26:38 | **08:32:30** | **351** (was 97) | 1 | ep-03 6005 08:26:37 (before ep-03 pairs) |
| s06_t01 | 18.83 | 06:19:03 | **06:23:43** | **280** (was 35) | 2 | none |
| s04_t01 | 14.83 | 04:09:25 | **04:12:07** | **161** (was −85) | 0 | ep-01 6005 04:08:56, ep-03 6005 04:08:59 (before) |
| s07_t01 | 14.01 | 08:39:31 | **08:44:37** | **305** (was 68) | 0 | none |

Reading of the table:
- The boots are the reverts at trial start; the pairs follow them. CO-15 changes no value in §10.1.
- `MAX_PAIR_DELTA_S = 60` drops no measured pair.
- A negative late gap means ep-01's pairs continue after the last agent event.
- *(owner 2026-11-12, after T6b.2)* **Corrected:** the "last agent event" and "late gap" columns first used the manifest-clipped window end − 300 s. Where the manifest clip cuts the window end (s04_t00, s06_t00, s07_t00, s03_t01, s06_t01, s04_t01, s07_t01), that time lies minutes before the real last agent event. The bold values are the last agent event in the window and the gap to it, as written by `src/clock_offset` (`late_gap_s` in `data/processed/<trial>.clock_offsets.csv`; the old values are kept in `stats.json` as `late_gap_clipped_end_s`). s02_t00, s03_t00, s05_t00 and s02_t01 are not clipped and do not change. ep-01's late gap is therefore −50 … 351 s on the development t01s (161 and 305 s on the clock-only t01s) and 141 … 515 s on t00.

### 10.6 Data-checker cross-check (independent SQL, 2026-11-12)
- **Columns:** present and populated. GUIDs are lower-case without braces; all-zero GUIDs are NULL with `logon_guid_state = 'zero'`.
- **s06_t01 ep-01:** the same pair deltas (min −18.828, max −10.986). With "nearest 4769 per 4624" (6 pairs) the median is −18.463 s; with rule A (5 pairs) it is −18.781 s.
- **s04_t01 ep-01:** −14.693 s (nearest) vs −14.66 s (A).
- **s07_t01 ep-01:** −14.009 s (nearest, 3 pairs) vs −12.26 s (A, 2 pairs). The 2-pair case is where the rules differ most (1.75 s).
- **GUID reuse:** 62 GUIDs with several 4624s in s06_t01 (mostly ep-03) and 29 with several 4769s. This confirms the need for CO-03.
- **Earlier snapshot days:** events from 09-17 … 10-12 are in the 10-26/27 DBs; none of them contributes an endpoint pair.
- **Time-change events:** not kept by the normaliser. *(T6b.2 CO-19 scan, 2026-11-12: the decoded **exports** do hold them. 9 of the 11 allowlisted trials have 4616 + Kernel-General System 1 pairs in the search span, all before the host's first pair (snapshot-revert catch-up: s02_t00 ep-02 +8.48 s; ep-02 +1 h 50 min in s06_t00 and +2 h 2 min in s07_t00, inside the agent window; ep-02 +2.9 … 15 days on the t01s) or routine 0–2 ms adjustments, some between pairs. None changes an offset; see `out/clock_offset/<trial>/clock_events.csv`.)* The channels present are Security {4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4768, 4769, 4776, 5140, 5145, 1102} and System {41, 104, 1074, 6005, 6006, 6008, 7045} (s06_t01).
