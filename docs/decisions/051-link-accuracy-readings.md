# 051 — Readings for T7.6: link accuracy module, key session, session comparison, key lock

**Date:** 2026-11-15 · **Status:** **accepted (owner, T7.6 plan approval 2026-11-15, revision 2 with additions 1 and 2).** · **Task:** T7 (7.6) · **Relates to:** spec [03_stitch](../specs/03_stitch.md) ST-25, ST-48, ST-50, ST-60..64, STA-05..08, L-ST1; spec [07_answer_key](../specs/07_answer_key.md) §8; 013, 019, 020, 044, 046, 047, 049, 050

## Context
T7.6 checks the stitch links against the approved development keys. The checks already exist in the real-data tests, but those tests read stitch internals and write no file. T10 needs the same check on t02–t10, run unchanged, from code that cannot leak the key into the pipeline. The spec leaves open:
- how the key's target 4624 and source session are read;
- how two sessions are compared;
- what the identity comparison uses while Q9 is open;
- how test keys are protected before T10.

**Read-only prototype** (scratchpad; DBs opened `mode=ro`; stitch outputs of 2026-11-14), on the six keyed t00 trials:
- 15/15 key hops each match exactly one stitch hop.
- Of the 11 hops with a key source session:
  - the key session is among the candidates 11/11;
  - rank 1 is the key session 11/11;
  - the key session is the only candidate 9/11 (the S04 pair has two).
- Tiers of those 11: WinRM 3 A + 1 B (s06-winrm-2, no Sysmon 3); SMB 7 B.
- The 4 background hops are `target_only`, tier D.
- `evidence_before_range` > 0 on s06-smb-1 (6) and s07-h-y (4).
- Session comparison by 4624 uid is possible on 11/11 hops:
  - the key uid comes directly from the key on 1 hop (s04-A-h1, `session_evidence.session_logon_uid`) and from the DB lookup of item 4 on 10;
  - each key session's logon ID has exactly one opening 4624 on its host;
  - the key uid equals the rank-1 `source_session_logon_uid` in 11/11.

## Decision
1. **Module and isolation.**
   - New package `src/evaluate/`, which will also be the T10 stage folder.
   - It reads only the stitch output files, the approved key and the trial DB, read-only. It never imports `stitch`, and `stitch` never imports it.
   - `src/stitch` still never opens `ground_truth/`.
   - The core functions take `split` as an argument. The CLI refuses any trial outside `clock_offset.params.DEVELOPMENT_TRIALS` before opening a file (as 046). Lifting that refusal at T10 needs the owner's approval and an amendment of 046 and this record.
2. **Integrity.** Each refusal below stops the run, and nothing is written:
   - a missing stitch file;
   - a stitch file whose SHA-256 differs from `run_info.json`;
   - a DB SHA-256 that differs from `run_info.db.sha256_after` or from the key's `db_sha256`, or that changes during the run;
   - a key whose `trial_id` differs from the trial.

   **The key.** It is read only from `ground_truth/approved/<trial>.yaml`. Drafts are never read. Approval is signalled by the file's location, because the approved files keep `status: draft`.
3. **ST-25 match.** The key's target 4624 is the member of a `hops.csv` hop whose uid is in `target_event_uids` and whose logon ID equals `target_logon_id`.
   - Outcome: `matched`, `unmatched` or `multiple`.
   - `key_logons_in_hop` = how many of the key's target-host 4624s are members of that hop, out of how many there are.
4. **Key source session (owner, fixed).**
   - It is `source_session_logon_id` / `session_evidence.session_id` where present. Otherwise it is the `(host, session_id)` of the key command's Sysmon 1 events (`agent_event_uids` whose `event_keys` entry is Sysmon 1), with `session_id` read from the DB.
   - **Its 4624 uid** is `session_evidence.session_logon_uid` where present. Otherwise it is looked up read-only in the DB, in `src/evaluate` only:
     - the source host's Security 4624 with `target_logon_id` = the session's logon ID;
     - at or before the earliest key command event of that session (time from `event_keys`);
     - in the same boot epoch as that command;
     - the latest such 4624 if several qualify.
   - **Boot epochs** follow 047 exactly:
     - System 41, 6005, 6008 are startup events; 1074, 6006 are shutdown events;
     - consecutive events of one kind at most `boot_group_s` apart form one group;
     - a shutdown group's boundary is its last event;
     - a startup group's boundary is its first event, unless a shutdown group comes right before it;
     - an event at a boundary instant belongs to the new boot.
   - Epochs use same-host logged times. `boot_group_s` is read from the stitch `run_info.json` `parameters`, never imported.
5. **Session comparison (owner addition 2).** Each keyed row records `session_compare`:
   - `logon_uid`: the key session has a 4624 uid and every candidate session row of the hop has a `source_session_logon_uid`. Sessions are equal when their uids are equal.
   - `host_logon_id`: otherwise, provided the key session's logon ID has opening 4624s in at most one boot epoch on its host. Sessions are equal when `(source_host, logon ID)` are equal.
   - `ambiguous_boot`: otherwise. No verdict is given: `among_candidates`, `rank1` and `only_candidate` are empty, and the row is counted apart.
6. **Verdicts.**
   - `among_candidates`: every key session is among the hop's candidate sessions.
   - `rank1`, one of:
     - `correct`: the rank-1 set equals the key set;
     - `tied_correct`: the key set is inside a larger rank-1 set;
     - `wrong`;
     - `no_candidate`: a `target_only` hop.
   - `only_candidate`: the candidate set equals the key set.
   - **A key hop without a key source session** (background, `time_account_only`) has `expected_target_only` = 1 and `target_only_ok` = 1 when the hop has only a `target_only` row.
7. **Identity.** The comparison uses the `hop_identity.csv` rows of (hop, key `logon_account`).
   - The value is computed under the six Q9 variants: reads all / non-system / key rule × `end_unknown` counted or not, with the definitions of the existing test helper. A deciding row has `order_ok` = 1 and an open session.
   - `identity_value` = the shared value, or `q9_dependent`.
   - `identity_match` = 1 / 0 / `q9_dependent`.
   - The order flags of the deciding rows are reported.
   - **This value is for comparison only. T9 owns IdentityCoherence.**
8. **Totals and labels.**
   - Totals are grouped by (`protocol_group`, `best_tier`). `protocol_group`: `smb` = smb + smb_service; `winrm`; `rdp`; `none`.
   - Every row carries `split`. Every `.md` opens with "DEVELOPMENT — not a result (decision 019)" when split = development.
   - The report states that WinRM tier A (port join) is reported apart from tier B, and that tier B on SMB is agreement with the key's command-line rule, not accuracy (L-ST1, spec 07 §8).
   - t01 trials (no approved key) get facts and totals with no right/wrong columns.
   - Outputs hold no command text. Account, image and name values are copied only from stitch columns already covered by STT-13.
9. **Key lock for T10 (owner addition 1).**
   - Manifest: `ground_truth/key_lock.csv`, columns `trial_id,key_path,sha256`. **The owner creates it; code never creates or writes it.**
   - **split = test:** the run is refused, writing nothing, when the manifest is missing or malformed, when the trial has no row or more than one row, or when the key's SHA-256 differs from the row.
   - **split = development:** the manifest is neither required nor read. `run_info.json` records `key.path`, `key.sha256` and `key.lock = not_required`.
   - Synthetic tests cover both splits. T7.6 does not create the manifest.
10. **STA-07 sensitivity.** The test harness, not `src/evaluate`, runs the stitcher with alternative parameters into a temporary folder and runs the accuracy module on the result. The numbers are printed and reported in PROGRESS; no `out/` file is written.

## Consequences
- T10 reuses `src/evaluate` with `split = test` after the owner writes `key_lock.csv` and amends the allowlist.
- An accuracy row can never feed back into the stitcher: the dependency points one way, and tests enforce it.
- Until T9, identity is compared on stitch facts under every Q9 variant. A `q9_dependent` row would show that Q9 matters; none is expected on development.

## Kill criteria
- Any development number differs from the prototype above: report it to the owner before T7.6 is marked done.
- A keyed development hop gets `ambiguous_boot` or `host_logon_id`: report it.
- Any stitch output, key or DB SHA-256 changes during T7.6: stop.

## Committee answer
**EN:** The accuracy check is a separate program. It reads the linker's saved output and the answer key, and the linker can never see the key. On the development trials, the linked source session was the key's session for every keyed hop. These are development numbers, not results. For SMB they show agreement with the key's own command-line rule, not measured accuracy. Before the test run, the owner locks each test key by its fingerprint, and a changed key is refused.
**TH:** การตรวจความถูกต้องเป็นโปรแกรมแยกต่างหาก อ่านผลที่ตัวเชื่อมโยงบันทึกไว้และเฉลย โดยตัวเชื่อมโยงไม่มีทางเห็นเฉลย บนข้อมูลพัฒนา เซสชันต้นทางที่เชื่อมได้ตรงกับเฉลยทุก hop ที่มีเฉลย แต่นี่เป็นตัวเลขระหว่างพัฒนา ไม่ใช่ผลการทดลอง และสำหรับ SMB เป็นเพียงความสอดคล้องกับกฎ command line ที่เฉลยใช้เอง ไม่ใช่ความแม่นยำที่วัดได้ ก่อนรันชุดทดสอบ เจ้าของงานจะล็อกเฉลยแต่ละไฟล์ด้วยลายนิ้วมือ (SHA-256) หากเฉลยถูกแก้ไขจะถูกปฏิเสธ
