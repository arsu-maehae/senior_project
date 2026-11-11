# Other-run leftovers in the approved t00 keys (S05 agent run in s06_t00 and s07_t00)

**Date:** 2026-11-12 · **Found by:** T6 stage A pre-check (decision 040), then a scan of all six t00 keys · **Status:** corrected drafts written for owner review; `ground_truth/approved/` unchanged

## Scan (all six t00 keys, s02–s07)
A finding is a key entry whose event meets both conditions:
- it lies **outside** the key's `agent.run_interval`;
- it belongs to **another run's agent tree**: the agent roots before this trial's run start (30-min walk-back, decision 026), their Sysmon 1 descendants, the splunkd process that parented only those roots, or a 4688 that corroborates such a process.

The scan looked at every event uid referenced anywhere in the key (steps, hops, unconfirmed, paths, agent fields; `event_keys` is the index of those) and at `agent.accounts`.

| Key | Other-run roots in the DB | Findings |
|---|---|---|
| s02_t00 | 0 | none |
| s03_t00 | 9 (ep-03, 2026-09-11…22) | none (no key entry refers to them) |
| s04_t00 | 0 | none |
| s05_t00 | 9 | none (no key entry refers to them) |
| s06_t00 | 11 (S05 run and earlier) | yes, see below |
| s07_t00 | 2 (S05 ep-02) | yes, see below |

The only events outside `run_interval` in any key are the s06/s07 entries below. Every other referenced event lies inside its key's interval.

## Why they are there (decision 026 leftover)
The s05, s06 and s07 t00 DBs share the ep-02 host files of 2026-10-12. The S05 ep-02 `pivot_admin` agent (start 07:06:28, decision 026 Context; `docs/research/agent_evidence.md` finding 2) and its splunkd network events are in all three.

The key builder scopes `agent_start` steps, `agent.sysmon3_event_uids` and `agent.accounts` to the **run days** (6-hour walk-back, `RUN_GAP_S`). Only the leftover-logon search uses the 30-minute run interval. So the S05 entries were listed in the s06 and s07 keys.

They never affected the run interval:
- its start comes from the 30-minute walk-back, which begins at each trial's own first root;
- its end is the latest step or hop time, and these entries are earlier than all of them.

## Entries removed in the drafts
| Key | Field | Entries removed | Times (UTC, 2026-10-12) |
|---|---|---|---|
| s06_t00 | `steps` | `s06-agent-ep-02-1` (agent_start, ep-02, admin_it): Sysmon 1 `7b4d1cf6…a451`, 4688 `6147fc0c…56d1` | 07:06:28.532 |
| s06_t00 | `agent.sysmon3_event_uids` | 4 of 8, ep-02 splunkd → 192.168.50.50:8888: `a3a57752…`, `f982bfd9…`, `558929f1…`, `6de32964…` | 07:03:46, 07:06:29, 07:07:40, 07:08:03 |
| s06_t00 | `event_keys` | the 6 uids above | |
| s07_t00 | `steps` | `s07-agent-ep-02-1` (agent_start, ep-02, admin_it): Sysmon 1 `a765fe8d…182f`, 4688 `8b4a334a…4273` | 07:06:28.532 |
| s07_t00 | `agent.sysmon3_event_uids` | 6 of 12, ep-02 splunkd → 192.168.50.50:8888: `a82e79c4…`, `7abfb572…`, `99d22a45…`, `9744ca66…`, `3c8a5998…`, `404e8163…` | 07:03:46, 07:06:29, 07:07:40, 07:08:03, 07:12:36, 07:12:46 |
| s07_t00 | `agent.accounts` | `system` (only the S05 ep-02 root at 07:03:46 has it; the s07 run's own roots are admin_it, svc_backup, svc_sql) | |
| s07_t00 | `event_keys` | the 8 uids above | |

**Not removed: `system` in s06 `agent.accounts`.** The s06 run's own first root has that account: an ep-03 PowerShell at 08:58:25.672, tied to the agent through the 4688 PID match. That root also sets the s06 run start. This corrects the earlier version of this note, which said `system` was S05-only in both keys; that check had looked only at Sysmon 1 roots whose parent image is splunkd.

The other step ids are not renumbered: the first remaining one is still `…-agent-ep-01-2`.

## Draft files and checks
| Draft | Diff vs approved (lines added / deleted) | `python -m answer_key verify` |
|---|---|---|
| `ground_truth/drafts/s06_t00.yaml` | +0 / −60 | ok, lock_ready; 84 events checked (approved 88; Sysmon 3 11 → 7) |
| `ground_truth/drafts/s07_t00.yaml` | +1 / −78 (the one added line is `"svc_sql"` without its trailing comma) | ok, lock_ready; 99 events checked (approved 105; Sysmon 3 12 → 6) |

Before writing, the script checked three things:
- re-serialising each approved key gives byte-identical text;
- every scan finding was handled;
- no other part of the key refers to a removed uid.

Nothing else in the keys changed. Unchanged drafts: s02, s03, s04 and s05 (identical to their approved keys). To accept: move the s06 and s07 drafts to `ground_truth/approved/` (owner only).

## Does this change anything already built?
No.
- `src/trial_window` does not read the keys.
- GTA-06 checks only the events of the key's hops, and none of the removed entries is a hop event.
