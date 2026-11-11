# S05 agent start (07:06:28) in the approved s06_t00 and s07_t00 keys

**Date:** 2026-11-12 · **Found by:** T6 stage A pre-check (decision 040) · **Status:** drafts written for owner review; `ground_truth/approved/` unchanged

## What
The approved s06_t00 and s07_t00 keys each list an `agent_start` step that belongs to S05 (the run of 2026-10-12 07:03–07:17), not to their own trial:

| Key | Step | Host | Time (UTC) | Account | Event uids (in `event_keys`) |
|---|---|---|---|---|---|
| s06_t00 | `s06-agent-ep-02-1` | ep-02 | 2026-10-12T07:06:28.532 | admin_it | Sysmon 1 `7b4d1cf6…a451` (record 49473); Security 4688 `6147fc0c…56d1` (record 1705666) |
| s07_t00 | `s07-agent-ep-02-1` | ep-02 | 2026-10-12T07:06:28.532 | admin_it | Sysmon 1 `a765fe8d…182f`; Security 4688 `8b4a334a…4273` |

Both steps lie well before their key's own `agent.run_interval`: s06 starts at 08:57:25.672, s07 at 09:09:49.665. No hop, path or other step refers to these events.

## Why it is there (decision 026 leftover)
The s05, s06 and s07 t00 DBs share host files from the same day. The ep-02 `pivot_admin` agent start at 07:06:28 is in all three (decision 026, Context; `docs/research/agent_evidence.md` finding 2).

The key builder scopes the two kinds of entry differently:
- `agent_start` steps are scoped to the **run days**, a 6-hour walk-back (`RUN_GAP_S`), so every splunkd launch on 2026-10-12 becomes a step;
- the leftover-logon search is scoped to the 30-minute **run interval**.

So the S05 launch is listed as a step of s06 and s07. It never affected the run interval:
- the interval start comes from the 30-minute walk-back, which begins at each trial's own first root;
- the interval end is the latest step or hop time, and this step is earlier than all of them.

## Correction (drafts)
- `ground_truth/drafts/s06_t00.yaml` and `ground_truth/drafts/s07_t00.yaml` are the approved keys with only these entries removed:
  - the one `agent_start` step;
  - its two `event_keys` entries.
- The diff is 28 deleted lines per file and nothing else. The other step ids are not renumbered: the first remaining one is still `…-agent-ep-01-2`.
- Before writing, the script checked that re-serialising the approved key gives byte-identical text, and that no other part of the key refers to the removed uids.
- `python -m answer_key verify` on both drafts: `ok: true`, `lock_ready: true` (s06 88 events checked, s07 105).
- To accept: move the drafts to `ground_truth/approved/` (owner only).

## Same cause, found but NOT changed in the drafts
These come from the same run-day scope. They are listed for the owner to decide; they do not affect any hop, path or GTA-06 result.
- `agent.sysmon3_event_uids`: ep-02 splunkd connections to 192.168.50.50:8888 from the S05 run:
  - s06: 4 of 8 (07:03:46, 07:06:29, 07:07:40, 07:08:03);
  - s07: 6 of 12 (the same four, plus 07:12:36 and 07:12:46).
- `agent.accounts`: `system` comes only from S05-era ep-02 splunkd children (07:03:46). Within each trial's run interval the agent accounts are admin_it, svc_backup and svc_sql. admin_it stays either way, through ep-01.
- The same pattern may exist in the s05 key (an earlier ep-02 start) or the t01 keys. It was not checked here.

## Does this change anything already built?
No.
- `src/trial_window` does not read the keys, and its windows start at each trial's own first root: 08:57:25.672 and 09:09:49.665.
- GTA-06 checks only the events of the key's hops, so the removed step was never part of it.
