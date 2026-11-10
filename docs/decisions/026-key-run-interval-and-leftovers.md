# 026 — Answer key: run interval, leftover logons and what the key does not claim

**Date:** 2026-11-10 · **Status:** proposed, needs owner approval · **Task:** T5 (5.2)

## Context
A trial DB holds host logs from other days and neighbouring trials: s05, s06 and s07 share the ep-01 admin_it logon at 07:05:15.541 on 2026-10-12; ep-03 holds splunkd roots from 2026-09-11…22; s05–s07 hold the ep-02 `pivot_admin` agent start at 07:06:28 (`docs/research/agent_evidence.md`, finding 2). The review of the first drafts (fact-checker and attacker) found that a search for `time_account_only` logons anchored at the first step missed S07's 09:11:08 admin_it logon, and a whole-day search pulled in other trials' logons.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Calendar day of the splunkd roots | Simple | Mixes trials exported on the same day; cuts a trial across midnight |
| B. Search the whole DB | Finds everything | Lists other trials' logons as hops of this trial |
| C. Run interval from the agent starts: start = the earliest splunkd root of the run found by walking back while roots are less than 30 minutes apart (`TRIAL_GAP_S` = 1800), minus 60 s; end = last step or command + 300 s | Matches the trials (longest gap inside a trial seen: about 110 s, S07); removes the 07:05:15 logon from s06 and s07 | The 30-minute value is an assumption; a longer pause inside one trial would cut its start |

## Decision
Option C. Run days (for the agent tree, dumps and agent network) come from a 6-hour walk-back (`RUN_GAP_S`); the leftover-logon search uses the 30-minute interval, recorded in each draft as `agent.run_interval` and `agent.run_day_rule`. Leftover logons inside it are listed as `time_account_only`, `unconfirmed`, never `confirmed` (decision 020). `run_day_spans_midnight` is flagged, not cut.

## Amendment (owner, 2026-11-10)
Keep the 30-minute gap for t00. `data/manifest.csv` has `first_event_utc` and `last_event_utc` per file, which are export spans, not trial start and end times; they are used as an outer clip of the run interval and recorded as `agent.manifest_span`. A check (`python -m answer_key check-overlap`, `out/answer_key/overlap.md`) flags any pair of trials whose run intervals overlap and marks a background hop `shared_with_trial` when the same event content exists in another trial's DB (the 07:05:15 admin_it logon is in s05, s06 and s07). Recheck on the ×10 trials.

## Consequences
Development leftovers: s04-t1 (10:55:28), s05-t1 (07:05:15), s06-t1 (08:59:36), s07-t1 (09:11:08), all admin_it ep-01 → ep-02 NTLM, with no agent command naming the target. Whether they are attack, benign or noise is the owner's open question (spec 07 section 8). The key window is used only to report where events fall (AK-12). Logons from a neighbouring trial that fall inside a run interval cannot be separated by the key alone.

## Kill criteria
If a t01 or test trial has a pause longer than 30 minutes between agent starts, or two trials share a run interval, change the value and record it here.

## Committee answer
**EN:** The key looks for unexplained logons only inside the time span of that trial's own agent activity, so logons from neighbouring trials in the same files are not listed as part of it.
**TH:** เฉลยหา logon ที่อธิบายไม่ได้เฉพาะในช่วงเวลาที่ agent ของรอบนั้นทำงาน logon จากรอบข้างในไฟล์เดียวกันจึงไม่ถูกนับเป็นของรอบนี้
