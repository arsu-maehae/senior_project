# 028 — Lock rule: background hops are reviewed, not confirmed; owner exclusion field

**Date:** 2026-11-10 · **Status:** accepted (owner, 2026-11-10) · **Task:** T5 (5.7 gate, supersedes the lock text in the 2026-11-10 answer on decision 026)

## Context
The first lock rule said no `unconfirmed` hop may remain in an approved key. Background hops (`time_account_only`, no agent or manual command names the target: `s04-t1`, `s05-t1`, `s06-t1`, `s07-t1`) cannot be confirmed by design, so that rule could never be met.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Keep "no unconfirmed hop" | Strict | Impossible for background hops |
| B. Background hops allowed when `reviewed: true`; no unconfirmed attack or benign hop; owner-only `excluded` field | Every hop is still looked at by the owner; attack and benign hops stay strictly confirmed | Background hops stay at low confidence (negatives in evaluation, spec 07 AK-19) |

## Decision
Option B. Hop fields: `reviewed` (bool), `reviewed_note`, `excluded` (bool), `excluded_reason`. They are owner fields, stored in `src/answer_key/owner_reviews.json` and applied by the builder; a hop id in that file that does not exist in the draft raises an error. `lock_ready` (spec 07 AK-21) is true only if every hop has a role; no hop that is not excluded is `unconfirmed` with role attack or benign; every background hop that is not excluded has `reviewed: true`; every excluded hop has a non-empty `excluded_reason`. `excluded` is set only on the owner's instruction. All four current background hops are marked `reviewed: true` (owner reviewed the rows, 2026-11-10); no hop is excluded.

## Consequences
A draft that passes `lock_ready` is still a draft until the owner moves it to `ground_truth/approved/`. Background hops count as negatives (AK-19).

## Kill criteria
If a background hop later turns out to be part of an attack path, change its role and basis and record it here.

## Committee answer
**EN:** Logons that no command explains stay in the key as reviewed background and count as non-attack; only the owner can exclude a hop.
**TH:** logon ที่ไม่มีคำสั่งใดอธิบายได้ยังอยู่ในเฉลยในฐานะ background ที่ตรวจแล้วและนับเป็นไม่ใช่การโจมตี มีเพียงเจ้าของงานที่ตัดทอน hop ออกได้
