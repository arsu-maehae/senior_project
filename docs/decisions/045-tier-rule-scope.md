# 045 — Which rows carry a tier: path-link rows only; clock pairs carry none

**Date:** 2026-11-13 · **Status:** **proposed — awaiting the owner** · **Task:** T7 (7.1), from review [08_clock_offset-2026-11-12](../reviews/08_clock_offset-2026-11-12.md) SF-9 · **Relates to:** 038 (`gate_tier` / `confidence_tier`), 043 (clock offset method)

## Context
CLAUDE.md (code rules) asks every output row that links events to record `method`, `candidate_count`,
`time_delta_ms`, a tier and the supporting `event_uid`s. Decision 038 names the tier of a gate row `gate_tier` and
the tier of a T7 link `confidence_tier`. Spec 08 §3 says the clock pairs (`out/clock_offset/<trial>/pairs.csv`:
endpoint 4624 ↔ dc01 4769 by LogonGuid) carry no tier. That exemption is written only in the spec; review 08 SF-9
asks for a line in a decision record.

Evidence: `pairs.csv` rows record `method`, `candidate_count`, `time_delta_ms` and both event uids (spec 08 §3).
The pairs are used only to estimate one number per host (the median, CO-05) and never become a hop, a link or a
path node. The stitch spec ([03_stitch](../specs/03_stitch.md) §3) gives a tier to every link row and every
artefact attachment.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. Give clock pairs a tier too | The CLAUDE.md sentence holds literally | A tier would have no meaning: a pair is exact by GUID or it is not a pair; the quality of the estimate is already `offset_status` and `offset_unc_ms` per host | spec 08 CO-03, CO-06 |
| B. The tier rule covers rows that link events **of a path**; measurement rows carry the other four fields but no tier | Says what the tier is for; no column without meaning | One more sentence to keep in mind when a new stage is added | spec 08 §3; decision 038 |

## Decision (proposed)
Option B. The tier required by the CLAUDE.md code rule applies to rows that link events of a candidate path:
`gate_tier` on gate rows and `confidence_tier` on stitch link rows and artefact attachments (decision 038).
Rows that pair events only to **measure** something (the clock pairs of spec 08, and the CO-10 check pairs) record
`method`, `candidate_count`, `time_delta_ms` and the event uids, and carry no tier. The quality of a clock estimate
is reported per host by `offset_status` and `offset_unc_ms`.

If the owner accepts, the CLAUDE.md code rule gains the words "(rows that only measure, such as the clock pairs
of spec 08, carry no tier; decision 045)". CLAUDE.md is not edited by this record.

## Consequences
No code or output changes. Spec 08 §3 and spec 03 §3 can cite this record. A future stage that pairs events must
say whether its rows are path links (tier) or measurements (no tier).

## Kill criteria
If a clock pair is ever used as a path link or a path node, this exemption no longer applies and the row needs a tier.

## Committee answer
**EN:** A tier tells how sure a link in an attack path is. The clock pairs are not links in a path; they are only used to measure how far each clock is off, and that quality is reported per host instead.
**TH:** ระดับความเชื่อมั่น (tier) บอกว่าการเชื่อมโยงในเส้นทางโจมตีน่าเชื่อถือเพียงใด ส่วนคู่เหตุการณ์ที่ใช้วัดนาฬิกาไม่ใช่การเชื่อมโยงในเส้นทาง ใช้เพื่อวัดความคลาดเคลื่อนของนาฬิกาเท่านั้น และคุณภาพของค่าที่วัดได้รายงานแยกต่อเครื่อง
