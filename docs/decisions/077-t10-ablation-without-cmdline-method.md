# 077 — T10 ablation without the command-line source method (PLAN 10.6, development data)

**Date:** 2026-11-25 · **Status:** accepted (stage lead; within spec 06 §10 D-F/D-G; owner instructions 2026-11-18 and
2026-11-24; for owner review) · **Task:** T10 (PLAN 10.6, development part) · **Relates to:** spec
[06_evaluate](../specs/06_evaluate.md) AB-01..11; [020](020-answer-key-provenance.md); Correction I; decision 013;
[072](072-evaluate-t10-readings-and-runner.md), [074](074-run-trial-implementation-readings.md)

## Context
PLAN 10.6 asks for at least one result that does not rest on the evidence the answer key uses. Under 020 the keys
confirm a hop only by an agent command line that names the target. The stitcher's tier-B method `cmdline_target`
uses the same kind of evidence.

Data-checker counts on the 6 keyed development trials, 2026-11-18:
- 5 of the 7 key attack hops are linked by `cmdline_target` only: s02-h1, s04-B-h1, s05-h1, s07-h-x and s07-h-y.
- 2 keep a port join and a 4648 link, at tier A: s03-h1 and s05-h2.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Switch off every use of command-line evidence in the stitcher, run in a scratch repo, report side by side without a verdict (**chosen**) | answers 10.6 directly; the default code path and outputs are unchanged (shown on the 9 development trials by the dry run and the control arm); no hypothesis is invented | a non-default switch in a reviewed stage |
| Drop only the `cmdline_target` link rows after the fact | no stitch change | names and counts from command lines would still shape tiers, `link_rank` and the data limits (ATK-EV-28) |
| Add a hypothesis for the ablation | a held / not held answer | a new hypothesis after the freeze needs the owner and a freeze record (065, 070) |

## Decision
1. **Switch.** `StitchParams.disabled_methods`, CLI `--disable-method cmdline_target`. No other name is accepted. The
   switch is refused when `--repo` (or `--out`) resolves into the real repository, and the runner refuses
   `--stitch-disable-method` the same way before any stage starts.
2. **Every use is switched off** (file:line in the working tree at the time of this record):
   - The command text is never read: `stitch/links.py` `read_commands` (≈407–410, called at ≈434).
   - `source.by_cmdline` returns an empty result (≈488). Through it, the cmdline count, `session_methods`, session
     data, link rows, `candidate_count_all` and the out-of-range evidence (≈699–720) carry no command-line
     evidence.
   - The name check loses its input, so it no longer breaks a tie or moves a `link_rank`, and it reads `not_run`
     (AB-13): `tiers.py` ≈134–135, ≈283–284.
   - The tier's consistent count covers only the sessions that are left (`tiers.py` ≈281).
   - The data limits count 0 cmdline events (`links.py` ≈316–318, ≈328).
   - The stats follow indirectly: `hops_by_methods_linked`, `candidate_count_all > 1`, and the hops.csv
     `candidate_count`.
3. **The default stays byte-identical** (shown on the 9 development trials; not a proof for other inputs).
   `disabled_methods` is written only when it is non-empty.
   - The default parameter block is identical in the working tree, at HEAD and in all 18 recorded stitch
     `run_info.json` / `stats.json` files (SHA-256 `b63fd046…`).
   - The dry run (2026-11-24, and again after this change) reproduces every stitch file byte for byte; `run_info.json`
     differs only in `generated_utc`.
4. **The run.** `python -m run_trial.ablation`:
   - It uses a scratch repo outside the repository, with the same allowlist, copy and deletion rules as the dry run.
   - `--results` is never run there, so no verdict exists.
   - The output is copied through a temporary folder and swapped into `out/ablation/no_cmdline/`. No stage reads that
     folder, and the tree check excludes exactly it.
5. **Reading.** The **hop reading** is the headline: key hops are mapped by target logon uids, which do not use the
   command lines. The node reading is shown beside it, labelled "key built from the same command-line evidence:
   node recall falls by construction". There is no threshold, comparator or verdict column, and every table carries
   the banner "ABLATION (cmdline_target disabled) — DEVELOPMENT, not a result".

## Consequences
DEVELOPMENT numbers, not results.

**Hop reading, unchanged** for `full`, `b1` and `b2`:
- top-1 0.900; per-trial MRR 0.933; per-key MRR 0.833
- contested s04/s07: per-key MRR 0.667
- S06 margins: `full` 0.306, `b1` −0.042, `b2` −0.333

**Node-based values fall.** In every attack trial, every node the ablation loses is a `source_evidence` node, and
every lost key node is one of the key's agent process events (`agent_event_uids` or `agent_corroboration_4688_uids`).
These are the Sysmon 1 / 4688 process starts that only the command-line method attaches. No node is gained. Lost key
nodes per trial: s02 6, s03 2, s04 8, s05 10, s07 16 (read-only check, 2026-11-25). This includes s03, whose hop keeps
its tier-A session through port and 4648 but loses its two command-line evidence nodes. b0's values move a little
because its budget is `full`'s all-node budget, which shrinks.
- node P/R/F1 `full`: 0.795/0.877/0.830 → 0.768/0.592/0.655
- AUC `full`: 0.972 → 0.909, with n_pos 6 → 4
- node-reading top-1: 0.900 → 0.700
- node-reading per-key MRR: 0.833 → 0.611

**Linking:**
- `cmdline_target` link rows: 18 → 0
- best tier: A 6 → 6, B 10 → 3, D 268 → 275
- the 5 cmdline-only key attack hops go from B to D, with no candidate session
- H4 labelled recall is unchanged (0.830 vs 0.423); the all-node budget moves (for example s07: 40 → 24)

**What this shows on development data:** removing the command-line method takes the source session away from 5 of
the 7 key attack hops, but it does not change how the ranking orders the key attack paths on the hop reading. The
switch does change path assembly, and with it the nodes each path holds (for example s07: 40 → 24 held nodes in the
top-k), so LengthScore and NodeScore could move. On these trials they did not move the order of the key attack
paths. This is a statement about the 6 keyed development trials, not a result.

## Kill criteria
- If the owner wants a held / not held answer for the ablation, that is a new hypothesis and needs a freeze record
  before T5.7.
- If a later change makes any default stitch file differ, the switch is wrong and is removed.

## Committee answer
**EN:** Our answer keys confirm a hop only when the attack agent's command line names the target. So we reran the
whole pipeline with the linker's command-line method switched off. On the development trials the ranking of the
attack paths stayed the same on the hop reading. The node measures dropped, and every node lost was one of the
agent process events the key itself lists, which we expected and label as such.
**TH:** เฉลยของเรายืนยัน hop เฉพาะเมื่อบรรทัดคำสั่งของ agent ระบุชื่อเครื่องเป้าหมาย เราจึงรันทั้งไปป์ไลน์ใหม่โดยปิดวิธีเชื่อมโยงที่ใช้บรรทัดคำสั่ง
บนข้อมูลชุดพัฒนา การจัดอันดับเส้นทางโจมตีในการอ่านแบบ hop ยังเหมือนเดิม ตัววัดระดับโหนดลดลง และทุกโหนดที่หายไปเป็นเหตุการณ์โปรเซสของ agent
ที่เฉลยระบุไว้เอง ซึ่งเราคาดไว้และระบุไว้ชัดเจน
