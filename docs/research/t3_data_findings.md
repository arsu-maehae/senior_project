# T3 data findings on the t00 databases (input for T4)

Source: read-only SQL on `data/processed/s0N_t00.sqlite3` (data-checker, 2026-11-10). Raw JSONL spot-checked for item 1. These are measurements, not design decisions. T4 (`/log-check`) owns the full reality check.

## 1. No SMB, RDP or WinRM Sysmon 3 on the endpoints of S02, S04 and S07 (blocks Correction I as written)
- Sysmon 3 rows to ports 445, 3389, 5985: **s02 0, s04 0, s07 0**. s03 has 5985 on ep-01/ep-03 and 1 row to 445 on ep-03; s05 has 5985 and 1 row to 445 on ep-03; s06 the same as s03.
- The raw JSONL for s02, s04, s07 (ep-01, ep-02 Sysmon) contains no `DestinationPort 445` at all, so the normaliser did not drop them. The same pattern finds the 2 rows in s01 ep-03 and 1 row in s03 ep-03.
- Those endpoints do log Sysmon 3 (s02: 22 rows, s04: 28, s07: 45), mostly to ports 5353 and 8888 from `splunkd.exe`.
- `Image = System` appears only in s01 ep-03 (2 rows, flagged trial). It is 0 in s02 to s07.
- Effect: for the SMB hops of S02, S04, S05, S07 the source-side link "4624 (IpAddress, IpPort) to Sysmon 3 (SourceIp/Port) to ProcessGuid" cannot be made from Sysmon 3. Of the remote 4624 rows with port > 0, only 4 (s03), 5 (s05) and 3 (s06) have any Sysmon 3 candidate (+-5 s, other host). No candidate set had 2 or more members.
- Likely cause (not verified): Sysmon configuration does not log inbound/outbound 445 on these endpoints. Needs the Sysmon config and the answer keys.

## 2. s01 t00 is target-side only (known, decision 001)
s01 dc01 and ep-01 are identical to s02's (same counts: dc01 Security 1,328, ep-01 Security 575). Do not sum s01 and s02 in statistics.

## 3. Windows are wider than the trials
Hosts hold events from several days (09-17, 09-21, 09-22, and the previous trial on 09-24; s05 to s07 also hold 09-24 data). Windows must be cut from the answer keys, not from the DB.

## 4. Other measurements
- 4624 remote logons are all Type 3 (no Type 10 with a source IP). Kerberos rows with `IpPort = 0`: s01 32, s02 26, s03 64, s04 36, s05 53, s06 52, s07 40. NTLM rows always have a port > 0 except 4 in s01.
- `::1` and `fe80::` sources are a large share of remote 4624 (s02: 155 of 261); the gate suppresses loopback.
- Kerberos confirmation (4624 logon_guid ↔ dc01 4769): s02 262/262, s04 435/435; s03 805/925, s05 562/667, s06 479/590 (the rest unexplained; not investigated).
- Missing channels: no dc01 Sysmon in s03, s04, s06, s07; no dc01 System in s06, s07; s06 has no System on ep-01/ep-03.
- Sysmon 10 on lsass: rundll32 dump rows (0x1410 + 0x1fffff) exist in s01 ep-01, s02 ep-01 and ep-02, s03 ep-01, s04 ep-01, s05 ep-01 and ep-02, s07 ep-01 (2 pairs). **s06 has none**, consistent with a benign baseline. Noise: VBoxService (up to 996 rows), MsMpEng, svchost, wmiprvse; wmiprvse and MsMpEng also use 0x1410, so the source image (rundll32) is a better marker than the mask alone.
- `session_id` is non-NULL on every Sysmon 1 and 4688 row; no zero logon ids in any DB.

## 5. Sysmon record time vs event time (measured 2026-11-10, `events.timestamp_utc - events.event_utc`)
- dc01, ep-01 (all trials), ep-02 (s01, s02, s04, s05), s04/s05/s07 ep-01: gap 0 to 60 s (max 28.2 s). Normal.
- ep-03 (s01, s03, s05, s06): 46 rows with a negative gap (min -11.5 s; s01 184 rows, min -26.3 s) and 114 rows over 60 s (max 59,944.6 s = 16.6 h, e.g. Sysmon 1 with UtcTime 2026-09-21T12:56:23Z and record time 2026-09-22T05:35:28Z).
- ep-02 in s06 and s07: 12 and 14 rows over 60 s (max 6,638 s and 7,341 s).
- Reading: clock steps or snapshot resume on the VMs hosted on VMware (host C). Not a code defect. Effect: time-window and time-delta rules in stitching must use a tolerance and flag rows from ep-02/ep-03 whose gap exceeds 60 s. T4 to check clock offsets against the DC.
