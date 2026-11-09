# 008 — account_name and domain rules

**Date:** 2026-11-10 · **Status:** accepted · **Task:** T3

## Context
NF-04: `svc_backup@LAB.LOCAL` (4769) and `LAB` + `svc_backup` (4624) must compare equal. The attacker pointed out that a local `EP-02\Administrator` and the domain `LAB\Administrator` both become `administrator`, and that Sysmon rows have no `domain`.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| A. Bare name only | Simple | Local and domain accounts merge |
| B. Bare `account_name` plus `domain_short`, parsed before stripping | Keeps the distinction | One more column |

## Decision
Option B (owner rule 2026-11-09 plus attacker). `account_name` strips `DOMAIN\` and `@REALM`, lowercases, and keeps a trailing `$`. `domain_short` = first label of the domain or realm, lowercase; for Sysmon `User`/`SourceUser` the prefix is parsed into `domain` before stripping (NF-18). `machine_account` follows `account_name` ending in `$`.

## Consequences
Identity joins use (`account_name`, `domain_short`). 4769 domain `LAB.LOCAL` and 4624 domain `LAB` both give `lab`.

## Kill criteria
If the lab ever has the same account name in two domains, review again.

## Committee answer
**EN:** We compare accounts by name and domain, so a local administrator is never confused with the domain one.
**TH:** เราเทียบบัญชีด้วยชื่อและโดเมน ผู้ดูแลเครื่องกับผู้ดูแลโดเมนจึงไม่ถูกสับสนกัน
