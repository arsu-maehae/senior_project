# 057 — PyYAML reads the Sigma rule files

**Date:** 2026-11-17 · **Status:** accepted (owner answer to the T8 plan, 2026-11-17) · **Task:** T8.2 · **Relates to:** [056](056-sigma-rule-list-lock.md) (own Sigma-subset matcher, rule files in standard Sigma YAML), spec [04_label](../specs/04_label.md) LB-04, LB-05, LB-13

## Context
Decision 056 keeps the 14 locked rules as standard Sigma YAML and matches them with our own subset matcher.
`pyproject.toml` declared only `evtx`, and the project venv had no YAML parser (`import yaml` failed on 2026-11-17).
The matcher needs to read mappings, lists, quoted strings with backslashes, and block scalars from the SigmaHQ files.

## Options considered
| Option | Pros | Cons | Evidence |
|---|---|---|---|
| A. PyYAML, `yaml.safe_load` only (**chosen**) | the standard parser; pySigma itself depends on it; little code | one new dependency | venv check; SigmaHQ files are plain YAML 1.1 |
| B. Our own mini YAML reader | no dependency | more code to test and explain; quoting and escape rules are easy to get wrong | – |
| C. Hand-written JSON copies of the rules | no dependency | two copies that must be kept equal | – |

## Decision
Option A. `pyyaml>=6.0` is added to `pyproject.toml` (installed: 6.0.3). Rule files are read only with
`yaml.safe_load`, never `yaml.load`. Matching is still our own code (056). Rule files are LF in the repo
(`.gitattributes`: `src/label/rules/* text eol=lf`), and their SHA-256 is taken over LF-normalised bytes (LB-13).

## Consequences
- A fresh machine needs `pip install -e .` again.
- YAML 1.1 rules apply (for example `yes` / `no` read as booleans), so the rule loader validates value types against
  the LB-05 subset and refuses anything unexpected.

## Kill criteria
- A locked rule file that `safe_load` reads differently from its Sigma meaning (found by LBT-04 / LBT-10). The loader
  then refuses that file, and the fix is a new record.

## Committee answer
**EN:** The rules stay in the standard Sigma format, so anyone can check them against SigmaHQ. We read them with the
standard YAML library in its safe mode and wrote only the matching ourselves, which is the part we must explain.
**TH:** กฎยังอยู่ในรูปแบบ Sigma มาตรฐาน ใครก็ตรวจเทียบกับ SigmaHQ ได้ เราอ่านไฟล์ด้วยไลบรารี YAML มาตรฐานในโหมดปลอดภัย และเขียนเองเฉพาะส่วนจับคู่กฎ ซึ่งเป็นส่วนที่ต้องอธิบายได้
