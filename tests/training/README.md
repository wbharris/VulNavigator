# Blind-CVE training (local first, autonomous Grok loop)

SuperGrok meters **compute**. Fetch, pytest, and rescan run on this machine.
Grok only reads `cases/error-pack.md` (~20 samples), then fixes without asking.

Reset: **11:17** weekly. New Grok session. Give the **current** Settings → Usage percent (not a leftover example).

## You type

```
train <percent>%
```

Grok runs `weekly.py --used N` with that percent (no confirmation), grows or rescans by the table below, reads the pack, fixes extractors, updates the skill, pytest, rescans, repeats up to `rounds`, then reports errors + fixes.

| % used | grow | rounds |
|---|---|---|
| 0–25 | +150 | 3 |
| 26–50 | +100 | 3 |
| 51–70 | +50 | 2 |
| 71–85 | +25 | 2 |
| 86–94 | +0 (fix-only) | 1 |
| 95–100 | pack only | 0 |

## Local commands (if you are not in Grok)

```bash
.venv/bin/python tests/training/weekly.py --used N --suggest-only
.venv/bin/python tests/training/weekly.py --used 0          # after reset: +150
.venv/bin/python tests/training/weekly.py --rescan
.venv/bin/python -m pytest -q
```

## Rules

- Description only. Strip `CVE-YYYY-NNNNN`. `--offline`. No `--source cve`.
- Phrase → CWE. Do not fail on NVD-only fields (CWE-20, AV:N with no remote wording).
- A pasted advisory without a CVE id is not an AI 0-day.
- Scorecards in `cases/` (gitignored). Commit `tests/data/blind_cve_2026.json`.
- Do not push unless asked.
