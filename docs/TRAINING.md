# VulNavigator™ training contract

Single source for blind-CVE scoring and glossary.
Skills and `tests/training/README.md` point here; do not fork these rules.

Product analyze path remains [`PRODUCT.md`](PRODUCT.md).

## What “blind” means

VulNavigator is scored on an NVD **English description only**:

1. Strip every `CVE-YYYY-NNNNN` (replace with `[ID REDACTED]`).
2. `analyze_text(..., offline=True)` — no NVD/KEV/EPSS, no `--source cve`.
3. Compare the case to **phrase-implied** fields in that prose (CWE, product, path, exposure, public-exploit *claim*).
4. Do **not** treat NVD-only labels as misses (CWE-20 with no matching words, AV:N with no remote wording).

Frozen corpus: `tests/data/blind_cve_2026.json` (first **300** CVE-2026-*, ids stripped). Pytest requires **>=300** rows. `--rescan` reuses frozen `nvd_cwe` / `nvd_cvss` / `nvd_products`. Scorecards in `cases/` stay gitignored.

Phrase → CWE rules live in `src/vulnavigator/data/phrase_cwe.py` (family, id, pattern, owner). Regression pack: `tests/data/phrase_families.json`.

## Score semantics

| Issue kind | Means | Fix |
|------------|--------|-----|
| phrase CWE miss | Prose names a taught class; case lacks that CWE | Add/fix a rule + fixture |
| product / path / remote miss | Tokens are in the description | Teach extractor from those words |
| conflict (AI 0-day, truncated product) | Wrong identity or last-word product | Fix identity / skip-list |
| leak (CVE or CVSS on a blind pass) | Id leaked into analyze | Keep stripping; do not pass `--source cve` |
| NVD-only CWE | Gold NVD CWE never stated in prose | Ignore |

A pasted advisory **without** a CVE id is **not** an AI 0-day.

## 15-minute quickstart

From repo root, after `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"`:

```bash
# 1. One narrative case (11-section markdown on stdout)
.venv/bin/vuln-nav analyze examples/narrative-rce.txt --offline
# expect: source narrative, CWE-94 from "remote code execution", internet-facing true,
#         not an AI 0-day (no Mythos/Daybreak/sandbox language)

# 2. Phrase pack + corpus gate
.venv/bin/python -m pytest -q tests/test_blind_advisory.py tests/test_phrase_cwe_lint.py tests/test_blind_corpus.py
# expect: pass (corpus >= 300)

# 3. Inspect one corpus sample and preflight
sed -n '1,12p' tests/data/blind_cve_2026.json
.venv/bin/python tests/training/weekly.py --preflight-only
```

To **fix one sample**: add a rule in `phrase_cwe.py`, a row in `phrase_families.json`, `pytest -q`, then `weekly.py --rescan` (needs a local `cases/blind-first-*.json` or it falls back / tells you to `--grow`).

## Glossary

| Term | Meaning |
|------|---------|
| **AI 0-day** | Mythos or Daybreak write-up (or prose that says the model/sandbox found it) with PoC/discovery. Usually **no CVE**. |
| **Advisory / NVD narrative** | Vendor or NVD English description. Blind training strips the CVE id. Still an advisory, not an AI 0-day. |
| **Scanner detection** | Nessus/Qualys/SARIF/… hit. Evidence of a **scan**, not a replayable exploit. |
| **Blind pass** | Description only, `--offline`, no CVE id in the input. |
| **Scorecard** | `cases/blind-first-N.json` — local issue list vs gold. Gitignored. |
| **Error pack** | Compact fail sample (`cases/error-pack.md`). |
| **Phrase CWE** | CWE implied by words in the description (`cwes_from_text`). |
| **NVD gold** | CWE/CVSS/CPE on the real CVE record. Used as context, not as a teach-this-phrase signal. |
