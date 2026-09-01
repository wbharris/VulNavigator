---
name: vulnavigator
description: Run vuln-nav analyze on a finding file and summarize the 11-section case.
argument-hint: "<finding_file> [options]"
allowed-tools:
  - read
  - exec
  - grep
  - glob
permissions:
  allow:
    - Exec(vuln-nav analyze)
    - Exec(.venv/bin/python)
    - Exec(.venv/bin/python -m pytest)
---

Run VulNavigator from this repository. Product contract: `docs/PRODUCT.md`.

## What this skill is

This skill invokes the CLI (`vuln-nav analyze`). It does **not** call MITRE MCP, OSV, Shodan, or Nuclei. ATT&CK / D3FEND / CSF IDs come from `src/vulnavigator/data/mappings.json`.

Do not start a web UI from this skill. That is `vulnavigator-web`, and the Flask app is not part of this package.

## Command

From the repo root (after `python3 -m venv .venv && .venv/bin/pip install -e .`):

```bash
.venv/bin/vuln-nav analyze <finding_file> [--source NAME] [--id ID] [--offline] [--json] [-o report.md]
```

If `vuln-nav` is already on PATH, that name is fine.

## Inputs

AI finders (primary): Daybreak `findings.json`, Mythos write-up, narrative ticket.

Scanners: Qualys, OpenVAS/GVM, Nessus, Rapid7, SARIF, Trivy/Snyk/Dependabot, Wiz/Prisma/Orca, Defender VM, CrowdStrike Spotlight, AWS Inspector, Nexus IQ, Nuclei JSONL, Burp/ZAP XML.

CVE-only (`CVE-YYYY-NNNNN`) is a fallback. Scanner hits are detections, not exploit proof.

Bundled examples: `examples/daybreak-findings.json`, `examples/mythos-zeroday.json`, `examples/narrative-rce.txt`, `examples/nessus-report.nessus`, `examples/sarif-report.sarif`, `examples/trivy-report.json`.

## Blind-CVE training (description only)

To train/test whether VulNavigator infers bug class, product, path, and exposure **without cheating via the CVE id**:

1. Take an NVD English **description only**. Strip every `CVE-YYYY-NNNNN` (and do not pass `--source cve`).
2. `vuln-nav analyze` that text `--offline` so NVD/KEV/EPSS cannot fill gaps.
3. Compare the case to the **hidden full CVE** (CWE, CVSS/AV:N, product/CPE, file, public-exploit claim).
4. Score **conflicts** (wrong CWE, AI 0-day label, truncated product) and **missing** fields.

Do **not** paste the CVE id into the Devin/web input for this loop. A lone id takes the CVE-only path and NVD writes the answer.

A pasted advisory without a CVE id is **not** an AI 0-day. Mythos/Daybreak (or narrative that says the model/sandbox found it) still are.

Narrative should pull, when the words are there:

- bug class → CWE (SQLi 89, XSS 79, SSTI 1336 before RCE 94, path traversal 22, upload 434, SSRF 918, CSRF 352, IDOR 639, missing auth 306/862, authentication bypass 288, stack overflow 121, heap-buffer-overflow 122, leak sensitive information 200, improper parsing of XML 611, inefficient regex 1333, undefined behavior 758, sudoers/privilege escalation 269, clear-text credentials 319, weak base64 credentials 261)
- `remotely` / `from remote` / `launched remotely` / `unauthenticated attacker` → `asset_internet_facing`
- Web bug-class CWE (SQLi, XSS, CSRF, SSRF, SSTI, upload, IDOR) implies network exposure unless the write-up is a local package-manager issue
- `CR & LF` / CRLF in headers → CWE-93 (in addition to SSRF if both are stated)
- `escape the directory` → CWE-24; `not tracked` → CWE-353; weakening IV/encryption → CWE-327/330
- `X is an open source…` / `The X is a tool` / `X (v1.2.3 and earlier)` / `This issue affects X:` / `MediaWiki - Name Extension` / `In version 1.2.3` / `up to <git hash>` → product (not the word `versions`, not `Insufficient`/`Improper`)
- file path **without** `:line` (`/student/index.php`, `search.php`)
- product + version (`in … System 1.0`, `Bagisto … versions prior to 2.3.10`) — not the last word (`System`, `including`, `versions`)
- “exploit has been released” → evidence **note** (claim, not a replayable PoC)

Frozen corpus: `tests/data/blind_cve_2026.json` (first **300** published CVE-2026-*, ids stripped; grows +150/week). Pytest `tests/test_blind_corpus.py` must stay green. Score **phrase → CWE** from the description, not NVD fields the prose never states (AV:N-only, CWE-20-only).

## Weekly training (autonomous, sized by SuperGrok %)

When the user reports SuperGrok usage from Settings → Usage as a percent (0–100):

1. **Do not ask to confirm.** Do not wait for more input.
2. Run `.venv/bin/python tests/training/weekly.py --used N` with **that** percent (suggests grow + rounds, then fetch/rescan + `cases/error-pack.md` locally).
3. Read **only** `cases/error-pack.md` and the `SUGGESTED` line. Do not open `blind-first-N.json`. Do not print every CVE. No subagents.
4. If mode is `report-only`, or the pack is CLEAN with nothing new: skip code edits and go to the final report.
5. Else implement phrase extractors (description text only), 3–8 tests in `tests/test_blind_advisory.py`, and skill bullets. Phrase → CWE; not NVD-only labels.
6. `.venv/bin/python -m pytest -q` then `.venv/bin/python tests/training/weekly.py --rescan`.
7. Read the **new** error pack. Repeat steps 5–6 up to the printed `rounds`. Stop early on CLEAN.
8. Do not push unless the user already said push.

**% → grow / fix rounds** (also printed by `weekly.py --used N --suggest-only`):

| % used | remaining | grow | rounds | mode |
|---|---|---|---|---|
| 0–25 | 75–100 | +150 | 3 | full |
| 26–50 | 50–74 | +100 | 3 | full |
| 51–70 | 30–49 | +50 | 2 | medium |
| 71–85 | 15–29 | +25 | 2 | small |
| 86–94 | 6–14 | +0 | 1 | fix-only |
| 95–100 | 0–5 | +0 | 0 | report-only |

**Final message** (always): suggested vs executed; CLEAN before → after; table of **errors found** and **fixes implemented** (phrase / CWE / product extractor / skill line); leftover fails (NVD-only, not taught). Details: `tests/training/README.md`.

## Pipeline (do not skip)

1. Normalize to one case file
2. Validate evidence / PoC / identity
3. Map ATT&CK, D3FEND, NIST CSF from local tables
4. Prioritize: exposure, replayable PoC, and whether mapping unlocks RCE/credentials. KEV/EPSS/CVSS only when a CVE exists and `--offline` was not used. Priority is not CVSS.
5. 11-section markdown or `--json`

AI 0-days (Mythos/Daybreak) usually have no CVE. Judge PoC + discovery write-up. Do not wait for NVD. Do not label a vendor advisory as an AI 0-day just because the id was stripped.

## After the report

Summarize for the user:

- validation status (`confirmed` / `plausible` / `unconfirmed` / `rejected`)
- priority and urgency
- what the agent guessed
- next actions (owner + done-when)

If they want a web form, point them to `vulnavigator-web` and say that UI is local/out-of-tree.

## Tests

```bash
.venv/bin/python -m pytest -q
.venv/bin/python tests/simulate_intake.py
.venv/bin/python tests/training/weekly.py          # compact error pack only
```
