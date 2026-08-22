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

## Pipeline (do not skip)

1. Normalize to one case file
2. Validate evidence / PoC / identity
3. Map ATT&CK, D3FEND, NIST CSF from local tables
4. Prioritize: exposure, replayable PoC, and whether mapping unlocks RCE/credentials. KEV/EPSS/CVSS only when a CVE exists and `--offline` was not used. Priority is not CVSS.
5. 11-section markdown or `--json`

## Recent Fixes

- **Title preservation**: Generic title rewrite now only applies to true narrative tickets (source_kind == "narrative"), preserving proper titles from structured JSON inputs.

AI 0-days usually have no CVE. Judge PoC + discovery write-up. Do not wait for NVD.

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
```
