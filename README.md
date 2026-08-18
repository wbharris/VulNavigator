# VulNavigator

Turn a **Mythos** or **Daybreak** finding — or a mainstream scanner export — into a case a defender can act on.

Those tools find bugs. This one answers: is it real, what can an attacker do with it, what do we do this week, and **what did the agent guess**.

**AI 0-days usually have no CVE.** The PoC/exploit and the write-up of how the model found the bug *are* the finding. Do not wait for NVD.

Repo: https://github.com/wbharris/VulNavigator

Full contract: [`docs/PRODUCT.md`](docs/PRODUCT.md).

## Install

```bash
git clone https://github.com/wbharris/VulNavigator.git
cd VulNavigator
python3 -m venv .venv && .venv/bin/pip install -e .
```

## Use

```bash
vuln-nav analyze FINDING [--source NAME] [--id ID] [--offline] [--json] [-o report.md]
```

| Input | Command |
|-------|---------|
| Daybreak `findings.json` or scan directory | `vuln-nav analyze findings.json` |
| Mythos write-up (JSON/markdown) | `vuln-nav analyze writeup.json --source mythos` |
| Narrative ticket / email | `vuln-nav analyze notes.txt` |
| Qualys / OpenVAS / Nessus | `vuln-nav analyze scan.nessus` |
| One finding in a batch | `vuln-nav analyze findings.json --id db-heap-h2-headers` |

`--offline` skips NVD / CISA KEV / FIRST EPSS. `--source` forces `mythos`, `daybreak`, `nessus`, `qualys`, `sarif`, `trivy`, and the other adapters.

## What you drop in

**AI finders (primary)**

| Source | File |
|--------|------|
| **Daybreak / Codex Security** | Official `findings.json`, a sealed scan directory, or one finding record |
| **Mythos** | Write-up JSON/markdown: title, target, **PoC**, **discovery**, reproduced |
| **Narrative** | Free-text ticket (internet-facing, RCE, no PoC yet, …) |

**Scanners and interchange**

| Source | File |
|--------|------|
| Qualys | VM XML or CSV (`QID`) |
| OpenVAS / GVM | Greenbone XML or CSV (NVT/OID) |
| Nessus | `.nessus` or Tenable CSV (`Plugin ID`) |
| Rapid7 InsightVM / Nexpose | Nexpose XML |
| SARIF | CodeQL, Semgrep, GHAS, other SAST |
| Trivy / Snyk / Dependabot | CI / SCA JSON |
| Wiz / Prisma / Orca | Cloud CNAPP JSON |
| Defender VM / CrowdStrike Spotlight | Endpoint VM JSON |
| AWS Inspector | Inspector2 findings JSON |
| Nexus IQ | Sonatype component JSON |
| Nuclei | JSONL |
| Burp / ZAP | DAST XML |

CVE-only (`CVE-YYYY-NNNNN`) is a fallback. Scanner hits are **detections**, not exploit proof.

## What you get

An 11-section markdown report (or `--json` case file):

1. Vulnerability summary  
2. Evidence (facts, **how it was found**, **PoC/exploit**, missing evidence)  
3. Validation notes  
4. Attacker behaviors / ATT&CK (ATLAS / AI RMF / F3 only if in scope)  
5. Defensive countermeasures (D3FEND)  
6. NIST CSF alignment  
7. Priority and urgency  
8. Remediation  
9. Compensating controls  
10. Next actions (owner + done-when)  
11. Confidence, assumptions, and what would improve the report  

Pipeline: **normalize → validate → map → prioritize → report**.

## Examples

```bash
vuln-nav analyze examples/daybreak-findings.json
vuln-nav analyze examples/mythos-zeroday.json          # no CVE — PoC + discovery
vuln-nav analyze examples/narrative-rce.txt
vuln-nav analyze examples/nessus-report.nessus
vuln-nav analyze examples/sarif-report.sarif
vuln-nav analyze examples/trivy-report.json
```

```bash
.venv/bin/python -m pytest -q
.venv/bin/python tests/simulate_intake.py    # all example intakes → tests/last-results.html
```

## Status

v0.1 on GitHub `main`. Next slice: pinned ATT&CK / D3FEND / ATLAS snapshots and a reasoning model.

## License

Copyright (C) 2026 wbharris

[GNU General Public License v3.0 or later](LICENSE) (GPL-3.0-or-later).
