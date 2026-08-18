# VulNavigator

Expected intake is a **Mythos** or **Daybreak** finding, or a mainstream scanner / SARIF export.

Those tools find bugs. This one answers: is it real, what can an attacker do with it, what do we do this week, and **what did the agent guess**.

Mythos and Daybreak **0-days usually have no CVE**. The PoC/exploit and the write-up of how the model found the bug *are* the finding.

Full contract: [`docs/PRODUCT.md`](docs/PRODUCT.md).

## What you drop in

| Source | File |
|--------|------|
| **Daybreak / Codex Security** | `findings.json`, a sealed scan directory, or one finding from that document |
| **Mythos** | Write-up JSON or markdown (title, target, PoC, reproduced) |
| **Qualys** | VM XML or CSV (`QID`) |
| **OpenVAS / GVM** | Greenbone XML or CSV (NVT/OID) |
| **Nessus** | `.nessus` or Tenable CSV (`Plugin ID`) |
| **Rapid7 InsightVM / Nexpose** | Nexpose XML |
| **SARIF** | CodeQL, Semgrep, GHAS, Daybreak SARIF, other SAST |
| **Trivy / Snyk / Dependabot** | CI / SCA JSON |
| **Wiz / Prisma / Orca** | Cloud CNAPP JSON |
| **Defender VM / CrowdStrike Spotlight** | Endpoint VM JSON |
| **AWS Inspector** | Inspector2 findings JSON |
| **Nexus IQ** | Sonatype component security JSON |
| **Nuclei** | JSONL |
| **Burp / ZAP** | DAST XML |

CVE-only is a fallback.

```bash
vuln-nav analyze findings.json
vuln-nav analyze mythos-writeup.json --source mythos
vuln-nav analyze scan.nessus
vuln-nav analyze qualys-report.xml
vuln-nav analyze openvas-report.xml
vuln-nav analyze findings.json --id db-heap-h2-headers
```

## What you get

1. **Normalize** the Mythos or Daybreak record
2. **Validate** it (finder evidence, KEV, EPSS)
3. **Map** it (ATT&CK → D3FEND → NIST CSF; ATLAS / AI RMF / F3 only when in scope)
4. **Report** priority, urgency, remediation, compensating controls, next actions
5. **Honesty layer** — every assumption, plus the questions that would improve the report

## Install

```bash
git clone https://github.com/wbharris/VulNavigator.git
cd VulNavigator
python3 -m venv .venv && .venv/bin/pip install -e .
```

## Examples

```bash
vuln-nav analyze examples/daybreak-findings.json
vuln-nav analyze examples/mythos-finding.json
vuln-nav analyze examples/nessus-report.nessus
vuln-nav analyze examples/qualys-report.xml
vuln-nav analyze examples/openvas-report.xml
vuln-nav analyze examples/sarif-report.sarif
vuln-nav analyze examples/trivy-report.json
```

`--offline` skips NVD / CISA KEV / FIRST EPSS. Scanner hits are detections, not exploit proof.

## Status

v0.1 — Mythos, Daybreak, and mainstream scanner/SARIF intake. Official CTID / D3FEND / ATLAS snapshots and a reasoning model are the next slice.

## License

Copyright (C) 2026 wbharris

[GNU General Public License v3.0 or later](LICENSE) (GPL-3.0-or-later).
