# VulNavigator

The expected input is a **Mythos** finding or a **Daybreak** (Codex Security) finding.

Those tools find bugs. This one answers: is it real, what can an attacker do with it, what do we do this week, and **what did the agent guess**.

Full contract: [`docs/PRODUCT.md`](docs/PRODUCT.md).

## What you drop in

| Source | File |
|--------|------|
| **Daybreak / Codex Security** | `findings.json` from a completed scan, a sealed scan directory (`findings.json` + `scan-manifest.json`), or one finding from that document |
| **Mythos** | The write-up JSON or markdown Mythos emitted (title, target, PoC, reproduced) |

CVE-only is a fallback, not the main path.

```bash
vuln-nav analyze findings.json
vuln-nav analyze /path/to/codex-security-scan/
vuln-nav analyze mythos-writeup.json --source mythos
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
vuln-nav analyze examples/mythos-finding.json -o report.md
```

`--offline` skips NVD / CISA KEV / FIRST EPSS.

## Status

v0.1 — Daybreak `codex-security.findings` v1 and Mythos write-ups. Official CTID / D3FEND / ATLAS snapshots and a reasoning model are the next slice.

## License

Copyright (C) 2026 wbharris

[GNU General Public License v3.0 or later](LICENSE) (GPL-3.0-or-later).
