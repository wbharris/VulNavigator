# VulNavigator

Turn a **Mythos** or **Daybreak** vulnerability finding into a case a defender can act on.

Those tools find bugs. This one answers: is it real, what can an attacker do with it, what do we do this week, and **what did the agent guess**.

Full contract: [`docs/PRODUCT.md`](docs/PRODUCT.md).

## What you get

1. **Normalize** the input (Daybreak JSON, Mythos JSON, a CVE, or a write-up)
2. **Validate** the finding (identity, KEV, EPSS, evidence quality)
3. **Map** it (ATT&CK → D3FEND → NIST CSF; ATLAS / AI RMF / F3 only when in scope)
4. **Report** priority, urgency, remediation, compensating controls, next actions
5. **Honesty layer** — every assumption, plus the questions that would improve the report

## Install

```bash
git clone https://github.com/wbharris/VulNavigator.git
cd VulNavigator
python3 -m pip install -e .
```

## Use

```bash
vuln-nav analyze examples/daybreak-finding.json
vuln-nav analyze examples/mythos-finding.json -o report.md
vuln-nav analyze CVE-2024-3400 --offline
vuln-nav analyze examples/daybreak-finding.json --json
```

`--offline` skips NVD / CISA KEV / FIRST EPSS. Live enrichment is used when the network is up.

## Status

v0.1 — CLI pipeline with curated CWE→ATT&CK heuristics. Official CTID / D3FEND / ATLAS snapshots and a reasoning model are the next slice.

## License

Copyright (C) 2026 wbharris

[GNU General Public License v3.0 or later](LICENSE) (GPL-3.0-or-later).
