---
name: vulnavigator
description: Analyze vulnerabilities using VulNavigator tool with MITRE ATT&CK and D3FEND integration
argument-hint: "<finding_file> [options]"
allowed-tools:
  - read
  - exec
  - grep
  - glob
permissions:
  allow:
    - Exec(vuln-nav analyze)
    - Exec(Projects/VulNavigator/.venv/bin/python)
---

Help analyze vulnerabilities using the VulNavigator tool with MITRE ATT&CK and D3FEND integration.

## VulNavigator Overview
VulNavigator transforms security findings from AI tools (Mythos, Daybreak) or mainstream scanners into actionable defender cases. It performs normalization, validation, ATT&CK/D3FEND/CSF mapping, prioritization, and generates comprehensive reports.

**NEW:** Web interface with live MITRE MCP integration for enhanced threat intelligence!

## Web Interface
Run the VulNavigator web interface at http://localhost:5000:
```bash
cd /home/iceroot
/home/iceroot/web_venv/bin/python vulnavigator_web.py
```

### Web Interface Features
- **Interactive web UI** for vulnerability analysis
- **MITRE ATT&CK integration** via compliance-api MCP server
- **D3FEND countermeasures** with implementation guidance
- **CVE lookup** via OSV.dev using voraxx-mcp-server
- **Shodan exposure assessment** for network intelligence
- **Smart enhancement** based on vulnerability type
- **Real-time threat intelligence** from MITRE databases

### Web Interface Usage
1. Open http://localhost:5000 in your browser
2. Enter findings as JSON, text, or CVE
3. Enable MITRE enhancement options:
   - 🚀 Enhance with MITRE data (ATT&CK + D3FEND)
   - 🔍 CVE lookup (OSV.dev)
   - 🌐 Shodan exposure (network intelligence)
4. Get enhanced reports with real threat intelligence

## Command Line Usage
Run VulNavigator analysis on a finding file:
```bash
vuln-nav analyze <finding_file> [--source NAME] [--id ID] [--offline] [--json] [-o report.md]
```

## Supported Input Sources
- **AI Finders**: Daybreak findings.json, Mythos write-ups, narrative tickets
- **Scanners**: Qualys VM XML/CSV, OpenVAS/GVM XML/CSV, Nessus .nessus, Rapid7 Nexpose XML, SARIF, Trivy/Snyk, Wiz/Prisma/Orca, Defender VM, CrowdStrike Spotlight, AWS Inspector, Nexus IQ, Nuclei JSONL, Burp/ZAP XML
- **CVE-only**: CVE-YYYY-NNNNN format as fallback

## Analysis Steps
1. **Normalize**: Convert scanner-specific format to standardized finding
2. **Validate**: Check evidence, PoC, reproducibility
3. **Map**: ATT&CK behaviors, D3FEND countermeasures, NIST CSF alignment
4. **Prioritize**: Using KEV, EPSS, CVSS scores
5. **Report**: Generate 11-section markdown or JSON case file

## MCP Integration
The VulNavigator web interface uses MCP servers for enhanced threat intelligence:

### compliance-api MCP Server
- **MITRE ATT&CK v15.0**: Adversary Tactics, Techniques, and Procedures
- **MITRE D3FEND v1.1**: Cybersecurity Countermeasures Knowledge Graph
- **CWE Top 25**: Most Dangerous Software Weaknesses (2024)

### voraxx-mcp-server (Direct Integration)
- **CVE lookup**: OSV.dev vulnerability database
- **Shodan exposure**: InternetDB network reconnaissance
- **Nuclei scanning**: Template-based vulnerability detection

## Report Sections
1. Vulnerability summary
2. Evidence (facts, how found, PoC/exploit, missing evidence)
3. Validation notes
4. Attacker behaviors / ATT&CK
5. Defensive countermeasures (D3FEND)
6. NIST CSF alignment
7. Priority and urgency
8. Remediation
9. Compensating controls
10. Next actions (owner + done-when)
11. Confidence, assumptions, and improvements

## Key Options
- `--source NAME`: Force specific adapter (mythos, daybreak, nessus, qualys, sarif, trivy, etc.)
- `--id ID`: Analyze single finding by ID (short token with letters, digits, _.:/=@+-)
- `--offline`: Skip live NVD, CISA KEV, and FIRST EPSS calls (still runs normalize/validate/mapping/report)
- `--json`: Output JSON case file instead of markdown
- `-o report.md`: Specify output file

## Example Files
Check the examples directory for sample inputs:
- `examples/daybreak-findings.json`
- `examples/mythos-zeroday.json`
- `examples/narrative-rce.txt`
- `examples/nessus-report.nessus`
- `examples/sarif-report.sarif`
- `examples/trivy-report.json`

## Test Command
Run example intakes:
```bash
.venv/bin/python tests/simulate_intake.py
```

When the user provides a finding file, analyze it using VulNavigator and provide a summary of the key findings, priority level, and recommended actions. For enhanced analysis with MITRE intelligence, suggest using the web interface at http://localhost:5000.