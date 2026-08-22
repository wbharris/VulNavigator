---
name: vulnavigator-web
description: Start VulNavigator web interface with MITRE MCP integration
argument-hint: ""
allowed-tools:
  - exec
  - read
permissions:
  allow:
    - Exec(/home/iceroot/web_venv/bin/python)
    - Exec(/home/iceroot/vulnavigator_web.py)
---

Start the VulNavigator web interface with live MITRE ATT&CK and D3FEND integration.

## VulNavigator Web Interface
The VulNavigator web interface provides an interactive UI for vulnerability analysis with enhanced threat intelligence from MITRE MCP servers.

## Starting the Web Interface
```bash
cd /home/iceroot
/home/iceroot/web_venv/bin/python vulnavigator_web.py
```

The interface will be available at:
- **Local**: http://localhost:5000
- **Network**: http://192.168.0.188:5000

## Web Interface Features
- **Interactive vulnerability analysis** through web UI
- **MITRE ATT&CK integration** via compliance-api MCP server
- **D3FEND countermeasures** with implementation guidance
- **CVE lookup** via OSV.dev using voraxx-mcp-server
- **Shodan exposure assessment** for network intelligence
- **Smart enhancement** based on vulnerability type
- **Real-time threat intelligence** from MITRE databases

## Usage
1. Open http://localhost:5000 in your browser
2. Enter findings as JSON, text, or CVE
3. Enable MITRE enhancement options:
   - 🚀 Enhance with MITRE data (ATT&CK + D3FEND)
   - 🔍 CVE lookup (OSV.dev)
   - 🌐 Shodan exposure (network intelligence)
4. Get enhanced reports with real threat intelligence

## Example Input
```json
{
  "title": "Log4Shell Vulnerability",
  "severity": "critical",
  "description": "Apache Log4j2 remote code execution vulnerability",
  "affected_component": "log4j-core",
  "cve": "CVE-2021-44228",
  "cvss_score": 10.0
}
```

## MCP Integration
The web interface uses MCP servers for enhanced threat intelligence:

### compliance-api MCP Server
- **MITRE ATT&CK v15.0**: Adversary Tactics, Techniques, and Procedures
- **MITRE D3FEND v1.1**: Cybersecurity Countermeasures Knowledge Graph
- **CWE Top 25**: Most Dangerous Software Weaknesses (2024)

### voraxx-mcp-server (Direct Integration)
- **CVE lookup**: OSV.dev vulnerability database
- **Shodan exposure**: InternetDB network reconnaissance
- **Nuclei scanning**: Template-based vulnerability detection

## Stopping the Web Interface
Press Ctrl+C in the terminal where the web interface is running, or use the terminal management to stop the process.

When the user wants to analyze vulnerabilities using the web interface, start the VulNavigator web server and provide the URL for access.