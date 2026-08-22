---
name: vulnavigator-web
description: Start a local out-of-tree VulNavigator Flask UI if the operator already has one.
argument-hint: ""
allowed-tools:
  - exec
  - read
permissions:
  allow:
    - Exec(python)
    - Exec(python3)
---

Start a **local** Flask UI for VulNavigator only if the operator already has that script. It is **not** shipped in this git repository.

## What this skill is not

- Not live MITRE ATT&CK / D3FEND MCP
- Not a substitute for `vuln-nav` (use the `vulnavigator` skill for analysis)
- Not a public service. Bind to `127.0.0.1`. Do not print LAN IPs from the machine.

The core CLI maps ATT&CK/D3FEND from `src/vulnavigator/data/mappings.json`. The local UI may append OSV.dev / Shodan InternetDB results. It does not query MITRE MCP.

## Locate the UI

Search in this order; stop at the first file that exists:

1. `$VULNAVIGATOR_WEB` if set
2. `vulnavigator_web.py` in the current workspace
3. `~/vulnavigator_web.py`

If none exist, stop. Tell the user the Flask UI is out of tree and they should use `vuln-nav analyze` instead. Do not invent a path.

Use that script’s interpreter if a sibling `web_venv` exists; otherwise `python3`. Example:

```bash
python3 vulnavigator_web.py
```

Prefer `--host 127.0.0.1 --port 5000` when the script accepts those flags. Otherwise assume `http://127.0.0.1:5000`.

## Optional lookups (if the local UI implements them)

A local UI may call `voraxx-mcp-server` for:

- CVE lookup via OSV.dev
- host exposure via Shodan InternetDB

Do not advertise Nuclei; the local UI does not run it.

## Usage to tell the user

1. Open `http://127.0.0.1:5000`
2. Paste JSON, narrative, or a CVE
3. Read the 11-section `vuln-nav` case first. Optional lookup sections are labeled separately.
