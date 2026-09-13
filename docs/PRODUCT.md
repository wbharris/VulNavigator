# VulNavigator™ product contract

End goal: a defender drops in a **Mythos** write-up, a **Daybreak** `findings.json`, a **narrative** ticket, or a scanner export and gets one 11-section case they can act on.

VulNavigator does **not** replace Mythos or Daybreak. It sits after them.

Repo: https://github.com/wbharris/VulNavigator

Blind-CVE training (separate from this product contract): [`TRAINING.md`](TRAINING.md).

**VulNavigator™** is a trademark of wbharris (common-law ™, not a registered ®). See [`TRADEMARK.md`](../TRADEMARK.md).

## User journey

```
Mythos | Daybreak | narrative | scanners / SARIF
                 │
                 ▼
           1. Normalize
                 │
                 ▼
           2. Validate
                 │
                 ▼
           3. Map
                 │
                 ▼
           4. 11-section report
      summary · evidence · validation · ATT&CK
      D3FEND · CSF · priority · remediation
      compensating controls · next actions
                 │
                 ▼
           5. Honesty layer
      confidence · assumptions · what would improve this
```

### 1. Normalize

Any supported input becomes one **case file**.

| Source | What we accept |
|--------|----------------|
| **Daybreak / Codex Security** | `documentType: codex-security.findings`, sealed scan directory, or one finding record |
| **Mythos** | Write-up JSON/markdown: title, target, CWE/bug class, **poc**, **discovery**, reproduced |
| **Narrative** | Free-text (ticket, email). Hints extracted: internet-facing, RCE (negation-aware), critical, no AI, no fraud, PoC/discovery sections. Also pulls tool name, finding id, host, endpoint, `file:line`, and component/version when present. A scanner *name* in prose sets `detected_tool` for detection-status; it does **not** relabel the source as Nessus/Qualys. |
| **Qualys** | VM XML (`QID` / `HOST` / `VULN`) or CSV with `QID` |
| **OpenVAS / GVM** | Greenbone XML `<report>` or CSV with NVT / OID |
| **Nessus** | `.nessus` or Tenable CSV. `--source nessus` also accepts `nexsus` |
| **Rapid7 InsightVM / Nexpose** | `NexposeReport` XML or InsightVM JSON (`resources` / `data`) |
| **SARIF** | v2.1 runs/results (CodeQL, Semgrep, GHAS, other SAST) |
| **Trivy / Snyk / Dependabot** | CI and GitHub SCA JSON |
| **Wiz / Prisma Cloud / Orca** | Cloud issue / alert JSON |
| **Microsoft Defender VM** | Graph-style `value[]` with `cveId` |
| **CrowdStrike Spotlight** | `resources[]` with `cve` + `host_info` |
| **AWS Inspector** | Inspector2 `findings[]` |
| **Nexus IQ** | `components[].securityData.securityIssues` |
| **Nuclei** | JSONL (`template-id`, `matched-at`) |
| **Burp / ZAP** | DAST XML |
| CVE only | Fallback: `CVE-YYYY-NNNNN` |

Unknown fields are kept on the case as `raw`.

### 2. Validate

Decide whether this is actionable — not whether it “sounds serious.”

| Check | Result |
|-------|--------|
| Identity | For **AI 0-days**: write-up + how it was found + PoC. CVE/NVD only when a CVE exists |
| CISA KEV / EPSS | Only when a CVE exists — **not expected** on new Mythos/Daybreak findings |
| Evidence quality | PoC / exploit / sandbox reproduction is the primary proof |
| Discovery | What the model traced (file, invariant, sanitizer) |
| Completeness | Component/version on *our* build so we can **replay the PoC** |

Statuses: `confirmed` · `plausible` · `unconfirmed` · `rejected`.

**Mythos and Daybreak 0-days will usually have no CVE.** That is normal. Do not wait for NVD. Judge the finding on the PoC and the discovery write-up.

| Finder gave you… | Status |
|------------------|--------|
| Sandbox / explicit `reproduced=true` | `confirmed` |
| Write-up + PoC text (no reproduction) | `plausible` — replay on our build |
| Scanner hit with CVE/CWE/location | `plausible` — detection, not exploit proof |
| CISA KEV (any product/version) | at most `plausible` — KEV is wild exploitation, not our build |
| Write-up + product, no CVE, no PoC | `unconfirmed` |
| Neither write-up nor PoC nor structured identity | `rejected` |

CISA KEV raises **priority/urgency**, not validation status. NVD description is enrichment, not identity. A PoC string is not reproduction.

Scanner hits (Qualys, Nessus, …) stay **detections**, not exploit proof. Unknown JSON is `generic`, not Mythos.

### 3. Map

Only after validation. Official catalogs first; the agent may only pick IDs that exist in the pinned knowledge bases.

| Overlay | When |
|---------|------|
| ATT&CK | Always (what an attacker can do with it) |
| D3FEND | Always (countermeasures on those techniques) |
| NIST CSF 2.0 | Always (leadership rollup) |
| ATLAS + AI RMF | Only if the asset is AI-in-scope |
| F3 (Fight Fraud Framework) | Only if payment / identity / ATO / mule risk is in play |
| CI Fortify | Only if tagged CI/OT (`--sector ics\|ot\|ci\|water\|energy\|…`, JSON `ot_in_scope`, or `--overlay fortify`). **Default off.** Isolation / recovery compensating controls — not a 12th section, not a CWE table. |
| NIST SSDF 1.2 | Software findings only. **Inferred on** for Mythos, Daybreak, SARIF, Trivy, Snyk, Dependabot. **Off** for host VM / OT / narrative unless `--overlay ssdf`. Practices used: `RV.1`, `RV.2`, `PS.4`, and `PW.8` on AI 0-days. Does **not** replace CSF. Force off with `--overlay no-ssdf` or `none`. |

Every mapped ID carries `provenance` and `confidence`. CI Fortify and SSDF IDs are canned overlays in `src/vulnavigator/overlays.py`, not rows in `mappings.json`. Overlay presence does **not** raise priority by itself (same rule as KEV: only when the path is real). Isolation is never a validation status.

CLI:

```bash
vuln-nav analyze scan.nessus --sector ics --offline
vuln-nav analyze examples/trivy-report.json --offline          # SSDF inferred
vuln-nav analyze examples/trivy-report.json --overlay no-ssdf  # SSDF off
vuln-nav analyze writeup.json --overlay fortify,ssdf
```

### 4. Report

Eleven sections (markdown) or `--json`:

1. Vulnerability summary  
2. Evidence — facts, **how the finder found it**, **PoC/exploit**, missing evidence  
3. Validation notes  
4. Likely attacker behaviors / ATT&CK (ATLAS / F3 / **CI Fortify** / **SSDF 1.2** only if tagged — still 11 sections)  
5. Defensive countermeasures (D3FEND)  
6. NIST CSF alignment (SSDF, if tagged, is a one-liner under CSF, not a replacement)  
7. Priority (`P1`–`P4`) and urgency (`immediate` / `this_week` / `30_days` / `backlog`)  
8. Recommended remediation (for 0-days: replay PoC, patch the described root cause — do not wait for a CVE; SSDF `RV`/`PS.4` when tagged)  
9. Compensating controls until the fix lands (**CI Fortify isolation/recovery** when OT-tagged)  
10. Next actions — owner and done-when (`ot-ops` when Fortify fires)  
11. Confidence, assumptions, uncertainty, what would improve the report (inferred overlay tags are called out here)  

Priority is not CVSS. Internet exposure, a replayable PoC, and whether the mapping unlocks RCE / credentials outweigh a naked 9.8 on an isolated lab box.

**`--offline`:** skips NVD / KEV / EPSS only. `case.kev`, `case.epss`, and `case.cvss` stay unset. Mapping tables are local (`src/vulnavigator/data/mappings.json`). Confidence values there (`confidence.cwe`, `narrative`, `overlay`, `default`) are ordinal, not calibrated probabilities. `map.py` reads those keys; it does not hardcode the scale.

**Live enrichment:** every CVE on the case is queried (cap 8). The case keeps **any KEV hit**, **max CVSS**, **max EPSS**, and the **union of NVD CWEs**. HTTP timeout is `--timeout` / `VULN_NAV_TIMEOUT` (default 12s). A batch of findings runs in parallel (`--workers` / `VULN_NAV_WORKERS`, default 4). Per-case CVE lookups stay sequential so batches do not nest thread pools. CISA KEV is cached in-process (`VULN_NAV_KEV_TTL` seconds, default 3600). Re-running `analyze_case` clears prior KEV/EPSS/CVSS/NVD text before enrich. Logging is stdlib (`VULN_NAV_LOG=json`, `--log-level`).

**SARIF:** parsed as SARIF. A SARIF-shaped result is not rewritten as a Daybreak finding even if `--source daybreak` was passed.

CI is [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (pytest, mypy, training preflight). Runtime stays zero third-party dependencies; mypy is a `dev` extra.

**Data quality** (0–100) is printed on the report: more gaps and assumptions lower the score. Use it to see which cases need more evidence.

### 5. Assumptions and “make this report better”

The agent must never hide a guess.

For AI 0-days the useful questions are:

- What is the **PoC** (commands, request, crash, sandbox log)?
- Can we **replay it on our build** (same file, commit, or image)?
- How did the model **find** it (path, invariant, sanitizer)?
- Is the service internet-facing?
- What data does it touch?
- Is this an AI host or a payment/ATO path?

A missing CVE is **not** the main gap on Mythos/Daybreak. If those answers arrive later, re-run the same case; mappings and priority can change.

## What success looks like

Simulation (every bundled example, offline):

```bash
python3 tests/simulate_intake.py
```

Writes `tests/last-results.html`. Scanner detections with a CVE/CWE/location must be `plausible`. AI 0-days with a PoC must be `plausible` or `confirmed`. A narrative with no PoC stays `unconfirmed`.

A user drops `examples/mythos-zeroday.json` (no CVE) or `examples/narrative-rce.txt` and can answer:

1. Is this real enough to work? (PoC / write-up, not NVD)
2. What could an attacker do with it?
3. What do we do this week vs later?
4. What can we put in front of it until the patch ships?
5. What did the agent guess, and what should I go find out?

## Out of scope for this package

This repository ships `vuln-nav` and the 11-section case. It does **not** ship:

- a web UI
- live MITRE ATT&CK / D3FEND / CWE MCP
- OSV.dev, Shodan, or Nuclei lookups

Optional Devin skill files under [`.devin/skills/`](../.devin/skills/) only document how an agent should run `vuln-nav` (or start a local Flask UI if the operator already has one). Mapping tables stay in `src/vulnavigator/data/mappings.json`. Priority is not CVSS; KEV/EPSS/CVSS apply only when a CVE exists and `--offline` was not used.
