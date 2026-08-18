# VulNavigator™ product contract

End goal: a defender drops in a **Mythos** write-up, a **Daybreak** `findings.json`, a **narrative** ticket, or a scanner export and gets one 11-section case they can act on.

VulNavigator does **not** replace Mythos or Daybreak. It sits after them.

Repo: https://github.com/wbharris/VulNavigator

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
| **Narrative** | Free-text (ticket, email). Hints extracted: internet-facing, RCE, critical, no AI, no fraud, PoC/discovery sections |
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
| Write-up + PoC / sandbox | `plausible` or `confirmed` — replay on our build |
| Write-up only | `unconfirmed` — ask for the PoC first |
| Neither write-up nor PoC | `rejected` |

Scanner hits (Qualys, Nessus, …) stay **detections**, not exploit proof.

### 3. Map

Only after validation. Official catalogs first; the agent may only pick IDs that exist in the pinned knowledge bases.

| Overlay | When |
|---------|------|
| ATT&CK | Always (what an attacker can do with it) |
| D3FEND | Always (countermeasures on those techniques) |
| NIST CSF 2.0 | Always (leadership rollup) |
| ATLAS + AI RMF | Only if the asset is AI-in-scope |
| F3 (Fight Fraud Framework) | Only if payment / identity / ATO / mule risk is in play |

Every mapped ID carries `provenance` and `confidence`.

### 4. Report

Eleven sections (markdown) or `--json`:

1. Vulnerability summary  
2. Evidence — facts, **how the finder found it**, **PoC/exploit**, missing evidence  
3. Validation notes  
4. Likely attacker behaviors / ATT&CK (ATLAS / F3 only if tagged)  
5. Defensive countermeasures (D3FEND)  
6. NIST CSF alignment  
7. Priority (`P1`–`P4`) and urgency (`immediate` / `this_week` / `30_days` / `backlog`)  
8. Recommended remediation (for 0-days: replay PoC, patch the described root cause — do not wait for a CVE)  
9. Compensating controls until the fix lands  
10. Next actions — owner and done-when  
11. Confidence, assumptions, uncertainty, what would improve the report  

Priority is not CVSS. Internet exposure, a replayable PoC, and whether the mapping unlocks RCE / credentials outweigh a naked 9.8 on an isolated lab box.

**`--offline`:** skips NVD / KEV / EPSS only. `case.kev`, `case.epss`, and `case.cvss` stay unset. Mapping tables are local (`src/vulnavigator/data/mappings.json`). Confidence values there are ordinal (0.62 CWE, 0.55 narrative RCE, 0.40 location-only), not calibrated probabilities.

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
