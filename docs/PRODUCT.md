# VulNavigator product contract

End goal: a defender drops in a **Mythos** (Anthropic) write-up or a **Daybreak** (OpenAI Codex Security) `findings.json` / scan directory and gets one case they can act on.

**Mythos** and **Daybreak** are the AI-finder path. **Qualys**, **OpenVAS**, and **Nessus** are the scanner path. CVE-only is a fallback.

VulNavigator does **not** replace Mythos or Daybreak. It sits after them. Findings without triage, mapping, and an honest “what we assumed” section are noise.

## User journey

```
Mythos | Daybreak | scanners (Qualys, Nessus, Rapid7, Wiz, Trivy, SARIF, …)
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
           4. Report
      priority · urgency · remediation
      compensating controls · next actions
                 │
                 ▼
           5. Honesty layer
      assumptions · what would improve this report
```

### 1. Normalize

Any supported input becomes one **case file**: identity, affected product, evidence, source severity, and whatever asset context was given.

Adapters (v1):

| Source | What we accept |
|--------|----------------|
| **Daybreak / Codex Security** | Official `documentType: codex-security.findings` (`findings.json`), a sealed scan directory, SARIF, or a single finding record |
| **Mythos** | Write-up JSON/markdown: title, target/project, CWE/bug class, PoC, reproduced / triage flags |
| **Qualys** | VM XML (`QID` / `HOST` / `VULN`) or CSV with a `QID` column |
| **OpenVAS / GVM** | Greenbone XML `<report>` or CSV with NVT / OID |
| **Nessus** | `.nessus` or Tenable CSV. `--source nessus` also accepts `nexsus` |
| **Rapid7 InsightVM / Nexpose** | `NexposeReport` XML |
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

Unknown fields are kept on the case as `raw` so nothing is silently dropped.

### 2. Validate

Decide whether this is a real, actionable finding — not whether it “sounds serious.”

| Check | Result |
|-------|--------|
| Identity | CVE/NVD **or** (for Mythos/Daybreak 0-days) write-up + how it was found + PoC |
| CISA KEV / EPSS | Only when a CVE exists — not expected on new AI 0-days |
| Evidence quality | PoC / exploit / sandbox reproduction is the primary proof |
| Discovery | What the model traced (file, invariant, sanitizer) |
| Completeness | Component/version on *our* build so we can replay the PoC |

Statuses: `confirmed` · `plausible` · `unconfirmed` · `rejected`.

**Mythos and Daybreak 0-days will usually have no CVE.** That is normal. Do not wait for NVD. Judge the finding on the PoC and the discovery write-up. A sandbox-reproduced Daybreak finding with no CVE is `confirmed` or `plausible`. A narrative with no PoC stays `unconfirmed`.

### 3. Map

Only after validation. Official catalogs first; the agent may only pick IDs that exist in the pinned knowledge bases.

| Overlay | When |
|---------|------|
| ATT&CK | Always (what an attacker can do with it) |
| D3FEND | Always (countermeasures on those techniques) |
| NIST CSF 2.0 | Always (leadership rollup) |
| ATLAS + AI RMF | Only if the asset is AI-in-scope |
| F3 (Fight Fraud Framework) | Only if payment / identity / ATO / mule risk is in play |

Every mapped ID carries `provenance` (`ctid-kev`, `cwe-heuristic`, `nvd-cwe`, `model-inferred`) and `confidence`.

### 4. Report (the thing the user keeps)

| Field | Meaning |
|-------|---------|
| **Priority** | `P1`–`P4` — how bad *here*, not just CVSS |
| **Urgency** | `immediate` (24h) · `this_week` · `30_days` · `backlog` |
| **Remediation** | Patch, upgrade, config, or code change — vendor/Daybreak patch first |
| **Compensating controls** | D3FEND (and CSF) you can apply *until* the fix lands |
| **Next actions** | Ordered human work: owner, artifact, done-when |

Priority is not CVSS. KEV, validated exploitability, internet exposure, and whether the mapping unlocks credential access or privilege escalation outweigh a naked 9.8 on an isolated lab box.

### 5. Assumptions and “make this report better”

The agent must never hide a guess.

**Assumptions** — defaults it used because the finding did not say. Example: “internet-facing: assumed **no** (not stated).”

**What would improve this report** — concrete missing facts, ranked by how much they would change priority or mapping:

- Is the service internet-facing?
- What identity / data does it touch?
- Is this an AI/model/RAG/agent host?
- Is there a payment or account-takeover path?
- Which build/version is actually deployed?
- Was the Daybreak/Mythos PoC reproduced on *our* build?

If those answers arrive later, the same case is re-run; mappings and priority can change.

## What success looks like

A user drops `daybreak-finding.json` or `mythos-finding.md` and, without another tool, can answer:

1. Is this real enough to work?
2. What could an attacker do with it (ATT&CK / ATLAS)?
3. What do we do this week vs later?
4. What can we put in front of it until the patch ships?
5. What did the agent guess, and what should I go find out?
