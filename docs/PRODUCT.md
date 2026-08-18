# VulNavigator product contract

End goal: a defender pastes or uploads a **Mythos** (Anthropic) or **Daybreak** (OpenAI / Codex Security) finding — or a CVE / advisory / scanner export — and gets one case they can act on.

VulNavigator does **not** replace those finders. It sits after them. Findings without triage, mapping, and an honest “what we assumed” section are noise.

## User journey

```
Mythos | Daybreak | CVE | advisory | scanner JSON
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
| Daybreak / Codex Security | JSON report: title, severity, locations, validation evidence, suggested patch |
| Mythos | JSON / markdown-ish finding: target, description, PoC, reproduced yes/no |
| CVE only | `CVE-YYYY-NNNNN` |
| Generic | Same schema fields under any vendor name |

Unknown fields are kept on the case as `raw` so nothing is silently dropped.

### 2. Validate

Decide whether this is a real, actionable finding — not whether it “sounds serious.”

| Check | Result |
|-------|--------|
| Identity resolves (NVD / CVE.org) | confirmed identity or still a 0-day claim |
| CISA KEV | exploited in the wild |
| EPSS | exploitation probability |
| Evidence quality | sandbox/PoC/reproduced vs description-only |
| Internal consistency | severity vs CWE vs claimed impact |
| Completeness | required fields present |

Statuses: `confirmed` · `plausible` · `unconfirmed` · `rejected`.

A Daybreak “reproduced in sandbox” finding with no CVE can still be `plausible`. A Mythos write-up with no product, no evidence, and a contradictory CWE is `unconfirmed` or `rejected`.

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
