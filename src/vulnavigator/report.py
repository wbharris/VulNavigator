"""Render a case as the 11-section defender report, or as JSON."""

from __future__ import annotations

import json

from vulnavigator.models import Case, is_ai_zeroday


def _bullets(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items] if items else ["- none"]


def _facts(case: Case) -> list[str]:
    facts: list[str] = []
    if "outdated" in f"{case.title} {case.description}".lower():
        facts.append("Component is described as outdated")
    if case.asset_internet_facing is True:
        facts.append("Component is internet-facing / client-facing")
    if any(m.id.split(".")[0] in {"T1190", "T1059", "T1203"} for m in case.attack):
        facts.append("Scanner or write-up indicates possible remote code execution")
    if case.data_class:
        facts.append(f"Application processes {case.data_class.replace('-', ' ')} data")
    if case.evidence.reproduced is False or (
        not case.evidence.reproduced and not case.evidence.sandbox and not case.evidence.poc
    ):
        facts.append("No evidence of successful exploitation was provided")
    if case.asset_ai_system is False:
        facts.append("No AI-specific concern indicated")
    if case.asset_fraud_relevant is False:
        facts.append("Fraud risk is not currently suspected")
    if case.source_severity:
        facts.append(f"Finder/scanner rated the finding {case.source_severity}")
    if case.evidence.poc.strip():
        facts.append("PoC / exploit steps were provided (primary evidence for an AI 0-day)")
    if case.evidence.discovery.strip():
        facts.append("Finder described how the vulnerability was discovered")
    if case.cves:
        facts.append("CVE(s): " + ", ".join(case.cves))
    elif is_ai_zeroday(case):
        facts.append("No CVE — expected for a Mythos/Daybreak 0-day")
    return facts or ["Writer provided a narrative with limited structured fields"]


def to_markdown(case: Case) -> str:
    attack_names = [f"`{m.id}` {m.name}" for m in case.attack]
    d3 = [f"`{m.id}` {m.name}" for m in case.d3fend]
    csf = [f"`{m.id}` {m.name}" for m in case.csf]
    overlay = []
    if case.atlas:
        overlay.append("ATLAS: " + ", ".join(f"`{m.id}` {m.name}" for m in case.atlas))
    if case.airmf:
        overlay.append("AI RMF: " + ", ".join(f"`{m.id}`" for m in case.airmf))
    if case.f3:
        overlay.append("F3: " + ", ".join(f"`{m.id}` {m.name}" for m in case.f3))

    prio_label = {
        "P1": "Critical / highest priority to remediate",
        "P2": "High — remediate this week",
        "P3": "Medium — schedule within 30 days",
        "P4": "Low / backlog",
    }.get(case.priority, case.priority)

    missing = [i.question for i in case.improve]
    if is_ai_zeroday(case) and not case.evidence.poc.strip():
        if not any("PoC" in q or "poc" in q.lower() for q in missing):
            missing.insert(0, "PoC or exploit the finder used (commands, request, crash, sandbox log)")

    rem = case.remediation or ["Identify the component and apply the vendor fix"]
    comp = case.compensating_controls or [
        "Temporary network segmentation / remove public access if feasible",
        "Firewall allowlisting and WAF or edge filtering (virtual patch)",
        "Enhanced logging and alerting on the exposed service",
        "Tightened service-account permissions",
        "Backup and recovery readiness",
    ]

    lines = [
        f"# {case.title}",
        "",
        f"*VulNavigator™* · *Source:* {case.source_kind}"
        + (f" `{case.finding_id}`" if case.finding_id else "")
        + f" · *Validation:* {case.validation_status}"
        + f" · *Confidence:* {case.confidence or 'medium'}",
        "",
        "## 1. Vulnerability Summary",
        "",
        f"**Finding:** {case.title}.",
        f"**Context:** {case.description.strip() or 'No additional write-up.'}",
        (
            f"**Current status:** Exploitability is {case.validation_status}. "
            f"Scanner/finder severity: {case.source_severity or 'not stated'}. "
            + (
                "Finder provided a PoC, exploit, or sandbox reproduction. "
                if (case.evidence.reproduced or case.evidence.sandbox or case.evidence.poc.strip())
                else "No PoC or exploit was attached. "
            )
        ),
        "",
        "## 2. Evidence Summary",
        "",
        "**Facts provided:**",
    ]
    lines.extend(_bullets(_facts(case)))
    if case.evidence.discovery.strip():
        lines += ["", "**How the finder found it:**", "", case.evidence.discovery.strip()]
    if case.evidence.poc.strip():
        lines += ["", "**PoC / exploit:**", "", case.evidence.poc.strip()]
    lines += ["", "**Missing evidence:**"]
    lines.extend(_bullets(missing))
    lines += ["", "## 3. Validation Notes", ""]
    lines.extend(_bullets(case.validation_notes))
    lines += [
        "",
        "Validation should confirm:",
        "- Replay the finder PoC on our deployed build (same file/commit/image)",
        "- The exact software/component and version the write-up names",
        "- Whether the vulnerable code path is reachable in our deployment",
        "- Whether mitigations exist (WAF, config restrictions, network controls)",
    ]
    if not is_ai_zeroday(case):
        lines.append("- Whether a known advisory/CVE applies")
    lines += [
        "",
        "## 4. Likely Attacker Behaviors / Technique Mapping",
        "",
        "Likely behaviors if exploitable:",
        "- Remote code execution against the exposed application component",
        "- Initial access through the internet-facing service",
        "- Follow-on actions such as credential theft, lateral movement, or data access",
        "",
        "**Tentative technique mapping (ATT&CK):**",
    ]
    lines.extend(_bullets(attack_names or ["Insufficient identity to map beyond a generic public-app exploit"]))
    if overlay:
        lines += ["", "**Overlays:**"]
        lines.extend(_bullets(overlay))
    else:
        lines += ["", "ATLAS / AI RMF / F3: not in scope based on the write-up."]
    lines += [
        "",
        "## 5. Defensive Countermeasures",
        "",
    ]
    if d3:
        lines.extend(_bullets(d3))
    else:
        lines.extend(
            [
                "- Restrict public exposure where possible",
                "- Apply vendor patch or upgrade to a fixed version",
                "- Add compensating network controls until remediation is complete",
                "- Monitor for abnormal requests, process launches, and web-server anomalies",
                "- Review logs for exploitation attempts",
                "- Validate least-privilege service permissions",
            ]
        )
    lines += [
        "",
        "## 6. NIST CSF Alignment",
        "",
        "Relevant functions and categories:",
        "- **Identify:** Asset and software inventory (`ID` / `GV.OC`)",
        "- **Protect:** Vulnerability management, secure configuration, access control (`PR.IR`, `PR.PS`, `PR.AA`)",
        "- **Detect:** Security monitoring and log analysis (`DE.CM`)",
        "- **Respond:** Triage and containment (`RS.MI`)",
        "- **Recover:** Restoration and validation after remediation",
    ]
    if csf:
        lines += ["", "Mapped categories from this case:"]
        lines.extend(_bullets(csf))
    lines += [
        "",
        "## 7. Priority Assessment",
        "",
        f"**Priority:** {case.priority} — {prio_label}",
        f"**Urgency:** {case.urgency}",
        "",
        "**Rationale:**",
    ]
    lines.extend(_bullets(case.priority_reasons))
    lines += ["", "## 8. Recommended Remediation", ""]
    lines.extend(_bullets(rem))
    lines += ["", "## 9. Compensating Controls", "", "If immediate patching is not possible:"]
    lines.extend(_bullets(comp))
    lines += ["", "## 10. Next Actions", ""]
    if case.next_actions:
        for a in case.next_actions:
            extra = f" — done when: {a.done_when}" if a.done_when else ""
            lines.append(f"- **{a.owner}:** {a.action}{extra}")
    else:
        lines.extend(
            [
                "- Obtain component name/version and host inventory",
                "- Map to known CVEs/advisories",
                "- Verify whether the exposure is truly internet reachable",
                "- Check logs for exploit attempts",
                "- Patch/upgrade and rescan",
                "- Escalate incident response if any compromise indicators are found",
            ]
        )
    lines += [
        "",
        "## 11. Confidence and Assumptions",
        "",
        f"**Confidence:** {case.confidence or 'medium'}",
        "",
        "**Assumptions:**",
    ]
    if case.assumptions:
        for a in case.assumptions:
            lines.append(f"- **{a.field}** = `{a.assumed}` because {a.because}. Impact: {a.impact}")
    else:
        lines.append("- The scanner critical rating reflects a real issue in a reachable component.")
        lines.append("- The component may be exploitable in the deployed configuration (not yet proven).")
    lines += [
        "",
        "**Uncertainty:**",
        "- Exploitability, exact vulnerability identity, and affected scope remain unconfirmed from the provided evidence.",
        "",
        "**Information that would make this report better:**",
    ]
    if case.improve:
        for i in case.improve:
            lines.append(f"- {i.question} — {i.why_it_matters} (changes: {i.would_change})")
    else:
        lines.append("- nothing material; re-run when the PoC is replayed on our build")
    lines.append("")
    return "\n".join(lines)


def to_json(case: Case) -> str:
    return json.dumps(case.to_dict(), indent=2, default=str) + "\n"
