"""Priority, urgency, actions, assumptions, and information gaps."""

from __future__ import annotations

from vulnavigator.models import Action, Assumption, Case, InfoNeed


def _assume(case: Case, field: str, assumed: str, because: str, impact: str) -> None:
    case.assumptions.append(
        Assumption(field=field, assumed=assumed, because=because, impact=impact)
    )


def _need(case: Case, question: str, why: str, change: str) -> None:
    case.improve.append(InfoNeed(question=question, why_it_matters=why, would_change=change))


def record_assumptions(case: Case) -> Case:
    if case.asset_internet_facing is None:
        _assume(
            case,
            "internet_facing",
            "no",
            "Finding did not say whether the component is reachable from the internet",
            "If it is exposed, urgency should usually rise one band",
        )
        _need(
            case,
            "Is this service internet-facing or reachable from an untrusted network?",
            "Exposure is the biggest swing factor after KEV / validated exploit",
            "Priority and urgency",
        )
    if case.asset_ai_system is None:
        _assume(
            case,
            "ai_system",
            "no",
            "No AI/model/RAG/agent tag on the finding — ATLAS and AI RMF left off",
            "If this hosts a model or agent, ATLAS/AI RMF overlays should fire",
        )
        _need(
            case,
            "Does this asset host a model, RAG index, training pipeline, or tool-calling agent?",
            "AI overlays stay dark unless we know this",
            "ATLAS / AI RMF sections",
        )
    if case.asset_fraud_relevant is None:
        _assume(
            case,
            "fraud_relevant",
            "no",
            "No payment / identity / ATO context — F3 left off",
            "A payment or login path would add F3 techniques and a fraud owner",
        )
        _need(
            case,
            "Does this sit on a payment, identity, or account-takeover path?",
            "Fraud teams need a different owner and SLA than a generic host vuln",
            "F3 overlay and next-action owners",
        )
    if not case.product:
        _assume(
            case,
            "product",
            "unknown",
            "No product / package name in the finding",
            "Cannot confirm we actually run the affected build",
        )
        _need(
            case,
            "What product, package, and deployed version do we run?",
            "A finding against software we do not ship is not our P1",
            "Validation status and priority",
        )
    if not case.version:
        _need(
            case,
            "Which exact version / commit / image digest is in production?",
            "Daybreak and Mythos findings are often against a tree, not our build",
            "Whether remediation is 'patch now' vs 'not applicable'",
        )
    if not case.evidence.poc and not case.evidence.reproduced and not case.evidence.sandbox:
        _need(
            case,
            "Is the finding directly exploitable in this deployment (reachable path, no WAF/virtual patch)?",
            "Without exploitability evidence this may be a false positive or an unreachable path",
            "Validation status (plausible → confirmed) and urgency",
        )
    if not case.data_class:
        _need(
            case,
            "What data does this component touch (none / internal / PII / payment)?",
            "Data class changes CSF language and legal/fraud involvement",
            "Priority rationale and owners",
        )
    if not case.cves:
        _need(
            case,
            "Has a CVE been assigned, or is disclosure still private?",
            "Without a CVE we cannot pull KEV/EPSS/NVD and must trust the finder",
            "Enrichment and priority",
        )
    return case


def prioritize(case: Case) -> Case:
    reasons: list[str] = []
    internet = bool(case.asset_internet_facing)
    high_path = any(m.id.split(".")[0] in {"T1068", "T1078", "T1059", "T1552"} for m in case.attack)

    if case.validation_status == "rejected":
        case.priority = "P4"
        case.urgency = "backlog"
        case.priority_reasons = ["Finding rejected — do not treat as a vuln"]
        return case

    score = 0
    if case.kev:
        score += 5
        reasons.append("CISA KEV (known exploited)")
    if case.epss is not None and case.epss >= 0.5:
        score += 3
        reasons.append(f"High EPSS ({case.epss:.2f})")
    elif case.epss is not None and case.epss >= 0.1:
        score += 1
        reasons.append(f"Elevated EPSS ({case.epss:.2f})")
    if case.cvss is not None and case.cvss >= 9.0:
        score += 2
        reasons.append(f"CVSS {case.cvss} critical")
    elif case.cvss is not None and case.cvss >= 7.0:
        score += 1
        reasons.append(f"CVSS {case.cvss} high")
    if case.source_severity.lower() in {"critical", "high"}:
        score += 1
        reasons.append(f"Finder severity={case.source_severity}")
    if case.evidence.reproduced or case.evidence.sandbox:
        score += 2
        reasons.append("Finder reproduced / sandbox-validated")
    if internet:
        score += 2
        reasons.append("Asset is internet-facing")
    if high_path:
        score += 1
        reasons.append("Mapping unlocks privilege, credentials, or code execution")
    if case.data_class:
        score += 1
        reasons.append(f"Data class: {case.data_class}")
    rce = any(m.id.split(".")[0] in {"T1190", "T1059", "T1203"} for m in case.attack)
    if internet and rce and case.source_severity.lower() == "critical":
        score += 2
        reasons.append("Internet-facing + possible RCE + scanner critical (exploitability still unconfirmed)")
    if case.validation_status == "unconfirmed" and not (internet and rce):
        score -= 2
        reasons.append("Validation is unconfirmed — do not over-rank")
    elif case.validation_status == "unconfirmed":
        reasons.append("Exploitability is unconfirmed — treat as highest-priority *validation*, not a confirmed breach")

    if score >= 7:
        case.priority, case.urgency = "P1", "immediate"
    elif score >= 4:
        case.priority, case.urgency = "P2", "this_week"
    elif score >= 2:
        case.priority, case.urgency = "P3", "30_days"
    else:
        case.priority, case.urgency = "P4", "backlog"

    case.priority_reasons = reasons or ["Default: limited signal"]
    if case.validation_status == "unconfirmed" and not case.cves:
        case.confidence = case.confidence or "medium"
    elif case.validation_status == "confirmed" or case.kev:
        case.confidence = case.confidence or "high"
    else:
        case.confidence = case.confidence or "medium"
    return case


def plan_actions(case: Case) -> Case:
    if case.validation_status == "rejected":
        case.next_actions = [
            Action("Close as not a vulnerability", "security", "Ticket notes why it was rejected")
        ]
        return case

    if not case.remediation:
        if case.cves:
            case.remediation.append(
                f"Apply the vendor / distro fix for {', '.join(case.cves)} and verify the package version"
            )
        else:
            case.remediation.extend(
                [
                    "Identify the exact component, version, and affected systems",
                    "Confirm vendor advisory / CVE applicability",
                    "Patch or upgrade to a non-vulnerable version",
                    "If patching cannot be immediate: remove public access if feasible, restrict source IPs, enforce WAF/edge filtering, disable the vulnerable path if supported",
                    "Rescan and review logs for exploitation attempts before and after the fix",
                ]
            )

    for ctrl in case.d3fend:
        case.compensating_controls.append(f"{ctrl.id} {ctrl.name} — until the fix is deployed")

    actions = [
        Action(
            "Confirm we run the affected product/version",
            "asset-owner",
            "Inventory shows version or 'not present'",
        ),
        Action(
            "Reproduce or review finder evidence on our build",
            "security",
            "Confirmed, plausible-unreachable, or false positive",
        ),
        Action(
            "Apply primary remediation and verify",
            "engineering",
            "Patched build deployed or change rejected with reason",
        ),
    ]
    if case.compensating_controls:
        actions.insert(
            2,
            Action(
                "Enable compensating controls if the patch cannot ship inside the urgency window",
                "security",
                "Control in place or accepted residual risk signed",
            ),
        )
    if case.asset_ai_system:
        actions.append(
            Action(
                "Review ATLAS path and AI RMF Measure/Manage owners",
                "ml-security",
                "AI-specific detections or evals queued",
            )
        )
    if case.asset_fraud_relevant:
        actions.append(
            Action(
                "Notify fraud / identity of the F3-relevant path",
                "fraud",
                "Fraud queue has the case and monitoring is on",
            )
        )
    case.next_actions = actions
    return case
