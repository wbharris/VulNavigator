"""Map a validated case onto ATT&CK, D3FEND, CSF, and optional overlays."""

from __future__ import annotations

from vulnavigator.models import Case, Mapping

# Curated CWE → ATT&CK. Provenance is heuristic, not CTID KEV.
CWE_ATTACK: dict[str, list[tuple[str, str, str]]] = {
    "CWE-78": [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
    "CWE-79": [("T1189", "Drive-by Compromise"), ("T1059.007", "JavaScript")],
    "CWE-89": [("T1190", "Exploit Public-Facing Application"), ("T1505", "Server Software Component")],
    "CWE-94": [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
    "CWE-119": [("T1203", "Exploitation for Client Execution"), ("T1068", "Exploitation for Privilege Escalation")],
    "CWE-121": [("T1203", "Exploitation for Client Execution"), ("T1068", "Exploitation for Privilege Escalation")],
    "CWE-400": [("T1499", "Endpoint Denial of Service"), ("T1190", "Exploit Public-Facing Application")],
    "CWE-125": [("T1203", "Exploitation for Client Execution")],
    "CWE-200": [("T1005", "Data from Local System")],
    "CWE-22": [("T1083", "File and Directory Discovery"), ("T1190", "Exploit Public-Facing Application")],
    "CWE-269": [("T1068", "Exploitation for Privilege Escalation")],
    "CWE-287": [("T1078", "Valid Accounts"), ("T1190", "Exploit Public-Facing Application")],
    "CWE-306": [("T1078", "Valid Accounts"), ("T1190", "Exploit Public-Facing Application")],
    "CWE-416": [("T1203", "Exploitation for Client Execution")],
    "CWE-434": [("T1190", "Exploit Public-Facing Application"), ("T1505.003", "Web Shell")],
    "CWE-502": [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
    "CWE-611": [("T1190", "Exploit Public-Facing Application")],
    "CWE-787": [("T1203", "Exploitation for Client Execution"), ("T1068", "Exploitation for Privilege Escalation")],
    "CWE-798": [("T1078", "Valid Accounts"), ("T1552", "Unsecured Credentials")],
    "CWE-918": [("T1090", "Proxy"), ("T1190", "Exploit Public-Facing Application")],
}

ATTACK_D3FEND: dict[str, list[tuple[str, str]]] = {
    "T1005": [("D3-DENCR", "Disk Encryption"), ("D3-NTA", "Network Traffic Analysis")],
    "T1059": [("D3-EAL", "Executable Allowlisting"), ("D3-PSA", "Process Spawn Analysis")],
    "T1068": [("D3-LFP", "Local File Permissions"), ("D3-SUCP", "System Unprivileged Configuration")],
    "T1078": [("D3-MFA", "Multi-factor Authentication"), ("D3-UAP", "User Account Permissions")],
    "T1083": [("D3-LFP", "Local File Permissions"), ("D3-NTA", "Network Traffic Analysis")],
    "T1090": [("D3-NTA", "Network Traffic Analysis"), ("D3-ITF", "Inbound Traffic Filtering")],
    "T1189": [("D3-ITF", "Inbound Traffic Filtering"), ("D3-UA", "URL Analysis")],
    "T1190": [("D3-ITF", "Inbound Traffic Filtering"), ("D3-NTA", "Network Traffic Analysis"), ("D3-IAVA", "Inbound Application Versioning")],
    "T1499": [("D3-ITF", "Inbound Traffic Filtering"), ("D3-NTA", "Network Traffic Analysis")],
    "T1203": [("D3-SAOR", "Segment Address Offset Randomization"), ("D3-AH", "Application Hardening")],
    "T1505": [("D3-ITF", "Inbound Traffic Filtering"), ("D3-NTA", "Network Traffic Analysis")],
    "T1552": [("D3-CRO", "Credential Rotation"), ("D3-MFA", "Multi-factor Authentication")],
}

ATTACK_CSF: dict[str, list[tuple[str, str]]] = {
    "T1005": [("PR.DS", "Data Security"), ("DE.CM", "Continuous Monitoring")],
    "T1059": [("PR.PS", "Platform Security"), ("DE.CM", "Continuous Monitoring")],
    "T1068": [("PR.AA", "Identity Management and Access Control"), ("PR.PS", "Platform Security")],
    "T1078": [("PR.AA", "Identity Management and Access Control"), ("DE.CM", "Continuous Monitoring")],
    "T1083": [("PR.DS", "Data Security"), ("DE.CM", "Continuous Monitoring")],
    "T1090": [("PR.IR", "Technology Infrastructure Resilience"), ("DE.CM", "Continuous Monitoring")],
    "T1189": [("PR.IR", "Technology Infrastructure Resilience"), ("DE.CM", "Continuous Monitoring")],
    "T1190": [("PR.IR", "Technology Infrastructure Resilience"), ("DE.CM", "Continuous Monitoring"), ("GV.OC", "Organizational Context")],
    "T1499": [("PR.IR", "Technology Infrastructure Resilience"), ("RS.MI", "Incident Mitigation")],
    "T1203": [("PR.PS", "Platform Security"), ("RS.MI", "Incident Mitigation")],
    "T1505": [("PR.PS", "Platform Security"), ("DE.CM", "Continuous Monitoring")],
    "T1552": [("PR.AA", "Identity Management and Access Control"), ("PR.DS", "Data Security")],
}

# Narrow ATLAS / F3 overlays — only when gated on.
AI_CWE_ATLAS: dict[str, list[tuple[str, str]]] = {
    "CWE-94": [("AML.T0051", "LLM Prompt Injection")],
    "CWE-502": [("AML.T0010", "AI Supply Chain Compromise")],
    "CWE-918": [("AML.T0053", "AI Agent Tool Invocation")],
    "CWE-200": [("AML.T0057", "LLM Data Leakage")],
    "CWE-798": [("AML.T0055", "Unsecured Credentials")],
}

FRAUD_ATTACK_F3: dict[str, list[tuple[str, str]]] = {
    "T1078": [("F3-ATO", "Account takeover via valid credentials")],
    "T1552": [("F3-CRED", "Abuse of exposed or reused credentials")],
    "T1190": [("F3-APP", "Fraud against a public application / payment path")],
}


def _add_unique(dest: list[Mapping], item: Mapping) -> None:
    if any(m.id == item.id and m.framework == item.framework for m in dest):
        return
    dest.append(item)


def map_case(case: Case) -> Case:
    if case.validation_status == "rejected":
        return case

    for cwe in case.cwes:
        for tid, name in CWE_ATTACK.get(cwe, []):
            _add_unique(
                case.attack,
                Mapping(
                    id=tid,
                    name=name,
                    framework="ATT&CK",
                    provenance="cwe-heuristic",
                    confidence=0.62,
                    rationale=f"{cwe} commonly enables {tid}",
                ),
            )

    # No CWE: still give a conservative public-app / client-exec guess when the
    # write-up is about a remotely reachable component.
    blob = f"{case.title} {case.description}".lower()
    if not case.attack and (
        "remote code execution" in blob or " rce " in blob or "remote cade execution" in blob
    ):
        _add_unique(
            case.attack,
            Mapping(
                id="T1190",
                name="Exploit Public-Facing Application",
                framework="ATT&CK",
                provenance="narrative-heuristic",
                confidence=0.55,
                rationale="Write-up claims possible RCE on an exposed application",
            ),
        )
        _add_unique(
            case.attack,
            Mapping(
                id="T1059",
                name="Command and Scripting Interpreter",
                framework="ATT&CK",
                provenance="narrative-heuristic",
                confidence=0.45,
                rationale="RCE typically implies code or command execution after exploit",
            ),
        )

    if not case.attack and case.locations:
        _add_unique(
            case.attack,
            Mapping(
                id="T1190",
                name="Exploit Public-Facing Application",
                framework="ATT&CK",
                provenance="location-heuristic",
                confidence=0.4,
                rationale="Code location present but no CWE; public-app exploit is a placeholder",
            ),
        )

    for tech in case.attack:
        parent = tech.id.split(".")[0]
        for did, dname in ATTACK_D3FEND.get(tech.id, ATTACK_D3FEND.get(parent, [])):
            _add_unique(
                case.d3fend,
                Mapping(
                    id=did,
                    name=dname,
                    framework="D3FEND",
                    provenance="attack-artifact",
                    confidence=tech.confidence,
                    rationale=f"Countermeasure for {tech.id}",
                ),
            )
        for cid, cname in ATTACK_CSF.get(tech.id, ATTACK_CSF.get(parent, [])):
            _add_unique(
                case.csf,
                Mapping(
                    id=cid,
                    name=cname,
                    framework="NIST CSF 2.0",
                    provenance="attack-crosswalk",
                    confidence=tech.confidence,
                    rationale=f"CSF rollup of {tech.id}",
                ),
            )

    if case.asset_ai_system:
        for cwe in case.cwes:
            for aid, aname in AI_CWE_ATLAS.get(cwe, []):
                _add_unique(
                    case.atlas,
                    Mapping(
                        id=aid,
                        name=aname,
                        framework="ATLAS",
                        provenance="cwe-heuristic",
                        confidence=0.5,
                        rationale=f"{cwe} on an AI-tagged asset",
                    ),
                )
        if case.atlas:
            case.airmf = [
                Mapping(
                    id="MEASURE",
                    name="Measure",
                    framework="NIST AI RMF",
                    provenance="atlas-rollup",
                    confidence=0.5,
                    rationale="Adversarial technique present — test and monitor",
                ),
                Mapping(
                    id="MANAGE",
                    name="Manage",
                    framework="NIST AI RMF",
                    provenance="atlas-rollup",
                    confidence=0.5,
                    rationale="Treat as an AI-system incident path until patched",
                ),
            ]

    if case.asset_fraud_relevant:
        for tech in case.attack:
            parent = tech.id.split(".")[0]
            for fid, fname in FRAUD_ATTACK_F3.get(tech.id, FRAUD_ATTACK_F3.get(parent, [])):
                _add_unique(
                    case.f3,
                    Mapping(
                        id=fid,
                        name=fname,
                        framework="F3",
                        provenance="attack-crosswalk",
                        confidence=0.45,
                        rationale=f"Fraud overlay of {tech.id} (asset marked fraud-relevant)",
                    ),
                )
    return case
