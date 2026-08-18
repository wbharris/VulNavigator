"""Validate a normalized finding before mapping."""

from __future__ import annotations

from vulnavigator.models import Case


def validate(case: Case) -> Case:
    notes: list[str] = []
    ev = case.evidence
    has_identity = bool(case.cves) or bool(case.nvd_description)
    has_product = bool(case.product or case.component or case.locations)
    has_writeup = len(case.description.strip()) >= 40
    has_proof = bool(ev.reproduced) or bool(ev.sandbox) or bool(ev.poc.strip())

    if case.cves and case.nvd_description:
        notes.append(f"{case.cves[0]} resolved in NVD")
    elif case.cves and not case.nvd_description:
        notes.append(f"{case.cves[0]} not resolved (offline or unknown to NVD)")
    else:
        notes.append("No CVE — treating as a 0-day / pre-CVE claim")

    if case.kev:
        notes.append("Listed in CISA KEV (exploited in the wild)")
    if case.epss is not None:
        notes.append(f"EPSS={case.epss:.3f}")
    if case.cvss is not None:
        notes.append(f"CVSS={case.cvss}")

    if has_proof:
        who = "Daybreak" if case.source_kind == "daybreak" else "Mythos" if case.source_kind == "mythos" else "Source"
        notes.append(f"{who} provided reproduction / sandbox / PoC evidence")
    else:
        notes.append("No reproduction evidence in the finding")
    if case.source_kind == "daybreak" and case.finder_confidence:
        notes.append(f"Daybreak confidence={case.finder_confidence}")
    if case.rule_id:
        notes.append(f"Finder rule/bug class: {case.rule_id}")

    if not has_product:
        notes.append("Affected product/component/location missing")
    if not has_writeup and not has_identity:
        notes.append("Description too thin to stand on its own")

    # Status
    if not has_identity and not has_writeup:
        status = "rejected"
        notes.append("Rejected: neither a CVE nor a usable write-up")
    elif case.kev or (has_identity and has_proof):
        status = "confirmed"
    elif has_proof and has_writeup:
        status = "plausible"
    elif has_identity or (has_writeup and has_product):
        status = "plausible" if has_writeup else "unconfirmed"
    else:
        status = "unconfirmed"

    # Contradictions
    sev = case.source_severity.lower()
    if sev in {"critical", "high"} and not has_proof and not case.kev:
        notes.append("Source severity is high/critical but evidence is thin")

    case.validation_status = status
    case.validation_notes = notes
    return case
