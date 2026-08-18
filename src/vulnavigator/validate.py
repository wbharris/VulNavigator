"""Validate a normalized finding before mapping."""

from __future__ import annotations

from vulnavigator.models import Case, is_ai_zeroday
from vulnavigator.scanners import SCANNER_KINDS


def validate(case: Case) -> Case:
    notes: list[str] = []
    ev = case.evidence
    has_identity = bool(case.cves) or bool(case.nvd_description)
    has_product = bool(case.product or case.component or case.locations)
    has_writeup = len(case.description.strip()) >= 40 or bool(ev.discovery.strip())
    has_proof = bool(ev.reproduced) or bool(ev.sandbox) or bool(ev.poc.strip())
    zeroday = is_ai_zeroday(case)

    if zeroday:
        notes.append(
            "No CVE expected — AI 0-day identity is the write-up, how it was found, and the PoC/exploit"
        )
    elif case.cves and case.nvd_description:
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
        who = {
            "daybreak": "Daybreak",
            "mythos": "Mythos",
        }.get(case.source_kind, case.source_kind.title() if case.source_kind in SCANNER_KINDS else "Source")
        notes.append(f"{who} provided a PoC / exploit or sandbox reproduction — that is the primary evidence")
    else:
        notes.append("No PoC, exploit, or sandbox reproduction in the finding")
    if ev.discovery.strip():
        notes.append("Finder described how the issue was discovered")
    if case.source_kind == "daybreak" and case.finder_confidence:
        notes.append(f"Daybreak confidence={case.finder_confidence}")
    if case.source_kind in SCANNER_KINDS:
        notes.append(f"{case.source_kind} scanner detection — not exploit-validated")
    if case.rule_id:
        notes.append(f"Finder rule/bug class: {case.rule_id}")

    if not has_product:
        notes.append("Affected product/component/location missing")
    if not has_writeup and not has_identity and not has_proof:
        notes.append("Description too thin to stand on its own")

    # Status — AI 0-days stand on write-up + PoC, not NVD
    if not has_identity and not has_writeup and not has_proof:
        status = "rejected"
        notes.append("Rejected: no write-up, no PoC, and no CVE")
    elif zeroday and ev.reproduced is False and not has_proof:
        status = "unconfirmed"
        notes.append("Writer said exploitability is not confirmed and no PoC was attached")
    elif case.kev or (has_identity and has_proof) or (zeroday and ev.sandbox and has_proof):
        status = "confirmed"
    elif has_proof and has_writeup:
        status = "plausible"
    elif zeroday and has_writeup:
        status = "unconfirmed"
        notes.append("0-day write-up only — replay a PoC before treating this as confirmed")
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
