"""Render a case as markdown or JSON."""

from __future__ import annotations

import json

from vulnavigator.models import Case


def _maps(title: str, items) -> list[str]:
    if not items:
        return [f"**{title}:** none"]
    lines = [f"**{title}:**"]
    for m in items:
        conf = f"{m.confidence:.2f}"
        lines.append(f"- `{m.id}` {m.name} — {m.provenance}, confidence {conf}. {m.rationale}")
    return lines


def to_markdown(case: Case) -> str:
    ev = "yes" if (case.evidence.reproduced or case.evidence.sandbox) else "no"
    lines = [
        f"# {case.title}",
        "",
        f"- **Source:** {case.source_kind}"
        + (f" `{case.finding_id}`" if case.finding_id else "")
        + (f" rule `{case.rule_id}`" if case.rule_id else ""),
        f"- **Validation:** {case.validation_status}",
        f"- **Priority:** {case.priority} · **Urgency:** {case.urgency}",
        f"- **CVE:** {', '.join(case.cves) or 'none'}",
        f"- **CWE:** {', '.join(case.cwes) or 'none'}",
        f"- **Product:** {case.product or 'unknown'} {case.component} {case.version}".rstrip(),
        f"- **Evidence reproduced/sandbox:** {ev}",
        "",
        "## Why this rank",
    ]
    lines.extend(f"- {r}" for r in case.priority_reasons)
    lines += ["", "## Validation notes"]
    lines.extend(f"- {n}" for n in case.validation_notes)
    if case.description:
        lines += ["", "## Finding", "", case.description.strip()]
    lines += ["", "## Mapping"]
    for title, bucket in (
        ("ATT&CK", case.attack),
        ("D3FEND", case.d3fend),
        ("NIST CSF 2.0", case.csf),
        ("ATLAS", case.atlas),
        ("NIST AI RMF", case.airmf),
        ("F3", case.f3),
    ):
        lines.extend(_maps(title, bucket))
        lines.append("")
    lines += ["## Remediation"]
    lines.extend(f"- {r}" for r in case.remediation)
    lines += ["", "## Compensating controls"]
    if case.compensating_controls:
        lines.extend(f"- {c}" for c in case.compensating_controls)
    else:
        lines.append("- none mapped")
    lines += ["", "## Next actions"]
    for a in case.next_actions:
        extra = f" — done when: {a.done_when}" if a.done_when else ""
        lines.append(f"- **{a.owner}:** {a.action}{extra}")
    lines += ["", "## Assumptions the agent made"]
    if case.assumptions:
        for a in case.assumptions:
            lines.append(f"- **{a.field}** = `{a.assumed}` because {a.because}. Impact: {a.impact}")
    else:
        lines.append("- none — context was complete")
    lines += ["", "## Information that would make this report better"]
    if case.improve:
        for i in case.improve:
            lines.append(f"- {i.question} — {i.why_it_matters} (changes: {i.would_change})")
    else:
        lines.append("- nothing material; re-run if the asset changes")
    lines.append("")
    return "\n".join(lines)


def to_json(case: Case) -> str:
    return json.dumps(case.to_dict(), indent=2, default=str) + "\n"
