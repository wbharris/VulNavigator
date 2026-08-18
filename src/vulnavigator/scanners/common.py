"""Shared scanner helpers."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import date
from typing import Any

from vulnavigator.models import Case, Evidence, Location

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CWE_RE = re.compile(r"CWE-\d+", re.I)
# Bare year-id fragments (Nexpose, some CSV exports). Not a CVE by itself.
YEAR_ID_RE = re.compile(r"(?<![A-Za-z0-9])(\d{4}-\d{4,})(?!\d)")
# Keys that make a dict look like one finding rather than a report wrapper.
_ROW_HINTS = frozenset(
    {
        "id",
        "alert_id",
        "qid",
        "pluginid",
        "plugin_id",
        "oid",
        "cve",
        "cves",
        "cveid",
        "cve_id",
        "vulnerabilityid",
        "template-id",
        "templateid",
        "ruleid",
        "title",
        "name",
        "alert",
        "description",
        "severity",
        "identifiers",
        "nexposeid",
        "findingarn",
        "vulnerabilitycve",
    }
)

SCANNER_KINDS = frozenset(
    {
        "qualys",
        "openvas",
        "nessus",
        "sarif",
        "rapid7",
        "defender",
        "wiz",
        "trivy",
        "snyk",
        "crowdstrike",
        "nuclei",
        "burp",
        "zap",
        "inspector",
        "nexus",
        "prisma",
        "orca",
        "dependabot",
    }
)

ALIASES = {
    # Documented typo: PRODUCT.md and --source accept "nexsus".
    "nexsus": "nessus",
    "tenable": "nessus",
    "tenable.io": "nessus",
    "tenable.sc": "nessus",
    "gvm": "openvas",
    "greenbone": "openvas",
    "insightvm": "rapid7",
    "nexpose": "rapid7",
    "mdvm": "defender",
    "microsoft-defender": "defender",
    "falcon": "crowdstrike",
    "spotlight": "crowdstrike",
    "aws-inspector": "inspector",
    "inspector2": "inspector",
    "sonatype": "nexus",
    "nexus-iq": "nexus",
    "nexusiq": "nexus",
    "prisma-cloud": "prisma",
    "codeql": "sarif",
    "semgrep": "sarif",
    "ghas": "sarif",
}


def alias_source(source: str) -> str:
    key = (source or "").strip().lower()
    return ALIASES.get(key, key)


def local_tag(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def xml_text(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    return (el.text or "").strip()


def xml_find(el: ET.Element, name: str) -> ET.Element | None:
    for child in el:
        if local_tag(child.tag) == name:
            return child
    return None


def xml_findall(el: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in el.iter() if local_tag(c.tag) == name]


def cves_of(*chunks: Any) -> list[str]:
    found: list[str] = []
    year_hi = date.today().year + 1
    for chunk in chunks:
        if chunk is None:
            continue
        text = chunk if isinstance(chunk, str) else json.dumps(chunk)
        for match in CVE_RE.findall(text):
            cve = match.upper()
            if cve not in found:
                found.append(cve)
        # Nexpose (and some CSV exports) store the year-id without a CVE- prefix.
        # Only promote those fragments when the same chunk mentions "cve".
        if "cve" not in text.lower():
            continue
        for raw in YEAR_ID_RE.findall(text):
            year = int(raw.split("-", 1)[0])
            if year < 1999 or year > year_hi:
                continue
            cve = f"CVE-{raw}"
            if cve not in found:
                found.append(cve)
    return found


def cwes_of(*chunks: Any) -> list[str]:
    found: list[str] = []
    for chunk in chunks:
        if chunk is None:
            continue
        text = chunk if isinstance(chunk, str) else json.dumps(chunk)
        for match in CWE_RE.findall(text):
            cwe = match.upper()
            if cwe not in found:
                found.append(cwe)
    return found


def skip_info(severity: str) -> bool:
    return severity.lower() in {"informational", "info", "log", "none", "note", ""}


def norm_sev(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    mapping = {
        "4": "critical",
        "5": "critical",
        "critical": "critical",
        "very high": "critical",
        "3": "high",
        "high": "high",
        "important": "high",
        "error": "high",
        "2": "medium",
        "medium": "medium",
        "moderate": "medium",
        "warning": "medium",
        "1": "low",
        "low": "low",
        "0": "informational",
        "informational": "informational",
        "info": "informational",
        "log": "informational",
        "note": "low",
    }
    if text in mapping:
        return mapping[text]
    try:
        score = float(text)
    except ValueError:
        return text
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "informational"


def make_case(
    *,
    kind: str,
    finding_id: str,
    title: str,
    description: str = "",
    cves: list[str] | None = None,
    cwes: list[str] | None = None,
    product: str = "",
    component: str = "",
    version: str = "",
    severity: str = "",
    remediation: str = "",
    output: str = "",
    location: str = "",
    extra_locations: list[Location] | None = None,
    raw: dict[str, Any] | None = None,
    rule_id: str = "",
) -> Case:
    """Build a scanner Case.

    ``finding_id`` is the instance identity (guid, host+plugin hit, alert id).
    ``rule_id`` is the stable rule/plugin/QID class. When omitted, scanners
    whose plugin/QID *is* the identity (Nessus, Qualys, OpenVAS) reuse
    ``finding_id``. Pass ``rule_id`` separately when they differ (SARIF).
    """
    locs: list[Location] = list(extra_locations or [])
    if location and not any(l.path == location for l in locs):
        locs.insert(0, Location(path=location))
    fid = str(finding_id or "")
    return Case(
        source=kind,
        source_kind=kind,
        finding_id=fid,
        rule_id=str(rule_id or "") or fid,
        title=title or f"{kind} {finding_id}".strip(),
        description=description,
        cves=cves or [],
        cwes=cwes or [],
        product=product,
        component=component,
        version=version,
        locations=locs,
        evidence=Evidence(
            notes=" | ".join(x for x in (f"{kind} scanner detection", output) if x)
        ),
        source_severity=norm_sev(severity) or str(severity).lower(),
        raw=raw or {},
        remediation=[remediation] if remediation else [],
    )


def flatten_rows(data: Any, keys: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return []
    for key in keys:
        val = data.get(key)
        if isinstance(val, list) and val and isinstance(val[0], dict):
            return [x for x in val if isinstance(x, dict)]
        if isinstance(val, dict):
            nested = flatten_rows(val, keys)
            if nested:
                return nested
    if not any(data.values()):
        return []
    # Bare object with no wrapper keys: treat as one row.
    if not keys:
        return [data]
    # Wrapper keys were given but none matched. Only wrap if this dict
    # itself looks like a finding, not a report envelope.
    hints = {str(k).lower() for k in data}
    return [data] if hints & _ROW_HINTS else []
