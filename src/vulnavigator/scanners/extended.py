"""SARIF, Rapid7, Defender, Wiz, Trivy, Snyk, and other useful intakes."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any

from vulnavigator.models import Case
from vulnavigator.scanners.common import (
    cves_of,
    cwes_of,
    flatten_rows,
    local_tag,
    make_case,
    skip_info,
    xml_find,
    xml_findall,
    xml_text,
)


def parse_sarif(data: dict[str, Any]) -> list[Case]:
    cases: list[Case] = []
    for run in data.get("runs") or []:
        tool = ((run.get("tool") or {}).get("driver") or {}).get("name") or "sarif"
        rules = {r.get("id"): r for r in ((run.get("tool") or {}).get("driver") or {}).get("rules") or [] if r.get("id")}
        for result in run.get("results") or []:
            rule_id = str(result.get("ruleId") or "")
            rule = rules.get(rule_id) or {}
            msg = result.get("message") or {}
            title = str(msg.get("text") or rule.get("shortDescription", {}).get("text") or rule_id or "SARIF finding")
            help_text = ""
            if isinstance(rule.get("help"), dict):
                help_text = str(rule["help"].get("text") or "")
            elif isinstance(rule.get("fullDescription"), dict):
                help_text = str(rule["fullDescription"].get("text") or "")
            locs = []
            for loc in result.get("locations") or []:
                phys = (loc or {}).get("physicalLocation") or {}
                uri = ((phys.get("artifactLocation") or {}).get("uri")) or ""
                line = (phys.get("region") or {}).get("startLine")
                locs.append(f"{uri}:{line}" if line else uri)
            props = result.get("properties") or rule.get("properties") or {}
            tags = props.get("tags") or []
            cases.append(
                make_case(
                    kind="sarif",
                    finding_id=str(result.get("guid") or rule_id),
                    title=f"[{tool}] {title}" if tool else title,
                    description=str(msg.get("text") or "") + (("\n\n" + help_text) if help_text else ""),
                    cves=cves_of(title, msg, props, tags, result),
                    cwes=cwes_of(tags, props, result, rule),
                    product=tool,
                    component=locs[0].split(":")[0] if locs else "",
                    severity=str(result.get("level") or props.get("severity") or "medium"),
                    location=locs[0] if locs else "",
                    raw=result,
                )
            )
    return cases


def parse_rapid7_xml(root: ET.Element) -> list[Case]:
    defs: dict[str, dict[str, str]] = {}
    for vuln in xml_findall(root, "vulnerability"):
        vid = vuln.attrib.get("id", "")
        refs = []
        for ref in vuln.iter():
            if local_tag(ref.tag) == "reference" and (ref.attrib.get("source") or "").upper() == "CVE":
                raw = xml_text(ref)
                refs.append(raw if raw.upper().startswith("CVE-") else f"CVE-{raw}")
        defs[vid] = {
            "title": vuln.attrib.get("title") or xml_text(xml_find(vuln, "title")),
            "severity": vuln.attrib.get("severity") or vuln.attrib.get("cvssScore") or "",
            "description": xml_text(xml_find(vuln, "description")),
            "solution": xml_text(xml_find(vuln, "solution")),
            "cves": " ".join(refs),
        }
    cases: list[Case] = []
    for node in xml_findall(root, "node"):
        host = node.attrib.get("address") or ""
        for test in xml_findall(node, "test"):
            status = (test.attrib.get("status") or "").lower()
            if status.startswith("not-vuln") or status in {"invulnerable", ""}:
                continue
            vid = test.attrib.get("id", "")
            meta = defs.get(vid, {})
            title = meta.get("title") or vid
            cases.append(
                make_case(
                    kind="rapid7",
                    finding_id=vid,
                    title=title,
                    description=meta.get("description") or title,
                    cves=cves_of(meta.get("cves"), title),
                    product=host,
                    severity=meta.get("severity") or "high",
                    remediation=meta.get("solution") or "",
                    location=host,
                    raw={"id": vid, "host": host, "status": status},
                )
            )
    if not cases:
        for vuln in xml_findall(root, "vulnerability"):
            vid = vuln.attrib.get("id", "")
            meta = defs.get(vid, {})
            if not meta.get("title"):
                continue
            cases.append(
                make_case(
                    kind="rapid7",
                    finding_id=vid,
                    title=meta["title"],
                    description=meta.get("description") or meta["title"],
                    cves=cves_of(meta.get("cves")),
                    severity=meta.get("severity") or "medium",
                    remediation=meta.get("solution") or "",
                    raw={"id": vid},
                )
            )
    return cases


def parse_burp_xml(root: ET.Element) -> list[Case]:
    cases: list[Case] = []
    for issue in xml_findall(root, "issue"):
        title = xml_text(xml_find(issue, "name"))
        host = xml_text(xml_find(issue, "host"))
        path = xml_text(xml_find(issue, "path"))
        cases.append(
            make_case(
                kind="burp",
                finding_id=xml_text(xml_find(issue, "type")) or title,
                title=title,
                description=xml_text(xml_find(issue, "issueDetail")) or xml_text(xml_find(issue, "issueBackground")),
                cves=cves_of(ET.tostring(issue, encoding="unicode")),
                cwes=cwes_of(xml_text(xml_find(issue, "vulnerabilityClassifications"))),
                product=host,
                component=path,
                severity=xml_text(xml_find(issue, "severity")),
                remediation=xml_text(xml_find(issue, "remediationBackground"))
                or xml_text(xml_find(issue, "remediationDetail")),
                location=f"{host}{path}",
                raw={"host": host, "path": path},
            )
        )
    return [c for c in cases if not skip_info(c.source_severity) or c.cves]


def parse_zap_xml(root: ET.Element) -> list[Case]:
    cases: list[Case] = []
    for item in xml_findall(root, "alertitem"):
        cwe = xml_text(xml_find(item, "cweid"))
        cases.append(
            make_case(
                kind="zap",
                finding_id=xml_text(xml_find(item, "pluginid")),
                title=xml_text(xml_find(item, "alert")) or xml_text(xml_find(item, "name")),
                description=xml_text(xml_find(item, "desc")),
                cves=cves_of(ET.tostring(item, encoding="unicode")),
                cwes=[f"CWE-{cwe}"] if cwe and not cwe.upper().startswith("CWE-") else ([cwe.upper()] if cwe else []),
                product=xml_text(xml_find(item, "uri")),
                component=xml_text(xml_find(item, "param")),
                severity=xml_text(xml_find(item, "riskdesc")) or xml_text(xml_find(item, "riskcode")),
                remediation=xml_text(xml_find(item, "solution")),
                location=xml_text(xml_find(item, "uri")),
                raw={"pluginid": xml_text(xml_find(item, "pluginid"))},
            )
        )
    return [c for c in cases if not skip_info(c.source_severity) or c.cves]


def parse_trivy(data: Any) -> list[Case]:
    cases: list[Case] = []
    results = data.get("Results") if isinstance(data, dict) else None
    if results is None and isinstance(data, list):
        results = data
    for result in results or []:
        target = str(result.get("Target") or "")
        for vuln in result.get("Vulnerabilities") or []:
            vid = str(vuln.get("VulnerabilityID") or "")
            cases.append(
                make_case(
                    kind="trivy",
                    finding_id=vid,
                    title=str(vuln.get("Title") or vid),
                    description=str(vuln.get("Description") or vuln.get("Title") or ""),
                    cves=cves_of(vid, vuln),
                    cwes=cwes_of(vuln.get("CweIDs"), vuln),
                    product=target,
                    component=str(vuln.get("PkgName") or ""),
                    version=str(vuln.get("InstalledVersion") or ""),
                    severity=str(vuln.get("Severity") or ""),
                    remediation=f"Upgrade to {vuln['FixedVersion']}" if vuln.get("FixedVersion") else "",
                    location=target,
                    raw=vuln,
                )
            )
    return cases


def parse_snyk(data: Any) -> list[Case]:
    rows = []
    if isinstance(data, dict):
        rows = data.get("vulnerabilities") or data.get("vulnerabilities") or []
        if not rows and isinstance(data.get("runs"), list):
            return parse_sarif(data)
    elif isinstance(data, list):
        rows = data
    cases: list[Case] = []
    for vuln in rows:
        if not isinstance(vuln, dict):
            continue
        ids = vuln.get("identifiers") or {}
        cves = list(ids.get("CVE") or [])
        cwes = [str(c) if str(c).upper().startswith("CWE-") else f"CWE-{c}" for c in (ids.get("CWE") or [])]
        cases.append(
            make_case(
                kind="snyk",
                finding_id=str(vuln.get("id") or ""),
                title=str(vuln.get("title") or vuln.get("id") or "Snyk finding"),
                description=str(vuln.get("description") or ""),
                cves=cves_of(*cves, vuln),
                cwes=cwes,
                product=str(vuln.get("packageName") or vuln.get("moduleName") or ""),
                version=str(vuln.get("version") or ""),
                severity=str(vuln.get("severity") or ""),
                location=str(vuln.get("from") or ""),
                raw=vuln,
            )
        )
    return cases


def parse_defender(data: Any) -> list[Case]:
    rows = flatten_rows(data, ("value", "findings", "vulnerabilities"))
    cases: list[Case] = []
    for row in rows:
        cve = str(row.get("cveId") or row.get("cve") or row.get("CVE") or "")
        cases.append(
            make_case(
                kind="defender",
                finding_id=str(row.get("id") or cve),
                title=str(row.get("vulnerabilityName") or row.get("displayName") or cve or "Defender finding"),
                description=str(row.get("description") or row.get("recommendedSecurityUpdate") or ""),
                cves=cves_of(cve, row),
                product=str(row.get("deviceName") or row.get("machineId") or row.get("productName") or ""),
                component=str(row.get("productName") or row.get("softwareVendor") or ""),
                version=str(row.get("productVersion") or ""),
                severity=str(row.get("severity") or row.get("cvssV3") or ""),
                remediation=str(row.get("recommendedSecurityUpdate") or ""),
                location=str(row.get("deviceName") or ""),
                raw=row,
            )
        )
    return cases


def parse_wiz(data: Any) -> list[Case]:
    rows = flatten_rows(data, ("issues", "nodes", "data", "vulnerabilities", "findings"))
    cases: list[Case] = []
    for row in rows:
        asset = row.get("vulnerableAsset") or row.get("resource") or row.get("entity") or {}
        if not isinstance(asset, dict):
            asset = {"name": asset}
        cve = str(row.get("name") or row.get("vulnerabilityCVE") or row.get("cve") or row.get("CVE") or "")
        cases.append(
            make_case(
                kind="wiz",
                finding_id=str(row.get("id") or cve),
                title=str(row.get("title") or row.get("name") or cve or "Wiz issue"),
                description=str(row.get("description") or row.get("CVEDescription") or row.get("detailedExplanation") or ""),
                cves=cves_of(cve, row),
                product=str(asset.get("name") or asset.get("id") or row.get("assetName") or ""),
                component=str(asset.get("type") or row.get("type") or ""),
                severity=str(row.get("severity") or ""),
                location=str(asset.get("name") or ""),
                raw=row,
            )
        )
    return cases


def parse_crowdstrike(data: Any) -> list[Case]:
    rows = flatten_rows(data, ("resources", "vulnerabilities", "detections"))
    cases: list[Case] = []
    for row in rows:
        cve_obj = row.get("cve") if isinstance(row.get("cve"), dict) else {}
        host = row.get("host_info") if isinstance(row.get("host_info"), dict) else {}
        cve = str(cve_obj.get("id") or row.get("cve_id") or "")
        cases.append(
            make_case(
                kind="crowdstrike",
                finding_id=str(row.get("id") or cve),
                title=cve or "CrowdStrike Spotlight finding",
                description=str(cve_obj.get("description") or row.get("status") or ""),
                cves=cves_of(cve, row),
                product=str(host.get("hostname") or host.get("local_ip") or ""),
                severity=str(cve_obj.get("exprt_rating") or cve_obj.get("severity") or row.get("severity") or ""),
                location=str(host.get("hostname") or ""),
                raw=row,
            )
        )
    return cases


def parse_inspector(data: Any) -> list[Case]:
    rows = flatten_rows(data, ("findings", "value"))
    cases: list[Case] = []
    for row in rows:
        pkg = row.get("packageVulnerabilityDetails") if isinstance(row.get("packageVulnerabilityDetails"), dict) else {}
        packages = pkg.get("vulnerablePackages") or []
        first = packages[0] if packages and isinstance(packages[0], dict) else {}
        rem = row.get("remediation") if isinstance(row.get("remediation"), dict) else {}
        rec = rem.get("recommendation") if isinstance(rem.get("recommendation"), dict) else {}
        vid = str(pkg.get("vulnerabilityId") or row.get("title") or "")
        cases.append(
            make_case(
                kind="inspector",
                finding_id=str(row.get("findingArn") or vid).split("/")[-1],
                title=str(row.get("title") or vid),
                description=str(row.get("description") or ""),
                cves=cves_of(vid, pkg, row),
                product=str(first.get("name") or ""),
                version=str(first.get("version") or ""),
                severity=str(row.get("severity") or ""),
                remediation=str(rec.get("text") or ""),
                raw=row,
            )
        )
    return cases


def parse_nexus(data: Any) -> list[Case]:
    cases: list[Case] = []
    components = []
    if isinstance(data, dict):
        components = data.get("components") or []
    elif isinstance(data, list):
        components = data
    for comp in components:
        if not isinstance(comp, dict):
            continue
        name = str(comp.get("displayName") or comp.get("componentIdentifier") or "")
        issues = ((comp.get("securityData") or {}).get("securityIssues")) or comp.get("securityIssues") or []
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            ref = str(issue.get("reference") or issue.get("url") or "")
            cases.append(
                make_case(
                    kind="nexus",
                    finding_id=ref or name,
                    title=f"{name}: {ref}".strip(": "),
                    description=str(issue.get("threatCategory") or ""),
                    cves=cves_of(ref, issue),
                    product=name,
                    severity=str(issue.get("severity") or issue.get("threatCategory") or ""),
                    raw=issue,
                )
            )
    return cases


def parse_prisma(data: Any) -> list[Case]:
    rows = flatten_rows(data, ("data", "vulnerabilities", "findings", "results"))
    cases: list[Case] = []
    for row in rows:
        cve = str(row.get("cve") or row.get("cveId") or row.get("CVE") or "")
        cases.append(
            make_case(
                kind="prisma",
                finding_id=str(row.get("id") or cve),
                title=str(row.get("title") or cve or "Prisma finding"),
                description=str(row.get("cause") or row.get("description") or ""),
                cves=cves_of(cve, row),
                product=str(row.get("packageName") or row.get("resourceName") or ""),
                version=str(row.get("packageVersion") or ""),
                severity=str(row.get("severity") or ""),
                raw=row,
            )
        )
    return cases


def parse_orca(data: Any) -> list[Case]:
    rows = flatten_rows(data, ("alerts", "data", "findings"))
    cases: list[Case] = []
    for row in rows:
        cves = row.get("cve_list") or row.get("cves") or []
        cases.append(
            make_case(
                kind="orca",
                finding_id=str(row.get("alert_id") or row.get("id") or ""),
                title=str(row.get("alert_type") or row.get("title") or "Orca alert"),
                description=str(row.get("details") or row.get("description") or ""),
                cves=cves_of(*cves, row),
                product=str(row.get("asset_name") or row.get("asset_unique_id") or ""),
                severity=str(row.get("severity") or ""),
                location=str(row.get("asset_name") or ""),
                raw=row,
            )
        )
    return cases


def parse_dependabot(data: Any) -> list[Case]:
    rows = flatten_rows(data, ("alerts", "dependabot", "value"))
    cases: list[Case] = []
    for row in rows:
        advisory = row.get("security_advisory") if isinstance(row.get("security_advisory"), dict) else {}
        vuln = row.get("security_vulnerability") if isinstance(row.get("security_vulnerability"), dict) else {}
        pkg = (vuln.get("package") or {}) if isinstance(vuln.get("package"), dict) else {}
        cve = str(advisory.get("cve_id") or advisory.get("ghsa_id") or "")
        cases.append(
            make_case(
                kind="dependabot",
                finding_id=str(row.get("number") or cve),
                title=str(advisory.get("summary") or cve or "Dependabot alert"),
                description=str(advisory.get("description") or ""),
                cves=cves_of(cve, advisory),
                product=str(pkg.get("name") or ""),
                severity=str(advisory.get("severity") or vuln.get("severity") or ""),
                remediation=str(vuln.get("first_patched_version", {}).get("identifier") or "")
                if isinstance(vuln.get("first_patched_version"), dict)
                else "",
                raw=row,
            )
        )
    return cases


def parse_nuclei(data: Any) -> list[Case]:
    rows = data if isinstance(data, list) else flatten_rows(data, ("results", "findings"))
    if isinstance(data, dict) and data.get("template-id"):
        rows = [data]
    cases: list[Case] = []
    for row in rows:
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        tid = str(row.get("template-id") or row.get("templateID") or "")
        cases.append(
            make_case(
                kind="nuclei",
                finding_id=tid,
                title=str(info.get("name") or tid),
                description=str(info.get("description") or row.get("matcher-name") or ""),
                cves=cves_of(info.get("classification"), info, row, tid),
                cwes=cwes_of(info.get("classification"), info),
                product=str(row.get("host") or row.get("matched-at") or ""),
                severity=str(info.get("severity") or ""),
                location=str(row.get("matched-at") or row.get("host") or ""),
                raw=row,
            )
        )
    return cases


def parse_rapid7_json(data: Any) -> list[Case]:
    rows = flatten_rows(data, ("vulnerabilities", "resources", "findings"))
    cases: list[Case] = []
    for row in rows:
        cves = row.get("cves") or row.get("cve") or []
        cases.append(
            make_case(
                kind="rapid7",
                finding_id=str(row.get("id") or row.get("nexposeId") or ""),
                title=str(row.get("title") or row.get("vulnerability_id") or "InsightVM finding"),
                description=str(row.get("description") or ""),
                cves=cves_of(*cves if isinstance(cves, list) else [cves], row),
                product=str(row.get("assetIp") or row.get("ip") or row.get("hostname") or ""),
                severity=str(row.get("severity") or row.get("severityScore") or ""),
                remediation=str(row.get("solution") or ""),
                raw=row,
            )
        )
    return cases


JSON_PARSERS = {
    "sarif": parse_sarif,
    "trivy": parse_trivy,
    "snyk": parse_snyk,
    "defender": parse_defender,
    "wiz": parse_wiz,
    "crowdstrike": parse_crowdstrike,
    "inspector": parse_inspector,
    "nexus": parse_nexus,
    "prisma": parse_prisma,
    "orca": parse_orca,
    "dependabot": parse_dependabot,
    "nuclei": parse_nuclei,
    "rapid7": parse_rapid7_json,
}


def detect_extended_json(data: Any) -> str:
    if isinstance(data, dict):
        if data.get("runs") is not None and (data.get("version") or data.get("$schema")):
            return "sarif"
        if data.get("Results") and any(isinstance(r, dict) and "Vulnerabilities" in r for r in data.get("Results") or []):
            return "trivy"
        if "vulnerabilities" in data and (data.get("ok") is not None or data.get("identifier") or "snyk" in json.dumps(data.get("vulnerabilities", [])[:1]).lower()):
            return "snyk"
        if data.get("components") and any(
            isinstance(c, dict) and (c.get("securityData") or c.get("securityIssues")) for c in data.get("components") or []
        ):
            return "nexus"
        blob = json.dumps(data).lower()
    elif isinstance(data, list) and data and isinstance(data[0], dict):
        blob = json.dumps(data[0]).lower()
        if "template-id" in data[0] or "template-id" in blob:
            return "nuclei"
        if "security_advisory" in data[0]:
            return "dependabot"
        if "VulnerabilityID" in data[0] or "PkgName" in data[0]:
            return "trivy"
    else:
        return ""
    if "packagevulnerabilitydetails" in blob or "findingarn" in blob:
        return "inspector"
    if "security_advisory" in blob:
        return "dependabot"
    if "host_info" in blob and ("exprt_rating" in blob or "spotlight" in blob or "cid" in blob):
        return "crowdstrike"
    if "cveid" in blob and ("devicename" in blob or "machineid" in blob or "recommendedsecurityupdate" in blob):
        return "defender"
    if "vulnerableasset" in blob or '"wiz"' in blob:
        return "wiz"
    if "cve_list" in blob and "alert_id" in blob:
        return "orca"
    if "nexpose" in blob or "insightvm" in blob or "realriskscore" in blob:
        return "rapid7"
    if "prismacloud" in blob or ("packagename" in blob and "packageversion" in blob and "cve" in blob):
        return "prisma"
    if "template-id" in blob and "matched-at" in blob:
        return "nuclei"
    return ""
