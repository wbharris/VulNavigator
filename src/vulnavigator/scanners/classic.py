"""Qualys, OpenVAS, and Nessus parsers."""

from __future__ import annotations

import csv
import io
import xml.etree.ElementTree as ET
from typing import Any

from vulnavigator.models import Case
from vulnavigator.scanners.common import (
    cves_of,
    flatten_rows,
    local_tag,
    make_case,
    skip_info,
    xml_find,
    xml_findall,
    xml_text,
)

NESSUS_SEV = {"0": "informational", "1": "low", "2": "medium", "3": "high", "4": "critical"}
QUALYS_SEV = {"1": "informational", "2": "low", "3": "medium", "4": "high", "5": "critical"}


def parse_nessus_xml(root: ET.Element) -> list[Case]:
    cases: list[Case] = []
    for host_el in xml_findall(root, "ReportHost"):
        host = host_el.attrib.get("name", "")
        for tag in host_el.iter():
            if local_tag(tag.tag) == "tag" and tag.attrib.get("name") == "host-ip":
                host = xml_text(tag) or host
        for item in host_el:
            if local_tag(item.tag) != "ReportItem":
                continue
            sev_n = item.attrib.get("severity", "0")
            severity = NESSUS_SEV.get(sev_n, item.attrib.get("risk_factor", sev_n))
            if skip_info(str(severity)) and sev_n == "0":
                continue
            plugin = item.attrib.get("pluginID", "")
            cves = [xml_text(c).upper() for c in item if local_tag(c.tag) == "cve" and xml_text(c)]
            cwes = []
            for c in item:
                if local_tag(c.tag) == "cwe" and xml_text(c):
                    raw = xml_text(c)
                    cwes.append(raw.upper() if raw.upper().startswith("CWE-") else f"CWE-{raw}")
            port = item.attrib.get("port", "")
            cases.append(
                make_case(
                    kind="nessus",
                    finding_id=plugin,
                    title=item.attrib.get("pluginName", ""),
                    description=xml_text(xml_find(item, "description")) or xml_text(xml_find(item, "synopsis")),
                    cves=cves_of(*cves),
                    cwes=cwes,
                    product=host,
                    component=item.attrib.get("svc_name") or port,
                    severity=str(severity),
                    remediation=xml_text(xml_find(item, "solution")),
                    output=xml_text(xml_find(item, "plugin_output")),
                    location=f"{host}:{port}" if port else host,
                    raw={"pluginID": plugin, "host": host, "port": port},
                )
            )
    return cases


def parse_qualys_xml(root: ET.Element) -> list[Case]:
    cases: list[Case] = []
    for det in xml_findall(root, "DETECTION"):
        qid = xml_text(xml_find(det, "QID"))
        sev = QUALYS_SEV.get(xml_text(xml_find(det, "SEVERITY")), xml_text(xml_find(det, "SEVERITY")))
        if skip_info(str(sev)) and xml_text(xml_find(det, "SEVERITY")) in {"1", ""}:
            continue
        results = xml_text(xml_find(det, "RESULTS"))
        port = xml_text(xml_find(det, "PORT"))
        host = xml_text(xml_find(det, "FQDN"))
        cases.append(
            make_case(
                kind="qualys",
                finding_id=qid,
                title=f"Qualys QID {qid}",
                description=results or f"Qualys detection QID {qid}",
                cves=cves_of(results, ET.tostring(det, encoding="unicode")),
                product=host,
                component=xml_text(xml_find(det, "SERVICE")) or port,
                severity=str(sev),
                output=results,
                location=f"{host}:{port}" if port else host,
                raw={"QID": qid, "host": host, "port": port},
            )
        )
    vuln_cases: list[Case] = []
    for host_el in list(root.iter()):
        if local_tag(host_el.tag) not in {"IP", "HOST"}:
            continue
        host = host_el.attrib.get("value") or host_el.attrib.get("name") or xml_text(xml_find(host_el, "IP"))
        for vuln in host_el:
            if local_tag(vuln.tag) != "VULN":
                continue
            qid = vuln.attrib.get("number") or xml_text(xml_find(vuln, "QID"))
            sev_n = vuln.attrib.get("severity") or xml_text(xml_find(vuln, "SEVERITY"))
            severity = QUALYS_SEV.get(sev_n, sev_n)
            if skip_info(str(severity)) and sev_n in {"1", ""}:
                continue
            title = xml_text(xml_find(vuln, "TITLE"))
            desc = xml_text(xml_find(vuln, "DIAGNOSIS")) or xml_text(xml_find(vuln, "CONSEQUENCE")) or title
            cve_ids = [xml_text(c) for c in vuln.iter() if local_tag(c.tag) in {"CVE_ID", "CVE"} and xml_text(c)]
            port = vuln.attrib.get("port") or xml_text(xml_find(vuln, "PORT"))
            vuln_cases.append(
                make_case(
                    kind="qualys",
                    finding_id=qid,
                    title=title or f"Qualys QID {qid}",
                    description=desc,
                    cves=cves_of(*cve_ids, desc),
                    product=str(host or ""),
                    component=str(port or ""),
                    severity=str(severity),
                    remediation=xml_text(xml_find(vuln, "SOLUTION")),
                    output=xml_text(xml_find(vuln, "RESULT")) or xml_text(xml_find(vuln, "RESULTS")),
                    location=f"{host}:{port}" if port else str(host or ""),
                    raw={"QID": qid, "host": host, "port": port},
                )
            )
    return vuln_cases or cases


def parse_openvas_xml(root: ET.Element) -> list[Case]:
    cases: list[Case] = []
    for result in xml_findall(root, "result"):
        nvt = xml_find(result, "nvt")
        oid = (nvt.attrib.get("oid") if nvt is not None else "") or xml_text(xml_find(result, "nvt"))
        title = xml_text(xml_find(nvt, "name") if nvt is not None else None) or xml_text(xml_find(result, "name"))
        threat = xml_text(xml_find(result, "threat")) or xml_text(xml_find(result, "severity"))
        host_el = xml_find(result, "host")
        host = xml_text(host_el)
        if host_el is not None and not host:
            host = host_el.attrib.get("name", "")
        port = xml_text(xml_find(result, "port"))
        desc = xml_text(xml_find(result, "description"))
        cve_text = xml_text(xml_find(nvt, "cve") if nvt is not None else None)
        solution = ""
        if nvt is not None:
            for part in xml_text(xml_find(nvt, "tags")).split("|"):
                if part.startswith("solution="):
                    solution = part.split("=", 1)[1]
        if skip_info(threat) and threat.lower() in {"informational", "log", ""}:
            continue
        cases.append(
            make_case(
                kind="openvas",
                finding_id=oid,
                title=title,
                description=desc or title,
                cves=cves_of(cve_text, desc),
                product=host,
                component=port,
                severity=threat,
                remediation=solution,
                output=desc,
                location=f"{host}:{port}" if port else host,
                raw={"oid": oid, "host": host, "port": port},
            )
        )
    return cases


def classic_json_cases(kind: str, data: Any) -> list[Case]:
    rows = flatten_rows(data, ("findings", "vulnerabilities", "detections", "results", "hosts"))
    cases: list[Case] = []
    for row in rows:
        if kind == "qualys":
            qid = str(row.get("QID") or row.get("qid") or "")
            cases.append(
                make_case(
                    kind="qualys",
                    finding_id=qid,
                    title=str(row.get("title") or row.get("TITLE") or f"Qualys QID {qid}"),
                    description=str(row.get("diagnosis") or row.get("RESULTS") or row.get("results") or ""),
                    cves=cves_of(row.get("cve"), row.get("cves"), row.get("CVE_ID"), row),
                    product=str(row.get("dns") or row.get("ip") or row.get("IP") or ""),
                    component=str(row.get("port") or row.get("PORT") or ""),
                    severity=QUALYS_SEV.get(str(row.get("severity") or row.get("SEVERITY") or ""), str(row.get("severity") or "")),
                    remediation=str(row.get("solution") or row.get("SOLUTION") or ""),
                    output=str(row.get("results") or row.get("RESULTS") or ""),
                    location=str(row.get("ip") or row.get("IP") or ""),
                    raw=row,
                )
            )
        elif kind == "nessus":
            plugin = str(row.get("pluginID") or row.get("plugin_id") or "")
            cases.append(
                make_case(
                    kind="nessus",
                    finding_id=plugin,
                    title=str(row.get("pluginName") or row.get("plugin_name") or ""),
                    description=str(row.get("description") or row.get("synopsis") or ""),
                    cves=cves_of(row.get("cve"), row.get("cves"), row),
                    product=str(row.get("host") or row.get("hostname") or ""),
                    component=str(row.get("port") or ""),
                    severity=str(row.get("severity") or row.get("risk_factor") or ""),
                    remediation=str(row.get("solution") or ""),
                    output=str(row.get("output") or row.get("plugin_output") or ""),
                    location=str(row.get("host") or ""),
                    raw=row,
                )
            )
        else:
            nvt = row.get("nvt") if isinstance(row.get("nvt"), dict) else {}
            oid = str(nvt.get("oid") or row.get("oid") or "")
            cases.append(
                make_case(
                    kind="openvas",
                    finding_id=oid,
                    title=str(nvt.get("name") or row.get("name") or ""),
                    description=str(row.get("description") or ""),
                    cves=cves_of(nvt.get("cve"), row.get("cve"), row),
                    product=str(row.get("host") or ""),
                    component=str(row.get("port") or ""),
                    severity=str(row.get("threat") or row.get("severity") or ""),
                    remediation=str(row.get("solution") or ""),
                    location=str(row.get("host") or ""),
                    raw=row,
                )
            )
    return cases


def classic_csv_cases(kind: str, rows: list[dict[str, str]], get) -> list[Case]:
    cases: list[Case] = []
    for row in rows:
        if kind == "qualys":
            qid = get(row, "QID")
            cases.append(
                make_case(
                    kind="qualys",
                    finding_id=qid,
                    title=get(row, "Title", "Vulnerability"),
                    description=get(row, "Threat", "Impact", "Results", "Title"),
                    cves=cves_of(get(row, "CVE ID", "CVE", "CVEs")),
                    product=get(row, "DNS", "IP", "Host"),
                    component=get(row, "Port"),
                    severity=QUALYS_SEV.get(get(row, "Severity"), get(row, "Severity")),
                    remediation=get(row, "Solution"),
                    output=get(row, "Results"),
                    location=get(row, "IP", "DNS", "Host"),
                    raw=dict(row),
                )
            )
        elif kind == "nessus":
            cases.append(
                make_case(
                    kind="nessus",
                    finding_id=get(row, "Plugin ID", "PluginID"),
                    title=get(row, "Name", "Plugin Name"),
                    description=get(row, "Description", "Synopsis"),
                    cves=cves_of(get(row, "CVE")),
                    product=get(row, "Host", "IP"),
                    component=get(row, "Port"),
                    severity=get(row, "Risk", "Severity"),
                    remediation=get(row, "Solution"),
                    output=get(row, "Plugin Output"),
                    location=get(row, "Host"),
                    raw=dict(row),
                )
            )
        else:
            cases.append(
                make_case(
                    kind="openvas",
                    finding_id=get(row, "OID", "NVT OID", "NVT"),
                    title=get(row, "NVT Name", "NVT", "Name"),
                    description=get(row, "Summary", "Description"),
                    cves=cves_of(get(row, "CVEs", "CVE")),
                    product=get(row, "IP", "Hostname", "Host"),
                    component=get(row, "Port"),
                    severity=get(row, "Severity", "CVSS", "Threat"),
                    remediation=get(row, "Solution"),
                    location=get(row, "IP", "Hostname"),
                    raw=dict(row),
                )
            )
    return cases
