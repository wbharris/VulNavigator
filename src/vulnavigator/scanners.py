"""Qualys, OpenVAS/GVM, and Nessus intake."""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from vulnavigator.models import Case, Evidence, Location

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

SCANNER_KINDS = frozenset({"qualys", "openvas", "nessus"})

NESSUS_SEV = {"0": "informational", "1": "low", "2": "medium", "3": "high", "4": "critical"}
QUALYS_SEV = {"1": "informational", "2": "low", "3": "medium", "4": "high", "5": "critical"}


def alias_source(source: str) -> str:
    key = (source or "").strip().lower()
    if key in {"nexsus", "nexus", "tenable", "tenable.io", "tenable.sc"}:
        return "nessus"
    if key in {"gvm", "greenbone", "openvas/gvm"}:
        return "openvas"
    return key


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _text(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _find(el: ET.Element, name: str) -> ET.Element | None:
    for child in el:
        if _local(child.tag) == name:
            return child
    return None


def _findall(el: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in el.iter() if _local(c.tag) == name]


def _cves(*chunks: Any) -> list[str]:
    found: list[str] = []
    for chunk in chunks:
        if chunk is None:
            continue
        text = chunk if isinstance(chunk, str) else json.dumps(chunk)
        for match in CVE_RE.findall(text):
            cve = match.upper()
            if cve not in found:
                found.append(cve)
    return found


def _skip_info(severity: str) -> bool:
    return severity.lower() in {"informational", "info", "log", "none", ""}


def _case(
    *,
    kind: str,
    finding_id: str,
    title: str,
    description: str,
    cves: list[str],
    cwes: list[str],
    product: str,
    component: str,
    severity: str,
    remediation: str,
    output: str,
    host: str,
    port: str,
    raw: dict[str, Any],
) -> Case:
    loc = ""
    if host and port:
        loc = f"{host}:{port}"
    elif host:
        loc = host
    return Case(
        source=kind,
        source_kind=kind,
        finding_id=finding_id,
        rule_id=finding_id,
        title=title or f"{kind} {finding_id}".strip(),
        description=description,
        cves=cves,
        cwes=cwes,
        product=product or host,
        component=component or port,
        locations=[Location(path=loc)] if loc else [],
        evidence=Evidence(
            notes=" | ".join(x for x in (f"{kind} scanner detection", output) if x)
        ),
        source_severity=severity,
        raw=raw,
        remediation=[remediation] if remediation else [],
    )


# ── XML ──────────────────────────────────────────────────────────


def detect_xml_kind(root: ET.Element) -> str:
    tag = _local(root.tag).lower()
    if tag == "nessusclientdata_v2" or _findall(root, "ReportItem"):
        return "nessus"
    blob = _local(root.tag).upper()
    if "QUALYS" in blob or _findall(root, "QID") or _findall(root, "DETECTION"):
        return "qualys"
    if tag == "scan" and _findall(root, "VULN"):
        return "qualys"
    if _findall(root, "nvt") or "openvas" in tag or "gmp" in tag:
        return "openvas"
    if tag == "report" and _findall(root, "result"):
        return "openvas"
    return ""


def parse_nessus_xml(root: ET.Element) -> list[Case]:
    cases: list[Case] = []
    for host_el in _findall(root, "ReportHost"):
        host = host_el.attrib.get("name", "")
        for tag in host_el.iter():
            if _local(tag.tag) == "tag" and tag.attrib.get("name") == "host-ip":
                host = _text(tag) or host
        for item in host_el:
            if _local(item.tag) != "ReportItem":
                continue
            sev_n = item.attrib.get("severity", "0")
            severity = NESSUS_SEV.get(sev_n, item.attrib.get("risk_factor", sev_n))
            if _skip_info(severity) and sev_n == "0":
                continue
            plugin = item.attrib.get("pluginID", "")
            title = item.attrib.get("pluginName", "")
            port = item.attrib.get("port", "")
            svc = item.attrib.get("svc_name", "")
            cves = [_text(c).upper() for c in item if _local(c.tag) == "cve" and _text(c)]
            cves = _cves(*cves)
            cwes = [f"CWE-{_text(c)}" if not _text(c).upper().startswith("CWE-") else _text(c).upper()
                    for c in item if _local(c.tag) == "cwe" and _text(c)]
            desc = _text(_find(item, "description")) or _text(_find(item, "synopsis"))
            solution = _text(_find(item, "solution"))
            output = _text(_find(item, "plugin_output"))
            cases.append(
                _case(
                    kind="nessus",
                    finding_id=plugin,
                    title=title,
                    description=desc,
                    cves=cves,
                    cwes=cwes,
                    product=host,
                    component=svc or port,
                    severity=str(severity).lower(),
                    remediation=solution,
                    output=output,
                    host=host,
                    port=port,
                    raw={"pluginID": plugin, "host": host, "port": port},
                )
            )
    return cases


def parse_qualys_xml(root: ET.Element) -> list[Case]:
    cases: list[Case] = []
    for det in _findall(root, "DETECTION"):
        qid = _text(_find(det, "QID"))
        sev = QUALYS_SEV.get(_text(_find(det, "SEVERITY")), _text(_find(det, "SEVERITY")))
        if _skip_info(str(sev)) and _text(_find(det, "SEVERITY")) in {"1", ""}:
            continue
        results = _text(_find(det, "RESULTS"))
        port = _text(_find(det, "PORT"))
        host = _text(_find(det, "FQDN"))
        cases.append(
            _case(
                kind="qualys",
                finding_id=qid,
                title=f"Qualys QID {qid}",
                description=results or f"Qualys detection QID {qid}",
                cves=_cves(results, ET.tostring(det, encoding="unicode")),
                cwes=[],
                product=host,
                component=_text(_find(det, "SERVICE")) or port,
                severity=str(sev).lower(),
                remediation="",
                output=results,
                host=host,
                port=port,
                raw={"QID": qid, "host": host, "port": port},
            )
        )

    if cases:
        # Prefer richer <VULN> records when both exist
        pass

    vuln_cases: list[Case] = []
    for host_el in list(root.iter()):
        if _local(host_el.tag) not in {"IP", "HOST"}:
            continue
        host = host_el.attrib.get("value") or host_el.attrib.get("name") or _text(_find(host_el, "IP"))
        for vuln in host_el:
            if _local(vuln.tag) != "VULN":
                continue
            qid = vuln.attrib.get("number") or _text(_find(vuln, "QID"))
            sev_n = vuln.attrib.get("severity") or _text(_find(vuln, "SEVERITY"))
            severity = QUALYS_SEV.get(sev_n, sev_n)
            if _skip_info(str(severity)) and sev_n in {"1", ""}:
                continue
            title = _text(_find(vuln, "TITLE"))
            desc = _text(_find(vuln, "DIAGNOSIS")) or _text(_find(vuln, "CONSEQUENCE")) or title
            solution = _text(_find(vuln, "SOLUTION"))
            cve_ids = [_text(c) for c in vuln.iter() if _local(c.tag) in {"CVE_ID", "CVE"} and _text(c)]
            port = vuln.attrib.get("port") or _text(_find(vuln, "PORT"))
            vuln_cases.append(
                _case(
                    kind="qualys",
                    finding_id=qid,
                    title=title or f"Qualys QID {qid}",
                    description=desc,
                    cves=_cves(*cve_ids, desc),
                    cwes=[],
                    product=host,
                    component=port,
                    severity=str(severity).lower(),
                    remediation=solution,
                    output=_text(_find(vuln, "RESULT")) or _text(_find(vuln, "RESULTS")),
                    host=str(host or ""),
                    port=str(port or ""),
                    raw={"QID": qid, "host": host, "port": port},
                )
            )
    return vuln_cases or cases


def parse_openvas_xml(root: ET.Element) -> list[Case]:
    cases: list[Case] = []
    for result in _findall(root, "result"):
        nvt = _find(result, "nvt")
        oid = (nvt.attrib.get("oid") if nvt is not None else "") or _text(_find(result, "nvt"))
        title = _text(_find(nvt, "name") if nvt is not None else None) or _text(_find(result, "name"))
        threat = _text(_find(result, "threat")) or _text(_find(result, "severity"))
        try:
            score = float(threat)
            if score >= 9:
                severity = "critical"
            elif score >= 7:
                severity = "high"
            elif score >= 4:
                severity = "medium"
            elif score > 0:
                severity = "low"
            else:
                severity = "informational"
        except ValueError:
            severity = threat.lower() or "medium"
        if _skip_info(severity) and severity in {"informational", "log"}:
            continue
        host_el = _find(result, "host")
        host = _text(host_el)
        if host_el is not None and not host:
            host = host_el.attrib.get("name", "")
        port = _text(_find(result, "port"))
        desc = _text(_find(result, "description"))
        cve_text = _text(_find(nvt, "cve") if nvt is not None else None)
        solution = ""
        if nvt is not None:
            tags = _text(_find(nvt, "tags"))
            for part in tags.split("|"):
                if part.startswith("solution="):
                    solution = part.split("=", 1)[1]
        cases.append(
            _case(
                kind="openvas",
                finding_id=oid,
                title=title,
                description=desc or title,
                cves=_cves(cve_text, desc),
                cwes=[],
                product=host,
                component=port,
                severity=severity,
                remediation=solution,
                output=desc,
                host=host,
                port=port,
                raw={"oid": oid, "host": host, "port": port},
            )
        )
    return cases


def parse_scanner_xml(text: str, source: str = "") -> list[Case]:
    root = ET.fromstring(text)
    kind = alias_source(source) if source else detect_xml_kind(root)
    if kind == "nessus":
        return parse_nessus_xml(root)
    if kind == "qualys":
        return parse_qualys_xml(root)
    if kind == "openvas":
        return parse_openvas_xml(root)
    guessed = detect_xml_kind(root)
    if guessed == "nessus":
        return parse_nessus_xml(root)
    if guessed == "qualys":
        return parse_qualys_xml(root)
    if guessed == "openvas":
        return parse_openvas_xml(root)
    raise ValueError("XML is not a Qualys, OpenVAS, or Nessus report")


# ── CSV ──────────────────────────────────────────────────────────


def _norm_header(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.strip().lower())


def detect_csv_kind(headers: list[str]) -> str:
    keys = {_norm_header(h) for h in headers}
    if "qid" in keys:
        return "qualys"
    if "pluginid" in keys or ({"plugin", "risk", "host"} <= keys):
        return "nessus"
    if "nvt" in keys or "oid" in keys or "nvtname" in keys:
        return "openvas"
    return ""


def _row_get(row: dict[str, str], *names: str) -> str:
    mapped = {_norm_header(k): v for k, v in row.items()}
    for name in names:
        val = mapped.get(_norm_header(name), "")
        if val:
            return val.strip()
    return ""


def parse_scanner_csv(text: str, source: str = "") -> list[Case]:
    sample = text.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(sample))
    if not reader.fieldnames:
        raise ValueError("CSV has no header")
    kind = alias_source(source) if source else detect_csv_kind(list(reader.fieldnames))
    if kind not in SCANNER_KINDS:
        raise ValueError("CSV is not a Qualys, OpenVAS, or Nessus export")
    cases: list[Case] = []
    for row in reader:
        if kind == "qualys":
            qid = _row_get(row, "QID")
            cases.append(
                _case(
                    kind="qualys",
                    finding_id=qid,
                    title=_row_get(row, "Title", "Vulnerability"),
                    description=_row_get(row, "Threat", "Impact", "Results", "Title"),
                    cves=_cves(_row_get(row, "CVE ID", "CVE", "CVEs")),
                    cwes=[],
                    product=_row_get(row, "DNS", "IP", "Host"),
                    component=_row_get(row, "Port"),
                    severity=QUALYS_SEV.get(_row_get(row, "Severity"), _row_get(row, "Severity").lower()),
                    remediation=_row_get(row, "Solution"),
                    output=_row_get(row, "Results"),
                    host=_row_get(row, "IP", "DNS", "Host"),
                    port=_row_get(row, "Port"),
                    raw=dict(row),
                )
            )
        elif kind == "nessus":
            sev = _row_get(row, "Risk", "Severity")
            cases.append(
                _case(
                    kind="nessus",
                    finding_id=_row_get(row, "Plugin ID", "PluginID"),
                    title=_row_get(row, "Name", "Plugin Name"),
                    description=_row_get(row, "Description", "Synopsis"),
                    cves=_cves(_row_get(row, "CVE")),
                    cwes=[],
                    product=_row_get(row, "Host", "IP"),
                    component=_row_get(row, "Port"),
                    severity=sev.lower(),
                    remediation=_row_get(row, "Solution"),
                    output=_row_get(row, "Plugin Output"),
                    host=_row_get(row, "Host"),
                    port=_row_get(row, "Port"),
                    raw=dict(row),
                )
            )
        else:
            cases.append(
                _case(
                    kind="openvas",
                    finding_id=_row_get(row, "OID", "NVT OID", "NVT"),
                    title=_row_get(row, "NVT Name", "NVT", "Name"),
                    description=_row_get(row, "Summary", "Description"),
                    cves=_cves(_row_get(row, "CVEs", "CVE")),
                    cwes=[],
                    product=_row_get(row, "IP", "Hostname", "Host"),
                    component=_row_get(row, "Port"),
                    severity=_row_get(row, "Severity", "CVSS", "Threat").lower(),
                    remediation=_row_get(row, "Solution"),
                    output=_row_get(row, "Summary"),
                    host=_row_get(row, "IP", "Hostname"),
                    port=_row_get(row, "Port"),
                    raw=dict(row),
                )
            )
    return [c for c in cases if not _skip_info(c.source_severity) or c.cves]


def looks_like_csv(text: str) -> bool:
    first = ""
    for line in text.splitlines():
        if line.strip():
            first = line
            break
    if "," not in first:
        return False
    headers = [_norm_header(h) for h in next(csv.reader(io.StringIO(first)))]
    return bool(detect_csv_kind(headers))


# ── JSON ─────────────────────────────────────────────────────────


def detect_json_kind(data: Any) -> str:
    blob = json.dumps(data).lower() if not isinstance(data, str) else data.lower()
    if "qid" in blob or "qualys" in blob:
        return "qualys"
    if "pluginid" in blob or "plugin_id" in blob or "plugin_name" in blob:
        return "nessus"
    if '"nvt"' in blob or "openvas" in blob or "greenbone" in blob:
        return "openvas"
    return ""


def _flatten_scanner_json(data: Any, kind: str) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("findings", "vulnerabilities", "detections", "results", "hosts"):
        val = data.get(key)
        if isinstance(val, list) and val and isinstance(val[0], dict):
            return [x for x in val if isinstance(x, dict)]
    if data.get("QID") or data.get("qid") or data.get("pluginID") or data.get("plugin_id"):
        return [data]
    return []


def cases_from_scanner_json(data: Any, source: str = "") -> list[Case] | None:
    kind = alias_source(source) if source in SCANNER_KINDS or alias_source(source) in SCANNER_KINDS else detect_json_kind(data)
    kind = alias_source(kind)
    if kind not in SCANNER_KINDS:
        return None
    rows = _flatten_scanner_json(data, kind)
    if not rows:
        return None
    cases: list[Case] = []
    for row in rows:
        if kind == "qualys":
            qid = str(row.get("QID") or row.get("qid") or "")
            cases.append(
                _case(
                    kind="qualys",
                    finding_id=qid,
                    title=str(row.get("title") or row.get("TITLE") or f"Qualys QID {qid}"),
                    description=str(row.get("diagnosis") or row.get("RESULTS") or row.get("results") or ""),
                    cves=_cves(row.get("cve"), row.get("cves"), row.get("CVE_ID"), row),
                    cwes=[],
                    product=str(row.get("dns") or row.get("ip") or row.get("IP") or ""),
                    component=str(row.get("port") or row.get("PORT") or ""),
                    severity=QUALYS_SEV.get(str(row.get("severity") or row.get("SEVERITY") or ""), str(row.get("severity") or "").lower()),
                    remediation=str(row.get("solution") or row.get("SOLUTION") or ""),
                    output=str(row.get("results") or row.get("RESULTS") or ""),
                    host=str(row.get("ip") or row.get("IP") or ""),
                    port=str(row.get("port") or row.get("PORT") or ""),
                    raw=row,
                )
            )
        elif kind == "nessus":
            plugin = str(row.get("pluginID") or row.get("plugin_id") or "")
            cases.append(
                _case(
                    kind="nessus",
                    finding_id=plugin,
                    title=str(row.get("pluginName") or row.get("plugin_name") or row.get("plugin_name") or ""),
                    description=str(row.get("description") or row.get("synopsis") or ""),
                    cves=_cves(row.get("cve"), row.get("cves"), row),
                    cwes=[],
                    product=str(row.get("host") or row.get("hostname") or ""),
                    component=str(row.get("port") or ""),
                    severity=str(row.get("severity") or row.get("risk_factor") or "").lower(),
                    remediation=str(row.get("solution") or ""),
                    output=str(row.get("output") or row.get("plugin_output") or ""),
                    host=str(row.get("host") or ""),
                    port=str(row.get("port") or ""),
                    raw=row,
                )
            )
        else:
            nvt = row.get("nvt") if isinstance(row.get("nvt"), dict) else {}
            oid = str(nvt.get("oid") or row.get("oid") or "")
            cases.append(
                _case(
                    kind="openvas",
                    finding_id=oid,
                    title=str(nvt.get("name") or row.get("name") or ""),
                    description=str(row.get("description") or ""),
                    cves=_cves(nvt.get("cve"), row.get("cve"), row),
                    cwes=[],
                    product=str(row.get("host") or ""),
                    component=str(row.get("port") or ""),
                    severity=str(row.get("threat") or row.get("severity") or "").lower(),
                    remediation=str(row.get("solution") or ""),
                    output=str(row.get("description") or ""),
                    host=str(row.get("host") or ""),
                    port=str(row.get("port") or ""),
                    raw=row,
                )
            )
    return cases
