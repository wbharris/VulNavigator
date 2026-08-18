"""Scanner and interchange intake."""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from vulnavigator.models import Case
from vulnavigator.scanners.classic import (
    classic_csv_cases,
    classic_json_cases,
    parse_nessus_xml,
    parse_openvas_xml,
    parse_qualys_xml,
)
from vulnavigator.scanners.common import SCANNER_KINDS, alias_source, local_tag, skip_info, xml_findall
from vulnavigator.scanners.extended import (
    JSON_PARSERS,
    detect_extended_json,
    parse_burp_xml,
    parse_rapid7_xml,
    parse_zap_xml,
)

__all__ = [
    "SCANNER_KINDS",
    "alias_source",
    "cases_from_scanner_json",
    "looks_like_csv",
    "looks_like_jsonl",
    "parse_jsonl",
    "parse_scanner_csv",
    "parse_scanner_xml",
]


def detect_xml_kind(root: ET.Element) -> str:
    tag = local_tag(root.tag).lower()
    if tag == "nessusclientdata_v2" or xml_findall(root, "ReportItem"):
        return "nessus"
    if tag in {"nexposereport", "nexposesimplexmlexport", "nexposesimplexmle"} or "nexpose" in tag:
        return "rapid7"
    if tag in {"issues", "burp"} or xml_findall(root, "issue") and xml_findall(root, "issueDetail"):
        return "burp"
    if tag == "owaspzapreport" or xml_findall(root, "alertitem"):
        return "zap"
    blob = tag.upper()
    if "QUALYS" in blob or xml_findall(root, "QID") or xml_findall(root, "DETECTION"):
        return "qualys"
    if tag == "scan" and xml_findall(root, "VULN"):
        return "qualys"
    if xml_findall(root, "nvt") or "openvas" in tag or "gmp" in tag:
        return "openvas"
    if tag == "report" and xml_findall(root, "result"):
        return "openvas"
    return ""


def parse_scanner_xml(text: str, source: str = "") -> list[Case]:
    root = ET.fromstring(text)
    kind = alias_source(source) if source else detect_xml_kind(root)
    parsers = {
        "nessus": parse_nessus_xml,
        "qualys": parse_qualys_xml,
        "openvas": parse_openvas_xml,
        "rapid7": parse_rapid7_xml,
        "burp": parse_burp_xml,
        "zap": parse_zap_xml,
    }
    if kind in parsers:
        return parsers[kind](root)
    guessed = detect_xml_kind(root)
    if guessed in parsers:
        return parsers[guessed](root)
    raise ValueError("XML is not a known scanner report (Qualys, OpenVAS, Nessus, Rapid7, Burp, ZAP)")


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
    if "nexposeid" in keys or "vulnerabilityid" in keys and "assetipaddress" in keys:
        return "rapid7"
    if "vulnerabilityid" in keys and "pkgname" in keys:
        return "trivy"
    if "cveid" in keys and ("devicename" in keys or "machinename" in keys):
        return "defender"
    if "snykid" in keys or "issueurl" in keys and "packagename" in keys:
        return "snyk"
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
        raise ValueError("CSV is not a recognized scanner export")
    rows = list(reader)
    if kind in {"qualys", "openvas", "nessus"}:
        cases = classic_csv_cases(kind, rows, _row_get)
    else:
        from vulnavigator.scanners.common import cves_of, make_case

        cases = []
        for row in rows:
            cases.append(
                make_case(
                    kind=kind,
                    finding_id=_row_get(row, "ID", "Issue ID", "CVE", "CVE ID", "Vulnerability ID"),
                    title=_row_get(row, "Title", "Name", "Vulnerability", "Alert"),
                    description=_row_get(row, "Description", "Summary", "Threat"),
                    cves=cves_of(_row_get(row, "CVE", "CVE ID", "CVEs")),
                    product=_row_get(row, "Host", "Asset", "Device name", "Package"),
                    severity=_row_get(row, "Severity", "Risk"),
                    remediation=_row_get(row, "Solution", "Remediation"),
                    raw=dict(row),
                )
            )
    return [c for c in cases if not skip_info(c.source_severity) or c.cves]


def looks_like_csv(text: str) -> bool:
    first = ""
    for line in text.splitlines():
        if line.strip():
            first = line
            break
    if "," not in first:
        return False
    try:
        headers = [_norm_header(h) for h in next(csv.reader(io.StringIO(first)))]
    except Exception:
        return False
    return bool(detect_csv_kind(headers))


def looks_like_jsonl(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 1:
        return False
    if not lines[0].lstrip().startswith("{"):
        return False
    try:
        json.loads(lines[0])
    except json.JSONDecodeError:
        return False
    if len(lines) == 1:
        return '"template-id"' in lines[0] or '"matched-at"' in lines[0]
    try:
        json.loads(lines[1])
        return True
    except json.JSONDecodeError:
        return False


def parse_jsonl(text: str, source: str = "") -> list[Case]:
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
    kind = alias_source(source) or detect_extended_json(rows) or "nuclei"
    parser = JSON_PARSERS.get(kind)
    if not parser:
        parser = JSON_PARSERS["nuclei"]
    return parser(rows)


def detect_json_kind(data: Any) -> str:
    ext = detect_extended_json(data)
    if ext:
        return ext
    blob = json.dumps(data).lower() if not isinstance(data, str) else data.lower()
    if "qid" in blob or "qualys" in blob:
        return "qualys"
    if "pluginid" in blob or "plugin_id" in blob or "plugin_name" in blob:
        return "nessus"
    if '"nvt"' in blob or "openvas" in blob or "greenbone" in blob:
        return "openvas"
    return ""


def cases_from_scanner_json(data: Any, source: str = "") -> list[Case] | None:
    kind = alias_source(source) if alias_source(source) in SCANNER_KINDS else detect_json_kind(data)
    kind = alias_source(kind)
    if kind not in SCANNER_KINDS:
        return None
    if kind in JSON_PARSERS:
        return JSON_PARSERS[kind](data)
    if kind in {"qualys", "openvas", "nessus"}:
        return classic_json_cases(kind, data)
    return None
