"""Pull structured artifacts out of free text without forcing a source_kind.

Does not reclassify Mythos vs Nessus from keywords in a sentence. It only
fills empty Case fields and sets ``detected_tool`` so validation can treat
raw pasted scanner notes as detections.
"""

from __future__ import annotations

import re

from vulnavigator.models import Case, Location

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CWE_RE = re.compile(r"CWE-\d+", re.I)

TOOL_RE = re.compile(
    r"\b(nessus|qualys|openvas|gvm|nexpose|insightvm|rapid7|trivy|snyk|nuclei|"
    r"burp|zap|codeql|semgrep|dependabot|inspector2?|wiz|prisma|orca|"
    r"crowdstrike|spotlight|defender|ghas)\b",
    re.I,
)
FINDING_ID_RE = re.compile(
    r"\b(?:qid|plugin(?:\s*id)?|template(?:-id)?|finding(?:\s*id)?|nvt|pluginid)"
    r"\s*[:=#]?\s*([A-Za-z0-9._:/-]{2,80})",
    re.I,
)
HOST_LABEL_RE = re.compile(
    r"\b(?:host|hostname|target(?:\s+host)?)\s*[:=]\s*([A-Za-z0-9._-]+)",
    re.I,
)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
ENDPOINT_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
FILELINE_RE = re.compile(r"\b((?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.\w+):(\d{1,6})\b")
COMPONENT_VER_RE = re.compile(
    r"\b([A-Za-z][\w.-]{1,48})(?:[@/]|[ \t]+v?)(\d+\.\d+(?:\.\d+){0,3}[a-z]?)\b"
)
POC_BLOCK_RE = re.compile(
    r"(?i)(?:poc|p\.o\.c\.|proof[-\s]of[-\s]concept|exploit(?:\s+steps)?|payload)\s*[:\-]\s*(\S.{8,400})"
)
REPLAY_HINT = re.compile(
    r"\b(sandbox|asan|replay|reproduced|curl |nc |wget |http(?:s)?://|crash|payload)\b",
    re.I,
)
DISCOVERY_PATH_RE = re.compile(
    r"(?i)\b(?:traced|found(?:\s+in)?|discovery|path)\b[^.\n]{0,40}"
    r"((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.\w+)"
)

_SKIP_COMPONENT = frozenset(
    {
        "cve",
        "cwe",
        "http",
        "https",
        "plugin",
        "host",
        "port",
        "version",
        "cvss",
        "on",
        "at",
        "in",
        "for",
        "with",
        "from",
        "to",
        "and",
        "the",
        "found",
    }
)


def infer_scanner_tool(text: str) -> str:
    match = TOOL_RE.search(text or "")
    return match.group(1).lower() if match else ""


def extract_artifacts(case: Case) -> Case:
    blob = f"{case.title}\n{case.description}\n{case.evidence.poc}\n{case.evidence.discovery}"
    if not blob.strip():
        return case

    if not case.detected_tool:
        case.detected_tool = infer_scanner_tool(blob)

    for match in CVE_RE.finditer(blob):
        cve = match.group(0).upper()
        if cve not in case.cves:
            case.cves.append(cve)
    for match in CWE_RE.finditer(blob):
        cwe = match.group(0).upper()
        if cwe not in case.cwes:
            case.cwes.append(cwe)

    if not case.finding_id:
        fid = FINDING_ID_RE.search(blob)
        if fid:
            case.finding_id = fid.group(1)

    if not case.host:
        labeled = HOST_LABEL_RE.search(blob)
        if labeled:
            case.host = labeled.group(1)
        else:
            ip = IP_RE.search(blob)
            if ip:
                case.host = ip.group(0)

    if not case.endpoint:
        ep = ENDPOINT_RE.search(blob)
        if ep:
            case.endpoint = ep.group(0).rstrip(".,;)")

    if not case.product or not case.version:
        for match in COMPONENT_VER_RE.finditer(blob):
            name, ver = match.group(1), match.group(2)
            if name.lower() in _SKIP_COMPONENT or name.upper().startswith("CVE"):
                continue
            if ver.count(".") >= 3:
                continue
            if not case.product:
                case.product = name
            if not case.version:
                case.version = ver
            break

    existing_paths = {loc.path for loc in case.locations}
    for match in FILELINE_RE.finditer(blob):
        path, line = match.group(1), int(match.group(2))
        if path not in existing_paths:
            case.locations.append(Location(path=path, line=line))
            existing_paths.add(path)

    if not case.evidence.poc:
        poc = POC_BLOCK_RE.search(blob)
        if poc and REPLAY_HINT.search(poc.group(1)):
            case.evidence.poc = poc.group(1).strip()

    if not case.evidence.discovery:
        disc = DISCOVERY_PATH_RE.search(blob)
        if disc:
            case.evidence.discovery = disc.group(0).strip()

    return case
