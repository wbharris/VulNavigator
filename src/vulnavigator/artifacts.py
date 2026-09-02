"""Pull structured artifacts out of free text without forcing a source_kind.

Does not reclassify Mythos vs Nessus from keywords in a sentence. It only
fills empty Case fields and sets ``detected_tool`` so validation can treat
raw pasted scanner notes as detections.
"""

from __future__ import annotations

import re

from vulnavigator.data.phrase_cwe import compiled_bug_cwe
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
        "versions",
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
        "system",
        "site",
        "server",
        "service",
        "application",
        "software",
        "including",
        "prior",
        "unknown",
        "part",
        "file",
        "argument",
        "index",
        "module",
        "this",
        "that",
        "affects",
        "insufficient",
        "improper",
        "earlier",
        "later",
        "missing",
        "unauthorized",
        "unauthenticated",
        "handling",
        "validation",
        "exposure",
        "policy",
        "enforcement",
        "neutralization",
        "limitation",
        "generation",
        "encoding",
        "control",
    }
)

_BUG_CWE = compiled_bug_cwe()

_IN_PRODUCT = re.compile(
    r"\bin\s+(.{3,80}?)\s+(?:(?:up to|before|prior to)\s+)?(?:v(?:ersion)?\s*)?(\d+\.\d+(?:\.\d+){0,2}[A-Za-z]{0,6})",
    re.I,
)
_DETECTED_IN = re.compile(
    r"(?:detected|identified|found)\s+in\s+"
    r"([A-Z][A-Za-z0-9.+-]*(?:\s+[A-Z0-9][A-Za-z0-9.+-]*){0,3})\s+v?(\d+\.\d+)",
)
_NAMED_PRIOR = re.compile(
    r"\b([A-Za-z][A-Za-z0-9.+-]{2,48})\b.{0,200}"
    r"(?:versions prior to|prior to version|before version|branch prior to|prior to)\s+"
    r"(?:FW)?v?(\d+\.\d+(?:\.\d+){0,2})",
    re.I,
)
_IN_SERIES = re.compile(
    r"\bin\s+([A-Z][A-Za-z0-9.+-]{2,40}(?:\s+[A-Z][A-Za-z0-9.+-]{2,40}){0,3})\s+series\b",
)
_IS_AN = re.compile(
    r"^([A-Za-z][A-Za-z0-9.+-]{1,48})\s+is an?\b",
    re.I,
)
_LEAD_IS = re.compile(
    r"^(?:The\s+)?([A-Z][A-Za-z0-9.+-]{1,48}(?:\s+[A-Z][A-Za-z0-9.+-]{1,48}){0,5})"
    r"(?:\s+v?\d+(?:\.\d+)*)?(?:\s*\([^)]{0,80}\))?\s+is\b",
)
_PAREN_VER = re.compile(
    r"(?:the\s+)?([A-Z][A-Za-z0-9][\w.+-]*(?:\s+[A-Z][A-Za-z0-9][\w.+-]*){0,5})"
    r"\s+\(\s*v?(\d+\.\d+(?:\.\d+){0,2})",
)
_LEAD_VERSIONS = re.compile(
    r"^(?:[A-Z][A-Za-z]+(?:'s)\s+)?([A-Za-z][\w.+-]{1,40}(?:\s+[A-Za-z][\w.+-]{1,40}){0,4})"
    r"\s+versions?\s+up to",
    re.I,
)
_ISSUE_AFFECTS = re.compile(
    r"This issue affects\s+([^:\n]{2,80}?)\s*:",
    re.I,
)
_MW_EXT = re.compile(
    r"MediaWiki\s*[-–]\s*([A-Za-z][\w]+(?:\s+[A-Za-z][\w]+){0,3})\s+(?:Extension|extension|Skin|skin)",
    re.I,
)
_THE_CRATE = re.compile(r"The\s+`([A-Za-z0-9._-]+)`\s+crate\b")
_IN_VERSION = re.compile(
    r"(?:In version|Version|Versions up to and including)\s+v?(\d+\.\d+(?:\.\d+){0,2})\b",
    re.I,
)
_FLAW_IN_VERSIONS = re.compile(
    r"^([A-Za-z][A-Za-z0-9.+-]{2,48})\b.{0,240}flaw in versions\s+v?(\d+\.\d+)",
    re.I,
)
_IN_UPTO_HASH = re.compile(
    r"\bin\s+([A-Za-z][\w.-]*(?:\s+[A-Za-z][\w.-]*){0,4})\s+up to\s+[0-9a-f]{7,}\b",
    re.I,
)
_PROVIDES = re.compile(r"^([A-Za-z][A-Za-z0-9.+-]{2,40})\s+provides\b", re.I | re.M)
_AFFECTED_PRODUCTS = re.compile(r"Affected Products:\s*([^\n(]+)", re.I)
_WP_PLUGIN = re.compile(r"(?:The\s+)?(.{3,80}?)\s+plugin for WordPress", re.I)
_AND_EARLIER = re.compile(
    r"versions?\s+v?(\d+\.\d[\w.]*)\s+and earlier",
    re.I,
)
_AND_BELOW = re.compile(
    r"versions?\s+v?(\d+\.\d[\w.]*)\s+and below",
    re.I,
)
_ABS_FILE = re.compile(
    r"(?:^|[\s(\"'])(/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,8})\b"
)
_REL_FILE = re.compile(
    r"\b((?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:php|asp|aspx|jsp|java|py|js|ts|go|c|cc|cpp|cxx|h|hh|hpp|rb|cgi))(?!\w)",
    re.I,
)
_PUBLIC_EXPLOIT = re.compile(
    r"exploit has been (?:released|disclosed|published)|"
    r"public(?:ly)? (?:available )?exploit|"
    r"exploit is now public|"
    r"poc (?:is|has been) (?:available|released)",
    re.I,
)



_BAD_PRODUCT_START = frozenset(
    {
        "a",
        "an",
        "the",
        "this",
        "that",
        "which",
        "when",
        "due",
        "insufficient",
        "improper",
        "exposure",
        "missing",
        "unauthorized",
        "unauthenticated",
        "remote",
        "local",
        "multiple",
        "affected",
        "earlier",
        "later",
        "vulnerability",
        "issue",
        "flaw",
        "bug",
        "error",
        "security",
        "malicious",
        "crafted",
        "attacker",
        "handling",
        "input",
        "validation",
        "control",
        "limitation",
        "neutralization",
        "encoding",
        "generation",
        "code",
        "policy",
        "enforcement",
        "files",
        "non-executable",
        "executable",
        "versions",
        "version",
        "including",
        "prior",
        "unknown",
        "part",
        "file",
        "argument",
        "index",
        "module",
        "system",
        "server",
        "service",
        "application",
        "software",
        "plugin",
    }
)


def _ok_product(name: str) -> bool:
    name = (name or "").strip().strip("`.,;:\"'")
    if not name or len(name) < 2:
        return False
    if re.search(r"\.\s", name) or ":" in name or ";" in name:
        return False
    words = name.split()
    if not words or len(words) > 8:
        return False
    first = words[0].lower().strip("'\"")
    if first in _SKIP_COMPONENT or first in _BAD_PRODUCT_START:
        return False
    return True


def _set_product(case: Case, name: str, ver: str | None = None) -> None:
    name = re.sub(r"^(?:the|a|an)\s+", "", (name or "").strip(), flags=re.I)
    name = name.strip(" `.,;:\"'")
    if not _ok_product(name):
        return
    if not case.product:
        case.product = name
    if ver and not case.version:
        case.version = ver


def cwes_from_text(text: str) -> list[str]:
    """CWEs implied by phrases in the write-up (training/scoring)."""
    found: list[str] = []
    blob = text or ""
    for pattern, cwe in _BUG_CWE:
        if pattern.search(blob) and cwe not in found:
            found.append(cwe)
    return found


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

    for pattern, cwe in _BUG_CWE:
        if pattern.search(blob) and cwe not in case.cwes:
            case.cwes.append(cwe)

    if not case.product or not case.version:
        lead_is = _LEAD_IS.search(blob.strip())
        if lead_is:
            _set_product(case, lead_is.group(1))
        lead = _IS_AN.search(blob.strip())
        if lead:
            _set_product(case, lead.group(1))
        provides = _PROVIDES.search(blob.strip())
        if provides:
            _set_product(case, provides.group(1))
        crate = _THE_CRATE.search(blob)
        if crate:
            _set_product(case, crate.group(1))
        paren = _PAREN_VER.search(blob)
        if paren:
            _set_product(case, paren.group(1), paren.group(2))
        lead_ver = _LEAD_VERSIONS.search(blob.strip())
        if lead_ver:
            _set_product(case, lead_ver.group(1))
        mw = _MW_EXT.search(blob)
        if mw:
            _set_product(case, f"MediaWiki {mw.group(1).strip()}")
        issue_aff = _ISSUE_AFFECTS.search(blob)
        if issue_aff:
            _set_product(case, issue_aff.group(1).strip())
        affected = _AFFECTED_PRODUCTS.search(blob)
        if affected:
            _set_product(case, affected.group(1).strip())
        wp = _WP_PLUGIN.search(blob)
        if wp:
            _set_product(case, wp.group(1).strip())
        earlier = _AND_EARLIER.search(blob) or _AND_BELOW.search(blob)
        if earlier and not case.version:
            case.version = earlier.group(1)
        ver = _IN_VERSION.search(blob)
        if ver and not case.version:
            case.version = ver.group(1)
        series = _IN_SERIES.search(blob)
        if series:
            _set_product(case, series.group(1))
        detected = _DETECTED_IN.search(blob)
        if detected:
            _set_product(case, detected.group(1), detected.group(2))
        for named in _NAMED_PRIOR.finditer(blob):
            _set_product(case, named.group(1), named.group(2))
            if case.product and case.version:
                break
        flaw = _FLAW_IN_VERSIONS.search(blob.strip())
        if flaw:
            _set_product(case, flaw.group(1), flaw.group(2))
        hashed = _IN_UPTO_HASH.search(blob)
        if hashed:
            _set_product(case, hashed.group(1).strip())
        if not case.product:
            inbound = _IN_PRODUCT.search(blob)
            if inbound:
                _set_product(case, inbound.group(1), inbound.group(2))
        if not case.product or not case.version:
            for match in COMPONENT_VER_RE.finditer(blob):
                name, ver = match.group(1), match.group(2)
                if name.lower() in _SKIP_COMPONENT or name.upper().startswith("CVE"):
                    continue
                if not _ok_product(name):
                    continue
                if ver.count(".") >= 3:
                    continue
                _set_product(case, name, ver)
                break

    existing_paths = {loc.path for loc in case.locations}
    for match in FILELINE_RE.finditer(blob):
        path, line = match.group(1), int(match.group(2))
        if path not in existing_paths:
            case.locations.append(Location(path=path, line=line))
            existing_paths.add(path)
    for match in list(_ABS_FILE.finditer(blob)) + list(_REL_FILE.finditer(blob)):
        path = match.group(1)
        if path not in existing_paths:
            case.locations.append(Location(path=path))
            existing_paths.add(path)

    if not case.evidence.poc:
        poc = POC_BLOCK_RE.search(blob)
        if poc and REPLAY_HINT.search(poc.group(1)):
            case.evidence.poc = poc.group(1).strip()

    if _PUBLIC_EXPLOIT.search(blob):
        note = "Write-up says a public exploit/PoC exists (not attached)."
        if note not in (case.evidence.notes or ""):
            case.evidence.notes = (case.evidence.notes + " " + note).strip()

    if not case.evidence.discovery:
        disc = DISCOVERY_PATH_RE.search(blob)
        if disc:
            case.evidence.discovery = disc.group(0).strip()

    return case
