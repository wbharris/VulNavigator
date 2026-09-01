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

_BUG_CWE = (
    (re.compile(r"server[- ]side template injection|\bsti\b", re.I), "CWE-1336"),
    (re.compile(r"sql\s*injection|\bsqli\b|arbitrary SQL|execute arbitrary SQL", re.I), "CWE-89"),
    (
        re.compile(
            r"cross[- ]site scripting|\bxss\b|save javascript|"
            r"javascript is executed|javascript execution|"
            r"execute arbitrary JavaScript|HTML injection|"
            r"inject scripts or HTML",
            re.I,
        ),
        "CWE-79",
    ),
    (re.compile(r"cross[- ]site request forgery|\bcsrf\b", re.I), "CWE-352"),
    (re.compile(r"server[- ]side request forgery|\bssrf\b", re.I), "CWE-918"),
    (re.compile(r"escape the directory|path restriction", re.I), "CWE-24"),
    (re.compile(r"path traversal|directory traversal", re.I), "CWE-22"),
    (re.compile(r"unrestricted (?:file )?upload|arbitrary file upload", re.I), "CWE-434"),
    (
        re.compile(
            r"header injection|\bcrlf\b|CR\s*&\s*LF|CRLF|CR\s+and\s+LF",
            re.I,
        ),
        "CWE-93",
    ),
    (re.compile(r"insecure direct object|\bidor\b", re.I), "CWE-639"),
    (
        re.compile(
            r"authorization bypass|missing permission checks|incorrect permission",
            re.I,
        ),
        "CWE-863",
    ),
    (re.compile(r"open redirect", re.I), "CWE-601"),
    (
        re.compile(
            r"missing authorization|unable to edit or delete",
            re.I,
        ),
        "CWE-862",
    ),
    (
        re.compile(
            r"missing authentication|no authentication|without any authentication|"
            r"unauthenticated attacker|exploitable without any authentication",
            re.I,
        ),
        "CWE-306",
    ),
    (re.compile(r"not tracked by|integrity check", re.I), "CWE-353"),
    (
        re.compile(
            r"weakening the subsequent encryption|weaken(?:s|ed|ing)? .{0,40}encryption",
            re.I,
        ),
        "CWE-327",
    ),
    (
        re.compile(
            r"initialization vector|returned the initial IV",
            re.I,
        ),
        "CWE-330",
    ),
    (
        re.compile(
            r"xml external entity|\bxxe\b|improper parsing of XML",
            re.I,
        ),
        "CWE-611",
    ),
    (re.compile(r"control characters|escape sequences|ANSI escape", re.I), "CWE-150"),
    (re.compile(r"os command", re.I), "CWE-78"),
    (re.compile(r"command injection|execute arbitrary command|arbitrary command", re.I), "CWE-77"),
    (
        re.compile(r"heap[- ]based buffer overflow|heap[- ]buffer[- ]overflow", re.I),
        "CWE-122",
    ),
    (
        re.compile(
            r"stack[- ]based buffer overflow|stack overflow|allocation on the stack",
            re.I,
        ),
        "CWE-121",
    ),
    (re.compile(r"buffer overflow|overflow the .{0,120}protocol|\boverflow the\b", re.I), "CWE-119"),
    (
        re.compile(
            r"out[- ]of[- ]bounds write|out of bounds write|out[- ]of[- ]bounds memory write",
            re.I,
        ),
        "CWE-787",
    ),
    (
        re.compile(
            r"out[- ]of[- ]bounds read|out of bounds read|out[- ]of[- ]bounds heap read|"
            r"\boob read\b|without valid bounds checking",
            re.I,
        ),
        "CWE-125",
    ),
    (re.compile(r"use[- ]after[- ]free", re.I), "CWE-416"),
    (re.compile(r"integer overflow|integer wraparound|overflows and underflows", re.I), "CWE-190"),
    (re.compile(r"integer underflow|\bunderflows\b", re.I), "CWE-191"),
    (re.compile(r"null pointer|null dereference", re.I), "CWE-476"),
    (
        re.compile(
            r"memory leak|never freed|without freeing|leaks approximately",
            re.I,
        ),
        "CWE-401",
    ),
    (re.compile(r"infinite loop", re.I), "CWE-835"),
    (
        re.compile(
            r"regular expression denial of service|\bredos\b|"
            r"inefficient regular expression|regular expression (?:complexity|exponential blowup)",
            re.I,
        ),
        "CWE-1333",
    ),
    (re.compile(r"undefined behavior", re.I), "CWE-758"),
    (re.compile(r"improper access control", re.I), "CWE-284"),
    (re.compile(r"unauthorized access", re.I), "CWE-287"),
    (
        re.compile(
            r"authentication bypass|bypass administrator authentication|"
            r"bypass authentication",
            re.I,
        ),
        "CWE-288",
    ),
    (re.compile(r"double free", re.I), "CWE-415"),
    (re.compile(r"format string", re.I), "CWE-134"),
    (re.compile(r"prototype pollution", re.I), "CWE-1321"),
    (
        re.compile(
            r"information disclosure|information leak|leak sensitive information|"
            r"obtain sensitive information|obtain information about|"
            r"exposure of sensitive information|local file read|\blfr\b|"
            r"full names of other users|enumerate the user names",
            re.I,
        ),
        "CWE-200",
    ),
    (
        re.compile(
            r"insecure deseriali[sz]ation|unsafe java deseriali[sz]ation|"
            r"deseriali[sz](?:e|ation|ing) of untrusted|deserializ(?:e|ing) untrusted|"
            r"pickle deseriali[sz]ation|malicious pickle",
            re.I,
        ),
        "CWE-502",
    ),
    (re.compile(r"race condition", re.I), "CWE-362"),
    (re.compile(r"divide by zero|division by zero", re.I), "CWE-369"),
    (re.compile(r"type confusion", re.I), "CWE-843"),
    (re.compile(r"off[- ]by[- ]one", re.I), "CWE-193"),
    (re.compile(r"uninitialized", re.I), "CWE-457"),
    (re.compile(r"same.origin|origin validation", re.I), "CWE-346"),
    (
        re.compile(
            r"clear[- ]?text(?: credentials)?|credentials in clear text|"
            r"plaintext (?:password|transmission)|transmitted in plaintext|"
            r"unencrypted (?:channel|traffic|\)|\s)|unsecured \(unencrypted\)",
            re.I,
        ),
        "CWE-319",
    ),
    (
        re.compile(
            r"sent in base64|reversible base64|base64(?:url)?(?: encoding)?.{0,40}(?:credential|password|cipher)|"
            r"not considered a strong cipher",
            re.I,
        ),
        "CWE-261",
    ),
    (re.compile(r"forced browsing|directly request", re.I), "CWE-425"),
    (re.compile(r"sudoers|privilege escalation|escalate privileges", re.I), "CWE-269"),
    (
        re.compile(
            r"authorization bypass through user[- ]controlled key|"
            r"iterate through predictable values|predictable values of",
            re.I,
        ),
        "CWE-639",
    ),
    (
        re.compile(
            r"php remote file inclusion|local file inclusion|\blfi\b|\brfi\b",
            re.I,
        ),
        "CWE-98",
    ),
    (
        re.compile(
            r"code injection|remote c[oa]de execution|\brce\b|execute malicious code",
            re.I,
        ),
        "CWE-94",
    ),
    (re.compile(r"improper encoding or escaping", re.I), "CWE-116"),
    (re.compile(r"mass assignment", re.I), "CWE-915"),
    (re.compile(r"ldap injection", re.I), "CWE-90"),
    (re.compile(r"decompression bombs?", re.I), "CWE-409"),
    (re.compile(r"dll search path", re.I), "CWE-427"),
    (
        re.compile(
            r"cross[- ]site websocket hijacking|\bcswsh\b|"
            r"accept connections from any origin|origin header validation|"
            r"origin header",
            re.I,
        ),
        "CWE-1385",
    ),
    (re.compile(r"missing httponly|httponly flag", re.I), "CWE-1004"),
    (
        re.compile(
            r"hijack an authenticated session|credentials as the session id",
            re.I,
        ),
        "CWE-384",
    ),
    (
        re.compile(
            r"brute[- ]force|without triggering lockout|unlimited password[- ]change",
            re.I,
        ),
        "CWE-307",
    ),
    (re.compile(r"windows device names", re.I), "CWE-67"),
    (re.compile(r"reduced entropy|bits of randomness", re.I), "CWE-331"),
    (re.compile(r"never released", re.I), "CWE-772"),
    (re.compile(r"long runtimes", re.I), "CWE-400"),
    (
        re.compile(
            r"requests against loopback|requests to local ip",
            re.I,
        ),
        "CWE-918",
    ),
    (re.compile(r"out of memory", re.I), "CWE-400"),

    (
        re.compile(
            r"unbounded (?:heap|memory)(?: allocation)?|unbounded (?:heap |memory )?allocation|"
            r"denial[- ]of[- ]service|heap exhaustion|OutOfMemoryError",
            re.I,
        ),
        "CWE-400",
    ),
    (
        re.compile(
            r"unbounded heap allocation|allocate a byte array of the declared length",
            re.I,
        ),
        "CWE-789",
    ),
    (re.compile(r"username enumeration|user enumeration", re.I), "CWE-204"),
    (re.compile(r"different error messages depending", re.I), "CWE-203"),
    (re.compile(r"improper authorization", re.I), "CWE-285"),
    (re.compile(r"improper authentication", re.I), "CWE-287"),
    (
        re.compile(
            r"skip email 2fa|incorrectly validate the password|"
            r"provides any password",
            re.I,
        ),
        "CWE-287",
    ),
    (re.compile(r"timing side[- ]channel", re.I), "CWE-208"),
)

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


TAUGHT_CWE = frozenset(cwe for _pat, cwe in _BUG_CWE)

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
