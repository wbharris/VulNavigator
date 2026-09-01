"""Extract structured hints from a free-text finding write-up."""

from __future__ import annotations

import re

from vulnavigator.artifacts import extract_artifacts
from vulnavigator.heuristics import mentions_rce, mentions_sensitive_data
from vulnavigator.models import Case
_CRITICAL = re.compile(r"\bcritical\b", re.I)
_INTERNET = re.compile(
    r"internet[-\s]?facing|public[-\s]?facing|client[-\s]?facing|"
    r"\bremotely\b|\bremote attacker\b|\blaunch(?:ed)? the attack remotely\b|"
    r"\blaunched remotely\b|\bperformed from remote\b|\bfrom remote\b|"
    r"\bunauthenticated remote\b|\bunauthenticated,\s*remote\b|"
    r"\bunauthenticated attacker\b|"
    r"password recovery endpoint|exploited remotely|"
    r"carried out remotely|REST API|plugin for WordPress",
    re.I,
)
_LOCAL_ONLY = re.compile(
    r"malicious package|package manager|local attacker|physical access|--destdir",
    re.I,
)
_WEB_CWE = frozenset(
    {
        "CWE-77",
        "CWE-78",
        "CWE-79",
        "CWE-89",
        "CWE-93",
        "CWE-203",
        "CWE-204",
        "CWE-285",
        "CWE-287",
        "CWE-352",
        "CWE-434",
        "CWE-639",
        "CWE-306",
        "CWE-862",
        "CWE-918",
        "CWE-1336",
        "CWE-1333",
        "CWE-284",
        "CWE-425",
        "CWE-863",
        "CWE-601",
        "CWE-288",
        "CWE-90",
        "CWE-98",
        "CWE-1385",
        "CWE-384",
        "CWE-611",
        "CWE-502",
        "CWE-915",
        "CWE-307",
        "CWE-1004",
        "CWE-269",
    }
)
_NO_AI = re.compile(r"no a[il]\b|not .*(ai|al) component|no (ai|al) components", re.I)
_NO_FRAUD = re.compile(r"fraud risk is not|not currently suspected|no fraud", re.I)
_NO_EXPLOIT = re.compile(
    r"exploitability has not been confirmed|not been confirmed|no evidence.{0,40}exploitation",
    re.I,
)
_OUTDATED = re.compile(r"\boutdated\b", re.I)
_POC_HEAD = re.compile(
    r"(?im)^(?:poc|p\.o\.c\.|proof[-\s]of[-\s]concept|exploit(?:\s+steps)?)\s*[:\-]\s*(.+)$"
)
_DISC_HEAD = re.compile(
    r"(?im)^(?:how\s+(?:it|the\s+(?:model|agent|scanner|finder))\s+found|discovery|analysis|root\s+cause)\s*[:\-]\s*(.+)$"
)


def _section_after(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    start = match.start(1)
    rest = text[start:]
    nxt = re.search(r"\n(?:[A-Z][^\n]{0,40}:|\n\n)", rest[1:])
    chunk = rest[: nxt.start() + 1] if nxt else rest
    return chunk.strip()


def apply_narrative(case: Case) -> Case:
    extract_artifacts(case)
    blob = f"{case.title}\n{case.description}"
    if not blob.strip():
        return case

    if case.asset_internet_facing is None and _INTERNET.search(blob):
        case.asset_internet_facing = True
    if case.asset_internet_facing is None and not _LOCAL_ONLY.search(blob):
        if any(cwe in _WEB_CWE for cwe in case.cwes):
            case.asset_internet_facing = True
    if case.asset_ai_system is None and _NO_AI.search(blob):
        case.asset_ai_system = False
    if case.asset_fraud_relevant is None and _NO_FRAUD.search(blob):
        case.asset_fraud_relevant = False
    if not case.source_severity and _CRITICAL.search(blob):
        case.source_severity = "critical"
    if not case.data_class and mentions_sensitive_data(blob):
        case.data_class = "sensitive-business"
    poc = _section_after(_POC_HEAD, blob)
    if poc and not case.evidence.poc:
        case.evidence.poc = poc
    disc = _section_after(_DISC_HEAD, blob)
    if disc and not case.evidence.discovery:
        case.evidence.discovery = disc
    if _NO_EXPLOIT.search(blob) and not case.evidence.poc:
        case.evidence.reproduced = False
        case.evidence.sandbox = False
    if mentions_rce(blob) and not case.cves and not case.cwes:
        case.cwes.append("CWE-94")
    if _OUTDATED.search(blob) and not case.product:
        case.component = case.component or "outdated application component"
    if (
        case.source_kind in {"unknown", "generic", "mythos"}
        and len(blob) > 200
        and not case.cves
        and not case.detected_tool
    ):
        # Prose ticket / analyst write-up, not a Mythos JSON object or scanner paste
        if "mythos" not in blob.lower() and "daybreak" not in blob.lower():
            case.source_kind = "narrative"
            case.source = case.source or "narrative"
    if case.source_kind == "narrative" and (not case.title or case.title == blob.splitlines()[0][:120]) and mentions_rce(blob):
        case.title = "Outdated internet-facing application component with potential RCE"
    return case
