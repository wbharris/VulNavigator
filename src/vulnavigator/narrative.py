"""Extract structured hints from a free-text finding write-up."""

from __future__ import annotations

import re

from vulnavigator.heuristics import mentions_rce
from vulnavigator.models import Case
_CRITICAL = re.compile(r"\bcritical\b", re.I)
_INTERNET = re.compile(r"internet[-\s]?facing|public[-\s]?facing|client[-\s]?facing", re.I)
_NO_AI = re.compile(r"no a[il]\b|not .*(ai|al) component|no (ai|al) components", re.I)
_NO_FRAUD = re.compile(r"fraud risk is not|not currently suspected|no fraud", re.I)
_NO_EXPLOIT = re.compile(
    r"exploitability has not been confirmed|not been confirmed|no evidence.{0,40}exploitation",
    re.I,
)
_SENSITIVE = re.compile(r"sensitive (business )?data|pii|payment", re.I)
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
    blob = f"{case.title}\n{case.description}"
    if not blob.strip():
        return case

    if case.asset_internet_facing is None and _INTERNET.search(blob):
        case.asset_internet_facing = True
    if case.asset_ai_system is None and _NO_AI.search(blob):
        case.asset_ai_system = False
    if case.asset_fraud_relevant is None and _NO_FRAUD.search(blob):
        case.asset_fraud_relevant = False
    if not case.source_severity and _CRITICAL.search(blob):
        case.source_severity = "critical"
    if not case.data_class and _SENSITIVE.search(blob):
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
    if mentions_rce(blob) and "CWE-94" not in case.cwes and not case.cves and not case.cwes:
        case.cwes.append("CWE-94")
    if _OUTDATED.search(blob) and not case.product:
        case.component = case.component or "outdated application component"
    if case.source_kind in {"unknown", "generic", "mythos"} and len(blob) > 200 and not case.cves:
        # Prose ticket / analyst write-up, not a Mythos JSON object
        if "mythos" not in blob.lower() and "daybreak" not in blob.lower():
            case.source_kind = "narrative"
            case.source = case.source or "narrative"
    if case.source_kind == "narrative" and (not case.title or case.title == blob.splitlines()[0][:120]) and mentions_rce(blob):
        case.title = "Outdated internet-facing application component with potential RCE"
    return case
