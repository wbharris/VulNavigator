"""Shared text heuristics.

``cade`` is an intentional alias for the common typo of ``code`` in
``remote code execution``. Patterns use word boundaries to limit false hits.
"""

from __future__ import annotations

import re

# rce | remote code execution | remote cade execution (typo)
RCE_RE = re.compile(r"\b(rce|remote\s+c[oa]de\s+execution)\b", re.I)
SENSITIVE_RE = re.compile(r"\b(sensitive(?:\s+business)?\s+data|pii|payment(?:s)?)\b", re.I)
# "no RCE", "does not involve RCE", "without sensitive data"
_NEG_PREFIX = re.compile(
    r"(?i)(?:\b(?:no|not|without)\b|\bdoes(?:\s+not)?\b|\bdoesn't\b|\bdo\s+not\b)\s[\w\s,/:-]{0,32}$"
)


def _unnegated(pattern: re.Pattern[str], text: str) -> bool:
    blob = text or ""
    for match in pattern.finditer(blob):
        prefix = blob[max(0, match.start() - 40) : match.start()]
        if _NEG_PREFIX.search(prefix):
            continue
        return True
    return False


def mentions_rce(text: str) -> bool:
    return _unnegated(RCE_RE, text or "")


def mentions_sensitive_data(text: str) -> bool:
    return _unnegated(SENSITIVE_RE, text or "")
