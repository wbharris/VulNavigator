"""Shared text heuristics.

``cade`` is an intentional alias for the common typo of ``code`` in
``remote code execution``. Patterns use word boundaries to limit false hits.
"""

from __future__ import annotations

import re

# rce | remote code execution | remote cade execution (typo)
RCE_RE = re.compile(r"\b(rce|remote\s+c[oa]de\s+execution)\b", re.I)


def mentions_rce(text: str) -> bool:
    return bool(RCE_RE.search(text or ""))
