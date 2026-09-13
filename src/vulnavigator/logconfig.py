"""Optional logging setup. Default is WARNING on stderr, text format.

    VULN_NAV_LOG=json|text
    VULN_NAV_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "", fmt: str = "") -> None:
    name = (fmt or os.environ.get("VULN_NAV_LOG") or "text").strip().lower()
    raw_level = (level or os.environ.get("VULN_NAV_LOG_LEVEL") or "WARNING").strip().upper()
    log_level = getattr(logging, raw_level, logging.WARNING)
    root = logging.getLogger("vulnavigator")
    if root.handlers:
        root.setLevel(log_level)
        return
    handler = logging.StreamHandler(sys.stderr)
    if name == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(log_level)
    root.propagate = False
