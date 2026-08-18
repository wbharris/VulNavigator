"""Live enrichment: NVD, CISA KEV, FIRST EPSS.

``--offline`` skips all network calls. ``case.kev``, ``case.epss``,
``case.cvss``, and ``case.nvd_description`` stay at defaults. The report
is still actionable. KEV/EPSS only raise priority when a CVE exists and
the network is up.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from vulnavigator.models import Case

log = logging.getLogger("vulnavigator.enrich")

UA = "VulNavigator/0.1 (+https://github.com/wbharris/VulNavigator)"
TIMEOUT = 12


def _get_json(url: str) -> dict[str, Any] | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def enrich(case: Case, offline: bool = False) -> Case:
    if offline:
        log.debug("offline: skip NVD/KEV/EPSS for %s", case.cves or case.title)
        return case
    if not case.cves:
        log.debug("no CVE: skip NVD/KEV/EPSS (expected for AI 0-days)")
        return case
    cve = case.cves[0]
    nvd = _get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}")
    if nvd and nvd.get("vulnerabilities"):
        cve_item = nvd["vulnerabilities"][0].get("cve", {})
        descs = cve_item.get("descriptions") or []
        en = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
        case.nvd_description = en or ""
        if not case.description:
            case.description = case.nvd_description
        metrics = cve_item.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            rows = metrics.get(key) or []
            if rows:
                data = rows[0].get("cvssData") or {}
                score = data.get("baseScore")
                if score is not None:
                    case.cvss = float(score)
                    break
        weaknesses = cve_item.get("weaknesses") or []
        for weak in weaknesses:
            for desc in weak.get("description") or []:
                val = str(desc.get("value") or "")
                if val.upper().startswith("CWE-") and val.upper() not in case.cwes:
                    case.cwes.append(val.upper())

    kev = _get_json(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    if kev:
        ids = {row.get("cveID") for row in kev.get("vulnerabilities") or []}
        case.kev = cve in ids

    epss = _get_json(f"https://api.first.org/data/v1/epss?cve={cve}")
    if epss and epss.get("data"):
        try:
            case.epss = float(epss["data"][0].get("epss"))
        except (TypeError, ValueError, KeyError):
            pass
    return case
