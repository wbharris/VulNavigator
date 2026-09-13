"""Live enrichment: NVD, CISA KEV, FIRST EPSS.

``--offline`` skips all network calls. ``case.kev``, ``case.epss``,
``case.cvss``, and ``case.nvd_description`` stay at defaults. The report
is still actionable. KEV/EPSS only raise priority when a CVE exists and
the network is up.

When a finding lists several CVEs, each is queried (capped) and the case
keeps the strongest signal: any KEV hit, max CVSS, max EPSS, union of CWEs.
"""

from __future__ import annotations

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from vulnavigator.models import Case

log = logging.getLogger("vulnavigator.enrich")

UA = "VulNavigator/0.1 (+https://github.com/wbharris/VulNavigator)"
DEFAULT_TIMEOUT = 12.0
MAX_CVES = 8
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def http_timeout(explicit: float | None = None) -> float:
    if explicit is not None:
        return max(1.0, float(explicit))
    raw = (os.environ.get("VULN_NAV_TIMEOUT") or "").strip()
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        return max(1.0, float(raw))
    except ValueError:
        return DEFAULT_TIMEOUT


def _get_json(url: str, timeout: float) -> dict[str, Any] | None:
    req = Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return None


def _nvd_fields(nvd: dict[str, Any] | None) -> tuple[str, float | None, list[str]]:
    if not nvd or not nvd.get("vulnerabilities"):
        return "", None, []
    cve_item = nvd["vulnerabilities"][0].get("cve", {})
    descs = cve_item.get("descriptions") or []
    en = next((d.get("value") for d in descs if d.get("lang") == "en"), "") or ""
    cvss = None
    metrics = cve_item.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows:
            data = rows[0].get("cvssData") or {}
            score = data.get("baseScore")
            if score is not None:
                cvss = float(score)
                break
    cwes: list[str] = []
    for weak in cve_item.get("weaknesses") or []:
        for desc in weak.get("description") or []:
            val = str(desc.get("value") or "").upper()
            if val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    return en, cvss, cwes


def _epss_score(payload: dict[str, Any] | None) -> float | None:
    if not payload or not payload.get("data"):
        return None
    try:
        return float(payload["data"][0].get("epss"))
    except (TypeError, ValueError, KeyError, IndexError):
        return None


def enrich(case: Case, offline: bool = False, timeout: float | None = None) -> Case:
    if offline:
        log.debug("offline: skip NVD/KEV/EPSS for %s", case.cves or case.title)
        return case
    if not case.cves:
        log.debug("no CVE: skip NVD/KEV/EPSS (expected for AI 0-days)")
        return case
    seconds = http_timeout(timeout)
    cves = case.cves[:MAX_CVES]
    kev = _get_json(KEV_URL, seconds)
    kev_ids = {row.get("cveID") for row in (kev or {}).get("vulnerabilities") or []}
    case.kev = any(cve in kev_ids for cve in cves)

    def _one(cve: str) -> tuple[str, dict[str, Any] | None, dict[str, Any] | None]:
        nvd = _get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}", seconds)
        epss = _get_json(f"https://api.first.org/data/v1/epss?cve={cve}", seconds)
        return cve, nvd, epss

    if len(cves) == 1:
        rows = [_one(cves[0])]
    else:
        workers = min(4, len(cves))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows = list(pool.map(_one, cves))

    best_cvss: float | None = None
    best_epss: float | None = None
    best_desc = ""
    for cve, nvd, epss in rows:
        desc, cvss, cwes = _nvd_fields(nvd)
        for cwe in cwes:
            if cwe not in case.cwes:
                case.cwes.append(cwe)
        if cvss is not None and (best_cvss is None or cvss > best_cvss):
            best_cvss = cvss
            if desc:
                best_desc = desc
        elif desc and not best_desc:
            best_desc = desc
        score = _epss_score(epss)
        if score is not None and (best_epss is None or score > best_epss):
            best_epss = score
        log.debug("enriched %s cvss=%s epss=%s kev=%s", cve, cvss, score, cve in kev_ids)

    if best_desc:
        case.nvd_description = best_desc
        if not case.description:
            case.description = best_desc
    if best_cvss is not None:
        case.cvss = best_cvss
    if best_epss is not None:
        case.epss = best_epss
    return case
