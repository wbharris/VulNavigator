"""NVD/KEV/EPSS enrichment: multi-CVE merge and timeout."""

from __future__ import annotations

from unittest.mock import patch

from vulnavigator.enrich import MAX_CVES, enrich, http_timeout
from vulnavigator.models import Case


def _nvd(cve: str, score: float, cwe: str, desc: str) -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve,
                    "descriptions": [{"lang": "en", "value": desc}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": score}}],
                    },
                    "weaknesses": [{"description": [{"value": cwe}]}],
                }
            }
        ]
    }


def test_http_timeout_env_and_floor(monkeypatch):
    monkeypatch.delenv("VULN_NAV_TIMEOUT", raising=False)
    assert http_timeout() == 12.0
    assert http_timeout(3) == 3.0
    assert http_timeout(0.1) == 1.0
    monkeypatch.setenv("VULN_NAV_TIMEOUT", "20")
    assert http_timeout() == 20.0
    monkeypatch.setenv("VULN_NAV_TIMEOUT", "nope")
    assert http_timeout() == 12.0


def test_enrich_offline_skips_network():
    case = Case(cves=["CVE-2024-3400"])
    with patch("vulnavigator.enrich._get_json") as get:
        enrich(case, offline=True)
        get.assert_not_called()
    assert case.kev is False
    assert case.cvss is None


def test_enrich_merges_all_cves_strongest_signal():
    case = Case(cves=["CVE-LOW", "CVE-KEV"])

    def fake_get(url: str, timeout: float) -> dict | None:
        if "known_exploited" in url:
            return {"vulnerabilities": [{"cveID": "CVE-KEV"}]}
        if "cveId=CVE-LOW" in url:
            return _nvd("CVE-LOW", 4.0, "CWE-20", "low issue")
        if "cveId=CVE-KEV" in url:
            return _nvd("CVE-KEV", 9.8, "CWE-78", "rce")
        if "cve=CVE-LOW" in url:
            return {"data": [{"epss": "0.01"}]}
        if "cve=CVE-KEV" in url:
            return {"data": [{"epss": "0.90"}]}
        return None

    with patch("vulnavigator.enrich._get_json", side_effect=fake_get):
        enrich(case, offline=False, timeout=2)

    assert case.kev is True
    assert case.cvss == 9.8
    assert case.epss == 0.90
    assert "CWE-20" in case.cwes
    assert "CWE-78" in case.cwes
    assert case.nvd_description == "rce"


def test_enrich_caps_cve_count():
    case = Case(cves=[f"CVE-2024-{i:04d}" for i in range(MAX_CVES + 5)])
    seen: list[str] = []

    def fake_get(url: str, timeout: float) -> dict | None:
        if "known_exploited" in url:
            return {"vulnerabilities": []}
        if "cveId=" in url:
            seen.append(url)
        return None

    with patch("vulnavigator.enrich._get_json", side_effect=fake_get):
        enrich(case, timeout=2)
    nvd_calls = [u for u in seen if "cveId=" in u]
    assert len(nvd_calls) == MAX_CVES
