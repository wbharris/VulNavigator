"""NVD/KEV/EPSS enrichment: multi-CVE merge and timeout."""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

from vulnavigator.enrich import MAX_CVES, clear_kev_cache, enrich, http_timeout
from vulnavigator.models import Case
from vulnavigator.pipeline import analyze_case


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


def test_nvd_malformed_basescore_does_not_abort():
    case = Case(cves=["CVE-BAD"])

    def fake_get(url: str, timeout: float) -> dict | None:
        if "known_exploited" in url:
            return {"vulnerabilities": []}
        if "cveId=" in url:
            return _nvd("CVE-BAD", "unknown", "CWE-20", "weird")  # type: ignore[arg-type]
        return {"data": [{"epss": "0.1"}]}

    clear_kev_cache()
    with patch("vulnavigator.enrich._get_json", side_effect=fake_get):
        enrich(case, timeout=2)
    assert case.cvss is None
    assert case.nvd_description == "weird"
    assert case.epss == 0.1


def test_kev_catalog_fetched_once_per_process():
    clear_kev_cache()
    seen: list[str] = []

    def fake_get(url: str, timeout: float) -> dict | None:
        seen.append(url)
        if "known_exploited" in url:
            return {"vulnerabilities": [{"cveID": "CVE-A"}]}
        return None

    with patch("vulnavigator.enrich._get_json", side_effect=fake_get):
        enrich(Case(cves=["CVE-A"]), timeout=2)
        enrich(Case(cves=["CVE-B"]), timeout=2)
    kev_hits = [u for u in seen if "known_exploited" in u]
    assert len(kev_hits) == 1


def test_kev_single_fetch_under_concurrent_workers():
    clear_kev_cache()
    barrier = threading.Barrier(8)
    hits: list[str] = []
    guard = threading.Lock()

    def fake_get(url: str, timeout: float) -> dict | None:
        if "known_exploited" in url:
            time.sleep(0.05)
            with guard:
                hits.append(url)
            return {"vulnerabilities": [{"cveID": "CVE-A"}]}
        return None

    def worker() -> None:
        barrier.wait()
        enrich(Case(cves=["CVE-A"]), timeout=2)

    with patch("vulnavigator.enrich._get_json", side_effect=fake_get):
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert len(hits) == 1


def test_reanalyze_offline_clears_live_enrichment():
    case = Case(
        title="component rce",
        description="sql injection in login form",
        cves=["CVE-KEV"],
        cwes=["CWE-89"],
    )

    def fake_get(url: str, timeout: float) -> dict | None:
        if "known_exploited" in url:
            return {"vulnerabilities": [{"cveID": "CVE-KEV"}]}
        if "cveId=" in url:
            return _nvd("CVE-KEV", 9.8, "CWE-89", "rce")
        if "epss" in url:
            return {"data": [{"epss": "0.9"}]}
        return None

    clear_kev_cache()
    with patch("vulnavigator.enrich._get_json", side_effect=fake_get):
        analyze_case(case, offline=False, timeout=2)
    assert case.kev is True
    assert case.cvss == 9.8
    assert case.epss == 0.9
    assert case.nvd_description == "rce"
    assert any("KEV" in r for r in case.priority_reasons)

    analyze_case(case, offline=True)
    assert case.kev is False
    assert case.cvss is None
    assert case.epss is None
    assert case.nvd_description == ""
    assert not any("KEV" in r for r in case.priority_reasons)
