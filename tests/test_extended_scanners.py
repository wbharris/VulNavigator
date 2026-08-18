from pathlib import Path

from vulnavigator.pipeline import analyze_path

ROOT = Path(__file__).resolve().parents[1]


def _one(name: str):
    cases = analyze_path(ROOT / "examples" / name, offline=True)
    assert cases, name
    return cases[0]


def test_sarif_codeql():
    case = _one("sarif-report.sarif")
    assert case.source_kind == "sarif"
    assert "CWE-89" in case.cwes


def test_trivy():
    case = _one("trivy-report.json")
    assert case.source_kind == "trivy"
    assert case.cves == ["CVE-2014-0160"]
    assert case.component == "openssl"


def test_snyk():
    case = _one("snyk-report.json")
    assert case.source_kind == "snyk"
    assert "CVE-2020-8203" in case.cves


def test_rapid7():
    case = _one("rapid7-report.xml")
    assert case.source_kind == "rapid7"
    assert "CVE-2014-0160" in case.cves


def test_defender():
    case = _one("defender-report.json")
    assert case.source_kind == "defender"
    assert case.cves == ["CVE-2014-0160"]


def test_wiz():
    case = _one("wiz-report.json")
    assert case.source_kind == "wiz"
    assert case.cves == ["CVE-2014-0160"]


def test_crowdstrike():
    case = _one("crowdstrike-report.json")
    assert case.source_kind == "crowdstrike"
    assert case.cves == ["CVE-2014-0160"]


def test_nuclei():
    case = _one("nuclei-report.jsonl")
    assert case.source_kind == "nuclei"
    assert "CVE-2014-0160" in case.cves


def test_inspector():
    case = _one("inspector-report.json")
    assert case.source_kind == "inspector"
    assert case.cves == ["CVE-2014-0160"]


def test_nexus():
    case = _one("nexus-report.json")
    assert case.source_kind == "nexus"
    assert case.cves == ["CVE-2021-44228"]


def test_dependabot():
    case = _one("dependabot-report.json")
    assert case.source_kind == "dependabot"
    assert case.cves == ["CVE-2020-8203"]


def test_burp():
    case = _one("burp-report.xml")
    assert case.source_kind == "burp"
    assert "CWE-89" in case.cwes


def test_zap():
    case = _one("zap-report.xml")
    assert case.source_kind == "zap"
    assert "CWE-89" in case.cwes


def test_prisma():
    case = _one("prisma-report.json")
    assert case.source_kind == "prisma"
    assert case.cves == ["CVE-2014-0160"]


def test_orca():
    case = _one("orca-report.json")
    assert case.source_kind == "orca"
    assert case.cves == ["CVE-2014-0160"]
