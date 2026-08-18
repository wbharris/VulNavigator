from pathlib import Path

from vulnavigator.pipeline import analyze_path

ROOT = Path(__file__).resolve().parents[1]


def test_nessus_xml():
    cases = analyze_path(ROOT / "examples/nessus-report.nessus", offline=True)
    assert len(cases) == 1
    case = cases[0]
    assert case.source_kind == "nessus"
    assert case.finding_id == "20007"
    assert case.cves == ["CVE-2014-0160"]
    assert "CWE-119" in case.cwes
    assert case.validation_status in {"confirmed", "plausible", "unconfirmed"}
    assert case.remediation


def test_qualys_xml():
    cases = analyze_path(ROOT / "examples/qualys-report.xml", offline=True)
    assert cases[0].source_kind == "qualys"
    assert cases[0].finding_id == "38227"
    assert cases[0].cves == ["CVE-2014-0160"]
    assert cases[0].product == "10.0.0.21"


def test_openvas_xml():
    cases = analyze_path(ROOT / "examples/openvas-report.xml", offline=True)
    assert cases[0].source_kind == "openvas"
    assert "103857" in cases[0].finding_id
    assert cases[0].cves == ["CVE-2014-0160"]


def test_nessus_csv():
    cases = analyze_path(ROOT / "examples/nessus-report.csv", offline=True)
    assert cases[0].source_kind == "nessus"
    assert cases[0].cves == ["CVE-2014-0160"]
