from pathlib import Path

from vulnavigator.pipeline import analyze_path
from vulnavigator.report import to_markdown

ROOT = Path(__file__).resolve().parents[1]


def test_sample_narrative_rce():
    cases = analyze_path(ROOT / "examples/narrative-rce.txt", offline=True)
    case = cases[0]
    assert case.source_kind == "narrative"
    assert case.asset_internet_facing is True
    assert case.asset_ai_system is False
    assert case.asset_fraud_relevant is False
    assert case.source_severity == "critical"
    assert case.data_class == "sensitive-business"
    assert case.validation_status == "unconfirmed"
    assert any(m.id == "T1190" for m in case.attack)
    assert case.priority == "P1"
    md = to_markdown(case)
    assert "## 1. Vulnerability Summary" in md
    assert "## 11. Confidence and Assumptions" in md
    assert "ATLAS" in md
    assert "medium" in md.lower()
    assert "PoC" in md or "poc" in md.lower()
    assert not any("CVE been assigned" in i.question for i in case.improve)


def test_ai_zeroday_poc_is_primary_evidence():
    cases = analyze_path(ROOT / "examples/mythos-zeroday.json", offline=True)
    case = cases[0]
    assert case.cves == []
    assert case.evidence.poc
    assert case.evidence.discovery
    assert case.validation_status in {"confirmed", "plausible"}
    assert any("PoC" in r or "0-day" in r or "sandbox" in r.lower() for r in case.priority_reasons)
    assert not any("CVE been assigned" in i.question for i in case.improve)
    md = to_markdown(case)
    assert "No CVE expected" in md or "No CVE — expected" in md
    assert "parse_headers" in md
