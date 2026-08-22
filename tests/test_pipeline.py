from pathlib import Path

from vulnavigator.pipeline import analyze_path, analyze_text
from vulnavigator.report import to_markdown

ROOT = Path(__file__).resolve().parents[1]


def test_daybreak_official_bundle():
    cases = analyze_path(ROOT / "examples/daybreak-findings.json", offline=True)
    assert len(cases) == 1
    case = cases[0]
    assert case.source_kind == "daybreak"
    assert case.finding_id == "db-heap-h2-headers"
    assert case.rule_id == "memory-safety.http2-header-decoder"
    assert "CWE-787" in case.cwes
    assert case.validation_status in {"confirmed", "plausible"}
    assert any(m.id in {"T1203", "T1068", "T1499", "T1190"} for m in case.attack)
    assert case.d3fend
    assert case.priority in {"P1", "P2"}
    assert case.asset_internet_facing is True
    md = to_markdown(case)
    assert "11. Confidence and Assumptions" in md
    assert "Information that would make this report better" in md


def test_daybreak_legacy_single():
    cases = analyze_path(ROOT / "examples/daybreak-finding.json", offline=True, source="daybreak")
    assert cases[0].source_kind == "daybreak"
    assert cases[0].cves == ["CVE-2026-00001"]


def test_mythos_offline_records_assumptions():
    cases = analyze_path(ROOT / "examples/mythos-finding.json", offline=True)
    case = cases[0]
    assert case.source_kind == "mythos"
    assert case.finding_id == "MYTHOS-2026-0042"
    assert case.validation_status in {"confirmed", "plausible"}
    fields = {a.field for a in case.assumptions}
    assert "internet_facing" in fields
    assert "ai_system" not in fields
    assert "fraud_relevant" not in fields
    assert case.asset_ai_system is None
    assert case.asset_fraud_relevant is None
    assert case.atlas == []
    assert case.f3 == []
    assert any("internet-facing" in i.question.lower() for i in case.improve)


def test_cve_only_offline():
    cases = analyze_text("CVE-2024-3400", offline=True)
    assert cases[0].cves == ["CVE-2024-3400"]
    assert cases[0].source_kind == "cve"
    assert cases[0].improve


def test_rejected_empty():
    cases = analyze_text("todo", offline=True)
    assert cases[0].validation_status == "rejected"
    assert cases[0].priority == "P4"
