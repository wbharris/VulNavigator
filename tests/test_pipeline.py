from pathlib import Path

from vulnavigator.pipeline import analyze_path, analyze_text
from vulnavigator.report import to_markdown

ROOT = Path(__file__).resolve().parents[1]


def test_daybreak_offline():
    case = analyze_path(ROOT / "examples/daybreak-finding.json", offline=True)
    assert case.source_kind == "daybreak"
    assert case.cves == ["CVE-2026-00001"]
    assert "CWE-787" in case.cwes
    assert case.validation_status in {"confirmed", "plausible"}
    assert any(m.id == "T1203" or m.id == "T1068" for m in case.attack)
    assert case.d3fend
    assert case.csf
    assert case.priority in {"P1", "P2"}
    assert case.assumptions == [] or all(a.field != "internet_facing" for a in case.assumptions)
    md = to_markdown(case)
    assert "Assumptions" in md
    assert "Information that would make this report better" in md


def test_mythos_offline_records_assumptions():
    case = analyze_path(ROOT / "examples/mythos-finding.json", offline=True)
    assert case.source_kind == "mythos"
    assert case.validation_status in {"confirmed", "plausible"}
    fields = {a.field for a in case.assumptions}
    assert "internet_facing" in fields
    assert "ai_system" in fields
    assert "fraud_relevant" in fields
    assert case.atlas == []
    assert case.f3 == []
    assert any("internet-facing" in i.question.lower() for i in case.improve)


def test_cve_only_offline():
    case = analyze_text("CVE-2024-3400", offline=True)
    assert case.cves == ["CVE-2024-3400"]
    assert case.source_kind == "cve"
    assert case.improve


def test_rejected_empty():
    case = analyze_text("todo", offline=True)
    assert case.validation_status == "rejected"
    assert case.priority == "P4"
