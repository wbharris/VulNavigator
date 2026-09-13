"""CI Fortify and NIST SSDF 1.2 gated overlays."""

from pathlib import Path

from vulnavigator.pipeline import analyze_path, analyze_text
from vulnavigator.report import to_markdown

ROOT = Path(__file__).resolve().parents[1]


def test_trivy_infers_ssdf_not_fortify():
    case = analyze_path(ROOT / "examples/trivy-report.json", offline=True)[0]
    assert case.asset_software_ssdf is True
    assert {m.id for m in case.ssdf} >= {"RV.1", "RV.2", "PS.4"}
    assert case.fortify == []
    md = to_markdown(case)
    assert "NIST SSDF 1.2" in md
    assert "CI Fortify:" not in md
    assert "## 12." not in md


def test_trivy_overlay_off():
    case = analyze_path(
        ROOT / "examples/trivy-report.json", offline=True, overlay="no-ssdf"
    )[0]
    assert case.ssdf == []
    assert "NIST SSDF 1.2:" not in to_markdown(case)


def test_mythos_zeroday_ssdf_includes_pw8():
    case = analyze_path(ROOT / "examples/mythos-zeroday.json", offline=True)[0]
    ids = {m.id for m in case.ssdf}
    assert {"RV.1", "RV.2", "PW.8"} <= ids
    assert case.fortify == []
    md = to_markdown(case)
    assert "PW.8" in md
    assert any("SSDF" in a.action or "SDLC" in a.action for a in case.next_actions)


def test_narrative_default_no_overlays():
    case = analyze_path(ROOT / "examples/narrative-rce.txt", offline=True)[0]
    assert case.ssdf == []
    assert case.fortify == []
    md = to_markdown(case)
    assert "CI Fortify / SSDF: not tagged" in md or "not tagged on this finding" in md


def test_nessus_sector_ics_fortify_not_ssdf():
    case = analyze_path(
        ROOT / "examples/nessus-report.nessus", offline=True, sector="ics"
    )[0]
    assert case.asset_ot_ci is True
    assert {m.id for m in case.fortify} == {"ISO.1", "ISO.2", "ISO.3", "REC.1"}
    assert case.ssdf == []
    md = to_markdown(case)
    assert "CI Fortify:" in md
    assert "isolate this path" in md.lower() or "ISO.2" in md
    assert any(a.owner == "ot-ops" for a in case.next_actions)
    assert "software_ssdf" not in {a.field for a in case.assumptions}
    assert any("ot_ci" == a.field for a in case.assumptions)


def test_nessus_default_no_fortify():
    case = analyze_path(ROOT / "examples/nessus-report.nessus", offline=True)[0]
    assert case.fortify == []
    assert case.ssdf == []


def test_rejected_skips_overlays():
    case = analyze_text("todo", offline=True, overlay="fortify,ssdf")[0]
    assert case.validation_status == "rejected"
    assert case.fortify == []
    assert case.ssdf == []


def test_json_ot_in_scope():
    cases = analyze_text(
        '{"source":"mythos","title":"x","description":"buffer overflow","cwe":"CWE-119",'
        '"poc":"run crash.sh","ot_in_scope":true}',
        offline=True,
    )
    case = cases[0]
    assert case.fortify
    assert case.ssdf  # mythos still infers SSDF
    assert "CI Fortify:" in to_markdown(case)


def test_overlay_none_disables_ssdf_inference():
    case = analyze_path(
        ROOT / "examples/mythos-zeroday.json", offline=True, overlay="none"
    )[0]
    assert case.ssdf == []
    assert case.fortify == []
