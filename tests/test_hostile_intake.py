"""Hostile / ugly intake: empty, malformed, multi-host, truncated."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnavigator.normalize import findings_from_path, findings_from_text
from vulnavigator.pipeline import analyze_path
from vulnavigator.report import to_markdown
from vulnavigator.scanners import looks_like_jsonl, parse_scanner_xml
from vulnavigator.scanners.extended import parse_rapid7_xml, parse_sarif, parse_snyk

ROOT = Path(__file__).resolve().parents[1]


def test_empty_text_fails_loudly():
    with pytest.raises(ValueError, match="empty"):
        findings_from_text("   ")


def test_malformed_xml_root():
    with pytest.raises(ValueError, match="not a known scanner"):
        parse_scanner_xml("<html><body>not a scan</body></html>")


def test_empty_unknown_xml_fails_loudly():
    with pytest.raises(ValueError, match="not a known scanner"):
        parse_scanner_xml("<SCAN></SCAN>")


def test_empty_qualys_csv_has_no_rows():
    assert findings_from_text("QID,Title,Severity\n") == []


def test_truncated_jsonl_fails_loudly():
    text = '{"template-id":"ok","info":{"name":"a"}}\n{"template-id":'
    assert looks_like_jsonl(text)
    with pytest.raises(ValueError, match="JSONL"):
        findings_from_text(text)


def test_single_json_object_is_not_jsonl():
    text = '{"template-id":"cves/CVE-2014-0160","info":{"name":"x","severity":"high"},"host":"h"}'
    assert looks_like_jsonl(text) is False
    cases = findings_from_text(text)
    assert cases
    assert cases[0].source_kind == "nuclei"


def test_empty_daybreak_findings_array():
    cases = findings_from_path(ROOT / "examples/daybreak-empty.json")
    assert cases == []


def test_sarif_keeps_all_locations_and_tool_as_product():
    data = json.loads((ROOT / "examples/sarif-multi.sarif").read_text())
    cases = parse_sarif(data)
    assert len(cases) == 1
    case = cases[0]
    assert case.product == "CodeQL"
    assert case.component == "src/db.js"
    assert case.rule_id == "js/sql-injection"
    assert case.finding_id == "js/sql-injection"
    assert len(case.locations) == 2
    assert {loc.path for loc in case.locations} == {"src/db.js", "src/api.js"}
    assert case.locations[0].line == 42


def test_rapid7_multi_host_emits_one_case_per_host():
    cases = analyze_path(ROOT / "examples/rapid7-multihost.xml", offline=True)
    assert len(cases) == 2
    hosts = {c.product for c in cases}
    assert hosts == {"10.0.0.44", "10.0.0.55"}
    assert all("CVE-2014-0160" in c.cves for c in cases)
    assert all(c.product for c in cases)


def test_rapid7_defs_only_no_hostless_case():
    import xml.etree.ElementTree as ET

    root = ET.fromstring(
        """<NexposeReport><VulnerabilityDefinitions>
        <vulnerability id="x" title="Only a definition" severity="5"/>
        </VulnerabilityDefinitions></NexposeReport>"""
    )
    assert parse_rapid7_xml(root) == []


def test_snyk_sarif_shape_uses_sarif_parser():
    data = json.loads((ROOT / "examples/snyk-sarif.json").read_text())
    cases = parse_snyk(data)
    assert cases
    assert cases[0].source_kind == "sarif"
    assert "CWE-89" in cases[0].cwes


def test_report_does_not_overclaim_rce_from_attack_ids_alone():
    from vulnavigator.models import Case, Mapping

    case = Case(
        source_kind="sarif",
        title="Possible SQL injection",
        description="A SQL injection was found.",
        cwes=["CWE-89"],
        attack=[Mapping(id="T1190", name="Exploit Public-Facing Application", framework="ATT&CK")],
        validation_status="plausible",
    )
    md = to_markdown(case)
    assert "not proof of RCE" in md
    assert "indicates possible remote code execution" not in md
    assert "Remote code execution against the exposed application component" not in md
    assert "Data access or tampering via injection" in md
