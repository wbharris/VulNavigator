"""Unit tests for scanner helpers in vulnavigator.scanners.common."""

from __future__ import annotations

from vulnavigator.cli import _source_arg
from vulnavigator.scanners.common import (
    alias_source,
    cves_of,
    flatten_rows,
    make_case,
    norm_sev,
)
from vulnavigator.scanners.extended import parse_sarif


def test_cves_of_prefixed_and_deduped():
    assert cves_of("see CVE-2014-0160 and cve-2014-0160") == ["CVE-2014-0160"]


def test_cves_of_promotes_nexpose_year_id_when_cve_mentioned():
    assert cves_of("reference source=CVE 2014-0160") == ["CVE-2014-0160"]
    assert cves_of({"source": "CVE", "id": "2015-0204"}) == ["CVE-2015-0204"]


def test_cves_of_does_not_promote_year_id_without_cve_token():
    assert cves_of("opened ticket 2014-0160 on the firewall") == []


def test_cves_of_does_not_promote_implausible_years():
    assert cves_of("cve-like 1990-1234 and 8080-8081") == []


def test_cves_of_does_not_duplicate_prefixed_then_bare():
    assert cves_of("CVE-2014-0160 plus source=CVE 2014-0160") == ["CVE-2014-0160"]


def test_norm_sev_vendor_and_numeric_values():
    assert norm_sev("note") == "low"
    assert norm_sev("NOTE") == "low"
    assert norm_sev("very high") == "critical"
    assert norm_sev("important") == "high"
    assert norm_sev("error") == "high"
    assert norm_sev("warning") == "medium"
    assert norm_sev("moderate") == "medium"
    assert norm_sev("info") == "informational"
    assert norm_sev("4") == "critical"
    assert norm_sev("5") == "critical"
    assert norm_sev("3") == "high"
    assert norm_sev("0") == "informational"
    assert norm_sev(9.8) == "critical"
    assert norm_sev("7.5") == "high"
    assert norm_sev("4.0") == "medium"
    assert norm_sev("0.1") == "low"
    assert norm_sev("0.0") == "informational"
    assert norm_sev("exprt") == "exprt"
    assert norm_sev(None) == ""


def test_flatten_rows_list_and_known_wrappers():
    rows = [{"id": "a"}, "skip", {"id": "b"}]
    assert flatten_rows(rows) == [{"id": "a"}, {"id": "b"}]
    wrapped = {"findings": [{"QID": "1"}, {"QID": "2"}]}
    assert flatten_rows(wrapped, ("findings", "vulnerabilities")) == [{"QID": "1"}, {"QID": "2"}]


def test_flatten_rows_wraps_row_shaped_object_when_keys_miss():
    row = {"QID": "38227", "title": "Heartbleed"}
    assert flatten_rows(row, ("findings", "vulnerabilities")) == [row]


def test_flatten_rows_does_not_wrap_report_envelope():
    envelope = {"report": "qualys", "exported": "2024-01-01", "count": 3}
    assert flatten_rows(envelope, ("findings", "vulnerabilities")) == []
    assert flatten_rows({"meta": True, "ok": 1}, ("findings",)) == []


def test_flatten_rows_empty_and_non_dict():
    assert flatten_rows("not-json") == []
    assert flatten_rows({}) == []
    assert flatten_rows({"x": ""}) == []


def test_alias_source_nexsus_typo_and_cli():
    assert alias_source("nexsus") == "nessus"
    assert alias_source("Nexsus") == "nessus"
    assert _source_arg("nexsus") == "nessus"
    assert alias_source("tenable") == "nessus"
    assert alias_source("nexpose") == "rapid7"


def test_make_case_rule_id_defaults_to_finding_id():
    case = make_case(kind="nessus", finding_id="20007", title="Heartbleed")
    assert case.finding_id == "20007"
    assert case.rule_id == "20007"


def test_make_case_rule_id_can_differ_from_finding_id():
    case = make_case(
        kind="sarif",
        finding_id="guid-1",
        rule_id="js/sql-injection",
        title="SQLi",
    )
    assert case.finding_id == "guid-1"
    assert case.rule_id == "js/sql-injection"


def test_sarif_keeps_rule_id_when_guid_is_present():
    data = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                        "ruleId": "js/sql-injection",
                        "level": "error",
                        "message": {"text": "SQLi"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/db.js"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    cases = parse_sarif(data)
    assert len(cases) == 1
    assert cases[0].finding_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert cases[0].rule_id == "js/sql-injection"
