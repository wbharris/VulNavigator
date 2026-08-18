"""Vendor-shape fixtures: nested envelopes, detection, Rapid7 scope, SARIF results."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnavigator.normalize import detect_kind, findings_from_path, findings_from_text
from vulnavigator.scanners import detect_csv_kind, detect_json_kind
from vulnavigator.scanners.extended import detect_extended_json, parse_rapid7_json, parse_sarif

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "name,kind",
    [
        ("defender-report.json", "defender"),
        ("defender-odata.json", "defender"),
        ("wiz-report.json", "wiz"),
        ("wiz-graphql.json", "wiz"),
        ("rapid7-report.json", "rapid7"),
        ("sarif-report.sarif", "sarif"),
        ("sarif-multi.sarif", "sarif"),
        ("sarif-same-rule.sarif", "sarif"),
        ("snyk-report.json", "snyk"),
        ("snyk-sarif.json", "sarif"),
        ("trivy-report.json", "trivy"),
        ("dependabot-report.json", "dependabot"),
        ("crowdstrike-report.json", "crowdstrike"),
        ("inspector-report.json", "inspector"),
        ("nexus-report.json", "nexus"),
        ("prisma-report.json", "prisma"),
        ("orca-report.json", "orca"),
    ],
)
def test_detect_extended_json_stable_per_vendor_file(name, kind):
    data = json.loads((ROOT / "examples" / name).read_text())
    assert detect_extended_json(data) == kind
    assert detect_json_kind(data) == kind


def test_detect_does_not_steal_daybreak_or_mythos():
    daybreak = json.loads((ROOT / "examples/daybreak-finding.json").read_text())
    mythos = json.loads((ROOT / "examples/mythos-finding.json").read_text())
    assert detect_extended_json(daybreak) == ""
    assert detect_extended_json(mythos) == ""


def test_defender_odata_envelope_is_one_finding():
    cases = findings_from_path(ROOT / "examples/defender-odata.json")
    assert len(cases) == 1
    case = cases[0]
    assert case.source_kind == "defender"
    assert case.finding_id == "mdvm-odata-1"
    assert case.cves == ["CVE-2014-0160"]
    assert case.product == "pc-finance-01"
    assert case.component == "OpenSSL"


def test_wiz_graphql_envelope_unwraps_nodes():
    cases = findings_from_path(ROOT / "examples/wiz-graphql.json")
    assert len(cases) == 1
    case = cases[0]
    assert case.source_kind == "wiz"
    assert case.finding_id == "wiz-gql-1"
    assert case.cves == ["CVE-2014-0160"]
    assert case.product == "i-0abc"
    assert case.component == "VIRTUAL_MACHINE"


def test_wiz_description_mentioning_plugin_id_still_detects_wiz():
    payload = {
        "issues": [
            {
                "id": "wiz-2",
                "title": "mentions plugin_id in the write-up",
                "vulnerabilityCVE": "CVE-2014-0160",
                "vulnerableAsset": {"name": "vm-1", "type": "VM"},
            }
        ]
    }
    assert detect_extended_json(payload) == "wiz"
    assert detect_kind(payload) == "wiz"
    cases = findings_from_text(json.dumps(payload))
    assert cases[0].source_kind == "wiz"
    assert cases[0].product == "vm-1"


def test_rapid7_json_prefers_asset_over_scan_host():
    data = json.loads((ROOT / "examples/rapid7-report.json").read_text())
    cases = parse_rapid7_json(data)
    assert len(cases) == 1
    case = cases[0]
    assert case.source_kind == "rapid7"
    assert case.product == "web-prod-01"
    assert case.locations[0].path == "10.0.0.44"
    assert case.product != "scan-alias"
    assert "10.0.0.99" not in (case.product, case.locations[0].path)
    assert case.cves == ["CVE-2014-0160"]


def test_rapid7_json_data_envelope_with_count():
    payload = {
        "meta": {"count": 1},
        "data": [
            {
                "id": "ssl-heartbleed",
                "title": "Heartbleed",
                "cves": ["CVE-2014-0160"],
                "assetIp": "10.0.0.44",
                "hostname": "web-01",
            }
        ],
    }
    assert detect_extended_json(payload) == "rapid7"
    cases = parse_rapid7_json(payload)
    assert len(cases) == 1
    assert cases[0].product == "web-01"
    assert cases[0].locations[0].path == "10.0.0.44"


def test_sarif_same_rule_two_results_keep_separate_locations():
    data = json.loads((ROOT / "examples/sarif-same-rule.sarif").read_text())
    cases = parse_sarif(data)
    assert len(cases) == 2
    assert {c.rule_id for c in cases} == {"js/sql-injection"}
    assert {c.finding_id for c in cases} == {"res-db", "res-api"}
    by_id = {c.finding_id: c for c in cases}
    assert [loc.path for loc in by_id["res-db"].locations] == ["src/db.js"]
    assert [loc.path for loc in by_id["res-api"].locations] == ["src/api.js"]
    assert by_id["res-db"].locations[0].line == 42
    assert by_id["res-api"].locations[0].line == 10
    assert by_id["res-db"].component == "src/db.js"
    assert by_id["res-api"].component == "src/api.js"


@pytest.mark.parametrize(
    "headers,kind",
    [
        (["QID", "Title", "Severity"], "qualys"),
        (["Plugin ID", "Risk", "Host"], "nessus"),
        (["NVT", "OID", "Host"], "openvas"),
        (["Nexpose ID", "Title"], "rapid7"),
        (["Vulnerability ID", "Asset IP Address"], "rapid7"),
        (["Vulnerability ID", "PkgName"], "trivy"),
        (["CVE ID", "Device name"], "defender"),
        (["Snyk ID", "Title"], "snyk"),
        (["Issue URL", "Package Name"], "snyk"),
        (["Host", "Severity", "Title"], ""),
        (["Vulnerability ID", "Title"], ""),
    ],
)
def test_detect_csv_kind_distinctive_headers(headers, kind):
    assert detect_csv_kind(headers) == kind
