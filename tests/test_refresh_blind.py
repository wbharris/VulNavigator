"""Blind-CVE scorecard helpers: dead NVD-CWE branch, rescore gold, pack fallback."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from vulnavigator.models import Case, Evidence, Location, Mapping


def _load(name: str, rel: str):
    path = Path(__file__).resolve().parent / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _refresh():
    return _load("refresh_blind_cve", "training/refresh_blind_cve.py")


def _error_pack():
    return _load("error_pack", "training/error_pack.py")


def _sqli_case(**kwargs) -> Case:
    base = Case(
        source_kind="narrative",
        cwes=["CWE-89"],
        product="School Management System",
        version="1.0",
        locations=[Location(path="/student/index.php")],
        evidence=Evidence(notes="public exploit released"),
        asset_internet_facing=True,
        validation_status="plausible",
        attack=[Mapping(id="T1190", framework="ATTACK")],
    )
    for key, value in kwargs.items():
        setattr(base, key, value)
    return base


SQLI_CVE = {
    "id": "CVE-2026-0544",
    "descriptions": [
        {
            "lang": "en",
            "value": (
                "A security flaw has been discovered in itsourcecode School Management "
                "System 1.0. This affects an unknown part of the file /student/index.php. "
                "The manipulation of the argument ID results in sql injection. "
                "It is possible to launch the attack remotely. "
                "The exploit has been released to the public and may be used for attacks."
            ),
        }
    ],
    "weaknesses": [{"description": [{"value": "CWE-89"}, {"value": "CWE-787"}]}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.3, "vectorString": "CVSS:3.1/AV:N"}}]},
    "configurations": [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "criteria": "cpe:2.3:a:itsourcecode:school_management_system:1.0:*:*:*:*:*:*:*"
                        }
                    ]
                }
            ]
        }
    ],
}


def test_issues_for_does_not_flag_nvd_only_cwe():
    r = _refresh()
    issues = r.issues_for(SQLI_CVE, _sqli_case())
    assert not any(i.startswith("MISSING: NVD CWE") for i in issues)
    assert issues == []


def test_issues_for_still_flags_phrase_cwe_miss():
    r = _refresh()
    issues = r.issues_for(SQLI_CVE, _sqli_case(cwes=[]))
    assert any("phrase CWE" in i and "CWE-89" in i for i in issues)


def test_synthetic_cve_keeps_corpus_cvss_and_products_without_scorecard():
    r = _refresh()
    item = {
        "cve": "CVE-2026-0544",
        "description": SQLI_CVE["descriptions"][0]["value"],
        "nvd_cwe": ["CWE-89"],
        "nvd_cvss": 7.3,
        "nvd_products": ["itsourcecode:school management system"],
    }
    cve = r._synthetic_cve(item, {})
    assert r.gold_cvss(cve)[0] == 7.3
    assert r.gold_cwes(cve) == ["CWE-89"]
    assert r.gold_products(cve) == ["itsourcecode:school management system"]
    row = r._row_for(cve, _sqli_case(), item["description"])
    assert row["nvd_cvss"] == 7.3
    assert row["nvd_products"] == ["itsourcecode:school management system"]


def test_synthetic_cve_falls_back_to_scorecard_products():
    r = _refresh()
    item = {
        "cve": "CVE-2026-0544",
        "description": "sql injection in foo",
        "nvd_cwe": ["CWE-89"],
        "nvd_cvss": None,
    }
    old = {"nvd_products": ["acme:widget"], "nvd_cvss": 9.8, "published": "2026-01-02"}
    cve = r._synthetic_cve(item, old)
    assert r.gold_cvss(cve)[0] == 9.8
    assert r.gold_products(cve) == ["acme:widget"]
    assert cve["published"] == "2026-01-02"


def test_resolve_scorecard_falls_back_to_latest(tmp_path, capsys):
    ep = _error_pack()
    ep.CASES = tmp_path
    (tmp_path / "blind-first-25.json").write_text("[]\n", encoding="utf-8")
    got = ep.resolve_scorecard(300)
    assert got.name == "blind-first-25.json"
    err = capsys.readouterr()
    assert "preflight FALLBACK: missing blind-first-300.json" in err.out
