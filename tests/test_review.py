"""Coverage for code-review items: scoring, 0-days, re-run, finding-id."""

from __future__ import annotations

import argparse

import pytest

from vulnavigator.cli import _finding_id_arg
from vulnavigator.heuristics import mentions_rce
from vulnavigator.map import map_case
from vulnavigator.models import Case, Evidence, is_ai_zeroday
from vulnavigator.pipeline import analyze_case
from vulnavigator.prioritize import plan_actions, prioritize, record_assumptions, score_data_quality
from vulnavigator.validate import validate


def test_rce_typo_cade_and_word_boundary():
    assert mentions_rce("may allow remote cade execution")
    assert mentions_rce("remote code execution")
    assert mentions_rce("RCE")
    assert not mentions_rce("traced")
    assert not mentions_rce("race condition")


def test_is_ai_zeroday():
    assert is_ai_zeroday(Case(source_kind="mythos", cves=[]))
    assert is_ai_zeroday(Case(source_kind="daybreak", cves=[]))
    assert is_ai_zeroday(Case(source_kind="narrative", cves=[]))
    assert not is_ai_zeroday(Case(source_kind="mythos", cves=["CVE-2024-1"]))
    assert not is_ai_zeroday(Case(source_kind="nessus", cves=[]))


def test_priority_unconfirmed_ai_zeroday_with_poc_internet_critical():
    case = Case(
        source_kind="mythos",
        title="heap overflow",
        description="AI found a heap overflow",
        source_severity="critical",
        asset_internet_facing=True,
        evidence=Evidence(poc="printf AAAA | nc host 80", reproduced=True),
        validation_status="plausible",
        cwes=["CWE-787"],
    )
    map_case(case)
    prioritize(case)
    assert case.priority in {"P1", "P2"}
    assert case.confidence


def test_priority_high_cvss_no_epss_no_exposure():
    case = Case(
        source_kind="nessus",
        title="lib",
        cves=["CVE-2014-0160"],
        cvss=9.8,
        validation_status="plausible",
    )
    prioritize(case)
    assert case.priority in {"P2", "P3", "P4"}
    assert any("CVSS" in r for r in case.priority_reasons)


def test_reprocess_does_not_duplicate_assumptions_or_controls():
    case = Case(
        source_kind="narrative",
        title="A scan identified an outdated internet-facing application component that may allow remote code execution. " * 2,
        description="A scan identified an outdated internet-facing application component that may allow remote code execution. Rated critical. No AI. Fraud not suspected. Sensitive business data.",
        remediation=["vendor patch"],
    )
    analyze_case(case, offline=True)
    n_assump = len(case.assumptions)
    n_ctrl = len(case.compensating_controls)
    n_rem = len(case.remediation)
    analyze_case(case, offline=True)
    assert len(case.assumptions) == n_assump
    assert len(case.compensating_controls) == n_ctrl
    assert len(case.remediation) == n_rem


def test_scanner_without_cve_is_not_called_a_zeroday():
    case = Case(
        source_kind="sarif",
        title="Possible SQL injection",
        description="A SQL injection was found in a query sink.",
        cwes=["CWE-89"],
        rule_id="js/sql-injection",
    )
    validate(case)
    record_assumptions(case)
    assert not any("treating as a 0-day" in n for n in case.validation_notes)
    assert not any("AI 0-days are judged" in i.why_it_matters for i in case.improve)
    assert not any("CVE been assigned" in i.question for i in case.improve)


def test_finding_id_validation():
    assert _finding_id_arg("") == ""
    assert _finding_id_arg("db-heap-h2-headers") == "db-heap-h2-headers"
    with pytest.raises(argparse.ArgumentTypeError):
        _finding_id_arg("x" * 300)
    with pytest.raises(argparse.ArgumentTypeError):
        _finding_id_arg("bad id with spaces and ; rm")


def test_kev_without_version_is_not_confirmed():
    case = Case(
        source_kind="generic",
        title="Apache Log4j2 JNDI lookup RCE",
        description="Message lookup substitution loads remote code via LDAP (Log4Shell).",
        product="log4j-core",
        component="JndiLookup",
        cves=["CVE-2021-44228"],
        kev=True,
        cvss=10.0,
        source_severity="critical",
    )
    validate(case)
    assert case.validation_status == "plausible"
    assert any("does not confirm" in n for n in case.validation_notes)


def test_kev_with_product_and_version_stays_plausible():
    case = Case(
        source_kind="generic",
        title="Log4Shell",
        description="JNDI lookup RCE in Log4j2.",
        product="log4j-core",
        version="2.14.1",
        cves=["CVE-2021-44228"],
        kev=True,
    )
    validate(case)
    assert case.validation_status == "plausible"
    assert any("does not confirm" in n for n in case.validation_notes)


def test_poc_text_is_not_reproduction():
    case = Case(
        source_kind="mythos",
        title="heap overflow",
        description="AI found a heap overflow in the parser.",
        evidence=Evidence(poc="printf AAAA | nc host 80"),
        cwes=["CWE-787"],
    )
    validate(case)
    assert case.validation_status == "plausible"
    assert case.validation_status != "confirmed"


def test_nvd_description_is_not_identity():
    case = Case(
        source_kind="generic",
        title="unknown",
        description="short",
        nvd_description="A long NVD paragraph that is enrichment only.",
    )
    validate(case)
    assert case.validation_status == "rejected"


def test_writeup_and_product_without_proof_is_unconfirmed():
    case = Case(
        source_kind="generic",
        title="Something in the login service",
        description="A reasonably long write-up about a bug in authentication handling.",
        product="login-service",
    )
    validate(case)
    assert case.validation_status == "unconfirmed"


def test_unknown_json_is_generic_not_mythos():
    from vulnavigator.normalize import findings_from_text

    cases = findings_from_text(
        '{"title": "Apache Log4j2 JNDI lookup RCE", "cve": "CVE-2021-44228", '
        '"product": "log4j-core", "description": "LDAP lookup RCE."}'
    )
    assert cases[0].source_kind == "generic"
    assert cases[0].cves == ["CVE-2021-44228"]
    assert cases[0].product == "log4j-core"


def test_prose_mentioning_nessus_is_not_a_nessus_scan():
    from vulnavigator.normalize import detect_kind

    assert detect_kind({"description": "Looks like a Nessus finding about SMB"}) == "generic"


def test_cwe400_does_not_add_t1499_when_rce_cwe_present():
    case = Case(
        source_kind="generic",
        title="Log4Shell",
        description="JNDI RCE",
        cves=["CVE-2021-44228"],
        cwes=["CWE-502", "CWE-400"],
        validation_status="plausible",
    )
    map_case(case)
    ids = {m.id.split(".")[0] for m in case.attack}
    assert "T1190" in ids or "T1059" in ids
    assert "T1499" not in ids


def test_data_quality_score_drops_with_gaps():
    thin = Case(source_kind="narrative", title="x", description="short")
    validate(thin)
    record_assumptions(thin)
    prioritize(thin)
    score_data_quality(thin)
    rich = Case(
        source_kind="mythos",
        title="overflow",
        description="x" * 90,
        product="edge-proxy",
        version="1.2.3",
        evidence=Evidence(poc="crash"),
        cwes=["CWE-787"],
    )
    validate(rich)
    record_assumptions(rich)
    prioritize(rich)
    score_data_quality(rich)
    assert rich.data_quality > thin.data_quality
    plan_actions(rich)
    assert rich.next_actions
