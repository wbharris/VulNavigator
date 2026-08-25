from vulnavigator.artifacts import extract_artifacts, infer_scanner_tool
from vulnavigator.heuristics import mentions_rce, mentions_sensitive_data
from vulnavigator.models import Case, Evidence
from vulnavigator.pipeline import analyze_text
from vulnavigator.prioritize import prioritize, score_data_quality
from vulnavigator.report import attack_class, to_markdown
from vulnavigator.validate import validate


def test_infer_scanner_from_tool_name():
    assert infer_scanner_tool("Nessus plugin 20007 reported Heartbleed") == "nessus"
    assert infer_scanner_tool("no scanner named here") == ""


def test_extract_artifacts_from_scanner_paste():
    case = Case(
        title="Heartbleed",
        description=(
            "Nessus Plugin ID: 20007 on host: 10.0.0.44 found openssl 1.0.1f. "
            "See src/ssl/heartbeat.c:88. Endpoint https://10.0.0.44:443/ "
            "PoC: curl -v https://10.0.0.44 --tls-max 1.1  # crash in heartbeat"
        ),
    )
    extract_artifacts(case)
    assert case.detected_tool == "nessus"
    assert case.finding_id == "20007"
    assert case.host == "10.0.0.44"
    assert case.product == "openssl"
    assert case.version.startswith("1.0.1")
    assert case.endpoint.startswith("https://10.0.0.44")
    assert any(loc.path.endswith("heartbeat.c") and loc.line == 88 for loc in case.locations)
    assert "curl" in case.evidence.poc


def test_poc_without_replay_language_is_ignored():
    case = Case(title="x", description="PoC: we should write one later")
    extract_artifacts(case)
    assert case.evidence.poc == ""


def test_raw_nessus_paste_is_scanner_plausible_not_mythos():
    text = (
        "Nessus Plugin ID: 20007 reported CVE-2014-0160 on host: edge-1. "
        "CWE-119 in openssl. This is a scanner detection from a weekly scan."
    )
    case = analyze_text(text, offline=True)[0]
    assert case.detected_tool == "nessus"
    assert case.source_kind != "nessus"
    assert case.validation_status == "plausible"
    assert any("nessus scanner detection" in n for n in case.validation_notes)


def test_negation_rce_and_sensitive():
    assert not mentions_rce("This finding does not involve RCE")
    assert mentions_rce("This is remote code execution")
    assert not mentions_sensitive_data("There is no sensitive data on this host")
    assert mentions_sensitive_data("The app stores PII")


def test_internet_facing_floor_after_deductions():
    case = Case(
        title="low signal exposed box",
        description="short",
        asset_internet_facing=True,
        validation_status="unconfirmed",
    )
    prioritize(case)
    assert case.priority == "P3"
    assert any("Internet-facing floor" in r for r in case.priority_reasons)


def test_data_quality_penalizes_missing_cwe_and_attack():
    thin = Case(title="x", description="short", validation_status="unconfirmed")
    score_data_quality(thin)
    rich = Case(
        title="x",
        description="short",
        validation_status="unconfirmed",
        cwes=["CWE-89"],
        attack=[],
    )
    # attack still empty → both penalized for attack; rich has CWE
    score_data_quality(rich)
    assert rich.data_quality > thin.data_quality


def test_hardcoded_creds_class_in_report():
    case = Case(
        source_kind="generic",
        title="Hardcoded AWS key in config",
        description="A secret is embedded in the image.",
        cwes=["CWE-798"],
        validation_status="plausible",
        evidence=Evidence(poc=""),
    )
    from vulnavigator.map import map_case

    map_case(case)
    assert attack_class(case) == "hardcoded_creds"
    md = to_markdown(case)
    assert "Hardcoded" in md
    assert "Rotate the exposed credential" in md


def test_missing_evidence_list_on_case():
    case = analyze_text(
        "A scan identified an outdated internet-facing application component "
        "that may allow remote code execution. Rated critical. No AI. "
        "Fraud not suspected. Sensitive business data.",
        offline=True,
    )[0]
    assert case.missing_evidence
    assert any("version" in q.lower() or "poc" in q.lower() for q in case.missing_evidence)
