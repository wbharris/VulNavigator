#!/usr/bin/env python3
"""Run every example intake through the real pipeline and validate the report.

Usage: python3 tests/simulate_intake.py
Exit 0 if every case passes.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vulnavigator.pipeline import analyze_path  # noqa: E402
from vulnavigator.report import to_markdown  # noqa: E402

SECTIONS = [
    "## 1. Vulnerability Summary",
    "## 2. Evidence Summary",
    "## 3. Validation Notes",
    "## 4. Likely Attacker Behaviors / Technique Mapping",
    "## 5. Defensive Countermeasures",
    "## 6. NIST CSF Alignment",
    "## 7. Priority Assessment",
    "## 8. Recommended Remediation",
    "## 9. Compensating Controls",
    "## 10. Next Actions",
    "## 11. Confidence and Assumptions",
]


@dataclass
class Spec:
    path: str
    kind: str
    label: str
    expect_cve: str | None = None
    expect_cwe: str | None = None
    expect_id: str | None = None
    expect_poc: bool = False
    expect_no_cve_nag: bool = False
    expect_priority: str | None = None
    source_flag: str = ""


SPECS: list[Spec] = [
    Spec("examples/daybreak-findings.json", "daybreak", "Daybreak official findings.json", expect_id="db-heap-h2-headers", expect_cwe="CWE-787"),
    Spec("examples/daybreak-finding.json", "daybreak", "Daybreak single finding", expect_cve="CVE-2026-00001", source_flag="daybreak"),
    Spec("examples/mythos-finding.json", "mythos", "Mythos write-up", expect_id="MYTHOS-2026-0042", expect_cwe="CWE-119"),
    Spec("examples/mythos-zeroday.json", "mythos", "Mythos 0-day (PoC, no CVE)", expect_id="MYTHOS-0DAY-001", expect_poc=True, expect_no_cve_nag=True),
    Spec("examples/narrative-rce.txt", "narrative", "Narrative ticket (possible RCE)", expect_priority="P1", expect_no_cve_nag=True),
    Spec("examples/nessus-report.nessus", "nessus", "Nessus .nessus XML", expect_cve="CVE-2014-0160", expect_id="20007"),
    Spec("examples/nessus-report.csv", "nessus", "Nessus CSV", expect_cve="CVE-2014-0160"),
    Spec("examples/qualys-report.xml", "qualys", "Qualys VM XML", expect_cve="CVE-2014-0160", expect_id="38227"),
    Spec("examples/openvas-report.xml", "openvas", "OpenVAS / GVM XML", expect_cve="CVE-2014-0160"),
    Spec("examples/rapid7-report.xml", "rapid7", "Rapid7 Nexpose XML", expect_cve="CVE-2014-0160"),
    Spec("examples/rapid7-report.json", "rapid7", "Rapid7 InsightVM JSON (asset+host)", expect_cve="CVE-2014-0160", expect_id="ssl-heartbleed"),
    Spec("examples/sarif-report.sarif", "sarif", "SARIF (CodeQL)", expect_cwe="CWE-89"),
    Spec("examples/sarif-same-rule.sarif", "sarif", "SARIF same rule, two files", expect_cwe="CWE-89"),
    Spec("examples/trivy-report.json", "trivy", "Trivy JSON", expect_cve="CVE-2014-0160"),
    Spec("examples/snyk-report.json", "snyk", "Snyk JSON", expect_cve="CVE-2020-8203"),
    Spec("examples/dependabot-report.json", "dependabot", "GitHub Dependabot JSON", expect_cve="CVE-2020-8203"),
    Spec("examples/wiz-report.json", "wiz", "Wiz issues JSON", expect_cve="CVE-2014-0160"),
    Spec("examples/wiz-graphql.json", "wiz", "Wiz GraphQL envelope", expect_cve="CVE-2014-0160", expect_id="wiz-gql-1"),
    Spec("examples/prisma-report.json", "prisma", "Prisma Cloud JSON", expect_cve="CVE-2014-0160"),
    Spec("examples/orca-report.json", "orca", "Orca alerts JSON", expect_cve="CVE-2014-0160"),
    Spec("examples/defender-report.json", "defender", "Microsoft Defender VM JSON", expect_cve="CVE-2014-0160"),
    Spec("examples/defender-odata.json", "defender", "Defender Graph OData envelope", expect_cve="CVE-2014-0160", expect_id="mdvm-odata-1"),
    Spec("examples/crowdstrike-report.json", "crowdstrike", "CrowdStrike Spotlight JSON", expect_cve="CVE-2014-0160"),
    Spec("examples/inspector-report.json", "inspector", "AWS Inspector2 JSON", expect_cve="CVE-2014-0160"),
    Spec("examples/nexus-report.json", "nexus", "Nexus IQ JSON", expect_cve="CVE-2021-44228"),
    Spec("examples/nuclei-report.jsonl", "nuclei", "Nuclei JSONL", expect_cve="CVE-2014-0160"),
    Spec("examples/burp-report.xml", "burp", "Burp DAST XML", expect_cwe="CWE-89"),
    Spec("examples/zap-report.xml", "zap", "OWASP ZAP XML", expect_cwe="CWE-89"),
]


def check(spec: Spec) -> tuple[bool, list[str], dict]:
    fails: list[str] = []
    path = ROOT / spec.path
    if not path.is_file():
        return False, [f"missing file {spec.path}"], {}
    try:
        cases = analyze_path(path, offline=True, source=spec.source_flag)
    except Exception as exc:  # noqa: BLE001
        return False, [f"analyze raised {exc}"], {}
    if not cases:
        return False, ["no cases produced"], {}
    case = cases[0]
    md = to_markdown(case)
    if case.source_kind != spec.kind:
        fails.append(f"source_kind={case.source_kind} want {spec.kind}")
    if spec.expect_cve and spec.expect_cve not in case.cves:
        fails.append(f"missing CVE {spec.expect_cve} (got {case.cves})")
    if spec.expect_cwe and spec.expect_cwe not in case.cwes:
        fails.append(f"missing CWE {spec.expect_cwe} (got {case.cwes})")
    if spec.expect_id and case.finding_id != spec.expect_id:
        fails.append(f"finding_id={case.finding_id!r} want {spec.expect_id!r}")
    if spec.expect_poc and not case.evidence.poc.strip():
        fails.append("expected PoC on AI 0-day")
    if spec.expect_no_cve_nag and any("CVE been assigned" in i.question for i in case.improve):
        fails.append("AI 0-day should not nag for a CVE")
    if spec.expect_priority and case.priority != spec.expect_priority:
        fails.append(f"priority={case.priority} want {spec.expect_priority}")
    if spec.kind in {"sarif", "burp", "zap"} and case.validation_status == "rejected":
        fails.append("SAST/DAST with CWE/location must not be rejected")
    if spec.expect_cve and case.validation_status not in {"confirmed", "plausible"}:
        fails.append(f"CVE finding should be plausible/confirmed, got {case.validation_status}")
    if spec.expect_poc and case.validation_status not in {"confirmed", "plausible"}:
        fails.append(f"AI 0-day with PoC should be plausible/confirmed, got {case.validation_status}")
    if spec.kind == "narrative" and case.validation_status not in {"unconfirmed", "plausible"}:
        fails.append(f"narrative without PoC should stay unconfirmed, got {case.validation_status}")
    if case.validation_status not in {"confirmed", "plausible", "unconfirmed", "rejected"}:
        fails.append(f"bad validation {case.validation_status}")
    if case.priority not in {"P1", "P2", "P3", "P4"}:
        fails.append(f"bad priority {case.priority}")
    for heading in SECTIONS:
        if heading not in md:
            fails.append(f"report missing {heading}")
    if "Confidence:" not in md:
        fails.append("report missing confidence")
    info = {
        "kind": case.source_kind,
        "title": case.title,
        "status": case.validation_status,
        "priority": case.priority,
        "urgency": case.urgency,
        "cves": case.cves,
        "cwes": case.cwes,
        "attack": [m.id for m in case.attack],
        "d3fend": [m.id for m in case.d3fend],
        "poc": bool(case.evidence.poc.strip()),
        "discovery": bool(case.evidence.discovery.strip()),
        "report": md,
    }
    return not fails, fails, info


def write_html(rows: list[tuple[Spec, bool, list[str], dict]]) -> None:
    out = ROOT / "tests" / "last-results.html"
    passed = sum(1 for _, ok, _, _ in rows if ok)
    failed = len(rows) - passed
    body = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        "<title>VulNavigator intake simulation</title>",
        "<style>body{font:16px/1.45 system-ui,sans-serif;max-width:58rem;margin:2rem auto;padding:0 1.25rem}",
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.4rem .55rem;text-align:left;vertical-align:top}",
        "th{background:#f3f3f3}.pass{color:#0a7a2f;font-weight:700}.fail{color:#b00020;font-weight:700}",
        "code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem}",
        "pre{background:#111;color:#e8e8e8;padding:1rem;overflow:auto;border-radius:6px;max-height:22rem}</style></head><body>",
        "<h1>VulNavigator last simulation</h1>",
        f"<p><strong>{date.today().isoformat()}</strong> · {len(rows)} intake types · ",
        f"<span class='{'pass' if failed == 0 else 'fail'}'>{passed} passed, {failed} failed</span></p>",
        "<p>Each example file was run through <code>analyze_path(..., offline=True)</code> ",
        "and the 11-section report was checked for source kind, identity, and required headings.</p>",
        "<table><thead><tr><th>Intake</th><th>File</th><th>Kind</th><th>Validation</th><th>Priority</th><th>Identity</th><th>Result</th></tr></thead><tbody>",
    ]
    for spec, ok, fails, info in rows:
        ident = ", ".join(info.get("cves") or info.get("cwes") or ([info.get("title", "")][:1]))
        cls = "pass" if ok else "fail"
        note = "" if ok else "<br>".join(fails)
        body.append(
            f"<tr><td>{spec.label}</td><td><code>{spec.path}</code></td>"
            f"<td>{info.get('kind', '')}</td><td>{info.get('status', '')}</td>"
            f"<td>{info.get('priority', '')} {info.get('urgency', '')}</td>"
            f"<td><code>{ident}</code></td><td class='{cls}'>{'PASS' if ok else 'FAIL'}{('<br>' + note) if note else ''}</td></tr>"
        )
    body.append("</tbody></table>")
    for spec, ok, _, info in rows:
        if not info.get("report"):
            continue
        body.append(f"<h2>{spec.label}</h2>")
        body.append(f"<p class='{'pass' if ok else 'fail'}'>{'PASS' if ok else 'FAIL'} · {info.get('status')} · {info.get('priority')}</p>")
        body.append("<pre>" + info["report"].replace("&", "&amp;").replace("<", "&lt;") + "</pre>")
    body.append("<p>Re-run: <code>python3 tests/simulate_intake.py</code></p></body></html>")
    out.write_text("\n".join(body), encoding="utf-8")


def main() -> int:
    print("=== VulNavigator intake simulation (real pipeline, offline) ===\n")
    rows = []
    pass_n = fail_n = 0
    for spec in SPECS:
        ok, fails, info = check(spec)
        rows.append((spec, ok, fails, info))
        if ok:
            pass_n += 1
            extra = info.get("status", "")
            print(f"  PASS  {spec.label} ({spec.kind}, {extra}, {info.get('priority')})")
        else:
            fail_n += 1
            print(f"  FAIL  {spec.label}")
            for f in fails:
                print(f"        - {f}")
    write_html(rows)
    print(f"\n=== {pass_n} passed, {fail_n} failed ===")
    print(f"HTML: {ROOT / 'tests' / 'last-results.html'}")
    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
