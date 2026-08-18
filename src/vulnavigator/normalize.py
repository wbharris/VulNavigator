"""Load Mythos and Daybreak findings into Case objects.

Primary inputs:
  - Daybreak / Codex Security: findings.json, a sealed scan directory,
    or a single finding record from that document
  - Mythos: a write-up JSON/markdown, or a Glasswing-style finding object

CVE-only and generic JSON still work, but they are not the expected path.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vulnavigator.models import Case, Evidence, Location

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CWE_RE = re.compile(r"CWE-\d+", re.I)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [str(value)]


def _cves_from(*chunks: Any) -> list[str]:
    found: list[str] = []
    for chunk in chunks:
        if chunk is None:
            continue
        text = chunk if isinstance(chunk, str) else json.dumps(chunk)
        for match in CVE_RE.findall(text):
            cve = match.upper()
            if cve not in found:
                found.append(cve)
    return found


def _cwes_from(*chunks: Any) -> list[str]:
    found: list[str] = []
    for chunk in chunks:
        if chunk is None:
            continue
        text = chunk if isinstance(chunk, str) else json.dumps(chunk)
        for match in CWE_RE.findall(text):
            cwe = match.upper()
            if cwe not in found:
                found.append(cwe)
    return found


def _optional_bool(data: dict[str, Any], *keys: str) -> bool | None:
    for key in keys:
        if key in data and data[key] is not None:
            val = data[key]
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                if val.lower() in {"true", "yes", "1"}:
                    return True
                if val.lower() in {"false", "no", "0"}:
                    return False
    return None


def _norm_cwe(values: Any) -> list[str]:
    out: list[str] = []
    for raw in _as_list(values):
        text = raw.strip()
        if not text:
            continue
        if text.upper().startswith("CWE-"):
            cwe = text.upper()
        elif text.isdigit():
            cwe = f"CWE-{text}"
        else:
            matches = CWE_RE.findall(text)
            for m in matches:
                if m.upper() not in out:
                    out.append(m.upper())
            continue
        if cwe not in out:
            out.append(cwe)
    return out


def detect_kind(data: Any, hint: str = "", forced: str = "") -> str:
    if forced in {"daybreak", "mythos", "cve", "generic"}:
        return forced
    blob = f"{hint} ".lower()
    if isinstance(data, dict):
        blob += json.dumps(data).lower()
        doc = str(data.get("documentType") or "")
        if doc.startswith("codex-security"):
            return "daybreak"
        if data.get("version") == "2.1.0" and "runs" in data:
            return "daybreak"
        if "hash" in data and "claude_severity" in data:
            return "mythos"
        if data.get("findingId") and data.get("ruleId") and data.get("taxonomy"):
            return "daybreak"
    else:
        blob += str(data).lower()
    if "daybreak" in blob or "codex-security" in blob or "codex security" in blob:
        return "daybreak"
    if "mythos" in blob or "glasswing" in blob:
        return "mythos"
    return "generic"


def _locations_from(items: Any) -> list[Location]:
    out: list[Location] = []
    if items is None:
        return out
    if isinstance(items, str):
        items = [{"path": items}]
    for item in items:
        if isinstance(item, str):
            out.append(Location(path=item))
        elif isinstance(item, dict):
            line = item.get("line") or item.get("startLine")
            snippet = str(item.get("snippet") or item.get("code") or "")
            out.append(
                Location(
                    path=str(item.get("path") or item.get("file") or item.get("uri") or ""),
                    line=int(line) if line not in (None, "") else None,
                    snippet=snippet,
                )
            )
    return out


def _daybreak_exposure(finding: dict[str, Any], attack: dict[str, Any]) -> bool | None:
    flagged = _optional_bool(finding, "internet_facing", "exposed")
    if flagged is not None:
        return flagged
    bits = [json.dumps(attack), json.dumps(finding.get("summary") or "")]
    blob = " ".join(bits).lower()
    remote = any(
        token in blob
        for token in (
            "unauthenticated remote",
            "internet-facing",
            "internet facing",
            "public-facing",
            "any client that can send",
        )
    )
    return True if remote else None


def case_from_daybreak(finding: dict[str, Any], scan: dict[str, Any] | None = None) -> Case:
    """Codex Security / Daybreak finding record (findings.json v1)."""
    sev = finding.get("severity") if isinstance(finding.get("severity"), dict) else {}
    tax = finding.get("taxonomy") if isinstance(finding.get("taxonomy"), dict) else {}
    conf = finding.get("confidence") if isinstance(finding.get("confidence"), dict) else {}
    val = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
    attack = finding.get("attackPath") if isinstance(finding.get("attackPath"), dict) else {}
    root = finding.get("rootCause")
    if isinstance(root, dict):
        root_text = str(root.get("summary") or "")
    else:
        root_text = str(root or "")

    evidence_bits: list[str] = []
    for ev in finding.get("codeEvidence") or []:
        if not isinstance(ev, dict):
            continue
        label = ev.get("label") or ev.get("id") or "evidence"
        path = ev.get("path") or ""
        expl = ev.get("explanation") or ""
        evidence_bits.append(f"{label} ({path}): {expl}".strip())

    loc_items = list(finding.get("locations") or [])
    for ev in finding.get("codeEvidence") or []:
        if isinstance(ev, dict) and ev.get("path") and ev.get("code"):
            loc_items.append(
                {
                    "path": ev.get("path"),
                    "startLine": ev.get("startLine"),
                    "snippet": ev.get("code"),
                }
            )

    disposition = str(val.get("disposition") or val.get("status") or "").lower()
    method = str(val.get("method") or "")
    reproduced = disposition in {"reportable", "reproduced", "validated", "confirmed"}
    sandbox = "sandbox" in method.lower() or bool(val.get("sandbox"))
    if not reproduced and val.get("conclusion"):
        reproduced = str(val.get("conclusion")).lower() in {"reportable", "confirmed", "true"}

    desc_parts = [
        str(finding.get("summary") or finding.get("description") or ""),
        root_text,
    ]
    if attack:
        reach = attack.get("reachability")
        dataflow = attack.get("dataflow")
        if isinstance(dataflow, dict):
            desc_parts.append(str(dataflow.get("narrative") or dataflow.get("outcome") or ""))
        elif isinstance(dataflow, str):
            desc_parts.append(dataflow)
        if isinstance(reach, dict):
            desc_parts.append(str(reach.get("narrative") or reach.get("outcome") or ""))
        elif isinstance(reach, str):
            desc_parts.append(reach)
    description = "\n\n".join(p.strip() for p in desc_parts if p and str(p).strip())

    target = (scan or {}).get("target") if isinstance((scan or {}).get("target"), dict) else {}
    product = str(
        finding.get("product")
        or target.get("displayName")
        or target.get("targetId")
        or ""
    )
    version = str(finding.get("version") or target.get("revision") or target.get("headRevision") or "")

    rem = finding.get("remediation")
    rem_text = rem if isinstance(rem, str) else str((rem or {}).get("summary") or "")
    extras = _as_list(finding.get("preventiveControls"))

    case = Case(
        source="daybreak",
        source_kind="daybreak",
        finding_id=str(finding.get("findingId") or finding.get("id") or ""),
        rule_id=str(finding.get("ruleId") or ""),
        scan_id=str((scan or {}).get("id") or finding.get("scanId") or ""),
        finder_confidence=str(conf.get("level") or ""),
        title=str(finding.get("title") or finding.get("ruleId") or "Daybreak finding"),
        description=description,
        cves=_cves_from(finding.get("cve"), finding.get("cves"), finding),
        cwes=_norm_cwe(tax.get("cwe") or finding.get("cwe") or finding.get("cwes")),
        product=product,
        component=str(finding.get("component") or tax.get("category") or ""),
        version=version,
        locations=_locations_from(loc_items),
        evidence=Evidence(
            reproduced=reproduced or None,
            sandbox=sandbox or None,
            poc=str(val.get("evidence") or val.get("poc") or ""),
            notes=" ".join(
                x
                for x in (
                    disposition,
                    method,
                    str(val.get("confidence_rationale") or conf.get("rationale") or ""),
                    "; ".join(evidence_bits[:4]),
                )
                if x
            ).strip(),
            references=_as_list(finding.get("references")),
        ),
        source_severity=str(sev.get("level") or finding.get("severity") or ""),
        asset_internet_facing=_daybreak_exposure(finding, attack),
        asset_ai_system=_optional_bool(finding, "ai_system", "ai_in_scope"),
        asset_fraud_relevant=_optional_bool(finding, "fraud_relevant", "payments"),
        data_class=str(finding.get("data_class") or ""),
        raw=finding,
    )
    if rem_text:
        case.remediation.append(rem_text)
    case.remediation.extend(extras)
    return case


def case_from_mythos(finding: dict[str, Any]) -> Case:
    """Mythos / Glasswing write-up or ledger-ish object."""
    target = finding.get("target") if isinstance(finding.get("target"), dict) else {}
    title = str(
        finding.get("title")
        or finding.get("name")
        or finding.get("bug_class")
        or finding.get("ant_id")
        or finding.get("hash")
        or "Mythos finding"
    )
    description = str(
        finding.get("description")
        or finding.get("details")
        or finding.get("writeup")
        or finding.get("report")
        or ""
    )
    sev = (
        finding.get("severity")
        or finding.get("claude_severity")
        or finding.get("vendor_severity")
        or finding.get("maintainer_severity")
        or ""
    )
    reproduced = finding.get("reproduced")
    if reproduced is None:
        reproduced = bool(finding.get("poc") or finding.get("proof_of_concept"))
        if finding.get("passed_triage") or finding.get("vendor_confirmed"):
            reproduced = True

    case = Case(
        source="mythos",
        source_kind="mythos",
        finding_id=str(finding.get("ant_id") or finding.get("finding_id") or finding.get("id") or ""),
        rule_id=str(finding.get("bug_class") or finding.get("ruleId") or ""),
        finder_confidence=str(finding.get("confidence") or ""),
        title=title,
        description=description,
        cves=_cves_from(finding.get("cve"), finding.get("cves"), finding.get("cve_ids"), title, description),
        cwes=_cwes_from(finding.get("cwe"), finding.get("cwes"), finding.get("bug_class"), title, description),
        product=str(
            finding.get("product")
            or target.get("product")
            or finding.get("project")
            or finding.get("package")
            or ""
        ),
        component=str(finding.get("component") or target.get("component") or ""),
        version=str(finding.get("version") or target.get("version") or ""),
        locations=_locations_from(finding.get("locations") or finding.get("affected_locations")),
        evidence=Evidence(
            reproduced=None if reproduced is None else bool(reproduced),
            sandbox=_optional_bool(finding, "sandbox", "sandbox_validated"),
            poc=str(finding.get("poc") or finding.get("proof_of_concept") or ""),
            notes=str(finding.get("status") or finding.get("reveal_tier") or ""),
            references=_as_list(finding.get("references")),
        ),
        source_severity=str(sev),
        asset_internet_facing=_optional_bool(finding, "internet_facing", "exposed"),
        asset_ai_system=_optional_bool(finding, "ai_system", "ai_in_scope"),
        asset_fraud_relevant=_optional_bool(finding, "fraud_relevant", "payments"),
        data_class=str(finding.get("data_class") or ""),
        raw=finding,
    )
    rem = finding.get("remediation") or finding.get("suggested_fix")
    if isinstance(rem, dict):
        rem = rem.get("summary") or rem.get("guidance")
    if rem:
        case.remediation.append(str(rem))
    return case


def case_from_generic(data: dict[str, Any], kind: str = "generic") -> Case:
    if kind == "daybreak":
        return case_from_daybreak(data)
    if kind == "mythos":
        return case_from_mythos(data)
    # Fall back: treat unknown JSON as a Mythos-style write-up if it has a narrative,
    # else as a thin Daybreak-like record.
    if data.get("findingId") or data.get("ruleId") or data.get("taxonomy"):
        return case_from_daybreak(data)
    return case_from_mythos({**data, "source": data.get("source") or kind})


def _extract_raw_findings(data: Any, kind: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Return (finding dicts, optional scan record)."""
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)], None
    if not isinstance(data, dict):
        raise ValueError("finding must be a JSON object or array")

    scan = data.get("scan") if isinstance(data.get("scan"), dict) else None
    if data.get("documentType") == "codex-security.findings":
        return [x for x in (data.get("findings") or []) if isinstance(x, dict)], scan
    if data.get("documentType") == "codex-security.scan-manifest":
        return [], data.get("scan") if isinstance(data.get("scan"), dict) else data
    if "runs" in data and isinstance(data.get("runs"), list):
        rows: list[dict[str, Any]] = []
        for run in data["runs"]:
            for result in (run or {}).get("results") or []:
                if isinstance(result, dict):
                    rows.append(result)
        return rows, None
    if isinstance(data.get("findings"), list):
        return [x for x in data["findings"] if isinstance(x, dict)], scan
    return [data], scan


def _sarif_to_daybreakish(result: dict[str, Any]) -> dict[str, Any]:
    locs = []
    for loc in result.get("locations") or []:
        phys = (loc or {}).get("physicalLocation") or {}
        art = phys.get("artifactLocation") or {}
        region = phys.get("region") or {}
        locs.append({"path": art.get("uri"), "startLine": region.get("startLine")})
    msg = result.get("message") or {}
    return {
        "findingId": str(result.get("guid") or result.get("fingerprint") or ""),
        "ruleId": str(result.get("ruleId") or ""),
        "title": str(msg.get("text") or result.get("ruleId") or "SARIF finding"),
        "summary": str(msg.get("text") or ""),
        "severity": {"level": str(result.get("level") or "medium")},
        "taxonomy": {"cwe": [], "category": ""},
        "locations": locs,
        "remediation": "",
        "validation": {},
        "provenance": {"source": "sarif"},
    }


def normalize_dict(data: dict[str, Any], source_hint: str = "", source: str = "") -> Case:
    kind = detect_kind(data, source_hint, source)
    cases = findings_from_document(data, source=kind)
    if not cases:
        raise ValueError("no findings in document")
    return cases[0]


def findings_from_document(
    data: Any,
    source: str = "",
    finding_id: str = "",
    hint: str = "",
    scan: dict[str, Any] | None = None,
) -> list[Case]:
    kind = detect_kind(data, hint, source)
    raw, embedded_scan = _extract_raw_findings(data, kind)
    scan = scan or embedded_scan
    if kind == "daybreak" and raw and raw[0].get("message") and "physicalLocation" in json.dumps(raw[0]):
        raw = [_sarif_to_daybreakish(r) for r in raw]
    cases: list[Case] = []
    for item in raw:
        item_kind = detect_kind(item, hint, kind if kind != "generic" else "")
        if item_kind == "daybreak":
            case = case_from_daybreak(item, scan)
        elif item_kind == "mythos":
            case = case_from_mythos(item)
        else:
            case = case_from_generic(item, item_kind)
        if finding_id and case.finding_id != finding_id and item.get("findingId") != finding_id:
            continue
        cases.append(case)
    return cases


def normalize_text(text: str, source_hint: str = "", source: str = "") -> Case:
    cases = findings_from_text(text, source=source, hint=source_hint)
    if not cases:
        raise ValueError("empty finding")
    return cases[0]


def findings_from_text(
    text: str,
    source: str = "",
    finding_id: str = "",
    hint: str = "",
    scan: dict[str, Any] | None = None,
) -> list[Case]:
    text = text.strip()
    if not text:
        raise ValueError("empty finding")
    if text[0] in "{[":
        data = json.loads(text)
        return findings_from_document(data, source=source, finding_id=finding_id, hint=hint, scan=scan)
    cves = _cves_from(text)
    if len(text.split()) == 1 and cves:
        return [
            Case(
                source="cve",
                source_kind="cve",
                title=cves[0],
                cves=cves,
                raw={"cve": cves[0]},
            )
        ]
    kind = detect_kind({"description": text}, hint, source) or "mythos"
    if kind == "daybreak":
        return [case_from_daybreak({"title": text.splitlines()[0][:120], "summary": text})]
    return [case_from_mythos({"title": text.splitlines()[0][:120], "description": text, "source": "mythos"})]


def _load_scan_dir(path: Path) -> tuple[Any, dict[str, Any] | None, str]:
    findings_path = path / "findings.json"
    manifest_path = path / "scan-manifest.json"
    if not findings_path.is_file():
        raise ValueError(f"no findings.json in scan directory {path}")
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    scan = None
    if manifest_path.is_file():
        man = json.loads(manifest_path.read_text(encoding="utf-8"))
        scan = man.get("scan") if isinstance(man.get("scan"), dict) else man
    return data, scan, "daybreak"


def findings_from_path(
    path: str | Path,
    source: str = "",
    finding_id: str = "",
) -> list[Case]:
    p = Path(path)
    if p.is_dir():
        data, scan, kind = _load_scan_dir(p)
        return findings_from_document(data, source=source or kind, finding_id=finding_id, hint=p.name, scan=scan)
    text = p.read_text(encoding="utf-8")
    return findings_from_text(text, source=source, finding_id=finding_id, hint=p.stem)


def normalize_path(path: str | Path, source_hint: str = "") -> Case:
    cases = findings_from_path(path, source=source_hint)
    if not cases:
        raise ValueError("no findings in input")
    return cases[0]
