"""Turn Mythos, Daybreak, CVE, or generic JSON into a Case."""

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


def _guess_kind(data: dict[str, Any], hint: str = "") -> str:
    blob = f"{hint} {json.dumps(data)}".lower()
    if "daybreak" in blob or "codex security" in blob or "codex_security" in blob:
        return "daybreak"
    if "mythos" in blob or "glasswing" in blob:
        return "mythos"
    if data.get("cve") and not data.get("title") and len(data) <= 3:
        return "cve"
    return "generic"


def _locations(data: dict[str, Any]) -> list[Location]:
    raw = data.get("locations") or data.get("affected_locations") or []
    out: list[Location] = []
    if isinstance(raw, str):
        raw = [{"path": raw}]
    for item in raw:
        if isinstance(item, str):
            out.append(Location(path=item))
        elif isinstance(item, dict):
            line = item.get("line") or item.get("startLine")
            out.append(
                Location(
                    path=str(item.get("path") or item.get("file") or ""),
                    line=int(line) if line not in (None, "") else None,
                    snippet=str(item.get("snippet") or item.get("code") or ""),
                )
            )
    return out


def _evidence(data: dict[str, Any]) -> Evidence:
    val = data.get("validation") if isinstance(data.get("validation"), dict) else {}
    status = str(val.get("status") or data.get("validation_status") or "").lower()
    reproduced = data.get("reproduced")
    if reproduced is None:
        if status in {"reproduced", "validated", "confirmed", "true"}:
            reproduced = True
        elif status in {"not_reproduced", "failed", "false"}:
            reproduced = False
    sandbox = val.get("sandbox")
    if sandbox is None:
        sandbox = data.get("sandbox_validated")
    poc = (
        data.get("poc")
        or data.get("proof_of_concept")
        or val.get("evidence")
        or val.get("poc")
        or ""
    )
    refs = _as_list(data.get("references") or val.get("references"))
    return Evidence(
        reproduced=None if reproduced is None else bool(reproduced),
        sandbox=None if sandbox is None else bool(sandbox),
        poc=str(poc),
        notes=str(val.get("notes") or data.get("evidence_notes") or ""),
        references=refs,
    )


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


def normalize_dict(data: dict[str, Any], source_hint: str = "") -> Case:
    kind = _guess_kind(data, source_hint)
    target = data.get("target") if isinstance(data.get("target"), dict) else {}
    rem = data.get("remediation") if isinstance(data.get("remediation"), dict) else {}

    title = str(
        data.get("title")
        or data.get("name")
        or data.get("summary")
        or data.get("cve")
        or "Untitled finding"
    )
    description = str(
        data.get("description")
        or data.get("details")
        or data.get("writeup")
        or rem.get("summary")
        or ""
    )
    cves = _cves_from(data.get("cve"), data.get("cves"), title, description, data)
    cwes = _cwes_from(data.get("cwe"), data.get("cwes"), title, description, data)

    product = str(
        data.get("product")
        or target.get("product")
        or data.get("package")
        or data.get("repo")
        or ""
    )
    component = str(
        data.get("component") or target.get("component") or data.get("module") or ""
    )
    version = str(data.get("version") or target.get("version") or data.get("affected_version") or "")

    patch = rem.get("summary") or rem.get("guidance") or data.get("suggested_fix") or ""

    case = Case(
        source=str(data.get("source") or kind),
        source_kind=kind,
        title=title,
        description=description,
        cves=cves,
        cwes=cwes,
        product=product,
        component=component,
        version=version,
        locations=_locations(data),
        evidence=_evidence(data),
        source_severity=str(data.get("severity") or data.get("source_severity") or ""),
        asset_internet_facing=_optional_bool(
            data, "internet_facing", "asset_internet_facing", "exposed"
        ),
        asset_ai_system=_optional_bool(data, "ai_system", "asset_ai_system", "ai_in_scope"),
        asset_fraud_relevant=_optional_bool(
            data, "fraud_relevant", "asset_fraud_relevant", "payments"
        ),
        data_class=str(data.get("data_class") or data.get("data_classification") or ""),
        raw=data,
    )
    if patch:
        case.remediation.append(str(patch))
    return case


def normalize_text(text: str, source_hint: str = "") -> Case:
    text = text.strip()
    if not text:
        raise ValueError("empty finding")
    if text[0] in "{[":
        data = json.loads(text)
        if isinstance(data, list):
            if not data:
                raise ValueError("empty finding list")
            data = data[0]
        if not isinstance(data, dict):
            raise ValueError("JSON finding must be an object")
        return normalize_dict(data, source_hint)
    cves = _cves_from(text)
    if len(text.split()) == 1 and cves:
        return Case(
            source="cve",
            source_kind="cve",
            title=cves[0],
            cves=cves,
            raw={"cve": cves[0]},
        )
    return Case(
        source=source_hint or "generic",
        source_kind=_guess_kind({"description": text}, source_hint),
        title=text.splitlines()[0][:120],
        description=text,
        cves=cves,
        cwes=_cwes_from(text),
        raw={"text": text},
    )


def normalize_path(path: str | Path, source_hint: str = "") -> Case:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    hint = source_hint or p.stem
    return normalize_text(text, hint)
