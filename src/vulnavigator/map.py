"""Map a validated case onto ATT&CK, D3FEND, CSF, and optional overlays.

Confidence (see data/mappings.json → confidence):
  0.62  CWE-heuristic — CWE commonly enables the technique
  0.55  narrative RCE claim
  0.45  follow-on execution after claimed RCE
  0.40  location-only placeholder
  0.50  ATLAS / AI RMF / F3 overlay when the asset is tagged
These are ordinal, not calibrated probabilities.
"""

from __future__ import annotations

import json
import logging
from functools import cache
from importlib.resources import files

from vulnavigator.heuristics import mentions_rce
from vulnavigator.models import Case, Mapping

log = logging.getLogger("vulnavigator.map")


@cache
def _tables() -> dict:
    raw = files("vulnavigator.data").joinpath("mappings.json").read_text(encoding="utf-8")
    return json.loads(raw)


def _pairs(table: str, key: str) -> list[tuple[str, str]]:
    rows = _tables().get(table, {}).get(key) or []
    return [(a, b) for a, b in rows]


def _conf(name: str) -> float:
    return float(_tables().get("confidence", {}).get(name, 0.5))


def _add_unique(dest: list[Mapping], item: Mapping) -> None:
    if any(m.id == item.id and m.framework == item.framework for m in dest):
        return
    dest.append(item)


def map_case(case: Case) -> Case:
    if case.validation_status == "rejected":
        log.debug("skip mapping rejected case %s", case.finding_id or case.title)
        return case

    conf_cwe = _conf("cwe")
    for cve in case.cves:
        for cwe in _tables().get("cve_cwe", {}).get(cve.upper(), []) or []:
            if cwe not in case.cwes:
                case.cwes.append(cwe)

    for cwe in case.cwes:
        for tid, name in _pairs("cwe_attack", cwe):
            _add_unique(
                case.attack,
                Mapping(
                    id=tid,
                    name=name,
                    framework="ATT&CK",
                    provenance="cwe-heuristic",
                    confidence=conf_cwe,
                    rationale=f"{cwe} commonly enables {tid}",
                ),
            )

    blob = f"{case.title} {case.description}"
    if not case.attack and mentions_rce(blob):
        log.info("narrative RCE heuristic for %s", case.title)
        _add_unique(
            case.attack,
            Mapping(
                id="T1190",
                name="Exploit Public-Facing Application",
                framework="ATT&CK",
                provenance="narrative-heuristic",
                confidence=_conf("narrative"),
                rationale="Write-up claims possible RCE on an exposed application",
            ),
        )
        _add_unique(
            case.attack,
            Mapping(
                id="T1059",
                name="Command and Scripting Interpreter",
                framework="ATT&CK",
                provenance="narrative-heuristic",
                confidence=_conf("narrative_followon"),
                rationale="RCE typically implies code or command execution after exploit",
            ),
        )

    if not case.attack and case.cves:
        log.info("CVE-only ATT&CK placeholder for %s", case.title)
        _add_unique(
            case.attack,
            Mapping(
                id="T1190",
                name="Exploit Public-Facing Application",
                framework="ATT&CK",
                provenance="cve-heuristic",
                confidence=_conf("location"),
                rationale="CVE present without a mapped CWE; public-app exploit is a placeholder",
            ),
        )

    if not case.attack and case.locations:
        log.info("location-only ATT&CK placeholder for %s", case.title)
        _add_unique(
            case.attack,
            Mapping(
                id="T1190",
                name="Exploit Public-Facing Application",
                framework="ATT&CK",
                provenance="location-heuristic",
                confidence=_conf("location"),
                rationale="Code location present but no CWE; public-app exploit is a placeholder",
            ),
        )

    for tech in case.attack:
        parent = tech.id.split(".")[0]
        for did, dname in _pairs("attack_d3fend", tech.id) or _pairs("attack_d3fend", parent):
            _add_unique(
                case.d3fend,
                Mapping(
                    id=did,
                    name=dname,
                    framework="D3FEND",
                    provenance="attack-artifact",
                    confidence=tech.confidence,
                    rationale=f"Countermeasure for {tech.id}",
                ),
            )
        for cid, cname in _pairs("attack_csf", tech.id) or _pairs("attack_csf", parent):
            _add_unique(
                case.csf,
                Mapping(
                    id=cid,
                    name=cname,
                    framework="NIST CSF 2.0",
                    provenance="attack-crosswalk",
                    confidence=tech.confidence,
                    rationale=f"CSF rollup of {tech.id}",
                ),
            )

    if case.asset_ai_system:
        for cwe in case.cwes:
            for aid, aname in _pairs("ai_cwe_atlas", cwe):
                _add_unique(
                    case.atlas,
                    Mapping(
                        id=aid,
                        name=aname,
                        framework="ATLAS",
                        provenance="cwe-heuristic",
                        confidence=_conf("overlay"),
                        rationale=f"{cwe} on an AI-tagged asset",
                    ),
                )
        if case.atlas:
            case.airmf = [
                Mapping(
                    id="MEASURE",
                    name="Measure",
                    framework="NIST AI RMF",
                    provenance="atlas-rollup",
                    confidence=_conf("overlay"),
                    rationale="Adversarial technique present — test and monitor",
                ),
                Mapping(
                    id="MANAGE",
                    name="Manage",
                    framework="NIST AI RMF",
                    provenance="atlas-rollup",
                    confidence=_conf("overlay"),
                    rationale="Treat as an AI-system incident path until patched",
                ),
            ]

    if case.asset_fraud_relevant:
        for tech in case.attack:
            parent = tech.id.split(".")[0]
            for fid, fname in _pairs("fraud_attack_f3", tech.id) or _pairs("fraud_attack_f3", parent):
                _add_unique(
                    case.f3,
                    Mapping(
                        id=fid,
                        name=fname,
                        framework="F3",
                        provenance="attack-crosswalk",
                        confidence=0.45,
                        rationale=f"Fraud overlay of {tech.id} (asset marked fraud-relevant)",
                    ),
                )
    return case
