"""Gated CI Fortify and NIST SSDF 1.2 overlays.

Same contract as ATLAS / AI RMF / F3: ATT&CK, D3FEND, and CSF always run.
These overlays fire only when the case is tagged in-scope. They are not
CWE→technique tables and they do not add a 12th report section.
"""

from __future__ import annotations

from vulnavigator.models import Action, Case, Mapping

# Software-producer / SCA / AI-finder kinds infer SSDF unless forced off.
SSDF_SOURCE_KINDS = frozenset(
    {"mythos", "daybreak", "sarif", "trivy", "snyk", "dependabot"}
)

OT_SECTORS = frozenset(
    {"ics", "ot", "ci", "water", "energy", "power", "transport", "wastewater"}
)

_FORTIFY = (
    (
        "ISO.1",
        "Identify vital systems",
        "Is this host on the minimum set that must keep the critical service up?",
    ),
    (
        "ISO.2",
        "Isolation points",
        "Can we cut IT / internet / vendor / cloud on this path and still deliver?",
    ),
    (
        "ISO.3",
        "Operate isolated",
        "Manual ops; no licensing, DNS, or identity that lives only on the business net.",
    ),
    (
        "REC.1",
        "Recover / rebuild",
        "Rebuild or fail to manual if isolation fails; practice it.",
    ),
)

_CONF = 0.50


def parse_overlay(value: str) -> set[str]:
    return {p.strip().lower() for p in (value or "").replace(";", ",").split(",") if p.strip()}


def apply_overlay_tags(case: Case, sector: str = "", overlay: str = "") -> Case:
    """Set OT/SSDF tags from CLI, JSON, then source-kind inference."""
    parts = parse_overlay(overlay)
    sector_l = (sector or "").strip().lower()
    raw = case.raw if isinstance(case.raw, dict) else {}

    if parts & {"none", "off"}:
        case.asset_ot_ci = False
        case.asset_software_ssdf = False
        case.overlay_ssdf_inferred = False
        return case

    if "fortify" in parts or "ci-fortify" in parts or sector_l in OT_SECTORS:
        case.asset_ot_ci = True
        if sector_l in OT_SECTORS:
            case.overlay_fortify_inferred = True

    ot_json = _raw_bool(raw, "ot_in_scope", "ci_in_scope", "asset_ot_ci", "ot")
    if ot_json is True:
        case.asset_ot_ci = True
    elif ot_json is False and case.asset_ot_ci is not True:
        case.asset_ot_ci = False

    raw_sector = str(raw.get("sector") or raw.get("ci_sector") or "").strip().lower()
    if raw_sector in OT_SECTORS:
        case.asset_ot_ci = True
        case.overlay_fortify_inferred = True

    if "ssdf" in parts:
        case.asset_software_ssdf = True
        case.overlay_ssdf_inferred = False
    if parts & {"no-ssdf", "ssdf-off"}:
        case.asset_software_ssdf = False
        case.overlay_ssdf_inferred = False

    ssdf_json = _raw_bool(raw, "ssdf_in_scope", "software_ssdf", "asset_software_ssdf")
    if ssdf_json is True:
        case.asset_software_ssdf = True
        case.overlay_ssdf_inferred = False
    elif ssdf_json is False:
        case.asset_software_ssdf = False
        case.overlay_ssdf_inferred = False

    if case.asset_software_ssdf is None:
        if case.source_kind in SSDF_SOURCE_KINDS:
            case.asset_software_ssdf = True
            case.overlay_ssdf_inferred = True
        else:
            case.asset_software_ssdf = False

    if case.asset_ot_ci is None:
        case.asset_ot_ci = False
    return case


def map_overlays(case: Case) -> Case:
    if case.validation_status == "rejected":
        return case
    if case.asset_ot_ci:
        for oid, name, rationale in _FORTIFY:
            _add(
                case.fortify,
                Mapping(
                    id=oid,
                    name=name,
                    framework="CI Fortify",
                    provenance="overlay",
                    confidence=_CONF,
                    rationale=rationale,
                ),
            )
    if case.asset_software_ssdf:
        _add(
            case.ssdf,
            Mapping(
                id="RV.1",
                name="Identify vulnerabilities",
                framework="NIST SSDF 1.2",
                provenance="overlay",
                confidence=_CONF,
                rationale="This finding is intake for vulnerability identification (RV.1)",
            ),
        )
        _add(
            case.ssdf,
            Mapping(
                id="RV.2",
                name="Assess, prioritize, and remediate vulnerabilities",
                framework="NIST SSDF 1.2",
                provenance="overlay",
                confidence=_CONF,
                rationale="Remediate or record not-applicable for this finding (RV.2)",
            ),
        )
        if _wants_ps4(case):
            _add(
                case.ssdf,
                Mapping(
                    id="PS.4",
                    name="Ensure software updates are robust and reliable",
                    framework="NIST SSDF 1.2",
                    provenance="overlay",
                    confidence=_CONF,
                    rationale="Fix is a software update; confirm it is tested and controllable",
                ),
            )
        if case.source_kind in {"mythos", "daybreak"}:
            _add(
                case.ssdf,
                Mapping(
                    id="PW.8",
                    name="Test executable code to identify vulnerabilities",
                    framework="NIST SSDF 1.2",
                    provenance="overlay",
                    confidence=_CONF,
                    rationale="AI 0-day: this class was not designed or tested out before release",
                ),
            )
    return case


def overlay_priority_reasons(case: Case) -> list[str]:
    """Narrative reasons only — do not change the priority score."""
    reasons: list[str] = []
    if case.asset_ot_ci and case.fortify:
        hot = bool(case.asset_internet_facing) or bool(case.evidence.poc.strip()) or bool(
            case.evidence.reproduced
        )
        if hot:
            reasons.append(
                "Path into vital OT — isolation is this-week compensating control (CI Fortify)"
            )
    if any(m.id == "PS.4" for m in case.ssdf):
        reasons.append(
            "Fix is a software update; confirm it is tested and controllable (SSDF PS.4)"
        )
    return reasons


def apply_overlay_actions(case: Case) -> None:
    if case.validation_status == "rejected":
        return
    if case.fortify:
        for line in (
            "CI Fortify ISO.2: isolate this path from IT / internet / vendor / cloud until the fix lands "
            "(VLANs alone are not isolation)",
            "CI Fortify ISO.3: confirm the critical service can run without licensing, DNS, or IdP on the business net",
            "CI Fortify REC.1: practice rebuild or fail-to-manual if isolation fails",
        ):
            if line not in case.compensating_controls:
                case.compensating_controls.append(line)
        case.next_actions.append(
            Action(
                "Map every connection from this host to vital OT and name isolation points",
                "ot-ops",
                "Diagram shows IT/vendor/cloud links and which can be cut",
            )
        )
        case.next_actions.append(
            Action(
                "Test isolation for this path (full cut, not a VLAN-only drill)",
                "ot-ops",
                "Service still delivers, or gaps (licensing/DNS/IdP) are listed",
            )
        )
    if case.ssdf:
        ps4 = "Confirm the vendor/package update is tested and customer-controllable (SSDF PS.4)"
        rv = "Record this finding in vuln intake and remediate or mark not-applicable (SSDF RV.1 / RV.2)"
        if any(m.id == "PS.4" for m in case.ssdf) and ps4 not in case.remediation:
            case.remediation.append(ps4)
        if rv not in case.remediation:
            case.remediation.append(rv)
        case.next_actions.append(
            Action(
                "Owner of the producing or consuming SDLC ships or accepts the update",
                "engineering",
                "Update deployed, deferred with date, or not-applicable recorded",
            )
        )


def _wants_ps4(case: Case) -> bool:
    if case.source_kind in {"trivy", "snyk", "dependabot", "nexus", "sarif"}:
        return True
    if case.cves:
        return True
    blob = f"{case.title} {case.description}".lower()
    return any(w in blob for w in ("update", "upgrade", "patch", "package"))


def _raw_bool(data: dict, *keys: str) -> bool | None:
    for key in keys:
        if key not in data or data[key] is None:
            continue
        val = data[key]
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            if val.lower() in {"true", "yes", "1"}:
                return True
            if val.lower() in {"false", "no", "0"}:
                return False
    return None


def _add(dest: list[Mapping], item: Mapping) -> None:
    if any(m.id == item.id and m.framework == item.framework for m in dest):
        return
    dest.append(item)



