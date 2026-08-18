"""Canonical case file for one vulnerability finding."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Location:
    path: str = ""
    line: int | None = None
    snippet: str = ""


@dataclass
class Evidence:
    reproduced: bool | None = None
    sandbox: bool | None = None
    poc: str = ""
    discovery: str = ""
    notes: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class Mapping:
    id: str
    name: str = ""
    framework: str = ""
    provenance: str = ""
    confidence: float = 0.0
    rationale: str = ""


@dataclass
class Action:
    action: str
    owner: str = "security"
    done_when: str = ""


@dataclass
class Assumption:
    field: str
    assumed: str
    because: str
    impact: str = ""


@dataclass
class InfoNeed:
    question: str
    why_it_matters: str
    would_change: str = ""


@dataclass
class Case:
    source: str = "generic"
    source_kind: str = "unknown"  # daybreak | mythos | cve | generic
    finding_id: str = ""
    rule_id: str = ""
    scan_id: str = ""
    finder_confidence: str = ""
    title: str = ""
    description: str = ""
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    product: str = ""
    component: str = ""
    version: str = ""
    locations: list[Location] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)
    source_severity: str = ""
    asset_internet_facing: bool | None = None
    asset_ai_system: bool | None = None
    asset_fraud_relevant: bool | None = None
    data_class: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    # filled later
    validation_status: str = "unconfirmed"
    validation_notes: list[str] = field(default_factory=list)
    nvd_description: str = ""
    cvss: float | None = None
    kev: bool = False
    epss: float | None = None
    attack: list[Mapping] = field(default_factory=list)
    d3fend: list[Mapping] = field(default_factory=list)
    csf: list[Mapping] = field(default_factory=list)
    atlas: list[Mapping] = field(default_factory=list)
    airmf: list[Mapping] = field(default_factory=list)
    f3: list[Mapping] = field(default_factory=list)
    priority: str = "P3"
    urgency: str = "30_days"
    priority_reasons: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    compensating_controls: list[str] = field(default_factory=list)
    next_actions: list[Action] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    improve: list[InfoNeed] = field(default_factory=list)
    confidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


AI_FINDERS = frozenset({"mythos", "daybreak", "narrative"})


def is_ai_zeroday(case: Case) -> bool:
    """Mythos/Daybreak/narrative 0-days are identified by write-up + PoC, not CVE."""
    return case.source_kind in AI_FINDERS and not case.cves
