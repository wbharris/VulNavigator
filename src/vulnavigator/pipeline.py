"""One-shot analyze pipeline.

Order is fixed (do not call the steps out of sequence):

    apply_narrative → enrich → validate → map → record_assumptions
    → prioritize → score_data_quality → plan_actions

Derived lists (mappings, assumptions, next actions, generated remediations)
are cleared at the start of each run so re-processing a Case is idempotent.
Finder-supplied remediations live on ``Case.source_remediation``.
"""

from __future__ import annotations

import logging
from pathlib import Path

from vulnavigator.enrich import enrich
from vulnavigator.map import map_case
from vulnavigator.models import Case
from vulnavigator.narrative import apply_narrative
from vulnavigator.normalize import findings_from_path, findings_from_text, normalize_path, normalize_text
from vulnavigator.prioritize import plan_actions, prioritize, record_assumptions, score_data_quality
from vulnavigator.validate import validate

log = logging.getLogger("vulnavigator.pipeline")

STEPS = (
    "narrative",
    "enrich",
    "validate",
    "map",
    "assumptions",
    "prioritize",
    "data_quality",
    "plan",
)


def reset_derived(case: Case) -> None:
    """Drop pipeline outputs so a second analyze_case does not duplicate them."""
    if case.remediation and not case.source_remediation:
        case.source_remediation = list(case.remediation)
    case.attack = []
    case.d3fend = []
    case.csf = []
    case.atlas = []
    case.airmf = []
    case.f3 = []
    case.assumptions = []
    case.improve = []
    case.next_actions = []
    case.compensating_controls = []
    case.priority_reasons = []
    case.validation_notes = []
    case.remediation = list(case.source_remediation)


def analyze_case(case: Case, offline: bool = False) -> Case:
    reset_derived(case)
    apply_narrative(case)
    enrich(case, offline=offline)
    validate(case)
    map_case(case)
    record_assumptions(case)
    prioritize(case)
    score_data_quality(case)
    plan_actions(case)
    log.info(
        "analyzed %s status=%s priority=%s quality=%s offline=%s",
        case.finding_id or case.title,
        case.validation_status,
        case.priority,
        case.data_quality,
        offline,
    )
    return case


def analyze_many(cases: list[Case], offline: bool = False) -> list[Case]:
    return [analyze_case(c, offline=offline) for c in cases]


def analyze_path(
    path: str | Path,
    offline: bool = False,
    source: str = "",
    finding_id: str = "",
) -> list[Case]:
    return analyze_many(findings_from_path(path, source=source, finding_id=finding_id), offline=offline)


def analyze_text(
    text: str,
    offline: bool = False,
    source_hint: str = "",
    source: str = "",
    finding_id: str = "",
) -> list[Case]:
    return analyze_many(
        findings_from_text(text, source=source or source_hint, finding_id=finding_id, hint=source_hint),
        offline=offline,
    )


def analyze_one_path(path: str | Path, offline: bool = False) -> Case:
    return analyze_case(normalize_path(path), offline=offline)


def analyze_one_text(text: str, offline: bool = False, source_hint: str = "") -> Case:
    return analyze_case(normalize_text(text, source_hint), offline=offline)
