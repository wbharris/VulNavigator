"""One-shot analyze pipeline."""

from __future__ import annotations

from pathlib import Path

from vulnavigator.enrich import enrich
from vulnavigator.map import map_case
from vulnavigator.models import Case
from vulnavigator.normalize import findings_from_path, findings_from_text, normalize_path, normalize_text
from vulnavigator.prioritize import plan_actions, prioritize, record_assumptions
from vulnavigator.validate import validate


def analyze_case(case: Case, offline: bool = False) -> Case:
    enrich(case, offline=offline)
    validate(case)
    map_case(case)
    record_assumptions(case)
    prioritize(case)
    plan_actions(case)
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
