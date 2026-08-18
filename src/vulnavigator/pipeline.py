"""One-shot analyze pipeline."""

from __future__ import annotations

from pathlib import Path

from vulnavigator.enrich import enrich
from vulnavigator.map import map_case
from vulnavigator.models import Case
from vulnavigator.normalize import normalize_path, normalize_text
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


def analyze_path(path: str | Path, offline: bool = False) -> Case:
    return analyze_case(normalize_path(path), offline=offline)


def analyze_text(text: str, offline: bool = False, source_hint: str = "") -> Case:
    return analyze_case(normalize_text(text, source_hint), offline=offline)
