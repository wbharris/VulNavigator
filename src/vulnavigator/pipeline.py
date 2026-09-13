"""One-shot analyze pipeline.

Order is fixed (do not call the steps out of sequence):

    apply_narrative → enrich → validate → map → record_assumptions
    → prioritize → score_data_quality → plan_actions

Derived lists (mappings, assumptions, next actions, generated remediations)
and live enrichment (NVD/KEV/EPSS/CVSS) are cleared at the start of each run
so re-processing a Case is idempotent. Finder-supplied remediations live on
``Case.source_remediation``.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from vulnavigator.enrich import enrich
from vulnavigator.map import map_case
from vulnavigator.models import Case
from vulnavigator.narrative import apply_narrative
from vulnavigator.normalize import findings_from_path, findings_from_text, normalize_path, normalize_text
from vulnavigator.overlays import apply_overlay_tags
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
    case.fortify = []
    case.ssdf = []
    case.assumptions = []
    case.improve = []
    case.next_actions = []
    case.compensating_controls = []
    case.priority_reasons = []
    case.validation_notes = []
    case.missing_evidence = []
    case.remediation = list(case.source_remediation)
    case.nvd_description = ""
    case.cvss = None
    case.kev = False
    case.epss = None


def _workers(explicit: int | None, n: int) -> int:
    if n <= 1:
        return 1
    if explicit is not None:
        return max(1, min(int(explicit), n, 32))
    raw = (os.environ.get("VULN_NAV_WORKERS") or "").strip()
    if raw:
        try:
            return max(1, min(int(raw), n, 32))
        except ValueError:
            pass
    return max(1, min(4, n))


def analyze_case(case: Case, offline: bool = False, timeout: float | None = None) -> Case:
    reset_derived(case)
    apply_narrative(case)
    enrich(case, offline=offline, timeout=timeout)
    validate(case)
    map_case(case)
    record_assumptions(case)
    case.missing_evidence = [i.question for i in case.improve]
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


def analyze_many(
    cases: list[Case],
    offline: bool = False,
    sector: str = "",
    overlay: str = "",
    timeout: float | None = None,
    workers: int | None = None,
) -> list[Case]:
    for case in cases:
        apply_overlay_tags(case, sector=sector, overlay=overlay)
    n = _workers(workers, len(cases))
    if n <= 1 or len(cases) <= 1:
        return [analyze_case(c, offline=offline, timeout=timeout) for c in cases]
    out: list[Case | None] = [None] * len(cases)
    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = {
            pool.submit(analyze_case, case, offline, timeout): i
            for i, case in enumerate(cases)
        }
        for fut in as_completed(futs):
            out[futs[fut]] = fut.result()
    return [c for c in out if c is not None]


def analyze_path(
    path: str | Path,
    offline: bool = False,
    source: str = "",
    finding_id: str = "",
    sector: str = "",
    overlay: str = "",
    timeout: float | None = None,
    workers: int | None = None,
) -> list[Case]:
    return analyze_many(
        findings_from_path(path, source=source, finding_id=finding_id),
        offline=offline,
        sector=sector,
        overlay=overlay,
        timeout=timeout,
        workers=workers,
    )


def analyze_text(
    text: str,
    offline: bool = False,
    source_hint: str = "",
    source: str = "",
    finding_id: str = "",
    sector: str = "",
    overlay: str = "",
    timeout: float | None = None,
    workers: int | None = None,
) -> list[Case]:
    return analyze_many(
        findings_from_text(text, source=source or source_hint, finding_id=finding_id, hint=source_hint),
        offline=offline,
        sector=sector,
        overlay=overlay,
        timeout=timeout,
        workers=workers,
    )


def analyze_one_path(path: str | Path, offline: bool = False) -> Case:
    return analyze_many([normalize_path(path)], offline=offline)[0]


def analyze_one_text(text: str, offline: bool = False, source_hint: str = "") -> Case:
    return analyze_many([normalize_text(text, source_hint)], offline=offline)[0]
