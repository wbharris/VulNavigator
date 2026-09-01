"""Frozen blind-CVE corpus: description only, no CVE id in the input."""

from __future__ import annotations

import json
from pathlib import Path

from vulnavigator.artifacts import cwes_from_text
from vulnavigator.models import is_ai_zeroday
from vulnavigator.pipeline import analyze_text

_BUFFER_FAMILY = {
    "CWE-119",
    "CWE-120",
    "CWE-121",
    "CWE-122",
    "CWE-125",
    "CWE-787",
}


def _cwe_overlap(gold: list[str], got: list[str]) -> bool:
    have = set(got)
    for item in gold:
        if item in have:
            return True
        if item in _BUFFER_FAMILY and have & _BUFFER_FAMILY:
            return True
    return False

CORPUS = Path(__file__).resolve().parent / "data" / "blind_cve_2026.json"


def _rows() -> list[dict]:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def test_corpus_exists_and_has_fifty():
    rows = _rows()
    assert len(rows) >= 50  # grows as refresh_blind_cve.py is rerun
    assert all("CVE-" not in (row.get("description") or "") for row in rows)


def test_blind_corpus_no_leak_not_ai_zeroday_cwe_overlap():
    for row in _rows():
        desc = row["description"]
        case = analyze_text(desc, offline=True)[0]
        assert case.cves == [], row["cve"]
        assert not is_ai_zeroday(case), row["cve"]
        expected = cwes_from_text(desc)
        for cwe in expected:
            assert cwe in case.cwes, f"{row['cve']}: phrase implies {cwe}, case has {case.cwes}"
        assert case.validation_status != "rejected", row["cve"]
        assert case.cvss is None, row["cve"]
