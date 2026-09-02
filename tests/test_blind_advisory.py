"""Phrase-family regression pack (positive, negative, ambiguity)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnavigator.models import is_ai_zeroday
from vulnavigator.pipeline import analyze_text

PACK = Path(__file__).resolve().parent / "data" / "phrase_families.json"


def _rows() -> list[dict]:
    return json.loads(PACK.read_text(encoding="utf-8"))


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r["id"])
def test_phrase_family(row: dict) -> None:
    case = analyze_text(row["text"], offline=True)[0]
    for cwe in row.get("expect_cwes") or []:
        assert cwe in case.cwes, f"{row['id']}: want {cwe}, got {case.cwes}"
    for cwe in row.get("forbid_cwes") or []:
        assert cwe not in case.cwes, f"{row['id']}: forbid {cwe}, got {case.cwes}"
    if "expect_facing" in row:
        if row["expect_facing"] is False:
            assert case.asset_internet_facing is not True, row["id"]
        else:
            assert case.asset_internet_facing is True, row["id"]
    if row.get("expect_product"):
        assert row["expect_product"].lower() in (case.product or "").lower(), case.product
    if row.get("expect_version"):
        assert case.version == row["expect_version"], case.version
    if row.get("expect_version_prefix"):
        assert (case.version or "").startswith(row["expect_version_prefix"]), case.version
    if row.get("expect_path_suffix"):
        assert any(loc.path.endswith(row["expect_path_suffix"]) for loc in case.locations)
    if row.get("expect_public_exploit"):
        assert "public exploit" in case.evidence.notes.lower()
    if row.get("not_ai_zeroday"):
        assert not is_ai_zeroday(case)
        assert not any("No CVE expected" in n for n in case.validation_notes)
        assert not any("AI 0-day identity" in n for n in case.validation_notes)
    if row.get("expect_source_kind"):
        assert case.source_kind == row["expect_source_kind"]
    if row.get("expect_cves_empty", True):
        assert case.cves == []


def test_phrase_family_cwes_are_deterministic() -> None:
    from vulnavigator.artifacts import cwes_from_text

    first = {row["id"]: cwes_from_text(row["text"]) for row in _rows()}
    second = {row["id"]: cwes_from_text(row["text"]) for row in _rows()}
    assert first == second
