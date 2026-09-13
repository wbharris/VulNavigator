"""NVIDIA NIM error-pack suggester: parse, validate, mocked chat."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from vulnavigator.data.phrase_cwe import FAMILIES


def _mod():
    path = Path(__file__).resolve().parent / "training" / "nim_suggest.py"
    spec = importlib.util.spec_from_file_location("nim_suggest", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


PACK = """\
# VulNavigator weekly error pack

## Samples (2 of 2 fails)

### CVE-2026-0544
nvd=['CWE-89'] vn=[] product='School Management System'
- MISSING: phrase CWE ['CWE-89'] not on case []

A security flaw has been discovered in itsourcecode School Management System 1.0. This affects an unknown part of the file /student/index.php. The manipulation of the argument ID results in sql injection. It is possible to launch the attack remotely.

### CVE-2026-9999
nvd=['CWE-20'] vn=[] product='Widget'
- MISSING: NVD CWE CWE-20

The vendor advisory says an application mishandles input. No more detail.

## Next
"""


def test_parse_pack_two_samples():
    m = _mod()
    rows = m.parse_pack(PACK)
    assert [r["cve"] for r in rows] == ["CVE-2026-0544", "CVE-2026-9999"]
    assert "sql injection" in rows[0]["description"]
    assert any("phrase CWE" in i for i in rows[0]["issues"])
    assert "CWE-20" in rows[1]["nvd_cwe"]


def test_validate_keeps_phrase_that_matches_sample():
    m = _mod()
    sample = m.parse_pack(PACK)[0]
    row = {
        "id": "sqli-index",
        "family": "injection",
        "cwe": "CWE-89",
        "pattern": r"sql\s*injection",
        "quote": "sql injection",
        "owner": "narrative",
        "reason": "prose names sql injection",
    }
    assert m.validate_candidate(sample, row) == []


def test_validate_rejects_pattern_not_in_sample():
    m = _mod()
    sample = m.parse_pack(PACK)[0]
    row = {
        "id": "xxe-miss",
        "family": "xml",
        "cwe": "CWE-611",
        "pattern": r"\bxxe\b|xml external entity",
        "quote": "xxe",
        "reason": "guess",
    }
    reasons = m.validate_candidate(sample, row)
    assert "pattern does not match sample" in reasons
    assert "quote not in sample" in reasons


def test_validate_rejects_nvd_only_cwe_id_pattern():
    m = _mod()
    sample = m.parse_pack(PACK)[1]
    row = {
        "id": "nvd-20",
        "family": "other",
        "cwe": "CWE-20",
        "pattern": r"CWE-20",
        "quote": "",
        "reason": "NVD listed CWE-20",
    }
    reasons = m.validate_candidate(sample, row)
    assert any("NVD-only" in r or "pattern does not match" in r for r in reasons)


def test_validate_rejects_ai_zeroday_and_bad_family():
    m = _mod()
    sample = m.parse_pack(PACK)[0]
    row = {
        "id": "bad",
        "family": "not-a-family",
        "cwe": "CWE-89",
        "pattern": r"sql\s*injection",
        "quote": "sql injection",
        "reason": "this is an AI 0-day",
    }
    reasons = m.validate_candidate(sample, row)
    assert "ai-0day claim" in reasons
    assert any("unknown family" in r for r in reasons)
    assert "not-a-family" not in FAMILIES


def test_parse_model_json_fenced():
    m = _mod()
    data = m.parse_model_json(
        '```json\n{"suggestions":[{"id":"x","cwe":"CWE-89"}],"skip":""}\n```'
    )
    assert data["suggestions"][0]["cwe"] == "CWE-89"


def test_run_dry_run_no_network():
    m = _mod()
    report = m.run(PACK, key="", model="x", base="http://127.0.0.1", dry_run=True)
    assert report["dry_run"] is True
    assert report["samples"] == 2
    assert report["results"][0]["cve"] == "CVE-2026-0544"


def test_run_empty_pack_notes_clean_scorecard():
    m = _mod()
    report = m.run("# pack\n\nNone.\n", key="", model="x", base="http://127.0.0.1", dry_run=True)
    assert report["samples"] == 0
    assert "clean scorecard" in report["note"]


def test_run_continues_after_one_timeout():
    m = _mod()
    calls = {"n": 0}

    def flaky(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("read timed out")
        return json.dumps({"suggestions": [], "skip": "NVD-only product miss"})

    report = m.run(
        PACK,
        key="fake",
        model="mock",
        base="http://127.0.0.1",
        sleep_s=0,
        chat=flaky,
    )
    assert report["results"][0]["error"].startswith("TimeoutError")
    assert report["results"][1]["skip"] == "NVD-only product miss"
    assert calls["n"] == 2


def test_run_mocked_chat_keeps_and_rejects():
    m = _mod()

    def fake_chat(**kwargs):
        prompt = kwargs["messages"][1]["content"]
        if "CVE-2026-0544" in prompt:
            return json.dumps(
                {
                    "suggestions": [
                        {
                            "id": "sqli-from-nim",
                            "family": "injection",
                            "cwe": "CWE-89",
                            "pattern": r"sql\s*injection",
                            "quote": "sql injection",
                            "owner": "narrative",
                            "reason": "named in prose",
                        }
                    ],
                    "skip": "",
                }
            )
        return json.dumps(
            {
                "suggestions": [
                    {
                        "id": "nvd-20",
                        "family": "other",
                        "cwe": "CWE-20",
                        "pattern": r"CWE-20",
                        "quote": "",
                        "reason": "from NVD gold",
                    }
                ],
                "skip": "",
            }
        )

    report = m.run(
        PACK,
        key="fake",
        model="mock",
        base="http://127.0.0.1",
        sleep_s=0,
        chat=fake_chat,
    )
    by_cve = {r["cve"]: r for r in report["results"]}
    assert len(by_cve["CVE-2026-0544"]["kept"]) == 1
    assert by_cve["CVE-2026-0544"]["kept"][0]["id"] == "sqli-from-nim"
    assert by_cve["CVE-2026-9999"]["kept"] == []
    assert by_cve["CVE-2026-9999"]["rejected"]


def test_main_dry_run_on_missing_pack(tmp_path, capsys):
    m = _mod()
    missing = tmp_path / "no-pack.md"
    with pytest.raises(SystemExit, match="missing"):
        m.main(["--pack", str(missing), "--dry-run"])


def test_main_dry_run_writes_json(tmp_path):
    m = _mod()
    pack = tmp_path / "error-pack.md"
    pack.write_text(PACK, encoding="utf-8")
    out = tmp_path / "nim-suggest.json"
    assert m.main(["--pack", str(pack), "--dry-run", "-o", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["samples"] == 2


@pytest.mark.skipif(not _mod().api_key(), reason="no NVIDIA_API_KEY")
def test_live_nim_one_sample_optional():
    m = _mod()
    sample = m.parse_pack(PACK)[0]
    try:
        result = m.suggest_one(
            sample,
            key=m.api_key(),
            model=m.DEFAULT_MODEL,
            base=m.DEFAULT_BASE,
            timeout=20,
        )
    except (RuntimeError, TimeoutError, OSError) as exc:
        pytest.skip(f"NIM unreachable: {exc}"[:240])
    assert result["cve"] == "CVE-2026-0544"
    for row in result["kept"]:
        assert row["cwe"].startswith("CWE-")
        assert row["family"] in FAMILIES
