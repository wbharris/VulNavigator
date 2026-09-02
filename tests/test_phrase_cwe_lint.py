"""Lint phrase → CWE rule table: ids, families, compile, exclusive overlaps."""

from __future__ import annotations

import re

from vulnavigator.artifacts import cwes_from_text
from vulnavigator.data.phrase_cwe import FAMILIES, PHRASE_CWE_RULES, compiled_bug_cwe


def test_rule_ids_unique_families_and_patterns_compile() -> None:
    ids = [r["id"] for r in PHRASE_CWE_RULES]
    assert len(ids) == len(set(ids))
    assert ids, "empty rule table"
    for rule in PHRASE_CWE_RULES:
        assert rule["family"] in FAMILIES, rule["id"]
        assert rule["cwe"].startswith("CWE-"), rule["id"]
        assert rule["owner"], rule["id"]
        re.compile(rule["pattern"], re.I)
        for other in rule.get("exclusive_with") or []:
            assert any(r["id"] == other for r in PHRASE_CWE_RULES), (rule["id"], other)
    compiled = compiled_bug_cwe()
    assert len(compiled) == len(PHRASE_CWE_RULES)
    assert [cwe for _pat, cwe in compiled] == [r["cwe"] for r in PHRASE_CWE_RULES]


def test_exclusive_rules_do_not_cofire_on_their_own_probes() -> None:
    by_id = {r["id"]: r for r in PHRASE_CWE_RULES}
    for rule in PHRASE_CWE_RULES:
        others = rule.get("exclusive_with") or []
        if not others:
            continue
        # A short probe that is just the first literal-ish alternative.
        probe = re.split(r"[|()]", rule["pattern"])[0]
        probe = probe.replace(r"\b", " ").replace(r"\s*", " ").replace("[- ]", " ")
        probe = re.sub(r"[\\^$*+?{}]", "", probe).strip()
        if len(probe) < 4:
            continue
        got = set(cwes_from_text(probe))
        for oid in others:
            assert by_id[oid]["cwe"] not in got or by_id[oid]["cwe"] == rule["cwe"], (
                rule["id"],
                oid,
                probe,
                got,
            )
