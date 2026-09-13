"""Lint local mapping tables: unique keys, pair shape, confidence names."""

from __future__ import annotations

from vulnavigator.map import _conf, _tables


def test_confidence_comes_from_mappings_json():
    conf = _tables()["confidence"]
    assert "default" in conf
    assert _conf("cwe") == float(conf["cwe"])
    assert _conf("narrative") == float(conf["narrative"])
    assert _conf("overlay") == float(conf["overlay"])
    assert _conf("does-not-exist") == float(conf["default"])


def test_mapping_tables_are_pairs():
    tables = _tables()
    for name in ("cwe_attack", "attack_d3fend", "attack_csf", "ai_cwe_atlas", "fraud_attack_f3"):
        blob = tables[name]
        assert blob, name
        for key, rows in blob.items():
            assert key, name
            assert isinstance(rows, list) and rows, key
            for row in rows:
                assert len(row) == 2, (name, key, row)
                assert row[0] and row[1], (name, key, row)


def test_crosswalk_ids_exist_in_attack_tables():
    tables = _tables()
    attack_ids = set(tables["attack_d3fend"]) | set(tables["attack_csf"])
    for rows in tables["cwe_attack"].values():
        for tid, _name in rows:
            parent = tid.split(".")[0]
            assert parent in attack_ids or tid in attack_ids, tid
