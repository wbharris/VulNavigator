"""SuperGrok % used → suggested grow / rounds."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _weekly():
    path = Path(__file__).resolve().parent / "training" / "weekly.py"
    spec = importlib.util.spec_from_file_location("weekly_train", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_suggest_table():
    w = _weekly()
    assert w.suggest(0)["grow"] == 150 and w.suggest(0)["rounds"] == 3
    assert w.suggest(20)["grow"] == 150
    assert w.suggest(40)["grow"] == 100
    assert w.suggest(60)["grow"] == 50
    plan = w.suggest(80)
    assert plan["grow"] == 25 and plan["rounds"] == 2 and plan["mode"] == "small"
    assert w.suggest(90)["mode"] == "fix-only"
    assert w.suggest(96)["mode"] == "report-only" and w.suggest(96)["rounds"] == 0
