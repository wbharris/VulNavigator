"""weekly.py preflight (corpus present, no usage-percent policy)."""

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


def test_preflight_ok_for_pack_rescan_grow(capsys):
    w = _weekly()
    w.preflight()
    w.preflight(rescan=True)
    w.preflight(grow=True)
    out = capsys.readouterr().out
    assert "preflight mode=pack" in out
    assert "preflight mode=rescan" in out
    assert "preflight mode=grow" in out
    assert "preflight FAIL" not in out
    assert w.corpus_n() >= 300
