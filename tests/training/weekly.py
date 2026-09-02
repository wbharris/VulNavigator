#!/usr/bin/env python3
"""Blind-CVE corpus refresh, rescan, and compact error pack.

  weekly.py --rescan           re-analyze frozen corpus, write pack
  weekly.py --grow             fetch next +150 CVE-2026 rows (needs NVD key)
  weekly.py --preflight-only   validate corpus/scorecard state
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = HERE.parent / "data" / "blind_cve_2026.json"
DEFAULT_GROW = 150


def _python() -> str:
    venv = ROOT / ".venv" / "bin" / "python"
    return str(venv) if venv.is_file() else sys.executable


def _run(args: list[str]) -> None:
    subprocess.check_call(args, cwd=str(ROOT))


def corpus_n() -> int:
    if not CORPUS.is_file():
        return 0
    return len(json.loads(CORPUS.read_text(encoding="utf-8")))


def preflight(*, rescan: bool = False, grow: bool = False) -> None:
    """Fail fast on missing corpus; warn on thin corpus or missing scorecards."""
    if not CORPUS.is_file():
        raise SystemExit(f"preflight FAIL: missing frozen corpus {CORPUS}")
    n = corpus_n()
    if grow:
        mode = "grow"
    elif rescan:
        mode = "rescan"
    else:
        mode = "pack"
    print(f"preflight mode={mode} corpus_n={n} path={CORPUS}", flush=True)
    if n == 0 and not grow:
        raise SystemExit("preflight FAIL: empty corpus; run weekly.py --grow")
    if n < 300:
        print(f"preflight WARN: corpus n={n} < 300 (pytest floor)", flush=True)
    cards = sorted((ROOT / "cases").glob("blind-first-*.json")) if (ROOT / "cases").is_dir() else []
    if not cards and not grow:
        print(
            "preflight WARN: no cases/blind-first-*.json; pack needs --grow or --rescan",
            flush=True,
        )
    print("preflight OK", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Blind-CVE corpus refresh and error pack.")
    parser.add_argument(
        "--grow",
        action="store_true",
        help=f"expand corpus by {DEFAULT_GROW} (NVD fetch)",
    )
    parser.add_argument("--rescan", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="validate corpus/scorecard state and exit (no fetch, no pack)",
    )
    args = parser.parse_args()
    py = _python()
    refresh = HERE / "refresh_blind_cve.py"
    pack = HERE / "error_pack.py"
    n = corpus_n()

    if args.preflight_only:
        preflight(rescan=args.rescan, grow=args.grow)
        return

    if args.grow:
        preflight(grow=True)
        target = args.limit or (n + DEFAULT_GROW if n else DEFAULT_GROW)
        print(f"grow corpus {n} → {target} (NVD fetch)")
        _run([py, str(refresh), str(target)])
        limit = target
    elif args.rescan:
        preflight(rescan=True)
        limit = args.limit or n or 300
        print(f"rescan n={limit} (no NVD fetch)")
        _run([py, str(refresh), str(limit), "--rescan"])
    else:
        preflight()
        limit = args.limit or n or 0

    pack_cmd = [py, str(pack), "--samples", str(args.samples)]
    if limit:
        pack_cmd.append(str(limit))
    _run(pack_cmd)


if __name__ == "__main__":
    main()
