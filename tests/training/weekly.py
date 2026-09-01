#!/usr/bin/env python3
"""Local-first weekly blind-CVE training, sized by SuperGrok % used.

  weekly.py --used N           N = SuperGrok Usage percent; suggest + execute
  weekly.py --used N --suggest-only
  weekly.py --rescan           re-analyze current corpus, then pack
  weekly.py --grow             ignore percent table; +150

Grok: when the operator gives a usage percent, run ``weekly.py --used N``
with that value, read ``cases/error-pack.md`` only, fix, pytest, ``--rescan``,
repeat up to the printed rounds. Do not wait for confirmation. End with
errors + fixes.
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


def suggest(used: int) -> dict:
    """Map SuperGrok % used → grow size and Grok fix rounds."""
    used = max(0, min(100, int(used)))
    remaining = 100 - used
    if remaining >= 75:
        grow, rounds, mode = 150, 3, "full"
    elif remaining >= 50:
        grow, rounds, mode = 100, 3, "full"
    elif remaining >= 30:
        grow, rounds, mode = 50, 2, "medium"
    elif remaining >= 15:
        grow, rounds, mode = 25, 2, "small"
    elif remaining >= 6:
        grow, rounds, mode = 0, 1, "fix-only"
    else:
        grow, rounds, mode = 0, 0, "report-only"
    n = corpus_n()
    target = n + grow if grow else n
    return {
        "used": used,
        "remaining": remaining,
        "grow": grow,
        "rounds": rounds,
        "mode": mode,
        "corpus": n,
        "target": target,
    }


def _print_suggest(plan: dict) -> None:
    print(
        "SUGGESTED "
        f"used={plan['used']}% remaining={plan['remaining']}% "
        f"mode={plan['mode']} grow=+{plan['grow']} "
        f"corpus={plan['corpus']} target={plan['target']} "
        f"rounds={plan['rounds']}"
    )
    print(
        "Table: 0–25% used → +150/3; 26–50% → +100/3; 51–70% → +50/2; "
        "71–85% → +25/2; 86–94% → fix-only/1; 95%+ → report-only"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Blind-CVE training sized by SuperGrok percent used."
    )
    parser.add_argument("--used", type=int, default=None, help="SuperGrok usage percent 0-100")
    parser.add_argument("--suggest-only", action="store_true")
    parser.add_argument(
        "--grow",
        action="store_true",
        help=f"expand by {DEFAULT_GROW} (ignore percent table)",
    )
    parser.add_argument("--rescan", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--samples", type=int, default=20)
    args = parser.parse_args()
    py = _python()
    refresh = HERE / "refresh_blind_cve.py"
    pack = HERE / "error_pack.py"
    n = corpus_n()
    plan = suggest(args.used) if args.used is not None else None

    if plan:
        _print_suggest(plan)
        if args.suggest_only:
            return
        if plan["mode"] == "report-only":
            print("mode=report-only: pack only, no fetch, no extractor edits")
        elif plan["grow"]:
            target = plan["target"]
            print(f"EXECUTE grow {n} → {target}")
            _run([py, str(refresh), str(target)])
            n = target
        else:
            print(f"EXECUTE rescan n={n or 300} (fix-only)")
            _run([py, str(refresh), str(args.limit or n or 300), "--rescan"])
        limit = args.limit or plan["target"] or n
        _run([py, str(pack), str(limit), "--samples", str(args.samples)])
        print()
        print(
            f"Grok: read cases/error-pack.md only. Fix extractors, update skill, "
            f"pytest, weekly.py --rescan. Repeat ≤ {plan['rounds']} times. "
            "Do not ask to continue. End with errors + fixes."
        )
        return

    if args.grow:
        target = args.limit or (n + DEFAULT_GROW if n else DEFAULT_GROW)
        print(f"grow corpus {n} → {target} (NVD fetch, local CPU)")
        _run([py, str(refresh), str(target)])
        limit = target
    elif args.rescan:
        limit = args.limit or n or 300
        print(f"rescan n={limit} (no NVD fetch)")
        _run([py, str(refresh), str(limit), "--rescan"])
    else:
        limit = args.limit or n or 0

    pack_cmd = [py, str(pack), "--samples", str(args.samples)]
    if limit:
        pack_cmd.append(str(limit))
    _run(pack_cmd)


if __name__ == "__main__":
    main()
