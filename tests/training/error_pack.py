#!/usr/bin/env python3
"""Compact fail report: issue counts + a few sample descriptions.

Run locally. Do not dump the full scorecard.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "cases"
CORPUS = Path(__file__).resolve().parents[1] / "data" / "blind_cve_2026.json"

GROW = 150
SAMPLES = 20
DESC_CHARS = 480

PACK_RULES = """\
When fixing extractors from this pack (description only, --offline):

- Teach only phrases present in the sample text.
- Add a `phrase_cwe.py` rule and a `tests/data/phrase_families.json` row.
- Phrase → CWE, not NVD-only labels. Contract: `docs/TRAINING.md`.
- `pytest -q`, then `weekly.py --rescan`. A pasted advisory without a CVE id is not an AI 0-day.
- Do not open `blind-first-N.json` or dump every fail.
"""


def _kind(issue: str) -> str:
    if issue.startswith("MISSING: NVD CWE"):
        return "NVD CWE miss"
    if issue.startswith("MISSING: phrase CWE"):
        return "phrase CWE miss"
    if issue.startswith("MISSING: product"):
        return "product miss"
    if issue.startswith("MISSING: file path"):
        return "file path miss"
    if issue.startswith("MISSING: empty ATT&CK"):
        return "empty ATT&CK"
    if issue.startswith("MISSING: remote"):
        return "remote miss"
    if issue.startswith("MISSING: RCE"):
        return "RCE miss"
    if issue.startswith("CONFLICT"):
        return "conflict"
    if issue.startswith("LEAK"):
        return "leak"
    return issue.split(":")[0] if ":" in issue else issue[:40]


def _latest_scorecard() -> Path:
    rows = sorted(CASES.glob("blind-first-*.json"), key=lambda p: p.stat().st_mtime)
    if not rows:
        raise SystemExit("no cases/blind-first-*.json — run weekly.py --grow first")
    return rows[-1]


def resolve_scorecard(limit: int = 0) -> Path:
    """Named scorecard, or newest local file if that limit was never written."""
    if not limit:
        return _latest_scorecard()
    score = CASES / f"blind-first-{limit}.json"
    if score.is_file():
        return score
    latest = _latest_scorecard()
    print(f"preflight FALLBACK: missing {score.name}; using {latest.name}", flush=True)
    return latest


def _limit_from_name(path: Path) -> int:
    try:
        return int(path.stem.split("-")[-1])
    except ValueError:
        return 0


def load_score(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_corpus() -> dict[str, dict]:
    if not CORPUS.is_file():
        return {}
    return {r["cve"]: r for r in json.loads(CORPUS.read_text(encoding="utf-8"))}


def pick_samples(fails: list[dict], n: int) -> list[dict]:
    """One example per issue kind, then fill remaining from later fails."""
    seen_kinds: set[str] = set()
    out: list[dict] = []
    for row in fails:
        kinds = {_kind(i) for i in row.get("issues") or []}
        if kinds - seen_kinds:
            out.append(row)
            seen_kinds |= kinds
        if len(out) >= n:
            return out
    for row in fails:
        if row in out:
            continue
        out.append(row)
        if len(out) >= n:
            break
    return out


def render(score_path: Path, samples: int = SAMPLES) -> str:
    rows = load_score(score_path)
    corpus = load_corpus()
    fails = [r for r in rows if r.get("issues")]
    kinds = Counter()
    for row in fails:
        for issue in row["issues"]:
            kinds[_kind(issue)] += 1
    limit = _limit_from_name(score_path)
    lines = [
        "# VulNavigator weekly error pack",
        "",
        f"Scorecard: `{score_path.relative_to(ROOT)}`  n={len(rows)}  "
        f"CLEAN {len(rows) - len(fails)}/{len(rows)}  fails={len(fails)}",
        f"Corpus rows: {len(corpus)}  (frozen file `{CORPUS.relative_to(ROOT)}`)",
        "",
        PACK_RULES,
        "## Issue kinds",
        "",
    ]
    if not kinds:
        lines.append("None. Do not add extractors. Regression only.")
        lines.append("")
        return "\n".join(lines)
    for name, count in kinds.most_common():
        lines.append(f"- {count} {name}")
    lines += ["", f"## Samples ({min(samples, len(fails))} of {len(fails)} fails)", ""]
    for row in pick_samples(fails, samples):
        cid = row.get("cve")
        desc = (corpus.get(cid) or {}).get("description") or row.get("blind") or ""
        lines.append(f"### {cid}")
        lines.append(f"nvd={row.get('nvd_cwe')} vn={row.get('vn_cwes')} product={row.get('vn_product')!r}")
        for issue in row.get("issues") or []:
            lines.append(f"- {issue}")
        lines.append("")
        lines.append(desc[:DESC_CHARS].rstrip() + ("…" if len(desc) > DESC_CHARS else ""))
        lines.append("")
    next_n = limit + GROW if limit else GROW
    lines += [
        "## Next",
        "",
        "```bash",
        ".venv/bin/python -m pytest -q",
        f".venv/bin/python tests/training/weekly.py --rescan --limit {limit or 300}",
        "```",
        "",
        f"Next grow (after this slice is clean): `weekly.py --grow` → {next_n}",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("limit", nargs="?", type=int, default=0, help="blind-first-N.json (default: newest)")
    parser.add_argument("--samples", type=int, default=SAMPLES)
    parser.add_argument("-o", "--out", type=Path, default=None)
    args = parser.parse_args()
    score = resolve_scorecard(args.limit)
    if not score.is_file():
        raise SystemExit(f"missing {score}")
    text = render(score, samples=args.samples)
    dest = args.out or (CASES / "error-pack.md")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text + "\n", encoding="utf-8")
    print(text)
    print(f"wrote {dest} ({len(text.encode('utf-8'))} bytes)", flush=True)


if __name__ == "__main__":
    main()
