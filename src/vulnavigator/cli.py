"""CLI: vuln-nav analyze FILE.

Expected input is a Mythos write-up or a Daybreak / Codex Security
findings.json (or a sealed scan directory that contains one).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vulnavigator import __version__
from vulnavigator.pipeline import analyze_path, analyze_text
from vulnavigator.report import to_json, to_markdown


def _render(cases, as_json: bool) -> str:
    if as_json:
        if len(cases) == 1:
            return to_json(cases[0])
        return json.dumps([c.to_dict() for c in cases], indent=2, default=str) + "\n"
    parts = [to_markdown(c) for c in cases]
    if len(parts) == 1:
        return parts[0]
    header = f"# VulNavigator batch — {len(cases)} finding(s)\n\n"
    return header + "\n\n---\n\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vuln-nav",
        description="Analyze a Mythos or Daybreak finding into an actionable case.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"vuln-nav {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    an = sub.add_parser(
        "analyze",
        help="Analyze a Mythos write-up or Daybreak findings.json / scan directory",
    )
    an.add_argument(
        "input",
        help="Mythos JSON/markdown, Daybreak findings.json, or a Codex Security scan directory",
    )
    an.add_argument("-o", "--output", help="Write report here (default: stdout)")
    an.add_argument("--json", action="store_true", help="Emit the case file as JSON")
    an.add_argument("--offline", action="store_true", help="Skip NVD / KEV / EPSS")
    an.add_argument(
        "--source",
        choices=("mythos", "daybreak"),
        help="Force the finder (auto-detected from Codex Security documents)",
    )
    an.add_argument(
        "--id",
        dest="finding_id",
        default="",
        help="Analyze only this Daybreak findingId (or Mythos id)",
    )

    args = parser.parse_args(argv)
    raw = args.input
    path = Path(raw)
    try:
        if path.exists():
            cases = analyze_path(
                path,
                offline=args.offline,
                source=args.source or "",
                finding_id=args.finding_id,
            )
        else:
            cases = analyze_text(
                raw,
                offline=args.offline,
                source=args.source or "",
                finding_id=args.finding_id,
            )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not cases:
        print("error: no findings matched", file=sys.stderr)
        return 1

    kinds = {c.source_kind for c in cases}
    print(
        f"analyzed {len(cases)} finding(s) from {', '.join(sorted(kinds))}",
        file=sys.stderr,
    )
    text = _render(cases, args.json)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
