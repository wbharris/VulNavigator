"""CLI: vuln-nav analyze FILE."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vulnavigator import __version__
from vulnavigator.pipeline import analyze_path, analyze_text
from vulnavigator.report import to_json, to_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vuln-nav",
        description="Normalize, validate, and map a Mythos or Daybreak finding.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"vuln-nav {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    an = sub.add_parser("analyze", help="Analyze a finding file or a CVE id")
    an.add_argument("input", help="Path to JSON/text finding, or CVE-YYYY-NNNNN")
    an.add_argument("-o", "--output", help="Write report here (default: stdout)")
    an.add_argument("--json", action="store_true", help="Emit the case file as JSON")
    an.add_argument("--offline", action="store_true", help="Skip NVD / KEV / EPSS")

    args = parser.parse_args(argv)
    raw = args.input
    path = Path(raw)
    try:
        if path.is_file():
            case = analyze_path(path, offline=args.offline)
        else:
            case = analyze_text(raw, offline=args.offline)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    text = to_json(case) if args.json else to_markdown(case)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
