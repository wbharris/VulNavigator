"""CLI: vuln-nav analyze FILE.

Expected intake: Mythos, Daybreak, and mainstream scanner / SARIF exports.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

FINDING_ID_RE = re.compile(r"^[\w.:/=@+-]{1,256}$")

from vulnavigator import __version__
from vulnavigator.pipeline import analyze_path, analyze_text
from vulnavigator.report import to_json, to_markdown
from vulnavigator.scanners import SCANNER_KINDS, alias_source

_SOURCES = ("mythos", "daybreak") + tuple(sorted(SCANNER_KINDS))


def _source_arg(value: str) -> str:
    mapped = alias_source(value)
    if mapped not in _SOURCES:
        raise argparse.ArgumentTypeError(
            f"unknown source {value!r} (try mythos, daybreak, qualys, openvas, nessus)"
        )
    return mapped


def _finding_id_arg(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if not FINDING_ID_RE.fullmatch(text):
        raise argparse.ArgumentTypeError(
            "finding id must be 1–256 characters: letters, digits, _.:/=@+-"
        )
    return text


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
        description="VulNavigator™ — analyze a Mythos, Daybreak, or scanner/SARIF finding.",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=(
            f"VulNavigator™ {__version__} (vuln-nav)\n"
            "VulNavigator is a trademark of wbharris."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    an = sub.add_parser(
        "analyze",
        help="Analyze a Mythos, Daybreak, or scanner/SARIF finding",
    )
    an.add_argument(
        "input",
        help="Finding file: Mythos, Daybreak, Qualys, OpenVAS, Nessus, Rapid7, SARIF, Trivy, Snyk, …",
    )
    an.add_argument("-o", "--output", help="Write report here (default: stdout)")
    an.add_argument("--json", action="store_true", help="Emit the case file as JSON")
    an.add_argument(
        "--offline",
        action="store_true",
        help=(
            "Skip NVD, CISA KEV, and FIRST EPSS. Mapping, validation, and the "
            "11-section report still run. Priority will not use live KEV/EPSS/CVSS."
        ),
    )
    an.add_argument(
        "--source",
        type=_source_arg,
        help="Force the source (mythos, daybreak, nessus, qualys, sarif, trivy, …)",
    )
    an.add_argument(
        "--id",
        dest="finding_id",
        default="",
        type=_finding_id_arg,
        help="Analyze only this finding id (Daybreak id, QID, plugin ID, NVT OID, Mythos id)",
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
