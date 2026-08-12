from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .reporters import render_json, render_markdown
from .scanner import scan_project


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-risk-scan",
        description="Scan agent-oriented projects for common static security risks.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Write the report to this file instead of stdout",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Report format (default: markdown)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        scan_result = scan_project(
            args.path,
            exclude_paths={args.output} if args.output is not None else None,
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        report = render_json(args.path, scan_result)
    else:
        report = render_markdown(args.path, scan_result)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
        print(
            f"Wrote {args.format} report to {args.output} "
            f"({len(scan_result.findings)} risks)."
        )
    else:
        print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
