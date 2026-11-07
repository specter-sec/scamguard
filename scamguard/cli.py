"""Command-line interface for ScamGuard."""

import argparse
import json
import logging
import sys
from typing import Sequence

from .engine import ScamDetector


def build_parser() -> argparse.ArgumentParser:
    """Create the command parser."""
    parser = argparse.ArgumentParser(
        prog="scamguard",
        description="Screen Urdu, Roman Urdu, and Hinglish messages for scam signals.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable informational logs.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan one message.")
    scan_parser.add_argument("text", nargs="?", help="Message text; stdin is used if omitted.")
    scan_parser.add_argument("--json", action="store_true", help="Print JSON output.")

    web_parser = subparsers.add_parser("web", help="Run the local Flask interface.")
    web_parser.add_argument(
        "--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)."
    )
    web_parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000).")
    web_parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    if args.command == "scan":
        message = args.text if args.text is not None else sys.stdin.read()
        result = ScamDetector().scan(message)
        if args.json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(f"Risk: {result.risk_level.value} ({result.score}/100)")
            for rule in result.triggered_rules:
                print(f"- [{rule.category}] {rule.title}: {rule.explanation}")
            if not result.triggered_rules:
                print(f"- {result.explanations[0]}")
        return 0

    if args.command == "web":
        from .web import create_app

        create_app().run(host=args.host, port=args.port, debug=args.debug)
        return 0

    parser.error("Unknown command")
    return 2
