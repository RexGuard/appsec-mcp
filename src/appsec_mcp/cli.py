"""Command line: `serve` (MCP over stdio), `scan` (headless, for CI) and `view` (local viewer)."""

import argparse
import json
import logging
import sys
from collections.abc import Sequence

from appsec_mcp import __version__
from appsec_mcp.context import AppContext, build_context
from appsec_mcp.errors import AppSecError
from appsec_mcp.logging_setup import configure_logging
from appsec_mcp.models.base import SEVERITY_RANK, severity_at_least
from appsec_mcp.models.finding import FindingItem
from appsec_mcp.models.scan import ScanRequest, ScanResult

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
_MAX_PRINTED = 500


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="appsec-mcp", description=__doc__)
    parser.add_argument("--version", action="version", version=f"appsec-mcp {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="Run the MCP server over stdio (default).")
    scan = sub.add_parser("scan", help="Scan a folder and print the results.")
    scan.add_argument("path")
    scan.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    scan.add_argument(
        "--fail-on",
        choices=list(SEVERITY_RANK),
        default=None,
        help="Exit 1 when any finding is at or above this severity.",
    )
    scan.add_argument("--max-file-kb", type=int, default=1024)
    view = sub.add_parser("view", help="Open the local results viewer.")
    view.add_argument("--port", type=int, default=0, help="0 picks a free port.")
    view.add_argument("--no-browser", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the `appsec-mcp` command."""
    args = _parser().parse_args(argv)
    ctx = build_context()
    configure_logging(ctx.settings.logs_dir)
    command = args.command or "serve"
    try:
        if command == "serve":
            return _serve(ctx)
        if command == "scan":
            return _scan(ctx, args)
        return _view(ctx, args)
    except AppSecError as exc:
        logger.error("%s: %s", exc.code, exc.message)
        print(f"Error {exc.code}: {exc.message}", file=sys.stderr)
        return EXIT_ERROR


def _serve(ctx: AppContext) -> int:
    from appsec_mcp.server import build_server

    build_server(ctx).run()
    return EXIT_OK


def _scan(ctx: AppContext, args: argparse.Namespace) -> int:
    result = ctx.scans.scan(ScanRequest(path=args.path, max_file_kb=args.max_file_kb))
    findings = ctx.queries.findings(result.scan_id, "info", _MAX_PRINTED, 0)
    if args.json:
        print(
            json.dumps({"scan": result.model_dump(), "findings": findings.model_dump()}, indent=2)
        )
    else:
        _print_text(result, findings.items)
    if args.fail_on and any(severity_at_least(f.severity, args.fail_on) for f in findings.items):
        return EXIT_FINDINGS
    return EXIT_OK


def _print_text(result: ScanResult, items: Sequence[FindingItem]) -> None:
    counts = result.counts
    print(
        f"Scan {result.scan_id} of {result.project}: score {result.score}/100 "
        f"({counts.critical} critical, {counts.high} high, {counts.medium} medium, "
        f"{counts.low} low) | {result.new} new, {result.fixed} fixed"
    )
    print(
        f"Read {result.files_read} files, skipped {result.files_skipped}. Scanners: "
        f"{', '.join(result.scanners_run) or 'none'}"
    )
    for skipped in result.scanners_skipped:
        print(f"  skipped {skipped.name}: {skipped.reason} {skipped.install_hint}")
    for item in items:
        location = f"{item.rel_path}:{item.line_start}" if item.line_start else item.rel_path
        print(f"[{item.severity.upper():8}] {item.title} - {location}")
        print(f"           {item.plain_explanation}")


def _view(ctx: AppContext, args: argparse.Namespace) -> int:
    from appsec_mcp.http_api import serve_viewer

    serve_viewer(ctx, port=args.port, open_browser=not args.no_browser)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
