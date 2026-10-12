"""Command line entry point: `appsec-mcp [serve]`."""

from __future__ import annotations

import argparse
import logging
import sys

from appsec_mcp import __version__


def _setup_logging() -> None:
    # stdout is reserved for the MCP protocol; everything human-readable goes to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appsec-mcp", description="Security checks for your code, over MCP."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="Start the MCP server over stdio (the default).")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging()
    if args.command in (None, "serve"):
        from appsec_mcp.server import run_stdio

        run_stdio()
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
