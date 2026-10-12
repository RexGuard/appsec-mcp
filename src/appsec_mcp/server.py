"""MCP tool definitions. Kept thin: each tool validates input, calls a service, and returns a model."""

from __future__ import annotations

import logging

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from appsec_mcp import __version__
from appsec_mcp.errors import AppSecError

log = logging.getLogger(__name__)

INSTRUCTIONS = """AppSec MCP checks the user's own source code for security problems.
- Start with scan_project on the project folder, then get_findings to list problems by severity.
- Explain findings in plain language; explain_finding gives what / why / how to fix.
- get_system_map and get_audit_ledger show what the app is made of and exactly what was read.
- Never apply a fix without showing the diff from propose_patch and getting the user's approval."""


def to_tool_error(err: AppSecError) -> ToolError:
    """Log a domain error, then convert it to the MCP error the client sees."""
    log.info("tool error %s: %s", err.code, err.message)
    return ToolError(err.to_text())


def create_server() -> MCPServer:
    server = MCPServer(name="appsec-mcp", version=__version__, instructions=INSTRUCTIONS)

    @server.tool(description="Check that the AppSec MCP server is running. Returns 'pong'.")
    def ping() -> str:
        return "pong"

    return server


def run_stdio() -> None:
    """Serve MCP over stdin/stdout. stdout carries protocol messages only."""
    create_server().run("stdio")
