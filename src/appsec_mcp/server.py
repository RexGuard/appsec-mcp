"""MCP tool definitions. Thin: validate input, call a service, convert domain errors."""

import logging
from collections.abc import Callable
from typing import Annotated, Literal, TypeVar

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from appsec_mcp import __version__
from appsec_mcp.context import AppContext
from appsec_mcp.errors import AppSecError
from appsec_mcp.models.base import ScannerName, Severity
from appsec_mcp.models.finding import FindingDetail, FindingList
from appsec_mcp.models.ledger import Ledger
from appsec_mcp.models.patch import PatchApplied, PatchProposal, PatchReverted, RecipeList
from appsec_mcp.models.scan import ScanList, ScanRequest, ScanResult
from appsec_mcp.models.system_map import SystemMapResult
from appsec_mcp.models.web_check import WebCheckResult

logger = logging.getLogger(__name__)

T = TypeVar("T")

Id = Annotated[int, Field(ge=1, le=2**53, description="A positive id from an earlier result.")]
Limit = Annotated[int, Field(ge=1, le=500)]
Offset = Annotated[int, Field(ge=0, le=10_000_000)]

INSTRUCTIONS = """\
AppSec MCP finds security problems in a local project and explains them in plain language.
Typical flow: scan_project(path) -> get_findings(scan_id) -> explain_finding(id) ->
propose_patch(id) -> show the diff to the user -> apply_patch(token) only after the user
approves -> scan_project again to confirm it is fixed. get_system_map and get_audit_ledger show
what the app is made of and exactly what was read. Never apply a patch without the user's OK.
"""


def _call[T](fn: Callable[[], T]) -> T:
    """Run a service call, turning domain errors into MCP tool errors."""
    try:
        return fn()
    except AppSecError as exc:
        logger.info("Tool error %s: %s", exc.code, exc.message)
        raise ToolError(f"{exc.code}: {exc.message}") from exc


async def _call_in_thread[T](fn: Callable[[], T]) -> T:
    """Like _call, but off the event loop for slow work (scans, network)."""
    return await anyio.to_thread.run_sync(lambda: _call(fn))


def build_server(ctx: AppContext) -> MCPServer:
    """Create the MCP server with every tool bound to `ctx`."""
    server = MCPServer("appsec-mcp", version=__version__, instructions=INSTRUCTIONS)

    @server.tool()
    def ping() -> str:
        """Check that the server is running."""
        return "pong"

    @server.tool()
    async def scan_project(
        path: Annotated[
            str, Field(min_length=1, max_length=4096, description="Project folder to scan.")
        ],
        scanners: list[ScannerName] | None = None,
        max_file_kb: Annotated[int, Field(ge=1, le=102_400)] = 1024,
    ) -> ScanResult:
        """Scan a project folder for security problems (code, secrets, dependencies, config).

        Reads files only; never changes them. Missing scanners are reported with install hints.
        """
        request = ScanRequest(path=path, scanners=scanners, max_file_kb=max_file_kb)
        return await _call_in_thread(lambda: ctx.scans.scan(request))

    @server.tool()
    def get_findings(
        scan_id: Id,
        min_severity: Severity = "low",
        limit: Limit = 50,
        offset: Offset = 0,
        include_fixed: bool = False,
    ) -> FindingList:
        """List a scan's findings, worst first, each with a plain-language explanation."""
        return _call(
            lambda: ctx.queries.findings(scan_id, min_severity, limit, offset, include_fixed)
        )

    @server.tool()
    def explain_finding(finding_id: Id) -> FindingDetail:
        """Explain one finding: what it is, why it matters, and how to fix it."""
        return _call(lambda: ctx.queries.explain(finding_id))

    @server.tool()
    def get_system_map(
        scan_id: Id, format: Literal["summary", "graph"] = "summary"
    ) -> SystemMapResult:
        """Show what the app is made of: entry points, routes, data stores, external services,
        secret locations and dependencies, with the risky spots (hotspots)."""
        if format == "graph":
            return SystemMapResult(graph=_call(lambda: ctx.queries.graph(scan_id)))
        return SystemMapResult(summary=_call(lambda: ctx.queries.map_summary(scan_id)))

    @server.tool()
    def get_audit_ledger(
        scan_id: Id,
        section: Literal["files", "rules", "all"] = "all",
        limit: Limit = 200,
        offset: Offset = 0,
    ) -> Ledger:
        """Show exactly what the scan read (with hashes), what it skipped and why, and every rule
        and scanner it ran."""
        return _call(lambda: ctx.queries.ledger(scan_id, section, limit, offset))

    @server.tool()
    def list_scans(project_path: str | None = None, limit: Limit = 20) -> ScanList:
        """List previous scans, newest first, with their scores."""
        return _call(lambda: ctx.queries.list_scans(project_path, limit))

    @server.tool()
    def list_recipes(scan_id: Id) -> RecipeList:
        """List hardening recipes ("add a security layer") and whether each fits this project."""
        return _call(lambda: ctx.patches.list_recipes(scan_id))

    @server.tool()
    def propose_patch(finding_id: Id) -> PatchProposal:
        """Prepare a fix for a finding and return the diff. Writes nothing. Show the diff to the
        user and apply it only after they approve."""
        return _call(lambda: ctx.patches.propose_patch(finding_id))

    @server.tool()
    def propose_hardening(
        scan_id: Id, recipe: Annotated[str, Field(min_length=1, max_length=64)]
    ) -> PatchProposal:
        """Prepare a hardening recipe (see list_recipes) as a diff. Writes nothing."""
        return _call(lambda: ctx.patches.propose_hardening(scan_id, recipe))

    @server.tool()
    def apply_patch(
        proposal_token: Annotated[str, Field(min_length=16, max_length=128)],
    ) -> PatchApplied:
        """Apply a proposed patch. Only call this after the user approved the diff. Files are
        backed up first, and the patch is refused if they changed since the proposal."""
        return _call(lambda: ctx.patches.apply_patch(proposal_token))

    @server.tool()
    def revert_patch(patch_id: Id, force: bool = False) -> PatchReverted:
        """Undo an applied patch, restoring the original files byte for byte."""
        return _call(lambda: ctx.patches.revert_patch(patch_id, force))

    @server.tool()
    async def check_website(
        url: Annotated[str, Field(min_length=8, max_length=2048)], allow_private: bool = False
    ) -> WebCheckResult:
        """Passively check a deployed website's HTTPS certificate, security headers and cookie
        flags using a single GET (plus redirects). Only check sites you own."""
        return await _call_in_thread(lambda: ctx.web.check(url, allow_private))

    return server
