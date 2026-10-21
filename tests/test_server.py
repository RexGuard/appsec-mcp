"""MCP contract tests through an in-process client."""

from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from appsec_mcp.context import AppContext
from appsec_mcp.models.finding import FindingDetail, FindingList
from appsec_mcp.models.ledger import Ledger
from appsec_mcp.models.patch import PatchApplied, PatchProposal, PatchReverted, RecipeList
from appsec_mcp.models.scan import ScanList, ScanResult
from appsec_mcp.models.system_map import SystemGraph, SystemSummary
from appsec_mcp.server import build_server

EXPECTED_TOOLS = {
    "ping",
    "scan_project",
    "get_findings",
    "explain_finding",
    "get_system_map",
    "get_audit_ledger",
    "list_scans",
    "list_recipes",
    "propose_patch",
    "propose_hardening",
    "apply_patch",
    "revert_patch",
    "check_website",
    "get_attack_chains",
    "mark_false_positive",
    "unmark_false_positive",
    "list_false_positives",
}


async def _call(client: Client, name: str, args: dict[str, Any]) -> dict[str, Any]:
    result = await client.call_tool(name, args)
    assert not result.is_error, result.content
    assert result.structured_content is not None
    return result.structured_content


async def test_ping_and_tool_list(ctx: AppContext) -> None:
    async with Client(build_server(ctx)) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        assert tools == EXPECTED_TOOLS
        result = await client.call_tool("ping", {})
        assert result.content[0].text == "pong"


async def test_full_flow_scan_explain_map_ledger(ctx: AppContext, apps: Path) -> None:
    async with Client(build_server(ctx)) as client:
        scan = ScanResult.model_validate(
            await _call(client, "scan_project", {"path": str(apps / "express_app")})
        )
        assert scan.counts.critical >= 1
        findings = FindingList.model_validate(
            await _call(client, "get_findings", {"scan_id": scan.scan_id})
        )
        assert findings.total == len(findings.items) > 0
        detail = FindingDetail.model_validate(
            await _call(client, "explain_finding", {"finding_id": findings.items[0].id})
        )
        assert detail.how_to_fix
        summary = SystemSummary.model_validate(
            (await _call(client, "get_system_map", {"scan_id": scan.scan_id}))["summary"]
        )
        assert "GET /users/:id" in summary.routes
        graph = SystemGraph.model_validate(
            (await _call(client, "get_system_map", {"scan_id": scan.scan_id, "format": "graph"}))[
                "graph"
            ]
        )
        assert graph.nodes
        ledger = Ledger.model_validate(
            await _call(client, "get_audit_ledger", {"scan_id": scan.scan_id})
        )
        assert ledger.files is not None and ledger.files.read == scan.files_read
        scans = ScanList.model_validate(await _call(client, "list_scans", {}))
        assert scans.items[0].scan_id == scan.scan_id


async def test_patch_flow_through_tools(ctx: AppContext, apps: Path) -> None:
    async with Client(build_server(ctx)) as client:
        scan = await _call(client, "scan_project", {"path": str(apps / "flask_app")})
        findings = FindingList.model_validate(
            await _call(client, "get_findings", {"scan_id": scan["scan_id"]})
        )
        debug = next(f for f in findings.items if f.cwe == "CWE-489")
        proposal = PatchProposal.model_validate(
            await _call(client, "propose_patch", {"finding_id": debug.id})
        )
        applied = PatchApplied.model_validate(
            await _call(client, "apply_patch", {"proposal_token": proposal.proposal_token})
        )
        assert applied.files_changed == ["app.py"]
        reverted = PatchReverted.model_validate(
            await _call(client, "revert_patch", {"patch_id": applied.patch_id})
        )
        assert reverted.files_restored == ["app.py"]
        recipes = RecipeList.model_validate(
            await _call(client, "list_recipes", {"scan_id": scan["scan_id"]})
        )
        assert any(r.id == "security_headers" and r.applicable for r in recipes.recipes)


@pytest.mark.parametrize(
    ("tool", "args", "code"),
    [
        ("get_findings", {"scan_id": 999}, "SCAN_NOT_FOUND"),
        ("explain_finding", {"finding_id": 999}, "FINDING_NOT_FOUND"),
        ("scan_project", {"path": "Z:/definitely/not/here"}, "PATH_NOT_FOUND"),
        ("apply_patch", {"proposal_token": "x" * 32}, "TOKEN_INVALID"),
        ("revert_patch", {"patch_id": 5}, "PATCH_NOT_FOUND"),
        ("check_website", {"url": "ftp://example.com"}, "URL_INVALID"),
    ],
)
async def test_errors_carry_codes(
    ctx: AppContext, tool: str, args: dict[str, Any], code: str
) -> None:
    async with Client(build_server(ctx)) as client:
        result = await client.call_tool(tool, args)
        assert result.is_error
        assert code in result.content[0].text


@pytest.mark.parametrize(
    "args",
    [
        {"scan_id": -1},
        {"scan_id": 0},
        {"scan_id": 1, "limit": 10**9},
        {"scan_id": "abc"},
        {"scan_id": 1, "min_severity": "bad"},
    ],
)
async def test_bad_inputs_are_rejected(ctx: AppContext, args: dict[str, Any]) -> None:
    async with Client(build_server(ctx)) as client:
        result = await client.call_tool("get_findings", args)
        assert result.is_error
