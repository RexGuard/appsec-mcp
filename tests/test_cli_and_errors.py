"""CLI exit codes and robustness of tool inputs (fuzz-style)."""

import json
import random
import string
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from appsec_mcp import cli
from appsec_mcp.context import AppContext
from appsec_mcp.errors import AppSecError, ErrorCode, NotFoundError
from appsec_mcp.server import build_server

SEED = 1234
FUZZ_ROUNDS = 40


def test_scan_command_fail_on(
    apps: Path, home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("APPSEC_MCP_HOME", str(home))
    assert cli.main(["scan", str(apps / "cpp_cli"), "--fail-on", "high"]) == cli.EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "score" in out and "gets" in out.lower()
    assert cli.main(["scan", str(apps / "cpp_cli"), "--json"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"]["total"] >= 3


def test_scan_command_reports_errors(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APPSEC_MCP_HOME", str(home))
    assert cli.main(["scan", str(home / "missing")]) == cli.EXIT_ERROR


def test_error_carries_code_and_message() -> None:
    error = NotFoundError(ErrorCode.SCAN_NOT_FOUND, "nope")
    assert isinstance(error, AppSecError)
    assert error.code == "SCAN_NOT_FOUND" and "nope" in str(error)


def _random_value(rng: random.Random) -> Any:
    choices: list[Any] = [
        rng.randint(-(10**12), 10**12),
        "".join(rng.choices(string.printable, k=rng.randint(0, 50))),
        "🙂" * rng.randint(1, 5),
        None,
        [],
        {},
        "../../etc/passwd",
        "C:\\Windows",
        10**30,
        -0.5,
        True,
    ]
    return rng.choice(choices)


async def test_fuzzed_tool_inputs_only_give_typed_errors(ctx: AppContext) -> None:
    rng = random.Random(SEED)
    tools = [
        "get_findings",
        "explain_finding",
        "get_system_map",
        "get_audit_ledger",
        "list_scans",
        "propose_patch",
        "apply_patch",
        "revert_patch",
        "list_recipes",
        "scan_project",
        "propose_hardening",
    ]
    async with Client(build_server(ctx)) as client:
        listed = {t.name: t for t in (await client.list_tools()).tools}
        for _ in range(FUZZ_ROUNDS):
            name = rng.choice(tools)
            params = list(listed[name].input_schema.get("properties", {}))
            args = {p: _random_value(rng) for p in params}
            result = await client.call_tool(name, args)
            if result.is_error:
                text = result.content[0].text
                assert "Error executing tool" in text
                assert "Traceback" not in text
