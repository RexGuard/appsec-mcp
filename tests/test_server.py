import subprocess
import sys

from mcp import Client

from appsec_mcp.errors import AppSecError, PathForbidden
from appsec_mcp.server import create_server, to_tool_error


async def test_ping_returns_pong():
    async with Client(create_server()) as client:
        result = await client.call_tool("ping", {})
    assert not result.is_error
    assert result.content[0].text == "pong"


async def test_ping_is_listed():
    async with Client(create_server()) as client:
        tools = await client.list_tools()
    assert "ping" in {t.name for t in tools.tools}


def test_domain_error_carries_code_and_plain_message():
    err = PathForbidden()
    assert isinstance(err, AppSecError)
    assert to_tool_error(err).args[0].startswith("PATH_FORBIDDEN: ")


def test_serve_writes_nothing_to_stdout_before_a_request():
    # With stdin closed the server exits at once; anything on stdout would corrupt the protocol.
    proc = subprocess.run(
        [sys.executable, "-m", "appsec_mcp", "serve"],
        input=b"",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert proc.stdout == b""


async def test_ping_over_real_stdio():
    from mcp import StdioServerParameters

    params = StdioServerParameters(command=sys.executable, args=["-m", "appsec_mcp", "serve"])
    async with Client(params) as client:
        result = await client.call_tool("ping", {})
    assert result.content[0].text == "pong"
