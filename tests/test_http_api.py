"""Local HTTP API: token required, localhost only, CSP set, validation errors."""

import socket
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from appsec_mcp import http_api
from appsec_mcp.context import AppContext
from appsec_mcp.http_api import CSP, TOKEN_HEADER, create_app
from appsec_mcp.models.scan import ScanRequest

TOKEN = "t" * 32


@pytest.fixture
def client(ctx: AppContext, apps: Path, tmp_path: Path) -> TestClient:
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>AppSec</title>")
    ctx.scans.scan(ScanRequest(path=str(apps / "express_app")))
    return TestClient(create_app(ctx, TOKEN, static))


def _get(client: TestClient, path: str, token: str | None = TOKEN):  # type: ignore[no-untyped-def]
    headers = {TOKEN_HEADER: token} if token else {}
    return client.get(path, headers=headers)


def test_requires_token(client: TestClient) -> None:
    assert _get(client, "/api/scans", None).status_code == 401
    assert _get(client, "/api/scans", "wrong").status_code == 401
    assert _get(client, "/api/scans").status_code == 200


def test_endpoints_return_real_data(client: TestClient) -> None:
    scans = _get(client, "/api/scans").json()["items"]
    scan_id = scans[0]["scan_id"]
    findings = _get(client, f"/api/scans/{scan_id}/findings").json()
    assert findings["total"] > 0
    detail = _get(client, f"/api/findings/{findings['items'][0]['id']}").json()
    assert detail["how_to_fix"]
    assert _get(client, f"/api/scans/{scan_id}/map").json()["nodes"]
    assert _get(client, f"/api/scans/{scan_id}/ledger?section=files").json()["files"]["read"] > 0
    assert _get(client, f"/api/scans/{scan_id}").json()["scan_id"] == scan_id


def test_errors(client: TestClient) -> None:
    assert _get(client, "/api/scans/999").status_code == 404
    assert _get(client, "/api/scans/1/findings?limit=99999").status_code == 422
    assert _get(client, "/api/scans/1/findings?min_severity=bad").status_code == 422
    assert _get(client, "/api/scans/1/ledger?section=x").status_code == 422


def test_security_headers_and_static(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200 and "AppSec" in response.text
    assert response.headers["content-security-policy"] == CSP
    assert response.headers["x-frame-options"] == "DENY"


def test_api_is_read_only(client: TestClient) -> None:
    response = client.post("/api/scans", headers={TOKEN_HEADER: TOKEN})
    assert response.status_code == 405


def test_binds_only_to_localhost(ctx: AppContext, monkeypatch: pytest.MonkeyPatch) -> None:
    bound: list[tuple[str, int]] = []

    class _FakeServer:
        def __init__(self, config: object) -> None:
            pass

        def run(self, sockets: list[socket.socket]) -> None:
            bound.append(sockets[0].getsockname())
            sockets[0].close()

    import uvicorn

    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    http_api.serve_viewer(ctx, port=0, open_browser=False)
    assert bound[0][0] == "127.0.0.1"
