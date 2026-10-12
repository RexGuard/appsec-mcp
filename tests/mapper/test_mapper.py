"""System mapper: expected routes and entry points per fixture, dedup, fallbacks, scale."""

from pathlib import Path

import pytest

from appsec_mcp.mapper.builder import build_map, summarize
from appsec_mcp.scan.ledger import LedgerCollector
from appsec_mcp.scan.walker import SourceFile, walk
from appsec_mcp.scanners.builtin import BuiltinScanner
from appsec_mcp.scanners.normalize import normalize
from tests.conftest import FIXTURE_NAMES, FIXTURES, load_expected


def _sources(root: Path) -> list[SourceFile]:
    return LedgerCollector().consume(walk(root, 1024 * 1024)).sources


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_routes_and_entry_points(name: str) -> None:
    root = FIXTURES / name
    sources = _sources(root)
    findings = normalize(BuiltinScanner().run(root, sources).findings)
    summary = summarize(build_map(name, sources, findings))
    expected = load_expected(name)
    assert set(expected["routes"]) <= set(summary.routes)
    assert set(expected["entry_points"]) <= set(summary.entry_points)
    assert summary.hotspots


def test_express_map_details() -> None:
    root = FIXTURES / "express_app"
    sources = _sources(root)
    findings = normalize(BuiltinScanner().run(root, sources).findings)
    graph = build_map("express_app", sources, findings)
    summary = summarize(graph)
    assert "MySQL" in summary.data_stores
    assert "https://api.stripe.com" in summary.external_services
    assert summary.secrets_locations == ["server.ts:5"]
    assert summary.dependencies_count == 3
    edges = [(e.source, e.target, e.kind) for e in graph.edges]
    assert len(edges) == len(set(edges))


def test_unsupported_language_falls_back_to_component(tmp_path: Path) -> None:
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "main.go").write_text("package main\nfunc main() {}\n")
    summary = summarize(build_map("go", _sources(tmp_path), []))
    assert "svc" in summary.components
    assert summary.routes == []


def test_nextjs_and_fastapi_routes(tmp_path: Path) -> None:
    route = tmp_path / "app" / "api" / "users"
    route.mkdir(parents=True)
    (route / "route.ts").write_text("export async function GET() {}\nexport function POST() {}\n")
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items/{id}')\ndef r(): ...\n"
    )
    routes = set(summarize(build_map("x", _sources(tmp_path), [])).routes)
    assert {"GET /api/users", "POST /api/users", "GET /items/{id}"} <= routes


def test_large_graph_builds(tmp_path: Path) -> None:
    lines = [f'app.get("/r{i}", h);' for i in range(300)]
    (tmp_path / "server.js").write_text("const app = express();\n" + "\n".join(lines))
    graph = build_map("big", _sources(tmp_path), [])
    assert len(graph.nodes) > 200
