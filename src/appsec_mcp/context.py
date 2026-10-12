"""Composition root: wires settings, storage, scanners and services together."""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from appsec_mcp.config import Settings, load_settings
from appsec_mcp.scanners.base import ScannerAdapter
from appsec_mcp.scanners.builtin import BuiltinScanner
from appsec_mcp.scanners.gitleaks import GitleaksScanner
from appsec_mcp.scanners.osv import OsvScanner
from appsec_mcp.scanners.semgrep import SemgrepScanner
from appsec_mcp.services.patch_service import PatchService
from appsec_mcp.services.query_service import QueryService
from appsec_mcp.services.repositories import Repositories
from appsec_mcp.services.scan_service import ScanService
from appsec_mcp.services.web_check_service import WebCheckService
from appsec_mcp.storage.db import Database


def default_adapters() -> list[ScannerAdapter]:
    """All scanners, in the order they are reported."""
    return [SemgrepScanner(), GitleaksScanner(), OsvScanner(), BuiltinScanner()]


@dataclass(frozen=True)
class AppContext:
    """Everything the MCP server, CLI and HTTP API need."""

    settings: Settings
    repos: Repositories
    scans: ScanService
    queries: QueryService
    patches: PatchService
    web: WebCheckService


def build_context(
    home: Path | None = None, adapters: Sequence[ScannerAdapter] | None = None
) -> AppContext:
    """Build the application. Pass `adapters` to inject fakes in tests."""
    settings = load_settings(home)
    repos = Repositories.over(Database(settings.db_path))
    queries = QueryService(repos)
    scans = ScanService(repos, adapters if adapters is not None else default_adapters())
    return AppContext(
        settings=settings,
        repos=repos,
        scans=scans,
        queries=queries,
        patches=PatchService(repos, queries, settings.backups_dir),
        web=WebCheckService(),
    )
