"""Shared fixtures: isolated data home, copies of the vulnerable apps, and an app context."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from appsec_mcp.context import AppContext, build_context
from appsec_mcp.scanners.builtin import BuiltinScanner

FIXTURES = Path(__file__).parent / "fixtures" / "vuln_apps"
FIXTURE_NAMES = ["express_app", "flask_app", "spring_app", "cpp_cli", "static_site"]


def load_expected(name: str) -> dict[str, Any]:
    """Read a fixture's expected.json."""
    return json.loads((FIXTURES / name / "expected.json").read_text(encoding="utf-8"))


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """A private APPSEC_MCP_HOME."""
    path = tmp_path / "home"
    path.mkdir()
    return path


@pytest.fixture
def apps(tmp_path: Path) -> Path:
    """A writable copy of all fixture apps (without expected.json)."""
    target = tmp_path / "apps"
    shutil.copytree(FIXTURES, target, ignore=shutil.ignore_patterns("expected.json"))
    return target


@pytest.fixture
def ctx(home: Path) -> AppContext:
    """App context using only the built-in scanner, so tests need no external binaries."""
    return build_context(home, adapters=[BuiltinScanner()])
