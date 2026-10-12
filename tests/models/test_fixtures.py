"""Every fixture's expected.json must point at a real line that contains the planted code."""

import json
from pathlib import Path

import pytest

from appsec_mcp.models import SEVERITY_ORDER

FIXTURES = Path(__file__).parent.parent / "fixtures" / "vuln_apps"
APPS = ["express_app", "flask_app", "spring_app", "cpp_cli", "static_site"]
CATEGORIES = {
    "sql_injection",
    "xss",
    "dom_xss",
    "hardcoded_secret",
    "cors_wildcard",
    "missing_security_headers",
    "vulnerable_dependency",
    "debug_mode",
    "code_injection",
    "missing_csrf",
    "env_committed",
    "insecure_deserialization",
    "buffer_overflow",
    "format_string",
    "mixed_content",
}


def _planted(app):
    return json.loads((FIXTURES / app / "expected.json").read_text(encoding="utf-8"))


def test_every_fixture_app_exists():
    assert sorted(p.name for p in FIXTURES.iterdir() if p.is_dir()) == sorted(APPS)


@pytest.mark.parametrize("app", APPS)
def test_expected_entries_point_at_planted_code(app):
    data = _planted(app)
    assert data["app"] == app
    assert data["planted"], "each fixture plants at least one issue"
    ids = [p["id"] for p in data["planted"]]
    assert len(ids) == len(set(ids))
    for p in data["planted"]:
        assert p["category"] in CATEGORIES
        assert p["scanner"] in {"semgrep", "gitleaks", "osv", "builtin"}
        assert p["severity"] in SEVERITY_ORDER
        assert p["cwe"].startswith("CWE-")
        lines = (FIXTURES / app / p["file"]).read_text(encoding="utf-8").splitlines()
        assert p["contains"] in lines[p["line"] - 1], f"{app} {p['id']}: line {p['line']} moved"


def test_spec_vulnerabilities_are_all_planted():
    cats = {app: {p["category"] for p in _planted(app)["planted"]} for app in APPS}
    assert {"sql_injection", "xss", "hardcoded_secret", "cors_wildcard"} <= cats["express_app"]
    assert {"debug_mode", "code_injection", "missing_csrf"} <= cats["flask_app"]
    assert {"sql_injection", "insecure_deserialization"} <= cats["spring_app"]
    assert {"buffer_overflow", "format_string"} <= cats["cpp_cli"]
    assert {"hardcoded_secret", "mixed_content"} <= cats["static_site"]
