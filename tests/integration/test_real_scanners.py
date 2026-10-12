"""Runs the real external scanners on the fixtures. Skipped when the binaries are missing."""

import pytest

from appsec_mcp.scan.ledger import LedgerCollector
from appsec_mcp.scan.walker import walk
from appsec_mcp.scanners.gitleaks import GitleaksScanner
from appsec_mcp.scanners.normalize import normalize
from appsec_mcp.scanners.osv import OsvScanner
from appsec_mcp.scanners.semgrep import SemgrepScanner
from tests.conftest import FIXTURE_NAMES, FIXTURES, load_expected

pytestmark = pytest.mark.scanners

_SEMGREP_CWES = {
    "CWE-89",
    "CWE-79",
    "CWE-95",
    "CWE-489",
    "CWE-502",
    "CWE-120",
    "CWE-242",
    "CWE-134",
}


@pytest.mark.skipif(not SemgrepScanner().is_available(), reason="Semgrep not installed")
@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_semgrep_recall(name: str) -> None:
    root = FIXTURES / name
    sources = LedgerCollector().consume(walk(root, 1024 * 1024)).sources
    found = {
        (f.rel_path, f.line_start, f.cwe)
        for f in normalize(SemgrepScanner().run(root, sources).findings)
    }
    for issue in load_expected(name)["issues"]:
        if issue["category"] == "code" and issue["cwe"] in _SEMGREP_CWES:
            assert (issue["file"], issue["line"], issue["cwe"]) in found, issue


@pytest.mark.skipif(not GitleaksScanner().is_available(), reason="gitleaks not installed")
def test_gitleaks_finds_express_secret() -> None:
    root = FIXTURES / "express_app"
    findings = GitleaksScanner().run(root, []).findings
    assert any(f.rel_path == "server.ts" for f in findings)


@pytest.mark.skipif(not OsvScanner().is_available(), reason="OSV-Scanner not installed")
def test_osv_finds_old_flask() -> None:
    findings = OsvScanner().run(FIXTURES / "flask_app", []).findings
    assert any("flask" in f.message.lower() for f in findings)
