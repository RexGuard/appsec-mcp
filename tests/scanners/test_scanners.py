"""Scanner adapters: built-in recall on fixtures, external adapters on recorded output."""

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from appsec_mcp.errors import AppSecError
from appsec_mcp.models.finding import RawFinding
from appsec_mcp.scan.ledger import LedgerCollector
from appsec_mcp.scan.walker import walk
from appsec_mcp.scanners import _subprocess
from appsec_mcp.scanners.builtin import BuiltinScanner
from appsec_mcp.scanners.gitleaks import GitleaksScanner, parse_gitleaks_json
from appsec_mcp.scanners.normalize import fingerprint, normalize
from appsec_mcp.scanners.osv import OsvScanner, parse_osv_json
from appsec_mcp.scanners.semgrep import SemgrepScanner, _bundled_rule_ids, parse_semgrep_json
from tests.conftest import FIXTURE_NAMES, FIXTURES, load_expected

RAW_SECRETS = [
    "51FAKEFAKEFAKEFAKE00000abcd",
    "django-insecure-FAKEfakeFAKEfake1234",
    "AIzaSyFAKEfakeFAKEfakeFAKEfakeFAKEfake12",
]


def _builtin(name: str) -> list[RawFinding]:
    root = FIXTURES / name
    sources = LedgerCollector().consume(walk(root, 1024 * 1024)).sources
    return BuiltinScanner().run(root, sources).findings


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_builtin_finds_every_planted_issue(name: str) -> None:
    found = {(f.rel_path, f.line_start, f.cwe) for f in normalize(_builtin(name))}
    for issue in load_expected(name)["issues"]:
        if issue.get("requires"):
            continue
        assert (issue["file"], issue["line"], issue["cwe"]) in found, issue


def test_builtin_records_rules_applied() -> None:
    root = FIXTURES / "cpp_cli"
    sources = LedgerCollector().consume(walk(root, 1024 * 1024)).sources
    result = BuiltinScanner().run(root, sources)
    rules = {r.rule_id: r.files_matched for r in result.rules}
    assert rules["builtin.c.gets"] == 1
    assert rules["builtin.js.eval"] == 0


def test_comments_do_not_trigger_rules(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("# eval(user_input)\nx = 1\n")
    sources = LedgerCollector().consume(walk(tmp_path, 1024)).sources
    assert BuiltinScanner().run(tmp_path, sources).findings == []


def test_normalize_redacts_dedupes_and_explains() -> None:
    findings = normalize(_builtin("express_app") + _builtin("static_site"))
    keys = [(f.rel_path, f.line_start, f.cwe) for f in findings]
    assert len(keys) == len(set(keys))
    for finding in findings:
        assert finding.plain_explanation and len(finding.plain_explanation.split()) <= 120
        for secret in RAW_SECRETS:
            assert secret not in finding.snippet_redacted
            assert secret not in finding.plain_explanation


def test_fingerprint_ignores_whitespace_but_not_code() -> None:
    assert fingerprint("r", "a", "x =  1") == fingerprint("r", "a", "x = 1")
    assert fingerprint("r", "a", "x = 1") != fingerprint("r", "a", "x = 2")


SEMGREP_JSON: dict[str, Any] = {
    "results": [
        {
            "check_id": "tmp.rules.py-sql-injection",
            "path": "app.py",
            "start": {"line": 31},
            "end": {"line": 31},
            "extra": {
                "message": "SQL",
                "severity": "ERROR",
                "lines": "cur.execute(f'...')",
                "metadata": {
                    "cwe": ["CWE-89: SQL Injection"],
                    "severity": "CRITICAL",
                    "appsec_fix": "sql_param",
                },
            },
        }
    ]
}


def test_parse_semgrep_json() -> None:
    [finding] = parse_semgrep_json(json.dumps(SEMGREP_JSON), Path("/root"))
    assert finding.rule_id == "semgrep.py-sql-injection"
    assert finding.cwe == "CWE-89" and finding.severity == "critical"
    assert finding.fix_kind == "sql_param" and finding.line_start == 31
    assert "semgrep.py-sql-injection" in _bundled_rule_ids()


def test_semgrep_adapter_with_mocked_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        out = json.dumps(SEMGREP_JSON) if "scan" in args else "1.99.0"
        return subprocess.CompletedProcess(args, 1, out.encode(), b"")

    monkeypatch.setattr(_subprocess.subprocess, "run", fake_run)
    result = SemgrepScanner(executable="semgrep").run(Path("/root"), [])
    assert result.findings[0].cwe == "CWE-89"
    scan_args = calls[0]
    assert scan_args[-2] == "--" and "--metrics=off" in scan_args
    assert any(
        r.rule_id == "semgrep.py-sql-injection" and r.files_matched == 1 for r in result.rules
    )


def test_missing_binaries_report_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_subprocess.shutil, "which", lambda name: None)
    for adapter in (SemgrepScanner(), GitleaksScanner(), OsvScanner()):
        assert not adapter.is_available()
        assert adapter.install_hint
        with pytest.raises(AppSecError):
            adapter.run(Path("."), [])


def test_subprocess_timeout_becomes_scanner_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(args: list[str], **_: Any) -> None:
        raise subprocess.TimeoutExpired(args, 1)

    monkeypatch.setattr(_subprocess.subprocess, "run", boom)
    with pytest.raises(AppSecError):
        _subprocess.run_command(["semgrep"], timeout_s=1)


def test_subprocess_output_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        _subprocess.subprocess,
        "run",
        lambda args, **_: subprocess.CompletedProcess(args, 0, b"x" * 100, b""),
    )
    with pytest.raises(AppSecError):
        _subprocess.run_command(["x"], max_output_bytes=10)


def test_parse_gitleaks_json() -> None:
    report = [
        {
            "RuleID": "stripe-access-token",
            "File": "server.ts",
            "StartLine": 5,
            "EndLine": 5,
            "Match": "sk_live_REDACTED",
            "Description": "Stripe key",
        }
    ]
    [finding] = parse_gitleaks_json(json.dumps(report), Path("/root"))
    assert finding.rule_id == "gitleaks.stripe-access-token"
    assert finding.cwe == "CWE-798" and finding.fix_kind == "hardcoded_secret"


def test_parse_osv_json(tmp_path: Path) -> None:
    payload = {
        "results": [
            {
                "source": {"path": str(tmp_path / "requirements.txt")},
                "packages": [
                    {
                        "package": {"name": "flask", "version": "2.0.1", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-xxxx",
                                "summary": "Cookie leak",
                                "database_specific": {"severity": "HIGH"},
                            }
                        ],
                    }
                ],
            }
        ]
    }
    [finding] = parse_osv_json(json.dumps(payload), tmp_path.resolve())
    assert finding.rel_path == "requirements.txt"
    assert finding.severity == "high" and finding.rule_id == "osv.GHSA-xxxx"
    assert "flask@2.0.1" in finding.message


def test_bad_json_raises() -> None:
    with pytest.raises(AppSecError):
        parse_semgrep_json("not json", Path("."))
    with pytest.raises(AppSecError):
        parse_osv_json("{", Path("."))
