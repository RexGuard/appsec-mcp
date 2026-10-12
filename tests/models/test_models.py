"""Model validation: good payloads pass, bad severities, ids and unknown fields fail."""

import pytest
from pydantic import ValidationError

from appsec_mcp.models.base import severity_at_least
from appsec_mcp.models.finding import FindingItem, RawFinding
from appsec_mcp.models.scan import ScanRequest, ScanResult, SeverityCounts
from appsec_mcp.models.system_map import MapNode
from appsec_mcp.models.web_check import WebCheckResult
from tests.conftest import FIXTURE_NAMES, FIXTURES, load_expected

_ITEM = {
    "id": 1,
    "severity": "high",
    "title": "SQL injection",
    "rel_path": "a.py",
    "line_start": 3,
    "plain_explanation": "x",
    "patchable": True,
    "status": "new",
    "scanner": "builtin",
    "cwe": "CWE-89",
}


def test_valid_payloads() -> None:
    FindingItem.model_validate(_ITEM)
    ScanRequest(path="/tmp/x", scanners=["builtin"], max_file_kb=10)
    ScanResult(
        scan_id=1,
        project="p",
        status="completed",
        score=90,
        counts=SeverityCounts(),
        new=0,
        fixed=0,
        scanners_run=["builtin"],
        scanners_skipped=[],
        files_read=1,
        files_skipped=0,
        duration_s=0.1,
    )
    WebCheckResult(
        url="https://a.b",
        final_url="https://a.b",
        status_code=200,
        tls=None,
        headers=[],
        cookies=[],
        score=100,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"severity": "urgent"},
        {"id": -1},
        {"id": 0},
        {"unknown": 1},
        {"status": "gone"},
    ],
)
def test_invalid_payloads(change: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        FindingItem.model_validate({**_ITEM, **change})


def test_scan_request_limits() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(path="", max_file_kb=1)
    with pytest.raises(ValidationError):
        ScanRequest(path="x", max_file_kb=0)
    with pytest.raises(ValidationError):
        ScanRequest(path="x", scanners=["nmap"])  # type: ignore[list-item]


def test_raw_finding_and_map_node_reject_bad_values() -> None:
    with pytest.raises(ValidationError):
        RawFinding(scanner="builtin", rule_id="r", severity="high", line_start=0)
    with pytest.raises(ValidationError):
        MapNode(id=1, kind="database", label="x")  # type: ignore[arg-type]


def test_severity_ordering() -> None:
    assert severity_at_least("critical", "high")
    assert not severity_at_least("low", "medium")


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_expected_files_point_at_real_lines(name: str) -> None:
    expected = load_expected(name)
    assert expected["issues"]
    for issue in expected["issues"]:
        path = FIXTURES / name / issue["file"]
        assert path.is_file(), issue
        if issue["line"] is not None:
            assert 1 <= issue["line"] <= len(path.read_text(encoding="utf-8").splitlines())
