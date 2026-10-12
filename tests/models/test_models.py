import pytest
from pydantic import ValidationError

from appsec_mcp.models import severity_at_least
from appsec_mcp.models.finding import FindingDetail, FindingSummary, GetFindingsRequest, GetFindingsResponse
from appsec_mcp.models.ledger import AuditLedger, LedgerFile
from appsec_mcp.models.patch import (
    ApplyPatchRequest,
    PatchProposal,
    ProposeHardeningRequest,
    RevertPatchRequest,
)
from appsec_mcp.models.scan import ListScansResponse, ScanProjectRequest, ScanProjectResponse
from appsec_mcp.models.system_map import GetSystemMapRequest, SystemGraph, SystemMapSummary
from appsec_mcp.models.web_check import CheckWebsiteRequest, WebsiteReport

SHA = "a" * 64

SCAN_RESPONSE = {
    "scan_id": 7,
    "status": "partial",
    "score": 42,
    "counts": {"critical": 1, "high": 3, "medium": 2, "low": 1, "info": 0},
    "new": 2,
    "fixed": 1,
    "scanners_run": ["builtin", "gitleaks"],
    "scanners_skipped": [
        {"name": "semgrep", "reason": "not installed", "install_hint": "pipx install semgrep"}
    ],
    "files_read": 12,
    "files_skipped": 3,
    "duration_s": 4.2,
}

FINDING = {
    "id": 3,
    "severity": "critical",
    "title": "SQL injection",
    "rel_path": "src/server.ts",
    "line_start": 14,
    "plain_explanation": "User input goes straight into a database query.",
    "patchable": True,
    "status": "new",
}


def test_scan_project_request_defaults():
    req = ScanProjectRequest(path="/home/me/app")
    assert req.max_file_kb == 1024
    assert req.scanners is None


@pytest.mark.parametrize(
    "payload",
    [
        {"path": ""},
        {"path": "/x", "scanners": ["nmap"]},
        {"path": "/x", "scanners": ["semgrep", "semgrep"]},
        {"path": "/x", "max_file_kb": 0},
        {"path": "/x", "unknown": 1},
    ],
)
def test_scan_project_request_rejects_bad_input(payload):
    with pytest.raises(ValidationError):
        ScanProjectRequest.model_validate(payload)


def test_scan_response_round_trips():
    resp = ScanProjectResponse.model_validate(SCAN_RESPONSE)
    assert ScanProjectResponse.model_validate(resp.model_dump()) == resp


def test_scan_response_rejects_out_of_range_score():
    with pytest.raises(ValidationError):
        ScanProjectResponse.model_validate({**SCAN_RESPONSE, "score": 101})


def test_findings_page_validates():
    page = GetFindingsResponse.model_validate({"total": 1, "items": [FINDING]})
    assert page.items[0].severity == "critical"


@pytest.mark.parametrize(
    "bad",
    [{"severity": "urgent"}, {"id": -1}, {"id": 0}, {"status": "open"}, {"line_start": 0}, {"extra": True}],
)
def test_finding_summary_rejects(bad):
    with pytest.raises(ValidationError):
        FindingSummary.model_validate({**FINDING, **bad})


def test_get_findings_request_limits():
    assert GetFindingsRequest(scan_id=1).min_severity == "low"
    with pytest.raises(ValidationError):
        GetFindingsRequest(scan_id=1, limit=10_000)
    with pytest.raises(ValidationError):
        GetFindingsRequest(scan_id=1, offset=-1)
    with pytest.raises(ValidationError):
        GetFindingsRequest(scan_id=-5)


def test_finding_detail_requires_cwe_format():
    base = {
        "id": 1,
        "title": "t",
        "severity": "high",
        "what": "w",
        "why_it_matters": "y",
        "how_to_fix": "h",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    }
    assert FindingDetail.model_validate({**base, "cwe": "CWE-89"}).cwe == "CWE-89"
    with pytest.raises(ValidationError):
        FindingDetail.model_validate({**base, "cwe": "89"})


def test_graph_edges_must_reference_nodes():
    nodes = [
        {"id": 1, "kind": "route", "label": "GET /users"},
        {"id": 2, "kind": "data_store", "label": "mysql"},
    ]
    SystemGraph.model_validate({"nodes": nodes, "edges": [{"source": 1, "target": 2, "kind": "reads"}]})
    with pytest.raises(ValidationError):
        SystemGraph.model_validate({"nodes": nodes, "edges": [{"source": 1, "target": 9, "kind": "reads"}]})
    with pytest.raises(ValidationError):
        SystemGraph.model_validate({"nodes": nodes, "edges": [{"source": 1, "target": 2, "kind": "owns"}]})


def test_map_summary_and_request():
    assert GetSystemMapRequest(scan_id=1).format == "summary"
    SystemMapSummary.model_validate(
        {
            "components": ["server"],
            "entry_points": ["src/server.ts"],
            "routes": ["GET /api/users"],
            "data_stores": ["mysql"],
            "external_services": [],
            "secrets_locations": ["src/config.ts:6"],
            "dependencies_count": 4,
            "hotspots": [{"node": "GET /api/users", "finding_count": 1}],
        }
    )


def test_ledger_file_reason_rules():
    LedgerFile(rel_path="a.py", status="read", sha256=SHA, size_bytes=10, language="python")
    LedgerFile(rel_path="logo.png", status="skipped", skip_reason="binary")
    with pytest.raises(ValidationError):
        LedgerFile(rel_path="a.py", status="skipped")
    with pytest.raises(ValidationError):
        LedgerFile(rel_path="a.py", status="read", sha256=SHA, skip_reason="binary")
    with pytest.raises(ValidationError):
        LedgerFile(rel_path="a.py", status="read")
    with pytest.raises(ValidationError):
        LedgerFile(rel_path="a.py", status="skipped", skip_reason="boring")


def test_audit_ledger_validates():
    AuditLedger.model_validate(
        {
            "files": {
                "read": 1,
                "skipped": 0,
                "items": [{"rel_path": "a.py", "status": "read", "sha256": SHA}],
            },
            "rules": [{"scanner": "semgrep", "rule_id": "python.lang.security.eval", "files_matched": 1}],
            "scanners": [{"name": "semgrep", "version": "1.90.0", "duration_s": 3.1}],
        }
    )


def test_patch_models():
    token = "t" * 43
    PatchProposal(
        patch_id=1,
        proposal_token=token,
        summary="Move the secret to .env",
        diff="--- a\n+++ b\n",
        files=["src/config.ts"],
        expires_at="2026-10-12T10:00:00Z",
    )
    ApplyPatchRequest(proposal_token=token)
    assert RevertPatchRequest(patch_id=1).force is False
    with pytest.raises(ValidationError):
        ApplyPatchRequest(proposal_token="short")
    with pytest.raises(ValidationError):
        ProposeHardeningRequest(scan_id=1, recipe="Rm -rf")


def test_website_models():
    assert CheckWebsiteRequest(url="https://myapp.com").allow_private is False
    for bad in ("ftp://x", "javascript:alert(1)", "file:///etc/passwd", ""):
        with pytest.raises(ValidationError):
            CheckWebsiteRequest(url=bad)
    WebsiteReport.model_validate(
        {
            "url": "https://myapp.com",
            "final_url": "https://myapp.com/",
            "tls": {"valid": True, "expires": "2027-01-01", "protocol": "TLSv1.3"},
            "headers": [
                {
                    "name": "Content-Security-Policy",
                    "present": False,
                    "verdict": "missing",
                    "plain_explanation": "Without it, injected scripts can run.",
                }
            ],
            "cookies": [{"name": "session", "secure": True, "httponly": True, "samesite": "lax"}],
            "score": 70,
        }
    )


def test_list_scans_response():
    ListScansResponse.model_validate(
        {"items": [{"scan_id": 1, "project": "shop", "started_at": "2026-10-12T09:00:00Z", "counts": {}}]}
    )


def test_severity_ordering():
    assert severity_at_least("critical", "low")
    assert severity_at_least("low", "low")
    assert not severity_at_least("info", "low")
