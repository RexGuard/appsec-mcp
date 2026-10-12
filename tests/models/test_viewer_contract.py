"""The viewer's mock JSON is the frozen API contract: it must validate against the Python models too."""

import json
from pathlib import Path

from appsec_mcp.models.finding import FindingDetail, GetFindingsResponse
from appsec_mcp.models.ledger import AuditLedger
from appsec_mcp.models.scan import ScanSummary
from appsec_mcp.models.system_map import SystemGraph

MOCK = Path(__file__).parents[2] / "viewer" / "src" / "mock"


def _load(name):
    return json.loads((MOCK / name).read_text(encoding="utf-8"))


def test_scan_bundle_matches_python_models():
    bundle = _load("scan.json")
    ScanSummary.model_validate(bundle["summary"])
    GetFindingsResponse.model_validate(bundle["findings"])
    for d in bundle["details"]:
        FindingDetail.model_validate(d)


def test_map_matches_python_models():
    SystemGraph.model_validate(_load("map.json"))


def test_ledger_matches_python_models():
    AuditLedger.model_validate(_load("ledger.json"))
