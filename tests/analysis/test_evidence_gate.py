"""Evidence gate: tiers come from the evidence, and severity is capped in code."""

import pytest

from appsec_mcp.analysis.evidence_gate import apply_gate, gate_summary, is_test_code
from appsec_mcp.models.finding import NormalizedFinding
from appsec_mcp.models.system_map import MapNode, SystemGraph

ROUTE_FILE = "src/server.ts"
GRAPH = SystemGraph(
    nodes=[
        MapNode(id=1, kind="component", label="src"),
        MapNode(id=2, kind="route", label="GET /users/:id", rel_path=ROUTE_FILE),
    ],
    edges=[],
)


def _finding(**overrides: object) -> NormalizedFinding:
    data: dict[str, object] = {
        "fingerprint": "fp",
        "scanner": "builtin",
        "rule_id": "builtin.js.sql-concat",
        "severity": "critical",
        "cwe": "CWE-89",
        "rel_path": "src/db/util.ts",
        "line_start": 3,
        "line_end": 3,
        "snippet_redacted": "x",
        "title": "SQL injection",
        "plain_explanation": "p",
        "fix_hint": "f",
        "fix_kind": None,
        "sources": ["builtin"],
    }
    data.update(overrides)
    return NormalizedFinding(**data)  # type: ignore[arg-type]


def test_bare_pattern_critical_is_demoted_to_high() -> None:
    (gated,) = apply_gate([_finding()], GRAPH, precision=True)
    assert gated.evidence_tier == "pattern"
    assert gated.severity == "high" and gated.reported_severity == "critical"
    assert any("not critical" in reason for reason in gated.evidence)


def test_critical_in_route_file_is_kept() -> None:
    (gated,) = apply_gate([_finding(rel_path=ROUTE_FILE)], GRAPH, precision=True)
    assert gated.evidence_tier == "reachable"
    assert gated.severity == "critical" and gated.reported_severity is None
    assert any("GET /users/:id" in reason for reason in gated.evidence)


def test_two_scanners_corroborate() -> None:
    (gated,) = apply_gate([_finding(sources=["builtin", "semgrep"])], GRAPH, precision=True)
    assert gated.evidence_tier == "corroborated" and gated.severity == "critical"


@pytest.mark.parametrize(
    ("scanner", "rule_id"),
    [("osv", "osv.GHSA-1"), ("gitleaks", "gitleaks.aws"), ("builtin", "builtin.secret.stripe-key")],
)
def test_precise_detectors_are_confirmed(scanner: str, rule_id: str) -> None:
    (gated,) = apply_gate(
        [_finding(scanner=scanner, rule_id=rule_id, sources=[scanner])], GRAPH, precision=True
    )
    assert gated.evidence_tier == "confirmed" and gated.severity == "critical"


def test_generic_secret_is_not_confirmed() -> None:
    finding = _finding(rule_id="builtin.secret.generic-assignment", cwe="CWE-798")
    (gated,) = apply_gate([finding], GRAPH, precision=True)
    assert gated.evidence_tier == "pattern"


def test_test_code_is_capped_at_low_unless_confirmed() -> None:
    weak, secret = apply_gate(
        [
            _finding(rel_path="tests/test_db.py"),
            _finding(rel_path="tests/conf.py", scanner="gitleaks", rule_id="gitleaks.x"),
        ],
        GRAPH,
        precision=True,
    )
    assert weak.severity == "low" and weak.reported_severity == "critical"
    assert secret.severity == "critical"


def test_precision_off_records_tiers_but_keeps_severity() -> None:
    (gated,) = apply_gate([_finding()], GRAPH, precision=False)
    assert gated.evidence_tier == "pattern" and gated.severity == "critical"
    assert gated.reported_severity is None


def test_precision_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APPSEC_MCP_PRECISION", "0")
    (gated,) = apply_gate([_finding()], GRAPH)
    assert gated.severity == "critical"


def test_gate_summary_counts_tiers_and_demotions() -> None:
    gated = apply_gate([_finding(), _finding(rel_path=ROUTE_FILE)], GRAPH, precision=True)
    summary = gate_summary(gated)
    assert summary["pattern"] == 1 and summary["reachable"] == 1 and summary["demoted"] == 1


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/a.py", True),
        ("src/__tests__/x.ts", True),
        ("src/user.test.ts", True),
        ("test_app.py", True),
        ("examples/demo.js", True),
        ("src/contest.py", False),
        ("src/app.py", False),
        (None, False),
    ],
)
def test_is_test_code(path: str | None, expected: bool) -> None:
    assert is_test_code(path) is expected
