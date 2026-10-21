"""Golden precision benchmark: on the fixtures, no critical finding may be a false positive.

Every critical the built-in scanner reports must match a planted issue in expected.json (same
file, CWE and line, give or take one line). This guards the evidence gate against regressions.
"""

from pathlib import Path

import pytest

from appsec_mcp.context import AppContext
from appsec_mcp.models.scan import ScanRequest
from tests.conftest import FIXTURE_NAMES, load_expected

_LINE_SLACK = 1


def _is_planted(
    item_path: str | None, line: int | None, cwe: str | None, issues: list[dict]
) -> bool:
    for issue in issues:
        if issue.get("file") != item_path or issue.get("cwe") != cwe:
            continue
        if line is None or issue.get("line") is None or abs(issue["line"] - line) <= _LINE_SLACK:
            return True
    return False


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_zero_false_criticals(ctx: AppContext, apps: Path, name: str) -> None:
    issues = load_expected(name)["issues"]
    scan = ctx.scans.scan(ScanRequest(path=str(apps / name)))
    criticals = ctx.queries.findings(scan.scan_id, "critical", 500, 0).items
    false_criticals = [
        (c.rel_path, c.line_start, c.cwe)
        for c in criticals
        if not _is_planted(c.rel_path, c.line_start, c.cwe, issues)
    ]
    assert false_criticals == []
