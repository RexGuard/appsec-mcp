"""False-positive feedback: suppressed findings are hidden, not counted, and not 'fixed'."""

from pathlib import Path

import pytest

from appsec_mcp.context import AppContext
from appsec_mcp.errors import AppSecError
from appsec_mcp.models.scan import ScanRequest


def test_marked_finding_is_hidden_on_rescan(ctx: AppContext, apps: Path) -> None:
    root = apps / "flask_app"
    first = ctx.scans.scan(ScanRequest(path=str(root)))
    target = ctx.queries.findings(first.scan_id, "info", 100, 0).items[0]
    result = ctx.feedback.mark(target.id, "Only reachable from an admin script.")
    assert result.suppressed

    second = ctx.scans.scan(ScanRequest(path=str(root)))
    assert second.suppressed == 1
    assert second.fixed == 0, "a suppressed finding must not be reported as fixed"
    titles = [
        (f.title, f.line_start) for f in ctx.queries.findings(second.scan_id, "info", 100, 0).items
    ]
    assert (target.title, target.line_start) not in titles
    assert sum(second.counts.model_dump().values()) == sum(first.counts.model_dump().values()) - 1

    listed = ctx.feedback.list_for(str(root))
    assert [s.reason for s in listed.items] == ["Only reachable from an admin script."]


def test_unmark_reports_it_again(ctx: AppContext, apps: Path) -> None:
    root = apps / "flask_app"
    first = ctx.scans.scan(ScanRequest(path=str(root)))
    target = ctx.queries.findings(first.scan_id, "info", 100, 0).items[0]
    ctx.feedback.mark(target.id, "not real")
    assert not ctx.feedback.unmark(target.id).suppressed
    again = ctx.scans.scan(ScanRequest(path=str(root)))
    assert again.suppressed == 0
    assert "not marked" in ctx.feedback.unmark(target.id).message


def test_list_for_unknown_project_raises(ctx: AppContext, tmp_path: Path) -> None:
    with pytest.raises(AppSecError):
        ctx.feedback.list_for(str(tmp_path))


def test_explain_shows_evidence(ctx: AppContext, apps: Path) -> None:
    scan = ctx.scans.scan(ScanRequest(path=str(apps / "express_app")))
    item = ctx.queries.findings(scan.scan_id, "info", 100, 0).items[0]
    detail = ctx.queries.explain(item.id)
    assert detail.evidence and detail.evidence_tier == item.evidence_tier
