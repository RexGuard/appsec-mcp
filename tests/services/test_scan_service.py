"""Scan service: persistence, re-scan diffing, partial scans, concurrency guard, queries."""

import threading
from collections.abc import Sequence
from pathlib import Path

import pytest

from appsec_mcp.context import AppContext, build_context
from appsec_mcp.errors import AppSecError, ErrorCode, ScannerError
from appsec_mcp.models.scan import ScanRequest
from appsec_mcp.scan.walker import SourceFile
from appsec_mcp.scanners.base import AdapterResult
from appsec_mcp.scanners.builtin import BuiltinScanner


class _BrokenScanner:
    name = "semgrep"
    install_hint = "hint"

    def is_available(self) -> bool:
        return True

    def version(self) -> str:
        return "0"

    def run(self, root: Path, files: Sequence[SourceFile]) -> AdapterResult:
        raise ScannerError(ErrorCode.SCANNER_FAILED, "boom")


class _MissingScanner(_BrokenScanner):
    name = "osv"

    def is_available(self) -> bool:
        return False


def test_scan_persists_and_explains(ctx: AppContext, apps: Path) -> None:
    result = ctx.scans.scan(ScanRequest(path=str(apps / "flask_app")))
    assert result.status == "completed" and 0 <= result.score < 100
    assert result.new == sum(result.counts.model_dump().values())
    page = ctx.queries.findings(result.scan_id, "info", 100, 0)
    assert page.total == len(page.items)
    for item in page.items:
        assert 0 < len(item.plain_explanation.split()) <= 120
    ledger = ctx.queries.ledger(result.scan_id, "all", 500, 0)
    assert ledger.files is not None and ledger.files.read == result.files_read
    assert ledger.rules and ledger.scanners[0].name == "builtin"


def test_rescan_marks_deleted_issue_fixed(ctx: AppContext, apps: Path) -> None:
    root = apps / "flask_app"
    first = ctx.scans.scan(ScanRequest(path=str(root)))
    app_py = root / "app.py"
    app_py.write_text(app_py.read_text().replace("    return str(eval(expr))", "    return expr"))
    second = ctx.scans.scan(ScanRequest(path=str(root)))
    assert second.fixed == 1 and second.new == 0
    assert second.score > first.score
    fixed = [
        f
        for f in ctx.queries.findings(second.scan_id, "info", 100, 0, True).items
        if f.status == "fixed"
    ]
    assert [f.cwe for f in fixed] == ["CWE-95"]
    statuses = {f.status for f in ctx.queries.findings(second.scan_id, "info", 100, 0).items}
    assert statuses == {"existing"}


def test_failed_scanner_makes_scan_partial(home: Path, apps: Path) -> None:
    ctx = build_context(home, adapters=[_BrokenScanner(), _MissingScanner(), BuiltinScanner()])
    result = ctx.scans.scan(ScanRequest(path=str(apps / "cpp_cli")))
    assert result.status == "partial"
    assert {s.name for s in result.scanners_skipped} == {"semgrep", "osv"}
    assert result.scanners_run == ["builtin"]


def test_scanner_selection(ctx: AppContext, apps: Path) -> None:
    result = ctx.scans.scan(ScanRequest(path=str(apps / "cpp_cli"), scanners=["semgrep"]))
    assert result.scanners_run == [] and result.counts.critical == 0


def test_concurrent_scan_of_same_root_is_refused(ctx: AppContext, apps: Path) -> None:
    root = (apps / "cpp_cli").resolve()
    started = threading.Event()
    release = threading.Event()

    class _Slow(BuiltinScanner):
        def run(self, root: Path, files: Sequence[SourceFile]) -> AdapterResult:
            started.set()
            release.wait(5)
            return super().run(root, files)

    slow_ctx = build_context(ctx.settings.home, adapters=[_Slow()])
    worker = threading.Thread(target=lambda: slow_ctx.scans.scan(ScanRequest(path=str(root))))
    worker.start()
    started.wait(5)
    with pytest.raises(AppSecError) as exc:
        slow_ctx.scans.scan(ScanRequest(path=str(root)))
    release.set()
    worker.join()
    assert exc.value.code == ErrorCode.SCAN_IN_PROGRESS


def test_list_scans_and_unknown_ids(ctx: AppContext, apps: Path) -> None:
    result = ctx.scans.scan(ScanRequest(path=str(apps / "static_site")))
    assert ctx.queries.list_scans(str(apps / "static_site"), 5).items[0].scan_id == result.scan_id
    assert ctx.queries.list_scans(str(apps / "nothing"), 5).items == []
    for call in (
        lambda: ctx.queries.findings(9999, "low", 10, 0),
        lambda: ctx.queries.explain(9999),
        lambda: ctx.queries.graph(9999),
    ):
        with pytest.raises(AppSecError):
            call()
