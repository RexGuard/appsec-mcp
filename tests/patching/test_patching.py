"""Patching: propose writes nothing, hash/expiry checks, rollback, byte-exact revert, re-scan."""

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from appsec_mcp.context import AppContext
from appsec_mcp.errors import AppSecError, ErrorCode
from appsec_mcp.models.finding import FindingItem
from appsec_mcp.models.scan import ScanRequest
from appsec_mcp.patching.fixers.base import FixTarget
from appsec_mcp.patching.fixers.sql import fix_sql
from appsec_mcp.patching.workspace import Workspace
from appsec_mcp.services.patch_service import PatchService


def _snapshot(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _scan_and_pick(ctx: AppContext, root: Path, cwe: str) -> tuple[int, FindingItem]:
    scan = ctx.scans.scan(ScanRequest(path=str(root)))
    items = ctx.queries.findings(scan.scan_id, "info", 100, 0).items
    return scan.scan_id, next(f for f in items if f.cwe == cwe)


@pytest.mark.parametrize(
    ("app", "cwe", "expected_text"),
    [
        ("express_app", "CWE-798", "process.env.STRIPE_KEY"),
        ("express_app", "CWE-89", '"SELECT * FROM users WHERE id = ?", [req.params.id]'),
        ("express_app", "CWE-942", "process.env.ALLOWED_ORIGINS"),
        ("flask_app", "CWE-89", '"SELECT * FROM users WHERE name = ?", (name,)'),
        ("flask_app", "CWE-489", "app.run(debug=False)"),
        ("cpp_cli", "CWE-120", 'snprintf(name, sizeof(name), "%s", argv[1]);'),
        ("cpp_cli", "CWE-242", "fgets(line, sizeof(line), stdin)"),
    ],
)
def test_fix_and_rescan(
    ctx: AppContext, apps: Path, app: str, cwe: str, expected_text: str
) -> None:
    root = apps / app
    _, finding = _scan_and_pick(ctx, root, cwe)
    before = _snapshot(root)
    proposal = ctx.patches.propose_patch(finding.id)
    assert _snapshot(root) == before, "propose must not write"
    assert proposal.diff.startswith(("--- a/", "--- /dev/null"))
    ctx.patches.apply_patch(proposal.proposal_token)
    changed = "".join((root / f).read_text() for f in proposal.files)
    assert expected_text in changed
    rescan = ctx.scans.scan(ScanRequest(path=str(root)))
    assert rescan.fixed >= 1
    still_open = {
        (f.rel_path, f.line_start, f.cwe)
        for f in ctx.queries.findings(rescan.scan_id, "info", 100, 0).items
    }
    assert (finding.rel_path, finding.line_start, cwe) not in still_open


def test_env_committed_fix_ignores_env(ctx: AppContext, apps: Path) -> None:
    root = apps / "flask_app"
    _, finding = _scan_and_pick(ctx, root, "CWE-538")
    ctx.patches.apply_patch(ctx.patches.propose_patch(finding.id).proposal_token)
    assert ".env" in (root / ".gitignore").read_text().splitlines()
    rescan = ctx.scans.scan(ScanRequest(path=str(root)))
    open_cwes = {f.cwe for f in ctx.queries.findings(rescan.scan_id, "info", 100, 0).items}
    assert "CWE-538" not in open_cwes and "CWE-798" not in open_cwes


def test_revert_is_byte_identical(ctx: AppContext, apps: Path) -> None:
    root = apps / "express_app"
    (root / "server.ts").write_bytes((root / "server.ts").read_bytes().replace(b"\n", b"\r\n"))
    _, finding = _scan_and_pick(ctx, root, "CWE-798")
    before = _snapshot(root)
    applied = ctx.patches.apply_patch(ctx.patches.propose_patch(finding.id).proposal_token)
    assert _snapshot(root) != before
    assert b"\r\n" in (root / "server.ts").read_bytes()
    reverted = ctx.patches.revert_patch(applied.patch_id)
    assert set(reverted.files_restored) == set(applied.files_changed)
    assert _snapshot(root) == before


def test_apply_refuses_changed_files(ctx: AppContext, apps: Path) -> None:
    root = apps / "flask_app"
    _, finding = _scan_and_pick(ctx, root, "CWE-489")
    proposal = ctx.patches.propose_patch(finding.id)
    (root / "app.py").write_text((root / "app.py").read_text() + "\n# edited\n")
    with pytest.raises(AppSecError) as exc:
        ctx.patches.apply_patch(proposal.proposal_token)
    assert exc.value.code == ErrorCode.FILES_CHANGED_SINCE_PROPOSAL


def test_token_is_single_use_and_expires(ctx: AppContext, apps: Path) -> None:
    root = apps / "cpp_cli"
    _, finding = _scan_and_pick(ctx, root, "CWE-242")
    proposal = ctx.patches.propose_patch(finding.id)
    ctx.patches.apply_patch(proposal.proposal_token)
    with pytest.raises(AppSecError) as reused:
        ctx.patches.apply_patch(proposal.proposal_token)
    assert reused.value.code == ErrorCode.TOKEN_INVALID

    _, strcpy = _scan_and_pick(ctx, root, "CWE-120")
    late = PatchService(
        ctx.repos,
        ctx.queries,
        ctx.settings.backups_dir,
        clock=lambda: datetime.now(UTC) + timedelta(hours=1),
    )
    with pytest.raises(AppSecError) as expired:
        late.apply_patch(ctx.patches.propose_patch(strcpy.id).proposal_token)
    assert expired.value.code == ErrorCode.PROPOSAL_EXPIRED


def test_failed_multi_file_write_rolls_back(ctx: AppContext, apps: Path) -> None:
    root = apps / "express_app"
    _, finding = _scan_and_pick(ctx, root, "CWE-798")
    before = _snapshot(root)
    writes: list[Path] = []

    def flaky_writer(path: Path, data: bytes) -> None:
        if writes:
            raise OSError("disk full")
        writes.append(path)
        path.write_bytes(data)

    flaky = PatchService(ctx.repos, ctx.queries, ctx.settings.backups_dir, writer=flaky_writer)
    proposal = flaky.propose_patch(finding.id)
    assert len(proposal.files) > 1
    with pytest.raises(AppSecError) as exc:
        flaky.apply_patch(proposal.proposal_token)
    assert exc.value.code == ErrorCode.WRITE_FAILED
    assert _snapshot(root) == before


def test_revert_refuses_edited_files_without_force(ctx: AppContext, apps: Path) -> None:
    root = apps / "flask_app"
    _, finding = _scan_and_pick(ctx, root, "CWE-489")
    applied = ctx.patches.apply_patch(ctx.patches.propose_patch(finding.id).proposal_token)
    (root / "app.py").write_text("changed later\n")
    with pytest.raises(AppSecError) as exc:
        ctx.patches.revert_patch(applied.patch_id)
    assert exc.value.code == ErrorCode.FILES_CHANGED_SINCE_APPLY
    ctx.patches.revert_patch(applied.patch_id, force=True)
    assert "debug=True" in (root / "app.py").read_text()
    with pytest.raises(AppSecError) as again:
        ctx.patches.revert_patch(applied.patch_id)
    assert again.value.code == ErrorCode.NOT_APPLIED


def test_not_patchable(ctx: AppContext, apps: Path) -> None:
    _, finding = _scan_and_pick(ctx, apps / "spring_app", "CWE-502")
    with pytest.raises(AppSecError) as exc:
        ctx.patches.propose_patch(finding.id)
    assert exc.value.code == ErrorCode.NOT_PATCHABLE


@pytest.mark.parametrize(
    ("source", "language", "expected"),
    [
        (
            'cur.execute("SELECT * FROM t WHERE a = " + a + " AND b = " + b)\n',
            "python",
            'cur.execute("SELECT * FROM t WHERE a = ? AND b = ?", (a, b,))\n',
        ),
        (
            'import psycopg2\ncur.execute(f"DELETE FROM t WHERE id = {item.id}")\n',
            "python",
            'import psycopg2\ncur.execute("DELETE FROM t WHERE id = %s", (item.id,))\n',
        ),
        (
            'const pg = require("pg");\nclient.query("SELECT 1 WHERE x = \'" + x + "\'", cb);\n',
            "javascript",
            'const pg = require("pg");\nclient.query("SELECT 1 WHERE x = $1", [x], cb);\n',
        ),
    ],
)
def test_sql_fixer_shapes(tmp_path: Path, source: str, language: str, expected: str) -> None:
    (tmp_path / "f").write_bytes(source.encode())
    ws = Workspace(tmp_path)
    line = source.count("\n", 0, source.index(".execute" if "execute" in source else ".query")) + 1
    assert fix_sql(ws, FixTarget("f", line, language)) is not None
    assert ws.changes()[0].after == expected


def test_sql_fixer_refuses_template_literals(tmp_path: Path) -> None:
    (tmp_path / "f").write_text("db.query(`SELECT * FROM t WHERE id = ${id}`);\n")
    assert fix_sql(Workspace(tmp_path), FixTarget("f", 1, "javascript")) is None
