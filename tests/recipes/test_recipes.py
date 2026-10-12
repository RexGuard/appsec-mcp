"""Hardening recipes: applicability per fixture, valid diffs, and findings cleared on re-scan."""

import shutil
from pathlib import Path

import pytest

from appsec_mcp.context import AppContext
from appsec_mcp.errors import AppSecError, ErrorCode
from appsec_mcp.models.scan import ScanRequest


def _applicable(ctx: AppContext, scan_id: int) -> dict[str, bool]:
    return {r.id: r.applicable for r in ctx.patches.list_recipes(scan_id).recipes}


def test_applicability_matrix(ctx: AppContext, apps: Path) -> None:
    express = ctx.scans.scan(ScanRequest(path=str(apps / "express_app"))).scan_id
    flask = ctx.scans.scan(ScanRequest(path=str(apps / "flask_app"))).scan_id
    cpp = ctx.scans.scan(ScanRequest(path=str(apps / "cpp_cli"))).scan_id
    assert _applicable(ctx, express) == {
        "security_headers": True,
        "rate_limit": True,
        "csrf": True,
        "env_secrets": True,
        "input_validation": True,
    }
    assert _applicable(ctx, flask)["csrf"] is True
    cpp_recipes = {r.id: r for r in ctx.patches.list_recipes(cpp).recipes}
    assert not cpp_recipes["security_headers"].applicable
    assert cpp_recipes["security_headers"].reason


@pytest.mark.parametrize(
    ("app", "recipe", "needle", "file"),
    [
        ("express_app", "security_headers", "app.use(helmet());", "server.ts"),
        ("express_app", "rate_limit", "rateLimit(", "server.ts"),
        ("express_app", "csrf", "Cross-site request blocked", "server.ts"),
        ("express_app", "input_validation", 'express.json({ limit: "100kb" })', "server.ts"),
        ("flask_app", "security_headers", "@app.after_request", "app.py"),
        ("flask_app", "rate_limit", "Limiter(get_remote_address", "app.py"),
        ("flask_app", "csrf", "CSRFProtect(app)", "app.py"),
        ("flask_app", "input_validation", 'app.config["MAX_CONTENT_LENGTH"]', "app.py"),
        ("flask_app", "env_secrets", "SECRET_KEY=", ".env.example"),
        (
            "spring_app",
            "security_headers",
            "javax.servlet",
            "src/main/java/com/example/demo/SecurityHeadersFilter.java",
        ),
    ],
)
def test_recipe_builds(
    ctx: AppContext, apps: Path, app: str, recipe: str, needle: str, file: str
) -> None:
    root = apps / app
    scan_id = ctx.scans.scan(ScanRequest(path=str(root))).scan_id
    proposal = ctx.patches.propose_hardening(scan_id, recipe)
    assert file in proposal.files and proposal.diff
    ctx.patches.apply_patch(proposal.proposal_token)
    assert needle in (root / file).read_text()


def test_python_recipes_produce_valid_python(ctx: AppContext, apps: Path) -> None:
    root = apps / "flask_app"
    for recipe in ("security_headers", "rate_limit", "csrf", "input_validation"):
        scan_id = ctx.scans.scan(ScanRequest(path=str(root))).scan_id
        ctx.patches.apply_patch(ctx.patches.propose_hardening(scan_id, recipe).proposal_token)
    compile((root / "app.py").read_text(), "app.py", "exec")


def test_security_headers_clears_finding(ctx: AppContext, apps: Path) -> None:
    root = apps / "express_app"
    scan = ctx.scans.scan(ScanRequest(path=str(root)))
    headers = next(
        f for f in ctx.queries.findings(scan.scan_id, "info", 100, 0).items if f.cwe == "CWE-693"
    )
    assert headers.patchable
    proposal = ctx.patches.propose_patch(headers.id)
    ctx.patches.apply_patch(proposal.proposal_token)
    rescan = ctx.scans.scan(ScanRequest(path=str(root)))
    open_cwes = {f.cwe for f in ctx.queries.findings(rescan.scan_id, "info", 100, 0).items}
    assert "CWE-693" not in open_cwes
    assert "helmet" in (root / "package.json").read_text()


def test_nextjs_middleware_created(ctx: AppContext, tmp_path: Path) -> None:
    root = tmp_path / "next"
    (root / "app" / "api" / "x").mkdir(parents=True)
    (root / "package.json").write_text('{"dependencies": {"next": "14.0.0"}}')
    (root / "app" / "api" / "x" / "route.ts").write_text("export function GET() {}\n")
    scan_id = ctx.scans.scan(ScanRequest(path=str(root))).scan_id
    proposal = ctx.patches.propose_hardening(scan_id, "security_headers")
    assert proposal.files == ["middleware.ts"]


def test_unknown_and_not_applicable(ctx: AppContext, apps: Path) -> None:
    scan_id = ctx.scans.scan(ScanRequest(path=str(apps / "cpp_cli"))).scan_id
    with pytest.raises(AppSecError) as unknown:
        ctx.patches.propose_hardening(scan_id, "magic")
    assert unknown.value.code == ErrorCode.RECIPE_NOT_FOUND
    with pytest.raises(AppSecError) as not_applicable:
        ctx.patches.propose_hardening(scan_id, "csrf")
    assert not_applicable.value.code == ErrorCode.RECIPE_NOT_APPLICABLE


def test_env_secrets_not_applicable_when_done(ctx: AppContext, apps: Path) -> None:
    root = apps / "flask_app"
    scan_id = ctx.scans.scan(ScanRequest(path=str(root))).scan_id
    ctx.patches.apply_patch(ctx.patches.propose_hardening(scan_id, "env_secrets").proposal_token)
    shutil.copy(root / ".env.example", root / ".env.example.bak")
    rescan = ctx.scans.scan(ScanRequest(path=str(root))).scan_id
    assert _applicable(ctx, rescan)["env_secrets"] is False
