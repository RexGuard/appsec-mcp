"""Attack chains on the vulnerable fixtures, end to end through a scan."""

from pathlib import Path

from appsec_mcp.context import AppContext
from appsec_mcp.models.scan import ScanRequest


def _chains(ctx: AppContext, root: Path):  # type: ignore[no-untyped-def]
    scan = ctx.scans.scan(ScanRequest(path=str(root)))
    return ctx.queries.attack_chains(scan.scan_id)


def test_express_sql_injection_chain_reaches_mysql(ctx: AppContext, apps: Path) -> None:
    chains = _chains(ctx, apps / "express_app")
    sql = [c for c in chains.items if c.kind == "input_to_injection" and "MySQL" in c.narrative]
    assert sql, [c.title for c in chains.items]
    chain = sql[0]
    assert chain.steps[0].kind == "entry" and chain.steps[-1].kind == "asset"
    assert any(step.finding_id for step in chain.steps)
    assert chain.confidence in ("likely", "verified")


def test_express_stripe_key_chain_names_stripe(ctx: AppContext, apps: Path) -> None:
    chains = _chains(ctx, apps / "express_app")
    secret = [c for c in chains.items if c.kind == "secret_to_service"]
    assert secret
    assert any("stripe" in step.label.lower() for step in secret[0].steps if step.kind == "asset")
    assert secret[0].confidence == "verified"


def test_chains_are_numbered_and_sorted(ctx: AppContext, apps: Path) -> None:
    chains = _chains(ctx, apps / "express_app")
    assert [c.id for c in chains.items] == list(range(1, chains.total + 1))
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    severities = [ranks[c.severity] for c in chains.items]
    assert severities == sorted(severities, reverse=True)


def test_hypothesis_chains_never_exceed_medium(ctx: AppContext, apps: Path) -> None:
    for name in ("express_app", "flask_app", "spring_app", "cpp_cli", "static_site"):
        for chain in _chains(ctx, apps / name).items:
            if chain.confidence == "hypothesis":
                assert chain.severity in ("medium", "low", "info")


def test_static_site_without_routes_has_no_injection_chains(ctx: AppContext, apps: Path) -> None:
    chains = _chains(ctx, apps / "static_site")
    assert all(c.kind != "vulnerable_dependency" for c in chains.items)
