"""Storage: idempotent migrations, CRUD per repository, parameterised SQL, indexes."""

import re
from pathlib import Path

from appsec_mcp.models.finding import NormalizedFinding
from appsec_mcp.models.ledger import LedgerFile, RuleApplied
from appsec_mcp.models.patch import FileChange
from appsec_mcp.models.system_map import MapEdge, MapNode, SystemGraph
from appsec_mcp.services.repositories import Repositories
from appsec_mcp.storage.db import Database
from appsec_mcp.storage.migrations import current_version, migrate

STORAGE_SRC = Path(__file__).parents[2] / "src" / "appsec_mcp" / "storage"


def _finding(fp: str, severity: str = "high") -> NormalizedFinding:
    return NormalizedFinding(
        fingerprint=fp,
        scanner="builtin",
        rule_id="r",
        severity=severity,
        cwe="CWE-89",  # type: ignore[arg-type]
        rel_path="a.py",
        line_start=1,
        line_end=1,
        snippet_redacted="x",
        title="t",
        plain_explanation="p",
        fix_hint="f",
        fix_kind="sql_param",
    )


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    db = Database(tmp_path / "a.db")
    with db.connect() as conn:
        first = current_version(conn)
        assert migrate(conn) == first
        indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {
        "idx_findings_scan_severity",
        "idx_files_read_scan",
        "idx_map_nodes_scan",
        "idx_findings_fingerprint",
    } <= indexes
    Database(tmp_path / "a.db")


def test_repositories_crud(tmp_path: Path) -> None:
    repos = Repositories.over(Database(tmp_path / "b.db"))
    project = repos.projects.get_or_create("/x", "x")
    assert repos.projects.get_or_create("/x", "x").id == project.id
    assert repos.projects.find_by_path("/x") == project
    scan_id = repos.scans.create(project.id)
    repos.scans.add_files(
        scan_id,
        [
            LedgerFile(rel_path="a.py", status="read", language="python", size_bytes=1, sha256="h"),
            LedgerFile(rel_path="node_modules", status="skipped", skip_reason="excluded_dir"),
        ],
    )
    repos.scans.add_rules(scan_id, [RuleApplied(scanner="builtin", rule_id="r", files_matched=1)])
    repos.findings.add_many(scan_id, [_finding("a"), _finding("b", "low")])
    repos.maps.save(
        scan_id,
        SystemGraph(
            nodes=[
                MapNode(id=1, kind="component", label="c"),
                MapNode(id=2, kind="route", label="r"),
            ],
            edges=[MapEdge(source=1, target=2, kind="handles")],
        ),
    )
    repos.scans.finish(scan_id, "completed", 80, {"counts": {"high": 1}})

    assert repos.scans.get(scan_id).score == 80  # type: ignore[union-attr]
    assert repos.scans.file_counts(scan_id) == (1, 1)
    assert repos.scans.rules(scan_id)[0].rule_id == "r"
    total, rows = repos.findings.page(scan_id, "medium", False, 10, 0)
    assert total == 1 and rows[0].fingerprint == "a"
    assert len(repos.maps.load(scan_id).edges) == 1
    assert repos.scans.list_recent(project.id, 5)[0].id == scan_id

    patch_id = repos.patches.create(
        project_id=project.id,
        finding_id=rows[0].id,
        recipe=None,
        token="tok",
        summary="s",
        diff="d",
        file_hashes={"a.py": "h"},
        changes=[FileChange(rel_path="a.py", before="a", after="b")],
        expires_at="2099-01-01T00:00:00+00:00",
    )
    repos.patches.set_status(patch_id, "applied", backup_dir="/b", applied=True)
    patch = repos.patches.get_by_token("tok")
    assert patch is not None and patch.status == "applied" and patch.backup_dir == "/b"


def test_all_sql_is_parameterised() -> None:
    """No %-formatting or .format() in SQL; f-strings may only splice UPPER_CASE constants."""
    for path in STORAGE_SRC.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert ".format(" not in text, path
        assert not re.search(r"execute\([^)]*%\s*\(", text), path
        for fstring in re.findall(r'f"([^"]*)"', text):
            for name in re.findall(r"\{([^}]+)\}", fstring):
                assert re.fullmatch(r"_[A-Z_]+", name), f"{path.name}: {{{name}}} in SQL"
