import re
import sqlite3
from pathlib import Path

import pytest

from appsec_mcp.storage import app_home, open_database
from appsec_mcp.storage.finding_repo import FindingRecord, FindingRepo
from appsec_mcp.storage.map_repo import EdgeRecord, MapRepo, NodeRecord
from appsec_mcp.storage.migrations import MIGRATIONS, current_version, migrate
from appsec_mcp.storage.patch_repo import PatchRepo
from appsec_mcp.storage.project_repo import ProjectRepo
from appsec_mcp.storage.scan_repo import FileRecord, RuleRecord, ScanRepo

STORAGE_SRC = Path(__file__).parents[2] / "src" / "appsec_mcp" / "storage"


def _finding(fp="fp1", severity="high", **kw):
    return FindingRecord(
        fingerprint=fp,
        scanner="semgrep",
        rule_id="r1",
        severity=severity,
        title="t",
        plain_explanation="p",
        **kw,
    )


@pytest.fixture
def project(db):
    return ProjectRepo(db).get_or_create("/work/shop", "shop")


@pytest.fixture
def scan(db, project):
    return ScanRepo(db).create(project.id)


def test_home_defaults_and_override(monkeypatch, tmp_path):
    monkeypatch.delenv("APPSEC_MCP_HOME")
    assert app_home() == Path.home() / ".appsec-mcp"
    monkeypatch.setenv("APPSEC_MCP_HOME", str(tmp_path))
    assert app_home() == tmp_path


def test_default_database_lives_in_home(tmp_path):
    db = open_database()
    try:
        assert (app_home() / "appsec.db").is_file()
    finally:
        db.close()


def test_migrations_are_idempotent(tmp_path):
    path = tmp_path / "m.db"
    open_database(path).close()
    open_database(path).close()
    conn = sqlite3.connect(path)
    assert current_version(conn) == len(MIGRATIONS)
    assert migrate(conn) == len(MIGRATIONS)
    conn.close()


def test_every_spec_table_and_index_exists(db):
    names = {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','index')")}
    for table in ("projects", "scans", "files_read", "rules_applied", "findings", "map_nodes", "map_edges", "patches"):
        assert table in names
    for index in (
        "idx_findings_scan_severity",
        "idx_files_read_scan",
        "idx_map_nodes_scan",
        "idx_findings_fingerprint",
    ):
        assert index in names


def test_foreign_keys_are_enforced(db):
    with pytest.raises(sqlite3.IntegrityError):
        ScanRepo(db).create(project_id=999)


def test_check_constraints_reject_bad_values(db, scan):
    with pytest.raises(sqlite3.IntegrityError):
        FindingRepo(db).add_many(scan.id, [_finding(severity="urgent")])


def test_project_get_or_create_is_stable(db):
    repo = ProjectRepo(db)
    a = repo.get_or_create("/work/a", "a")
    assert repo.get_or_create("/work/a", "a").id == a.id
    assert repo.get(a.id) == a
    assert repo.by_path("/nope") is None
    assert [p.root_path for p in repo.list()] == ["/work/a"]


def test_scan_lifecycle(db, project):
    repo = ScanRepo(db)
    first = repo.create(project.id)
    assert first.status == "running"
    assert repo.running_for_project(project.id) == first
    repo.finish(first.id, "completed", 80, {"counts": {"high": 1}})
    done = repo.get(first.id)
    assert done.status == "completed" and done.score == 80 and done.summary == {"counts": {"high": 1}}
    assert done.finished_at is not None
    second = repo.create(project.id)
    assert repo.previous_finished(project.id, second.id).id == first.id
    assert repo.previous_finished(project.id, first.id) is None
    assert [s.id for s in repo.list(project.id)] == [second.id, first.id]
    assert repo.get(12345) is None


def test_ledger_round_trip(db, scan):
    repo = ScanRepo(db)
    repo.add_files(
        scan.id,
        [
            FileRecord("a.py", "read", "python", 10, "a" * 64),
            FileRecord("logo.png", "skipped", skip_reason="binary"),
        ],
    )
    assert repo.file_counts(scan.id) == {"read": 1, "skipped": 1}
    assert {f.rel_path for f in repo.files(scan.id)} == {"a.py", "logo.png"}
    assert len(repo.files(scan.id, limit=1, offset=1)) == 1
    repo.add_rules(scan.id, [RuleRecord("semgrep", "x", "1.0", 0), RuleRecord("semgrep", "y", "1.0", 2)])
    assert [r.rule_id for r in repo.rules(scan.id)] == ["y", "x"]


def test_findings_filter_page_and_count(db, scan):
    repo = FindingRepo(db)
    ids = repo.add_many(
        scan.id,
        [_finding("a", "low"), _finding("b", "critical"), _finding("c", "info"), _finding("d", "high", patchable=True)],
    )
    assert len(ids) == 4
    assert [f.severity for f in repo.list(scan.id)] == ["critical", "high", "low", "info"]
    assert [f.severity for f in repo.list(scan.id, min_severity="high")] == ["critical", "high"]
    assert repo.count(scan.id, "low") == 3
    assert len(repo.list(scan.id, limit=2, offset=1)) == 2
    got = repo.get(ids[3])
    assert got.patchable is True and got.id == ids[3]
    assert repo.counts_by_severity(scan.id) == {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 1}
    assert repo.fingerprints(scan.id) == {"a", "b", "c", "d"}


def test_map_round_trip_dedupes_edges(db, scan):
    repo = MapRepo(db)
    a, b = repo.add_nodes(
        scan.id, [NodeRecord("route", "GET /", "app.py", {"line": 3}, 1), NodeRecord("data_store", "db")]
    )
    assert repo.add_edges(scan.id, [EdgeRecord(a, b, "reads"), EdgeRecord(a, b, "reads")]) == 1
    nodes = repo.nodes(scan.id)
    assert nodes[0].meta == {"line": 3} and nodes[0].finding_count == 1
    assert repo.edges(scan.id) == [EdgeRecord(a, b, "reads")]


def test_patch_lifecycle(db, project):
    repo = PatchRepo(db)
    p = repo.create(project.id, "tok" * 12, "--- a\n+++ b\n", {"a.py": "f" * 64}, recipe="security_headers")
    assert p.status == "proposed" and p.file_hashes == {"a.py": "f" * 64}
    assert repo.by_token("tok" * 12).id == p.id
    repo.mark_applied(p.id, "/backups/1")
    applied = repo.get(p.id)
    assert applied.status == "applied" and applied.backup_dir == "/backups/1" and applied.applied_at
    repo.set_status(p.id, "reverted")
    assert repo.get(p.id).status == "reverted"
    with pytest.raises(sqlite3.IntegrityError):
        repo.create(project.id, "tok" * 12, "d", {})


def test_failed_transaction_rolls_back(db, scan):
    repo = FindingRepo(db)
    with pytest.raises(sqlite3.IntegrityError):
        repo.add_many(scan.id, [_finding("ok"), _finding("bad", severity="nope")])
    assert repo.count(scan.id) == 0


def test_all_sql_is_parameterised():
    """No SQL is built from values: every f-string in an execute() may only splice fixed column lists or `?` lists."""
    offenders = []
    for path in STORAGE_SRC.glob("*_repo.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"\.format\(|%\s*\(|\"\s*%\s", text):
            offenders.append(f"{path.name}: string formatting near SQL")
        for m in re.finditer(r'f"([^"]*)"', text):
            for expr in re.findall(r"\{([^}]*)\}", m.group(1)):
                if expr not in {"_COLUMNS", "placeholders"}:
                    offenders.append(f"{path.name}: f-string splices {expr!r}")
    assert offenders == []
