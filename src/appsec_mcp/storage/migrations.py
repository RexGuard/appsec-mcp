"""Schema migrations. Each migration runs once, in order, inside a transaction."""

import logging
import sqlite3

logger = logging.getLogger(__name__)

_MIGRATIONS: list[str] = [
    """
    CREATE TABLE projects (
        id INTEGER PRIMARY KEY,
        root_path TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL CHECK (status IN ('running','completed','failed','partial')),
        score INTEGER CHECK (score BETWEEN 0 AND 100),
        summary_json TEXT
    );
    CREATE TABLE files_read (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        rel_path TEXT NOT NULL,
        language TEXT,
        size_bytes INTEGER,
        sha256 TEXT,
        status TEXT NOT NULL CHECK (status IN ('read','skipped')),
        skip_reason TEXT
    );
    CREATE TABLE rules_applied (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        scanner TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        scanner_version TEXT,
        files_matched INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE findings (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        scanner TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
        cwe TEXT,
        rel_path TEXT,
        line_start INTEGER,
        line_end INTEGER,
        snippet_redacted TEXT,
        title TEXT NOT NULL,
        plain_explanation TEXT NOT NULL,
        fix_hint TEXT,
        fix_kind TEXT,
        patchable INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL CHECK (status IN ('new','existing','fixed'))
    );
    CREATE TABLE map_nodes (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        local_id INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('component','entry_point','route','data_store',
                                           'external_service','secret','dependency')),
        label TEXT NOT NULL,
        rel_path TEXT,
        meta_json TEXT,
        finding_count INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE map_edges (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        source_local_id INTEGER NOT NULL,
        target_local_id INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('imports','calls','handles','reads','depends_on'))
    );
    CREATE TABLE patches (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id),
        finding_id INTEGER REFERENCES findings(id),
        recipe TEXT,
        proposal_token TEXT UNIQUE NOT NULL,
        summary TEXT NOT NULL,
        diff TEXT NOT NULL,
        file_hashes_json TEXT NOT NULL,
        changes_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('proposed','applied','reverted','expired')),
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        applied_at TEXT,
        backup_dir TEXT
    );
    CREATE INDEX idx_findings_scan_severity ON findings(scan_id, severity);
    CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
    CREATE INDEX idx_files_read_scan ON files_read(scan_id);
    CREATE INDEX idx_rules_applied_scan ON rules_applied(scan_id);
    CREATE INDEX idx_map_nodes_scan ON map_nodes(scan_id);
    CREATE INDEX idx_map_edges_scan ON map_edges(scan_id);
    CREATE INDEX idx_scans_project ON scans(project_id);
    """,
]


def current_version(conn: sqlite3.Connection) -> int:
    """Return the applied schema version (0 for a new database)."""
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return int(row[0] or 0)


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations. Safe to call any number of times."""
    version = current_version(conn)
    for index, script in enumerate(_MIGRATIONS[version:], start=version + 1):
        logger.info("Applying schema migration %d", index)
        statements = [s.strip() for s in script.split(";") if s.strip()]
        with conn:
            for statement in statements:
                conn.execute(statement)
            conn.execute("INSERT INTO schema_version (version) VALUES (?)", (index,))
    return current_version(conn)
