"""Schema migrations (docs/plan/SPEC.md, "Database schema"). Applying them twice is a no-op."""

from __future__ import annotations

import sqlite3

MIGRATIONS: tuple[str, ...] = (
    # 1: initial schema
    """
    CREATE TABLE projects (
        id INTEGER PRIMARY KEY,
        root_path TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
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
        skip_reason TEXT CHECK (skip_reason IN
            ('gitignored','too_large','binary','excluded_dir','symlink_outside_root'))
    );
    CREATE TABLE rules_applied (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        scanner TEXT NOT NULL CHECK (scanner IN ('semgrep','gitleaks','osv','builtin')),
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
        patchable INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','existing','fixed'))
    );
    CREATE TABLE map_nodes (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN
            ('component','entry_point','route','data_store','external_service','secret','dependency')),
        label TEXT NOT NULL,
        rel_path TEXT,
        meta_json TEXT,
        finding_count INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE map_edges (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        source_node_id INTEGER NOT NULL REFERENCES map_nodes(id) ON DELETE CASCADE,
        target_node_id INTEGER NOT NULL REFERENCES map_nodes(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('imports','calls','handles','reads','depends_on')),
        UNIQUE (scan_id, source_node_id, target_node_id, kind)
    );
    CREATE TABLE patches (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
        recipe TEXT,
        proposal_token TEXT UNIQUE NOT NULL,
        diff TEXT NOT NULL,
        file_hashes_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('proposed','applied','reverted','expired')),
        created_at TEXT NOT NULL,
        applied_at TEXT,
        backup_dir TEXT
    );
    CREATE INDEX idx_findings_scan_severity ON findings(scan_id, severity);
    CREATE INDEX idx_files_read_scan ON files_read(scan_id);
    CREATE INDEX idx_map_nodes_scan ON map_nodes(scan_id);
    CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
    CREATE INDEX idx_scans_project ON scans(project_id, id);
    """,
)


def current_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def migrate(conn: sqlite3.Connection) -> int:
    """Apply every migration newer than the database's `user_version`. Returns the new version."""
    version = current_version(conn)
    for number, script in enumerate(MIGRATIONS, start=1):
        if number <= version:
            continue
        # executescript commits first; wrap so a failed migration leaves no half-built schema.
        conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {number};\nCOMMIT;")
        version = number
    return version
