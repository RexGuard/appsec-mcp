"""Scans and their audit ledger (files read or skipped, rules applied)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from appsec_mcp.storage.db import Database, utc_now


@dataclass(frozen=True)
class Scan:
    id: int
    project_id: int
    started_at: str
    finished_at: str | None
    status: str
    score: int | None
    summary: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FileRecord:
    rel_path: str
    status: str
    language: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    skip_reason: str | None = None


@dataclass(frozen=True)
class RuleRecord:
    scanner: str
    rule_id: str
    scanner_version: str | None = None
    files_matched: int = 0


def _scan(row: Any) -> Scan:
    d = dict(row)
    summary = json.loads(d.pop("summary_json") or "{}")
    return Scan(**d, summary=summary)


class ScanRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, project_id: int) -> Scan:
        with self.db.transaction() as c:
            cur = c.execute(
                "INSERT INTO scans (project_id, started_at, status) VALUES (?, ?, 'running')",
                (project_id, utc_now()),
            )
        scan = self.get(int(cur.lastrowid or 0))
        if scan is None:  # pragma: no cover - the row was just written
            raise RuntimeError("row vanished after insert")
        return scan

    def finish(self, scan_id: int, status: str, score: int | None, summary: dict[str, Any]) -> None:
        with self.db.transaction() as c:
            c.execute(
                "UPDATE scans SET finished_at = ?, status = ?, score = ?, summary_json = ? WHERE id = ?",
                (utc_now(), status, score, json.dumps(summary, sort_keys=True), scan_id),
            )

    def get(self, scan_id: int) -> Scan | None:
        row = self.db.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _scan(row) if row else None

    def list(self, project_id: int | None = None, limit: int = 20) -> list[Scan]:
        if project_id is None:
            rows = self.db.conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        else:
            rows = self.db.conn.execute(
                "SELECT * FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT ?", (project_id, limit)
            )
        return [_scan(r) for r in rows.fetchall()]

    def previous_finished(self, project_id: int, before_scan_id: int) -> Scan | None:
        """The latest completed or partial scan of the project before the given one (for diffing)."""
        row = self.db.conn.execute(
            "SELECT * FROM scans WHERE project_id = ? AND id < ? AND status IN ('completed','partial') "
            "ORDER BY id DESC LIMIT 1",
            (project_id, before_scan_id),
        ).fetchone()
        return _scan(row) if row else None

    def running_for_project(self, project_id: int) -> Scan | None:
        row = self.db.conn.execute(
            "SELECT * FROM scans WHERE project_id = ? AND status = 'running' ORDER BY id DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        return _scan(row) if row else None

    # ── Ledger ──────────────────────────────────────────────────────────────
    def add_files(self, scan_id: int, files: Iterable[FileRecord]) -> int:
        rows = [(scan_id, f.rel_path, f.language, f.size_bytes, f.sha256, f.status, f.skip_reason) for f in files]
        with self.db.transaction() as c:
            c.executemany(
                "INSERT INTO files_read (scan_id, rel_path, language, size_bytes, sha256, status, skip_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def files(self, scan_id: int, limit: int = 200, offset: int = 0) -> list[FileRecord]:
        rows = self.db.conn.execute(
            "SELECT rel_path, status, language, size_bytes, sha256, skip_reason FROM files_read "
            "WHERE scan_id = ? ORDER BY status, rel_path LIMIT ? OFFSET ?",
            (scan_id, limit, offset),
        ).fetchall()
        return [FileRecord(**dict(r)) for r in rows]

    def file_counts(self, scan_id: int) -> dict[str, int]:
        rows = self.db.conn.execute(
            "SELECT status, COUNT(*) AS n FROM files_read WHERE scan_id = ? GROUP BY status", (scan_id,)
        ).fetchall()
        counts = {"read": 0, "skipped": 0}
        counts.update({r["status"]: r["n"] for r in rows})
        return counts

    def add_rules(self, scan_id: int, rules: Iterable[RuleRecord]) -> int:
        rows = [(scan_id, r.scanner, r.rule_id, r.scanner_version, r.files_matched) for r in rules]
        with self.db.transaction() as c:
            c.executemany(
                "INSERT INTO rules_applied (scan_id, scanner, rule_id, scanner_version, files_matched) "
                "VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def rules(self, scan_id: int) -> list[RuleRecord]:
        rows = self.db.conn.execute(
            "SELECT scanner, rule_id, scanner_version, files_matched FROM rules_applied "
            "WHERE scan_id = ? ORDER BY scanner, files_matched DESC, rule_id",
            (scan_id,),
        ).fetchall()
        return [RuleRecord(**dict(r)) for r in rows]
