"""Scans: one row per scan run, plus the ledger tables that belong to it."""

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from appsec_mcp.models.ledger import LedgerFile, RuleApplied
from appsec_mcp.storage.db import Database, utc_now


@dataclass(frozen=True)
class ScanRow:
    """A stored scan joined with its project."""

    id: int
    project_id: int
    project_name: str
    root_path: str
    started_at: str
    finished_at: str | None
    status: str
    score: int | None
    summary: dict[str, Any]


_SCAN_SELECT = """
    SELECT s.id, s.project_id, p.name AS project_name, p.root_path, s.started_at,
           s.finished_at, s.status, s.score, s.summary_json
    FROM scans s JOIN projects p ON p.id = s.project_id
"""


def _to_scan(row: Any) -> ScanRow:
    data = dict(row)
    summary = json.loads(data.pop("summary_json") or "{}")
    return ScanRow(**data, summary=summary)


class ScanRepo:
    """Create, finish and query scans and their ledger rows."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def create(self, project_id: int) -> int:
        """Insert a running scan and return its id."""
        with self._db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (project_id, started_at, status) VALUES (?, ?, 'running')",
                (project_id, utc_now()),
            )
            return int(cur.lastrowid or 0)

    def finish(self, scan_id: int, status: str, score: int | None, summary: dict[str, Any]) -> None:
        """Mark a scan finished with its final status, score and summary."""
        with self._db.connect() as conn:
            conn.execute(
                "UPDATE scans SET finished_at = ?, status = ?, score = ?, summary_json = ? "
                "WHERE id = ?",
                (utc_now(), status, score, json.dumps(summary), scan_id),
            )

    def get(self, scan_id: int) -> ScanRow | None:
        """Return one scan."""
        with self._db.connect() as conn:
            row = conn.execute(f"{_SCAN_SELECT} WHERE s.id = ?", (scan_id,)).fetchone()
        return _to_scan(row) if row else None

    def list_recent(self, project_id: int | None, limit: int) -> list[ScanRow]:
        """Return the newest scans, optionally for one project."""
        with self._db.connect() as conn:
            if project_id is None:
                rows = conn.execute(f"{_SCAN_SELECT} ORDER BY s.id DESC LIMIT ?", (limit,))
            else:
                rows = conn.execute(
                    f"{_SCAN_SELECT} WHERE s.project_id = ? ORDER BY s.id DESC LIMIT ?",
                    (project_id, limit),
                )
            return [_to_scan(r) for r in rows.fetchall()]

    def previous_completed(self, project_id: int, before_scan_id: int) -> ScanRow | None:
        """Return the latest finished scan of a project before `before_scan_id`."""
        with self._db.connect() as conn:
            row = conn.execute(
                f"{_SCAN_SELECT} WHERE s.project_id = ? AND s.id < ? "
                "AND s.status IN ('completed', 'partial') ORDER BY s.id DESC LIMIT 1",
                (project_id, before_scan_id),
            ).fetchone()
        return _to_scan(row) if row else None

    def add_files(self, scan_id: int, files: Iterable[LedgerFile]) -> None:
        """Bulk insert ledger file entries."""
        with self._db.connect() as conn:
            conn.executemany(
                "INSERT INTO files_read (scan_id, rel_path, language, size_bytes, sha256, status, "
                "skip_reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        scan_id,
                        f.rel_path,
                        f.language,
                        f.size_bytes,
                        f.sha256,
                        f.status,
                        f.skip_reason,
                    )
                    for f in files
                ),
            )

    def add_rules(self, scan_id: int, rules: Iterable[RuleApplied]) -> None:
        """Bulk insert the rules each scanner applied."""
        with self._db.connect() as conn:
            conn.executemany(
                "INSERT INTO rules_applied (scan_id, scanner, rule_id, scanner_version, "
                "files_matched) VALUES (?, ?, ?, ?, ?)",
                (
                    (scan_id, r.scanner, r.rule_id, r.scanner_version, r.files_matched)
                    for r in rules
                ),
            )

    def file_counts(self, scan_id: int) -> tuple[int, int]:
        """Return (read, skipped) file counts."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM files_read WHERE scan_id = ? GROUP BY status",
                (scan_id,),
            ).fetchall()
        counts = {r["status"]: r["n"] for r in rows}
        return counts.get("read", 0), counts.get("skipped", 0)

    def files(self, scan_id: int, limit: int, offset: int) -> list[LedgerFile]:
        """Return a page of ledger file entries, skipped first then by path."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT rel_path, language, size_bytes, sha256, status, skip_reason "
                "FROM files_read WHERE scan_id = ? ORDER BY status DESC, rel_path "
                "LIMIT ? OFFSET ?",
                (scan_id, limit, offset),
            ).fetchall()
        return [LedgerFile(**dict(r)) for r in rows]

    def rules(self, scan_id: int) -> list[RuleApplied]:
        """Return every rule applied in a scan."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT scanner, rule_id, scanner_version, files_matched FROM rules_applied "
                "WHERE scan_id = ? ORDER BY scanner, rule_id",
                (scan_id,),
            ).fetchall()
        return [RuleApplied(**dict(r)) for r in rows]
