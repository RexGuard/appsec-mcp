"""Findings: stored per scan, with the status relative to the previous scan."""

from collections.abc import Iterable
from dataclasses import dataclass

from appsec_mcp.models.base import SEVERITY_RANK
from appsec_mcp.models.finding import NormalizedFinding
from appsec_mcp.storage.db import Database


@dataclass(frozen=True)
class FindingRow:
    """A stored finding."""

    id: int
    scan_id: int
    fingerprint: str
    scanner: str
    rule_id: str
    severity: str
    cwe: str | None
    rel_path: str | None
    line_start: int | None
    line_end: int | None
    snippet_redacted: str
    title: str
    plain_explanation: str
    fix_hint: str
    fix_kind: str | None
    patchable: bool
    status: str


_COLUMNS = (
    "id, scan_id, fingerprint, scanner, rule_id, severity, cwe, rel_path, line_start, line_end, "
    "snippet_redacted, title, plain_explanation, fix_hint, fix_kind, patchable, status"
)
_SEVERITY_ORDER_SQL = (
    "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
    "WHEN 'low' THEN 1 ELSE 0 END"
)

_PAGE_WHERE = f"WHERE scan_id = ? AND {_SEVERITY_ORDER_SQL} >= ? AND status IN (?, ?, ?)"


def _to_row(row: object) -> FindingRow:
    data = dict(row)  # type: ignore[call-overload]
    data["patchable"] = bool(data["patchable"])
    data["snippet_redacted"] = data["snippet_redacted"] or ""
    data["fix_hint"] = data["fix_hint"] or ""
    return FindingRow(**data)


class FindingRepo:
    """Insert and query findings."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def add_many(self, scan_id: int, findings: Iterable[NormalizedFinding]) -> int:
        """Bulk insert findings and return how many were stored."""
        rows = [
            (
                scan_id,
                f.fingerprint,
                f.scanner,
                f.rule_id,
                f.severity,
                f.cwe,
                f.rel_path,
                f.line_start,
                f.line_end,
                f.snippet_redacted,
                f.title,
                f.plain_explanation,
                f.fix_hint,
                f.fix_kind,
                int(f.fix_kind is not None),
                f.status,
            )
            for f in findings
        ]
        with self._db.connect() as conn:
            conn.executemany(
                "INSERT INTO findings (scan_id, fingerprint, scanner, rule_id, severity, cwe, "
                "rel_path, line_start, line_end, snippet_redacted, title, plain_explanation, "
                "fix_hint, fix_kind, patchable, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def get(self, finding_id: int) -> FindingRow | None:
        """Return one finding."""
        with self._db.connect() as conn:
            row = conn.execute(
                f"SELECT {_COLUMNS} FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
        return _to_row(row) if row else None

    def page(
        self, scan_id: int, min_severity: str, include_fixed: bool, limit: int, offset: int
    ) -> tuple[int, list[FindingRow]]:
        """Return (total, page) of findings at or above `min_severity`, worst first."""
        statuses = ("new", "existing", "fixed") if include_fixed else ("new", "existing", "")
        params = (scan_id, SEVERITY_RANK[min_severity], *statuses)
        with self._db.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM findings {_PAGE_WHERE}", params).fetchone()[
                0
            ]
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM findings {_PAGE_WHERE} "
                f"ORDER BY status = 'fixed', {_SEVERITY_ORDER_SQL} DESC, rel_path, line_start "
                "LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
        return int(total), [_to_row(r) for r in rows]

    def for_scan(self, scan_id: int, include_fixed: bool = False) -> list[FindingRow]:
        """Return all findings of a scan."""
        with self._db.connect() as conn:
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
        found = [_to_row(r) for r in rows]
        return found if include_fixed else [f for f in found if f.status != "fixed"]
