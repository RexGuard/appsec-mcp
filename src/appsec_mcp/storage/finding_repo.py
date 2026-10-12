from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from appsec_mcp.models.common import SEVERITY_ORDER
from appsec_mcp.storage.db import Database


@dataclass(frozen=True)
class FindingRecord:
    fingerprint: str
    scanner: str
    rule_id: str
    severity: str
    title: str
    plain_explanation: str
    cwe: str | None = None
    rel_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    snippet_redacted: str | None = None
    fix_hint: str | None = None
    patchable: bool = False
    status: str = "new"
    id: int | None = field(default=None, compare=False)
    scan_id: int | None = field(default=None, compare=False)


_COLUMNS = (
    "fingerprint, scanner, rule_id, severity, title, plain_explanation, cwe, rel_path, "
    "line_start, line_end, snippet_redacted, fix_hint, patchable, status"
)


def _record(row) -> FindingRecord:
    d = dict(row)
    d["patchable"] = bool(d["patchable"])
    return FindingRecord(**d)


def _severities_at_least(floor: str) -> list[str]:
    return [s for s, rank in SEVERITY_ORDER.items() if rank >= SEVERITY_ORDER[floor]]


class FindingRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add_many(self, scan_id: int, findings: Iterable[FindingRecord]) -> list[int]:
        ids: list[int] = []
        with self.db.transaction() as c:
            for f in findings:
                cur = c.execute(
                    f"INSERT INTO findings (scan_id, {_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",  # noqa: S608
                    (
                        scan_id,
                        f.fingerprint,
                        f.scanner,
                        f.rule_id,
                        f.severity,
                        f.title,
                        f.plain_explanation,
                        f.cwe,
                        f.rel_path,
                        f.line_start,
                        f.line_end,
                        f.snippet_redacted,
                        f.fix_hint,
                        int(f.patchable),
                        f.status,
                    ),
                )
                ids.append(int(cur.lastrowid or 0))
        return ids

    def get(self, finding_id: int) -> FindingRecord | None:
        row = self.db.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return _record(row) if row else None

    def list(self, scan_id: int, min_severity: str = "info", limit: int = 50, offset: int = 0) -> list[FindingRecord]:
        sevs = _severities_at_least(min_severity)
        placeholders = ",".join("?" for _ in sevs)
        rows = self.db.conn.execute(
            f"SELECT * FROM findings WHERE scan_id = ? AND severity IN ({placeholders}) "  # noqa: S608
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, rel_path, line_start, id LIMIT ? OFFSET ?",
            (scan_id, *sevs, limit, offset),
        ).fetchall()
        return [_record(r) for r in rows]

    def count(self, scan_id: int, min_severity: str = "info") -> int:
        sevs = _severities_at_least(min_severity)
        placeholders = ",".join("?" for _ in sevs)
        row = self.db.conn.execute(
            f"SELECT COUNT(*) FROM findings WHERE scan_id = ? AND severity IN ({placeholders})",  # noqa: S608
            (scan_id, *sevs),
        ).fetchone()
        return int(row[0])

    def counts_by_severity(self, scan_id: int) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        rows = self.db.conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? AND status != 'fixed' GROUP BY severity",
            (scan_id,),
        ).fetchall()
        counts.update({r["severity"]: r["n"] for r in rows})
        return counts

    def fingerprints(self, scan_id: int) -> set[str]:
        rows = self.db.conn.execute(
            "SELECT fingerprint FROM findings WHERE scan_id = ? AND status != 'fixed'", (scan_id,)
        ).fetchall()
        return {r[0] for r in rows}
