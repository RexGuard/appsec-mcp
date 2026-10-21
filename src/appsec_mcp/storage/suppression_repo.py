"""False-positive suppressions: findings a user rejected, remembered per project by fingerprint."""

from dataclasses import dataclass

from appsec_mcp.storage.db import Database, utc_now

_COLUMNS = "id, project_id, fingerprint, title, rel_path, reason, created_at"


@dataclass(frozen=True)
class SuppressionRow:
    """A finding the user marked as a false positive."""

    id: int
    project_id: int
    fingerprint: str
    title: str
    rel_path: str | None
    reason: str
    created_at: str


class SuppressionRepo:
    """Add, remove and list suppressions."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def add(
        self, project_id: int, fingerprint: str, title: str, rel_path: str | None, reason: str
    ) -> None:
        """Remember a false positive; marking it again updates the reason."""
        with self._db.connect() as conn:
            conn.execute(
                "INSERT INTO suppressions (project_id, fingerprint, title, rel_path, reason, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (project_id, fingerprint) DO UPDATE SET reason = excluded.reason",
                (project_id, fingerprint, title, rel_path, reason, utc_now()),
            )

    def remove(self, project_id: int, fingerprint: str) -> bool:
        """Forget a suppression. Returns False if there was none."""
        with self._db.connect() as conn:
            cursor = conn.execute(
                "DELETE FROM suppressions WHERE project_id = ? AND fingerprint = ?",
                (project_id, fingerprint),
            )
        return cursor.rowcount > 0

    def fingerprints(self, project_id: int) -> set[str]:
        """Every suppressed fingerprint of a project."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT fingerprint FROM suppressions WHERE project_id = ?", (project_id,)
            ).fetchall()
        return {r["fingerprint"] for r in rows}

    def for_project(self, project_id: int) -> list[SuppressionRow]:
        """All suppressions of a project, newest first."""
        with self._db.connect() as conn:
            rows = conn.execute(
                f"SELECT {_COLUMNS} FROM suppressions WHERE project_id = ? ORDER BY id DESC",
                (project_id,),
            ).fetchall()
        return [SuppressionRow(**dict(r)) for r in rows]
