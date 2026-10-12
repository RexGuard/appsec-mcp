"""Projects: one row per scanned root folder."""

from dataclasses import dataclass

from appsec_mcp.storage.db import Database, utc_now


@dataclass(frozen=True)
class ProjectRow:
    """A stored project."""

    id: int
    root_path: str
    name: str
    created_at: str


class ProjectRepo:
    """Create and look up projects."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def get_or_create(self, root_path: str, name: str) -> ProjectRow:
        """Return the project for `root_path`, creating it on first use."""
        with self._db.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO projects (root_path, name, created_at) VALUES (?, ?, ?)",
                (root_path, name, utc_now()),
            )
            row = conn.execute(
                "SELECT id, root_path, name, created_at FROM projects WHERE root_path = ?",
                (root_path,),
            ).fetchone()
        return ProjectRow(**dict(row))

    def get(self, project_id: int) -> ProjectRow | None:
        """Return a project by id."""
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT id, root_path, name, created_at FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
        return ProjectRow(**dict(row)) if row else None

    def find_by_path(self, root_path: str) -> ProjectRow | None:
        """Return a project by its resolved root path."""
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT id, root_path, name, created_at FROM projects WHERE root_path = ?",
                (root_path,),
            ).fetchone()
        return ProjectRow(**dict(row)) if row else None
