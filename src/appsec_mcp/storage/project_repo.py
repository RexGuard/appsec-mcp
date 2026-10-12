from __future__ import annotations

from dataclasses import dataclass

from appsec_mcp.storage.db import Database, utc_now


@dataclass(frozen=True)
class Project:
    id: int
    root_path: str
    name: str
    created_at: str


class ProjectRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get_or_create(self, root_path: str, name: str) -> Project:
        with self.db.transaction() as c:
            c.execute(
                "INSERT INTO projects (root_path, name, created_at) VALUES (?, ?, ?) ON CONFLICT(root_path) DO NOTHING",
                (root_path, name, utc_now()),
            )
        found = self.by_path(root_path)
        if found is None:  # pragma: no cover - the row was just written
            raise RuntimeError("row vanished after insert")
        return found

    def get(self, project_id: int) -> Project | None:
        row = self.db.conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return Project(**dict(row)) if row else None

    def by_path(self, root_path: str) -> Project | None:
        row = self.db.conn.execute("SELECT * FROM projects WHERE root_path = ?", (root_path,)).fetchone()
        return Project(**dict(row)) if row else None

    def list(self) -> list[Project]:
        rows = self.db.conn.execute("SELECT * FROM projects ORDER BY id").fetchall()
        return [Project(**dict(r)) for r in rows]
