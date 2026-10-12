from __future__ import annotations

import json
from dataclasses import dataclass

from appsec_mcp.storage.db import Database, utc_now


@dataclass(frozen=True)
class PatchRecord:
    id: int
    project_id: int
    finding_id: int | None
    recipe: str | None
    proposal_token: str
    diff: str
    file_hashes: dict[str, str]
    status: str
    created_at: str
    applied_at: str | None
    backup_dir: str | None


def _record(row) -> PatchRecord:
    d = dict(row)
    d["file_hashes"] = json.loads(d.pop("file_hashes_json"))
    return PatchRecord(**d)


class PatchRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self,
        project_id: int,
        proposal_token: str,
        diff: str,
        file_hashes: dict[str, str],
        finding_id: int | None = None,
        recipe: str | None = None,
    ) -> PatchRecord:
        with self.db.transaction() as c:
            cur = c.execute(
                "INSERT INTO patches (project_id, finding_id, recipe, proposal_token, diff, file_hashes_json, "
                "status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'proposed', ?)",
                (
                    project_id,
                    finding_id,
                    recipe,
                    proposal_token,
                    diff,
                    json.dumps(file_hashes, sort_keys=True),
                    utc_now(),
                ),
            )
        rec = self.get(int(cur.lastrowid or 0))
        if rec is None:  # pragma: no cover - the row was just written
            raise RuntimeError("row vanished after insert")
        return rec

    def get(self, patch_id: int) -> PatchRecord | None:
        row = self.db.conn.execute("SELECT * FROM patches WHERE id = ?", (patch_id,)).fetchone()
        return _record(row) if row else None

    def by_token(self, token: str) -> PatchRecord | None:
        row = self.db.conn.execute("SELECT * FROM patches WHERE proposal_token = ?", (token,)).fetchone()
        return _record(row) if row else None

    def mark_applied(self, patch_id: int, backup_dir: str) -> None:
        with self.db.transaction() as c:
            c.execute(
                "UPDATE patches SET status = 'applied', applied_at = ?, backup_dir = ? WHERE id = ?",
                (utc_now(), backup_dir, patch_id),
            )

    def set_status(self, patch_id: int, status: str) -> None:
        with self.db.transaction() as c:
            c.execute("UPDATE patches SET status = ? WHERE id = ?", (status, patch_id))
