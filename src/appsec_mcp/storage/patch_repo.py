"""Patches: proposals bound to file hashes, and their apply/revert state."""

import json
from dataclasses import dataclass

from appsec_mcp.models.patch import FileChange
from appsec_mcp.storage.db import Database, utc_now


@dataclass(frozen=True)
class PatchRow:
    """A stored patch."""

    id: int
    project_id: int
    finding_id: int | None
    recipe: str | None
    proposal_token: str
    summary: str
    diff: str
    file_hashes: dict[str, str | None]
    changes: list[FileChange]
    status: str
    created_at: str
    expires_at: str
    applied_at: str | None
    backup_dir: str | None


_COLUMNS = (
    "id, project_id, finding_id, recipe, proposal_token, summary, diff, file_hashes_json, "
    "changes_json, status, created_at, expires_at, applied_at, backup_dir"
)


def _to_row(row: object) -> PatchRow:
    data = dict(row)  # type: ignore[call-overload]
    data["file_hashes"] = json.loads(data.pop("file_hashes_json"))
    data["changes"] = [FileChange(**c) for c in json.loads(data.pop("changes_json"))]
    return PatchRow(**data)


class PatchRepo:
    """Create and update patch rows."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def create(
        self,
        *,
        project_id: int,
        finding_id: int | None,
        recipe: str | None,
        token: str,
        summary: str,
        diff: str,
        file_hashes: dict[str, str | None],
        changes: list[FileChange],
        expires_at: str,
    ) -> int:
        """Store a new proposal and return its id."""
        with self._db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO patches (project_id, finding_id, recipe, proposal_token, summary, "
                "diff, file_hashes_json, changes_json, status, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?)",
                (
                    project_id,
                    finding_id,
                    recipe,
                    token,
                    summary,
                    diff,
                    json.dumps(file_hashes),
                    json.dumps([c.model_dump() for c in changes]),
                    utc_now(),
                    expires_at,
                ),
            )
            return int(cur.lastrowid or 0)

    def get(self, patch_id: int) -> PatchRow | None:
        """Return a patch by id."""
        with self._db.connect() as conn:
            row = conn.execute(
                f"SELECT {_COLUMNS} FROM patches WHERE id = ?", (patch_id,)
            ).fetchone()
        return _to_row(row) if row else None

    def get_by_token(self, token: str) -> PatchRow | None:
        """Return a patch by its proposal token."""
        with self._db.connect() as conn:
            row = conn.execute(
                f"SELECT {_COLUMNS} FROM patches WHERE proposal_token = ?", (token,)
            ).fetchone()
        return _to_row(row) if row else None

    def set_status(
        self, patch_id: int, status: str, *, backup_dir: str | None = None, applied: bool = False
    ) -> None:
        """Update a patch's status (and backup folder / apply time when given)."""
        with self._db.connect() as conn:
            conn.execute(
                "UPDATE patches SET status = ?, backup_dir = COALESCE(?, backup_dir), "
                "applied_at = CASE WHEN ? THEN ? ELSE applied_at END WHERE id = ?",
                (status, backup_dir, int(applied), utc_now(), patch_id),
            )
