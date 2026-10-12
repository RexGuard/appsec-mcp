"""Applies and reverts file changes safely: hash check, backup, write, roll back on failure."""

import logging
import os
from collections.abc import Callable, Sequence
from pathlib import Path

from appsec_mcp.errors import ErrorCode, PatchError
from appsec_mcp.models.patch import FileChange
from appsec_mcp.patching.backups import BackupEntry, read_manifest, restore, write_backup
from appsec_mcp.patching.textio import encode, file_sha256, sha256_bytes
from appsec_mcp.security.paths import confine

logger = logging.getLogger(__name__)

Writer = Callable[[Path, bytes], None]


def atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file and rename, so a crash never leaves half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.appsec-tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


class PatchEngine:
    """File operations for one project root. The writer is injectable for failure tests."""

    def __init__(self, root: Path, writer: Writer = atomic_write) -> None:
        self._root = root
        self._write = writer

    def current_hashes(self, rel_paths: Sequence[str]) -> dict[str, str | None]:
        """SHA-256 of each file now (None for files that do not exist)."""
        return {rel: file_sha256(confine(self._root, rel)) for rel in rel_paths}

    def apply(
        self, changes: Sequence[FileChange], expected: dict[str, str | None], backup_dir: Path
    ) -> list[str]:
        """Write all changes or none of them. Returns the changed paths."""
        if self.current_hashes(list(expected)) != expected:
            raise PatchError(
                ErrorCode.FILES_CHANGED_SINCE_PROPOSAL,
                "The files changed after this fix was proposed. Ask for a new proposal.",
            )
        entries = [
            BackupEntry(
                rel_path=c.rel_path,
                existed=expected.get(c.rel_path) is not None,
                after_sha256=sha256_bytes(encode(c.after)),
            )
            for c in changes
        ]
        write_backup(self._root, backup_dir, entries)
        written: list[BackupEntry] = []
        try:
            for change, entry in zip(changes, entries, strict=True):
                self._write(confine(self._root, change.rel_path), encode(change.after))
                written.append(entry)
        except OSError as exc:
            logger.error("Patch write failed, rolling back %d file(s): %s", len(written), exc)
            restore(self._root, backup_dir, written)
            raise PatchError(
                ErrorCode.WRITE_FAILED,
                f"Writing the fix failed ({exc}). Nothing was changed: all files were restored.",
            ) from exc
        return [c.rel_path for c in changes]

    def revert(self, backup_dir: Path, force: bool) -> list[str]:
        """Restore every file from the backup. Refuses if files changed since apply."""
        entries = read_manifest(backup_dir)
        if not force:
            current = self.current_hashes([e.rel_path for e in entries])
            if any(current[e.rel_path] != e.after_sha256 for e in entries):
                raise PatchError(
                    ErrorCode.FILES_CHANGED_SINCE_APPLY,
                    "These files were edited after the fix was applied. Reverting would lose "
                    "those edits; call revert_patch again with force=true to do it anyway.",
                )
        return restore(self._root, backup_dir, entries)
