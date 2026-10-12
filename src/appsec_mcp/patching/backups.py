"""Backups taken before a patch writes anything, and restoring from them."""

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from appsec_mcp.security.paths import confine

_MANIFEST = "manifest.json"
_FILES_DIR = "files"


@dataclass(frozen=True)
class BackupEntry:
    """One file covered by a backup."""

    rel_path: str
    existed: bool
    after_sha256: str


def write_backup(root: Path, backup_dir: Path, entries: list[BackupEntry]) -> None:
    """Copy every existing target file into `backup_dir` and write the manifest."""
    files_dir = backup_dir / _FILES_DIR
    files_dir.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        if entry.existed:
            target = files_dir / entry.rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(confine(root, entry.rel_path), target)
    manifest = [entry.__dict__ for entry in entries]
    (backup_dir / _MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def read_manifest(backup_dir: Path) -> list[BackupEntry]:
    """Load the manifest of a backup."""
    data = json.loads((backup_dir / _MANIFEST).read_text(encoding="utf-8"))
    return [BackupEntry(**item) for item in data]


def restore(root: Path, backup_dir: Path, entries: list[BackupEntry]) -> list[str]:
    """Put every file back exactly as it was; delete files the patch created."""
    restored: list[str] = []
    for entry in entries:
        target = confine(root, entry.rel_path)
        if entry.existed:
            target.write_bytes((backup_dir / _FILES_DIR / entry.rel_path).read_bytes())
        elif target.exists():
            target.unlink()
        restored.append(entry.rel_path)
    return restored
