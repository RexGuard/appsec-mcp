"""The audit ledger: what a scan read, what it skipped and why."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from appsec_mcp.scan.walker import WalkedFile, WalkEntry
from appsec_mcp.storage.scan_repo import FileRecord


@dataclass
class Ledger:
    files: list[FileRecord] = field(default_factory=list)
    read: int = 0
    skipped: int = 0

    def record(self, entry: WalkEntry) -> None:
        if isinstance(entry, WalkedFile):
            self.read += 1
            self.files.append(
                FileRecord(
                    rel_path=entry.rel_path,
                    status="read",
                    language=entry.language,
                    size_bytes=entry.size_bytes,
                    sha256=entry.sha256,
                )
            )
        else:
            self.skipped += 1
            self.files.append(
                FileRecord(
                    rel_path=entry.rel_path, status="skipped", size_bytes=entry.size_bytes, skip_reason=entry.reason
                )
            )

    def track(self, entries: Iterable[WalkEntry]) -> Iterator[WalkedFile]:
        """Record every entry and pass the readable files through, keeping the walk lazy."""
        for entry in entries:
            self.record(entry)
            if isinstance(entry, WalkedFile):
                yield entry

    def accounts_for(self, rel_path: str) -> bool:
        """True when the file is in the ledger itself or under a folder the ledger skipped."""
        for rec in self.files:
            if rec.rel_path == rel_path:
                return True
            if rec.rel_path.endswith("/") and rel_path.startswith(rec.rel_path):
                return True
        return False
