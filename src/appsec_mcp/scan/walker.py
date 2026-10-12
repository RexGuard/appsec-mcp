"""A lazy, root-confined file walker that records every path in the audit ledger."""

import hashlib
import logging
import os
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pathspec

from appsec_mcp.models.ledger import LedgerFile, SkipReason
from appsec_mcp.scan.language import detect_language
from appsec_mcp.security.paths import is_inside

logger = logging.getLogger(__name__)

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "build",
        "dist",
        "venv",
        ".venv",
        "target",
        "__pycache__",
        ".next",
        ".nuxt",
        ".gradle",
        ".idea",
        ".vscode",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "coverage",
        ".tox",
        "out",
        "bin",
        "obj",
        "vendor",
    }
)
_BINARY_SNIFF_BYTES = 8192
_READ_WORKERS = 8


@dataclass(frozen=True)
class SourceFile:
    """A file that was read: its text is kept for scanners and the mapper."""

    rel_path: str
    abs_path: Path
    language: str | None
    size_bytes: int
    sha256: str
    text: str


@dataclass(frozen=True)
class WalkEvent:
    """One walker result: a ledger entry, plus the file content when it was read."""

    ledger: LedgerFile
    source: SourceFile | None = None


class _IgnoreRules:
    """Stack of .gitignore specs, each anchored at the folder that defined it."""

    def __init__(self) -> None:
        self._specs: list[tuple[str, pathspec.PathSpec]] = []

    def load(self, folder: Path, rel_folder: str) -> int:
        """Load `folder/.gitignore` if present; return how many specs were pushed (0 or 1)."""
        gitignore = folder / ".gitignore"
        if not gitignore.is_file():
            return 0
        try:
            lines = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            logger.warning("Could not read %s", gitignore)
            return 0
        self._specs.append((rel_folder, pathspec.PathSpec.from_lines("gitignore", lines)))
        return 1

    def pop(self, count: int) -> None:
        """Drop the last `count` specs when leaving a folder."""
        for _ in range(count):
            self._specs.pop()

    def matches(self, rel_path: str, is_dir: bool) -> bool:
        """True when any active .gitignore excludes `rel_path`."""
        for base, spec in self._specs:
            local = rel_path[len(base) + 1 :] if base else rel_path
            if spec.match_file(f"{local}/" if is_dir else local):
                return True
        return False


def _skip(rel_path: str, reason: SkipReason, size: int | None = None) -> WalkEvent:
    return WalkEvent(
        LedgerFile(
            rel_path=rel_path,
            status="skipped",
            skip_reason=reason,
            size_bytes=size,
            language=detect_language(rel_path),
        )
    )


def _read_file(path: Path, rel_path: str, size: int, max_bytes: int) -> WalkEvent:
    if size > max_bytes:
        return _skip(rel_path, "too_large", size)
    try:
        data = path.read_bytes()
    except OSError:
        logger.warning("Could not read %s", rel_path)
        return _skip(rel_path, "unreadable")
    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        return _skip(rel_path, "binary", size)
    digest = hashlib.sha256(data).hexdigest()
    language = detect_language(rel_path)
    source = SourceFile(
        rel_path, path, language, len(data), digest, data.decode("utf-8", errors="replace")
    )
    ledger = LedgerFile(
        rel_path=rel_path, language=language, size_bytes=len(data), sha256=digest, status="read"
    )
    return WalkEvent(ledger, source)


def walk(root: Path, max_file_bytes: int) -> Iterator[WalkEvent]:
    """Yield one event per path under `root`, depth first, in sorted order.

    O(n) in the number of paths. Files of each folder are read in parallel (first reads are
    dominated by antivirus and disk latency), but events still come out in sorted order.
    Excluded and ignored folders are recorded once and not descended into. Symlinks are never
    followed out of the root, and symlinked folders are not followed at all (to avoid cycles).
    """
    root = root.resolve()
    with ThreadPoolExecutor(max_workers=_READ_WORKERS) as pool:
        walker = _Walker(root, max_file_bytes, pool)
        yield from walker.walk_dir(root, "")


class _Walker:
    """Depth-first traversal state for one walk."""

    def __init__(self, root: Path, max_bytes: int, pool: ThreadPoolExecutor) -> None:
        self.root = root
        self.max_bytes = max_bytes
        self.pool = pool
        self.rules = _IgnoreRules()

    def walk_dir(self, folder: Path, rel_folder: str) -> Iterator[WalkEvent]:
        """Yield events for one folder, recursing into sub-folders in sorted order."""
        pushed = self.rules.load(folder, rel_folder)
        try:
            with os.scandir(folder) as iterator:
                entries = sorted(iterator, key=lambda e: e.name)
        except OSError:
            logger.warning("Could not list %s", folder)
            self.rules.pop(pushed)
            yield _skip(rel_folder or ".", "unreadable")
            return
        planned = [
            self._plan(entry, f"{rel_folder}/{entry.name}" if rel_folder else entry.name)
            for entry in entries
        ]
        for item in planned:
            if isinstance(item, Future):
                yield item.result()
            elif isinstance(item, WalkEvent):
                yield item
            else:
                yield from self.walk_dir(*item)
        self.rules.pop(pushed)

    def _plan(
        self, entry: os.DirEntry[str], rel_path: str
    ) -> "WalkEvent | Future[WalkEvent] | tuple[Path, str]":
        """Classify an entry: a ready event, a pending file read, or a folder to descend."""
        path = Path(entry.path)
        try:
            if entry.is_symlink():
                return self._plan_symlink(path, rel_path)
            is_dir = entry.is_dir(follow_symlinks=False)
            size = 0 if is_dir else entry.stat(follow_symlinks=False).st_size
        except OSError:
            logger.warning("Could not stat %s", rel_path)
            return _skip(rel_path, "unreadable")
        if is_dir and entry.name in DEFAULT_EXCLUDED_DIRS:
            return _skip(rel_path, "excluded_dir")
        if self.rules.matches(rel_path, is_dir):
            return _skip(rel_path, "gitignored")
        if is_dir:
            return (path, rel_path)
        return self.pool.submit(_read_file, path, rel_path, size, self.max_bytes)

    def _plan_symlink(self, path: Path, rel_path: str) -> "WalkEvent | Future[WalkEvent]":
        if not is_inside(self.root, path):
            return _skip(rel_path, "symlink_outside_root")
        if path.is_dir():
            return _skip(rel_path, "symlink_dir")
        return self.pool.submit(_read_file, path, rel_path, path.stat().st_size, self.max_bytes)
