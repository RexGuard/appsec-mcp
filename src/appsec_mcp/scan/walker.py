"""A lazy, root-confined file walker that accounts for every file it sees.

Each entry under the scan root is yielded exactly once as either a `WalkedFile` (read) or a
`SkippedEntry` with a reason. A skipped folder stands for everything inside it, so together the
entries account for 100% of the tree. Work is O(n) in the number of entries; folders that are
skipped are never descended into.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pathspec

from appsec_mcp.scan.language import detect_language, looks_binary
from appsec_mcp.security.paths import is_within

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "bower_components", "build", "dist", "out", "target",
        "venv", ".venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        ".tox", ".next", ".nuxt", ".gradle", ".idea", ".vscode", "vendor", "coverage",
    }
)  # fmt: skip

_HEAD = 8192


@dataclass(frozen=True)
class WalkedFile:
    rel_path: str  # POSIX separators, relative to the root
    path: Path
    language: str | None
    size_bytes: int
    sha256: str
    text: str


@dataclass(frozen=True)
class SkippedEntry:
    rel_path: str  # folders end with "/"
    reason: str  # gitignored | too_large | binary | excluded_dir | symlink_outside_root
    size_bytes: int | None = None


WalkEntry = WalkedFile | SkippedEntry


class _IgnoreRules:
    """Stacked .gitignore files: each applies to paths below the folder that holds it."""

    def __init__(self) -> None:
        self._specs: list[tuple[str, pathspec.GitIgnoreSpec]] = []

    def push(self, rel_dir: str, gitignore: Path) -> bool:
        try:
            lines = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return False
        self._specs.append((rel_dir, pathspec.GitIgnoreSpec.from_lines(lines)))
        return True

    def pop(self) -> None:
        self._specs.pop()

    def ignored(self, rel_path: str, is_dir: bool) -> bool:
        for base, spec in self._specs:
            sub = rel_path[len(base) + 1 :] if base else rel_path
            if spec.match_file(sub + "/" if is_dir else sub):
                return True
        return False


def walk(
    root: Path, max_file_kb: int = 1024, excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS
) -> Iterator[WalkEntry]:
    """Yield every entry under an already-validated, resolved `root`."""
    rules = _IgnoreRules()
    yield from _walk_dir(root, root, "", rules, max_file_kb * 1024, excluded_dirs)


def _walk_dir(
    root: Path, folder: Path, rel_dir: str, rules: _IgnoreRules, max_bytes: int, excluded: frozenset[str]
) -> Iterator[WalkEntry]:
    pushed = rules.push(rel_dir, folder / ".gitignore") if (folder / ".gitignore").is_file() else False
    try:
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            try:
                is_link = entry.is_symlink()
                is_dir = entry.is_dir(follow_symlinks=True)
            except OSError:
                continue
            if is_link:
                try:
                    target = Path(entry.path).resolve(strict=True)
                except (OSError, RuntimeError):
                    yield SkippedEntry(rel + ("/" if is_dir else ""), "symlink_outside_root")
                    continue
                if not is_within(root, target):
                    yield SkippedEntry(rel + ("/" if is_dir else ""), "symlink_outside_root")
                    continue
                if is_dir:
                    # Points back into the project: its files are walked at their real location.
                    yield SkippedEntry(rel + "/", "excluded_dir")
                    continue
            if is_dir:
                if entry.name in excluded:
                    yield SkippedEntry(rel + "/", "excluded_dir")
                elif rules.ignored(rel, is_dir=True):
                    yield SkippedEntry(rel + "/", "gitignored")
                else:
                    yield from _walk_dir(root, Path(entry.path), rel, rules, max_bytes, excluded)
                continue
            if not entry.is_file(follow_symlinks=True):
                continue  # sockets, FIFOs, devices: not source code
            yield _file_entry(Path(entry.path), rel, rules, max_bytes)
    finally:
        if pushed:
            rules.pop()


def _file_entry(path: Path, rel: str, rules: _IgnoreRules, max_bytes: int) -> WalkEntry:
    try:
        size = path.stat().st_size
    except OSError:
        size = None
    if rules.ignored(rel, is_dir=False):
        return SkippedEntry(rel, "gitignored", size)
    if size is not None and size > max_bytes:
        return SkippedEntry(rel, "too_large", size)
    try:
        data = path.read_bytes()
    except OSError:
        return SkippedEntry(rel, "binary", size)
    if looks_binary(rel, data[:_HEAD]):
        return SkippedEntry(rel, "binary", len(data))
    return WalkedFile(
        rel_path=rel,
        path=path,
        language=detect_language(rel),
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        text=data.decode("utf-8", errors="replace"),
    )
