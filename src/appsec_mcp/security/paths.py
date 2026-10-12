"""Path confinement: validating the scan root and keeping every read and write inside it."""

from __future__ import annotations

import os
import sys
from pathlib import Path, PurePath

from appsec_mcp.errors import PathForbidden, PathNotDirectory, PathNotFound

# System folders that are never a project, together with everything under them.
_FORBIDDEN_TREES_POSIX = ("/etc", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys", "/System", "/Library")
_FORBIDDEN_TREES_WINDOWS = ("C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)")


def _forbidden_trees() -> list[Path]:
    names = _FORBIDDEN_TREES_WINDOWS if sys.platform == "win32" else _FORBIDDEN_TREES_POSIX
    windir = os.environ.get("SYSTEMROOT") if sys.platform == "win32" else None
    trees = [Path(n) for n in names]
    if windir:
        trees.append(Path(windir))
    return trees


def is_within(root: Path, path: Path) -> bool:
    """True when `path` is `root` or inside it. Both must already be resolved."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def resolve_scan_root(raw: str | os.PathLike[str]) -> Path:
    """Validate a user-supplied project folder and return it fully resolved.

    Raises PATH_NOT_FOUND, PATH_NOT_DIRECTORY or PATH_FORBIDDEN (filesystem root, the home folder
    itself, and system folders such as /etc, /usr and C:\\Windows).
    """
    text = os.fspath(raw).strip()
    if not text or "\x00" in text:
        raise PathNotFound("Give me the path of your project folder.")
    path = Path(text).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError):
        raise PathNotFound(f"I can't find the folder {text}.") from None
    except (OSError, RuntimeError):
        raise PathNotFound(f"I can't open the folder {text}.") from None
    if not resolved.is_dir():
        raise PathNotDirectory(f"{text} is a file. Point me at the folder that contains your project.")
    if resolved.parent == resolved:
        raise PathForbidden("That's the top of the whole drive. Point me at one project folder instead.")
    home = Path.home().resolve()
    if resolved == home:
        raise PathForbidden("That's your whole home folder. Point me at one project folder inside it.")
    for tree in _forbidden_trees():
        if _same_or_inside(resolved, tree):
            raise PathForbidden(f"{resolved} is a system folder, not a project. Point me at your project folder.")
    return resolved


def _same_or_inside(path: Path, tree: Path) -> bool:
    if sys.platform == "win32":
        p, t = PurePath(str(path).lower()), PurePath(str(tree).lower())
        return p == t or t in p.parents
    return path == tree or tree in path.parents


def confine(root: Path, rel_path: str) -> Path:
    """Resolve `rel_path` under `root`, refusing anything (.., absolute paths, symlinks) that escapes it."""
    candidate = (root / rel_path).resolve()
    if not is_within(root, candidate):
        raise PathForbidden(f"{rel_path} is outside the project folder.")
    return candidate
