"""Path confinement: resolve scan roots and keep every read and write inside them."""

import os
from pathlib import Path

from appsec_mcp.errors import ErrorCode, PathError

_FORBIDDEN_POSIX = ("/", "/etc", "/usr", "/bin", "/sbin", "/var", "/System", "/Library")


def _forbidden_roots() -> set[Path]:
    roots = {Path(p) for p in _FORBIDDEN_POSIX}
    roots.add(Path.home())
    system_root = os.environ.get("SYSTEMROOT")
    if system_root:
        roots.add(Path(system_root))
    for drive_root in (Path(Path.cwd().anchor), Path(Path.home().anchor)):
        roots.add(drive_root)
    return {r.resolve() for r in roots}


def _is_under(path: Path, ancestor: Path) -> bool:
    return path == ancestor or ancestor in path.parents


def resolve_scan_root(raw: str) -> Path:
    """Resolve and validate a scan root. Raises PathError with a plain-language message."""
    root = Path(raw).expanduser()
    if not root.exists():
        raise PathError(ErrorCode.PATH_NOT_FOUND, f"The folder '{raw}' does not exist.")
    root = root.resolve()
    if not root.is_dir():
        raise PathError(ErrorCode.PATH_NOT_DIRECTORY, f"'{raw}' is a file, not a folder.")
    if root in _forbidden_roots() or _is_system_dir(root):
        raise PathError(
            ErrorCode.PATH_FORBIDDEN,
            f"Scanning '{root}' is not allowed because it is a system or home folder. "
            "Point me at your project folder instead.",
        )
    return root


def _is_system_dir(root: Path) -> bool:
    system_root = os.environ.get("SYSTEMROOT")
    system_dirs = [Path(p).resolve() for p in ("/etc", "/usr")]
    if system_root:
        system_dirs.append(Path(system_root).resolve())
    return any(_is_under(root, d) for d in system_dirs)


def confine(root: Path, rel_path: str) -> Path:
    """Join `rel_path` onto `root` and refuse anything that escapes the root."""
    candidate = (root / rel_path).resolve()
    if not _is_under(candidate, root.resolve()):
        raise PathError(
            ErrorCode.PATH_OUTSIDE_ROOT, f"'{rel_path}' points outside the project folder."
        )
    return candidate


def is_inside(root: Path, path: Path) -> bool:
    """True when the resolved `path` is inside the resolved `root`."""
    return _is_under(path.resolve(), root.resolve())
