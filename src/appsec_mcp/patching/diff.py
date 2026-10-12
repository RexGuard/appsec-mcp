"""Unified diffs for proposals."""

import difflib
from collections.abc import Sequence

from appsec_mcp.models.patch import FileChange


def unified_diff(changes: Sequence[FileChange]) -> str:
    """One unified diff covering every changed or created file."""
    parts: list[str] = []
    for change in changes:
        before = (change.before or "").splitlines(keepends=True)
        after = change.after.splitlines(keepends=True)
        from_name = "/dev/null" if change.before is None else f"a/{change.rel_path}"
        lines = difflib.unified_diff(
            before, after, fromfile=from_name, tofile=f"b/{change.rel_path}", n=3
        )
        parts.extend(line if line.endswith("\n") else f"{line}\n" for line in lines)
    return "".join(parts).replace("\r\n", "\n")
