"""Shared types and source-editing helpers for fixers."""

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from appsec_mcp.patching.textio import newline_of
from appsec_mcp.patching.workspace import Workspace


@dataclass(frozen=True)
class FixTarget:
    """Where to fix: one line of one file."""

    rel_path: str
    line: int
    language: str | None


@dataclass(frozen=True)
class FixOutcome:
    """A fixer's plain-language summary. The edits live in the Workspace."""

    summary: str


def base_dir(rel_path: str) -> str:
    """Folder of a file, '' for the root."""
    parent = PurePosixPath(rel_path).parent.as_posix()
    return "" if parent == "." else parent


def replace_line(
    ws: Workspace, target: FixTarget, pattern: re.Pattern[str], replacement: str
) -> bool:
    """Apply `pattern.sub(replacement)` once on the target line. Returns True when it changed."""
    text = ws.read(target.rel_path)
    if text is None:
        return False
    lines = text.splitlines(keepends=True)
    index = target.line - 1
    if not 0 <= index < len(lines):
        return False
    new_line, count = pattern.subn(replacement, lines[index], count=1)
    if count == 0:
        return False
    lines[index] = new_line
    ws.write(target.rel_path, "".join(lines))
    return True


def ensure_python_import(ws: Workspace, rel_path: str, statement: str = "import os") -> None:
    """Add an import after any shebang, docstring or __future__ imports if missing."""
    text = ws.read(rel_path) or ""
    if re.search(rf"^{re.escape(statement)}\s*$", text, re.MULTILINE):
        return
    lines = text.splitlines(keepends=True)
    newline = newline_of(text)
    insert_at = 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if index == 0 and stripped.startswith("#!"):
            insert_at = 1
        elif stripped.startswith("from __future__"):
            insert_at = index + 1
    lines.insert(insert_at, f"{statement}{newline}")
    ws.write(rel_path, "".join(lines))


def ensure_c_include(ws: Workspace, rel_path: str, language: str | None) -> None:
    """Make sure the header for snprintf/fgets is included."""
    text = ws.read(rel_path) or ""
    if re.search(r"#\s*include\s*<(?:cstdio|stdio\.h)>", text):
        return
    header = "#include <cstdio>" if language == "cpp" else "#include <stdio.h>"
    ws.write(rel_path, f"{header}{newline_of(text)}{text}")


def env_name(variable: str | None, default: str) -> str:
    """UPPER_SNAKE environment variable name from a code identifier."""
    if not variable:
        return default
    snake = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", variable).upper()
    snake = re.sub(r"[^A-Z0-9_]", "_", snake).strip("_")
    return snake or default
