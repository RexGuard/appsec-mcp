"""Recipe context and shared editing helpers."""

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Protocol

from appsec_mcp.patching.fixers.base import FixOutcome
from appsec_mcp.patching.textio import newline_of
from appsec_mcp.patching.workspace import Workspace

logger = logging.getLogger(__name__)

JS_LANGS = frozenset({"javascript", "typescript"})


@dataclass(frozen=True)
class AppFile:
    """A file that creates the web app object, and where."""

    rel_path: str
    line: int
    var: str
    language: str | None


@dataclass
class RecipeContext:
    """What a recipe needs: the workspace, read files and detected frameworks."""

    ws: Workspace
    files: list[tuple[str, str | None]]
    frameworks: set[str] = field(default_factory=set)

    def sources(self, languages: Iterable[str]) -> list[str]:
        """Read file paths in the given languages."""
        wanted = set(languages)
        return [rel for rel, lang in self.files if lang in wanted]

    def language_of(self, rel_path: str) -> str | None:
        """Language of a read file."""
        return next((lang for rel, lang in self.files if rel == rel_path), None)

    def find_app(self, pattern: re.Pattern[str], languages: Iterable[str]) -> AppFile | None:
        """First file whose text matches `pattern` (group 'var' = app variable)."""
        for rel in self.sources(languages):
            text = self.ws.read(rel) or ""
            match = pattern.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                return AppFile(rel, line, match.group("var"), self.language_of(rel))
        return None

    def any_text(self, pattern: re.Pattern[str], languages: Iterable[str]) -> bool:
        """True when any read file in `languages` matches."""
        return any(pattern.search(self.ws.read(rel) or "") for rel in self.sources(languages))


class Recipe(Protocol):
    """A hardening recipe."""

    id: str
    title: str
    description: str

    def check(self, ctx: RecipeContext) -> tuple[bool, str]:
        """Return (applicable, reason)."""
        ...

    def build(self, ctx: RecipeContext) -> FixOutcome:
        """Record the edits in ctx.ws and return a summary."""
        ...


EXPRESS_APP = re.compile(r"(?:const|let|var)\s+(?P<var>\w+)\s*=\s*express\(\s*\)\s*;?")
FLASK_APP = re.compile(r"^(?P<var>\w+)\s*=\s*Flask\([^\n]*\)\s*$", re.MULTILINE)
FASTAPI_APP = re.compile(r"^(?P<var>\w+)\s*=\s*FastAPI\([^\n]*\)\s*$", re.MULTILINE)
SPRING_APP = re.compile(r"@SpringBootApplication[\s\S]*?class\s+(?P<var>\w+)")


def insert_after_line(ws: Workspace, rel_path: str, line: int, block: list[str]) -> None:
    """Insert lines after 1-based `line`, using the file's newline style."""
    text = ws.read(rel_path) or ""
    newline = newline_of(text)
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += newline
    lines[line:line] = [f"{entry}{newline}" for entry in block]
    ws.write(rel_path, "".join(lines))


def add_js_import(ws: Workspace, rel_path: str, binding: str, module: str) -> int:
    """Add an import/require at the top if missing; return how many lines were added."""
    text = ws.read(rel_path) or ""
    if re.search(rf"[\"']{re.escape(module)}[\"']", text):
        return 0
    uses_esm = bool(re.search(r"^\s*import\s", text, re.MULTILINE))
    statement = (
        f'import {binding} from "{module}";'
        if uses_esm
        else f'const {binding} = require("{module}");'
    )
    last_import = 0
    for index, line in enumerate(text.splitlines(), start=1):
        if re.match(r"\s*(import\s|(const|let|var)\s+\w+\s*=\s*require\()", line):
            last_import = index
    insert_after_line(ws, rel_path, last_import, [statement])
    return 1


def add_npm_dependency(ws: Workspace, app_rel: str, name: str, version: str) -> None:
    """Add a dependency to the package.json next to (or above) the app file."""
    folder = PurePosixPath(app_rel).parent
    for candidate in [folder, *folder.parents]:
        rel = (candidate / "package.json").as_posix().removeprefix("./")
        text = ws.read(rel)
        if text is None:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Could not parse %s; not adding %s", rel, name)
            return
        deps = data.setdefault("dependencies", {})
        if name not in deps:
            deps[name] = version
            ws.write(rel, json.dumps(data, indent=2) + newline_of(text))
        return


def add_requirement(ws: Workspace, app_rel: str, requirement: str) -> None:
    """Add a line to requirements.txt next to the app file (creating it if needed)."""
    folder = PurePosixPath(app_rel).parent.as_posix()
    rel = "requirements.txt" if folder == "." else f"{folder}/requirements.txt"
    package = re.split(r"[=<>~!\[]", requirement, maxsplit=1)[0].lower()
    text = ws.read(rel) or ""
    if any(
        re.split(r"[=<>~!\[\s]", line.strip(), maxsplit=1)[0].lower() == package
        for line in text.splitlines()
    ):
        return
    ws.ensure_lines(rel, [requirement])
