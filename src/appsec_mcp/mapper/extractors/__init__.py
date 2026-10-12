"""Per-language extractors. Each exposes `extract(source) -> FileFacts`."""

from collections.abc import Callable
from pathlib import PurePosixPath

from appsec_mcp.mapper.extractors import cpp, html, java, js_ts, python
from appsec_mcp.mapper.facts import FileFacts
from appsec_mcp.scan.walker import SourceFile

Extractor = Callable[[SourceFile], FileFacts]

_BY_LANGUAGE: dict[str, Extractor] = {
    "javascript": js_ts.extract,
    "typescript": js_ts.extract,
    "npm": js_ts.extract,
    "python": python.extract,
    "requirements": python.extract,
    "java": java.extract,
    "kotlin": java.extract,
    "maven": java.extract,
    "c": cpp.extract,
    "cpp": cpp.extract,
    "cmake": cpp.extract,
    "html": html.extract,
}
_BY_NAME: dict[str, Extractor] = {
    "vcpkg.json": cpp.extract,
    "conanfile.txt": cpp.extract,
    "build.gradle": java.extract,
    "build.gradle.kts": java.extract,
}


def extractor_for(source: SourceFile) -> Extractor | None:
    """Pick the extractor for a file, or None when the language is unsupported."""
    by_name = _BY_NAME.get(PurePosixPath(source.rel_path).name.lower())
    if by_name:
        return by_name
    return _BY_LANGUAGE.get(source.language or "")
