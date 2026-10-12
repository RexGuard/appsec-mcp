"""C/C++ extraction: main(), database and network libraries, CMake/vcpkg/conan deps."""

import json
import logging
import re
from pathlib import PurePosixPath

from appsec_mcp.mapper.facts import FileFacts
from appsec_mcp.scan.walker import SourceFile

logger = logging.getLogger(__name__)

_ENTRY = re.compile(r"\bint\s+(?:w?main|WinMain)\s*\(")
_INCLUDE = re.compile(r"#\s*include\s*[<\"]([^>\"]+)[>\"]")
_FIND_PACKAGE = re.compile(r"find_package\s*\(\s*(\w+)", re.IGNORECASE)
_HEADERS_STORES: dict[str, str] = {
    "sqlite3.h": "SQLite",
    "mysql.h": "MySQL",
    "libpq-fe.h": "PostgreSQL",
    "hiredis/hiredis.h": "Redis",
}
_HEADERS_SERVICES: dict[str, str] = {
    "curl/curl.h": "HTTP client (libcurl)",
    "cpr/cpr.h": "HTTP client (cpr)",
}


def extract(source: SourceFile) -> FileFacts:
    """Extract facts from C/C++ sources and build manifests."""
    name = PurePosixPath(source.rel_path).name.lower()
    if name == "cmakelists.txt":
        return FileFacts(dependencies=_FIND_PACKAGE.findall(source.text))
    if name == "vcpkg.json":
        return _vcpkg(source)
    if name == "conanfile.txt":
        return _conan(source)
    facts = FileFacts()
    if _ENTRY.search(source.text):
        facts.entry_point = "has a main() function"
    for header in _INCLUDE.findall(source.text):
        if header in _HEADERS_STORES:
            facts.data_stores.add(_HEADERS_STORES[header])
        if header in _HEADERS_SERVICES:
            facts.external_services.add(_HEADERS_SERVICES[header])
    return facts


def _vcpkg(source: SourceFile) -> FileFacts:
    try:
        data = json.loads(source.text)
    except json.JSONDecodeError:
        logger.warning("Could not parse %s", source.rel_path)
        return FileFacts()
    deps = [d if isinstance(d, str) else str(d.get("name")) for d in data.get("dependencies", [])]
    return FileFacts(dependencies=deps)


def _conan(source: SourceFile) -> FileFacts:
    deps: list[str] = []
    in_requires = False
    for line in source.text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_requires = stripped == "[requires]"
        elif in_requires and stripped:
            deps.append(stripped.replace("/", "@", 1))
    return FileFacts(dependencies=deps)
