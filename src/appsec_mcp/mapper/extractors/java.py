"""Java extraction: Spring routes, JDBC stores, HTTP clients, Maven/Gradle deps."""

import re
from pathlib import PurePosixPath

from appsec_mcp.mapper.facts import FileFacts
from appsec_mcp.scan.walker import SourceFile

_CLASS_MAPPING = re.compile(
    r"@RequestMapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]+)\"[^)]*\)\s*"
    r"(?:@\w+(?:\([^)]*\))?\s*)*(?:public\s+)?class\b"
)
_METHOD_MAPPING = re.compile(
    r"@(Get|Post|Put|Delete|Patch|Request)Mapping(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?"
    r"\"([^\"]*)\")?"
)
_ENTRY = re.compile(r"public\s+static\s+void\s+main\s*\(")
_JDBC = re.compile(r"jdbc:(\w+)")
_HTTP_HOST = re.compile(r"\"(https?://[^/\"]+)")
_POM_DEP = re.compile(
    r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>"
    r"(?:\s*<version>([^<]+)</version>)?"
)
_GRADLE_DEP = re.compile(
    r"(?:implementation|api|compile|runtimeOnly)\s*\(?\s*[\"']([\w.\-]+):([\w.\-]+)(?::([\w.\-]+))?"
)


def extract(source: SourceFile) -> FileFacts:
    """Extract facts from a Java/Kotlin file, pom.xml or build.gradle."""
    name = PurePosixPath(source.rel_path).name
    if name == "pom.xml":
        return _deps(source, _POM_DEP)
    if name.startswith("build.gradle"):
        return _deps(source, _GRADLE_DEP)
    facts = FileFacts()
    text = source.text
    if _ENTRY.search(text):
        facts.entry_point = "has a main() method"
    prefix_match = _CLASS_MAPPING.search(text)
    prefix = prefix_match.group(1).rstrip("/") if prefix_match else ""
    for kind, path in _METHOD_MAPPING.findall(text):
        if prefix_match and kind == "Request" and path == prefix_match.group(1):
            continue
        method = "ANY" if kind == "Request" else kind.upper()
        facts.routes.append(f"{method} {f'{prefix}{path}' or '/'}")
        facts.frameworks.add("spring")
    if "DataSource" in text or "JdbcTemplate" in text:
        facts.data_stores.add("SQL database (JDBC)")
    for engine in _JDBC.findall(text):
        facts.data_stores.add(engine)
    if "RestTemplate" in text or "WebClient" in text or "HttpClient" in text:
        facts.external_services.update(_HTTP_HOST.findall(text))
    return facts


def _deps(source: SourceFile, pattern: re.Pattern[str]) -> FileFacts:
    facts = FileFacts()
    for group, artifact, version in pattern.findall(source.text):
        label = f"{group}:{artifact}"
        facts.dependencies.append(f"{label}@{version}" if version else label)
        if "spring-boot" in artifact:
            facts.frameworks.add("spring")
    return facts
