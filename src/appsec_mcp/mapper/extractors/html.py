"""HTML extraction: pages as entry points and third-party script/style hosts."""

import re
from pathlib import PurePosixPath

from appsec_mcp.mapper.facts import FileFacts
from appsec_mcp.scan.walker import SourceFile

_EXTERNAL = re.compile(
    r"<(?:script|link|iframe)\b[^>]*\b(?:src|href)\s*=\s*[\"'](https?://[^/\"']+)", re.IGNORECASE
)
_FETCH_HOST = re.compile(r"\bfetch\s*\(\s*[\"'`](https?://[^/\"'`]+)")
_ENTRY_NAMES = frozenset({"index.html", "index.htm"})


def extract(source: SourceFile) -> FileFacts:
    """Extract facts from an HTML page."""
    facts = FileFacts()
    if PurePosixPath(source.rel_path).name.lower() in _ENTRY_NAMES:
        facts.entry_point = "web page served to visitors"
    facts.external_services.update(_EXTERNAL.findall(source.text))
    facts.external_services.update(_FETCH_HOST.findall(source.text))
    return facts
