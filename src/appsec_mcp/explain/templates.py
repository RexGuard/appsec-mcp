"""Plain-language explanations built from the curated catalog. No LLM call is needed."""

from dataclasses import dataclass
from functools import cache
from importlib import resources

import yaml

from appsec_mcp.models.finding import RawFinding

MAX_WORDS = 120
_DEFAULT_KEY = "default"


@dataclass(frozen=True)
class CatalogEntry:
    """Curated wording for one CWE."""

    title: str
    what: str
    why: str
    fix: str
    references: tuple[str, ...]


@dataclass(frozen=True)
class Explanation:
    """Everything a user sees about one finding."""

    title: str
    plain: str
    what: str
    why: str
    how_to_fix: str
    references: tuple[str, ...]


@cache
def load_catalog() -> dict[str, CatalogEntry]:
    """Load and cache the bundled catalog."""
    text = (resources.files("appsec_mcp.explain") / "catalog.yml").read_text(encoding="utf-8")
    raw: dict[str, dict[str, object]] = yaml.safe_load(text)
    return {
        key: CatalogEntry(
            title=str(value["title"]),
            what=str(value["what"]),
            why=str(value["why"]),
            fix=str(value["fix"]),
            references=tuple(str(r) for r in value["references"]),  # type: ignore[attr-defined]
        )
        for key, value in raw.items()
    }


def truncate_words(text: str, limit: int = MAX_WORDS) -> str:
    """Cut text to at most `limit` words, ending with an ellipsis when cut."""
    words = text.split()
    if len(words) <= limit:
        return " ".join(words)
    return " ".join(words[: limit - 1]) + " …"


def explain(finding: RawFinding) -> Explanation:
    """Build the explanation for a raw finding."""
    catalog = load_catalog()
    entry = catalog.get(finding.cwe or "", catalog[_DEFAULT_KEY])
    location = _location(finding)
    specific = finding.message.strip().rstrip(".") if finding.message else entry.what.rstrip(".")
    plain = truncate_words(f"{specific}{location}. {entry.why}")
    what = truncate_words(f"{entry.what} {specific}.")
    return Explanation(
        title=_title(entry, finding),
        plain=plain,
        what=what,
        why=entry.why,
        how_to_fix=entry.fix,
        references=entry.references,
    )


def _title(entry: CatalogEntry, finding: RawFinding) -> str:
    if finding.scanner == "osv" and finding.snippet:
        return f"{entry.title}: {finding.snippet.split()[-1]}"
    return entry.title


def _location(finding: RawFinding) -> str:
    if finding.rel_path and finding.line_start:
        return f" (in {finding.rel_path}, line {finding.line_start})"
    if finding.rel_path:
        return f" (in {finding.rel_path})"
    return ""
