"""Normalise raw findings: redact, explain, fingerprint and deduplicate."""

import hashlib
import re
from collections.abc import Iterable

from appsec_mcp.explain.templates import explain
from appsec_mcp.models.base import SEVERITY_RANK
from appsec_mcp.models.finding import NormalizedFinding, RawFinding
from appsec_mcp.security.redact import redact_text

_WHITESPACE = re.compile(r"\s+")
_MAX_SNIPPET_CHARS = 400


def fingerprint(rule_key: str, rel_path: str | None, snippet: str) -> str:
    """Stable id for diffing across scans: survives line moves, changes when the code changes."""
    normalized = _WHITESPACE.sub(" ", snippet).strip()
    data = f"{rule_key}\x1f{rel_path or ''}\x1f{normalized}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _dedupe_key(raw: RawFinding) -> tuple[str, int, str]:
    return (raw.rel_path or "", raw.line_start or 0, raw.cwe or raw.rule_id)


def normalize(raws: Iterable[RawFinding]) -> list[NormalizedFinding]:
    """Deduplicate by (file, line, CWE), keeping the most severe; O(n) over findings."""
    best: dict[tuple[str, int, str], RawFinding] = {}
    for raw in raws:
        key = _dedupe_key(raw)
        current = best.get(key)
        if current is None or _better(raw, current):
            best[key] = raw
    return [_to_normalized(raw) for raw in best.values()]


def _better(candidate: RawFinding, current: RawFinding) -> bool:
    if SEVERITY_RANK[candidate.severity] != SEVERITY_RANK[current.severity]:
        return SEVERITY_RANK[candidate.severity] > SEVERITY_RANK[current.severity]
    return candidate.fix_kind is not None and current.fix_kind is None


def _to_normalized(raw: RawFinding) -> NormalizedFinding:
    snippet = redact_text(raw.snippet)[:_MAX_SNIPPET_CHARS]
    redacted_raw = raw.model_copy(update={"snippet": snippet, "message": redact_text(raw.message)})
    explanation = explain(redacted_raw)
    return NormalizedFinding(
        fingerprint=fingerprint(raw.cwe or raw.rule_id, raw.rel_path, snippet),
        scanner=raw.scanner,
        rule_id=raw.rule_id,
        severity=raw.severity,
        cwe=raw.cwe,
        rel_path=raw.rel_path,
        line_start=raw.line_start,
        line_end=raw.line_end,
        snippet_redacted=snippet,
        title=explanation.title,
        plain_explanation=explanation.plain,
        fix_hint=explanation.how_to_fix,
        fix_kind=raw.fix_kind,
    )
