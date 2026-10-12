"""Security score (0-100) and severity counts."""

from collections import Counter
from collections.abc import Iterable

from appsec_mcp.models.scan import SeverityCounts

MAX_SCORE = 100
SEVERITY_PENALTY: dict[str, int] = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


def count_severities(severities: Iterable[str]) -> SeverityCounts:
    """Count findings per severity."""
    counts = Counter(severities)
    return SeverityCounts(**{name: counts.get(name, 0) for name in SEVERITY_PENALTY})


def score(counts: SeverityCounts) -> int:
    """100 minus a penalty per open finding, clamped to 0..100."""
    penalty = sum(getattr(counts, name) * weight for name, weight in SEVERITY_PENALTY.items())
    return max(0, MAX_SCORE - penalty)
