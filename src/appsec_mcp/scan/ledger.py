"""Collects walker events into the audit ledger and the list of files to scan."""

from collections.abc import Iterable
from dataclasses import dataclass, field

from appsec_mcp.models.ledger import LedgerFile
from appsec_mcp.scan.walker import SourceFile, WalkEvent


@dataclass
class LedgerCollector:
    """Accumulates ledger entries and readable source files in one O(n) pass."""

    entries: list[LedgerFile] = field(default_factory=list)
    sources: list[SourceFile] = field(default_factory=list)

    def consume(self, events: Iterable[WalkEvent]) -> "LedgerCollector":
        """Drain an event stream into the collector."""
        for event in events:
            self.entries.append(event.ledger)
            if event.source is not None:
                self.sources.append(event.source)
        return self

    @property
    def read_count(self) -> int:
        """Number of files read."""
        return sum(1 for e in self.entries if e.status == "read")

    @property
    def skipped_count(self) -> int:
        """Number of paths skipped."""
        return sum(1 for e in self.entries if e.status == "skipped")
