"""The scanner adapter interface every scanner implements."""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from appsec_mcp.models.base import ScannerName
from appsec_mcp.models.finding import RawFinding
from appsec_mcp.models.ledger import RuleApplied
from appsec_mcp.scan.walker import SourceFile


@dataclass
class AdapterResult:
    """What one scanner run produced."""

    findings: list[RawFinding] = field(default_factory=list)
    rules: list[RuleApplied] = field(default_factory=list)


class ScannerAdapter(Protocol):
    """A scanner the scan service can run. Implementations must never raise on missing tools."""

    name: ScannerName
    install_hint: str

    def is_available(self) -> bool:
        """True when the scanner can run on this machine."""
        ...

    def version(self) -> str:
        """The scanner version string, or 'unknown'."""
        ...

    def run(self, root: Path, files: Sequence[SourceFile]) -> AdapterResult:
        """Scan `files` under `root`. May raise ScannerError on failure."""
        ...


def count_rule_matches(
    scanner: ScannerName, version: str, findings: Sequence[RawFinding], rule_ids: Sequence[str]
) -> list[RuleApplied]:
    """Build ledger rows: every applied rule with the number of distinct files it matched."""
    matched: dict[str, set[str]] = {rule_id: set() for rule_id in rule_ids}
    for finding in findings:
        matched.setdefault(finding.rule_id, set()).add(finding.rel_path or "")
    return [
        RuleApplied(
            scanner=scanner, rule_id=rule_id, scanner_version=version, files_matched=len(paths)
        )
        for rule_id, paths in sorted(matched.items())
    ]
