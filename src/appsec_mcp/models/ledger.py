"""Audit ledger models: exactly what was read, skipped and checked."""

from typing import Literal

from pydantic import Field

from appsec_mcp.models.base import ScannerName, StrictModel
from appsec_mcp.models.scan import ScannerRun, SkippedScanner

FileStatus = Literal["read", "skipped"]
SkipReason = Literal[
    "gitignored",
    "too_large",
    "binary",
    "excluded_dir",
    "symlink_outside_root",
    "symlink_dir",
    "unreadable",
]


class LedgerFile(StrictModel):
    """One path the walker saw."""

    rel_path: str
    language: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    sha256: str | None = None
    status: FileStatus
    skip_reason: SkipReason | None = None


class RuleApplied(StrictModel):
    """One rule a scanner applied, and on how many files it matched."""

    scanner: ScannerName
    rule_id: str
    scanner_version: str | None = None
    files_matched: int = Field(default=0, ge=0)


class LedgerFiles(StrictModel):
    """Paged file entries plus totals."""

    read: int = Field(ge=0)
    skipped: int = Field(ge=0)
    items: list[LedgerFile]


class Ledger(StrictModel):
    """Response of get_audit_ledger."""

    files: LedgerFiles | None = None
    rules: list[RuleApplied] | None = None
    scanners: list[ScannerRun]
    scanners_skipped: list[SkippedScanner]
