"""get_audit_ledger: exactly what was read, skipped and checked."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from appsec_mcp.models.common import Id, Offset, RelPath, ScannerName, Sha256, StrictModel

SkipReason = Literal["gitignored", "too_large", "binary", "excluded_dir", "symlink_outside_root"]


class GetAuditLedgerRequest(StrictModel):
    scan_id: Id
    section: Literal["files", "rules", "all"] = "all"
    limit: int = Field(default=200, ge=1, le=5000)
    offset: Offset = 0


class LedgerFile(StrictModel):
    rel_path: RelPath
    language: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    sha256: Sha256 | None = None
    status: Literal["read", "skipped"]
    skip_reason: SkipReason | None = None

    @model_validator(mode="after")
    def _reason_matches_status(self) -> LedgerFile:
        if self.status == "skipped" and self.skip_reason is None:
            raise ValueError("a skipped file needs a skip_reason")
        if self.status == "read" and self.skip_reason is not None:
            raise ValueError("a read file has no skip_reason")
        if self.status == "read" and self.sha256 is None:
            raise ValueError("a read file needs its sha256")
        return self


class LedgerFiles(StrictModel):
    read: int = Field(ge=0)
    skipped: int = Field(ge=0)
    items: list[LedgerFile]


class RuleApplied(StrictModel):
    scanner: ScannerName
    rule_id: str = Field(min_length=1)
    files_matched: int = Field(ge=0)


class ScannerRun(StrictModel):
    name: ScannerName
    version: str | None = None
    duration_s: float = Field(ge=0)


class AuditLedger(StrictModel):
    files: LedgerFiles | None = None
    rules: list[RuleApplied] | None = None
    scanners: list[ScannerRun] = Field(default_factory=list)
