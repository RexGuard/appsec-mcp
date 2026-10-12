"""Scan request and response models."""

from typing import Literal

from pydantic import Field

from appsec_mcp.models.base import PositiveId, ScannerName, StrictModel

ScanStatus = Literal["running", "completed", "failed", "partial"]
MAX_FILE_KB_LIMIT = 100 * 1024


class ScanRequest(StrictModel):
    """Input to scan_project."""

    path: str = Field(min_length=1)
    scanners: list[ScannerName] | None = None
    max_file_kb: int = Field(default=1024, ge=1, le=MAX_FILE_KB_LIMIT)


class SeverityCounts(StrictModel):
    """Number of open findings per severity."""

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)


class SkippedScanner(StrictModel):
    """A scanner that did not run, and how to get it running."""

    name: ScannerName
    reason: str
    install_hint: str


class ScannerRun(StrictModel):
    """A scanner that ran, for the ledger."""

    name: ScannerName
    version: str
    duration_s: float = Field(ge=0)
    findings: int = Field(default=0, ge=0)


class ScanResult(StrictModel):
    """Compact summary returned by scan_project."""

    scan_id: PositiveId
    project: str
    status: ScanStatus
    score: int = Field(ge=0, le=100)
    counts: SeverityCounts
    new: int = Field(ge=0)
    fixed: int = Field(ge=0)
    scanners_run: list[ScannerName]
    scanners_skipped: list[SkippedScanner]
    files_read: int = Field(ge=0)
    files_skipped: int = Field(ge=0)
    duration_s: float = Field(ge=0)


class ScanSummary(StrictModel):
    """One scan in a listing."""

    scan_id: PositiveId
    project: str
    root_path: str
    started_at: str
    status: ScanStatus
    score: int | None = Field(default=None, ge=0, le=100)
    counts: SeverityCounts


class ScanList(StrictModel):
    """Response of list_scans."""

    items: list[ScanSummary]
