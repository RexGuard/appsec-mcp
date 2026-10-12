"""scan_project and list_scans."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from appsec_mcp.models.common import Id, ScannerName, StrictModel

ScanStatus = Literal["running", "completed", "failed", "partial"]
Score = Annotated[int, Field(ge=0, le=100)]
Count = Annotated[int, Field(ge=0)]


class ScanProjectRequest(StrictModel):
    path: str = Field(min_length=1, max_length=4096, description="Project folder to scan.")
    scanners: list[ScannerName] | None = Field(
        default=None, description="Scanners to run. Default: every scanner that is installed."
    )
    max_file_kb: int = Field(default=1024, ge=1, le=102_400, description="Skip files larger than this.")

    @model_validator(mode="after")
    def _unique_scanners(self) -> ScanProjectRequest:
        if self.scanners is not None and len(set(self.scanners)) != len(self.scanners):
            raise ValueError("scanners must not repeat")
        return self


class SeverityCounts(StrictModel):
    critical: Count = 0
    high: Count = 0
    medium: Count = 0
    low: Count = 0
    info: Count = 0


class SkippedScanner(StrictModel):
    name: ScannerName
    reason: str = Field(min_length=1)
    install_hint: str = ""


class ScanProjectResponse(StrictModel):
    scan_id: Id
    status: ScanStatus
    score: Score
    counts: SeverityCounts
    new: Count = Field(description="Findings not present in the previous scan of this project.")
    fixed: Count = Field(description="Findings from the previous scan that are gone now.")
    scanners_run: list[ScannerName]
    scanners_skipped: list[SkippedScanner]
    files_read: Count
    files_skipped: Count
    duration_s: float = Field(ge=0)


class ListScansRequest(StrictModel):
    project_path: str | None = Field(default=None, max_length=4096)
    limit: int = Field(default=20, ge=1, le=200)


class ScanListItem(StrictModel):
    scan_id: Id
    project: str
    started_at: str
    score: Score | None = None
    counts: SeverityCounts


class ListScansResponse(StrictModel):
    items: list[ScanListItem]


class ScanSummary(ScanProjectResponse):
    """One scan as the viewer's HTTP API serves it (`GET /api/scans/{id}`)."""

    project: str = Field(min_length=1)
    started_at: str
