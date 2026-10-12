"""get_findings and explain_finding."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, HttpUrl

from appsec_mcp.models.common import Id, Offset, RelPath, Severity, StrictModel

FindingStatus = Literal["new", "existing", "fixed"]


class GetFindingsRequest(StrictModel):
    scan_id: Id
    min_severity: Severity = "low"
    limit: int = Field(default=50, ge=1, le=500)
    offset: Offset = 0


class FindingSummary(StrictModel):
    id: Id
    severity: Severity
    title: str = Field(min_length=1)
    rel_path: RelPath | None = None
    line_start: int | None = Field(default=None, ge=1)
    plain_explanation: str = Field(min_length=1)
    patchable: bool
    status: FindingStatus


class GetFindingsResponse(StrictModel):
    total: int = Field(ge=0)
    items: list[FindingSummary]


class ExplainFindingRequest(StrictModel):
    finding_id: Id


class FindingDetail(StrictModel):
    id: Id
    title: str = Field(min_length=1)
    severity: Severity
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    what: str = Field(min_length=1, description="What the problem is, in plain language.")
    why_it_matters: str = Field(min_length=1)
    how_to_fix: str = Field(min_length=1)
    snippet_redacted: str | None = None
    references: list[HttpUrl] = Field(default_factory=list)
