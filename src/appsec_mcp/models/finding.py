"""Finding models: raw scanner output, stored findings and explanations."""

from pydantic import Field

from appsec_mcp.models.base import (
    EvidenceTier,
    FindingStatus,
    PositiveId,
    ScannerName,
    Severity,
    StrictModel,
)


class RawFinding(StrictModel):
    """A finding as a scanner adapter reports it, before normalising."""

    scanner: ScannerName
    rule_id: str = Field(min_length=1)
    severity: Severity
    cwe: str | None = None
    rel_path: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    snippet: str = ""
    message: str = ""
    fix_kind: str | None = None


class NormalizedFinding(StrictModel):
    """A deduplicated, redacted and explained finding ready to store."""

    fingerprint: str
    scanner: ScannerName
    rule_id: str
    severity: Severity
    cwe: str | None
    rel_path: str | None
    line_start: int | None
    line_end: int | None
    snippet_redacted: str
    title: str
    plain_explanation: str
    fix_hint: str
    fix_kind: str | None
    status: FindingStatus = "new"
    sources: list[ScannerName] = Field(default_factory=list)
    evidence_tier: EvidenceTier = "pattern"
    reported_severity: Severity | None = None
    evidence: list[str] = Field(default_factory=list)


class FindingItem(StrictModel):
    """One finding in a list."""

    id: PositiveId
    severity: Severity
    title: str
    rel_path: str | None
    line_start: int | None
    plain_explanation: str
    patchable: bool
    status: FindingStatus
    scanner: ScannerName
    cwe: str | None
    evidence_tier: EvidenceTier = "pattern"


class FindingList(StrictModel):
    """Response of get_findings."""

    total: int = Field(ge=0)
    items: list[FindingItem]


class FindingDetail(StrictModel):
    """Response of explain_finding."""

    id: PositiveId
    title: str
    severity: Severity
    cwe: str | None
    rel_path: str | None
    line_start: int | None
    scanner: ScannerName
    rule_id: str
    what: str
    why_it_matters: str
    how_to_fix: str
    snippet_redacted: str
    patchable: bool
    references: list[str]
    evidence_tier: EvidenceTier = "pattern"
    reported_severity: Severity | None = Field(
        default=None, description="The scanner's severity, when the evidence gate changed it."
    )
    evidence: list[str] = Field(default_factory=list)
