"""Shared model base and literal types."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
ScannerName = Literal["semgrep", "gitleaks", "osv", "builtin"]
FindingStatus = Literal["new", "existing", "fixed"]
# How strong the evidence behind a finding is, weakest first. See analysis/evidence_gate.py.
EvidenceTier = Literal["pattern", "reachable", "corroborated", "confirmed"]

SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
EVIDENCE_RANK: dict[str, int] = {"pattern": 1, "reachable": 2, "corroborated": 3, "confirmed": 4}

PositiveId = Annotated[int, Field(ge=1)]


class StrictModel(BaseModel):
    """Base model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid")


def severity_at_least(severity: str, minimum: str) -> bool:
    """True when `severity` is as severe as `minimum` or more."""
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[minimum]
