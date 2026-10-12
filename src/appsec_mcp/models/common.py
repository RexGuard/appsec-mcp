"""Shared types: severities, scanner names, ids, and the strict base model."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
ScannerName = Literal["semgrep", "gitleaks", "osv", "builtin"]

SEVERITY_ORDER: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

Id = Annotated[int, Field(ge=1, description="Database id (1 or more).")]
Offset = Annotated[int, Field(ge=0, le=1_000_000)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
RelPath = Annotated[str, Field(min_length=1, max_length=4096, description="Path relative to the scan root.")]


def severity_at_least(severity: str, floor: str) -> bool:
    """True when `severity` is at or above `floor`."""
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[floor]


class StrictModel(BaseModel):
    """Rejects unknown fields so typos in tool calls fail loudly instead of being ignored."""

    model_config = ConfigDict(extra="forbid", frozen=False, str_strip_whitespace=False)
