"""Attack chain models: how several findings and parts of the app line up into one attack path."""

from typing import Literal

from pydantic import Field

from appsec_mcp.models.base import EvidenceTier, PositiveId, Severity, StrictModel

ChainKind = Literal["input_to_injection", "secret_to_service", "vulnerable_dependency"]
ChainConfidence = Literal["hypothesis", "likely", "verified"]
StepKind = Literal["entry", "weakness", "asset"]


class ChainStep(StrictModel):
    """One hop of a chain: where an attacker gets in, the weakness used, or what is hit."""

    kind: StepKind
    label: str
    rel_path: str | None = None
    finding_id: PositiveId | None = None
    evidence_tier: EvidenceTier | None = None


class AttackChain(StrictModel):
    """A multi-hop path from outside the app to something worth protecting."""

    id: PositiveId
    kind: ChainKind
    title: str
    severity: Severity
    confidence: ChainConfidence
    narrative: str
    steps: list[ChainStep] = Field(min_length=2)


class AttackChainList(StrictModel):
    """Response of get_attack_chains."""

    total: int = Field(ge=0)
    items: list[AttackChain]
