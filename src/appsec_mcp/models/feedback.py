"""False-positive feedback models."""

from pydantic import Field

from appsec_mcp.models.base import StrictModel


class FeedbackResult(StrictModel):
    """Response of mark_false_positive and unmark_false_positive."""

    finding_id: int = Field(ge=1)
    title: str
    rel_path: str | None
    suppressed: bool
    message: str


class Suppression(StrictModel):
    """A finding hidden from future scans because the user rejected it."""

    title: str
    rel_path: str | None
    reason: str
    created_at: str


class SuppressionList(StrictModel):
    """Response of list_false_positives."""

    project: str
    items: list[Suppression]
