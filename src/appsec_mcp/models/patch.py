"""Patch and hardening recipe models."""

from typing import Literal

from pydantic import Field

from appsec_mcp.models.base import PositiveId, StrictModel

PatchStatus = Literal["proposed", "applied", "reverted", "expired"]


class PatchProposal(StrictModel):
    """Response of propose_patch and propose_hardening. Nothing is written yet."""

    patch_id: PositiveId
    proposal_token: str
    summary: str
    diff: str
    files: list[str]
    expires_at: str


class PatchApplied(StrictModel):
    """Response of apply_patch."""

    patch_id: PositiveId
    status: Literal["applied"] = "applied"
    files_changed: list[str]
    backup_dir: str


class PatchReverted(StrictModel):
    """Response of revert_patch."""

    patch_id: PositiveId
    status: Literal["reverted"] = "reverted"
    files_restored: list[str]


class Recipe(StrictModel):
    """A hardening recipe and whether it fits this project."""

    id: str
    title: str
    description: str
    applicable: bool
    reason: str


class RecipeList(StrictModel):
    """Response of list_recipes."""

    recipes: list[Recipe]


class FileChange(StrictModel):
    """New content for one file. `before` is None when the file is created."""

    rel_path: str = Field(min_length=1)
    before: str | None
    after: str
