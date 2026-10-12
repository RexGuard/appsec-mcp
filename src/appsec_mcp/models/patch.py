"""Recipes, propose_patch / propose_hardening, apply_patch and revert_patch."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from appsec_mcp.models.common import Id, RelPath, StrictModel

RecipeId = str


class ListRecipesRequest(StrictModel):
    scan_id: Id


class Recipe(StrictModel):
    id: RecipeId = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    applicable: bool
    reason: str = Field(description="Why it does or doesn't fit this project.")


class RecipeList(StrictModel):
    recipes: list[Recipe]


class ProposePatchRequest(StrictModel):
    finding_id: Id


class ProposeHardeningRequest(StrictModel):
    scan_id: Id
    recipe: RecipeId = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")


class PatchProposal(StrictModel):
    patch_id: Id
    proposal_token: str = Field(min_length=32, max_length=128)
    summary: str = Field(min_length=1)
    diff: str = Field(min_length=1)
    files: list[RelPath] = Field(min_length=1)
    expires_at: str


class ApplyPatchRequest(StrictModel):
    proposal_token: str = Field(min_length=32, max_length=128)


class ApplyPatchResponse(StrictModel):
    patch_id: Id
    status: Literal["applied"] = "applied"
    files_changed: list[RelPath]
    backup_dir: str


class RevertPatchRequest(StrictModel):
    patch_id: Id
    force: bool = False


class RevertPatchResponse(StrictModel):
    patch_id: Id
    status: Literal["reverted"] = "reverted"
    files_restored: list[RelPath]
