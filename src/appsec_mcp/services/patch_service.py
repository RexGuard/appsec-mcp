"""Propose, apply and revert patches and hardening recipes. Every write needs a proposal token."""

import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

from appsec_mcp.config import PROPOSAL_TTL_MINUTES
from appsec_mcp.errors import ErrorCode, NotFoundError, PatchError
from appsec_mcp.models.patch import PatchApplied, PatchProposal, PatchReverted, Recipe, RecipeList
from appsec_mcp.patching.diff import unified_diff
from appsec_mcp.patching.engine import PatchEngine, Writer, atomic_write
from appsec_mcp.patching.fixers import FIXERS, RECIPE_PREFIX
from appsec_mcp.patching.fixers.base import FixOutcome, FixTarget
from appsec_mcp.patching.workspace import Workspace
from appsec_mcp.recipes.common import RecipeContext
from appsec_mcp.recipes.registry import RECIPES, detect_frameworks
from appsec_mcp.scan.language import detect_language
from appsec_mcp.services.query_service import QueryService
from appsec_mcp.services.repositories import Repositories

logger = logging.getLogger(__name__)

_TOKEN_BYTES = 32
_MAX_LEDGER_FILES = 100_000
Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class PatchService:
    """The only code path that writes to a user's project."""

    def __init__(
        self,
        repos: Repositories,
        queries: QueryService,
        backups_dir: Path,
        clock: Clock = _utc_now,
        writer: Writer = atomic_write,
    ) -> None:
        self._repos = repos
        self._queries = queries
        self._backups_dir = backups_dir
        self._clock = clock
        self._writer = writer

    def propose_patch(self, finding_id: int) -> PatchProposal:
        """Build a fix for one finding. Writes nothing."""
        row = self._queries.finding_row(finding_id)
        if not row.patchable or row.status == "fixed" or not row.fix_kind or not row.rel_path:
            raise PatchError(
                ErrorCode.NOT_PATCHABLE,
                f"Finding {finding_id} has no automatic fix. How to fix it by hand: {row.fix_hint}",
            )
        if row.fix_kind.startswith(RECIPE_PREFIX):
            return self.propose_hardening(
                row.scan_id, row.fix_kind.removeprefix(RECIPE_PREFIX), finding_id=finding_id
            )
        scan = self._queries.scan_row(row.scan_id)
        root = Path(scan.root_path)
        ws = Workspace(root)
        target = FixTarget(row.rel_path, row.line_start or 1, detect_language(row.rel_path))
        outcome = FIXERS[row.fix_kind](ws, target)
        if outcome is None or not ws.changes():
            raise PatchError(
                ErrorCode.NOT_PATCHABLE,
                "This code has a shape I can't rewrite "
                f"safely. How to fix it by hand: {row.fix_hint}",
            )
        return self._store(scan.project_id, ws, outcome, finding_id=finding_id, recipe=None)

    def list_recipes(self, scan_id: int) -> RecipeList:
        """Every recipe with whether it fits this project and why."""
        ctx = self._recipe_context(scan_id)
        items = []
        for recipe in RECIPES.values():
            applicable, reason = recipe.check(ctx)
            items.append(
                Recipe(
                    id=recipe.id,
                    title=recipe.title,
                    description=recipe.description,
                    applicable=applicable,
                    reason=reason,
                )
            )
        return RecipeList(recipes=items)

    def propose_hardening(
        self, scan_id: int, recipe_id: str, finding_id: int | None = None
    ) -> PatchProposal:
        """Build a hardening recipe for a scanned project. Writes nothing."""
        recipe = RECIPES.get(recipe_id)
        if recipe is None:
            raise NotFoundError(
                ErrorCode.RECIPE_NOT_FOUND,
                f"Unknown recipe '{recipe_id}'. Available: {', '.join(RECIPES)}.",
            )
        ctx = self._recipe_context(scan_id)
        applicable, reason = recipe.check(ctx)
        if not applicable:
            raise PatchError(ErrorCode.RECIPE_NOT_APPLICABLE, reason)
        outcome = recipe.build(ctx)
        scan = self._queries.scan_row(scan_id)
        return self._store(
            scan.project_id, ctx.ws, outcome, finding_id=finding_id, recipe=recipe_id
        )

    def _recipe_context(self, scan_id: int) -> RecipeContext:
        scan = self._queries.scan_row(scan_id)
        files = [
            (f.rel_path, f.language)
            for f in self._repos.scans.files(scan_id, _MAX_LEDGER_FILES, 0)
            if f.status == "read"
        ]
        frameworks = detect_frameworks(self._repos.maps.load(scan_id))
        return RecipeContext(ws=Workspace(Path(scan.root_path)), files=files, frameworks=frameworks)

    def _store(
        self,
        project_id: int,
        ws: Workspace,
        outcome: FixOutcome,
        *,
        finding_id: int | None,
        recipe: str | None,
    ) -> PatchProposal:
        changes = ws.changes()
        engine = PatchEngine(ws.root, self._writer)
        hashes = engine.current_hashes([c.rel_path for c in changes])
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        expires = self._clock() + timedelta(minutes=PROPOSAL_TTL_MINUTES)
        diff = unified_diff(changes)
        patch_id = self._repos.patches.create(
            project_id=project_id,
            finding_id=finding_id,
            recipe=recipe,
            token=token,
            summary=outcome.summary,
            diff=diff,
            file_hashes=hashes,
            changes=changes,
            expires_at=expires.isoformat(timespec="seconds"),
        )
        return PatchProposal(
            patch_id=patch_id,
            proposal_token=token,
            summary=outcome.summary,
            diff=diff,
            files=[c.rel_path for c in changes],
            expires_at=expires.isoformat(timespec="seconds"),
        )

    def apply_patch(self, proposal_token: str) -> PatchApplied:
        """Apply a proposal after checking it is valid, fresh and the files are unchanged."""
        patch = self._repos.patches.get_by_token(proposal_token)
        if patch is None or patch.status != "proposed":
            raise PatchError(
                ErrorCode.TOKEN_INVALID, "That proposal token is not valid or was already used."
            )
        if self._clock() > datetime.fromisoformat(patch.expires_at):
            self._repos.patches.set_status(patch.id, "expired")
            raise PatchError(
                ErrorCode.PROPOSAL_EXPIRED,
                f"The proposal is older than {PROPOSAL_TTL_MINUTES} minutes. Ask for a new one.",
            )
        project = self._repos.projects.get(patch.project_id)
        assert project is not None
        backup_dir = self._backups_dir / str(patch.id)
        engine = PatchEngine(Path(project.root_path), self._writer)
        changed = engine.apply(patch.changes, patch.file_hashes, backup_dir)
        self._repos.patches.set_status(
            patch.id, "applied", backup_dir=str(backup_dir), applied=True
        )
        logger.info("Applied patch %d to %d file(s)", patch.id, len(changed))
        return PatchApplied(patch_id=patch.id, files_changed=changed, backup_dir=str(backup_dir))

    def revert_patch(self, patch_id: int, force: bool = False) -> PatchReverted:
        """Restore the files an applied patch changed, byte for byte."""
        patch = self._repos.patches.get(patch_id)
        if patch is None:
            raise NotFoundError(ErrorCode.PATCH_NOT_FOUND, f"There is no patch with id {patch_id}.")
        if patch.status != "applied" or not patch.backup_dir:
            raise PatchError(
                ErrorCode.NOT_APPLIED,
                f"Patch {patch_id} is '{patch.status}', so there is nothing to revert.",
            )
        project = self._repos.projects.get(patch.project_id)
        assert project is not None
        restored = PatchEngine(Path(project.root_path), self._writer).revert(
            Path(patch.backup_dir), force
        )
        self._repos.patches.set_status(patch_id, "reverted")
        logger.info("Reverted patch %d", patch_id)
        return PatchReverted(
            patch_id=patch_id,
            files_restored=sorted(restored, key=lambda p: PurePosixPath(p).as_posix()),
        )
