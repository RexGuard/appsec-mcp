"""Recipe: keep secrets in .env, out of git, with a documented .env.example."""

import re
from pathlib import PurePosixPath

from appsec_mcp.patching.fixers.base import FixOutcome
from appsec_mcp.patching.workspace import Workspace
from appsec_mcp.recipes.common import RecipeContext

_KEY = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", re.MULTILINE)
_TEMPLATES = (".example", ".sample", ".template", ".dist")


class EnvSecretsRecipe:
    """Ensures .env is ignored and .env.example lists the variable names (never values)."""

    id = "env_secrets"
    title = "Set up .env for secrets"
    description = (
        "Adds .env to .gitignore and writes .env.example with the variable names your "
        "app needs, so secrets stay out of git."
    )

    def check(self, ctx: RecipeContext) -> tuple[bool, str]:
        """Applicable when building it would change something."""
        probe = RecipeContext(ws=Workspace(ctx.ws.root), files=ctx.files, frameworks=ctx.frameworks)
        self.build(probe)
        if probe.ws.changes():
            return True, ".env is not fully set up (gitignore or .env.example is missing)."
        return False, ".env is already ignored and documented."

    def build(self, ctx: RecipeContext) -> FixOutcome:
        """Record the edits."""
        names: list[str] = []
        for rel, lang in ctx.files:
            name = PurePosixPath(rel).name
            if lang == "dotenv" and not name.endswith(_TEMPLATES):
                names.extend(_KEY.findall(ctx.ws.read(rel) or ""))
        ctx.ws.ensure_env_ignored()
        if names:
            ctx.ws.ensure_env_example(sorted(set(names)))
        return FixOutcome(
            "Keeps .env files out of git and lists the variable names (without "
            "values) in .env.example. If .env was committed before, run "
            "`git rm --cached .env` and rotate its secrets."
        )
