"""Fixer registry: `fix_kind` on a finding names the fixer that can patch it."""

from collections.abc import Callable

from appsec_mcp.patching.fixers.base import FixOutcome, FixTarget
from appsec_mcp.patching.fixers.secret import fix_secret
from appsec_mcp.patching.fixers.simple import (
    fix_cors,
    fix_debug,
    fix_env_gitignore,
    fix_gets,
    fix_strcpy,
)
from appsec_mcp.patching.fixers.sql import fix_sql
from appsec_mcp.patching.workspace import Workspace

Fixer = Callable[[Workspace, FixTarget], FixOutcome | None]

FIXERS: dict[str, Fixer] = {
    "hardcoded_secret": fix_secret,
    "sql_param": fix_sql,
    "flask_debug": fix_debug,
    "cors_allowlist": fix_cors,
    "strcpy": fix_strcpy,
    "gets": fix_gets,
    "env_gitignore": fix_env_gitignore,
}

RECIPE_PREFIX = "recipe:"
