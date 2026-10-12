"""Recipe: CSRF protection (Flask-WTF for Flask, an Origin check for Express)."""

import re

from appsec_mcp.patching.fixers.base import FixOutcome, ensure_python_import
from appsec_mcp.recipes.common import (
    EXPRESS_APP,
    FLASK_APP,
    JS_LANGS,
    RecipeContext,
    add_requirement,
    insert_after_line,
)

_ALREADY = re.compile(r"CSRFProtect|csrf", re.IGNORECASE)
_ORIGIN_CHECK = [
    "{var}.use((req, res, next) => {{",
    '  const unsafe = !["GET", "HEAD", "OPTIONS"].includes(req.method);',
    '  const allowed = (process.env.ALLOWED_ORIGINS || "").split(",");',
    '  const origin = req.get("origin") || req.get("referer") || "";',
    "  if (unsafe && !allowed.some((o) => o && origin.startsWith(o))) {{",
    '    return res.status(403).send("Cross-site request blocked");',
    "  }}",
    "  return next();",
    "}});",
]


class CsrfRecipe:
    """Blocks cross-site form submissions."""

    id = "csrf"
    title = "Add CSRF protection"
    description = "Rejects state-changing requests that did not come from your own site."

    def check(self, ctx: RecipeContext) -> tuple[bool, str]:
        """Applicable to Flask and Express apps without CSRF protection."""
        if ctx.any_text(_ALREADY, ("javascript", "typescript", "python")):
            return False, "CSRF protection is already set up."
        if ctx.find_app(FLASK_APP, ["python"]) or ctx.find_app(EXPRESS_APP, JS_LANGS):
            return True, "No CSRF protection found."
        return False, (
            "Supported for Flask and Express. Spring Security enables CSRF by default; "
            "token-based APIs (FastAPI, Next.js route handlers) usually don't need it."
        )

    def build(self, ctx: RecipeContext) -> FixOutcome:
        """Record the edits."""
        flask = ctx.find_app(FLASK_APP, ["python"])
        if flask:
            insert_after_line(ctx.ws, flask.rel_path, flask.line, [f"CSRFProtect({flask.var})"])
            ensure_python_import(ctx.ws, flask.rel_path, "from flask_wtf.csrf import CSRFProtect")
            add_requirement(ctx.ws, flask.rel_path, "Flask-WTF>=1.2")
            return FixOutcome(
                "Turns on Flask-WTF CSRF protection. Every HTML form must now include "
                "{{ csrf_token() }} in a hidden field named csrf_token, and the app needs a "
                "SECRET_KEY. Run `pip install -r requirements.txt` afterwards."
            )
        express = ctx.find_app(EXPRESS_APP, JS_LANGS)
        assert express is not None
        block = [line.format(var=express.var) for line in _ORIGIN_CHECK]
        insert_after_line(ctx.ws, express.rel_path, express.line, block)
        ctx.ws.ensure_env_example(["ALLOWED_ORIGINS"])
        return FixOutcome(
            "Adds a middleware that blocks POST/PUT/PATCH/DELETE requests whose "
            "Origin is not in ALLOWED_ORIGINS. Set ALLOWED_ORIGINS before deploying."
        )
