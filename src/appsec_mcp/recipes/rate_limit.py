"""Recipe: limit how many requests one client can make (Express, Flask)."""

import re

from appsec_mcp.patching.fixers.base import FixOutcome, ensure_python_import
from appsec_mcp.recipes.common import (
    EXPRESS_APP,
    FLASK_APP,
    JS_LANGS,
    RecipeContext,
    add_js_import,
    add_npm_dependency,
    add_requirement,
    insert_after_line,
)

_ALREADY = re.compile(r"express-rate-limit|flask_limiter|Limiter\(|slowapi", re.IGNORECASE)


class RateLimitRecipe:
    """Adds a global per-IP rate limit."""

    id = "rate_limit"
    title = "Add rate limiting"
    description = "Limits each IP address to 100 requests per 15 minutes to slow down abuse."

    def check(self, ctx: RecipeContext) -> tuple[bool, str]:
        """Applicable to Express and Flask apps without a limiter."""
        if ctx.any_text(_ALREADY, ("javascript", "typescript", "python")):
            return False, "A rate limiter is already set up."
        if ctx.find_app(EXPRESS_APP, JS_LANGS) or ctx.find_app(FLASK_APP, ["python"]):
            return True, "No rate limiter found."
        return False, (
            "Supported for Express and Flask. For FastAPI use slowapi; for Spring use "
            "Bucket4j or your API gateway."
        )

    def build(self, ctx: RecipeContext) -> FixOutcome:
        """Record the edits."""
        express = ctx.find_app(EXPRESS_APP, JS_LANGS)
        if express:
            added = add_js_import(ctx.ws, express.rel_path, "rateLimit", "express-rate-limit")
            insert_after_line(
                ctx.ws,
                express.rel_path,
                express.line + added,
                [f"{express.var}.use(rateLimit({{ windowMs: 15 * 60 * 1000, limit: 100 }}));"],
            )
            add_npm_dependency(ctx.ws, express.rel_path, "express-rate-limit", "^7.4.0")
            return FixOutcome(
                "Adds express-rate-limit: 100 requests per 15 minutes per IP. Run "
                "`npm install` afterwards."
            )
        flask = ctx.find_app(FLASK_APP, ["python"])
        assert flask is not None
        insert_after_line(
            ctx.ws,
            flask.rel_path,
            flask.line,
            [
                f"limiter = Limiter(get_remote_address, app={flask.var}, "
                'default_limits=["100 per 15 minutes"])'
            ],
        )
        ensure_python_import(
            ctx.ws, flask.rel_path, "from flask_limiter.util import get_remote_address"
        )
        ensure_python_import(ctx.ws, flask.rel_path, "from flask_limiter import Limiter")
        add_requirement(ctx.ws, flask.rel_path, "Flask-Limiter>=3.5")
        return FixOutcome(
            "Adds Flask-Limiter: 100 requests per 15 minutes per IP. Run "
            "`pip install -r requirements.txt` afterwards."
        )
