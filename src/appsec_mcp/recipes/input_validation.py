"""Recipe: cap request body sizes, the first layer of input validation."""

import re

from appsec_mcp.patching.fixers.base import FixOutcome
from appsec_mcp.recipes.common import (
    EXPRESS_APP,
    FLASK_APP,
    JS_LANGS,
    RecipeContext,
    insert_after_line,
)

_EXPRESS_JSON = re.compile(r"express\.json\(\s*\)")
_EXPRESS_LIMIT = re.compile(r"express\.json\(\s*\{[^}]*limit")
_FLASK_LIMIT = re.compile(r"MAX_CONTENT_LENGTH")
_BODY_LIMIT = '"100kb"'
_FLASK_MAX_BYTES = "1 * 1024 * 1024"


class InputValidationRecipe:
    """Limits request body size for Express and Flask."""

    id = "input_validation"
    title = "Limit request body size"
    description = (
        "Rejects oversized request bodies, which blocks a class of denial-of-service "
        "and parser attacks. Pair it with schema validation (zod, pydantic)."
    )

    def check(self, ctx: RecipeContext) -> tuple[bool, str]:
        """Applicable to Express and Flask apps without a body limit."""
        if ctx.find_app(EXPRESS_APP, JS_LANGS):
            if ctx.any_text(_EXPRESS_LIMIT, JS_LANGS):
                return False, "express.json already has a size limit."
            return True, "express.json has no size limit."
        if ctx.find_app(FLASK_APP, ["python"]):
            if ctx.any_text(_FLASK_LIMIT, ["python"]):
                return False, "MAX_CONTENT_LENGTH is already set."
            return True, "Flask accepts request bodies of any size."
        return False, (
            "Supported for Express and Flask. FastAPI and Spring validate bodies with "
            "pydantic / Bean Validation (@Valid); add limits in your server config."
        )

    def build(self, ctx: RecipeContext) -> FixOutcome:
        """Record the edits."""
        express = ctx.find_app(EXPRESS_APP, JS_LANGS)
        if express:
            text = ctx.ws.read(express.rel_path) or ""
            if _EXPRESS_JSON.search(text):
                ctx.ws.write(
                    express.rel_path,
                    _EXPRESS_JSON.sub(f"express.json({{ limit: {_BODY_LIMIT} }})", text, count=1),
                )
            else:
                insert_after_line(
                    ctx.ws,
                    express.rel_path,
                    express.line,
                    [f"{express.var}.use(express.json({{ limit: {_BODY_LIMIT} }}));"],
                )
            return FixOutcome("Limits JSON request bodies to 100 KB.")
        flask = ctx.find_app(FLASK_APP, ["python"])
        assert flask is not None
        insert_after_line(
            ctx.ws,
            flask.rel_path,
            flask.line,
            [f'{flask.var}.config["MAX_CONTENT_LENGTH"] = {_FLASK_MAX_BYTES}'],
        )
        return FixOutcome("Rejects request bodies larger than 1 MB (HTTP 413).")
