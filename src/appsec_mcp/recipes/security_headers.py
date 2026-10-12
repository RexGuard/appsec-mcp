"""Recipe: send standard security headers (CSP, nosniff, frame protection, referrer policy)."""

import re
from pathlib import PurePosixPath

from appsec_mcp.patching.fixers.base import FixOutcome
from appsec_mcp.recipes.common import (
    EXPRESS_APP,
    FASTAPI_APP,
    FLASK_APP,
    JS_LANGS,
    SPRING_APP,
    RecipeContext,
    add_js_import,
    add_npm_dependency,
    insert_after_line,
)

_ALREADY = re.compile(r"helmet|Talisman|X-Content-Type-Options|SecurityHeaders", re.IGNORECASE)
_HEADERS = (
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
)
_ALL_CODE = ("javascript", "typescript", "python", "java", "kotlin")


class SecurityHeadersRecipe:
    """Adds header middleware for Express, Flask, FastAPI, Next.js or Spring Boot."""

    id = "security_headers"
    title = "Add security headers"
    description = (
        "Sends Content-Security-Policy, X-Content-Type-Options, X-Frame-Options and "
        "Referrer-Policy on every response."
    )

    def check(self, ctx: RecipeContext) -> tuple[bool, str]:
        """Applicable when a supported app exists and no header middleware is present."""
        if ctx.any_text(_ALREADY, _ALL_CODE):
            return False, "Security headers are already configured."
        if _target(ctx):
            return True, "No security header middleware found."
        return False, "No Express, Flask, FastAPI, Next.js or Spring Boot app was found."

    def build(self, ctx: RecipeContext) -> FixOutcome:
        """Record the edits for the detected framework."""
        target = _target(ctx)
        if target == "express":
            return _express(ctx)
        if target == "flask":
            return _python(ctx, FLASK_APP, "after_request")
        if target == "fastapi":
            return _python(ctx, FASTAPI_APP, "middleware")
        if target == "nextjs":
            return _nextjs(ctx)
        return _spring(ctx)


def _target(ctx: RecipeContext) -> str | None:
    if ctx.find_app(EXPRESS_APP, JS_LANGS):
        return "express"
    if ctx.find_app(FLASK_APP, ["python"]):
        return "flask"
    if ctx.find_app(FASTAPI_APP, ["python"]):
        return "fastapi"
    if "nextjs" in ctx.frameworks and not _next_middleware_exists(ctx):
        return "nextjs"
    if ctx.find_app(SPRING_APP, ["java"]):
        return "spring"
    return None


def _express(ctx: RecipeContext) -> FixOutcome:
    app = ctx.find_app(EXPRESS_APP, JS_LANGS)
    assert app is not None
    added = add_js_import(ctx.ws, app.rel_path, "helmet", "helmet")
    insert_after_line(ctx.ws, app.rel_path, app.line + added, [f"{app.var}.use(helmet());"])
    add_npm_dependency(ctx.ws, app.rel_path, "helmet", "^7.1.0")
    return FixOutcome(
        "Adds the helmet middleware, which sets a safe default set of security "
        "headers on every response. Run `npm install` afterwards."
    )


def _python(ctx: RecipeContext, pattern: re.Pattern[str], style: str) -> FixOutcome:
    app = ctx.find_app(pattern, ["python"])
    assert app is not None
    sets = [f'    response.headers.setdefault("{n}", "{v}")' for n, v in _HEADERS]
    if style == "after_request":
        block = [
            "",
            "",
            f"@{app.var}.after_request",
            "def _set_security_headers(response):",
            *sets,
            "    return response",
        ]
    else:
        block = [
            "",
            "",
            f'@{app.var}.middleware("http")',
            "async def _set_security_headers(request, call_next):",
            "    response = await call_next(request)",
            *sets,
            "    return response",
        ]
    insert_after_line(ctx.ws, app.rel_path, app.line, block)
    return FixOutcome(
        "Adds a small hook that sets security headers on every response. Loosen "
        "the Content-Security-Policy if your pages load scripts from other sites."
    )


def _next_middleware_exists(ctx: RecipeContext) -> bool:
    return any(
        PurePosixPath(rel).stem == "middleware"
        and PurePosixPath(rel).parent.as_posix() in (".", "src")
        for rel, _ in ctx.files
    )


def _nextjs(ctx: RecipeContext) -> FixOutcome:
    folder = (
        "src/"
        if any(rel.startswith("src/app/") or rel.startswith("src/pages/") for rel, _ in ctx.files)
        else ""
    )
    sets = [f'  response.headers.set("{n}", "{v}");' for n, v in _HEADERS]
    body = [
        'import { NextResponse } from "next/server";',
        "",
        "export function middleware() {",
        "  const response = NextResponse.next();",
        *sets,
        "  return response;",
        "}",
        "",
    ]
    ctx.ws.write(f"{folder}middleware.ts", "\n".join(body))
    return FixOutcome(
        "Creates a Next.js middleware.ts that sets security headers on every response."
    )


def _spring(ctx: RecipeContext) -> FixOutcome:
    app = ctx.find_app(SPRING_APP, ["java"])
    assert app is not None
    text = ctx.ws.read(app.rel_path) or ""
    package_match = re.search(r"^package\s+([\w.]+);", text, re.MULTILINE)
    package = package_match.group(1) if package_match else None
    servlet = "javax" if _spring_boot_2(ctx) else "jakarta"
    sets = [f'        response.setHeader("{n}", "{v}");' for n, v in _HEADERS]
    lines = ([f"package {package};", ""] if package else []) + [
        "import java.io.IOException;",
        "",
        f"import {servlet}.servlet.FilterChain;",
        f"import {servlet}.servlet.ServletException;",
        f"import {servlet}.servlet.http.HttpServletRequest;",
        f"import {servlet}.servlet.http.HttpServletResponse;",
        "",
        "import org.springframework.stereotype.Component;",
        "import org.springframework.web.filter.OncePerRequestFilter;",
        "",
        "@Component",
        "public class SecurityHeadersFilter extends OncePerRequestFilter {",
        "    @Override",
        "    protected void doFilterInternal(HttpServletRequest request, "
        "HttpServletResponse response, FilterChain chain)",
        "            throws ServletException, IOException {",
        *sets,
        "        chain.doFilter(request, response);",
        "    }",
        "}",
        "",
    ]
    folder = PurePosixPath(app.rel_path).parent.as_posix()
    ctx.ws.write(f"{folder}/SecurityHeadersFilter.java", "\n".join(lines))
    return FixOutcome(
        "Adds a SecurityHeadersFilter component that sets security headers on every response."
    )


def _spring_boot_2(ctx: RecipeContext) -> bool:
    pom = ctx.ws.read("pom.xml") or ""
    return bool(re.search(r"spring-boot-starter-parent</artifactId>\s*<version>2\.", pom))
