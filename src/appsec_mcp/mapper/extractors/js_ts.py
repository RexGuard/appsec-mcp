"""JavaScript/TypeScript extraction: Express and Next.js routes, stores, services, npm deps."""

import json
import logging
import re
from pathlib import PurePosixPath

from appsec_mcp.mapper.facts import FileFacts
from appsec_mcp.scan.walker import SourceFile

logger = logging.getLogger(__name__)

_EXPRESS_ROUTE = re.compile(
    r"\b(?:app|router|\w+Router|server)\.(get|post|put|delete|patch|all)\(\s*[\"'`]([^\"'`]+)"
)
_NEXT_APP_ROUTE = re.compile(r"(?:^|/)app/(.*?)/?route\.(?:t|j)sx?$")
_NEXT_PAGES_API = re.compile(r"(?:^|/)pages/(api/.+?)\.(?:t|j)sx?$")
_NEXT_METHOD = re.compile(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b")
_ENTRY = re.compile(r"\.listen\s*\(|\bcreateServer\s*\(")
_FETCH_HOST = re.compile(
    r"\b(?:fetch|axios(?:\.\w+)?|got|request)\s*\(\s*[\"'`](https?://[^/\"'`$]+)"
)
_IMPORT = re.compile(r"(?:from\s+[\"']([^\"']+)[\"']|require\(\s*[\"']([^\"']+)[\"']\s*\))")

DATA_STORE_MODULES: dict[str, str] = {
    "mysql": "MySQL",
    "mysql2": "MySQL",
    "pg": "PostgreSQL",
    "postgres": "PostgreSQL",
    "mongoose": "MongoDB",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "ioredis": "Redis",
    "sqlite3": "SQLite",
    "better-sqlite3": "SQLite",
    "@prisma/client": "Prisma (database)",
    "sequelize": "SQL database (Sequelize)",
    "typeorm": "SQL database (TypeORM)",
    "knex": "SQL database (Knex)",
    "firebase-admin": "Firebase",
}
SERVICE_MODULES: dict[str, str] = {
    "stripe": "Stripe",
    "openai": "OpenAI",
    "@anthropic-ai/sdk": "Anthropic",
    "aws-sdk": "AWS",
    "twilio": "Twilio",
    "@sendgrid/mail": "SendGrid",
    "@supabase/supabase-js": "Supabase",
    "firebase": "Firebase",
}


def extract(source: SourceFile) -> FileFacts:
    """Extract facts from a JS/TS file, or from package.json."""
    if PurePosixPath(source.rel_path).name == "package.json":
        return _package_json(source)
    facts = FileFacts()
    text = source.text
    if _ENTRY.search(text):
        facts.entry_point = "starts an HTTP server"
    for method, path in _EXPRESS_ROUTE.findall(text):
        facts.routes.append(f"{method.upper()} {path}")
        facts.frameworks.add("express")
    _next_routes(source, facts)
    for module in _imports(text):
        if module in DATA_STORE_MODULES:
            facts.data_stores.add(DATA_STORE_MODULES[module])
        if module in SERVICE_MODULES:
            facts.external_services.add(SERVICE_MODULES[module])
        if module.startswith("@aws-sdk/"):
            facts.external_services.add("AWS")
        if module == "express":
            facts.frameworks.add("express")
    facts.external_services.update(_FETCH_HOST.findall(text))
    return facts


def _imports(text: str) -> set[str]:
    return {a or b for a, b in _IMPORT.findall(text)}


def _next_routes(source: SourceFile, facts: FileFacts) -> None:
    app_match = _NEXT_APP_ROUTE.search(source.rel_path)
    pages_match = _NEXT_PAGES_API.search(source.rel_path)
    if app_match:
        route = "/" + app_match.group(1)
        methods = _NEXT_METHOD.findall(source.text) or ["ANY"]
        facts.routes.extend(f"{m} {route}" for m in methods)
        facts.frameworks.add("nextjs")
    elif pages_match:
        facts.routes.append(f"ANY /{pages_match.group(1)}")
        facts.frameworks.add("nextjs")


def _package_json(source: SourceFile) -> FileFacts:
    facts = FileFacts()
    try:
        data = json.loads(source.text)
    except json.JSONDecodeError:
        logger.warning("Could not parse %s", source.rel_path)
        return facts
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            facts.dependencies.append(f"{name}@{version}")
    deps = {
        d.split("@")[0] if not d.startswith("@") else d.rsplit("@", 1)[0]
        for d in facts.dependencies
    }
    facts.frameworks.update(f for f in ("express", "next") if f in deps)
    if "next" in deps:
        facts.frameworks.add("nextjs")
    return facts
