"""Python extraction: Flask and FastAPI routes, stores, services, requirements."""

import re
from pathlib import PurePosixPath

from appsec_mcp.mapper.facts import FileFacts
from appsec_mcp.scan.walker import SourceFile

_FLASK_ROUTE = re.compile(
    r"@\w+\.route\(\s*[\"']([^\"']+)[\"'](?:[^)]*?methods\s*=\s*[\[(]([^\])]*)[\])])?"
)
_FASTAPI_ROUTE = re.compile(r"@\w+\.(get|post|put|delete|patch)\(\s*[\"']([^\"']+)")
_ENTRY = re.compile(r"if\s+__name__\s*==\s*[\"']__main__[\"']|\buvicorn\.run\s*\(")
_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.MULTILINE)
_HTTP_HOST = re.compile(
    r"\b(?:requests|httpx|session|client)\.(?:get|post|put|patch|delete|request)\(\s*"
    r"(?:[\"'](?:GET|POST|PUT|PATCH|DELETE)[\"']\s*,\s*)?f?[\"'](https?://[^/\"'{]+)"
)
_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(?:[=<>~!]=?\s*([\w.*+-]+))?")

DATA_STORE_MODULES: dict[str, str] = {
    "sqlite3": "SQLite",
    "psycopg2": "PostgreSQL",
    "psycopg": "PostgreSQL",
    "asyncpg": "PostgreSQL",
    "pymongo": "MongoDB",
    "motor": "MongoDB",
    "redis": "Redis",
    "sqlalchemy": "SQL database (SQLAlchemy)",
    "mysql": "MySQL",
    "pymysql": "MySQL",
    "django": "Django ORM database",
    "peewee": "SQL database (peewee)",
}
SERVICE_MODULES: dict[str, str] = {
    "stripe": "Stripe",
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "boto3": "AWS",
    "twilio": "Twilio",
    "sendgrid": "SendGrid",
    "supabase": "Supabase",
    "firebase_admin": "Firebase",
}


def extract(source: SourceFile) -> FileFacts:
    """Extract facts from a Python file or requirements.txt."""
    if PurePosixPath(source.rel_path).name == "requirements.txt":
        return _requirements(source)
    facts = FileFacts()
    text = source.text
    if _ENTRY.search(text):
        facts.entry_point = "runs as a program"
    for path, methods in _FLASK_ROUTE.findall(text):
        names = re.findall(r"[A-Za-z]+", methods) or ["GET"]
        facts.routes.extend(f"{m.upper()} {path}" for m in names)
        facts.frameworks.add("flask")
    for method, path in _FASTAPI_ROUTE.findall(text):
        facts.routes.append(f"{method.upper()} {path}")
        facts.frameworks.add("fastapi")
    for a, b in _IMPORT.findall(text):
        top = (a or b).split(".")[0]
        if top in DATA_STORE_MODULES:
            facts.data_stores.add(DATA_STORE_MODULES[top])
        if top in SERVICE_MODULES:
            facts.external_services.add(SERVICE_MODULES[top])
        if top in ("flask", "fastapi"):
            facts.frameworks.add(top)
    facts.external_services.update(_HTTP_HOST.findall(text))
    return facts


def _requirements(source: SourceFile) -> FileFacts:
    facts = FileFacts()
    for line in source.text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        match = _REQUIREMENT.match(stripped)
        if match:
            name, version = match.group(1), match.group(2)
            facts.dependencies.append(f"{name}@{version}" if version else name)
    return facts
