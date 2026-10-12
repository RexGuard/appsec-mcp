"""Move a hard-coded secret into an environment variable."""

import re

from appsec_mcp.patching.fixers.base import (
    FixOutcome,
    FixTarget,
    base_dir,
    ensure_python_import,
    env_name,
)
from appsec_mcp.patching.workspace import Workspace

_ASSIGNMENT = re.compile(
    r"(?P<lhs>(?:(?:const|let|var)\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[\w\[\]<>| ]+)?"
    r"\s*=\s*|[\"']?(?P<key>[A-Za-z_][\w-]*)[\"']?\s*:\s*)"
    r"(?P<quote>[\"'`])(?P<value>[^\"'`\n]{8,})(?P=quote)"
)
_DEFAULT_NAME = "APP_SECRET"


def fix_secret(ws: Workspace, target: FixTarget) -> FixOutcome | None:
    """Replace the string literal holding the secret with an environment lookup."""
    text = ws.read(target.rel_path)
    if text is None or target.language not in ("javascript", "typescript", "python"):
        return None
    lines = text.splitlines(keepends=True)
    index = target.line - 1
    if not 0 <= index < len(lines):
        return None
    match = _ASSIGNMENT.search(lines[index])
    if match is None:
        return None
    name = env_name(match.group("name") or match.group("key"), _DEFAULT_NAME)
    lookup = f'os.environ["{name}"]' if target.language == "python" else f"process.env.{name}"
    start, end = match.span("quote")[0], match.end()
    lines[index] = f"{lines[index][:start]}{lookup}{lines[index][end:]}"
    ws.write(target.rel_path, "".join(lines))
    if target.language == "python":
        ensure_python_import(ws, target.rel_path)
    folder = base_dir(target.rel_path)
    ws.ensure_env_example([name], folder)
    ws.ensure_env_ignored(folder)
    return FixOutcome(
        f"Moves the secret out of the code into the {name} environment variable, lists {name} "
        "in .env.example (without the value) and keeps .env out of git. Put the real value in "
        f".env or your host's settings. Important: this key was already exposed, so rotate it "
        "(create a new one and revoke the old one)."
    )
