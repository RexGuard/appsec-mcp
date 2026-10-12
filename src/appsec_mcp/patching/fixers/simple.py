"""One-line fixers: debug mode, CORS allow-list, strcpy, gets, .env ignore."""

import re

from appsec_mcp.patching.fixers.base import (
    FixOutcome,
    FixTarget,
    base_dir,
    ensure_c_include,
    ensure_python_import,
    replace_line,
)
from appsec_mcp.patching.workspace import Workspace

_DEBUG_KWARG = re.compile(r"\bdebug\s*=\s*True\b")
_DEBUG_SETTING = re.compile(r"^(\s*DEBUG\s*=\s*)True\b")
_JS_CORS_EMPTY = re.compile(r"\bcors\(\s*\)")
_JS_ORIGIN_STAR = re.compile(r"\borigin\s*:\s*[\"']\*[\"']")
_PY_CORS_APP = re.compile(r"\bCORS\(\s*app\s*\)")
_PY_ORIGINS_STAR = re.compile(r"\borigins\s*=\s*[\"']\*[\"']")
_PY_ALLOW_ORIGINS = re.compile(r"\ballow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]")
_STRCPY = re.compile(r"\bstrcpy\s*\(\s*([A-Za-z_]\w*)\s*,\s*(.+?)\s*\)\s*;")
_GETS = re.compile(r"(?<![\w.])gets\s*\(\s*([A-Za-z_]\w*)\s*\)")
_JS_ORIGINS = '(process.env.ALLOWED_ORIGINS || "").split(",")'
_PY_ORIGINS = 'os.environ.get("ALLOWED_ORIGINS", "").split(",")'


def fix_debug(ws: Workspace, target: FixTarget) -> FixOutcome | None:
    """Turn debug mode off."""
    if replace_line(ws, target, _DEBUG_KWARG, "debug=False") or replace_line(
        ws, target, _DEBUG_SETTING, r"\1False"
    ):
        return FixOutcome(
            "Turns debug mode off. To debug locally, switch it on only on your own "
            "machine (for example with the FLASK_DEBUG=1 environment variable)."
        )
    return None


def fix_cors(ws: Workspace, target: FixTarget) -> FixOutcome | None:
    """Replace a wildcard CORS policy with an allow-list from ALLOWED_ORIGINS."""
    if target.language in ("javascript", "typescript"):
        changed = replace_line(ws, target, _JS_CORS_EMPTY, f"cors({{ origin: {_JS_ORIGINS} }})")
        changed = changed or replace_line(ws, target, _JS_ORIGIN_STAR, f"origin: {_JS_ORIGINS}")
    elif target.language == "python":
        changed = (
            replace_line(ws, target, _PY_CORS_APP, f"CORS(app, origins={_PY_ORIGINS})")
            or replace_line(ws, target, _PY_ORIGINS_STAR, f"origins={_PY_ORIGINS}")
            or replace_line(ws, target, _PY_ALLOW_ORIGINS, f"allow_origins={_PY_ORIGINS}")
        )
        if changed:
            ensure_python_import(ws, target.rel_path)
    else:
        changed = False
    if not changed:
        return None
    ws.ensure_env_example(["ALLOWED_ORIGINS"], base_dir(target.rel_path))
    return FixOutcome(
        "Only the websites listed in the ALLOWED_ORIGINS environment variable "
        "(comma separated, e.g. https://myapp.com) may call the API. Set it before "
        "you deploy, otherwise browsers will block every cross-site call."
    )


def fix_strcpy(ws: Workspace, target: FixTarget) -> FixOutcome | None:
    """strcpy(dst, src) -> snprintf(dst, sizeof(dst), "%s", src)."""
    if not replace_line(ws, target, _STRCPY, r'snprintf(\1, sizeof(\1), "%s", \2);'):
        return None
    ensure_c_include(ws, target.rel_path, target.language)
    return FixOutcome(
        "Replaces strcpy with snprintf, which never writes past the buffer and "
        "always adds the terminating zero. This uses sizeof(destination), so it is "
        "only correct when the destination is an array, not a pointer."
    )


def fix_gets(ws: Workspace, target: FixTarget) -> FixOutcome | None:
    """gets(buf) -> fgets(buf, sizeof(buf), stdin)."""
    if not replace_line(ws, target, _GETS, r"fgets(\1, sizeof(\1), stdin)"):
        return None
    ensure_c_include(ws, target.rel_path, target.language)
    return FixOutcome(
        "Replaces gets with fgets, which stops at the buffer size. Note that fgets "
        "keeps the trailing newline; strip it if your code relies on that."
    )


def fix_env_gitignore(ws: Workspace, target: FixTarget) -> FixOutcome | None:
    """Ignore .env files in git."""
    ws.ensure_env_ignored(base_dir(target.rel_path))
    if not ws.changes():
        return None
    return FixOutcome(
        "Adds .env to .gitignore so it is not committed. If it was already "
        "committed, also run `git rm --cached .env` and rotate every secret in it."
    )
