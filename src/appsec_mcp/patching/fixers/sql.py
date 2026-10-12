"""Rewrite string-built SQL into a parameterised query, for the simple shapes we can parse.

Supported: ``x.query("..." + a + "...", cb)`` (JS), ``cur.execute("..." + a)`` and
``cur.execute`` with an f-string such as ``f"...{a}..."`` (Python). Anything else is reported as
not patchable.
"""

import re
from dataclasses import dataclass

from appsec_mcp.patching.fixers.base import FixOutcome, FixTarget
from appsec_mcp.patching.workspace import Workspace

_CALL = re.compile(r"\.(?:query|execute|executemany|raw)\s*\(\s*")
_PG_JS = re.compile(r"(?:require\(\s*|from\s+)[\"']pg[\"']")
_PY_PERCENT_DRIVERS = re.compile(
    r"^\s*(?:import|from)\s+(?:psycopg2?|pymysql|mysql|MySQLdb)\b", re.MULTILINE
)
_FSTRING_FIELD = re.compile(r"\{([^{}!:]+)\}")
_QUOTES = "\"'`"
_OPEN = "([{"
_CLOSE = ")]}"


@dataclass(frozen=True)
class _Part:
    """A string literal or an expression between `+` signs."""

    literal: bool
    text: str
    fstring: bool = False


def _string_end(text: str, start: int) -> int | None:
    quote = text[start]
    i = start + 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i
        if text[i] == "\n" and quote != "`":
            return None
        i += 1
    return None


def _flush(parts: list[_Part], expr: list[str]) -> None:
    joined = "".join(expr).strip()
    if joined:
        parts.append(_Part(False, joined))
    expr.clear()


def _scan_argument(text: str, start: int) -> tuple[list[_Part], int] | None:
    """Split the first call argument at top-level `+`. Returns (parts, end offset)."""
    parts: list[_Part] = []
    expr: list[str] = []
    depth = 0
    i = start
    while i < len(text):
        char = text[i]
        if depth == 0 and not "".join(expr).strip():
            is_f = char in "fF" and i + 1 < len(text) and text[i + 1] in "\"'"
            quote_at = i + 1 if is_f else i
            if text[quote_at] in _QUOTES:
                end = _string_end(text, quote_at)
                if end is None:
                    return None
                parts.append(_Part(True, text[quote_at + 1 : end], is_f))
                expr.clear()
                i = end + 1
                continue
        if char in _OPEN:
            depth += 1
        elif char in _CLOSE and depth > 0:
            depth -= 1
        elif (char in _CLOSE or char == ",") and depth == 0:
            _flush(parts, expr)
            return parts, i
        elif char == "+" and depth == 0:
            _flush(parts, expr)
            i += 1
            continue
        expr.append(char)
        i += 1
    return None


def _expand_fstrings(parts: list[_Part]) -> list[_Part]:
    expanded: list[_Part] = []
    for part in parts:
        if not part.fstring:
            expanded.append(part)
            continue
        cursor = 0
        for field in _FSTRING_FIELD.finditer(part.text):
            expanded.append(_Part(True, part.text[cursor : field.start()]))
            expanded.append(_Part(False, field.group(1).strip()))
            cursor = field.end()
        expanded.append(_Part(True, part.text[cursor:]))
    return expanded


def _build_sql(parts: list[_Part], placeholder: str) -> tuple[str, list[str]] | None:
    """Join literals, replacing each expression (and quotes around it) with a placeholder."""
    sql = ""
    params: list[str] = []
    strip_next_quote = False
    for part in parts:
        if part.literal:
            text = part.text[1:] if strip_next_quote and part.text.startswith("'") else part.text
            strip_next_quote = False
            sql += text
            continue
        if sql.endswith("'"):
            sql = sql[:-1]
            strip_next_quote = True
        params.append(part.text)
        sql += placeholder.replace("{n}", str(len(params)))
    if not params or any(char in sql for char in '"{}'):
        return None
    return sql, params


def fix_sql(ws: Workspace, target: FixTarget) -> FixOutcome | None:
    """Turn the query on the target line into a parameterised one."""
    text = ws.read(target.rel_path)
    if text is None or target.language not in ("javascript", "typescript", "python"):
        return None
    line_start = _offset_of_line(text, target.line)
    call = _CALL.search(text, line_start)
    if call is None or "\n" in text[line_start : call.start()]:
        return None
    scanned = _scan_argument(text, call.end())
    if scanned is None:
        return None
    parts, arg_end = scanned
    if any(p.literal and "${" in p.text for p in parts):
        return None
    if target.language == "python":
        parts = _expand_fstrings(parts)
    placeholder = _placeholder(text, target.language)
    built = _build_sql(parts, placeholder)
    if built is None:
        return None
    sql, params = built
    joined = ", ".join(params)
    param_text = f"({joined},)" if target.language == "python" else f"[{joined}]"
    ws.write(target.rel_path, f'{text[: call.end()]}"{sql}", {param_text}{text[arg_end:]}')
    return FixOutcome(
        f"Sends {joined} to the database as a separate parameter instead of pasting it into the "
        f"SQL text, so it can never change the query. Placeholder style: "
        f"{placeholder.replace('{n}', '1')}."
    )


def _placeholder(text: str, language: str | None) -> str:
    if language == "python":
        return "%s" if _PY_PERCENT_DRIVERS.search(text) else "?"
    return "${n}" if _PG_JS.search(text) else "?"


def _offset_of_line(text: str, line: int) -> int:
    offset = 0
    for _ in range(line - 1):
        next_break = text.find("\n", offset)
        if next_break == -1:
            return len(text)
        offset = next_break + 1
    return offset
