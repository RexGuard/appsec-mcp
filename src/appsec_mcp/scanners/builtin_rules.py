"""Line-level rules for the built-in scanner. Data only: patterns, severities, CWEs, fixers."""

import re
from dataclasses import dataclass

from appsec_mcp.models.base import Severity

JS_LANGS = frozenset({"javascript", "typescript", "html"})
PY_LANGS = frozenset({"python"})
JAVA_LANGS = frozenset({"java", "kotlin"})
C_LANGS = frozenset({"c", "cpp"})
HTML_LANGS = frozenset({"html"})
CODE_LANGS = JS_LANGS | PY_LANGS | JAVA_LANGS | C_LANGS


@dataclass(frozen=True)
class LineRule:
    """A regex applied to each non-comment line of files in `languages`."""

    rule_id: str
    languages: frozenset[str]
    regex: re.Pattern[str]
    severity: Severity
    cwe: str
    message: str
    fix_kind: str | None = None


def _re(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


_SQL_VERBS = r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b"
_SQL_LITERAL = rf"(?:\"[^\"]*{_SQL_VERBS}[^\"]*\"|'[^']*{_SQL_VERBS}[^']*')"

LINE_RULES: tuple[LineRule, ...] = (
    LineRule(
        "builtin.js.eval",
        JS_LANGS,
        _re(r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\("),
        "high",
        "CWE-95",
        "Code built from a string is executed with eval.",
    ),
    LineRule(
        "builtin.js.sql-concat",
        JS_LANGS - HTML_LANGS,
        _re(rf"\.(?:query|execute|raw)\s*\(\s*{_SQL_LITERAL}\s*\+", re.IGNORECASE),
        "critical",
        "CWE-89",
        "SQL query built by joining strings with user input.",
        "sql_param",
    ),
    LineRule(
        "builtin.js.sql-template",
        JS_LANGS - HTML_LANGS,
        _re(
            r"\.(?:query|execute|raw)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b"
            r"[^`]*\$\{",
            re.IGNORECASE,
        ),
        "critical",
        "CWE-89",
        "SQL query built with a template string.",
    ),
    LineRule(
        "builtin.js.xss-response",
        JS_LANGS - HTML_LANGS,
        _re(r"\bres\.(?:send|write|end)\s*\([^)]*\breq\.(?:query|params|body)"),
        "high",
        "CWE-79",
        "Request data is written straight into the HTML response.",
    ),
    LineRule(
        "builtin.js.dom-xss",
        JS_LANGS,
        _re(
            r"\.(?:innerHTML|outerHTML)\s*=(?!=)|\bdocument\.write\s*\(|"
            r"dangerouslySetInnerHTML"
        ),
        "high",
        "CWE-79",
        "HTML is inserted into the page without escaping.",
    ),
    LineRule(
        "builtin.js.cors-wildcard",
        JS_LANGS - HTML_LANGS,
        _re(
            r"\bcors\(\s*\)|\borigin\s*:\s*[\"']\*[\"']|"
            r"Access-Control-Allow-Origin[\"']?\s*,\s*[\"']\*"
        ),
        "medium",
        "CWE-942",
        "CORS allows every website to call this API.",
        "cors_allowlist",
    ),
    LineRule(
        "builtin.js.command-injection",
        JS_LANGS - HTML_LANGS,
        _re(r"\bexec(?:Sync)?\s*\(\s*(?:[^\"'`)]*\+|`[^`]*\$\{)"),
        "high",
        "CWE-78",
        "A shell command is built from variables.",
    ),
    LineRule(
        "builtin.js.tls-disabled",
        JS_LANGS - HTML_LANGS,
        _re(
            r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\]?\s*=\s*"
            r"[\"']?0"
        ),
        "high",
        "CWE-295",
        "TLS certificate checks are turned off.",
    ),
    LineRule(
        "builtin.py.eval",
        PY_LANGS,
        _re(r"(?<![\w.])(?:eval|exec)\s*\("),
        "high",
        "CWE-95",
        "Code built from a string is executed with eval or exec.",
    ),
    LineRule(
        "builtin.py.sql-fstring",
        PY_LANGS,
        _re(
            r"\.(?:execute|executemany|raw)\s*\(\s*f(?:\"[^\"]*|'[^']*)"
            r"\{(?![A-Z_][A-Z0-9_]*\})"
        ),
        "critical",
        "CWE-89",
        "SQL query built with an f-string.",
        "sql_param",
    ),
    LineRule(
        "builtin.py.sql-concat",
        PY_LANGS,
        _re(rf"\.(?:execute|executemany|raw)\s*\(\s*{_SQL_LITERAL}\s*(?:\+|%\s)", re.IGNORECASE),
        "critical",
        "CWE-89",
        "SQL query built by joining strings with user input.",
        "sql_param",
    ),
    LineRule(
        "builtin.py.debug-mode",
        PY_LANGS,
        _re(r"\.run\([^)]*\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True\b"),
        "high",
        "CWE-489",
        "Debug mode is switched on.",
        "flask_debug",
    ),
    LineRule(
        "builtin.py.deserialization",
        PY_LANGS,
        _re(r"\bpickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Loader)"),
        "high",
        "CWE-502",
        "Untrusted data is deserialised.",
    ),
    LineRule(
        "builtin.py.shell-injection",
        PY_LANGS,
        _re(r"\bshell\s*=\s*True|\bos\.(?:system|popen)\s*\("),
        "high",
        "CWE-78",
        "A shell command is run through the system shell.",
    ),
    LineRule(
        "builtin.py.tls-disabled",
        PY_LANGS,
        _re(r"\bverify\s*=\s*False\b"),
        "medium",
        "CWE-295",
        "TLS certificate checks are turned off.",
    ),
    LineRule(
        "builtin.py.cors-wildcard",
        PY_LANGS,
        _re(
            r"\bCORS\(\s*app\s*\)|\borigins\s*=\s*[\"']\*[\"']|"
            r"allow_origins\s*=\s*\[\s*[\"']\*[\"']"
        ),
        "medium",
        "CWE-942",
        "CORS allows every website to call this API.",
        "cors_allowlist",
    ),
    LineRule(
        "builtin.java.sql-concat",
        JAVA_LANGS,
        _re(
            r"\.(?:executeQuery|executeUpdate|execute|prepareStatement|addBatch)\s*\(\s*"
            r"\"[^\"]*\"\s*\+"
        ),
        "critical",
        "CWE-89",
        "SQL query built by joining strings with user input.",
    ),
    LineRule(
        "builtin.java.deserialization",
        JAVA_LANGS,
        _re(r"\bnew\s+ObjectInputStream\s*\("),
        "high",
        "CWE-502",
        "Untrusted bytes are deserialised into Java objects.",
    ),
    LineRule(
        "builtin.java.command-injection",
        JAVA_LANGS,
        _re(r"Runtime\.getRuntime\(\)\.exec\s*\("),
        "high",
        "CWE-78",
        "An operating-system command is run.",
    ),
    LineRule(
        "builtin.java.weak-hash",
        JAVA_LANGS,
        _re(r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\""),
        "medium",
        "CWE-328",
        "A weak hash (MD5/SHA-1) is used.",
    ),
    LineRule(
        "builtin.c.strcpy",
        C_LANGS,
        _re(r"\bstrcpy\s*\("),
        "high",
        "CWE-120",
        "strcpy() copies without checking the buffer size.",
        "strcpy",
    ),
    LineRule(
        "builtin.c.strcat",
        C_LANGS,
        _re(r"\bstrcat\s*\("),
        "high",
        "CWE-120",
        "strcat() appends without checking the buffer size.",
    ),
    LineRule(
        "builtin.c.gets",
        C_LANGS,
        _re(r"(?<![\w.])gets\s*\("),
        "critical",
        "CWE-242",
        "gets() can never be used safely.",
        "gets",
    ),
    LineRule(
        "builtin.c.format-string",
        C_LANGS,
        _re(
            r"(?<![\w.])printf\s*\(\s*[A-Za-z_][\w.\->\[\]]*\s*\)|"
            r"\bfprintf\s*\(\s*\w+\s*,\s*[A-Za-z_][\w.\->\[\]]*\s*\)"
        ),
        "high",
        "CWE-134",
        "A variable is used as the printf format string.",
    ),
    LineRule(
        "builtin.c.sprintf",
        C_LANGS,
        _re(r"(?<![\w.])sprintf\s*\("),
        "medium",
        "CWE-120",
        "sprintf() writes without checking the buffer size.",
    ),
    LineRule(
        "builtin.c.system",
        C_LANGS,
        _re(r"(?<![\w.])system\s*\("),
        "medium",
        "CWE-78",
        "An operating-system command is run through the shell.",
    ),
    LineRule(
        "builtin.html.mixed-content",
        HTML_LANGS,
        _re(
            r"<(?:script|link|iframe|img)\b[^>]*\b(?:src|href)\s*=\s*[\"']http://"
            r"(?!localhost|127\.0\.0\.1)",
            re.IGNORECASE,
        ),
        "medium",
        "CWE-319",
        "A resource is loaded over plain http.",
    ),
)

_COMMENT_PREFIXES = ("//", "/*", "*", "<!--")


def is_comment(line: str, language: str | None) -> bool:
    """Cheap comment detection so rules don't fire on commented-out code."""
    stripped = line.lstrip()
    if language == "python" and stripped.startswith("#"):
        return True
    return stripped.startswith(_COMMENT_PREFIXES)
