"""The built-in scanner: line rules, secret patterns and project-level config checks.

It needs no external binary, so every scan produces results even on a fresh machine.
"""

import re
from collections.abc import Iterator, Sequence
from pathlib import Path, PurePosixPath

from appsec_mcp import __version__
from appsec_mcp.models.finding import RawFinding
from appsec_mcp.scan.walker import SourceFile
from appsec_mcp.scanners.base import AdapterResult, count_rule_matches
from appsec_mcp.scanners.builtin_rules import CODE_LANGS, LINE_RULES, is_comment
from appsec_mcp.security.redact import SECRET_PATTERNS, is_placeholder

_CRITICAL_SECRETS = frozenset({"secret.stripe-key", "secret.aws-access-key", "secret.private-key"})
_CONFIG_LANGS = frozenset({"dotenv", "properties", "ini", "yaml", "toml"})
SUPPRESS_MARKER = "appsec-ignore"
_MIN_UNSTRUCTURED_SECRET_LEN = 24
_QUOTED_GENERIC = re.compile(
    r"(?i)\b[\w-]*(?:secret|passw(?:or)?d|api[_-]?key|access[_-]?key|auth[_-]?token|token)"
    r"[\w-]*[\"']?\s*[:=]\s*[\"'](?P<secret>[^\"'\s]{8,})[\"']"
)
_SECRET_FIXABLE_LANGS = frozenset({"javascript", "typescript", "python"})
_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
_SKIP_SECRET_FILES = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "expected.json"}
)

RULE_ENV_COMMITTED = "builtin.config.env-committed"
RULE_MISSING_HEADERS = "builtin.config.missing-security-headers"
RULE_MISSING_CSRF = "builtin.config.missing-csrf"
_PROJECT_RULES = (RULE_ENV_COMMITTED, RULE_MISSING_HEADERS, RULE_MISSING_CSRF)

_HEADER_MARKERS = re.compile(
    r"helmet|Talisman|X-Content-Type-Options|Content-Security-Policy|SecurityHeaders",
    re.IGNORECASE,
)
_CSRF_MARKERS = re.compile(r"CSRFProtect|csrf|xsrf", re.IGNORECASE)
_APP_FACTORIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("express", re.compile(r"=\s*express\(\s*\)")),
    ("flask", re.compile(r"=\s*Flask\(")),
    ("fastapi", re.compile(r"=\s*FastAPI\(")),
)
_FORM_POST = re.compile(r"request\.form|methods\s*=\s*\[[^\]]*[\"']POST[\"']")
_EXPRESS_SESSION = re.compile(r"express-session|cookie-session|cookie-parser")
_EXPRESS_POST = re.compile(r"\b(?:app|router)\.(?:post|put|patch|delete)\s*\(")


class BuiltinScanner:
    """Regex-based checks that ship with the tool."""

    name = "builtin"
    install_hint = "Built in; nothing to install."

    def is_available(self) -> bool:
        """Always available."""
        return True

    def version(self) -> str:
        """The package version."""
        return __version__

    def rule_ids(self) -> list[str]:
        """Every rule this scanner applies."""
        ids = [r.rule_id for r in LINE_RULES]
        ids += [f"builtin.{p.rule_id}" for p in SECRET_PATTERNS]
        return [*ids, *_PROJECT_RULES]

    def run(self, root: Path, files: Sequence[SourceFile]) -> AdapterResult:
        """Scan every file once (O(total lines)), then run the project-level checks."""
        findings: list[RawFinding] = []
        for source in files:
            findings.extend(_scan_lines(source))
        findings.extend(_project_checks(files))
        rules = count_rule_matches("builtin", self.version(), findings, self.rule_ids())
        return AdapterResult(findings=findings, rules=rules)


def _looks_secret(value: str) -> bool:
    """Generic assignments only count when the value has a digit or is long.

    This skips names such as header keys ("X-AppSec-Token") and enum values.
    """
    return any(c.isdigit() for c in value) or len(value) >= _MIN_UNSTRUCTURED_SECRET_LEN


def _scan_lines(source: SourceFile) -> Iterator[RawFinding]:
    language = source.language
    check_secrets = PurePosixPath(source.rel_path).name not in _SKIP_SECRET_FILES
    for number, line in enumerate(source.text.splitlines(), start=1):
        if SUPPRESS_MARKER in line:
            continue
        if language in CODE_LANGS and not is_comment(line, language):
            yield from _line_rule_hits(source, number, line)
        if check_secrets:
            yield from _secret_hits(source, number, line)


def _line_rule_hits(source: SourceFile, number: int, line: str) -> Iterator[RawFinding]:
    for rule in LINE_RULES:
        if source.language in rule.languages and rule.regex.search(line):
            yield RawFinding(
                scanner="builtin",
                rule_id=rule.rule_id,
                severity=rule.severity,
                cwe=rule.cwe,
                rel_path=source.rel_path,
                line_start=number,
                line_end=number,
                snippet=line.strip(),
                message=rule.message,
                fix_kind=rule.fix_kind,
            )


def _secret_hits(source: SourceFile, number: int, line: str) -> Iterator[RawFinding]:
    fixable = source.language in _SECRET_FIXABLE_LANGS
    for pattern in SECRET_PATTERNS:
        regex = pattern.regex
        if pattern.rule_id == "secret.generic-assignment" and source.language not in _CONFIG_LANGS:
            regex = _QUOTED_GENERIC
        match = regex.search(line)
        if match is None or is_placeholder(match.group("secret")):
            continue
        if pattern.rule_id == "secret.generic-assignment" and not _looks_secret(
            match.group("secret")
        ):
            continue
        severity = "critical" if pattern.rule_id in _CRITICAL_SECRETS else "high"
        yield RawFinding(
            scanner="builtin",
            rule_id=f"builtin.{pattern.rule_id}",
            severity=severity,
            cwe="CWE-798",
            rel_path=source.rel_path,
            line_start=number,
            line_end=number,
            snippet=line.strip(),
            message=f"{pattern.title} written in the source.",
            fix_kind="hardcoded_secret" if fixable else None,
        )


def _project_checks(files: Sequence[SourceFile]) -> Iterator[RawFinding]:
    yield from _env_committed(files)
    code = [f for f in files if f.language in CODE_LANGS]
    all_text_has_headers = any(_HEADER_MARKERS.search(f.text) for f in code)
    all_text_has_csrf = any(_CSRF_MARKERS.search(f.text) for f in code)
    uses_session = any(_EXPRESS_SESSION.search(f.text) for f in files)
    for source in code:
        for framework, factory in _APP_FACTORIES:
            line_no = _first_match_line(source.text, factory)
            if line_no is None:
                continue
            if not all_text_has_headers:
                yield _config_finding(
                    source,
                    line_no,
                    RULE_MISSING_HEADERS,
                    "medium",
                    "CWE-693",
                    f"The {framework} app sends no security headers.",
                    "recipe:security_headers",
                )
            if not all_text_has_csrf and _needs_csrf(framework, source.text, uses_session):
                yield _config_finding(
                    source,
                    line_no,
                    RULE_MISSING_CSRF,
                    "medium",
                    "CWE-352",
                    f"The {framework} app accepts forms without CSRF protection.",
                    "recipe:csrf",
                )


def _needs_csrf(framework: str, text: str, uses_session: bool) -> bool:
    if framework == "flask":
        return bool(_FORM_POST.search(text))
    if framework == "express":
        return uses_session and bool(_EXPRESS_POST.search(text))
    return False


def _env_committed(files: Sequence[SourceFile]) -> Iterator[RawFinding]:
    for source in files:
        name = PurePosixPath(source.rel_path).name
        if source.language == "dotenv" and not name.endswith(_ENV_TEMPLATE_SUFFIXES):
            yield _config_finding(
                source,
                1,
                RULE_ENV_COMMITTED,
                "high",
                "CWE-538",
                f"{name} is not ignored by git, so it will be committed.",
                "env_gitignore",
            )


def _first_match_line(text: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(text)
    return text.count("\n", 0, match.start()) + 1 if match else None


def _config_finding(
    source: SourceFile,
    line_no: int,
    rule_id: str,
    severity: str,
    cwe: str,
    message: str,
    fix_kind: str | None,
) -> RawFinding:
    lines = source.text.splitlines()
    snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
    return RawFinding(
        scanner="builtin",
        rule_id=rule_id,
        severity=severity,
        cwe=cwe,  # type: ignore[arg-type]
        rel_path=source.rel_path,
        line_start=line_no,
        line_end=line_no,
        snippet=snippet,
        message=message,
        fix_kind=fix_kind,
    )
