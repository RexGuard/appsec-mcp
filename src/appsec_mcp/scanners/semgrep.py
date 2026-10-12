"""Semgrep OSS adapter, using the bundled offline rule pack."""

import json
import logging
import os
from collections.abc import Sequence
from importlib import resources
from pathlib import Path
from typing import Any

from appsec_mcp.errors import ErrorCode, ScannerError
from appsec_mcp.models.finding import RawFinding
from appsec_mcp.scan.walker import SourceFile
from appsec_mcp.scanners._subprocess import find_executable, first_line_version, run_command
from appsec_mcp.scanners.base import AdapterResult, count_rule_matches

logger = logging.getLogger(__name__)

EXTRA_CONFIGS_ENV = "APPSEC_MCP_SEMGREP_CONFIGS"
_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}
_OK_EXIT_CODES = (0, 1)


def bundled_rules_path() -> Path:
    """Path of the bundled Semgrep rule file."""
    return Path(str(resources.files("appsec_mcp.scanners") / "rules" / "semgrep.yml"))


class SemgrepScanner:
    """Runs `semgrep scan --json` with local rules only (no registry download by default)."""

    name = "semgrep"
    install_hint = (
        "Install Semgrep with `pipx install semgrep` (macOS/Linux). On Windows use "
        "`pip install semgrep` (native beta) or run it inside WSL."
    )

    def __init__(self, executable: str | None = None) -> None:
        self._exe = executable or find_executable("semgrep")

    def is_available(self) -> bool:
        """True when the semgrep binary is on PATH."""
        return self._exe is not None

    def version(self) -> str:
        """Semgrep's version string."""
        return first_line_version(self._exe, "--version") if self._exe else "unknown"

    def run(self, root: Path, files: Sequence[SourceFile]) -> AdapterResult:
        """Scan the root and normalise Semgrep's JSON output."""
        if self._exe is None:
            raise ScannerError(ErrorCode.SCANNER_FAILED, "Semgrep is not installed.")
        configs = [str(bundled_rules_path())]
        configs += [c for c in os.environ.get(EXTRA_CONFIGS_ENV, "").split(",") if c]
        args = [self._exe, "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check"]
        for config in configs:
            args += ["--config", config]
        args += ["--", str(root)]
        result = run_command(args, cwd=root)
        if result.returncode not in _OK_EXIT_CODES:
            logger.error("Semgrep failed (%d): %s", result.returncode, result.stderr[:500])
            raise ScannerError(ErrorCode.SCANNER_FAILED, "Semgrep exited with an error.")
        findings = parse_semgrep_json(result.stdout, root)
        rule_ids = _bundled_rule_ids()
        version = self.version()
        return AdapterResult(findings, count_rule_matches("semgrep", version, findings, rule_ids))


def _bundled_rule_ids() -> list[str]:
    ids: list[str] = []
    for line in bundled_rules_path().read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("- id:"):
            ids.append(f"semgrep.{stripped.removeprefix('- id:').strip()}")
    return ids


def parse_semgrep_json(stdout: str, root: Path) -> list[RawFinding]:
    """Convert Semgrep's JSON report into RawFindings with root-relative paths."""
    try:
        payload: dict[str, Any] = json.loads(stdout or "{}")
    except json.JSONDecodeError as exc:
        logger.error("Semgrep output is not JSON")
        raise ScannerError(ErrorCode.SCANNER_FAILED, "Semgrep output was not valid JSON.") from exc
    return [_to_raw(item, root) for item in payload.get("results", [])]


def _to_raw(item: dict[str, Any], root: Path) -> RawFinding:
    extra = item.get("extra", {})
    metadata = extra.get("metadata", {})
    cwe = metadata.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if isinstance(cwe, str):
        cwe = cwe.split(":")[0].strip()
    severity = _SEVERITY_MAP.get(
        str(metadata.get("severity") or extra.get("severity")).upper(), "medium"
    )
    return RawFinding(
        scanner="semgrep",
        rule_id=f"semgrep.{str(item.get('check_id', 'unknown')).split('.')[-1]}",
        severity=severity,  # type: ignore[arg-type]
        cwe=cwe,
        rel_path=_relative(item.get("path", ""), root),
        line_start=item.get("start", {}).get("line"),
        line_end=item.get("end", {}).get("line"),
        snippet=str(extra.get("lines", "")).strip(),
        message=str(extra.get("message", "")),
        fix_kind=metadata.get("appsec_fix"),
    )


def _relative(path: str, root: Path) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(root).as_posix()
        except ValueError:
            return candidate.as_posix()
    return candidate.as_posix()
