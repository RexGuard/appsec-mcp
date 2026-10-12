"""OSV-Scanner adapter for known-vulnerable dependencies."""

import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from appsec_mcp.errors import ErrorCode, ScannerError
from appsec_mcp.models.base import Severity
from appsec_mcp.models.finding import RawFinding
from appsec_mcp.scan.walker import SourceFile
from appsec_mcp.scanners._subprocess import find_executable, first_line_version, run_command
from appsec_mcp.scanners.base import AdapterResult, count_rule_matches

logger = logging.getLogger(__name__)

_OK_EXIT_CODES = (0, 1)
_NO_PACKAGES_EXIT = 128
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


class OsvScanner:
    """Runs `osv-scanner scan source -r --format json`."""

    name = "osv"
    install_hint = (
        "Install OSV-Scanner: `winget install Google.OSVScanner` (Windows), "
        "`brew install osv-scanner` (macOS) or `go install github.com/google/osv-scanner/v2/cmd/"
        "osv-scanner@latest`."
    )

    def __init__(self, executable: str | None = None) -> None:
        self._exe = executable or find_executable("osv-scanner")

    def is_available(self) -> bool:
        """True when osv-scanner is on PATH."""
        return self._exe is not None

    def version(self) -> str:
        """OSV-Scanner's version string."""
        return first_line_version(self._exe, "--version") if self._exe else "unknown"

    def run(self, root: Path, files: Sequence[SourceFile]) -> AdapterResult:
        """Scan lockfiles and manifests under the root."""
        if self._exe is None:
            raise ScannerError(ErrorCode.SCANNER_FAILED, "OSV-Scanner is not installed.")
        args = [self._exe, "scan", "source", "--format", "json", "-r", str(root)]
        result = run_command(args, cwd=root)
        if result.returncode == _NO_PACKAGES_EXIT:
            return AdapterResult()
        if result.returncode not in _OK_EXIT_CODES:
            logger.error("OSV-Scanner failed (%d): %s", result.returncode, result.stderr[:500])
            raise ScannerError(ErrorCode.SCANNER_FAILED, "OSV-Scanner exited with an error.")
        findings = parse_osv_json(result.stdout, root)
        version = self.version()
        rule_ids = sorted({f.rule_id for f in findings})
        return AdapterResult(findings, count_rule_matches("osv", version, findings, rule_ids))


def parse_osv_json(stdout: str, root: Path) -> list[RawFinding]:
    """Convert OSV-Scanner JSON into one RawFinding per vulnerable package and advisory."""
    try:
        payload: dict[str, Any] = json.loads(stdout or "{}")
    except json.JSONDecodeError as exc:
        logger.error("OSV-Scanner output is not JSON")
        raise ScannerError(ErrorCode.SCANNER_FAILED, "OSV output was not valid JSON.") from exc
    findings: list[RawFinding] = []
    for result in payload.get("results", []):
        source_path = Path(str(result.get("source", {}).get("path", "")))
        rel = _relative(source_path, root)
        for package in result.get("packages", []):
            info = package.get("package", {})
            for vuln in package.get("vulnerabilities", []):
                findings.append(_to_raw(info, vuln, rel))
    return findings


def _to_raw(info: dict[str, Any], vuln: dict[str, Any], rel: str) -> RawFinding:
    name = f"{info.get('name', '?')}@{info.get('version', '?')}"
    severity_label = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    summary = vuln.get("summary") or vuln.get("details", "")[:200] or "Known vulnerability."
    cwe_ids = vuln.get("database_specific", {}).get("cwe_ids") or []
    return RawFinding(
        scanner="osv",
        rule_id=f"osv.{vuln.get('id', 'unknown')}",
        severity=_SEVERITY_MAP.get(severity_label, "medium"),
        cwe=cwe_ids[0] if cwe_ids else "CWE-1395",
        rel_path=rel,
        snippet=f"{info.get('ecosystem', '')} {name}",
        message=f"{name}: {summary}",
    )


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.name
