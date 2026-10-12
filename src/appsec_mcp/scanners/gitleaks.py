"""gitleaks adapter for leaked secrets. Runs with --redact so raw secrets never reach us."""

import json
import logging
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from appsec_mcp.errors import ErrorCode, ScannerError
from appsec_mcp.models.finding import RawFinding
from appsec_mcp.scan.walker import SourceFile
from appsec_mcp.scanners._subprocess import find_executable, first_line_version, run_command
from appsec_mcp.scanners.base import AdapterResult, count_rule_matches

logger = logging.getLogger(__name__)

_OK_EXIT_CODES = (0, 1)


class GitleaksScanner:
    """Runs `gitleaks detect --no-git` over the working tree."""

    name = "gitleaks"
    install_hint = (
        "Install gitleaks: `winget install gitleaks` (Windows), `brew install gitleaks` (macOS) "
        "or download a release from github.com/gitleaks/gitleaks."
    )

    def __init__(self, executable: str | None = None) -> None:
        self._exe = executable or find_executable("gitleaks")

    def is_available(self) -> bool:
        """True when gitleaks is on PATH."""
        return self._exe is not None

    def version(self) -> str:
        """gitleaks' version string."""
        return first_line_version(self._exe, "version") if self._exe else "unknown"

    def run(self, root: Path, files: Sequence[SourceFile]) -> AdapterResult:
        """Scan the root and parse the redacted JSON report."""
        if self._exe is None:
            raise ScannerError(ErrorCode.SCANNER_FAILED, "gitleaks is not installed.")
        with tempfile.TemporaryDirectory(prefix="appsec-gitleaks-") as tmp:
            report = Path(tmp) / "report.json"
            args = [
                self._exe,
                "detect",
                "--no-git",
                "--redact",
                "--no-banner",
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--source",
                str(root),
            ]
            result = run_command(args, cwd=root)
            if result.returncode not in _OK_EXIT_CODES:
                logger.error("gitleaks failed (%d): %s", result.returncode, result.stderr[:500])
                raise ScannerError(ErrorCode.SCANNER_FAILED, "gitleaks exited with an error.")
            text = report.read_text(encoding="utf-8") if report.exists() else "[]"
        findings = parse_gitleaks_json(text, root)
        version = self.version()
        rule_ids = sorted({f.rule_id for f in findings})
        return AdapterResult(findings, count_rule_matches("gitleaks", version, findings, rule_ids))


def parse_gitleaks_json(text: str, root: Path) -> list[RawFinding]:
    """Convert a gitleaks JSON report into RawFindings."""
    try:
        items: list[dict[str, Any]] = json.loads(text or "[]") or []
    except json.JSONDecodeError as exc:
        logger.error("gitleaks report is not JSON")
        raise ScannerError(ErrorCode.SCANNER_FAILED, "gitleaks report was not valid JSON.") from exc
    findings = []
    for item in items:
        file_path = Path(str(item.get("File", "")))
        rel = file_path.resolve().relative_to(root) if file_path.is_absolute() else file_path
        findings.append(
            RawFinding(
                scanner="gitleaks",
                rule_id=f"gitleaks.{item.get('RuleID', 'secret')}",
                severity="high",
                cwe="CWE-798",
                rel_path=rel.as_posix(),
                line_start=item.get("StartLine") or None,
                line_end=item.get("EndLine") or None,
                snippet=str(item.get("Match", "")),
                message=str(item.get("Description", "A secret was found in the source.")),
                fix_kind="hardcoded_secret",
            )
        )
    return findings
