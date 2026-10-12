"""Safe subprocess execution for external scanners: list args, timeout, output cap."""

import logging
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from appsec_mcp.config import SCANNER_MAX_OUTPUT_BYTES, SCANNER_TIMEOUT_S
from appsec_mcp.errors import ErrorCode, ScannerError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandResult:
    """Exit code and captured output of a finished command."""

    returncode: int
    stdout: str
    stderr: str


def find_executable(name: str) -> str | None:
    """Return the full path of an executable on PATH, or None."""
    return shutil.which(name)


def run_command(
    args: Sequence[str],
    *,
    timeout_s: float = SCANNER_TIMEOUT_S,
    max_output_bytes: int = SCANNER_MAX_OUTPUT_BYTES,
    cwd: Path | None = None,
) -> CommandResult:
    """Run a command without a shell. Raises ScannerError on timeout, oversize output or OSError."""
    try:
        completed = subprocess.run(
            list(args), capture_output=True, timeout=timeout_s, cwd=cwd, check=False
        )
    except subprocess.TimeoutExpired as exc:
        logger.error("Command timed out after %ss: %s", timeout_s, args[0])
        raise ScannerError(
            ErrorCode.SCANNER_FAILED, f"{args[0]} took longer than {timeout_s:.0f} s."
        ) from exc
    except OSError as exc:
        logger.error("Command could not start: %s (%s)", args[0], exc)
        raise ScannerError(ErrorCode.SCANNER_FAILED, f"{args[0]} could not start: {exc}") from exc
    if len(completed.stdout) > max_output_bytes:
        logger.error("Command output too large: %s (%d bytes)", args[0], len(completed.stdout))
        raise ScannerError(
            ErrorCode.SCANNER_FAILED, f"{args[0]} produced more output than the safety limit."
        )
    return CommandResult(
        completed.returncode,
        completed.stdout.decode("utf-8", errors="replace"),
        completed.stderr.decode("utf-8", errors="replace"),
    )


def first_line_version(executable: str, *flags: str) -> str:
    """Run `<exe> <flags>` and return the first output line, or 'unknown'."""
    try:
        result = run_command([executable, *flags], timeout_s=30)
    except ScannerError:
        return "unknown"
    text = (result.stdout or result.stderr).strip()
    return text.splitlines()[0].strip() if text else "unknown"
