"""Logging: stderr (stdout belongs to the MCP protocol) plus a rotating file."""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_MAX_LOG_BYTES = 2 * 1024 * 1024
_BACKUP_COUNT = 3


def configure_logging(logs_dir: Path, level: int = logging.INFO) -> None:
    """Send logs to stderr and to logs_dir/appsec-mcp.log. Never to stdout."""
    logs_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    formatter = logging.Formatter(_FORMAT)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    stderr_handler.setLevel(logging.WARNING)
    file_handler = RotatingFileHandler(
        logs_dir / "appsec-mcp.log",
        maxBytes=_MAX_LOG_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(stderr_handler)
    root.addHandler(file_handler)
