"""SQLite connection handling. Each operation opens a short-lived connection."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from appsec_mcp.storage.migrations import migrate

_BUSY_TIMEOUT_S = 30.0


def utc_now() -> str:
    """Current time as an ISO-8601 UTC string."""
    return datetime.now(UTC).isoformat(timespec="seconds")


class Database:
    """A SQLite file plus a connection factory. Thread-safe because connections are not shared."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            migrate(conn)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection; commit on success, roll back on error, always close."""
        conn = sqlite3.connect(self.path, timeout=_BUSY_TIMEOUT_S)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            raise
        finally:
            conn.close()
